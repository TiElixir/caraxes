#include "loader/elf/elf.hpp"

#include <fstream>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <utility>

namespace caraxes::elf {
namespace {
std::uint64_t read_integer(const std::vector<std::uint8_t> &b, std::size_t off,
                           std::size_t width, Endian endian) {
  if (width == 0 || width > 8 || off > b.size() || width > b.size() - off)
    throw Error("ELF field extends beyond file");
  std::uint64_t result = 0;
  if (endian == Endian::Little) {
    for (std::size_t i = 0; i < width; ++i)
      result |= static_cast<std::uint64_t>(b[off + i]) << (i * 8);
  } else {
    for (std::size_t i = 0; i < width; ++i)
      result = (result << 8) | b[off + i];
  }
  return result;
}

void require_range(std::uint64_t offset, std::uint64_t size,
                   std::size_t file_size, const char *what) {
  if (offset > file_size || size > file_size - offset)
    throw Error(std::string("ELF ") + what + " extends beyond file");
}

std::uint64_t checked_product(std::uint64_t left, std::uint64_t right,
                              const char *what) {
  if (right != 0 && left > std::numeric_limits<std::uint64_t>::max() / right)
    throw Error(std::string("ELF ") + what + " size overflows");
  return left * right;
}

std::string string_at(const std::vector<std::uint8_t> &bytes,
                      std::uint64_t index, std::uint64_t end) {
  if (index >= end || end > bytes.size())
    throw Error("ELF string is outside its string table");
  std::string result;
  while (index < end && bytes[index] != 0)
    result.push_back(static_cast<char>(bytes[index++]));
  if (index == end)
    throw Error("ELF string is not NUL terminated");
  return result;
}
} // namespace

File parse(const std::vector<std::uint8_t> &bytes) {
  if (bytes.size() < 16 || bytes[0] != 0x7f || bytes[1] != 'E' ||
      bytes[2] != 'L' || bytes[3] != 'F')
    throw Error("not an ELF file");
  if (bytes[4] != 1 && bytes[4] != 2)
    throw Error("unsupported ELF class");
  if (bytes[5] != 1 && bytes[5] != 2)
    throw Error("unsupported ELF endianness");
  if (bytes[6] != 1)
    throw Error("unsupported ELF identification version");

  File file;
  file.bytes = bytes;
  file.header.elf_class = static_cast<Class>(bytes[4]);
  file.header.endian = static_cast<Endian>(bytes[5]);
  const auto e = file.header.endian;
  const bool is64 = file.header.elf_class == Class::Elf64;
  const std::size_t minimum = is64 ? 64 : 52;
  if (bytes.size() < minimum)
    throw Error("ELF header is truncated");

  const auto u16 = [&](std::size_t o) { return read_integer(bytes, o, 2, e); };
  const auto u32 = [&](std::size_t o) { return read_integer(bytes, o, 4, e); };
  const auto u64 = [&](std::size_t o) { return read_integer(bytes, o, 8, e); };
  file.header.type = static_cast<std::uint16_t>(u16(16));
  file.header.machine = static_cast<std::uint16_t>(u16(18));
  file.header.version = static_cast<std::uint32_t>(u32(20));
  if (is64) {
    file.header.entry = u64(24); file.header.program_header_offset = u64(32);
    file.header.section_header_offset = u64(40); file.header.flags = u32(48);
    file.header.header_size = static_cast<std::uint16_t>(u16(52));
    file.header.program_header_size = static_cast<std::uint16_t>(u16(54));
    file.header.program_header_count = static_cast<std::uint16_t>(u16(56));
    file.header.section_header_size = static_cast<std::uint16_t>(u16(58));
    file.header.section_header_count = static_cast<std::uint16_t>(u16(60));
    file.header.section_name_string_table_index = static_cast<std::uint16_t>(u16(62));
  } else {
    file.header.entry = u32(24); file.header.program_header_offset = u32(28);
    file.header.section_header_offset = u32(32); file.header.flags = u32(36);
    file.header.header_size = static_cast<std::uint16_t>(u16(40));
    file.header.program_header_size = static_cast<std::uint16_t>(u16(42));
    file.header.program_header_count = static_cast<std::uint16_t>(u16(44));
    file.header.section_header_size = static_cast<std::uint16_t>(u16(46));
    file.header.section_header_count = static_cast<std::uint16_t>(u16(48));
    file.header.section_name_string_table_index = static_cast<std::uint16_t>(u16(50));
  }
  if (file.header.header_size < minimum)
    throw Error("invalid ELF header size");
  require_range(0, file.header.header_size, bytes.size(), "header");
  if (file.header.version != 1)
    throw Error("unsupported ELF version");

  const auto &h = file.header;
  std::uint64_t program_header_count = h.program_header_count;
  std::uint64_t section_header_count = h.section_header_count;
  std::uint64_t section_name_string_table_index =
      h.section_name_string_table_index;

  // ELF reserves marker values in the fixed-width header for files whose
  // actual counts do not fit. The real values live in section header zero.
  const bool needs_extended_numbering =
      program_header_count == 0xffff || section_header_count == 0 ||
      section_name_string_table_index == 0xffff;
  if (needs_extended_numbering && h.section_header_offset != 0 &&
      h.section_header_size != 0) {
    const auto expected_section_header_size = is64 ? 64u : 40u;
    if (h.section_header_size < expected_section_header_size)
      throw Error("invalid section header size for extended numbering");
    require_range(h.section_header_offset, h.section_header_size, bytes.size(),
                  "extended section header zero");
    const auto section_zero = h.section_header_offset;
    if (section_header_count == 0) {
      section_header_count = is64 ? u64(section_zero + 32)
                                  : u32(section_zero + 20);
    }
    if (program_header_count == 0xffff) {
      program_header_count = is64 ? u32(section_zero + 44)
                                  : u32(section_zero + 28);
    }
    if (section_name_string_table_index == 0xffff) {
      section_name_string_table_index = is64 ? u32(section_zero + 40)
                                             : u32(section_zero + 24);
    }
  } else if (program_header_count == 0xffff ||
             section_name_string_table_index == 0xffff) {
    throw Error("ELF extended numbering requires section header zero");
  }
  file.header.program_header_count_full = program_header_count;
  file.header.section_header_count_full = section_header_count;
  file.header.section_name_string_table_index_full =
      section_name_string_table_index;

  if (program_header_count) {
    const auto expected = is64 ? 56u : 32u;
    if (h.program_header_size < expected) throw Error("invalid program header size");
    const auto table_size = checked_product(h.program_header_size,
                                            program_header_count,
                                            "program header table");
    require_range(h.program_header_offset, table_size, bytes.size(), "program header table");
    for (std::uint64_t i = 0; i < program_header_count; ++i) {
      const auto o = h.program_header_offset + static_cast<std::uint64_t>(i) * h.program_header_size;
      ProgramHeader p; p.type = u32(o);
      if (is64) { p.flags=u32(o+4); p.offset=u64(o+8); p.virtual_address=u64(o+16); p.physical_address=u64(o+24); p.file_size=u64(o+32); p.memory_size=u64(o+40); p.alignment=u64(o+48); }
      else { p.offset=u32(o+4); p.virtual_address=u32(o+8); p.physical_address=u32(o+12); p.file_size=u32(o+16); p.memory_size=u32(o+20); p.flags=u32(o+24); p.alignment=u32(o+28); }
      file.program_headers.push_back(p);
    }
  }
  if (section_header_count) {
    const auto expected = is64 ? 64u : 40u;
    if (h.section_header_size < expected) throw Error("invalid section header size");
    const auto table_size = checked_product(h.section_header_size,
                                            section_header_count,
                                            "section header table");
    require_range(h.section_header_offset, table_size, bytes.size(), "section header table");
    if (section_name_string_table_index != 0 &&
        section_name_string_table_index >= section_header_count)
      throw Error("invalid section-name string table index");
    for (std::uint64_t i = 0; i < section_header_count; ++i) {
      const auto o = h.section_header_offset + static_cast<std::uint64_t>(i) * h.section_header_size;
      SectionHeader s; s.name_offset=u32(o); s.type=u32(o+4);
      if (is64) { s.flags=u64(o+8); s.address=u64(o+16); s.offset=u64(o+24); s.size=u64(o+32); s.link=u32(o+40); s.info=u32(o+44); s.alignment=u64(o+48); s.entry_size=u64(o+56); }
      else { s.flags=u32(o+8); s.address=u32(o+12); s.offset=u32(o+16); s.size=u32(o+20); s.link=u32(o+24); s.info=u32(o+28); s.alignment=u32(o+32); s.entry_size=u32(o+36); }
      if (s.type != 8) require_range(s.offset, s.size, bytes.size(), "section");
      file.sections.push_back(s);
    }
    if (section_name_string_table_index != 0) {
      const auto &str = file.sections[section_name_string_table_index];
      if (str.type != 3) throw Error("section-name string table is not STRTAB");
      require_range(str.offset, str.size, bytes.size(), "section-name string table");
      for (auto &s : file.sections) {
        if (s.name_offset >= str.size)
          throw Error("section name offset outside string table");
        const auto start = str.offset + s.name_offset;
        s.name = string_at(file.bytes, start, str.offset + str.size);
      }
    }
    std::map<std::pair<std::uint32_t, std::uint64_t>, std::string> symbol_names;
    for (std::uint32_t table_index = 0;
         table_index < file.sections.size(); ++table_index) {
      const auto &table = file.sections[table_index];
      if (table.type != 2 && table.type != 11) continue;
      const auto expected_entry_size = is64 ? 24u : 16u;
      if (table.size == 0)
        continue;
      if (table.entry_size < expected_entry_size)
        throw Error("invalid symbol table entry size");
      require_range(table.offset, table.size, bytes.size(), "symbol table");
      if (table.link >= file.sections.size()) throw Error("symbol string table index is invalid");
      const auto &strings = file.sections[table.link];
      if (strings.type != 3) throw Error("symbol string table is not STRTAB");
      if (table.size % table.entry_size != 0) throw Error("symbol table has partial entry");
      const auto count = table.size / table.entry_size;
      for (std::uint64_t i = 0; i < count; ++i) {
        const auto o = table.offset + checked_product(i, table.entry_size,
                                                       "symbol table");
        Symbol symbol;
        const auto name_offset = u32(o);
        if (name_offset >= strings.size) throw Error("symbol name outside string table");
        require_range(strings.offset, strings.size, bytes.size(),
                      "symbol string table");
        symbol.name = string_at(file.bytes, strings.offset + name_offset,
                                strings.offset + strings.size);
        if (is64) { symbol.info = bytes[o + 4]; symbol.other = bytes[o + 5]; symbol.section_index = static_cast<std::uint16_t>(u16(o + 6)); symbol.value = u64(o + 8); symbol.size = u64(o + 16); }
        else { symbol.value = u32(o + 4); symbol.size = u32(o + 8); symbol.info = bytes[o + 12]; symbol.other = bytes[o + 13]; symbol.section_index = static_cast<std::uint16_t>(u16(o + 14)); }
        symbol.dynamic = table.type == 11;
        symbol_names.emplace(std::make_pair(table_index, i), symbol.name);
        file.symbols.push_back(std::move(symbol));
      }
    }

    for (std::uint32_t section_index = 0;
         section_index < file.sections.size(); ++section_index) {
      const auto &table = file.sections[section_index];
      const bool rela = table.type == 4;
      const bool rel = table.type == 9;
      if (!rela && !rel)
        continue;
      const auto expected_entry_size =
          is64 ? (rela ? 24u : 16u) : (rela ? 12u : 8u);
      if (table.size == 0)
        continue;
      if (table.entry_size < expected_entry_size)
        throw Error("invalid relocation entry size");
      require_range(table.offset, table.size, bytes.size(), "relocation table");
      if (table.size % table.entry_size != 0)
        throw Error("relocation table has partial entry");
      if (table.link >= file.sections.size() ||
          (file.sections[table.link].type != 2 &&
           file.sections[table.link].type != 11))
        throw Error("relocation symbol table index is invalid");

      const auto count = table.size / table.entry_size;
      for (std::uint64_t i = 0; i < count; ++i) {
        const auto o = table.offset +
                       checked_product(i, table.entry_size, "relocation table");
        Relocation relocation;
        relocation.section_index = section_index;
        if (is64) {
          relocation.offset = u64(o);
          relocation.info = u64(o + 8);
          relocation.type = relocation.info & 0xffffffffULL;
          relocation.symbol_index = relocation.info >> 32;
          if (rela)
            relocation.addend = static_cast<std::int64_t>(u64(o + 16));
        } else {
          relocation.offset = u32(o);
          relocation.info = u32(o + 4);
          relocation.type = relocation.info & 0xfU;
          relocation.symbol_index = relocation.info >> 8;
          if (rela)
            relocation.addend = static_cast<std::int32_t>(u32(o + 8));
        }
        const auto symbol = symbol_names.find(
            std::make_pair(table.link, relocation.symbol_index));
        if (symbol != symbol_names.end())
          relocation.symbol_name = symbol->second;
        file.relocations.push_back(std::move(relocation));
      }
    }
  }
  return file;
}

File parse_file(const std::filesystem::path &path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw Error("could not open file: " + path.string());
  in.seekg(0, std::ios::end); const auto end = in.tellg();
  if (end < 0) throw Error("could not determine file size");
  if (static_cast<std::uintmax_t>(end) >
      std::numeric_limits<std::size_t>::max())
    throw Error("file is too large for this process");
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
  in.seekg(0); if (!bytes.empty()) in.read(reinterpret_cast<char *>(bytes.data()), bytes.size());
  if (!in && !bytes.empty()) throw Error("could not read file");
  return parse(bytes);
}

const SectionHeader *File::section(const std::string &name) const {
  for (const auto &section : sections)
    if (section.name == name)
      return &section;
  return nullptr;
}

std::vector<std::uint8_t> File::section_bytes(const SectionHeader &section) const {
  if (section.type == 8) {
    if (section.size > std::numeric_limits<std::size_t>::max())
      throw Error("NOBITS section is too large");
    const auto size = static_cast<std::size_t>(section.size);
    if (size > std::vector<std::uint8_t>().max_size())
      throw Error("NOBITS section is too large");
    try {
      return std::vector<std::uint8_t>(size, 0);
    } catch (const std::bad_alloc &) {
      throw Error("could not allocate NOBITS section");
    }
  }
  require_range(section.offset, section.size, bytes.size(), "section");
  if (section.size > std::numeric_limits<std::size_t>::max())
    throw Error("section is too large");
  const auto begin = bytes.begin() + static_cast<std::size_t>(section.offset);
  const auto end = begin + static_cast<std::size_t>(section.size);
  return {begin, end};
}

std::optional<std::uint64_t> File::virtual_to_file(
    std::uint64_t address) const {
  for (const auto &program : program_headers) {
    if (program.type != 1 || address < program.virtual_address)
      continue;
    const auto delta = address - program.virtual_address;
    if (delta >= program.file_size ||
        program.offset > std::numeric_limits<std::uint64_t>::max() - delta)
      continue;
    return program.offset + delta;
  }
  return std::nullopt;
}

std::optional<std::uint64_t> File::file_to_virtual(
    std::uint64_t offset) const {
  for (const auto &program : program_headers) {
    if (program.type != 1 || offset < program.offset)
      continue;
    const auto delta = offset - program.offset;
    if (delta >= program.file_size ||
        program.virtual_address > std::numeric_limits<std::uint64_t>::max() -
                                      delta)
      continue;
    return program.virtual_address + delta;
  }
  return std::nullopt;
}

const char *class_name(Class c) {
  return c == Class::Elf32 ? "ELF32" : c == Class::Elf64 ? "ELF64" : "Unknown";
}

const char *endian_name(Endian e) {
  return e == Endian::Little ? "Little Endian"
                             : e == Endian::Big ? "Big Endian" : "Unknown";
}

const char *type_name(std::uint16_t t) {
  switch (t) {
  case 0:
    return "NONE";
  case 1:
    return "REL";
  case 2:
    return "EXEC";
  case 3:
    return "DYN";
  case 4:
    return "CORE";
  default:
    return "Unknown";
  }
}

const char *machine_name(std::uint16_t m) {
  switch (m) {
  case 3:
    return "x86";
  case 62:
    return "x86-64";
  case 40:
    return "ARM";
  case 183:
    return "AArch64";
  case 243:
    return "RISC-V";
  default:
    return "Unknown";
  }
}
} // namespace caraxes::elf
