#include "loader/elf/elf.hpp"

#include <fstream>
#include <limits>
#include <stdexcept>

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

std::string string_at(const std::vector<std::uint8_t> &bytes, std::uint64_t index) {
  std::string result;
  while (index < bytes.size() && bytes[index] != 0)
    result.push_back(static_cast<char>(bytes[index++]));
  if (index == bytes.size())
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

  const auto &h = file.header;
  if (h.program_header_count) {
    const auto expected = is64 ? 56u : 32u;
    if (h.program_header_size < expected) throw Error("invalid program header size");
    require_range(h.program_header_offset, static_cast<std::uint64_t>(h.program_header_size) * h.program_header_count, bytes.size(), "program header table");
    for (std::uint16_t i = 0; i < h.program_header_count; ++i) {
      const auto o = h.program_header_offset + static_cast<std::uint64_t>(i) * h.program_header_size;
      ProgramHeader p; p.type = u32(o);
      if (is64) { p.flags=u32(o+4); p.offset=u64(o+8); p.virtual_address=u64(o+16); p.physical_address=u64(o+24); p.file_size=u64(o+32); p.memory_size=u64(o+40); p.alignment=u64(o+48); }
      else { p.offset=u32(o+4); p.virtual_address=u32(o+8); p.physical_address=u32(o+12); p.file_size=u32(o+16); p.memory_size=u32(o+20); p.flags=u32(o+24); p.alignment=u32(o+28); }
      file.program_headers.push_back(p);
    }
  }
  if (h.section_header_count) {
    const auto expected = is64 ? 64u : 40u;
    if (h.section_header_size < expected) throw Error("invalid section header size");
    require_range(h.section_header_offset, static_cast<std::uint64_t>(h.section_header_size) * h.section_header_count, bytes.size(), "section header table");
    if (h.section_name_string_table_index >= h.section_header_count) throw Error("invalid section-name string table index");
    for (std::uint16_t i = 0; i < h.section_header_count; ++i) {
      const auto o = h.section_header_offset + static_cast<std::uint64_t>(i) * h.section_header_size;
      SectionHeader s; s.name_offset=u32(o); s.type=u32(o+4);
      if (is64) { s.flags=u64(o+8); s.address=u64(o+16); s.offset=u64(o+24); s.size=u64(o+32); s.link=u32(o+40); s.info=u32(o+44); s.alignment=u64(o+48); s.entry_size=u64(o+56); }
      else { s.flags=u32(o+8); s.address=u32(o+12); s.offset=u32(o+16); s.size=u32(o+20); s.link=u32(o+24); s.info=u32(o+28); s.alignment=u32(o+32); s.entry_size=u32(o+36); }
      if (s.type != 8) require_range(s.offset, s.size, bytes.size(), "section");
      file.sections.push_back(s);
    }
    const auto &str = file.sections[h.section_name_string_table_index];
    if (str.type != 3) throw Error("section-name string table is not STRTAB");
    require_range(str.offset, str.size, bytes.size(), "section-name string table");
    for (auto &s : file.sections) {
      if (s.name_offset >= str.size) throw Error("section name offset outside string table");
      const auto start = str.offset + s.name_offset;
      s.name = string_at(file.bytes, start);
    }
    for (const auto &table : file.sections) {
      if (table.type != 2 && table.type != 11) continue;
      if (table.entry_size == 0) continue;
      require_range(table.offset, table.size, bytes.size(), "symbol table");
      if (table.link >= file.sections.size()) throw Error("symbol string table index is invalid");
      const auto &strings = file.sections[table.link];
      if (strings.type != 3) throw Error("symbol string table is not STRTAB");
      if (table.size % table.entry_size != 0) throw Error("symbol table has partial entry");
      const auto count = table.size / table.entry_size;
      for (std::uint64_t i = 0; i < count; ++i) {
        const auto o = table.offset + i * table.entry_size;
        Symbol symbol;
        const auto name_offset = u32(o);
        if (name_offset >= strings.size) throw Error("symbol name outside string table");
        symbol.name = string_at(file.bytes, strings.offset + name_offset);
        if (is64) { symbol.info = bytes[o + 4]; symbol.other = bytes[o + 5]; symbol.section_index = static_cast<std::uint16_t>(u16(o + 6)); symbol.value = u64(o + 8); symbol.size = u64(o + 16); }
        else { symbol.value = u32(o + 4); symbol.size = u32(o + 8); symbol.info = bytes[o + 12]; symbol.other = bytes[o + 13]; symbol.section_index = static_cast<std::uint16_t>(u16(o + 14)); }
        symbol.dynamic = table.type == 11;
        file.symbols.push_back(std::move(symbol));
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
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
  in.seekg(0); if (!bytes.empty()) in.read(reinterpret_cast<char *>(bytes.data()), bytes.size());
  if (!in && !bytes.empty()) throw Error("could not read file");
  return parse(bytes);
}

const SectionHeader *File::section(const std::string &name) const { for (const auto &s : sections) if (s.name == name) return &s; return nullptr; }
std::vector<std::uint8_t> File::section_bytes(const SectionHeader &s) const { if (s.offset > bytes.size() || s.size > bytes.size() - s.offset) throw Error("section extends beyond file"); return {bytes.begin() + s.offset, bytes.begin() + s.offset + s.size}; }
std::optional<std::uint64_t> File::virtual_to_file(std::uint64_t address) const { for (const auto &p : program_headers) if (p.type == 1 && address >= p.virtual_address && address - p.virtual_address < p.file_size) return p.offset + address - p.virtual_address; return std::nullopt; }
std::optional<std::uint64_t> File::file_to_virtual(std::uint64_t offset) const { for (const auto &p : program_headers) if (p.type == 1 && offset >= p.offset && offset - p.offset < p.file_size) return p.virtual_address + offset - p.offset; return std::nullopt; }
const char *class_name(Class c) { return c == Class::Elf32 ? "ELF32" : "ELF64"; }
const char *endian_name(Endian e) { return e == Endian::Little ? "Little Endian" : "Big Endian"; }
const char *type_name(std::uint16_t t) { return t == 1 ? "REL" : t == 2 ? "EXEC" : t == 3 ? "DYN" : "Unknown"; }
const char *machine_name(std::uint16_t m) { return m == 62 ? "x86-64" : m == 3 ? "x86" : "Unknown"; }
} // namespace caraxes::elf
