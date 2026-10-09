#include "loader/elf/elf.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>

int main(int argc, char **argv) {
  const auto file = caraxes::elf::parse_file(argc > 1 ? argv[1] : "../hello");
  assert(file.header.elf_class == caraxes::elf::Class::Elf64);
  assert(file.header.endian == caraxes::elf::Endian::Little);
  assert(file.header.machine == 62);
  assert(file.header.entry != 0);
  assert(!file.program_headers.empty());
  assert(!file.sections.empty());
  assert(file.section(".text") != nullptr);
  assert(file.section(".shstrtab") != nullptr);
  assert(file.section(".text")->size > 0);
  assert(!file.relocations.empty());

  const auto *bss = file.section(".bss");
  assert(bss != nullptr);
  assert(file.section_bytes(*bss).size() == bss->size);

  auto write16 = [](std::vector<std::uint8_t> &bytes, std::size_t offset,
                    std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
  };
  auto write64 = [](std::vector<std::uint8_t> &bytes, std::size_t offset,
                    std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i)
      bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
  };
  auto extended_sections = file.bytes;
  write16(extended_sections, 60, 0); // e_shnum = SHN_XNUM
  write64(extended_sections, static_cast<std::size_t>(file.header.section_header_offset) +
                                32,
          file.sections.size());
  const auto extended = caraxes::elf::parse(extended_sections);
  assert(extended.sections.size() == file.sections.size());
  assert(extended.header.section_header_count_full == file.sections.size());

  auto extended_programs = file.bytes;
  write16(extended_programs, 56, 0xffff); // e_phnum = PN_XNUM
  write16(extended_programs, static_cast<std::size_t>(file.header.section_header_offset) +
                               44,
          static_cast<std::uint16_t>(file.program_headers.size()));
  const auto extended_phdrs = caraxes::elf::parse(extended_programs);
  assert(extended_phdrs.program_headers.size() == file.program_headers.size());

  bool rejected = false;
  try {
    caraxes::elf::parse(std::vector<std::uint8_t>{0x7f, 'E', 'L', 'F', 2, 1});
  } catch (const caraxes::elf::Error &) {
    rejected = true;
  }
  assert(rejected);
  std::cout << "ELF loader tests passed\n";
}
