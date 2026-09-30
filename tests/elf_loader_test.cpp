#include "loader/elf/elf.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
  const auto file = caraxes::elf::parse_file("../hello");
  assert(file.header.elf_class == caraxes::elf::Class::Elf64);
  assert(file.header.endian == caraxes::elf::Endian::Little);
  assert(file.header.machine == 62);
  assert(file.header.entry != 0);
  assert(!file.program_headers.empty());
  assert(!file.sections.empty());
  assert(file.section(".text") != nullptr);
  assert(file.section(".shstrtab") != nullptr);
  assert(file.section(".text")->size > 0);

  bool rejected = false;
  try {
    caraxes::elf::parse(std::vector<std::uint8_t>{0x7f, 'E', 'L', 'F', 2, 1});
  } catch (const caraxes::elf::Error &) {
    rejected = true;
  }
  assert(rejected);
  std::cout << "ELF loader tests passed\n";
}
