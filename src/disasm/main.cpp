#include "disasm/disasm.hpp"

#include <iomanip>
#include <iostream>

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    std::cerr << "usage: caraxes-disasm <binary> [section]\n";
    return 1;
  }
  try {
    const auto file = caraxes::elf::parse_file(argv[1]);
    const auto instructions = caraxes::disasm::disassemble_section(
        file, argc == 3 ? argv[2] : ".text");
    for (const auto &instruction : instructions) {
      std::cout << std::hex << std::setw(16) << std::setfill('0')
                << instruction.address << "  ";
      for (const auto byte : instruction.bytes)
        std::cout << std::setw(2) << static_cast<unsigned>(byte) << ' ';
      std::cout << std::setfill(' ') << "  " << instruction.text() << '\n';
    }
  } catch (const std::exception &error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  }
}
