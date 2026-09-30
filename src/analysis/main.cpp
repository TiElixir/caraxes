#include "analysis/analysis.hpp"
#include "loader/elf/elf.hpp"
#include <iostream>

int main(int argc, char **argv) {
  if (argc != 2) { std::cerr << "usage: caraxes-analysis <binary>\n"; return 1; }
  try {
    const auto file = caraxes::elf::parse_file(argv[1]);
    const auto *text = file.section(".text");
    if (!text || text->size == 0) throw caraxes::elf::Error("binary has no .text section");
    std::vector<std::uint8_t> bytes(file.bytes.begin() + text->offset, file.bytes.begin() + text->offset + text->size);
    std::cout << caraxes::analysis::report(caraxes::analysis::analyze(bytes, text->address, file.header.entry));
  } catch (const std::exception &e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
}
