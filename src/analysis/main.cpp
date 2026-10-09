#include "analysis/analysis.hpp"
#include "loader/elf/elf.hpp"

#include <iostream>
#include <vector>

int main(int argc, char **argv) {
  if (argc != 2) { std::cerr << "usage: caraxes-analysis <binary>\n"; return 1; }
  try {
    const auto file = caraxes::elf::parse_file(argv[1]);
    if (file.header.elf_class != caraxes::elf::Class::Elf64 ||
        file.header.machine != 62)
      throw caraxes::elf::Error("analysis currently supports ELF64 x86-64 binaries");
    const auto *text = file.section(".text");
    if (!text || text->size == 0) throw caraxes::elf::Error("binary has no .text section");
    const auto bytes = file.section_bytes(*text);
    std::vector<caraxes::analysis::FunctionSeed> seeds;
    for (const auto &symbol : file.symbols) {
      const auto type = static_cast<std::uint8_t>(symbol.info & 0x0f);
      if (symbol.name.empty() || (type != 2 && type != 10) || symbol.value == 0)
        continue;
      if (symbol.value < text->address || symbol.value - text->address >= text->size)
        continue;
      seeds.push_back({symbol.value, symbol.size, symbol.name});
    }
    std::cout << caraxes::analysis::report(
        caraxes::analysis::analyze(bytes, text->address, file.header.entry, seeds));
  } catch (const std::exception &e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
}
