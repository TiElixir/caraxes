#include "analysis/analysis.hpp"
#include "decompiler/decompiler.hpp"
#include "decompiler/project.hpp"
#include "loader/elf/elf.hpp"

#include <cassert>
#include <iostream>

int main(int argc, char **argv) {
  const std::vector<std::uint8_t> add{0x89, 0xf8, 0x01, 0xf0, 0xc3};
  const auto result = caraxes::decompiler::decompile(add, 0x401000, "add");
  assert(result.code.find("return") != std::string::npos);
  assert(result.code.find("arg0") != std::string::npos);
  assert(result.code.find("arg1") != std::string::npos);
  assert(result.code.find("+") != std::string::npos);
  assert(result.code.find("arg2") == std::string::npos);

  const std::vector<std::uint8_t> sub{0x89, 0xf8, 0x29, 0xf0, 0xc3};
  const auto subtraction = caraxes::decompiler::decompile(sub, 0x401000, "sub");
  assert(subtraction.code.find("-") != std::string::npos);

  const std::vector<std::uint8_t> branch{
      0x85, 0xff, 0x74, 0x05, 0x89, 0xf8, 0xc3, 0x90, 0x90, 0x31, 0xc0, 0xc3};
  const auto recovered_branch =
      caraxes::decompiler::decompile(branch, 0x401000, "choose");
  assert(recovered_branch.code.find("goto loc_") != std::string::npos);
  assert(recovered_branch.code.find("arg0") != std::string::npos);

  const auto file = caraxes::elf::parse_file(argc > 1 ? argv[1] : "../hello");
  const auto *text = file.section(".text");
  assert(text != nullptr);
  const auto project = caraxes::decompiler::decompile_project(
      file, *text,
      caraxes::analysis::analyze(file.section_bytes(*text), text->address,
                                 file.header.entry));
  assert(project.code.find("Caraxes self-contained") != std::string::npos);
  assert(project.json.find("\"engine\":\"caraxes-native\"") !=
         std::string::npos);
  assert(!project.functions.empty());
  assert(!project.data.empty());
  std::cout << "decompiler tests passed\n";
}
