#include "decompiler/decompiler.hpp"

#include <cassert>
#include <iostream>

int main() {
  const std::vector<std::uint8_t> add{0x89, 0xf8, 0x01, 0xf0, 0xc3};
  const auto result = caraxes::decompiler::decompile(add, 0x401000, "add");
  assert(result.code.find("return") != std::string::npos);
  assert(result.code.find("arg0") != std::string::npos);
  assert(result.code.find("arg1") != std::string::npos);
  assert(result.code.find("+") != std::string::npos);

  const std::vector<std::uint8_t> sub{0x89, 0xf8, 0x29, 0xf0, 0xc3};
  const auto subtraction = caraxes::decompiler::decompile(sub, 0x401000, "sub");
  assert(subtraction.code.find("-") != std::string::npos);
  std::cout << "decompiler tests passed\n";
}
