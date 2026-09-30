#include "analysis/analysis.hpp"
#include <cassert>
#include <iostream>

int main() {
  const std::vector<std::uint8_t> code{0xe8, 1, 0, 0, 0, 0xc3, 0x90, 0xc3};
  const auto a = caraxes::analysis::analyze(code, 0x1000);
  assert(a.functions.size() == 2); assert(a.xrefs.size() == 1); assert(a.functions[0].blocks[0].instructions.back().is_return);
  assert(a.functions[0].size > 0); assert(!a.functions[0].callees.empty());
  assert(caraxes::analysis::report(a).find("functions: 2") != std::string::npos);
  std::cout << "analysis tests passed\n";
}
