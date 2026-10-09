#include "analysis/analysis.hpp"
#include <cassert>
#include <iostream>

int main() {
  const std::vector<std::uint8_t> code{0xe8, 1, 0, 0, 0, 0xc3, 0x90, 0xc3};
  const auto a = caraxes::analysis::analyze(code, 0x1000);
  assert(a.functions.size() == 2); assert(a.xrefs.size() == 1); assert(a.functions[0].blocks[0].instructions.back().is_return);
  assert(a.functions[0].size > 0); assert(!a.functions[0].callees.empty());
  assert(caraxes::analysis::report(a).find("functions: 2") != std::string::npos);

  const std::vector<std::uint8_t> branch{
      0x85, 0xff,             // test edi, edi
      0x74, 0x05,             // je 0x2009
      0x89, 0xf8, 0xc3,       // mov eax, edi; ret
      0x90, 0x90,             // padding
      0x31, 0xc0, 0xc3        // xor eax, eax; ret
  };
  const auto branched = caraxes::analysis::analyze(branch, 0x2000);
  assert(!branched.functions.empty());
  assert(branched.functions.front().blocks.size() >= 2);
  assert(!branched.functions.front().blocks.front().successors.empty());
  std::cout << "analysis tests passed\n";
}
