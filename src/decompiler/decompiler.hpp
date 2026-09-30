#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace caraxes::decompiler {

struct Result {
  std::string name;
  std::uint64_t address{};
  std::string code;
};

Result decompile(const std::vector<std::uint8_t> &bytes, std::uint64_t address,
                 const std::string &name = "sub");

} // namespace caraxes::decompiler
