#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace caraxes::decompiler {

struct Options {
  // Names recovered from ELF symbols or a prior analysis pass. Calls whose
  // targets are not present here receive a stable sub_<address> name.
  std::map<std::uint64_t, std::string> function_names;
  bool include_address_comments{true};
};

struct Result {
  std::string name;
  std::uint64_t address{};
  std::string code;
};

Result decompile(const std::vector<std::uint8_t> &bytes, std::uint64_t address,
                 const std::string &name = "sub",
                 const Options &options = {});

} // namespace caraxes::decompiler
