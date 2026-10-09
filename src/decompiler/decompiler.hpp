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
  std::map<std::uint64_t, std::size_t> function_argument_counts;
  std::map<std::uint64_t, std::string> data_names;
  std::map<std::string, std::string> data_values;
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

std::size_t infer_argument_count(const std::vector<std::uint8_t> &bytes,
                                 std::uint64_t address);

} // namespace caraxes::decompiler
