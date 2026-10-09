#pragma once

#include "analysis/analysis.hpp"
#include "decompiler/decompiler.hpp"
#include "loader/elf/elf.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace caraxes::decompiler {

struct ProjectOptions {
  std::map<std::uint64_t, std::string> function_names;
  std::map<std::uint64_t, std::string> data_names;
  bool include_address_comments{true};
};

struct RecoveredFunction {
  std::string name;
  std::uint64_t address{};
  std::uint64_t size{};
  std::size_t blocks{};
  std::size_t callers{};
  std::size_t callees{};
  std::string code;
};

struct RecoveredData {
  std::uint64_t address{};
  std::string name;
  std::string section;
  std::string value;
  bool string_literal{};
};

struct ProjectResult {
  std::string code;
  std::string json;
  std::vector<RecoveredFunction> functions;
  std::vector<RecoveredData> data;
};

// Render a complete self-contained report from Caraxes' own ELF, CFG, xref,
// and expression-recovery records. No external decompiler is invoked.
ProjectResult decompile_project(
    const elf::File &file, const elf::SectionHeader &executable_section,
    const analysis::Analysis &analysis,
    const ProjectOptions &options = {});

} // namespace caraxes::decompiler
