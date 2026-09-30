#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace caraxes::analysis {

struct Instruction {
  std::uint64_t address{};
  std::uint8_t opcode{};
  std::uint8_t size{};
  std::string mnemonic;
  std::uint64_t target{};
  bool is_branch{};
  bool is_call{};
  bool is_return{};
};

struct BasicBlock {
  std::uint64_t address{};
  std::vector<Instruction> instructions;
  std::vector<std::uint64_t> predecessors;
  std::vector<std::uint64_t> successors;
};
struct Function {
  std::uint64_t address{};
  std::uint64_t size{};
  std::string name;
  std::vector<BasicBlock> blocks;
  std::vector<std::uint64_t> callers;
  std::vector<std::uint64_t> callees;
};
struct CrossReference { std::uint64_t from{}; std::uint64_t to{}; std::string kind; };
struct IRValue { std::uint64_t address{}; std::string operation; std::vector<std::string> inputs; };
struct Analysis {
  std::vector<Function> functions;
  std::vector<CrossReference> xrefs;
  std::vector<IRValue> ir;
};

// A deliberately small, safe x86-64 analysis suitable for stripped binaries.
Analysis analyze(const std::vector<std::uint8_t> &text, std::uint64_t base,
                 std::uint64_t entry = 0);
std::string decompile(const Function &function);
std::string report(const Analysis &analysis);

} // namespace caraxes::analysis
