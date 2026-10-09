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

  std::vector<std::uint8_t> bytes;
  std::string operands;
  bool valid{true};
  bool has_target{};
  bool is_conditional{};
  bool is_terminal{};
  bool is_indirect{};
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
struct FunctionSeed {
  std::uint64_t address{};
  std::uint64_t size{};
  std::string name;
};
struct Analysis {
  std::vector<Function> functions;
  std::vector<CrossReference> xrefs;
  std::vector<IRValue> ir;
};

// Analyze an x86-64 executable region. Seeds normally come from ELF function
// symbols; direct call targets and the entry point are discovered automatically
// so stripped binaries still receive useful function boundaries.
Analysis analyze(const std::vector<std::uint8_t> &text, std::uint64_t base,
                 std::uint64_t entry = 0,
                 const std::vector<FunctionSeed> &seeds = {});
std::string decompile(const Function &function);
std::string report(const Analysis &analysis);

} // namespace caraxes::analysis
