#pragma once

#include "loader/elf/elf.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace caraxes::disasm {

// Capstone's C structs are deliberately kept out of the public analysis API.
// These small value types contain the instruction facts needed by the CFG and
// decompiler passes while keeping the rest of the project independent of a
// particular Capstone version.
enum class OperandKind : std::uint8_t {
  Invalid,
  Register,
  Immediate,
  Memory,
  FloatingPoint,
};

struct MemoryOperand {
  std::string segment;
  std::string base;
  std::string index;
  std::int32_t scale{1};
  std::int64_t displacement{};
};

struct Operand {
  OperandKind kind{OperandKind::Invalid};
  std::uint8_t size{};
  std::uint8_t access{};
  std::string register_name;
  std::int64_t immediate{};
  MemoryOperand memory;
};

class InstructionDecoder {
public:
  virtual ~InstructionDecoder() = default;
  virtual std::vector<struct Instruction> decode(
      const std::vector<std::uint8_t> &bytes, std::uint64_t address) const = 0;
};

class X86_64InstructionDecoder final : public InstructionDecoder {
public:
  std::vector<struct Instruction> decode(
      const std::vector<std::uint8_t> &bytes, std::uint64_t address) const override;
};

struct Instruction {
  std::uint64_t address{};
  std::vector<std::uint8_t> bytes;
  std::uint32_t id{};
  std::string mnemonic;
  std::string operands;

  std::string text() const;

  // Flow and operand metadata used by higher-level static analysis.
  std::uint8_t size{};
  std::vector<Operand> operand_details;
  bool valid{true};
  bool has_target{};
  std::uint64_t target{};
  bool is_branch{};
  bool is_conditional{};
  bool is_call{};
  bool is_return{};
  bool is_terminal{};
  bool is_indirect{};
};

// Disassemble bytes as x86-64 instructions beginning at address.
std::vector<Instruction> disassemble(const std::vector<std::uint8_t> &bytes,
                                     std::uint64_t address = 0);

std::vector<Instruction> decode(const InstructionDecoder &decoder,
                                const std::vector<std::uint8_t> &bytes,
                                std::uint64_t address = 0);

// Disassemble an ELF section (by default, the executable .text section).
std::vector<Instruction> disassemble_section(const elf::File &file,
                                              const std::string &section = ".text");

} // namespace caraxes::disasm
