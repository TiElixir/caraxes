#pragma once

#include "loader/elf/elf.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace caraxes::disasm {

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
