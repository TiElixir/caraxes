#include "disasm/disasm.hpp"

#include <capstone/capstone.h>

#include <stdexcept>

namespace caraxes::disasm {

std::string Instruction::text() const {
  return operands.empty() ? mnemonic : mnemonic + " " + operands;
}

std::vector<Instruction> disassemble(const std::vector<std::uint8_t> &bytes,
                                     std::uint64_t address) {
  csh handle = 0;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    throw std::runtime_error("could not initialize Capstone x86-64 disassembler");
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

  cs_insn *decoded = nullptr;
  const auto count = cs_disasm(handle, bytes.data(), bytes.size(), address, 0, &decoded);
  std::vector<Instruction> result;
  result.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    Instruction instruction;
    instruction.address = decoded[i].address;
    instruction.bytes.assign(decoded[i].bytes, decoded[i].bytes + decoded[i].size);
    instruction.id = decoded[i].id;
    instruction.mnemonic = decoded[i].mnemonic;
    instruction.operands = decoded[i].op_str;
    result.push_back(std::move(instruction));
  }
  cs_free(decoded, count);
  cs_close(&handle);
  return result;
}

std::vector<Instruction> X86_64InstructionDecoder::decode(
    const std::vector<std::uint8_t> &bytes, std::uint64_t address) const {
  return disassemble(bytes, address);
}

std::vector<Instruction> decode(const InstructionDecoder &decoder,
                                const std::vector<std::uint8_t> &bytes,
                                std::uint64_t address) {
  return decoder.decode(bytes, address);
}

std::vector<Instruction> disassemble_section(const elf::File &file,
                                              const std::string &section_name) {
  if (file.header.elf_class != elf::Class::Elf64 || file.header.machine != 62)
    throw std::runtime_error("disassembly requires an x86-64 ELF file");
  const auto *section = file.section(section_name);
  if (!section) throw std::runtime_error("ELF section not found: " + section_name);
  if ((section->flags & 0x4) == 0)
    throw std::runtime_error("ELF section is not executable: " + section_name);
  if (section->offset > file.bytes.size() || section->size > file.bytes.size() - section->offset)
    throw std::runtime_error("ELF section extends beyond file");
  std::vector<std::uint8_t> bytes(file.bytes.begin() + section->offset,
                                  file.bytes.begin() + section->offset + section->size);
  return disassemble(bytes, section->address);
}

} // namespace caraxes::disasm
