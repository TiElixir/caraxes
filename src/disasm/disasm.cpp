#include "disasm/disasm.hpp"

#include <capstone/capstone.h>

#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace caraxes::disasm {
namespace {

class DecoderHandle {
public:
  DecoderHandle() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
      throw std::runtime_error("could not initialize Capstone x86-64 disassembler");
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
      cs_close(&handle);
      throw std::runtime_error("could not enable Capstone instruction details");
    }
  }
  ~DecoderHandle() { cs_close(&handle); }
  csh handle{};
};

std::string register_name(csh handle, unsigned int register_id) {
  if (register_id == 0)
    return {};
  const char *name = cs_reg_name(handle, register_id);
  return name ? name : "reg";
}

Operand make_operand(csh handle, const cs_x86_op &source) {
  Operand result;
  result.size = source.size;
  result.access = source.access;
  switch (source.type) {
  case X86_OP_REG:
    result.kind = OperandKind::Register;
    result.register_name = register_name(handle, source.reg);
    break;
  case X86_OP_IMM:
    result.kind = OperandKind::Immediate;
    result.immediate = source.imm;
    break;
  case X86_OP_MEM:
    result.kind = OperandKind::Memory;
    result.memory.segment = register_name(handle, source.mem.segment);
    result.memory.base = register_name(handle, source.mem.base);
    result.memory.index = register_name(handle, source.mem.index);
    result.memory.scale = source.mem.scale;
    result.memory.displacement = source.mem.disp;
    break;
  default:
    result.kind = OperandKind::Invalid;
    break;
  }
  return result;
}

bool is_unconditional_jump(const std::string &mnemonic) {
  return mnemonic == "jmp" || mnemonic == "ljmp";
}

void classify(csh handle, cs_insn &decoded, Instruction &result) {
  const bool call = cs_insn_group(handle, &decoded, CS_GRP_CALL) != 0;
  const bool jump = cs_insn_group(handle, &decoded, CS_GRP_JUMP) != 0;
  const bool ret = cs_insn_group(handle, &decoded, CS_GRP_RET) != 0;

  result.is_call = call;
  result.is_return = ret;
  result.is_branch = call || jump;
  result.is_conditional = jump && !is_unconditional_jump(result.mnemonic);
  result.is_terminal = ret || (jump && !result.is_conditional) ||
                       result.mnemonic == "hlt" || result.mnemonic == "ud2" ||
                       result.mnemonic == "int3";

  if (!decoded.detail)
    return;

  const auto &x86 = decoded.detail->x86;
  result.operand_details.reserve(x86.op_count);
  for (std::uint8_t i = 0; i < x86.op_count; ++i)
    result.operand_details.push_back(make_operand(handle, x86.operands[i]));

  // A direct branch/call has an immediate operand. Capstone resolves x86
  // relative immediates to their absolute runtime address for this field.
  if (call || jump) {
    for (const auto &operand : result.operand_details) {
      if (operand.kind == OperandKind::Immediate) {
        result.has_target = true;
        result.target = static_cast<std::uint64_t>(operand.immediate);
        break;
      }
    }
    result.is_indirect = !result.has_target;
  }
}

Instruction invalid_instruction(const std::vector<std::uint8_t> &bytes,
                                std::size_t offset, std::uint64_t address) {
  Instruction result;
  result.address = address;
  result.size = 1;
  result.valid = false;
  result.bytes.push_back(bytes[offset]);
  result.mnemonic = "db";
  result.operands = "0x";
  const char *digits = "0123456789abcdef";
  result.operands.push_back(digits[(bytes[offset] >> 4) & 0xf]);
  result.operands.push_back(digits[bytes[offset] & 0xf]);
  return result;
}

} // namespace

std::string Instruction::text() const {
  return operands.empty() ? mnemonic : mnemonic + " " + operands;
}

std::vector<Instruction> disassemble(const std::vector<std::uint8_t> &bytes,
                                     std::uint64_t address) {
  if (bytes.size() > std::numeric_limits<std::uint64_t>::max() - address)
    throw std::runtime_error("disassembly address range overflows");
  DecoderHandle decoder;
  const auto handle = decoder.handle;
  const auto free_instruction = [](cs_insn *instruction) { cs_free(instruction, 1); };
  std::unique_ptr<cs_insn, decltype(free_instruction)> decoded(cs_malloc(handle),
                                                             free_instruction);
  if (!decoded)
    throw std::runtime_error("could not allocate Capstone instruction record");

  std::vector<Instruction> result;
  result.reserve(bytes.size() / 3);

  // Decode one instruction at a time so an invalid byte does not hide all
  // subsequent code. This also gives the analysis layer an explicit data
  // record instead of silently losing bytes after a Capstone decode failure.
  for (std::size_t offset = 0; offset < bytes.size();) {
    const auto *cursor = bytes.data() + offset;
    auto remaining = bytes.size() - offset;
    auto instruction_address = address + offset;
    const auto before = remaining;
    if (!cs_disasm_iter(handle, &cursor, &remaining, &instruction_address,
                        decoded.get()) ||
        decoded->size == 0 || decoded->size > before) {
      result.push_back(invalid_instruction(bytes, offset, address + offset));
      ++offset;
      continue;
    }

    Instruction instruction;
    instruction.address = decoded->address;
    instruction.size = decoded->size;
    instruction.bytes.assign(decoded->bytes, decoded->bytes + decoded->size);
    instruction.id = decoded->id;
    instruction.mnemonic = decoded->mnemonic;
    instruction.operands = decoded->op_str;
    classify(handle, *decoded, instruction);
    result.push_back(std::move(instruction));
    offset += decoded->size;
  }
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
  if (file.header.elf_class != elf::Class::Elf64 || file.header.machine != 62 ||
      file.header.endian != elf::Endian::Little)
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
