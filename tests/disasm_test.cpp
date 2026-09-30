#include "disasm/disasm.hpp"

#include <cassert>
#include <iostream>

int main() {
  const std::vector<std::uint8_t> bytes{0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3};
  const auto instructions = caraxes::disasm::disassemble(bytes, 0x401000);
  assert(instructions.size() == 4);
  assert(instructions[0].address == 0x401000);
  assert(instructions[0].mnemonic == "push");
  assert(instructions[1].mnemonic == "mov");
  assert(instructions.back().mnemonic == "ret");
  assert(instructions.back().text() == "ret");

  caraxes::disasm::X86_64InstructionDecoder decoder;
  const auto through_interface = caraxes::disasm::decode(decoder, bytes, 0x401000);
  assert(through_interface.size() == instructions.size());

  const auto file = caraxes::elf::parse_file("../hello");
  const auto text = caraxes::disasm::disassemble_section(file);
  assert(!text.empty());
  std::cout << "Disassembler tests passed\n";
}
