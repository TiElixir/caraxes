#include "decompiler/decompiler.hpp"

#include <capstone/capstone.h>
#include <map>
#include <sstream>
#include <stdexcept>

namespace caraxes::decompiler {
namespace {
std::string reg(csh h, unsigned r) { const char *n = cs_reg_name(h, r); return n ? n : "reg"; }
std::string operand(csh h, const cs_x86_op &o) {
  if (o.type == X86_OP_IMM) return std::to_string(o.imm);
  if (o.type == X86_OP_REG) return reg(h, o.reg);
  if (o.type == X86_OP_MEM) {
    std::ostringstream s; s << "mem_" << o.mem.disp;
    return s.str();
  }
  return "unknown";
}
std::string arg_name(const std::string &r) {
  if (r == "edi" || r == "rdi") return "arg0";
  if (r == "esi" || r == "rsi") return "arg1";
  if (r == "edx" || r == "rdx") return "arg2";
  if (r == "ecx" || r == "rcx") return "arg3";
  if (r == "r8d" || r == "r8") return "arg4";
  if (r == "r9d" || r == "r9") return "arg5";
  return r;
}
}

Result decompile(const std::vector<std::uint8_t> &bytes, std::uint64_t address,
                 const std::string &name) {
  csh h{}; if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) throw std::runtime_error("Capstone initialization failed");
  cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
  cs_insn *insns = nullptr; const auto count = cs_disasm(h, bytes.data(), bytes.size(), address, 0, &insns);
  std::map<std::string, std::string> values;
  std::ostringstream body; body << "int " << name << "(";
  for (int i=0;i<6;++i) { if (i) body << ", "; body << "int arg" << i; } body << ") {\n";
  std::string compare;
  for (std::size_t i=0;i<count;++i) {
    auto &x = insns[i]; const auto &detail = x.detail->x86;
    std::vector<std::string> ops; for (uint8_t j=0;j<detail.op_count;++j) ops.push_back(operand(h, detail.operands[j]));
    if (std::string(x.mnemonic) == "push" || std::string(x.mnemonic) == "pop" || std::string(x.mnemonic) == "leave" || std::string(x.mnemonic) == "nop") continue;
    if (std::string(x.mnemonic) == "cmp" && ops.size() == 2) { compare = arg_name(ops[0]) + " == " + arg_name(ops[1]); continue; }
    if (std::string(x.mnemonic) == "mov" && ops.size() == 2) { values[ops[0]] = arg_name(values.contains(ops[1]) ? values[ops[1]] : ops[1]); continue; }
    if ((std::string(x.mnemonic) == "add" || std::string(x.mnemonic) == "sub" || std::string(x.mnemonic) == "imul") && ops.size() == 2) {
      const auto lhs = values.contains(ops[0]) ? values[ops[0]] : arg_name(ops[0]); const auto rhs = values.contains(ops[1]) ? values[ops[1]] : arg_name(ops[1]); const char *op = std::string(x.mnemonic)=="add"?"+":std::string(x.mnemonic)=="sub"?"-":"*"; values[ops[0]] = "(" + lhs + " " + op + " " + rhs + ")"; continue;
    }
    if (std::string(x.mnemonic) == "ret") { auto it = values.find("eax"); body << "    return " << (it == values.end() ? "eax" : it->second) << ";\n"; continue; }
    if (std::string(x.mnemonic).rfind("j", 0) == 0) { body << "    /* control flow: " << x.mnemonic << " " << x.op_str << " */\n"; continue; }
    body << "    /* unsupported at 0x" << std::hex << x.address << ": " << x.mnemonic << " " << x.op_str << " */\n";
  }
  body << "}\n"; cs_free(insns, count); cs_close(&h); return {name, address, body.str()};
}
} // namespace caraxes::decompiler
