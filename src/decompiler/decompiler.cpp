#include "decompiler/decompiler.hpp"

#include "disasm/disasm.hpp"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace caraxes::decompiler {
namespace {

using RegisterValues = std::map<std::string, std::string>;
using ArgumentRegisters = std::set<std::string>;

const std::vector<std::string> &argument_registers() {
  static const std::vector<std::string> registers{
      "rdi", "rsi", "rdx", "rcx", "r8", "r9"};
  return registers;
}

std::string canonical_register(const std::string &name) {
  if (name == "rax" || name == "eax" || name == "ax" || name == "al" ||
      name == "ah")
    return "rax";
  if (name == "rbx" || name == "ebx" || name == "bx" || name == "bl" ||
      name == "bh")
    return "rbx";
  if (name == "rcx" || name == "ecx" || name == "cx" || name == "cl" ||
      name == "ch")
    return "rcx";
  if (name == "rdx" || name == "edx" || name == "dx" || name == "dl" ||
      name == "dh")
    return "rdx";
  if (name == "rsi" || name == "esi" || name == "si" || name == "sil")
    return "rsi";
  if (name == "rdi" || name == "edi" || name == "di" || name == "dil")
    return "rdi";
  if (name == "rbp" || name == "ebp" || name == "bp" || name == "bpl")
    return "rbp";
  if (name == "rsp" || name == "esp" || name == "sp" || name == "spl")
    return "rsp";
  if (name == "rip" || name == "eip")
    return "rip";
  if (name.size() >= 2 && name[0] == 'r' &&
      std::isdigit(static_cast<unsigned char>(name[1]))) {
    std::size_t end = 1;
    while (end < name.size() &&
           std::isdigit(static_cast<unsigned char>(name[end])))
      ++end;
    if (end == name.size() ||
        (end + 1 == name.size() &&
         (name[end] == 'b' || name[end] == 'w' || name[end] == 'd')))
      return name.substr(0, end);
  }
  return name;
}

int argument_index(const std::string &register_name) {
  const auto canonical = canonical_register(register_name);
  const auto &registers = argument_registers();
  const auto it = std::find(registers.begin(), registers.end(), canonical);
  return it == registers.end()
             ? -1
             : static_cast<int>(std::distance(registers.begin(), it));
}

std::string sanitize_identifier(const std::string &value,
                                const std::string &fallback) {
  std::string result;
  result.reserve(value.size());
  for (const auto character : value) {
    const auto unsigned_character =
        static_cast<unsigned char>(character);
    if (std::isalnum(unsigned_character) || character == '_')
      result.push_back(character);
    else
      result.push_back('_');
  }
  if (result.empty())
    result = fallback;
  if (std::isdigit(static_cast<unsigned char>(result.front())))
    result.insert(result.begin(), '_');
  return result;
}

std::string address_name(std::uint64_t address) {
  std::ostringstream stream;
  stream << "0x" << std::hex << address;
  return stream.str();
}

std::string subroutine_name(std::uint64_t address,
                            const Options &options) {
  const auto it = options.function_names.find(address);
  if (it != options.function_names.end())
    return sanitize_identifier(it->second, "sub_" + address_name(address));
  std::ostringstream stream;
  stream << "sub_" << std::hex << address;
  return stream.str();
}

std::string immediate_expression(std::int64_t immediate) {
  if (immediate >= -4096 && immediate <= 4096)
    return std::to_string(immediate);
  std::ostringstream stream;
  if (immediate < 0) {
    const auto magnitude = 0 - static_cast<std::uint64_t>(immediate);
    stream << "-0x" << std::hex << magnitude;
  } else {
    stream << "0x" << std::hex << static_cast<std::uint64_t>(immediate);
  }
  return stream.str();
}

std::string stack_name(const std::string &base, std::int64_t displacement) {
  std::ostringstream stream;
  if (base == "rbp") {
    if (displacement > 0 && displacement >= 16 && displacement % 8 == 0) {
      stream << "arg" << (6 + (displacement - 16) / 8);
      return stream.str();
    }
    stream << (displacement < 0 ? "local_" : "stack_");
  } else {
    stream << "stack_";
  }
  const auto magnitude = displacement < 0
                             ? 0 - static_cast<std::uint64_t>(displacement)
                             : static_cast<std::uint64_t>(displacement);
  stream << "0x" << std::hex << magnitude;
  return stream.str();
}

std::string memory_expression(const disasm::Operand &operand,
                              std::uint64_t address, std::uint8_t size,
                              const RegisterValues &values,
                              const ArgumentRegisters &input_arguments,
                              const std::map<std::uint64_t, std::string> &data_names) {
  const auto &memory = operand.memory;
  if (memory.base == "rbp" || memory.base == "rsp") {
    if (memory.index.empty() && memory.segment.empty())
      return stack_name(memory.base, memory.displacement);
  }

  if (memory.base == "rip" && memory.index.empty()) {
    const auto absolute = static_cast<std::uint64_t>(
        static_cast<std::int64_t>(address + size) + memory.displacement);
    const auto named = data_names.find(absolute);
    std::ostringstream stream;
    if (named != data_names.end())
      stream << named->second;
    else
      stream << "global_" << std::hex << absolute;
    return stream.str();
  }

  std::ostringstream stream;
  stream << "memory[";
  if (!memory.base.empty()) {
    const auto canonical = canonical_register(memory.base);
    const auto value = values.find(canonical);
    if (value != values.end())
      stream << value->second;
    else if (const auto index = argument_index(canonical);
             index >= 0 && input_arguments.contains(canonical))
      stream << "arg" << index;
    else
      stream << canonical;
  } else {
    stream << immediate_expression(memory.displacement);
  }
  if (!memory.index.empty()) {
    stream << " + ";
    const auto canonical = canonical_register(memory.index);
    const auto value = values.find(canonical);
    if (value != values.end())
      stream << value->second;
    else
      stream << canonical;
    if (memory.scale != 1)
      stream << " * " << memory.scale;
  }
  if (memory.displacement != 0 && !memory.base.empty()) {
    const auto magnitude = memory.displacement < 0
                               ? 0 - static_cast<std::uint64_t>(memory.displacement)
                               : static_cast<std::uint64_t>(memory.displacement);
    stream << (memory.displacement < 0 ? " - 0x" : " + 0x") << std::hex
           << magnitude;
  }
  stream << "]";
  return stream.str();
}

std::string register_expression(const disasm::Operand &operand,
                                const RegisterValues &values,
                                const ArgumentRegisters &input_arguments) {
  const auto canonical = canonical_register(operand.register_name);
  const auto value = values.find(canonical);
  if (value != values.end())
    return value->second;
  const auto index = argument_index(canonical);
  if (index >= 0 && input_arguments.contains(canonical)) {
    std::ostringstream stream;
    stream << "arg" << index;
    return stream.str();
  }
  return canonical;
}

std::string operand_expression(const disasm::Operand &operand,
                               std::uint64_t address, std::uint8_t size,
                               const RegisterValues &values,
                               const ArgumentRegisters &input_arguments,
                               const std::map<std::uint64_t, std::string> &data_names) {
  switch (operand.kind) {
  case disasm::OperandKind::Register:
    return register_expression(operand, values, input_arguments);
  case disasm::OperandKind::Immediate:
    return immediate_expression(operand.immediate);
  case disasm::OperandKind::Memory:
    return memory_expression(operand, address, size, values,
                             input_arguments, data_names);
  case disasm::OperandKind::FloatingPoint:
    return "floating_point";
  default:
    return "unknown_operand";
  }
}

std::string operand_lvalue(const disasm::Operand &operand,
                           std::uint64_t address, std::uint8_t size,
                           const RegisterValues &values,
                           const ArgumentRegisters &input_arguments,
                           const std::map<std::uint64_t, std::string> &data_names) {
  if (operand.kind == disasm::OperandKind::Register)
    return canonical_register(operand.register_name);
  return operand_expression(operand, address, size, values, input_arguments,
                            data_names);
}

bool is_data_expression(const std::string &value,
                        const std::map<std::uint64_t, std::string> &data_names) {
  return std::any_of(data_names.begin(), data_names.end(),
                     [&value](const auto &entry) { return entry.second == value; });
}

std::string assignment_expression(
    const std::string &value,
    const std::map<std::uint64_t, std::string> &data_names) {
  if (is_data_expression(value, data_names) ||
      (value.size() > 0 && value.front() == '&'))
    return "((uintptr_t)(" + value + "))";
  return value;
}

bool is_read_operand(const disasm::Instruction &instruction, std::size_t index,
                     const disasm::Operand &operand) {
  if (operand.kind == disasm::OperandKind::Memory)
    return !operand.memory.base.empty() || !operand.memory.index.empty() ||
           (operand.access & CS_AC_READ) != 0;
  if ((operand.access & CS_AC_READ) != 0)
    return true;
  if (operand.access != 0)
    return false;
  const auto &mnemonic = instruction.mnemonic;
  const bool destination_first =
      (mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "lea" ||
       mnemonic == "movzx" || mnemonic == "movsx" || mnemonic == "movsxd") &&
      index == 0;
  return !destination_first;
}

bool is_write_operand(const disasm::Instruction &instruction,
                      std::size_t index, const disasm::Operand &operand) {
  if (operand.kind != disasm::OperandKind::Register)
    return false;
  if ((operand.access & CS_AC_WRITE) != 0)
    return true;
  if (operand.access != 0)
    return false;
  const auto &mnemonic = instruction.mnemonic;
  return index == 0 &&
         (mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "lea" ||
          mnemonic == "movzx" || mnemonic == "movsx" ||
          mnemonic == "movsxd" || mnemonic == "pop" || mnemonic == "sete" ||
          mnemonic == "setne");
}

ArgumentRegisters infer_input_arguments(
    const std::vector<disasm::Instruction> &instructions) {
  ArgumentRegisters result;
  std::set<std::string> defined_registers;
  for (const auto &instruction : instructions) {
    const bool zero_idiom =
        (instruction.mnemonic == "xor" || instruction.mnemonic == "sub") &&
        instruction.operand_details.size() >= 2 &&
        instruction.operand_details[0].kind == disasm::OperandKind::Register &&
        instruction.operand_details[1].kind == disasm::OperandKind::Register &&
        canonical_register(instruction.operand_details[0].register_name) ==
            canonical_register(instruction.operand_details[1].register_name);

    for (std::size_t i = 0; i < instruction.operand_details.size(); ++i) {
      const auto &operand = instruction.operand_details[i];
      if (operand.kind == disasm::OperandKind::Register &&
          is_read_operand(instruction, i, operand) && !zero_idiom) {
        const auto canonical = canonical_register(operand.register_name);
        if (argument_index(canonical) >= 0 &&
            !defined_registers.contains(canonical))
          result.insert(canonical);
      }
      if (operand.kind == disasm::OperandKind::Memory) {
        for (const auto &register_name :
             {operand.memory.base, operand.memory.index}) {
          if (register_name.empty())
            continue;
          const auto canonical = canonical_register(register_name);
          if (argument_index(canonical) >= 0 &&
              !defined_registers.contains(canonical))
            result.insert(canonical);
        }
      }
      if (is_write_operand(instruction, i, operand))
        defined_registers.insert(canonical_register(operand.register_name));
    }
    if (instruction.is_call)
      defined_registers.insert("rax");
  }
  return result;
}

std::string condition_for(const std::string &mnemonic, const std::string &left,
                          const std::string &right) {
  const std::string fallback = "0";
  if (left.empty())
    return fallback;
  const auto rhs = right.empty() ? "0" : right;
  if (left == rhs) {
    if (mnemonic == "je" || mnemonic == "jz" || mnemonic == "jge" ||
        mnemonic == "jle" || mnemonic == "jae" || mnemonic == "jbe")
      return "1";
    if (mnemonic == "jne" || mnemonic == "jnz" || mnemonic == "jg" ||
        mnemonic == "jl" || mnemonic == "ja" || mnemonic == "jb")
      return "0";
  }
  if (mnemonic == "je" || mnemonic == "jz")
    return "(" + left + " == " + rhs + ")";
  if (mnemonic == "jne" || mnemonic == "jnz")
    return "(" + left + " != " + rhs + ")";
  if (mnemonic == "ja" || mnemonic == "jnbe")
    return "((unsigned long)" + left + " > (unsigned long)" + rhs + ")";
  if (mnemonic == "jae" || mnemonic == "jnb" || mnemonic == "jnc")
    return "((unsigned long)" + left + " >= (unsigned long)" + rhs + ")";
  if (mnemonic == "jb" || mnemonic == "jnae" || mnemonic == "jc")
    return "((unsigned long)" + left + " < (unsigned long)" + rhs + ")";
  if (mnemonic == "jbe" || mnemonic == "jna")
    return "((unsigned long)" + left + " <= (unsigned long)" + rhs + ")";
  if (mnemonic == "jg" || mnemonic == "jnle")
    return "(" + left + " > " + rhs + ")";
  if (mnemonic == "jge" || mnemonic == "jnl")
    return "(" + left + " >= " + rhs + ")";
  if (mnemonic == "jl" || mnemonic == "jnge")
    return "(" + left + " < " + rhs + ")";
  if (mnemonic == "jle" || mnemonic == "jng")
    return "(" + left + " <= " + rhs + ")";
  if (mnemonic == "js")
    return "((long)" + left + " < 0)";
  if (mnemonic == "jns")
    return "((long)" + left + " >= 0)";
  if (mnemonic == "jo" || mnemonic == "jp" || mnemonic == "jpe")
    return "0";
  if (mnemonic == "jno" || mnemonic == "jnp" || mnemonic == "jpo")
    return "0";
  return fallback;
}

std::string target_label(std::uint64_t target) {
  std::ostringstream stream;
  stream << "loc_" << std::hex << target;
  return stream.str();
}

std::string call_arguments(const RegisterValues &values,
                           const ArgumentRegisters &input_arguments,
                           std::size_t maximum_arguments = 6) {
  int last = -1;
  for (std::size_t i = 0;
       i < argument_registers().size() && i < maximum_arguments; ++i) {
    const auto &register_name = argument_registers()[i];
    if (values.contains(register_name) || input_arguments.contains(register_name))
      last = static_cast<int>(i);
  }
  std::ostringstream stream;
  for (int i = 0; i <= last; ++i) {
    if (i != 0)
      stream << ", ";
    const auto &register_name = argument_registers()[static_cast<std::size_t>(i)];
    const auto value = values.find(register_name);
    if (value != values.end())
      stream << value->second;
    else
      stream << "arg" << i;
  }
  return stream.str();
}

std::size_t format_argument_count(const std::string &format) {
  std::size_t count = 0;
  for (std::size_t i = 0; i + 1 < format.size(); ++i) {
    if (format[i] != '%')
      continue;
    if (format[i + 1] == '%') {
      ++i;
      continue;
    }
    ++count;
  }
  return count;
}

void assign_register(const disasm::Operand &destination,
                     const std::string &value, RegisterValues &values) {
  if (destination.kind == disasm::OperandKind::Register)
    values[canonical_register(destination.register_name)] = value;
}

} // namespace

Result decompile(const std::vector<std::uint8_t> &bytes, std::uint64_t address,
                 const std::string &name, const Options &options) {
  const auto instructions = disasm::disassemble(bytes, address);
  const auto input_arguments = infer_input_arguments(instructions);

  std::set<std::uint64_t> labels;
  for (const auto &instruction : instructions) {
    if (instruction.is_branch && !instruction.is_call &&
        instruction.has_target && instruction.target >= address &&
        instruction.target - address < bytes.size())
      labels.insert(instruction.target);
  }

  RegisterValues values;
  std::string compare_left;
  std::string compare_right;
  bool have_comparison = false;
  std::ostringstream body;
  const auto safe_name = sanitize_identifier(name, "sub");
  body << "int " << safe_name << "(";
  int highest_argument = -1;
  for (const auto &register_name : input_arguments)
    highest_argument = std::max(highest_argument, argument_index(register_name));
  if (highest_argument < 0) {
    // Old-style empty parameter lists keep the recovered listing callable
    // when a compiler-generated thunk passes through an unknown argument set.
    body << "";
  } else {
    for (int i = 0; i <= highest_argument; ++i) {
      if (i != 0)
        body << ", ";
      body << "int arg" << i << " __attribute__((unused))";
    }
  }
  body << ") {\n"
       << "    uintptr_t rax __attribute__((unused)) = 0, rbx __attribute__((unused)) = 0, "
       << "rcx __attribute__((unused)) = 0, rdx __attribute__((unused)) = 0, "
       << "rsi __attribute__((unused)) = 0, rdi __attribute__((unused)) = 0, "
       << "rbp __attribute__((unused)) = 0, rsp __attribute__((unused)) = 0, "
       << "r8 __attribute__((unused)) = 0, r9 __attribute__((unused)) = 0;\n";
  std::set<std::string> locals;
  for (const auto &instruction : instructions) {
    for (const auto &operand : instruction.operand_details) {
      if (operand.kind == disasm::OperandKind::Memory &&
          (operand.memory.base == "rbp" || operand.memory.base == "rsp"))
        locals.insert(stack_name(operand.memory.base, operand.memory.displacement));
    }
  }
  for (const auto &local : locals)
    body << "    int " << local << " __attribute__((unused)) = 0;\n";
  if (!locals.empty())
    body << '\n';

  bool emitted_return = false;
  for (const auto &instruction : instructions) {
    if (labels.contains(instruction.address))
      body << "  " << target_label(instruction.address) << ":\n";
    if (options.include_address_comments) {
      body << "    /* " << address_name(instruction.address) << ": "
           << instruction.text() << " */\n";
    }

    const auto &mnemonic = instruction.mnemonic;
    const auto &operands = instruction.operand_details;
    auto expression = [&](const disasm::Operand &operand) {
      return operand_expression(operand, instruction.address, instruction.size,
                                values, input_arguments, options.data_names);
    };
    auto lvalue = [&](const disasm::Operand &operand) {
      return operand_lvalue(operand, instruction.address, instruction.size,
                            values, input_arguments, options.data_names);
    };

    if (!instruction.valid) {
      body << "    /* undecodable byte preserved */\n";
      continue;
    }
    if (mnemonic == "nop" || mnemonic == "endbr64" || mnemonic == "push" ||
        mnemonic == "pop" || mnemonic == "leave") {
      continue;
    }

    if (mnemonic == "cmp" && operands.size() >= 2) {
      compare_left = expression(operands[0]);
      compare_right = expression(operands[1]);
      have_comparison = true;
      continue;
    }
    if (mnemonic == "test" && operands.size() >= 2) {
      compare_left = expression(operands[0]);
      compare_right = expression(operands[1]);
      if (compare_left == compare_right)
        compare_right = "0";
      have_comparison = true;
      continue;
    }

    if (!mnemonic.empty() && mnemonic[0] == 'j' && mnemonic != "jmp" &&
        instruction.is_conditional) {
      const auto condition = have_comparison
                                 ? condition_for(mnemonic, compare_left,
                                                 compare_right)
                                 : condition_for(mnemonic, {}, {});
      if (instruction.has_target)
        if (labels.contains(instruction.target))
          body << "    if (" << condition << ") goto "
               << target_label(instruction.target) << ";\n";
        else
          body << "    /* conditional branch to external address "
               << address_name(instruction.target) << " */\n";
      else
        body << "    /* conditional indirect branch */\n";
      have_comparison = false;
      continue;
    }
    if (mnemonic == "jmp") {
      if (instruction.has_target && labels.contains(instruction.target))
        body << "    goto " << target_label(instruction.target) << ";\n";
      else
        body << "    /* jump to external or indirect target */\n";
      continue;
    }

    if (instruction.is_call) {
      std::string call;
      std::size_t argument_limit = argument_registers().size();
      if (instruction.has_target) {
        const auto callee = subroutine_name(instruction.target, options);
        if (callee == "printf" || callee == "__isoc99_scanf") {
          const auto format = options.data_values.find(
              values.contains("rdi") ? values.at("rdi") : std::string{});
          argument_limit = format == options.data_values.end()
                               ? 2
                               : 1 + format_argument_count(format->second);
        } else if (callee == "puts" || callee == "putchar")
          argument_limit = 1;
        else if (callee == "fprintf" || callee == "sprintf")
          argument_limit = 3;
        else if (callee == "snprintf")
          argument_limit = 4;
        else if (const auto count = options.function_argument_counts.find(
                     instruction.target);
                 count != options.function_argument_counts.end())
          argument_limit = count->second;
        call = callee + "(" +
               call_arguments(values, input_arguments, argument_limit) + ")";
      } else if (!operands.empty()) {
        call = "call_indirect(" + expression(operands.front()) + ")";
      } else {
        call = "call_indirect()";
      }
      // Keep the result in the architectural return register. This avoids
      // duplicating a call as a side effect when the next instruction stores
      // eax/rax into a local variable.
      body << "    rax = " << call << ";\n";
      values["rax"] = "rax";
      continue;
    }

    if (mnemonic == "ret") {
      std::string returned = "rax";
      const auto value = values.find("rax");
      if (value != values.end())
        returned = value->second;
      if (!operands.empty())
        returned = expression(operands.front());
      body << "    return " << returned << ";\n";
      emitted_return = true;
      continue;
    }

    if (mnemonic == "mov" || mnemonic == "movabs" || mnemonic == "movzx" ||
        mnemonic == "movsx" || mnemonic == "movsxd" || mnemonic == "lea") {
      if (operands.size() >= 2) {
        auto right = expression(operands[1]);
        if (mnemonic == "lea" &&
            operands[1].kind == disasm::OperandKind::Memory &&
            (operands[1].memory.base == "rbp" ||
             operands[1].memory.base == "rsp"))
          right = "&" + right;
        const auto destination = lvalue(operands[0]);
        if (operands[0].kind == disasm::OperandKind::Register)
          assign_register(operands[0], right, values);
        body << "    " << destination << " = "
             << assignment_expression(right, options.data_names) << ";\n";
      } else {
        body << "    /* incomplete " << mnemonic << " */\n";
      }
      continue;
    }

    if (mnemonic == "xor" && operands.size() >= 2 &&
        operands[0].kind == disasm::OperandKind::Register &&
        operands[1].kind == disasm::OperandKind::Register &&
        canonical_register(operands[0].register_name) ==
            canonical_register(operands[1].register_name)) {
      const auto destination = lvalue(operands[0]);
      assign_register(operands[0], "0", values);
      body << "    " << destination << " = 0;\n";
      continue;
    }

    const auto is_binary = mnemonic == "add" || mnemonic == "sub" ||
                           mnemonic == "imul" || mnemonic == "and" ||
                           mnemonic == "or" || mnemonic == "xor" ||
                           mnemonic == "shl" || mnemonic == "sal" ||
                           mnemonic == "shr" || mnemonic == "sar";
    if (is_binary && operands.size() >= 2) {
      const auto destination = lvalue(operands[0]);
      std::string value;
      const char *operator_text = "+";
      if (mnemonic == "sub")
        operator_text = "-";
      else if (mnemonic == "imul")
        operator_text = "*";
      else if (mnemonic == "and")
        operator_text = "&";
      else if (mnemonic == "or")
        operator_text = "|";
      else if (mnemonic == "xor")
        operator_text = "^";
      else if (mnemonic == "shl" || mnemonic == "sal")
        operator_text = "<<";
      else if (mnemonic == "shr" || mnemonic == "sar")
        operator_text = ">>";

      if (mnemonic == "imul" && operands.size() >= 3) {
        value = "(" + expression(operands[1]) + " * " +
                expression(operands[2]) + ")";
      } else {
        const auto left = expression(operands[0]);
        value = "(" + left + " " + operator_text + " " +
                expression(operands[1]) + ")";
      }
      assign_register(operands[0], value, values);
      body << "    " << destination << " = " << value << ";\n";
      continue;
    }

    if ((mnemonic == "inc" || mnemonic == "dec" || mnemonic == "neg" ||
         mnemonic == "not") && !operands.empty()) {
      const auto destination = lvalue(operands[0]);
      const auto value = expression(operands[0]);
      std::string updated;
      if (mnemonic == "inc")
        updated = "(" + value + " + 1)";
      else if (mnemonic == "dec")
        updated = "(" + value + " - 1)";
      else if (mnemonic == "neg")
        updated = "(-" + value + ")";
      else
        updated = "(~" + value + ")";
      assign_register(operands[0], updated, values);
      body << "    " << destination << " = " << updated << ";\n";
      continue;
    }

    if (!mnemonic.empty() && mnemonic.rfind("set", 0) == 0 &&
        !operands.empty()) {
      const auto destination = lvalue(operands[0]);
      const auto condition = have_comparison
                                 ? condition_for("j" + mnemonic.substr(3),
                                                 compare_left, compare_right)
                                 : "0";
      assign_register(operands[0], "(" + condition + " ? 1 : 0)", values);
      body << "    " << destination << " = (" << condition
           << " ? 1 : 0);\n";
      continue;
    }

    if (mnemonic == "hlt" || mnemonic == "ud2" || mnemonic == "int3") {
      body << "    __builtin_trap();\n";
      continue;
    }

    body << "    /* unsupported at " << address_name(instruction.address)
         << ": " << instruction.text() << " */\n";
  }

  if (!emitted_return)
    body << "    /* no explicit return recovered */\n    return 0;\n";
  body << "}\n";
  return {safe_name, address, body.str()};
}

std::size_t infer_argument_count(const std::vector<std::uint8_t> &bytes,
                                 std::uint64_t address) {
  const auto arguments = infer_input_arguments(disasm::disassemble(bytes, address));
  std::size_t count = 0;
  for (const auto &register_name : arguments)
    count = std::max(count, static_cast<std::size_t>(argument_index(register_name) + 1));
  return count;
}

} // namespace caraxes::decompiler
