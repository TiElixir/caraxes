#include "analysis/analysis.hpp"

#include "disasm/disasm.hpp"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace caraxes::analysis {
namespace {

bool in_range(std::uint64_t address, std::uint64_t base,
              std::size_t size) {
  return address >= base && address - base < size;
}

std::string hex_address(std::uint64_t address) {
  std::ostringstream stream;
  stream << "0x" << std::hex << address;
  return stream.str();
}

std::string fallback_name(std::uint64_t address) {
  std::ostringstream stream;
  stream << "sub_" << std::hex << address;
  return stream.str();
}

Instruction convert_instruction(const disasm::Instruction &source) {
  Instruction result;
  result.address = source.address;
  result.opcode = source.bytes.empty() ? 0 : source.bytes.front();
  result.size = static_cast<std::uint8_t>(source.size);
  result.mnemonic = source.mnemonic;
  result.target = source.target;
  result.is_branch = source.is_branch;
  result.is_call = source.is_call;
  result.is_return = source.is_return;
  result.bytes = source.bytes;
  result.operands = source.operands;
  result.valid = source.valid;
  result.has_target = source.has_target;
  result.is_conditional = source.is_conditional;
  result.is_terminal = source.is_terminal;
  result.is_indirect = source.is_indirect;
  return result;
}

void append_unique(std::vector<std::uint64_t> &values,
                   std::uint64_t value) {
  if (std::find(values.begin(), values.end(), value) == values.end())
    values.push_back(value);
}

} // namespace

Analysis analyze(const std::vector<std::uint8_t> &text, std::uint64_t base,
                 std::uint64_t entry,
                 const std::vector<FunctionSeed> &seeds) {
  Analysis result;
  if (text.empty())
    return result;

  const auto decoded = disasm::disassemble(text, base);
  if (decoded.empty())
    return result;

  std::map<std::uint64_t, std::size_t> instruction_indices;
  std::map<std::uint64_t, FunctionSeed> function_seeds;
  std::map<std::uint64_t, std::size_t> function_indices;

  for (std::size_t i = 0; i < decoded.size(); ++i)
    instruction_indices.emplace(decoded[i].address, i);

  auto add_seed = [&](std::uint64_t address, std::uint64_t size,
                      const std::string &name) {
    if (!in_range(address, base, text.size()))
      return;
    const auto instruction = instruction_indices.find(address);
    if (instruction == instruction_indices.end() ||
        !decoded[instruction->second].valid)
      return;

    auto [it, inserted] = function_seeds.emplace(
        address, FunctionSeed{address, size, name});
    if (!inserted) {
      if (it->second.name.empty() && !name.empty())
        it->second.name = name;
      if (it->second.size == 0 && size != 0)
        it->second.size = size;
    }
  };

  if (entry != 0 && in_range(entry, base, text.size()))
    add_seed(entry, 0, {});
  else
    add_seed(base, 0, {});

  for (const auto &seed : seeds)
    add_seed(seed.address, seed.size, seed.name);

  // Direct call targets are the strongest stripped-binary function signal.
  // A small prologue heuristic supplements them for unreferenced routines
  // emitted by common ELF toolchains, without treating every branch target as
  // a new function.
  for (std::size_t i = 0; i < decoded.size(); ++i) {
    const auto &instruction = decoded[i];
    if (instruction.is_call && instruction.has_target &&
        in_range(instruction.target, base, text.size()))
      add_seed(instruction.target, 0, {});

    if (instruction.valid && instruction.mnemonic == "endbr64")
      add_seed(instruction.address, 0, {});

    if (i > 0 && decoded[i - 1].is_return && instruction.valid &&
        (instruction.mnemonic == "push" || instruction.mnemonic == "sub"))
      add_seed(instruction.address, 0, {});
  }

  for (const auto &[start, seed] : function_seeds) {
    Function function;
    function.address = start;
    function.name = seed.name.empty() ? fallback_name(start) : seed.name;

    std::set<std::uint64_t> pending{start};
    std::set<std::uint64_t> block_starts{start};
    std::set<std::uint64_t> processed_blocks;

    auto enqueue_block = [&](std::uint64_t address) {
      if (!in_range(address, base, text.size()))
        return;
      const auto instruction = instruction_indices.find(address);
      if (instruction == instruction_indices.end() ||
          !decoded[instruction->second].valid)
        return;
      // A call target/name seed starts its own function. It is not silently
      // folded into the preceding function when control falls through.
      const auto other_function = function_seeds.find(address);
      if (other_function != function_seeds.end() && address != start)
        return;
      if (block_starts.insert(address).second)
        pending.insert(address);
    };

    while (!pending.empty()) {
      const auto block_start = *pending.begin();
      pending.erase(pending.begin());
      if (!processed_blocks.insert(block_start).second)
        continue;

      const auto start_instruction = instruction_indices.find(block_start);
      if (start_instruction == instruction_indices.end() ||
          !decoded[start_instruction->second].valid)
        continue;

      BasicBlock block;
      block.address = block_start;
      std::set<std::uint64_t> instructions_in_block;
      auto cursor = start_instruction->second;

      while (cursor < decoded.size()) {
        const auto &decoded_instruction = decoded[cursor];
        if (!decoded_instruction.valid ||
            !instructions_in_block.insert(decoded_instruction.address).second)
          break;

        if (decoded_instruction.address != block_start &&
            function_seeds.contains(decoded_instruction.address))
          break;

        block.instructions.push_back(convert_instruction(decoded_instruction));
        const auto next = decoded_instruction.address + decoded_instruction.size;

        if (!decoded_instruction.valid || decoded_instruction.is_terminal)
          break;

        if (decoded_instruction.is_branch && !decoded_instruction.is_call) {
          if (decoded_instruction.has_target)
            enqueue_block(decoded_instruction.target);
          if (decoded_instruction.is_conditional)
            enqueue_block(next);
          break;
        }

        const auto next_instruction = instruction_indices.find(next);
        if (next_instruction == instruction_indices.end())
          break;
        if (block_starts.contains(next) || function_seeds.contains(next))
          break;
        cursor = next_instruction->second;
      }

      if (!block.instructions.empty())
        function.blocks.push_back(std::move(block));
    }

    std::sort(function.blocks.begin(), function.blocks.end(),
              [](const BasicBlock &left, const BasicBlock &right) {
                return left.address < right.address;
              });

    std::set<std::uint64_t> block_addresses;
    for (const auto &block : function.blocks)
      block_addresses.insert(block.address);

    for (auto &block : function.blocks) {
      if (block.instructions.empty())
        continue;
      const auto &last = block.instructions.back();
      const auto next = last.address + last.size;
      auto add_successor = [&](std::uint64_t target) {
        if (block_addresses.contains(target))
          append_unique(block.successors, target);
      };

      if (last.is_branch && !last.is_call) {
        if (last.has_target)
          add_successor(last.target);
        if (last.is_conditional)
          add_successor(next);
      } else if (!last.is_terminal) {
        add_successor(next);
      }
    }

    for (auto &block : function.blocks) {
      for (const auto successor : block.successors) {
        auto target = std::find_if(
            function.blocks.begin(), function.blocks.end(),
            [successor](const BasicBlock &candidate) {
              return candidate.address == successor;
            });
        if (target != function.blocks.end())
          append_unique(target->predecessors, block.address);
      }
    }

    for (const auto &block : function.blocks) {
      for (const auto &instruction : block.instructions) {
        function.size = std::max(
            function.size,
            instruction.address + instruction.size - function.address);
      }
    }
    if (seed.size > function.size)
      function.size = seed.size;

    if (!function.blocks.empty()) {
      function_indices.emplace(function.address, result.functions.size());
      result.functions.push_back(std::move(function));
    }
  }

  // Emit cross-references and a compact instruction IR in deterministic
  // function/block order. The set prevents duplicate records when a compiler
  // emits overlapping symbol ranges or multiple names for one address.
  std::set<std::tuple<std::uint64_t, std::uint64_t, std::string>> xref_keys;
  auto add_xref = [&](std::uint64_t from, std::uint64_t to,
                      const std::string &kind) {
    if (xref_keys.emplace(from, to, kind).second)
      result.xrefs.push_back({from, to, kind});
  };

  std::map<std::uint64_t, const disasm::Instruction *> source_by_address;
  for (const auto &instruction : decoded)
    source_by_address.emplace(instruction.address, &instruction);

  for (auto &function : result.functions) {
    for (const auto &block : function.blocks) {
      for (const auto &instruction : block.instructions) {
        result.ir.push_back({instruction.address, instruction.mnemonic,
                             instruction.operands.empty()
                                 ? std::vector<std::string>{}
                                 : std::vector<std::string>{instruction.operands}});

        if (instruction.is_call && instruction.has_target) {
          append_unique(function.callees, instruction.target);
          add_xref(instruction.address, instruction.target, "call");
        } else if (instruction.is_branch && !instruction.is_call &&
                   instruction.has_target) {
          add_xref(instruction.address, instruction.target,
                   instruction.is_conditional ? "conditional_jump" : "jump");
        }

        const auto source = source_by_address.find(instruction.address);
        if (source == source_by_address.end())
          continue;
        for (const auto &operand : source->second->operand_details) {
          if (operand.kind != disasm::OperandKind::Memory ||
              operand.memory.base != "rip")
            continue;
          const auto target = static_cast<std::uint64_t>(
              static_cast<std::int64_t>(instruction.address + instruction.size) +
              operand.memory.displacement);
          add_xref(instruction.address, target, "data");
        }
      }
    }
    std::sort(function.callees.begin(), function.callees.end());
  }

  for (const auto &function : result.functions) {
    for (const auto callee : function.callees) {
      const auto target = function_indices.find(callee);
      if (target != function_indices.end())
        append_unique(result.functions[target->second].callers,
                      function.address);
    }
  }

  return result;
}

std::string decompile(const Function &function) {
  std::ostringstream stream;
  const auto name = function.name.empty() ? fallback_name(function.address)
                                          : function.name;
  stream << "int " << name << "(void) {\n";
  for (const auto &block : function.blocks) {
    stream << "  loc_" << std::hex << block.address << ":\n";
    for (const auto &instruction : block.instructions) {
      stream << "    /* " << hex_address(instruction.address) << " */ "
             << instruction.mnemonic;
      if (!instruction.operands.empty())
        stream << " " << instruction.operands;
      stream << ";\n";
    }
  }
  stream << "}\n";
  return stream.str();
}

std::string report(const Analysis &analysis) {
  std::ostringstream stream;
  stream << "functions: " << analysis.functions.size() << "\n"
         << "xrefs: " << analysis.xrefs.size() << "\n"
         << "ir: " << analysis.ir.size() << "\n";

  for (const auto &function : analysis.functions) {
    stream << "\nfunction " << function.name << " @ "
           << hex_address(function.address) << " size=" << std::dec
           << function.size << " blocks=" << function.blocks.size() << "\n";
    if (!function.callers.empty()) {
      stream << "  callers:";
      for (const auto caller : function.callers)
        stream << " " << hex_address(caller);
      stream << "\n";
    }
    if (!function.callees.empty()) {
      stream << "  callees:";
      for (const auto callee : function.callees)
        stream << " " << hex_address(callee);
      stream << "\n";
    }
    for (const auto &block : function.blocks) {
      stream << "  block " << hex_address(block.address) << " preds=";
      for (const auto predecessor : block.predecessors)
        stream << hex_address(predecessor) << " ";
      stream << "succs=";
      for (const auto successor : block.successors)
        stream << hex_address(successor) << " ";
      stream << "\n";
      for (const auto &instruction : block.instructions) {
        stream << "    " << hex_address(instruction.address) << "  "
               << instruction.mnemonic;
        if (!instruction.operands.empty())
          stream << " " << instruction.operands;
        stream << "\n";
      }
    }
  }

  if (!analysis.xrefs.empty()) {
    stream << "\nxrefs:\n";
    for (const auto &xref : analysis.xrefs)
      stream << "  " << hex_address(xref.from) << " -> "
             << hex_address(xref.to) << " " << xref.kind << "\n";
  }
  return stream.str();
}

} // namespace caraxes::analysis
