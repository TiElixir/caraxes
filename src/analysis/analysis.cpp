#include "analysis/analysis.hpp"

#include <algorithm>
#include <set>
#include <sstream>

namespace caraxes::analysis {
namespace {
Instruction decode(const std::vector<std::uint8_t> &b, std::size_t i,
                   std::uint64_t base) {
  Instruction x{base + i, b[i], 1, "db", 0, false, false, false};
  auto rel32 = [&] {
    const auto value = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(b[i + 1]) |
        (static_cast<std::uint32_t>(b[i + 2]) << 8) |
        (static_cast<std::uint32_t>(b[i + 3]) << 16) |
        (static_cast<std::uint32_t>(b[i + 4]) << 24));
    return static_cast<std::uint64_t>(x.address + 5 + value);
  };
  if (b[i] == 0xc3) { x.mnemonic = "ret"; x.is_return = true; }
  else if (b[i] == 0xe8 && i + 4 < b.size()) { x.size = 5; x.mnemonic = "call"; x.target = rel32(); x.is_branch = x.is_call = true; }
  else if (b[i] == 0xe9 && i + 4 < b.size()) { x.size = 5; x.mnemonic = "jmp"; x.target = rel32(); x.is_branch = true; }
  else if (b[i] == 0xeb && i + 1 < b.size()) { x.size = 2; x.mnemonic = "jmp"; x.target = x.address + 2 + static_cast<std::int8_t>(b[i + 1]); x.is_branch = true; }
  else if (b[i] >= 0x70 && b[i] <= 0x7f && i + 1 < b.size()) { x.size = 2; x.mnemonic = "jcc"; x.target = x.address + 2 + static_cast<std::int8_t>(b[i + 1]); x.is_branch = true; }
  else if (b[i] == 0x0f && i + 5 < b.size() && b[i + 1] >= 0x80 && b[i + 1] <= 0x8f) { x.size = 6; x.mnemonic = "jcc"; x.target = x.address + 6 + static_cast<std::int32_t>(static_cast<std::uint32_t>(b[i + 2]) | (static_cast<std::uint32_t>(b[i + 3]) << 8) | (static_cast<std::uint32_t>(b[i + 4]) << 16) | (static_cast<std::uint32_t>(b[i + 5]) << 24)); x.is_branch = true; }
  else if (b[i] == 0x90) x.mnemonic = "nop";
  return x;
}
}

Analysis analyze(const std::vector<std::uint8_t> &text, std::uint64_t base,
                 std::uint64_t entry) {
  Analysis out;
  if (text.empty()) return out;
  std::set<std::uint64_t> starts{entry >= base && entry < base + text.size() ? entry : base};
  std::vector<Instruction> decoded;
  for (std::size_t i = 0; i < text.size();) {
    auto ins = decode(text, i, base);
    decoded.push_back(ins);
    if (ins.is_call && ins.target >= base && ins.target < base + text.size()) starts.insert(ins.target);
    i += ins.size;
  }
  for (const auto &ins : decoded) {
    if (ins.is_branch && !ins.is_call && ins.target >= base && ins.target < base + text.size()) starts.insert(ins.target);
  }
  for (auto start : starts) {
    Function fn;
    fn.address = start;
    auto it = std::lower_bound(decoded.begin(), decoded.end(), start,
                               [](const Instruction &ins, std::uint64_t address) { return ins.address < address; });
    if (it == decoded.end() || it->address != start) continue;
    std::set<std::uint64_t> block_starts{start};
    for (auto cursor = it; cursor != decoded.end(); ++cursor) {
      if (cursor->is_branch) {
        if (cursor->target >= base && cursor->target < base + text.size()) block_starts.insert(cursor->target);
        const auto fallthrough = cursor->address + cursor->size;
        if (cursor->mnemonic == "jcc" && fallthrough < base + text.size()) block_starts.insert(fallthrough);
      }
      if (cursor->is_return) break;
    }
    for (auto block_start : block_starts) {
      auto block_it = std::lower_bound(decoded.begin(), decoded.end(), block_start,
                                       [](const Instruction &ins, std::uint64_t address) { return ins.address < address; });
      if (block_it == decoded.end() || block_it->address != block_start) continue;
      BasicBlock block; block.address = block_start;
      for (auto cursor = block_it; cursor != decoded.end(); ++cursor) {
        block.instructions.push_back(*cursor);
        const auto next = cursor->address + cursor->size;
        if (cursor->is_return || (cursor->is_branch && !cursor->is_call) || (next != base + text.size() && block_starts.contains(next))) break;
      }
      if (!block.instructions.empty()) fn.blocks.push_back(std::move(block));
    }
    std::sort(fn.blocks.begin(), fn.blocks.end(), [](const BasicBlock &a, const BasicBlock &b) { return a.address < b.address; });
    for (auto &block : fn.blocks) {
      if (block.instructions.empty()) continue;
      const auto &last = block.instructions.back();
      if (last.is_branch && !last.is_call && last.target) block.successors.push_back(last.target);
      if (!last.is_return && (!last.is_branch || last.mnemonic == "jcc")) {
        const auto next = last.address + last.size;
        if (std::any_of(fn.blocks.begin(), fn.blocks.end(), [next](const BasicBlock &candidate) { return candidate.address == next; })) block.successors.push_back(next);
      }
    }
    for (auto &block : fn.blocks) for (auto target : block.successors) for (auto &candidate : fn.blocks) if (candidate.address == target) candidate.predecessors.push_back(block.address);
    if (!fn.blocks.empty()) fn.size = fn.blocks.back().instructions.back().address + fn.blocks.back().instructions.back().size - fn.address;
    for (const auto &block : fn.blocks) for (const auto &ins : block.instructions) {
      if (ins.is_call) { out.xrefs.push_back({ins.address, ins.target, "call"}); fn.callees.push_back(ins.target); }
      out.ir.push_back({ins.address, ins.mnemonic, {}});
    }
    std::sort(fn.callees.begin(), fn.callees.end()); fn.callees.erase(std::unique(fn.callees.begin(), fn.callees.end()), fn.callees.end());
    out.functions.push_back(std::move(fn));
  }
  return out;
}

std::string decompile(const Function &f) { std::ostringstream s; s << "function sub_" << std::hex << f.address << "() {\n"; for (const auto &b : f.blocks) { s << "  block_" << b.address << ":\n"; for (const auto &i : b.instructions) s << "    " << i.mnemonic << ";\n"; } return s.str() + "}\n"; }
std::string report(const Analysis &a) { std::ostringstream s; s << "functions: " << a.functions.size() << "\n" << "xrefs: " << a.xrefs.size() << "\n" << "ir: " << a.ir.size() << "\n"; for (const auto &f : a.functions) s << decompile(f); return s.str(); }
} // namespace caraxes::analysis
