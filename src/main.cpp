#include "disasm/disasm.hpp"
#include "analysis/analysis.hpp"
#include "loader/elf/elf.hpp"
#include "decompiler/decompiler.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace {
void usage() { std::cout << "Caraxes static analysis toolkit\nUsage: Caraxes <binary> [options]\n       Caraxes <command> <binary> [options]\n\nWith only a binary path, Caraxes decodes its executable .text section.\nCommands: info sections strings hexdump symbols disasm functions cfg callgraph xrefs decompile\n"; }
std::string json_escape(const std::string &s) { std::string o; for (char c : s) { if (c == '"' || c == '\\') o += '\\'; o += c; } return o; }
}
int main(int argc, char **argv) {
  if (argc < 2 || std::string(argv[1]) == "--help") { usage(); return argc < 2 ? 1 : 0; }
  if (std::string(argv[1]) == "--version") { std::cout << "Caraxes 0.1.0\n"; return 0; }
  const std::string first = argv[1];
  const std::string commands = "info sections strings hexdump symbols disasm functions cfg callgraph xrefs decompile";
  const bool is_command = commands.find(first) != std::string::npos &&
                          (first == "info" || first == "sections" || first == "strings" ||
                           first == "hexdump" || first == "symbols" || first == "disasm" ||
                           first == "functions" || first == "cfg" || first == "callgraph" ||
                           first == "xrefs" || first == "decompile");
  const std::string command = is_command ? first : "disasm";
  const int binary_index = is_command ? 2 : 1;
  if (argc <= binary_index) { usage(); return 1; }
  bool json = false; for (int i = binary_index + 1; i < argc; ++i) if (std::string(argv[i]) == "--json") json = true;
  try {
    const auto file = caraxes::elf::parse_file(argv[binary_index]);
    const auto &h = file.header;
    if (command == "info") {
      if (json) { std::cout << "{\"class\":\"" << caraxes::elf::class_name(h.elf_class) << "\",\"endian\":\"" << caraxes::elf::endian_name(h.endian) << "\",\"type\":\"" << caraxes::elf::type_name(h.type) << "\",\"machine\":\"" << caraxes::elf::machine_name(h.machine) << "\",\"entry\":" << h.entry << ",\"program_headers\":" << file.program_headers.size() << ",\"sections\":" << file.sections.size() << "}\n"; }
      else std::cout << "Class: " << caraxes::elf::class_name(h.elf_class) << "\nData: " << caraxes::elf::endian_name(h.endian) << "\nType: " << caraxes::elf::type_name(h.type) << "\nMachine: " << caraxes::elf::machine_name(h.machine) << "\nEntry: 0x" << std::hex << h.entry << std::dec << "\nProgram headers: " << file.program_headers.size() << "\nSections: " << file.sections.size() << "\n";
    } else if (command == "sections") {
      for (std::size_t i = 0; i < file.sections.size(); ++i) { const auto &s = file.sections[i]; std::cout << std::setw(2) << i << " " << std::left << std::setw(20) << s.name << " addr=0x" << std::hex << s.address << " offset=0x" << s.offset << " size=0x" << s.size << std::dec << "\n"; }
    } else if (command == "symbols") {
      for (const auto &s : file.symbols) if (!s.name.empty()) std::cout << "0x" << std::hex << s.value << std::dec << " " << s.name << (s.dynamic ? " [dyn]" : "") << "\n";
    } else if (command == "strings") {
      for (const auto &s : file.sections) { if (!(s.flags & 2) && s.type != 8 && s.size) { auto bytes = file.section_bytes(s); std::string cur; for (std::size_t i=0;i<bytes.size();++i) { if (std::isprint(bytes[i])) cur += static_cast<char>(bytes[i]); else { if (cur.size() >= 4) std::cout << "0x" << std::hex << s.address + i - cur.size() << std::dec << " " << cur << "\n"; cur.clear(); } } if (cur.size() >= 4) std::cout << "0x" << std::hex << s.address + bytes.size() - cur.size() << std::dec << " " << cur << "\n"; } }
    } else if (command == "hexdump") {
      std::size_t limit = std::min<std::size_t>(file.bytes.size(), 256); for (std::size_t i=0;i<limit;i+=16) { std::cout << std::hex << std::setw(8) << std::setfill('0') << i << "  "; for (std::size_t j=0;j<16 && i+j<limit;++j) std::cout << std::setw(2) << static_cast<unsigned>(file.bytes[i+j]) << ' '; std::cout << std::setfill(' ') << "\n"; }
    } else if (command == "disasm") {
      std::string section = ".text"; for (int i=binary_index+1;i<argc-1;++i) if (std::string(argv[i]) == "--section") section = argv[i+1];
      for (const auto &ins : caraxes::disasm::disassemble_section(file, section)) {
        std::cout << "0x" << std::hex << ins.address << "    " << std::setfill('0');
        for (const auto byte : ins.bytes) std::cout << std::setw(2) << static_cast<unsigned>(byte) << ' ';
        std::cout << std::setfill(' ') << std::dec << "  " << ins.mnemonic;
        if (!ins.operands.empty()) std::cout << " " << ins.operands;
        std::cout << "\n";
      }
    } else if (command == "functions" || command == "cfg" || command == "callgraph" || command == "xrefs" || command == "decompile") {
      const auto *text = file.section(".text"); if (!text) throw std::runtime_error("ELF section not found: .text");
      const auto result = caraxes::analysis::analyze(file.section_bytes(*text), text->address, file.header.entry);
      if (command == "functions") for (const auto &f : result.functions) std::cout << "0x" << std::hex << f.address << std::dec << " size=" << f.size << " blocks=" << f.blocks.size() << " callees=" << f.callees.size() << "\n";
      else if (command == "cfg") for (const auto &f : result.functions) { std::cout << "function 0x" << std::hex << f.address << std::dec << "\n"; for (const auto &b : f.blocks) { std::cout << "  block 0x" << std::hex << b.address << " successors="; for (auto target : b.successors) std::cout << "0x" << target << ' '; std::cout << std::dec << "\n"; } }
      else if (command == "callgraph") for (const auto &x : result.xrefs) std::cout << "0x" << std::hex << x.from << " -> 0x" << x.to << std::dec << "\n";
      else if (command == "xrefs") for (const auto &x : result.xrefs) std::cout << "0x" << std::hex << x.from << " -> 0x" << x.to << std::dec << " " << x.kind << "\n";
      else {
        for (const auto &f : result.functions) {
          if (f.address < text->address || f.address - text->address >= text->size) continue;
          const auto offset = static_cast<std::size_t>(f.address - text->address);
          const auto length = std::min<std::size_t>(f.size ? f.size : text->size - offset, text->size - offset);
          std::ostringstream name_stream; name_stream << "sub_" << std::hex << f.address;
          const auto text_bytes = file.section_bytes(*text);
          std::cout << caraxes::decompiler::decompile(std::vector<std::uint8_t>(text_bytes.begin() + offset, text_bytes.begin() + offset + length), f.address, name_stream.str()).code;
        }
      }
    } else { usage(); return 1; }
  } catch (const std::exception &e) { std::cerr << "error: " << e.what() << '\n'; return 1; }
}
