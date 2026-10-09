#include "analysis/analysis.hpp"
#include "decompiler/decompiler.hpp"
#include "decompiler/project.hpp"
#include "disasm/disasm.hpp"
#include "loader/elf/elf.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void usage() {
  std::cout
      << "Caraxes static reverse-engineering toolkit\n\n"
      << "Usage:\n"
      << "  caraxes <binary> [options]\n"
      << "  caraxes <command> <binary> [options]\n\n"
      << "Commands:\n"
      << "  info       ELF identity, entry point, and table counts\n"
      << "  segments   ELF program headers and load ranges\n"
      << "  sections   section addresses, offsets, flags, and sizes\n"
      << "  symbols    static and dynamic symbols\n"
      << "  relocations relocation entries and resolved symbol names\n"
      << "  strings    printable strings with virtual addresses\n"
      << "  hexdump    bounded file hexdump\n"
      << "  disasm     Capstone x86-64 disassembly\n"
      << "  functions  discovered functions and call relationships\n"
      << "  cfg        basic blocks, instructions, and CFG edges\n"
      << "  callgraph  direct call edges\n"
      << "  xrefs      call, branch, and RIP-relative data references\n"
      << "  decompile  C-like recovered output for every discovered function\n"
      << "  report     complete textual analysis report\n\n"
      << "Options:\n"
      << "  --section NAME  analyze/disassemble NAME instead of .text\n"
      << "  --json          JSON for info, functions, or decompile\n"
      << "  --output FILE   save decompile output to FILE\n"
      << "  --limit N       maximum hexdump bytes (default: 256)\n"
      << "  --offset N      hexdump starting file offset (default: 0)\n"
      << "  --help          show this help\n"
      << "  --version       show the program version\n\n"
      << "With only a binary path, Caraxes runs the disassembler on its"
         " executable section.\n";
}

std::string json_escape(const std::string &value) {
  std::ostringstream output;
  for (const auto character : value) {
    switch (character) {
    case '"':
      output << "\\\"";
      break;
    case '\\':
      output << "\\\\";
      break;
    case '\n':
      output << "\\n";
      break;
    case '\r':
      output << "\\r";
      break;
    case '\t':
      output << "\\t";
      break;
    default:
      if (static_cast<unsigned char>(character) < 0x20)
        output << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(static_cast<unsigned char>(character))
               << std::setfill(' ') << std::dec;
      else
        output << character;
      break;
    }
  }
  return output.str();
}

bool is_command(const std::string &value) {
  return value == "info" || value == "segments" || value == "sections" ||
         value == "symbols" || value == "relocations" || value == "strings" ||
         value == "hexdump" || value == "disasm" || value == "functions" ||
         value == "cfg" || value == "callgraph" || value == "xrefs" ||
         value == "decompile" || value == "report";
}

std::uint64_t parse_number(const std::string &value, const char *what) {
  if (value.empty() || value.front() == '-' ||
      std::isspace(static_cast<unsigned char>(value.front())))
    throw std::runtime_error(std::string("invalid ") + what + ": " + value);
  std::size_t consumed = 0;
  const auto result = std::stoull(value, &consumed, 0);
  if (consumed != value.size())
    throw std::runtime_error(std::string("invalid ") + what + ": " + value);
  return result;
}

void write_export(const std::filesystem::path &path, const std::string &text,
                  const std::filesystem::path &binary) {
  if (path.empty()) {
    std::cout << text;
    if (!std::cout)
      throw std::runtime_error("could not write export to stdout");
    return;
  }
  if (std::filesystem::exists(path) && std::filesystem::equivalent(path, binary))
    throw std::runtime_error("output file must differ from the input binary");
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream << text;
  stream.close();
  if (!stream)
    throw std::runtime_error("could not write output: " + path.string());
}

const caraxes::elf::SectionHeader *selected_section(
    const caraxes::elf::File &file, const std::string &requested) {
  if (const auto *section = file.section(requested))
    return section;
  if (requested != ".text")
    return nullptr;
  for (const auto &section : file.sections) {
    if ((section.flags & 0x4) != 0 && section.type != 8 && section.size != 0)
      return &section;
  }
  return nullptr;
}

std::vector<caraxes::analysis::FunctionSeed> function_seeds(
    const caraxes::elf::File &file,
    const caraxes::elf::SectionHeader &text) {
  std::vector<caraxes::analysis::FunctionSeed> seeds;
  for (const auto &symbol : file.symbols) {
    const auto type = static_cast<std::uint8_t>(symbol.info & 0x0f);
    if (symbol.name.empty() || (type != 2 && type != 10) || symbol.value == 0)
      continue;
    if (symbol.value < text.address || symbol.value - text.address >= text.size)
      continue;
    seeds.push_back({symbol.value, symbol.size, symbol.name});
  }
  return seeds;
}

std::map<std::uint64_t, std::string> function_names(
    const std::vector<caraxes::analysis::FunctionSeed> &seeds) {
  std::map<std::uint64_t, std::string> result;
  for (const auto &seed : seeds) {
    const auto it = result.find(seed.address);
    if (it == result.end() || it->second.empty())
      result[seed.address] = seed.name;
  }
  return result;
}

std::map<std::uint64_t, std::string> data_names(
    const caraxes::elf::File &file) {
  std::map<std::uint64_t, std::string> result;
  for (const auto &symbol : file.symbols) {
    const auto type = static_cast<std::uint8_t>(symbol.info & 0x0f);
    if (symbol.name.empty() || symbol.value == 0 || type == 2 || type == 10)
      continue;
    result.emplace(symbol.value, symbol.name);
  }
  return result;
}

std::map<std::uint64_t, std::string> imported_plt_names(
    const caraxes::elf::File &file) {
  std::map<std::uint64_t, std::string> result;
  const auto *plt = file.section(".plt");
  if (!plt)
    plt = file.section(".plt.sec");
  if (!plt)
    return result;

  std::map<std::uint32_t, std::size_t> ordinal_by_table;
  for (const auto &relocation : file.relocations) {
    if (relocation.section_index >= file.sections.size())
      continue;
    const auto &table = file.sections[relocation.section_index];
    if (table.name != ".rela.plt" && table.name != ".rel.plt")
      continue;
    if (relocation.symbol_name.empty())
      continue;
    const auto ordinal = ordinal_by_table[relocation.section_index]++;
    const auto entry_size = plt->entry_size == 0 ? 16 : plt->entry_size;
    const auto stub_index = plt->name == ".plt" ? ordinal + 1 : ordinal;
    const auto address = plt->address + stub_index * entry_size;
    if (address >= plt->address && address - plt->address < plt->size)
      result[address] = relocation.symbol_name;
  }
  return result;
}

std::string hex(std::uint64_t value) {
  std::ostringstream output;
  output << "0x" << std::hex << value;
  return output.str();
}

void print_instruction(const caraxes::analysis::Instruction &instruction,
                       const std::string &indent) {
  std::cout << indent << hex(instruction.address) << "  ";
  for (const auto byte : instruction.bytes)
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(byte) << ' ';
  std::cout << std::setfill(' ') << std::dec << "  " << instruction.mnemonic;
  if (!instruction.operands.empty())
    std::cout << " " << instruction.operands;
  if (!instruction.valid)
    std::cout << "  ; undecodable byte";
  std::cout << '\n';
}

void print_info(const caraxes::elf::File &file, bool json) {
  const auto &header = file.header;
  if (json) {
    std::cout << "{\"class\":\"" << json_escape(caraxes::elf::class_name(header.elf_class))
              << "\",\"endian\":\""
              << json_escape(caraxes::elf::endian_name(header.endian))
              << "\",\"type\":\""
              << json_escape(caraxes::elf::type_name(header.type))
              << "\",\"machine\":\""
              << json_escape(caraxes::elf::machine_name(header.machine))
              << "\",\"entry\":" << header.entry
              << ",\"program_headers\":" << file.program_headers.size()
              << ",\"sections\":" << file.sections.size()
              << ",\"symbols\":" << file.symbols.size()
              << ",\"relocations\":" << file.relocations.size() << "}\n";
    return;
  }
  std::cout << "Class:            " << caraxes::elf::class_name(header.elf_class)
            << "\nData:             " << caraxes::elf::endian_name(header.endian)
            << "\nType:             " << caraxes::elf::type_name(header.type)
            << "\nMachine:          " << caraxes::elf::machine_name(header.machine)
            << "\nEntry point:      " << hex(header.entry)
            << "\nProgram headers:  " << file.program_headers.size()
            << "\nSections:         " << file.sections.size()
            << "\nSymbols:          " << file.symbols.size()
            << "\nRelocations:      " << file.relocations.size() << '\n';
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 2 || std::string(argv[1]) == "--help") {
    usage();
    return argc < 2 ? 1 : 0;
  }
  if (std::string(argv[1]) == "--version") {
    std::cout << "Caraxes 0.2.0\n";
    return 0;
  }

  const std::string first = argv[1];
  const bool command_present = is_command(first);
  const std::string command = command_present ? first : "disasm";
  const int binary_index = command_present ? 2 : 1;
  if (argc <= binary_index) {
    usage();
    return 1;
  }

  bool json = false;
  std::string section_name = ".text";
  std::size_t hexdump_limit = 256;
  std::size_t hexdump_offset = 0;
  std::filesystem::path output_path;
  bool output_option = false;
  try {
    for (int i = binary_index + 1; i < argc; ++i) {
    const std::string option = argv[i];
    if (option == "--json") {
      json = true;
    } else if (option == "--section") {
      if (i + 1 >= argc)
        throw std::runtime_error("--section requires a name");
      section_name = argv[++i];
    } else if (option == "--output") {
      if (i + 1 >= argc)
        throw std::runtime_error(option + " requires a value");
      output_path = argv[++i];
      output_option = true;
    } else if (option == "--limit") {
      if (i + 1 >= argc)
        throw std::runtime_error("--limit requires a number");
      hexdump_limit = static_cast<std::size_t>(parse_number(argv[++i], "limit"));
    } else if (option == "--offset") {
      if (i + 1 >= argc)
        throw std::runtime_error("--offset requires a number");
      hexdump_offset = static_cast<std::size_t>(parse_number(argv[++i], "offset"));
    } else if (option == "--help") {
      usage();
      return 0;
    } else {
      std::cerr << "error: unknown option: " << option << '\n';
      return 1;
    }
    }
    if (output_option && command != "decompile")
      throw std::runtime_error("--output requires the decompile command");
    if (json && command != "info" && command != "functions" && command != "decompile")
      throw std::runtime_error("--json is supported for info, functions, and decompile");
    const auto file = caraxes::elf::parse_file(argv[binary_index]);
    if (command == "info") {
      print_info(file, json);
      return 0;
    }

    if (command == "sections") {
      for (std::size_t i = 0; i < file.sections.size(); ++i) {
        const auto &section = file.sections[i];
        std::cout << std::setw(3) << i << " " << std::left << std::setw(24)
                  << (section.name.empty() ? "<unnamed>" : section.name)
                  << std::right << " type=" << std::setw(2) << section.type
                  << " flags=0x" << std::hex << section.flags
                  << " addr=" << hex(section.address)
                  << " offset=" << hex(section.offset)
                  << " size=" << hex(section.size) << std::dec << '\n';
      }
      return 0;
    }

    if (command == "segments") {
      for (std::size_t i = 0; i < file.program_headers.size(); ++i) {
        const auto &program = file.program_headers[i];
        std::cout << std::setw(3) << i << " type=" << std::setw(2)
                  << program.type << " flags=0x" << std::hex << program.flags
                  << " offset=" << hex(program.offset)
                  << " vaddr=" << hex(program.virtual_address)
                  << " filesz=" << hex(program.file_size)
                  << " memsz=" << hex(program.memory_size)
                  << " align=" << hex(program.alignment) << std::dec << '\n';
      }
      return 0;
    }

    if (command == "symbols") {
      for (const auto &symbol : file.symbols) {
        if (symbol.name.empty())
          continue;
        const auto binding = static_cast<unsigned>(symbol.info >> 4);
        const auto type = static_cast<unsigned>(symbol.info & 0x0f);
        std::cout << hex(symbol.value) << " " << std::left << std::setw(32)
                  << symbol.name << std::right << " size=" << symbol.size
                  << " bind=" << binding << " type=" << type
                  << " section=" << symbol.section_index
                  << (symbol.dynamic ? " [dyn]" : "") << '\n';
      }
      return 0;
    }

    if (command == "relocations") {
      for (const auto &relocation : file.relocations) {
        const auto section = relocation.section_index < file.sections.size()
                                 ? file.sections[relocation.section_index].name
                                 : "<invalid>";
        std::cout << section << " offset=" << hex(relocation.offset)
                  << " type=" << relocation.type
                  << " symbol=" << relocation.symbol_index;
        if (!relocation.symbol_name.empty())
          std::cout << " (" << relocation.symbol_name << ")";
        if (relocation.section_index < file.sections.size() &&
            file.sections[relocation.section_index].type == 4)
          std::cout << " addend=" << relocation.addend;
        std::cout << '\n';
      }
      return 0;
    }

    if (command == "strings") {
      for (const auto &section : file.sections) {
        if ((section.flags & 0x4) != 0 || section.type == 8 || section.size == 0)
          continue;
        const auto bytes = file.section_bytes(section);
        std::string current;
        std::size_t start = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
          if (std::isprint(static_cast<unsigned char>(bytes[i]))) {
            if (current.empty())
              start = i;
            current.push_back(static_cast<char>(bytes[i]));
          } else {
            if (current.size() >= 4)
              std::cout << hex(section.address + start) << " " << current << '\n';
            current.clear();
          }
        }
        if (current.size() >= 4)
          std::cout << hex(section.address + start) << " " << current << '\n';
      }
      return 0;
    }

    if (command == "hexdump") {
      if (hexdump_offset > file.bytes.size())
        throw std::runtime_error("hexdump offset is outside the file");
      const auto length = std::min(hexdump_limit, file.bytes.size() - hexdump_offset);
      for (std::size_t row = 0; row < length; row += 16) {
        const auto count = std::min<std::size_t>(16, length - row);
        std::cout << std::hex << std::setw(8) << std::setfill('0')
                  << hexdump_offset + row << std::setfill(' ') << "  ";
        for (std::size_t column = 0; column < 16; ++column) {
          if (column < count)
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(file.bytes[hexdump_offset + row + column])
                      << std::setfill(' ') << ' ';
          else
            std::cout << "   ";
        }
        std::cout << " |";
        for (std::size_t column = 0; column < count; ++column) {
          const auto character = file.bytes[hexdump_offset + row + column];
          std::cout << (std::isprint(static_cast<unsigned char>(character))
                            ? static_cast<char>(character)
                            : '.');
        }
        std::cout << "|\n" << std::dec;
      }
      return 0;
    }

    const auto *section = selected_section(file, section_name);
    if (!section)
      throw std::runtime_error("executable ELF section not found: " + section_name);
    if (file.header.elf_class != caraxes::elf::Class::Elf64 ||
        file.header.machine != 62)
      throw std::runtime_error("analysis currently supports ELF64 x86-64 binaries");
    const auto section_bytes = file.section_bytes(*section);

    if (command == "disasm") {
      for (const auto &instruction :
           caraxes::disasm::disassemble(section_bytes, section->address)) {
        std::cout << hex(instruction.address) << "  ";
        for (const auto byte : instruction.bytes)
          std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned>(byte) << ' ';
        std::cout << std::setfill(' ') << std::dec << "  "
                  << instruction.text();
        if (!instruction.valid)
          std::cout << "  ; undecodable byte";
        std::cout << '\n';
      }
      return 0;
    }

    const auto seeds = function_seeds(file, *section);
    const auto result = caraxes::analysis::analyze(
        section_bytes, section->address, file.header.entry, seeds);

    if (command == "functions") {
      if (json) {
        std::cout << "[\n";
        for (std::size_t i = 0; i < result.functions.size(); ++i) {
          const auto &function = result.functions[i];
          std::cout << "  {\"name\":\"" << json_escape(function.name)
                    << "\",\"address\":" << function.address
                    << ",\"size\":" << function.size
                    << ",\"blocks\":" << function.blocks.size()
                    << ",\"callers\":" << function.callers.size()
                    << ",\"callees\":" << function.callees.size() << "}"
                    << (i + 1 == result.functions.size() ? "\n" : ",\n");
        }
        std::cout << "]\n";
      } else {
        for (const auto &function : result.functions) {
          std::cout << hex(function.address) << " " << std::left
                    << std::setw(28) << function.name << std::right
                    << " size=" << function.size
                    << " blocks=" << function.blocks.size()
                    << " callers=" << function.callers.size()
                    << " callees=" << function.callees.size() << '\n';
        }
      }
      return 0;
    }

    if (command == "cfg") {
      for (const auto &function : result.functions) {
        std::cout << "function " << function.name << " @ "
                  << hex(function.address) << '\n';
        for (const auto &block : function.blocks) {
          std::cout << "  block " << hex(block.address) << "\n"
                    << "    predecessors:";
          for (const auto predecessor : block.predecessors)
            std::cout << " " << hex(predecessor);
          std::cout << "\n    successors:";
          for (const auto successor : block.successors)
            std::cout << " " << hex(successor);
          std::cout << '\n';
          for (const auto &instruction : block.instructions)
            print_instruction(instruction, "    ");
        }
      }
      return 0;
    }

    if (command == "callgraph") {
      for (const auto &xref : result.xrefs) {
        if (xref.kind == "call")
          std::cout << hex(xref.from) << " -> " << hex(xref.to) << '\n';
      }
      return 0;
    }

    if (command == "xrefs") {
      for (const auto &xref : result.xrefs)
        std::cout << hex(xref.from) << " -> " << hex(xref.to) << " "
                  << xref.kind << '\n';
      return 0;
    }

    if (command == "decompile") {
      caraxes::decompiler::ProjectOptions options;
      options.function_names = function_names(seeds);
      options.data_names = data_names(file);
      for (const auto &[address, name] : imported_plt_names(file))
        options.function_names[address] = name;
      for (const auto &function : result.functions)
        options.function_names[function.address] = function.name;
      const auto project = caraxes::decompiler::decompile_project(
          file, *section, result, options);
      write_export(output_path,
                   json ? project.json : project.code,
                   argv[binary_index]);
      return 0;
    }

    if (command == "report") {
      std::cout << caraxes::analysis::report(result);
      return 0;
    }

    usage();
    return 1;
  } catch (const std::exception &error) {
    std::cerr << "error: " << error.what() << '\n';
    return 1;
  }
}
