#include "decompiler/project.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <set>
#include <stdexcept>
#include <utility>

namespace caraxes::decompiler {
namespace {

std::string hex(std::uint64_t value) {
  std::ostringstream stream;
  stream << "0x" << std::hex << value;
  return stream.str();
}

std::string json_escape(const std::string &value) {
  std::ostringstream stream;
  for (const auto character : value) {
    switch (character) {
    case '"':
      stream << "\\\"";
      break;
    case '\\':
      stream << "\\\\";
      break;
    case '\n':
      stream << "\\n";
      break;
    case '\r':
      stream << "\\r";
      break;
    case '\t':
      stream << "\\t";
      break;
    default:
      if (static_cast<unsigned char>(character) < 0x20)
        stream << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(static_cast<unsigned char>(character))
               << std::setfill(' ') << std::dec;
      else
        stream << character;
      break;
    }
  }
  return stream.str();
}

std::string identifier(std::string value, std::uint64_t address) {
  for (auto &character : value) {
    const auto safe = static_cast<unsigned char>(character);
    if (!std::isalnum(safe) && character != '_')
      character = '_';
  }
  if (value.empty()) {
    std::ostringstream stream;
    stream << "global_" << std::hex << address;
    value = stream.str();
  }
  if (std::isdigit(static_cast<unsigned char>(value.front())))
    value.insert(value.begin(), '_');
  return value;
}

std::string call_name(std::uint64_t address,
                      const std::map<std::uint64_t, std::string> &names) {
  const auto named = names.find(address);
  if (named != names.end())
    return identifier(named->second, address);
  std::ostringstream stream;
  stream << "sub_" << std::hex << address;
  return stream.str();
}

bool has_standard_declaration(const std::string &name) {
  static const std::set<std::string> names{
      "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar",
      "malloc", "calloc", "realloc", "free", "memcpy", "memmove",
      "memset", "memcmp", "strcmp", "strncmp", "strlen", "abort",
      "exit", "atexit"};
  return names.contains(name);
}

std::string escaped_c_string(const std::vector<std::uint8_t> &bytes,
                             std::size_t start) {
  std::ostringstream stream;
  stream << '"';
  for (std::size_t i = start; i < bytes.size() && bytes[i] != 0; ++i) {
    const auto byte = bytes[i];
    switch (byte) {
    case '\\':
      stream << "\\\\";
      break;
    case '"':
      stream << "\\\"";
      break;
    case '\n':
      stream << "\\n";
      break;
    case '\r':
      stream << "\\r";
      break;
    case '\t':
      stream << "\\t";
      break;
    default:
      if (std::isprint(static_cast<unsigned char>(byte)))
        stream << static_cast<char>(byte);
      else {
        stream << "\\x" << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(byte) << std::setfill(' ') << std::dec;
      }
      break;
    }
  }
  stream << '"';
  return stream.str();
}

const elf::SectionHeader *containing_section(
    const elf::File &file, std::uint64_t address) {
  for (const auto &section : file.sections) {
    if (section.size == 0 || address < section.address)
      continue;
    if (address - section.address < section.size)
      return &section;
  }
  return nullptr;
}

std::vector<std::uint8_t> function_bytes(
    const elf::File &file, const elf::SectionHeader &section,
    const analysis::Function &function) {
  if (function.address < section.address ||
      function.address - section.address >= section.size)
    return {};
  const auto start = function.address - section.address;
  if (section.offset > file.bytes.size() ||
      start > file.bytes.size() - section.offset)
    return {};
  const auto section_available = file.bytes.size() -
                                 static_cast<std::size_t>(section.offset + start);
  const auto available = std::min<std::uint64_t>(section.size - start,
                                                  section_available);
  const auto requested = function.size == 0
                             ? available
                             : std::min<std::uint64_t>(function.size, available);
  if (requested > std::numeric_limits<std::size_t>::max())
    return {};
  const auto offset = static_cast<std::size_t>(section.offset + start);
  const auto length = static_cast<std::size_t>(requested);
  return {file.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
          file.bytes.begin() + static_cast<std::ptrdiff_t>(offset + length)};
}

std::map<std::uint64_t, std::string> symbol_names(const elf::File &file) {
  std::map<std::uint64_t, std::string> result;
  for (const auto &symbol : file.symbols) {
    if (symbol.name.empty() || symbol.value == 0)
      continue;
    const auto type = static_cast<std::uint8_t>(symbol.info & 0x0f);
    if (type == 2 || type == 10)
      continue;
    result.emplace(symbol.value, identifier(symbol.name, symbol.value));
  }
  return result;
}

std::vector<RecoveredData> recover_data(
    const elf::File &file, const analysis::Analysis &analysis,
    const ProjectOptions &options) {
  std::set<std::uint64_t> addresses;
  for (const auto &xref : analysis.xrefs)
    if (xref.kind == "data")
      addresses.insert(xref.to);
  for (const auto &[address, name] : options.data_names)
    static_cast<void>(addresses.insert(address));

  const auto symbols = symbol_names(file);
  std::vector<RecoveredData> result;
  for (const auto address : addresses) {
    const auto *section = containing_section(file, address);
    if (!section)
      continue;
    const auto offset = address - section->address;
    const auto name_it = options.data_names.find(address);
    const auto symbol_it = symbols.find(address);
    const auto name = name_it != options.data_names.end()
                          ? identifier(name_it->second, address)
                          : symbol_it != symbols.end()
                                ? symbol_it->second
                                : identifier({}, address);
    RecoveredData data{address, name, section->name, {}, false};
    if (section->type == 8) {
      result.push_back(std::move(data));
      continue;
    }
    if (offset > section->size || section->offset > file.bytes.size() ||
        offset > file.bytes.size() - section->offset)
      continue;
    const auto file_offset = static_cast<std::size_t>(section->offset + offset);
    const auto available = std::min<std::uint64_t>(section->size - offset,
                                                    file.bytes.size() - file_offset);
    if (available >= 4) {
      const auto end = static_cast<std::size_t>(available);
      const auto nul = std::find(file.bytes.begin() + file_offset,
                                 file.bytes.begin() + file_offset + end,
                                 static_cast<std::uint8_t>(0));
      const auto length = static_cast<std::size_t>(nul - (file.bytes.begin() + file_offset));
      bool printable = length >= 4;
      for (std::size_t i = 0; printable && i < length; ++i)
        printable = std::isprint(
                        static_cast<unsigned char>(file.bytes[file_offset + i])) != 0 ||
                    file.bytes[file_offset + i] == '\n' ||
                    file.bytes[file_offset + i] == '\r' ||
                    file.bytes[file_offset + i] == '\t';
      if (printable) {
        data.value = escaped_c_string(file.bytes, file_offset);
        data.string_literal = true;
      }
    }
    result.push_back(std::move(data));
  }
  return result;
}

} // namespace

ProjectResult decompile_project(const elf::File &file,
                                const elf::SectionHeader &executable_section,
                                const analysis::Analysis &analysis,
                                const ProjectOptions &options) {
  ProjectResult result;
  result.data = recover_data(file, analysis, options);

  Options function_options;
  function_options.function_names = options.function_names;
  function_options.data_names = options.data_names;
  function_options.include_address_comments = options.include_address_comments;
  for (const auto &function : analysis.functions)
    function_options.function_names[function.address] = function.name;

  std::ostringstream code;
  code << "/* Caraxes self-contained reverse-engineering output. */\n"
       << "/* Format: " << elf::class_name(file.header.elf_class) << " "
       << elf::machine_name(file.header.machine) << ", section "
       << executable_section.name << " at " << hex(executable_section.address)
       << ". */\n"
       << "/* Expressions are inferred; unsupported operations remain annotated. */\n\n";

  code << "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\n"
       << "static uintptr_t call_indirect(uintptr_t target, ...) {\n"
       << "    (void)target;\n    return 0;\n}\n\n";

  std::set<std::uint64_t> defined_addresses;
  std::set<std::string> fallback_calls;
  for (const auto &function : analysis.functions)
    defined_addresses.insert(function.address);
  for (const auto &xref : analysis.xrefs) {
    if (xref.kind != "call" || defined_addresses.contains(xref.to))
      continue;
    const auto name = call_name(xref.to, options.function_names);
    if (!has_standard_declaration(name) && fallback_calls.insert(name).second)
      code << "static uintptr_t " << name
           << "(uintptr_t value, ...) { (void)value; return 0; }\n";
  }
  if (!fallback_calls.empty())
    code << '\n';

  if (!result.data.empty()) {
    code << "/* Recovered data references */\n";
    for (const auto &data : result.data) {
      if (data.string_literal)
        code << "static const char " << data.name
             << "[] __attribute__((unused)) = " << data.value
             << "; /* " << hex(data.address) << " " << data.section << " */\n";
      else if (data.section == ".bss" || data.section == ".data" ||
               data.section == ".got" || data.section == ".got.plt" ||
               data.section == ".dynamic" || data.section.empty() ||
               (file.section(data.section) &&
                (file.section(data.section)->flags & 0x4) != 0))
        code << "static uintptr_t " << data.name
             << " __attribute__((unused)) = 0; /* " << hex(data.address)
             << " " << data.section << " */\n";
      else
        code << "extern unsigned char " << data.name << "[]; /* "
             << hex(data.address) << " " << data.section << " */\n";
    }
    code << '\n';
  }

  for (const auto &data : result.data)
    function_options.data_names[data.address] = data.name;

  for (const auto &function : analysis.functions) {
    const auto bytes = function_bytes(file, executable_section, function);
    if (bytes.empty())
      continue;
    auto function_code =
        decompile(bytes, function.address, function.name, function_options);
    if (function_code.name != "main") {
      const auto marker = "int " + function_code.name + "(";
      const auto replacement =
          "static __attribute__((unused)) int " + function_code.name + "(";
      const auto position = function_code.code.find(marker);
      if (position != std::string::npos)
        function_code.code.replace(position, marker.size(), replacement);
    }
    result.functions.push_back({function.name, function.address, function.size,
                                function.blocks.size(), function.callers.size(),
                                function.callees.size(), function_code.code});
    code << "/* function " << function.name << " @ " << hex(function.address)
         << " size=" << function.size << " blocks=" << function.blocks.size()
         << " callers=" << function.callers.size()
         << " callees=" << function.callees.size() << " */\n"
         << function_code.code << '\n';
  }
  result.code = code.str();

  std::ostringstream json;
  json << "{\"schema_version\":1,\"engine\":\"caraxes-native\","
       << "\"format\":\"" << json_escape(elf::class_name(file.header.elf_class))
       << " " << json_escape(elf::machine_name(file.header.machine))
       << "\",\"section\":\"" << json_escape(executable_section.name)
       << "\",\"functions\":[";
  for (std::size_t i = 0; i < result.functions.size(); ++i) {
    const auto &function = result.functions[i];
    if (i != 0)
      json << ',';
    json << "{\"name\":\"" << json_escape(function.name)
         << "\",\"address\":" << function.address
         << ",\"size\":" << function.size
         << ",\"blocks\":" << function.blocks
         << ",\"callers\":" << function.callers
         << ",\"callees\":" << function.callees
         << ",\"code\":\"" << json_escape(function.code) << "\"}";
  }
  json << "],\"data\":[";
  for (std::size_t i = 0; i < result.data.size(); ++i) {
    const auto &data = result.data[i];
    if (i != 0)
      json << ',';
    json << "{\"address\":" << data.address << ",\"name\":\""
         << json_escape(data.name) << "\",\"section\":\""
         << json_escape(data.section) << "\",\"value\":\""
         << json_escape(data.value) << "\",\"string_literal\":"
         << (data.string_literal ? "true" : "false") << "}";
  }
  json << "],\"xrefs\":[";
  for (std::size_t i = 0; i < analysis.xrefs.size(); ++i) {
    const auto &xref = analysis.xrefs[i];
    if (i != 0)
      json << ',';
    json << "{\"from\":" << xref.from << ",\"to\":" << xref.to
         << ",\"kind\":\"" << json_escape(xref.kind) << "\"}";
  }
  json << "],\"code\":\"" << json_escape(result.code) << "\"}\n";
  result.json = json.str();
  return result;
}

} // namespace caraxes::decompiler
