#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace caraxes::elf {

enum class Class : std::uint8_t { Elf32 = 1, Elf64 = 2 };
enum class Endian : std::uint8_t { Little = 1, Big = 2 };

struct ProgramHeader {
  std::uint32_t type{};
  std::uint32_t flags{};
  std::uint64_t offset{};
  std::uint64_t virtual_address{};
  std::uint64_t physical_address{};
  std::uint64_t file_size{};
  std::uint64_t memory_size{};
  std::uint64_t alignment{};
};

struct SectionHeader {
  std::uint32_t name_offset{};
  std::uint32_t type{};
  std::uint64_t flags{};
  std::uint64_t address{};
  std::uint64_t offset{};
  std::uint64_t size{};
  std::uint32_t link{};
  std::uint32_t info{};
  std::uint64_t alignment{};
  std::uint64_t entry_size{};
  std::string name;
};

struct Symbol {
  std::string name;
  std::uint64_t value{};
  std::uint64_t size{};
  std::uint8_t info{};
  std::uint8_t other{};
  std::uint16_t section_index{};
  bool dynamic{};
};

struct Relocation {
  std::uint64_t offset{};
  std::uint64_t info{};
  std::uint64_t type{};
  std::uint64_t symbol_index{};
  std::int64_t addend{};
  std::uint32_t section_index{};
  std::string symbol_name;
};

struct Header {
  Class elf_class{};
  Endian endian{};
  std::uint16_t type{};
  std::uint16_t machine{};
  std::uint32_t version{};
  std::uint64_t entry{};
  std::uint64_t program_header_offset{};
  std::uint64_t section_header_offset{};
  std::uint32_t flags{};
  std::uint16_t header_size{};
  std::uint16_t program_header_size{};
  std::uint16_t program_header_count{};
  std::uint16_t section_header_size{};
  std::uint16_t section_header_count{};
  std::uint16_t section_name_string_table_index{};
  // Extended ELF numbering values. For ordinary files these mirror the
  // 16-bit header fields; for PN_XNUM/SHN_XINDEX files they contain the
  // resolved values stored in section header zero.
  std::uint64_t program_header_count_full{};
  std::uint64_t section_header_count_full{};
  std::uint64_t section_name_string_table_index_full{};
};

struct File {
  Header header;
  std::vector<ProgramHeader> program_headers;
  std::vector<SectionHeader> sections;
  std::vector<Symbol> symbols;
  std::vector<Relocation> relocations;
  std::vector<std::uint8_t> bytes;

  const SectionHeader *section(const std::string &name) const;
  std::vector<std::uint8_t> section_bytes(const SectionHeader &section) const;
  std::optional<std::uint64_t> virtual_to_file(std::uint64_t address) const;
  std::optional<std::uint64_t> file_to_virtual(std::uint64_t offset) const;
};

class Error : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};

File parse(const std::vector<std::uint8_t> &bytes);
File parse_file(const std::filesystem::path &path);
const char *class_name(Class value);
const char *endian_name(Endian value);
const char *type_name(std::uint16_t value);
const char *machine_name(std::uint16_t value);

} // namespace caraxes::elf
