#include <fstream>
#include <iostream>

bool isELF(const char magic[]);
const char *getClass(unsigned char c);
const char *getData(unsigned char c);
const char *getType(unsigned short type);

const char *getMachine(unsigned short machine);

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cout << "Invalid usage\n";
    return 1;
  }
  std::ifstream file(argv[1], std::ios::binary);
  // fail to open
  if (!file) {
    std::cout << "Could not open file!\n";
    return 1;
  }

  // magic number checker
  // magic number is a number which basically tells us what type of file is
  // this, generally first 4
  char magic[4];
  file.read(magic, 4);

  // we check if its an ELF file or nah
  if (isELF(magic)) {
    std::cout << "YES\n";
  } else {
    std::cout << "NO\n";
    return 0;
  }
  // ELF
  //
  //
  char elf_class;
  file.read(&elf_class, 1);

  std::cout << "Class: " << getClass((unsigned char)elf_class) << '\n';
  // DATA
  //
  //
  char elf_data;
  file.read(&elf_data, 1);
  std::cout << "Data: " << getData((unsigned char)elf_data) << '\n';
  // TYPE
  //
  //
  file.seekg(0x10);
  unsigned char type[2];
  file.read(reinterpret_cast<char *>(type), 2);
  unsigned short typeValue = type[0] | (type[1] << 8);
  // std::cout << "Type: " << std::hex << (int)type[0] << " " << (int)type[1] <<
  // '\n';

  std::cout << "Type: " << getType(typeValue) << '\n';

  file.seekg(0x12);

  unsigned char machine[2];
  file.read(reinterpret_cast<char *>(machine), 2);

  unsigned short machineValue = machine[0] | (machine[1] << 8);
  std::cout << std::dec;
  std::cout << "Machine: " << getMachine(machineValue) << '\n';

  file.seekg(0x18);

  unsigned char entry[8];
  file.read(reinterpret_cast<char *>(entry), 8);
  unsigned long long entryValue = 0;

  for (int i = 0; i < 8; i++) {
    entryValue |= (unsigned long long)entry[i] << (8 * i);
  }
  std::cout << "Entry: 0x" << std::hex << entryValue << '\n';
}

bool isELF(const char magic[]) {
  if ((unsigned char)magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' &&
      magic[3] == 'F') {
    return true;
  } else {
    return false;
  }
}

const char *getClass(unsigned char c) {
  if (c == 1)
    return "ELF32";
  if (c == 2)
    return "ELF64";
  return "Unknown";
}

const char *getData(unsigned char c) {
  if (c == 1)
    return "Little Endian";
  if (c == 2)
    return "Big Endian";
  return "Unknown";
}

const char *getType(unsigned short type) {
  if (type == 1)
    return "REL";
  if (type == 2)
    return "EXEC";
  if (type == 3)
    return "DYN";
  return "Unknown";
}

const char *getMachine(unsigned short machine) {
  if (machine == 62)
    return "x86-64";

  return "Unknown";
}
