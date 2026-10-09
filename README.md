
# Caraxes

<table>
  <tr>
    <td width="240" align="center" valign="middle">
      <img src="https://github.com/user-attachments/assets/8f2b99da-6573-4d9d-8810-537af607d3f5" width="220" alt="Caraxes logo" />
    </td>
    <td valign="middle">
      <p><strong>Caraxes</strong> is a self-contained, CLI-first reverse-engineering toolkit for Linux ELF64 x86-64 binaries.</p>
      <p>It provides the core workflow expected from a native static-analysis workbench without delegating analysis to an external decompiler.</p>
    </td>
  </tr>
</table>

<p align="left">
  <a href="https://isocpp.org/"><img src="https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square&logo=c%2B%2B&logoColor=white" alt="C++20" /></a>
  <a href="https://cmake.org/"><img src="https://img.shields.io/badge/CMake-3.20%2B-064F8C?style=flat-square&logo=cmake&logoColor=white" alt="CMake 3.20 or newer" /></a>
  <a href="https://www.capstone-engine.org/"><img src="https://img.shields.io/badge/Capstone-x86--64-4C8BF5?style=flat-square" alt="Capstone x86-64" /></a>
  <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux" /></a>
  <img src="https://img.shields.io/badge/engine-Caraxes%20native-8A2BE2?style=flat-square" alt="Caraxes native engine" />
</p>

```text
ELF loader → Capstone disassembly → function/CFG analysis
           → symbols/relocations/xrefs → native C-like recovery
```

Caraxes is built as an inspectable analysis pipeline. Functions retain address
provenance, CFG edges remain explicit, and unsupported instructions are emitted
as annotated evidence rather than silently converted into guesses.

## At a glance

| Area | What Caraxes provides |
| --- | --- |
| Binary format | Bounds-checked ELF32/ELF64 headers, sections, segments, symbols, relocations, and `SHT_NOBITS` data |
| Disassembly | Capstone-backed x86-64 instructions, bytes, operands, targets, and invalid-byte preservation |
| Analysis | Function discovery, recursive CFGs, callers/callees, callgraph edges, and data xrefs |
| Recovery | Native register, stack-local, arithmetic, branch, call, and string/global recovery |
| Automation | Text reports, JSON artifacts, strict GCC round-trip testing, and sanitizer coverage |

## Quick start

Install dependencies, configure, build, and run the complete test workflow:

```bash
# Debian / Ubuntu
sudo apt install build-essential cmake libcapstone-dev pkg-config

cmake -S . -B build
make -C build test
```

`make test` builds Caraxes and its test executables before running CTest. The
round-trip test compiles the current `hello.c`, recovers `recovered.c`, compiles
the recovered source with GCC and `-Wall -Wextra -Werror`, then compares both
programs using deterministic input.

## Capabilities

### ELF metadata

- Little- and big-endian ELF32/ELF64 integer decoding
- Extended numbering for large program and section tables
- Bounds and overflow validation before every binary-owned read
- Program headers, sections, symbols, and REL/RELA relocations
- x86-64 PLT/import name recovery
- Virtual-address/file-offset conversion
- Printable strings, bounded hexdumps, and zero-filled `.bss` access

### Disassembly and analysis

- Intel-style x86-64 disassembly with raw instruction bytes
- Register, immediate, memory, and RIP-relative operand metadata
- Explicit invalid-byte records when decoding fails
- Function seeds from entry points, symbols, direct calls, `endbr64`, and
  common compiler prologues
- Recursive reachable-control-flow traversal
- Basic blocks with predecessor and successor edges
- Direct callgraph and call-site cross-references
- Branch and RIP-relative data references
- Deterministic terminal reports and JSON summaries

### Native recovery

The recovery engine runs entirely inside Caraxes. It does not invoke another
reverse-engineering product or shell out to an external analyzer.

It recovers common System V AMD64 patterns including:

- Integer arguments and register aliases (`eax`/`rax`, `edi`/`rdi`)
- Constant propagation and register-transfer expressions
- Integer arithmetic, shifts, comparisons, tests, and zeroing idioms
- `rbp`/`rsp` stack locals and address-taking for input pointers
- RIP-relative globals and printable format strings
- Direct calls with inferred internal arity
- Format-aware `printf`/`scanf` argument emission
- Conditional branches, labels, returns, and safe indirect fallbacks

When source-level reconstruction would require unsupported assumptions, the
output keeps the machine-level instruction comment and marks the uncertainty.

## Requirements

- Linux x86-64
- GCC or another C++20 compiler
- CMake 3.20 or newer
- GNU Make or another CMake-supported build tool
- Capstone development headers and library
- Python 3 for the round-trip test
- `pkg-config` recommended for Capstone discovery

Arch Linux:

```bash
sudo pacman -S --needed base-devel cmake capstone pkgconf python
```

Debian or Ubuntu:

```bash
sudo apt install build-essential cmake libcapstone-dev pkg-config python3
```

## Build outputs

| Binary | Purpose |
| --- | --- |
| `build/caraxes` | Unified loader, disassembler, analyzer, and native recovery CLI |
| `build/caraxes-analysis` | Standalone function, CFG, and xref report |
| `build/caraxes-disasm` | Standalone Capstone disassembler |

## Command reference

### General

```bash
./build/caraxes --help
./build/caraxes --version
```

### Inspect an ELF

```bash
./build/caraxes info ./hello
./build/caraxes info ./hello --json
./build/caraxes segments ./hello
./build/caraxes sections ./hello
./build/caraxes symbols ./hello
./build/caraxes relocations ./hello
./build/caraxes strings ./hello
./build/caraxes hexdump ./hello --limit 256
```

### Disassemble and analyze

```bash
./build/caraxes disasm ./hello --section .text
./build/caraxes functions ./hello --json
./build/caraxes cfg ./hello
./build/caraxes callgraph ./hello
./build/caraxes xrefs ./hello
./build/caraxes report ./hello
./build/caraxes-analysis ./hello
./build/caraxes-disasm ./hello .text
```

### Recover C-like output

```bash
./build/caraxes decompile ./hello --output recovered.c
./build/caraxes decompile ./hello --json --output recovered.json
./build/caraxes decompile ./hello --section .text
```

The generated source includes C headers, recovered data declarations, pseudo-
register state, stack locals, function metadata, address comments, imported
call names, and compilable fallbacks for unsupported operations.

Example recovered arithmetic:

```c
int add(int arg0, int arg1) {
    /* 0x1139: push rbp */
    /* ... */
    rax = (local_0x8 + local_0x4);
    return (local_0x8 + local_0x4);
}
```

## Round-trip validation

Run the complete compile → recover → compile → compare procedure:

```bash
cmake -S . -B build
make -C build test
```

Run only the end-to-end test:

```bash
ctest --test-dir build -R roundtrip --output-on-failure
```

Or invoke the procedure directly:

```bash
python3 tests/roundtrip_test.py build/caraxes hello.c
```

The current interactive sample is tested with `12` and `30`, producing:

```text
Enter a number: Enter another number: The sum of 12 and 30 is: 42
```

The test compares stdout, stderr, and exit status between the original and
recovered executables. Its generated files live in a temporary directory.

## JSON output

`decompile --json` emits a `caraxes-native` artifact containing:

- `schema_version`, `engine`, executable format, and analyzed section
- `functions` with names, addresses, sizes, block/caller/callee counts, and code
- `data` with addresses, names, sections, and recovered string literals
- `xrefs` with source, destination, and reference kind
- the complete rendered `code` field

## Architecture

```text
src/
├── loader/elf/       ELF model, validation, symbols, relocations
├── disasm/           Capstone decoder and operand records
├── analysis/         Function discovery, CFG, xrefs, callers/callees, IR
├── decompiler/       Register recovery and complete project renderer
└── main.cpp          CLI presentation and command dispatch
tests/
├── elf_loader_test.cpp
├── disasm_test.cpp
├── analysis_test.cpp
├── decompiler_test.cpp
└── roundtrip_test.py
```

The pipeline is deliberately layered:

1. The loader validates and exposes ELF structures.
2. The disassembler creates stable Caraxes instruction records.
3. The analyzer discovers functions and builds CFG/xref records.
4. The native decompiler recovers expressions, locals, calls, and returns.
5. The project renderer combines code, data, metadata, and JSON output.
6. The CLI exposes the results for terminal use and shell pipelines.

## Accuracy and boundaries

Caraxes is static analysis software. It does not execute the input binary and
does not claim that inferred output is the original source. Compilation can
remove or transform original names, exact types, signedness, comments, macros,
structured loops, switch statements, and runtime indirect targets.

Function discovery is strongest when symbols, relocations, or direct calls are
available. Optimized, stripped, obfuscated, and self-modifying programs may
produce more low-level output. Indirect calls and jumps remain explicitly
marked when instruction bytes do not identify a unique destination.

The architecture-specific analysis target is currently ELF64 x86-64. The
loader can inspect broader ELF metadata, while disassembly and recovery reject
unsupported machine formats.

## Development verification

Standard suite:

```bash
make -C build test
```

Sanitizer suite:

```bash
cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
make -C build-sanitize test
```

## License

No license has been selected yet. Until a license is added to the repository,
all rights remain with the project author.
