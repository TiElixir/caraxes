# Caraxes

Caraxes is a self-contained, CLI-first reverse-engineering toolkit for Linux
ELF64 x86-64 binaries. It provides the core workflow expected from a native
static-analysis workbench without delegating analysis to an external
decompiler:

```text
ELF loader → Capstone disassembly → function/CFG analysis
           → symbols/relocations/xrefs → native C-like recovery
```

The project is intentionally inspectable. Every recovered function is tied to
an address range, every CFG edge is explicit, and unsupported instructions are
preserved as annotated output instead of being silently guessed away.

## Features

### ELF and binary metadata

- ELF32/ELF64 parsing with little- and big-endian integer decoding
- Extended ELF numbering support for large program/section tables
- Bounds and overflow validation for headers, tables, string tables, and data
- Program-header and section inspection
- Static and dynamic symbol extraction
- REL/RELA relocation decoding
- x86-64 PLT name resolution for imported calls
- Virtual-address/file-offset conversion
- Printable-string extraction and bounded hexdumps
- Zero-filled `.bss`/`SHT_NOBITS` section access

### Disassembly and analysis

- Capstone x86-64 decoding with raw bytes, Intel syntax, and operand metadata
- Register, immediate, memory, and RIP-relative operand details
- Explicit invalid-byte records when decoding fails
- Function discovery from entry points, symbols, direct calls, `endbr64`, and
  common function prologues
- Recursive reachable-control-flow analysis
- Basic blocks with predecessor and successor edges
- Direct call graph
- Call, branch, and RIP-relative data cross-references
- Deterministic textual reports and JSON summaries

### Native C-like recovery

The recovery engine is implemented inside Caraxes. It does not invoke another
reverse-engineering product, shell out to an external analyzer, or require a
runtime beyond C++ and Capstone.

It currently recovers:

- System V AMD64 integer arguments from register use
- Register aliases such as `eax`/`rax` and `edi`/`rdi`
- Constant propagation and register assignments
- Integer arithmetic, shifts, comparisons, tests, and zeroing idioms
- `rbp`/`rsp` stack locals
- RIP-relative globals and printable string literals
- Direct and indirect calls
- Conditional branches, labels, returns, and explicit indirect jumps
- Function names, sizes, callers, callees, data references, and CFG metadata

When a higher-level reconstruction would require unsupported assumptions, the
output retains the original instruction address and emits a comment or a
low-level expression. This keeps the result useful for further analysis while
making uncertainty visible.

## Requirements

- Linux x86-64
- C++20 compiler
- CMake 3.20 or newer
- Capstone 5 development headers and library
- `pkg-config` is recommended; CMake also supports manual Capstone discovery

Arch Linux:

```bash
sudo pacman -S --needed base-devel cmake capstone pkgconf
```

Debian or Ubuntu:

```bash
sudo apt install build-essential cmake libcapstone-dev pkg-config
```

## Build and test

From the repository root:

```bash
cmake -S . -B build
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The build produces:

| Binary | Purpose |
| --- | --- |
| `build/caraxes` | Unified loader, disassembler, analyzer, and native recovery CLI |
| `build/caraxes-analysis` | Standalone function/CFG/xref report |
| `build/caraxes-disasm` | Standalone Capstone disassembler |

## CLI usage

General help:

```bash
./build/caraxes --help
./build/caraxes --version
```

Inspect the binary:

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

Disassemble an executable section:

```bash
./build/caraxes disasm ./hello
./build/caraxes disasm ./hello --section .text
./build/caraxes-disasm ./hello .text
```

Analyze functions and relationships:

```bash
./build/caraxes functions ./hello
./build/caraxes functions ./hello --json
./build/caraxes cfg ./hello
./build/caraxes callgraph ./hello
./build/caraxes xrefs ./hello
./build/caraxes report ./hello
./build/caraxes-analysis ./hello
```

Generate the full native recovery output:

```bash
./build/caraxes decompile ./hello > recovered.c
./build/caraxes decompile ./hello --output recovered.c
./build/caraxes decompile ./hello --json --output recovered.json
./build/caraxes decompile ./hello --section .text
```

## Round-trip validation

The repository includes an end-to-end behavior test for the sample program. It
compiles `hello.c`, executes the original binary, recovers `recovered.c` with
Caraxes, compiles the recovered source with strict warnings, executes it, and
compares stdout, stderr, and exit status.

Run it through CTest:

```bash
ctest --test-dir build -R roundtrip --output-on-failure
```

Run the procedure directly:

```bash
python3 tests/roundtrip_test.py build/caraxes hello.c
```

The recovered file is generated in a temporary directory for the test and is
not treated as a repository source file. The renderer adds the required C
headers, declares recovered globals and pseudo-register state, provides safe
fallbacks for unresolved indirect operations, and keeps unsupported native
instructions as comments so the generated translation unit remains compilable.

The `decompile` command includes recovered data declarations, all discovered
functions, address comments, CFG-derived function metadata, direct imported
call names, and explicit instruction-level fallbacks.

For the repository sample, the `add` function is recovered in the form:

```c
int add(int arg0, int arg1) {
    /* 0x1139: push rbp */
    /* ... */
    rax = (local_0x8 + local_0x4);
    return (local_0x8 + local_0x4);
}
```

The JSON decompile schema contains:

- `schema_version` and `engine` (`caraxes-native`)
- executable format and analyzed section
- `functions` with names, addresses, sizes, block/caller/callee counts, and
  recovered code
- `data` with names, addresses, section names, and recovered string literals
- `xrefs` with source, destination, and reference kind
- the complete rendered `code` output

## Architecture

```text
src/
├── loader/elf/       ELF model, validation, symbols, relocations
├── disasm/           Capstone decoder and project-owned operand records
├── analysis/         Function discovery, CFG, callers/callees, xrefs, IR
├── decompiler/       Register recovery and complete project output
└── main.cpp          CLI presentation and command dispatch
tests/
├── elf_loader_test.cpp
├── disasm_test.cpp
├── analysis_test.cpp
└── decompiler_test.cpp
```

The core layers are separate:

1. The loader validates file-owned offsets and exposes ELF structures.
2. The disassembler converts executable bytes to stable Caraxes records.
3. The analyzer builds function and CFG records without relying on symbols
   being present.
4. The decompiler performs deterministic expression and stack recovery.
5. The project renderer combines functions, data, xrefs, and metadata into a
   complete C-like text or JSON artifact.
6. The CLI formats those artifacts for terminal use and shell pipelines.

## Accuracy and boundaries

Caraxes is static analysis software. It does not execute the input binary and
does not claim that inferred output is the original source. Compilation can
remove or transform:

- original local and parameter names
- exact source types, signedness, aliases, and ownership
- comments, macros, templates, and compiler intent
- structured loops and `switch` statements
- runtime-dispatched indirect targets

Function discovery is strongest when symbols, relocation data, or direct call
targets are available. Optimized, stripped, obfuscated, or self-modifying
programs require additional heuristics and may leave more low-level output.
Indirect calls and jumps remain explicitly marked when instruction bytes do not
provide a unique destination.

The analysis and native recovery target is currently ELF64 x86-64. The loader
can inspect ELF32 and big-endian metadata, while architecture-specific
disassembly and recovery intentionally reject unsupported machine formats.

## Development verification

Standard tests:

```bash
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The test suite covers ELF header/table validation, extended numbering,
relocations, `SHT_NOBITS`, Capstone flow metadata, function discovery, CFG
edges, argument inference, arithmetic recovery, project JSON output, and the
compile/recover/recompile/runtime-output round trip.

For an additional sanitizer pass:

```bash
cmake -S . -B build-sanitize \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer'
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
```

## License

No license has been selected yet. Until a license is added to the repository,
all rights remain with the project author.
