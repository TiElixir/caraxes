# Caraxes

Caraxes is an educational, CLI-first reverse-engineering toolkit for Linux x86-64. It focuses on static analysis of ELF binaries and produces human-readable output suitable for shell pipelines. Machine-readable output is being introduced incrementally.

The project intentionally has no GUI, web UI, TUI, dashboard, or visualization frontend. CFG output can be extended with external Graphviz tooling in future releases.

## Features

- ELF32/ELF64 parsing with little- and big-endian support
- Safe bounds checking for ELF headers, program headers, section headers, string tables, and symbol tables
- ELF section and program-header inspection
- `.symtab` and `.dynsym` symbol extraction
- Printable-string extraction
- Hexdump output
- Virtual-address and file-offset conversion helpers
- x86-64 disassembly through Capstone
- Initial function discovery from entry points and direct call targets
- Basic-block and CFG successor analysis
- Call cross-references
- Minimal architecture-independent IR records
- Educational textual decompiler output

## Requirements

- Linux x86-64
- C++20 compiler
- CMake 3.20 or newer
- Capstone 5 development headers and library
- pkg-config is recommended, but CMake also supports manual Capstone discovery

On Arch Linux, install the dependencies with:

```bash
sudo pacman -S --needed base-devel cmake capstone pkgconf
```

## Build

From the project root:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The build produces:

- `build/caraxes` - unified CLI
- `build/caraxes-analysis` - analysis pipeline utility
- `build/caraxes-disasm` - Capstone disassembly utility

## Usage

General help and version information:

```bash
./build/caraxes --help
./build/caraxes --version
```

Inspect an ELF file:

```bash
./build/caraxes info ./hello
./build/caraxes sections ./hello
./build/caraxes symbols ./hello
./build/caraxes strings ./hello
./build/caraxes hexdump ./hello
```

Running Caraxes with only a binary path is shorthand for decoding the
executable `.text` section:

```bash
./build/caraxes ./hello
```

Each decoded instruction reports its virtual address, bytes, mnemonic, and
operands. Capstone is hidden behind the project-owned `InstructionDecoder`
interface so later architectures or decoder implementations do not leak into
the analysis pipeline.

The `decompile` command now has a small, deterministic C-like expression
recovery pass for common integer functions. It uses Capstone operand metadata,
not an LLM: register arguments follow the System V AMD64 convention, moves and
basic arithmetic are propagated through an abstract register state, and return
values are rendered as expressions. Unsupported instructions are emitted as
explicit comments rather than silently guessed.

For example, a function containing `mov eax, edi; add eax, esi; ret` can be
rendered as:

```c
int add(int arg0, int arg1) {
    return (arg0 + arg1);
}
```

This is intentionally a foundation rather than a complete source recovery
system. Reliable reconstruction of optimized control flow, pointers, types,
stack variables, aliases, loops, switches, and interprocedural semantics
requires additional IR, data-flow, type-inference, and control-flow
structuring passes.

### What can be recovered

The executable contains instruction bytes, addresses, relocation/linkage
metadata, symbols when they were not stripped, and raw data. Compilation does
not preserve the original source-level names, types, comments, or exact control
structure in general. Caraxes therefore treats decompilation as inference:
function boundaries can be proposed from symbols, entry points, and branch
targets; basic blocks are split at control-flow boundaries; and later IR/data
flow passes can recover likely values and stack locations. None of these
inferences should claim to recreate the original source exactly.

The current CFG pass uses decoded control-flow targets and fall-through edges.
It is intentionally explicit rather than hidden behind an external decompiler
library, which makes its assumptions testable as the IR and variable-recovery
passes are expanded.

Disassemble the `.text` section:

```bash
./build/caraxes disasm ./hello
./build/caraxes disasm ./hello --section .text
```

Run the initial analysis pipeline:

```bash
./build/caraxes functions ./hello
./build/caraxes cfg ./hello
./build/caraxes callgraph ./hello
./build/caraxes xrefs ./hello
./build/caraxes decompile ./hello
```

The standalone tools provide focused interfaces:

```bash
./build/caraxes-disasm ./hello
./build/caraxes-analysis ./hello
```

`info` supports JSON output for scripting:

```bash
./build/caraxes info ./hello --json
```

## Architecture

```text
src/
├── analysis/       Function discovery, CFG, xrefs, IR, decompiler
├── disasm/         Capstone-backed x86-64 instruction decoding
├── loader/elf/     ELF representation and safe binary parsing
└── main.cpp        CLI command dispatch and presentation
```

Analysis code is kept separate from CLI presentation wherever practical. The ELF loader owns binary-format concerns, while disassembly and analysis consume loader data through internal representations.

## Testing

The test suite currently covers:

- ELF header, section, program-header, and section-name parsing
- Malformed/truncated ELF rejection
- Basic analysis and control-flow records
- Capstone instruction decoding and ELF `.text` disassembly

Run all tests with:

```bash
ctest --test-dir build --output-on-failure
```

## Current Scope and Limitations

Caraxes is an educational toolkit and does not attempt to reproduce Ghidra's analysis depth. Current analysis is intentionally conservative and incomplete:

- Function discovery is heuristic and does not yet fully reconstruct compiler-generated boundaries.
- CFG construction is an initial basic-block implementation.
- IR and data-flow support are minimal and evolving.
- Decompilation is illustrative and must not be treated as recovered source code.
- JSON output is currently available for the `info` command and will expand as command schemas stabilize.
- Dynamic debugging and ML-assisted analysis are not implemented in the current core.
- The current disassembler targets x86-64 ELF binaries.

## Development Principles

- Keep the project compiling after each milestone.
- Prefer standard C++20 and small, understandable abstractions.
- Use Capstone instead of reimplementing the x86 instruction set.
- Validate malformed input safely before consuming offsets or sizes.
- Keep static analysis independent from CLI formatting.
- Add tests with each major subsystem.
- Do not add frontend or graphical-interface dependencies.

## License

No license has been selected yet. Until a license is added to the repository, all rights remain with the project author.
