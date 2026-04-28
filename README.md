# dbger.c

`dbger.c` is an x86_64 debugger and disassembler for Linux, written from the ground up in C. 

## Overview

The project consists of two main components:
- **Debugger**: An early-stage debugger targeting x86_64 binaries (work in progress).
- **Disassembler**: A static analysis and disassembler library built on top of [Intel XED](https://github.com/intelxed/xed).

## Building

To build the debugger from source, simply run:

```sh
make
```

## Documentation

- **disasm.c**: For deep dives into the disassembler library and usage examples, refer to the [disasm directory](./disasm/).

## Preview

<img width="1214" height="1013" alt="Debugger Preview" src="https://github.com/user-attachments/assets/ec4c8b39-4e31-45a7-8228-89dec927911c" />
