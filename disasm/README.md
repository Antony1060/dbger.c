## disasm.c
A quite basic x86_64 disassembler library intended for use in the debugger that I'm making.

### Building
```sh
make clean && make
```

### Basic usage
All structs can be found in [disasm.h](./disasm.h)
```c
// elf_data should be somewhere on the heap, or at least alive while disasm_ctx_t is used by something
//  disasm_ctx_t points to sections in it
void *elf_data = /* raw ELF data*/;

disasm_ctx_t *ctx;

if (disasm_from_elf(&ctx, elf_data) < 0) {
    printf("Failed to disassemble");
    exit(1);
}

for (size_t i = 0; i < ctx->n_sections; i++) {
    disasm_section_t *section = &ctx->sections[i];

    printf("section %s (%lu (%zu)):\n", section->name, section->code_start, section->size);
    for (size_t j = 0; j < section->n_symbols; j++) {
        disasm_symbol_t *sym = &section->symbols[j];

        printf("\t %p: %s\n", sym->addr, sym->name);
    }

    for (size_t j = 0; j < section->n_instructions; j++) {
        disasm_instruction_t *inst = &section->instructions[j];

        printf("instruction at %p: %s\t%s\n", (void *) inst->addr, inst->inst_name, inst->inst_args);
        if (inst->is_branch_like)
            printf("\tis branch\n");

        if (inst->has_branch_meta) {
            disasm_branch_meta_t *branch = &inst->branch_meta;
            
            if (branch->pretty_target[0])
                printf("\t%s", branch->pretty_target);

            printf("\t# 0x%lx\n", branch->resolved_addr);
        }
    }
}

disasm_free(ctx);
```

### Examples
There's currently one example of how the library can be used, it's just a simple CLI that will accept an ELF file and print out the disassembly.

#### Building
```sh
make examples
```

#### Usage
```sh
# disassembles itself, recommended to run with less because output can be quite big
./build/examples/cli ./build/examples/cli | less -r
```