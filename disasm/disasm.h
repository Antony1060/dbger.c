#ifndef __DISASM_H
#define __DISASM_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    union {
        uint32_t value;
        uint8_t bytes[4];
    } ei_magic;
    uint8_t ei_class;
    uint8_t ei_data;
    uint8_t ei_version;
    uint8_t ei_osabi;
    uint8_t ei_abiversion;
    uint8_t ei_pad[7];
} disasm_elf_ident_t;

typedef struct {
    // pointer to some location in elf binary
    char *name;
    uintptr_t addr;
} disasm_symbol_t;

typedef struct {
    uintptr_t resolved_addr;

    disasm_symbol_t *symbol;
    size_t symbol_offset;

    bool is_plt;
    bool is_got;

    char *pretty_target;
} disasm_branch_meta_t;

typedef struct {
    uintptr_t addr;

    // pointer to some location in elf binary
    uint8_t *inst_raw;
    size_t inst_size;

    char *inst_name;
    char *inst_args;

    disasm_symbol_t *closest_symbol;
    size_t closest_symbol_offset;

    bool is_branch_like;
    bool has_branch_meta;
    disasm_branch_meta_t branch_meta;
} disasm_instruction_t;

typedef struct {
    // pointer to some location in elf binary
    char *name;

    uintptr_t code_start;
    size_t size;

    disasm_symbol_t *symbols;
    size_t n_symbols;

    disasm_instruction_t *instructions;
    size_t n_instructions;
} disasm_section_t;

typedef struct {
    disasm_elf_ident_t elf_ident;
    disasm_section_t *sections;
    size_t n_sections;
} disasm_ctx_t;

int disasm_from_elf(disasm_ctx_t **out, void *elf_data);

void free_instruction(disasm_instruction_t *inst);

void free_section(disasm_section_t *section);

void disasm_free(disasm_ctx_t *ctx);

// internal functions
size_t __disasm_read_first_instruction(uint8_t *code, size_t code_len, char* buffer, size_t len, void *ip, uint64_t* jump_target, xed_category_enum_t* category);

void __disasm_color_instruction(char* buffer, char* name, char* args);

#endif // __DISASM_H
