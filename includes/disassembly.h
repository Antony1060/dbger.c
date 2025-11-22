#ifndef __DBGER_DISASSEMBLY
#define __DBGER_DISASSEMBLY

#include "state.h"

typedef struct {
    uint64_t addr;
    size_t size;
    char *name;
    char *args;
    char *symbol_name;
    size_t symbol_offset;
    uint64_t jump_target;
    char *pretty_target;
} basic_instruction;

int open_and_disasm(disasm_ctx_t *ctx, void **_elf_data, size_t *stat_size, const char *target_pathname);

void instruction_convert_from_disasm(disasm_instruction_t *inst, uint64_t addr, basic_instruction *_inst);

ssize_t find_rich_instruction_in_map(state_ctx *ctx, uint64_t addr, proc_map *map, disasm_section_t **section, disasm_instruction_t **_inst);

int disassemble_remote_at_addr(pid_t pid, uint64_t addr, basic_instruction *_inst, char* work_buf, char *work_name, char *work_args);

#endif // __DBGER_DISASSEMBLY
