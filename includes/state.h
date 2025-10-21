#ifndef __DBGER_STATE
#define __DBGER_STATE

#include<disasm/disasm.h>

typedef struct {
    pid_t pid;
    struct user_regs_struct *regs;
    disasm_ctx_t *d_ctx;
    // inst will have n_sections items of arrays of section->size (code_start to code_end)
    disasm_instruction_t ***inst;
    proc_map *maps;
} state_ctx;

void print_state(state_ctx ctx);

#endif // __DBGER_STATE
