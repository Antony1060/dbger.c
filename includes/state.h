#ifndef __DBGER_STATE
#define __DBGER_STATE

#include<disasm/disasm.h>

typedef struct {
    pid_t pid;
    struct user_regs_struct *regs;
    disasm_instruction_t **inst;
} state_ctx;

void print_state(state_ctx ctx);

#endif // __DBGER_STATE
