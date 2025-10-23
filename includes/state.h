#ifndef __DBGER_STATE
#define __DBGER_STATE

#include<disasm/disasm.h>

#include "maps.h"

typedef struct {
    pid_t pid;
    char *target_pathname;
    struct user_regs_struct *regs;
    disasm_ctx_t *d_ctx;
    proc_map_array *maps;
} state_ctx;

void print_state(state_ctx *ctx);

#endif // __DBGER_STATE
