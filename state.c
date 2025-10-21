#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/uio.h>
#include<xed/xed-interface.h>

#include "ansi.h"
#include "util.h"
#include "state.h"

static void print_instruction(pid_t pid, unsigned long long rip) {
    uint8_t inst[15];
    struct iovec remote_inst = { (void*) rip, 15 };
    struct iovec local_inst = { &inst, 15 };

    ssize_t b_read = process_vm_readv(pid, &local_inst, 1, &remote_inst, 1, 0);

    xed_decoded_inst_t xedd;
    ssize_t i;
    for (i = 0; i < b_read; i++) {
        xed_error_enum_t xed_error;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

        xed_error = xed_decode(&xedd, (const xed_uint8_t *) inst, i);
        if (xed_error == XED_ERROR_NONE)
            break;
    }

    if (i >= b_read) {
        printf("\t" HRED "error (unrecognized instruction)" CRESET "\n");
        return;
    }

    char buf[128];
    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 128, (const xed_uint64_t) rip, 0, 0)) {
        fprintf(stderr, "ERROR: xed_format_context()\n");
        exit(1);
    }

    printf("" HBLU "%s" CRESET "\n", buf);
}

void print_regs(state_ctx ctx) {
    #define printreg(reg) printf("\t" GRN #reg HBLK ": " BLU "0x%llx " HBLK "(" CYN "%lld" HBLK ") " CRESET "\n", ctx.regs->reg, ctx.regs->reg);

    printreg(rax);
    printreg(rcx);
    printreg(rdx);
    printreg(rsi);
    printreg(rdi);
    printreg(rip);
    printreg(rsp);
    printreg(rbp);
}

void print_stack(state_ctx ctx) {
    (void) ctx;
}

void print_call_trace(state_ctx ctx) {
    (void) ctx;
}

void print_disassembly(state_ctx ctx) {
    print_instruction(ctx.pid, ctx.regs->rip);
}

static inline void print_separator(const char * title) {
    printf(HBLK "-- " BWHT "%-12s" HBLK " ----------------" CRESET "\n", title);
}

void print_state(state_ctx ctx) {
    print_separator("registers");
    print_regs(ctx);
    print_separator("stack");
    print_stack(ctx);
    print_separator("call trace");
    print_call_trace(ctx);
    print_separator("disassembly");
    print_disassembly(ctx);
    print_separator("end");
}
