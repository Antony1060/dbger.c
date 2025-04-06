#define _GNU_SOURCE

#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<string.h>
#include<sys/wait.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/uio.h>
#include<linux/ptrace.h>
#include<stdbool.h>
#include<stdint.h>
#include<xed/xed-interface.h>

#include "ansi.c"

#define PRINT_REGS 0

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

void print_instruction(pid_t pid, unsigned long long rip) {
    // 16 bytes, instruction can be up to 15 bytes of size, so we take 2 words (each 8 bytes)
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
        fprintf(stderr, "\t" HRED "error (unrecognized instruction)" CRESET "\n");
        return;
    }

    char buf[128];
    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 128, (const xed_uint64_t) rip, 0, 0)) {
        fprintf(stderr, "ERROR: xed_format_context()\n");
        exit(1);
    }

    fprintf(stderr, "" HBLU "%s" CRESET "\n", buf);
}

void print_regs(pid_t pid) {
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
        errquit("ptrace(PTRACE_GETREGS)");

    fprintf(stderr, HYEL "0x%llx" HBLK ": " CRESET, regs.rip);

    #define printreg(reg) fprintf(stderr, "\t" GRN #reg HBLK ": " BLU "0x%llx " HBLK "(" CYN "%lld" HBLK ") " CRESET "\n", regs.reg, regs.reg);

    print_instruction(pid, regs.rip);

    if (PRINT_REGS) {
        printreg(rax);
        printreg(rcx);
        printreg(rdx);
        printreg(rsi);
        printreg(rdi);
        printreg(rip);
        printreg(rsp);
        fprintf(stderr, "\n");
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command...>\n", argv[0]);
        return 1;
    }

    xed_tables_init();

    pid_t pid = fork();
    if (pid == 0) {
        if (execvp(argv[1], argv + 1) < 0)
            errquit("Failed to start process");

        return 0;
    }

    fprintf(stderr, "Tracing: %d\n", pid);

    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) < 0)
        errquit("ptrace(PTRACE_ATTACH)");

    int wstatus;
    while (1) {
        if (waitpid(pid, &wstatus, WCONTINUED) < 0)
            errquit("Failed to wait for process");

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            fprintf(stderr, "\nProcess exit: %d\n", WEXITSTATUS(wstatus));
            break;
        }

        if (WIFSTOPPED(wstatus)) {
            int signal = WSTOPSIG(wstatus);
            if (signal == SIGTRAP) {
                print_regs(pid);
            } else {
                fprintf(stderr, "Signal: %d (SIG%s)\n", signal, sigabbrev_np(signal));
            }
        }

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");
    }

    return 0;
}
