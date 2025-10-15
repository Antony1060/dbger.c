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
#include "maps.c"

#define PRINT_REGS 1

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

static inline size_t min(size_t a, size_t b) {
    return (a < b ? a : b);
}

uint8_t INT3 = 0xCC;

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
        printreg(rbp);
        printreg(rip);
        fprintf(stderr, "\n");
    }
}

int get_pid_pathname(pid_t pid, char *pathname, size_t n) {
    char file_name[64];
    snprintf(file_name, 64, "/proc/%d/exe", pid);

    return readlink(file_name, pathname, n);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command...>\n", argv[0]);
        return 1;
    }

    xed_tables_init();

    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace(PTRACE_TRACEME)");

        if (raise(SIGSTOP) != 0) {
            fprintf(stderr, "raise failed\n");
            return 1;
        }

        if (execvp(argv[1], argv + 1) < 0)
            errquit("Failed to start process");

        return 0;
    }

    // wait for SIGSTOP
    if (waitpid(pid, NULL, 0) < 0)
        errquit("Failed to wait for process");

    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) < 0)
        errquit("ptrace(PTRACE_SETOPTIONS)");

    // continue until execve
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
        errquit("ptrace(PTRACE_CONT)");

    int wstatus;
    while (1) {
        if (waitpid(pid, &wstatus, 0) < 0)
            errquit("Failed to wait for process");

        if (WIFSTOPPED(wstatus) && (wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)))
            break;

        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_CONT)");
    }

    // don't care about exec anymore
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) < 0)
        errquit("ptrace(PTRACE_SETOPTIONS)");

    char target_pathname[128];
    if (get_pid_pathname(pid, target_pathname, 128) < 0)
        errquit("get_pid_pathname(pid, ...)");

    fprintf(stderr, "Tracing: %d (%s)\n", pid, target_pathname);

    proc_map *maps = NULL;
    int maps_size = 0;

    struct {
        uint64_t word;
        uint64_t addr;
    } break_meta = {0};

    struct {
        uint64_t start;
        uint64_t end;
    } guess_exec = {0};
    
    if ((maps_size = proc_map_from_pid(&maps, pid)) < 0) {
        fprintf(stderr, "Failed to read /proc/%d/maps\n", pid);
        return 1;
    }

    for (int i = 0; i < maps_size; i++) {
        proc_map map = maps[i];

        printf("%s (%lx-%lx) (%b)\n", map.pathname, map.addr_start, map.addr_end, map.perms);
        if (map.perms & MAP_PERM_EXEC && !strncmp(target_pathname, map.pathname, min(strlen(map.pathname), strlen(target_pathname)))) {
            guess_exec.start = map.addr_start;
            guess_exec.end = map.addr_end;
        }
    }

    if (!guess_exec.start) {
        fprintf(stderr, "failed to find start section\n");

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");
    } else {
        fprintf(stderr, "start section found (%lx-%lx)\n", guess_exec.start, guess_exec.end);
        // read instruction byte at beginning
        uint64_t word = ptrace(PTRACE_PEEKDATA, pid, guess_exec.start, 0);

        break_meta.word = word;
        break_meta.addr = guess_exec.start;

        // write an INT3 interrupt at that address
        if (ptrace(PTRACE_POKEDATA, pid, guess_exec.start, INT3) < 0)
            errquit("ptrace(PTRACE_POKEDATA)");

        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_CONT)");
    }

    while (1) {
        if (waitpid(pid, &wstatus, WCONTINUED) < 0)
            errquit("Failed to wait for process");

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            fprintf(stderr, "\nProcess exit: %d\n", WEXITSTATUS(wstatus));
            break;
        }

        if (!WIFSTOPPED(wstatus)) {
            fprintf(stderr, "ptrace caught, not stopped\n");
            continue;
        }

        int signal = WSTOPSIG(wstatus);
        if (signal != SIGTRAP) {
            fprintf(stderr, "Signal: %d (SIG%s)\n", signal, sigabbrev_np(signal));
        }

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
            errquit("ptrace(PTRACE_GETREGS)");

        // if int3, replace with original, move rip one back
        if (break_meta.word && break_meta.addr && signal == SIGTRAP) {
            // wtite old instruction byte
            if (ptrace(PTRACE_POKEDATA, pid, break_meta.addr, break_meta.word) < 0)
                errquit("ptrace(PTRACE_POKEDATA)");

            // move rip back by one
            regs.rip--;
            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
                errquit("ptrace(PTRACE_SETREGS)");

            break_meta.word = 0, break_meta.addr = 0;
        }

        print_regs(pid);

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");

        getchar();
    }

    free_proc_maps(maps, maps_size);

    return 0;
}
