#include<stdio.h>
#include<stdlib.h>
#include<sys/wait.h>
#include<sys/ptrace.h>
#include<sys/user.h>

#include <disasm/disasm.h>

#include "ansi.h"
#include "util.h"
#include "breakpoint.h"
#include "maps.h"
#include "state.h"
#include "trace.h"

static inline size_t min(size_t a, size_t b) {
    return (a < b ? a : b);
}

int get_pid_pathname(pid_t pid, char *pathname, size_t n) {
    char file_name[64];
    snprintf(file_name, 64, "/proc/%d/exe", pid);

    return readlink(file_name, pathname, n);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command...>\n", argv[0]);
        return 1;
    }

    pid_t pid;
    if (fork_and_trace(&pid, argv[1], argv + 1) < 0)
        errquit("trace_and_fork(...)");

    // get process pathname
    char target_pathname[128];
    if (get_pid_pathname(pid, target_pathname, 128) < 0)
        errquit("get_pid_pathname(pid, ...)");

    fprintf(stderr, "Tracing: %d (%s)\n", pid, target_pathname);

    // get process maps
    proc_map *maps = NULL;
    int maps_size = 0;

    if ((maps_size = proc_map_from_pid(&maps, pid)) < 0) {
        fprintf(stderr, "Failed to read /proc/%d/maps\n", pid);
        return 1;
    }

    // guess the first executable part of the binary,
    //  the idea is to skip the glibc runtime that the process starts in
    proc_map guess_exec = {0};

    for (int i = 0; i < maps_size; i++) {
        proc_map map = maps[i];

        fprintf(stderr, "%s (%lx-%lx) (%b)\n", map.pathname, map.addr_start, map.addr_end, map.perms);
        if (map.perms & MAP_PERM_EXEC && !strncmp(map.pathname, target_pathname, min(strlen(map.pathname), strlen(target_pathname)))) {
            guess_exec = map;
        }
    }

    break_meta last_break = {0};

    if (!guess_exec.addr_start) {
        fprintf(stderr, "failed to find start section\n");

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");
    } else {
        fprintf(stderr, "start section found (%lx-%lx)\n", guess_exec.addr_start, guess_exec.addr_end);
        if (set_breakpoint(&last_break, pid, guess_exec.addr_start) < 0)
            errquit("set_breakpoint(..)");

        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_CONT)");
    }

    // main loop
    int wstatus;
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
            continue;
        }

        if (break_present(&last_break)) {
            if (end_breakpoint(&last_break, pid) < 0)
                errquit("end_breakpoint(..)");
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
            errquit("ptrace(PTRACE_GETREGS)");

        // TODO: move to print_state
        // TODO: include all other sections of the program that might be executable
        // TODO: show which map it's executing from
        if (regs.rip < guess_exec.addr_start || regs.rip > guess_exec.addr_end) {
            printf("Not in binary\n");
        }

        print_state(pid, &regs);

        getchar();

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");
    }

    free_proc_maps(maps, maps_size);

    return 0;
}
