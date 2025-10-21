#include<stdio.h>
#include<stdlib.h>
#include<sys/wait.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/mman.h>

#include "ansi.h"
#include "util.h"
#include "breakpoint.h"
#include "maps.h"
#include "state.h"
#include "trace.h"
#include "disassembly.h"

int get_pid_pathname(pid_t pid, char *pathname, size_t n) {
    char file_name[256];
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
    char target_pathname[256];
    memset(target_pathname, 0, sizeof(*target_pathname) * 256);
    if (get_pid_pathname(pid, target_pathname, 128) < 0)
        errquit("get_pid_pathname(pid, ...)");

    fprintf(stderr, "* tracing: %d (%s)\n", pid, target_pathname);

    // get process maps
    proc_map_array maps;

    if (proc_maps_from_pid(&maps, pid) < 0) {
        fprintf(stderr, "Failed to read /proc/%d/maps\n", pid);
        return 1;
    }

    // guess the first executable part of the binary,
    //  the idea is to skip the glibc runtime that the process starts in
    proc_map guess_exec = {0};

    // find first executable section in the binary
    for (size_t i = 0; i < maps.length; i++) {
        proc_map map = maps.items[i];

        if (map.perms & MAP_PERM_EXEC && !strncmp_min(map.pathname, target_pathname)) {
            guess_exec = map;
        }
    }

    __print_maps(&maps);

    // load and disassemble the binary
    void *elf_data;
    disasm_ctx_t *d_ctx;
    size_t target_file_size;
    if (open_and_disasm(&d_ctx, &elf_data, &target_file_size, target_pathname) < 0) {
        fprintf(stderr, "ERROR: failed to disassemble\n");
        return 1;
    }

    printf("disasm_ctx_t: %p\n", d_ctx);
    // inst_arr[section_idx] -> disasm_instruction_t *[] - array of pointers for that section
    disasm_instruction_t ***inst_arr = malloc(sizeof(*inst_arr) * d_ctx->n_sections);
    // allocate the array
    for (size_t i = 0; i < d_ctx->n_sections; i++) {
        const size_t size = sizeof(**inst_arr) * d_ctx->sections[i].size;
        inst_arr[i] = malloc(size);
        memset(inst_arr[i], 0, size);
    }
    // fill disassembly in a linear array
    fill_instruction_array(d_ctx, inst_arr);

    // last breakpoint set
    break_meta last_break = {0};

    // if the executable section was found, set a breakpoint and continue
    //  otherwise single step
    if (!guess_exec.addr_start) {
        fprintf(stderr, "failed to find start section\n");

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");
    } else {
        fprintf(stderr, "* start section found (%lx-%lx)\n", guess_exec.addr_start, guess_exec.addr_end);
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

        // reload maps
        size_t old_maps_size = maps.length;
        free_proc_maps(&maps);
        if (proc_maps_from_pid(&maps, pid) < 0) {
            fprintf(stderr, "Failed to read /proc/%d/maps\n", pid);
            break;
        }

        if (old_maps_size != maps.length) {
            printf("* maps possibly changed\n");
            __print_maps(&maps);
        }

        if (break_present(&last_break)) {
            if (end_breakpoint(&last_break, pid) < 0)
                errquit("end_breakpoint(..)");
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
            errquit("ptrace(PTRACE_GETREGS)");

        state_ctx s_ctx = {
            .pid = pid,
            .target_pathname = target_pathname,
            .regs = &regs,
            .d_ctx = d_ctx,
            .inst = inst_arr,
            .maps = &maps,
        };
        print_state(&s_ctx);

        getchar();

        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
            errquit("ptrace(PTRACE_SINGLESTEP)");
    }

    free_proc_maps(&maps);

    for (size_t i = 0; i < d_ctx->n_sections; i++) {
        free(inst_arr[i]);
    }
    free(inst_arr);

    disasm_free(d_ctx);

    munmap(elf_data, target_file_size);

    return 0;
}
