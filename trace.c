#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<sys/ptrace.h>

#include "util.h"
#include "trace.h"

int fork_and_trace(pid_t *pid, const char *program, char **argv) {
    *pid = fork();
    if (*pid == 0) {
        // we are not in the same process here, this should not return and end up in main somehow

        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            errquit("ptrace(PTRACE_TRACEME)");

        if (raise(SIGSTOP) != 0) {
            fprintf(stderr, "raise failed\n");
            exit(1);
        }

        if (execvp(program, argv) < 0)
            errquit("Failed to start process");

        exit(0);
    }

    int res;

    // wait for SIGSTOP
    if ((res = waitpid(*pid, NULL, 0)) < 0)
        return res;

    if (ptrace(PTRACE_SETOPTIONS, *pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC) < 0)
        return res;

    // continue until execve
    if (ptrace(PTRACE_CONT, *pid, 0, 0) < 0)
        return res;

    int wstatus;
    while (1) {
        if ((res = waitpid(*pid, &wstatus, 0)) < 0)
            return res;

        if (WIFSTOPPED(wstatus) && (wstatus >> 8 == (SIGTRAP | PTRACE_EVENT_EXEC << 8)))
            break;

        if (ptrace(PTRACE_CONT, *pid, 0, 0) < 0)
            return res;
    }

    // don't care about exec anymore
    if (ptrace(PTRACE_SETOPTIONS, *pid, 0, PTRACE_O_EXITKILL) < 0)
        return res;

    // at this point, the forked process has completed the execve
    //  the kernel has set up the new process and
    //  the debugger can give it permission to continue

    return 0;
}
