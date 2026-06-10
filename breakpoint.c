#include<stdint.h>
#include<stdbool.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/user.h>

#include "breakpoint.h"

int INT3 = 0xCC;

// TODO: store a list of breakpoints here, main should see if any match when it interrupts 
// TODO: deleting breakpoints
// TODO: breakpoint should trigger every time it comes to it, i.e. restoring
bool break_present(break_meta *meta) {
    return meta->_word && meta->addr;
}

int set_breakpoint(break_meta *meta, pid_t pid, uint64_t where) {
    // read word previously there
    uint64_t word = ptrace(PTRACE_PEEKDATA, pid, where, 0);

    meta->_word = word;
    meta->addr = where;

    // write an INT3 interrupt at that address
    return ptrace(PTRACE_POKEDATA, pid, where, INT3);
}

int end_breakpoint(break_meta *meta, pid_t pid) {
    struct user_regs_struct regs;

    int res;
    if ((res = ptrace(PTRACE_GETREGS, pid, 0, &regs)) < 0)
        return res;

    // write old instruction word
    if ((res = ptrace(PTRACE_POKEDATA, pid, meta->addr, meta->_word)) < 0)
        return res;

    // move rip back by one
    regs.rip--;
    if ((res = ptrace(PTRACE_SETREGS, pid, 0, &regs)) < 0)
        return res;

    meta->_word = 0, meta->addr = 0;
    return 0;
}
