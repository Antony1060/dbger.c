#include<stdint.h>
#include<stdbool.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/user.h>

#include "breakpoint.h"

int INT3 = 0xCC;

bool break_present(break_meta *meta) {
    return meta->_word && meta->_addr;
}

int set_breakpoint(break_meta *meta, pid_t pid, uint64_t where) {
    // read word previously there
    uint64_t word = ptrace(PTRACE_PEEKDATA, pid, where, 0);

    meta->_word = word;
    meta->_addr = where;

    // write an INT3 interrupt at that address
    return ptrace(PTRACE_POKEDATA, pid, where, INT3);
}

int end_breakpoint(break_meta *meta, pid_t pid) {
    struct user_regs_struct regs;

    int res;
    if ((res = ptrace(PTRACE_GETREGS, pid, 0, &regs)) < 0)
        return res;

    // write old instruction word
    if ((res = ptrace(PTRACE_POKEDATA, pid, meta->_addr, meta->_word)) < 0)
        return res;

    // move rip back by one
    regs.rip--;
    if ((res = ptrace(PTRACE_SETREGS, pid, 0, &regs)) < 0)
        return res;

    meta->_word = 0, meta->_addr = 0;
    return 0;
}
