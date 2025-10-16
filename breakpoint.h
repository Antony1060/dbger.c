#ifndef __DBGER_BREAKPOINT
#define __DBGER_BREAKPOINT

typedef struct {
    uint64_t _word;
    uint64_t _addr;
} break_meta;

bool break_present(break_meta *meta);

int set_breakpoint(break_meta *meta, pid_t pid, uint64_t where);

int end_breakpoint(break_meta *meta, pid_t pid);

#endif // __DBGER_BREAKPOINT
