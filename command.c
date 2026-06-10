#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<readline/readline.h>
#include<readline/history.h>

#include "command.h"

#include "ansi.h"
#include "util.h"
#include "state.h"
#include "disassembly.h"
#include "breakpoint.h"

#define NEXT_RET(_next) do { free(_line); *next = (_next); return 0; } while (0)

static char *trim_str(char* line) {
    size_t line_n = strlen(line);
    while (line_n > 0 && isspace(*line)) {
        line++;
        line_n--;
    }

    while (line_n > 0 && isspace(line[line_n - 1])) line_n--;
    line[line_n] = 0;

    return line;
}

static void print_help() {
    printf(BWHT "Commands\n" CRESET);
    printf("    " GRN "%-42s" CRESET " %s\n", "help", "Show this help message");
    printf("\n");
    printf("    " GRN "%-42s" CRESET " %s\n", "c, continue", "Continue until the next breakpoint");
    printf("    " GRN "%-42s" CRESET " %s\n", "s, step", "Step one instruction");
    printf("    " GRN "%-42s" CRESET " %s\n", "[n]c, [n]s", "Continue or step n times");
    printf("\n");
    printf("    " GRN "%-42s" CRESET " %s\n", "b, bp, breakpoint <location>", "Set a breakpoint");
    printf("    " GRN "%-42s" CRESET " %s\n", "lb, list-bp, list-breakpoints", "List breakpoints");
    printf("    " GRN "%-42s" CRESET " %s\n", "ls, list-sym, list-symbols", "List symbols");
    printf("    " GRN "%-42s" CRESET " %s\n", "maps", "List process memory maps");
    printf("    " GRN "%-42s" CRESET " %s\n", "da, disas, disassemble <symbol>", "Disassemble a symbol");
    printf("    " GRN "%-42s" CRESET " %s\n", "da, disas, disassemble <location> <n>", "Disassemble n instructions at an address");
    printf("    " GRN "%-42s" CRESET " %s\n", "memdump <location> <n>", "Dump n bytes at an address");
    printf("    " GRN "%-42s" CRESET " %s\n", "exit", "Exit the debugger");
    printf("\n");
    printf("    " GRN "%-42s" CRESET " %s\n", "<enter>", "Repeat the last continue/step action");
    printf("\n");
    printf("    " HBLU "%-42s" CRESET " %s\n", "<location>", "<addr/symbol>[+offset]");
}

static void format_perms(int perms, char* buffer) {
    if (perms & MAP_PERM_READ)
        buffer[0] = 'r';

    if (perms & MAP_PERM_WRITE)
        buffer[1] = 'w';

    if (perms & MAP_PERM_EXEC)
        buffer[2] = 'x';

    if (perms & MAP_PERM_SHARED)
        buffer[3] = 's';

    if (perms & MAP_PERM_PRIVATE)
        buffer[3] = 'p';
}

static void print_maps(state_ctx *ctx) {
    printf(BWHT "%-18s %-18s Perms %-18s %-18s Path name\n" CRESET, "Start", "End", "Size", "Offset");
    for (size_t i = 0; i < ctx->maps->length; i++) {
        proc_map map = ctx->maps->items[i];

        char perms[5] = "----";
        format_perms(map.perms, perms);
        printf(HYEL "0x%016lx" HBLK "-" HYEL "0x%016lx" CRESET " %-5s 0x%-16lx 0x%-16lx " HBLU "%s\n", map.addr_start, map.addr_end, perms, map.addr_end - map.addr_start, map.offset, map.pathname);
    }
}

static void print_symbols(state_ctx *ctx) {
    for (size_t i = 0; i < ctx->d_ctx->n_sections; i++) {
        disasm_section_t *section = &ctx->d_ctx->sections[i];
        printf(HBLK "" CRESET "%s" HBLK ":\n" CRESET, section->name);

        if (section->n_symbols == 0) {
            printf("\tNo symbols\n");
        }

        for (size_t j = 0; j < section->n_symbols; j++) {
            printf("\t" HYEL "0x%016lx" HBLK " -> " GRN "%s\n", section->symbols[j].addr, section->symbols[j].name);
        }

        if (i < ctx->d_ctx->n_sections - 1)
            printf("\n");
    }
}

typedef struct {
    size_t length;
    char **items;
} args_arr;

static void split_args(char *input, char **cmd, args_arr *args) {
    size_t capacity = 4;
    args->items = malloc(capacity * sizeof(*args->items));

    *cmd = NULL;
    char *curr = input;
    bool ok = 1;
    while (ok) {
        curr = trim_str(curr);
        size_t space = 0;
        while (curr[space] && curr[space] != ' ') space++;

        if (!curr[space]) ok = 0;

        curr[space] = 0;

        if (!*cmd) {
            *cmd = curr;
            curr = &curr[space + 1];
            continue;
        }

        args->items[args->length++] = curr;
        if (args->length >= capacity) {
            capacity *= 2;
            args->items = realloc(args->items, capacity * sizeof(*args->items));
        }
        
        curr = &curr[space + 1];
    }
}

// TODO: support proper negative (currently +- works (not great with hex), but just - would be nice)
//  this is just ass ngl
static int resolve_location(state_ctx *ctx, char *input, uint64_t *addr_out) {
    size_t plus = 0;
    while (input[plus] && input[plus] != '+') plus++;

    char *offset_str = 0;
    if (input[plus] && input[plus + 1])
        offset_str = &input[plus + 1];

    input[plus] = '\0';

    int64_t offset = 0;
    if (offset_str && sscanf(offset_str, "0x%lx", &offset) != 1 && sscanf(offset_str, "%ld", &offset) != 1)
        return -1;

    disasm_symbol_t *sym = find_symbol_by_name(ctx->d_ctx, input);
    if (sym) {
        *addr_out = ctx->self_exec->addr_start + sym->addr;
        *addr_out += offset;
        return 0;
    }

    if (sscanf(input, "0x%lx", addr_out) != 1 && sscanf(input, "%lu", addr_out) != 1)
        return -1;

    *addr_out += offset;

    return 0;
}

typedef struct {
    size_t length;
    size_t capacity;
    break_meta *items;
} breakpoint_arr;

static breakpoint_arr breakpoints = {0};

// TODO: don't allow breakpoints to locations that already exist
static int handle_breakpoint(state_ctx *ctx, args_arr *args) {
    if (args->length != 1)
        return -1;

    uint64_t addr;
    if (resolve_location(ctx, args->items[0], &addr) < 0)
        return -1;
    
    break_meta bp;
    if (set_breakpoint(&bp, ctx->pid, addr) < 0)
        return -1;

    if (!breakpoints.items) {
        breakpoints.capacity = 4;
        breakpoints.items = malloc(breakpoints.capacity * sizeof(*breakpoints.items));
    }

    breakpoints.items[breakpoints.length++] = bp;
    if (breakpoints.length >= breakpoints.capacity) {
        breakpoints.capacity *= 2;
        breakpoints.items = realloc(breakpoints.items, breakpoints.capacity * sizeof(*breakpoints.items));
    }

    printf(HGRN " * " CRESET "Breakpoint" HBLK "(" HBLU "%zu" HBLK ")" CRESET " set at " HYEL "0x%016lx\n", breakpoints.length, bp.addr);

    return 0;
}

static void handle_list_breakpoints() {
    printf(BWHT "Index  Address\n" CRESET);

    for (size_t i = 0; i < breakpoints.length; i++) {
        printf(HBLU "%-6zu " HYEL "0x%016lx\n" CRESET, i + 1, breakpoints.items[i].addr);
    }

}

int handle_input(state_ctx *ctx, trace_next *next) {
    static trace_next default_behaviour = TRACE_INST_STEP;

    // TODO: make this better
    //  right now this is very primitive, e.g. 4s will step when first typed and
    //  other 3 times when this function is called, but this will cause the whole
    //  state to get printed even when that is not desired
    //  so we get state 4 times instead of 1
    static uint32_t __last_command_was_multiple_cnt = 0;
    if (__last_command_was_multiple_cnt > 0) {
        __last_command_was_multiple_cnt--;

        *next = default_behaviour;
        return 0;
    }

    while (1) {
        char *_line = readline(BHBLK " > " CRESET);
        if (_line == NULL)
            return -1;

        char *line = trim_str(_line);
        size_t line_n = strlen(line);
        if (line_n == 0)
            NEXT_RET(default_behaviour);

        add_history(line);
        
        char *cmd;
        size_t cmd_n = strlen(cmd);
        args_arr args = {0};
        split_args(line, &cmd, &args);

        // [n]c or [n]s behaviour for multiple continues/steps
        bool is_cont = 0;
        if ((is_cont = cmd[cmd_n - 1] == 'c') || cmd[cmd_n - 1] == 's') {
            uint32_t cnt = 0;
            int scanned = sscanf(cmd, is_cont ? "%uc" : "%us", &cnt);

            if (scanned > 0) {
                default_behaviour = is_cont ? TRACE_CONTINUE : TRACE_INST_STEP;
                __last_command_was_multiple_cnt = MAX((uint32_t) 1, cnt) - 1;

                NEXT_RET(default_behaviour);
            }
        }

        if (strcmp(line, "help") == 0) {
            print_help();
            continue;
        }

        if (strcmp(line, "c") == 0 || strcmp(line, "continue") == 0) {
            default_behaviour = TRACE_CONTINUE;
            NEXT_RET(default_behaviour);
        }

        if (strcmp(line, "s") == 0 || strcmp(line, "step") == 0) {
            default_behaviour = TRACE_INST_STEP;
            NEXT_RET(default_behaviour);
        }

        if (strcmp(line, "b") == 0 || strcmp(line, "bp") == 0 || strcmp(line, "breakpoint") == 0) {
            if (handle_breakpoint(ctx, &args) < 0) {
                printf(HYEL " ! Invalid usage, make sure the location correct and in writeable mapping\n");
            }

            continue;
        }

        if (strcmp(line, "lb") == 0 || strcmp(line, "list-bp") == 0 || strcmp(line, "list-breakpoints") == 0) {
            handle_list_breakpoints();
            continue;
        }

        if (strcmp(line, "ls") == 0 || strcmp(line, "list-sym") == 0 || strcmp(line, "list-symbols") == 0) {
            print_symbols(ctx);
            continue;
        }

        if (strcmp(line, "maps") == 0) {
            print_maps(ctx);
            continue;
        }

        if (strcmp(line, "da") == 0 || strcmp(line, "disas") == 0 || strcmp(line, "disassemble") == 0) {
            printf(HYEL " ! Not implemented yet\n");
            continue;
        }

        if (strcmp(line, "memdump") == 0) {
            printf(HYEL " ! Not implemented yet\n");
            continue;
        }

        if (strcmp(line, "exit") == 0) {
            NEXT_RET(TRACE_EXIT);
        }

        printf(HYEL " ! Invalid command, type 'help' to display all options\n");
        continue;
    }
}

#undef NEXT_RET
