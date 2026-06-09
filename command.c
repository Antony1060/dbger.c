#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<readline/readline.h>
#include<readline/history.h>

#include "command.h"

#include "ansi.h"
#include "util.h"
#include "state.h"

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

// all commands
/*
help
b/bp/breakpoint <addr/symbol>[+offset]
lb/list-bp/list-breakpoints
ls/list-sym/list-symbols
maps
+ exit
da/disas/disassemble <symbol> / <addr> <inst_num>
memdump <addr> <bytes_num>

trace behaviour:
+ [n]c/continue (up to next breakpoint)
+ [n]s/step (up to instruction)
+ <enter> is last selected trace behaviour
*/
static void print_help() {
    printf("TODO\n");
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

        // [n]c or [n]s behaviour for multipl continues/steps
        bool is_cont = 0;
        if ((is_cont = line[line_n - 1] == 'c') || line[line_n - 1] == 's') {
            uint32_t cnt = 0;
            int scanned = sscanf(line, is_cont ? "%uc" : "%us", &cnt);

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
            printf(HYEL " ! Not implemented yet\n");
            continue;
        }

        if (strcmp(line, "lb") == 0 || strcmp(line, "list-bp") == 0 || strcmp(line, "list-breakpoints") == 0) {
            printf(HYEL " ! Not implemented yet\n");
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
