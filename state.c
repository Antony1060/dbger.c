// big file lol

#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/uio.h>
#include<ctype.h>
#include<xed/xed-interface.h>

#include "ansi.h"
#include "util.h"
#include "state.h"
#include "maps.h"
#include "disassembly.h"
#include "ds_set_u64.h"

const size_t REG_SIZE = sizeof(void *);

const size_t DISASSEMBLY_BEFORE = 4;
const size_t DISASSEMBLY_AFTER = 8;
const size_t DISASSEMBLY_INSTRUCTIONS = DISASSEMBLY_BEFORE + DISASSEMBLY_AFTER;

const size_t STACK_ROWS = 12;

const size_t STRING_PRINT_MAX = 32;

static size_t print_forward_disassembly(pid_t pid, uint64_t rip);
static void print_instruction(uint64_t rip, basic_instruction *inst);
static proc_map *find_map_at_addr(state_ctx *ctx, uint64_t addr);

// returns how many were printed if it expects the string to continue
//  0 otherwise
static size_t try_print_as_string(unsigned long long reg, size_t curr_printed) {
    unsigned char *as_str = (unsigned char *) &reg;

    // don't do anything if the first symbol is not printable
    if (!isprint(as_str[0])) {
        return 0;
    }

    if (curr_printed == 0)
        printf(" " HYEL "\"");

    size_t printable = 0;
    size_t i;
    for (i = 0; i < sizeof(reg); i++) {
        if (curr_printed + i >= STRING_PRINT_MAX) {
            printable = 0;
            printf("...");
            break;
        }

        unsigned char c = as_str[i];

        if (c == 0)
            break;

        if (!isprint(c)) {
            printf("\\x%.2x", c);
            continue;
        }

        printable++;
        printf("%c", c);
    }

    bool want_more = printable == sizeof(reg);
    if (!want_more)
        printf("\"" CRESET);

    return want_more ? printable : 0;
}

static void print_value_raw(state_ctx *ctx, unsigned long long reg, unsigned long long reg_src) {
    printf(HBLU "0x%llx", reg);

    // this is a very opinionated and heuristic flow
    size_t printed = 0;
    size_t curr;
    while ((curr = try_print_as_string(reg, printed)) > 0) {
        printed += curr;
        reg_src += sizeof(long);

        // check bounds
        //  if reg_src is 0 or (it's not on stack and it's not on heap)
        if (
            !reg_src ||
            (!(ctx->stack && reg_src >= ctx->stack->addr_start && reg_src <= ctx->stack->addr_end) &&
            !(ctx->heap && reg_src >= ctx->heap->addr_start && reg_src <= ctx->heap->addr_end))
        ) {
            break;
        }

        errno = 0;
        unsigned long word = ptrace(PTRACE_PEEKDATA, ctx->pid, reg_src, 0);
        if (errno != 0) {
            printf(RED " (error)");
            break;
        }

        reg = word;
    }

    // if it's still higher than 0, meaning loop was broken because it couldn't read the next word
    //  we need to close the string manually
    if (curr > 0)
        printf(HYEL "\"" CRESET);
}

// maybe too fancy?
static void print_reg_instruction(basic_instruction *inst) {
    if (inst->symbol_name) {
        printf(WHT "<" GRN "%s" HBLU "+0x%.2lx" WHT "> ", inst->symbol_name, inst->symbol_offset);
    }

    printf(BLU "%s " HGRN "%s" CRESET, inst->name, inst->args);

    if (inst->jump_target) {
        if (inst->pretty_target && inst->pretty_target[0])
            printf(" %s", inst->pretty_target);

        printf(HBLK " # 0x%lx", inst->jump_target);
    }

    printf(CRESET);
}

static void print_code_reg(state_ctx *ctx, unsigned long long reg) {
    printf(HRED "0x%llx", reg);

    proc_map *current = find_map_at_addr(ctx, reg);

    // so it's always available in both rich and in place path
    basic_instruction _inst = {0};

    if (!current || strncmp_min(current->pathname, ctx->target_pathname))
        goto in_place_disassemble;

    disasm_section_t *section = 0;
    disasm_instruction_t *inst = 0;
    if (find_rich_instruction_in_map(ctx, reg, current, &section, &inst) < 0)
        goto in_place_disassemble;

    instruction_convert_from_disasm(inst, reg, &_inst);

    printf(HBLK " -> ");
    print_reg_instruction(&_inst);

    return;

in_place_disassemble:
    char buffer[256];
    char name[32];
    char args[256];

    if(disassemble_remote_at_addr(ctx->pid, reg, &_inst, buffer, name, args) < 0)
        goto fail;

    printf(HBLK " -> ");
    print_reg_instruction(&_inst);

    return;

fail:
    printf(HRED " (code)" CRESET);

    return;
}

static void print_memory_chain(state_ctx *ctx, ds_set_u64 *visited, unsigned long long reg) {
    unsigned long long reg_src;
    while (1) {
        if (ds_set_u64_find(visited, reg))
            break;

        ds_set_u64_insert(visited, reg);

        bool heap = 0;
        bool stack = 0;
        if (
            (stack = (ctx->stack && reg >= ctx->stack->addr_start && reg <= ctx->stack->addr_end)) ||
            (heap = (ctx->heap && reg >= ctx->heap->addr_start && reg <= ctx->heap->addr_end))
        ) {
            errno = 0;
            unsigned long word = ptrace(PTRACE_PEEKDATA, ctx->pid, reg, 0);
            if (errno != 0) {
                printf(RED "(error) ");
                break;
            }


            if (stack) {
                printf(HMAG "0x%llx", reg);
            } else if (heap) {
                printf(HYEL "0x%llx", reg);
            } else {
                printf(RED "(error) ");
                break;
            }

            printf(HBLK " -> " CRESET);

            reg_src = reg;
            reg = word;

            continue;
        }

        for (size_t i = 0; i < ctx->maps->length; i++) {
            proc_map *map = &ctx->maps->items[i];

            // if we're in a code region, call a custom function and end the loop
            if (map->perms & MAP_PERM_EXEC && reg >= map->addr_start && reg <= map->addr_end) {
                print_code_reg(ctx, reg);
                return;
            }
        }

        break;
    }

    print_value_raw(ctx, reg, reg_src);
    printf(CRESET);
}

static void print_flags(state_ctx *ctx) {
    uint8_t carry = ctx->regs->eflags & UINT64_C(0x0001);
    uint8_t zero = ctx->regs->eflags & UINT64_C(0x0040);
    uint8_t sign = ctx->regs->eflags & UINT64_C(0x0080);
    uint8_t overflow = ctx->regs->eflags & UINT64_C(0x0800);

    printf("  " BGRN "flags" HBLK ": ");

    #define printflag(name, flag) do { \
        printf(BWHT name HYEL "="); \
        if (flag) \
            printf(BGRN "1"); \
        else \
            printf(WHT "0"); \
        printf("  "); \
    } while (0);

    printflag("CF", carry);
    printflag("ZF", zero);
    printflag("SF", sign);
    printflag("OF", overflow);

    #undef printflag

    printf(CRESET "\n");
}

static void print_regs(state_ctx *ctx) {
    ds_set_u64 visited;
    ds_set_u64_init(&visited);

    #define printreg(reg) do { \
        printf("    " GRN "%3s" HBLK ": " BLU, #reg "\0"); \
        ds_set_u64_clear(&visited); \
        print_memory_chain(ctx, &visited, ctx->regs->reg); \
        printf(CRESET "\n"); \
    } while (0);

    printreg(rip);
    printreg(rax);
    printreg(rbx);
    printreg(rcx);
    printreg(rdx);
    printreg(rsi);
    printreg(rdi);
    printreg(r8);
    printreg(r9);
    printreg(r10);
    printreg(r11);
    printreg(r12);
    printreg(r13);
    printreg(r14);
    printreg(r15);
    printreg(rsp);
    printreg(rbp);

    #undef printreg

    ds_set_u64_free(&visited);

    print_flags(ctx);
}

static void print_stack(state_ctx *ctx) {
    uint64_t sp = ctx->regs->rsp;
    uint64_t bp = ctx->regs->rbp;

    ds_set_u64 visited;
    ds_set_u64_init(&visited);

    for (size_t curr = sp; curr < sp + (STACK_ROWS * REG_SIZE); curr += REG_SIZE) {
        size_t diff = curr - sp;

        errno = 0;
        unsigned long word = ptrace(PTRACE_PEEKDATA, ctx->pid, curr, 0);
        if (errno != 0)
            break;

        if (curr == sp) {
            printf(BHBLU "$rsp" HBLK " | ");
        } else if (curr == bp) {
            printf(BHBLU "$rbp" HBLK " | ");
        } else {
            printf(HBLK "     | ");
        }

        printf(HYEL "0x%lx " WHT "<" GRN "rsp" HBLU "+0x%.2lx" WHT ">: ", curr, diff);

        ds_set_u64_clear(&visited);
        print_memory_chain(ctx, &visited, word);

        printf("\n");
    }

    ds_set_u64_free(&visited);
}

static void print_call_trace(state_ctx *ctx) {
    uint64_t bp = ctx->regs->rbp;
    uint64_t sp = ctx->regs->rsp;

    uint8_t depth = 0;
    while (1) {
        uint64_t curr;
        if (depth == 0) {
            curr = ctx->regs->rip;
        } else {
            errno = 0;
            unsigned long val_bp = ptrace(PTRACE_PEEKDATA, ctx->pid, bp, 0);
            if (errno != 0)
                break;

            errno = 0;
            unsigned long val_bp_after = ptrace(PTRACE_PEEKDATA, ctx->pid, bp + REG_SIZE, 0);
            if (errno != 0)
                break;

            errno = 0;
            unsigned long val_sp = ptrace(PTRACE_PEEKDATA, ctx->pid, sp, 0);
            if (errno != 0)
                break;

            errno = 0;
            unsigned long val_sp_after = ptrace(PTRACE_PEEKDATA, ctx->pid, sp + REG_SIZE, 0);
            if (errno != 0)
                break;

            // eh, I don't like this, I need to figure out a better way of choosing this
            if (depth == 1) {
                bool val_sp_exec = 0;
                bool val_sp_after_exec = 0;

                for (size_t i = 0; i < ctx->maps->length; i++) {
                    proc_map *map = &ctx->maps->items[i];

                    if (!(map->perms & MAP_PERM_EXEC))
                        continue;

                    if (map->addr_start <= val_sp && map->addr_end >= val_sp)
                        val_sp_exec = 1;
                    
                    if (map->addr_start <= val_sp_after && map->addr_end >= val_sp_after)
                        val_sp_after_exec = 1;
                }

                if (val_sp_exec) {
                    curr = val_sp;
                } else if (val_sp_after_exec && (ctx->stack && ctx->stack->addr_start <= val_sp && ctx->stack->addr_end >= val_sp)) {
                    bp = val_sp;
                    curr = val_sp_after;
                } else {
                    bp = val_bp;
                    curr = val_bp_after;
                }
            } else {
                bp = val_bp;
                curr = val_bp_after;
            }
        }

        proc_map *map = find_map_at_addr(ctx, curr);
        if (!map)
            break;

        if (!strncmp_min(map->pathname, ctx->target_pathname)) {
            size_t map_start = map->addr_start;
            size_t map_offset = map->offset;
            if (ctx->d_ctx->elf_header.e_type == 0x2) {
                map_start = 0;
                map_offset = 0;
            }

            disasm_section_t *section = 0;
            disasm_instruction_t *inst = 0;
            ssize_t idx = find_rich_instruction_in_map(ctx, curr, map, &section, &inst);
            if (idx < 0)
                break;

            disasm_symbol_t *sym = inst->closest_symbol;
            if (!sym)
                break;

            printf(WHT "%u. ", depth);

            if (depth == 0)
                printf(BGRN "%s", sym->name);
            else
                printf(GRN "%s", sym->name);

            printf(HBLU "+%lx" WHT "()" HBLK " <- " WHT "0x%lx\n", inst->closest_symbol_offset, inst->addr + map_start - map_offset);
        } else {
            char *map_name = basename(map->pathname);

            printf(WHT "%u. " HBLK "somewhere in ", depth);

            if (depth == 0)
                printf(BRED "%s", map_name);
            else
                printf(RED "%s", map_name);

            printf(WHT "()" HBLK " <- " WHT "0x%lx\n", curr);
        }

        depth++;
    }
}

static proc_map *find_map_at_addr(state_ctx *ctx, uint64_t addr) {
    for (size_t i = 0; i < ctx->maps->length; i++) {
        proc_map *map = &ctx->maps->items[i];

        if (map->perms & MAP_PERM_EXEC && addr >= map->addr_start && addr <= map->addr_end)
            return map;
    }

    return 0;
}

// a lot of params lol
static void print_instruction(uint64_t rip, basic_instruction *inst) {
    if (rip == inst->addr) {
        printf(HBLK " => ");
        printf(BYEL "0x%.16lx", inst->addr);
    } else {
        if (inst->addr < rip) {
            printf(HBLK "  | ");
        } else {
            printf("    ");
        };
        printf(HYEL "0x%.16lx", inst->addr);
    }

    if (inst->symbol_name) {
        printf(WHT " <" GRN "%s" HBLU "+0x%.2lx" WHT ">", inst->symbol_name, inst->symbol_offset);
    }

    printf(WHT ": " BLU "%s" CRESET "\t " HGRN "%s" CRESET, inst->name, inst->args);

    if (inst->jump_target) {
        if (inst->pretty_target && inst->pretty_target[0])
            printf(" %s", inst->pretty_target);

        printf(HBLK "    # 0x%lx", inst->jump_target);
    }

    printf(CRESET);
}

static int print_rich_disassembly(state_ctx *s_ctx, proc_map *map) {
    disasm_section_t *section = 0;
    disasm_instruction_t *inst = 0;
    ssize_t _idx = find_rich_instruction_in_map(s_ctx, s_ctx->regs->rip, map, &section, &inst);
    if (_idx < 0)
        return -1;

    size_t idx = (size_t) _idx;

    // find instructions around this one
    size_t end = MIN(section->n_instructions - 1, idx + DISASSEMBLY_INSTRUCTIONS);
    size_t needed_before = DISASSEMBLY_INSTRUCTIONS - MIN(end - idx, DISASSEMBLY_AFTER);
    size_t start = needed_before > idx ? 0 : idx - needed_before;
    size_t after = MIN(DISASSEMBLY_INSTRUCTIONS - (idx - start), end - idx);
    end = idx + after;

    for (size_t i = start; i <= end; i++) {
        disasm_instruction_t *curr = &section->instructions[i];

        // ternareee
        uint64_t addr = curr->addr < inst->addr ?
            s_ctx->regs->rip - (inst->addr - curr->addr):
            s_ctx->regs->rip + (curr->addr - inst->addr);

        basic_instruction _inst = {0};
        instruction_convert_from_disasm(curr, addr, &_inst);

        print_instruction(s_ctx->regs->rip, &_inst);
        printf("\n");
    }

    return 0;
}

static void print_disassembly(state_ctx *ctx) {
    proc_map *current = find_map_at_addr(ctx, ctx->regs->rip);
    if (!current) {
        printf(RED "unknown memory executing\n" CRESET);
    } else {
        printf(BWHT "currently in " BHRED "%s\n" CRESET, current->pathname);
    }

    if (!current || strncmp_min(current->pathname, ctx->target_pathname)) {
        printf(HYEL "  not the source binary, expect poorer disassembly\n" CRESET);
        print_forward_disassembly(ctx->pid, ctx->regs->rip);
        return;
    }

    if (print_rich_disassembly(ctx, current) < 0) {
        printf(HYEL "  ?? what, rich disassembly failed, expect poorer disassembly\n" CRESET);
        print_forward_disassembly(ctx->pid, ctx->regs->rip);
    }
}

static inline void print_separator(const char *title) {
    printf(HBLK "-- " BWHT "%-12s" HBLK " ----------------" CRESET "\n", title);
}

void print_state(state_ctx *ctx) {
    printf(HBLK "-- " CYN "%d" BWHT ": " HYEL "%s" CRESET "\n", ctx->pid, ctx->target_pathname);
    print_separator("registers");
    print_regs(ctx);
    print_separator("stack");
    print_stack(ctx);
    print_separator("call trace");
    print_call_trace(ctx);
    print_separator("disassembly");
    print_disassembly(ctx);
    print_separator("end");
}

static size_t print_forward_disassembly(pid_t pid, uint64_t _rip) {
    char buffer[256];
    char name[32];
    char args[256];

    uint64_t rip = _rip;
    size_t inst_read;
    for (inst_read = 0; inst_read < DISASSEMBLY_INSTRUCTIONS + 1; inst_read++) {
        basic_instruction _inst = {0};
        if(disassemble_remote_at_addr(pid, rip, &_inst, buffer, name, args) < 0)
            break;

        print_instruction(_rip, &_inst);
        printf(CRESET "\n");

        rip += _inst.size;
    }

    return inst_read;
}
