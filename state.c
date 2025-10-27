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

const size_t AROUND_BEFORE = 4;
const size_t AROUND_AFTER = 8;
const size_t AROUND_INSTRUCTIONS = AROUND_BEFORE + AROUND_AFTER;

const size_t STRING_PRINT_MAX = 32;

static size_t print_forward_disassembly(pid_t pid, uint64_t rip);

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
        long word = ptrace(PTRACE_PEEKDATA, ctx->pid, reg_src, 0);
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

static void print_code_reg(state_ctx *ctx, unsigned long long reg) {
    (void) ctx;
    printf(HRED "0x%llx (code)", reg);

    // if it's in binary, print rich, otherwise, poke data and invoke the disassembler
    //  basically the same thing that is done in the disassembly section
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
            long word = ptrace(PTRACE_PEEKDATA, ctx->pid, reg, 0);
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
}

static void print_register_resolved(state_ctx *ctx, ds_set_u64 *visited, unsigned long long reg) {
    print_memory_chain(ctx, visited, reg);
}

static void print_regs(state_ctx *ctx) {
    ds_set_u64 visited;
    ds_set_u64_init(&visited);

    #define printreg(reg) do { \
        printf("\t" GRN "%3s" HBLK ": " BLU, #reg "\0"); \
        ds_set_u64_clear(&visited); \
        print_register_resolved(ctx, &visited, ctx->regs->reg); \
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
}

static void print_stack(state_ctx *ctx) {
    (void) ctx;
}

static void print_call_trace(state_ctx *ctx) {
    (void) ctx;
}

proc_map *find_current_map(state_ctx *ctx) {
    for (size_t i = 0; i < ctx->maps->length; i++) {
        proc_map *map = &ctx->maps->items[i];

        uint64_t rip = ctx->regs->rip;
        if (map->perms & MAP_PERM_EXEC && rip >= map->addr_start && rip <= map->addr_end)
            return map;
    }

    return 0;
}

static inline size_t find_instruction_in_section(disasm_section_t *section, uint64_t addr, disasm_instruction_t **inst) {
    *inst = 0;

    size_t low = 0;
    size_t high = section->n_instructions - 1;

    while (low <= high) {
        size_t mid = low + (high - low) / 2;

        disasm_instruction_t *curr = &section->instructions[mid];
        if (curr->addr < addr)
            low = mid + 1;
        else if (curr->addr > addr)
            high = mid - 1;
        else {
            *inst = curr;
            return mid;
        }
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
    uint64_t current_addr = s_ctx->regs->rip - map->addr_start + map->offset;

    // in case its not a dynamic (PIE) binary,
    //  RIP is the same as the mapping start and the instruction address
    //  (I think)
    if (s_ctx->d_ctx->elf_header.e_type == 0x2) {
        current_addr = s_ctx->regs->rip;
    }

    disasm_ctx_t *ctx = s_ctx->d_ctx;
    disasm_section_t *section = 0;
    size_t section_idx;
    for (section_idx = 0; section_idx < ctx->n_sections; section_idx++) {
        disasm_section_t *curr = &ctx->sections[section_idx];

        if (current_addr >= curr->code_start && current_addr <= curr->code_start + curr->size) {
            section = curr;
            break;
        }
    }

    if (!section)
        return -1;

    disasm_instruction_t *inst = 0;
    size_t idx = find_instruction_in_section(section, current_addr, &inst);
    if (!inst)
        return -1;

    // find instructions around this one
    size_t end = MIN(section->n_instructions - 1, idx + AROUND_INSTRUCTIONS);
    size_t needed_before = AROUND_INSTRUCTIONS - MIN(end - idx, AROUND_AFTER);
    size_t start = needed_before > idx ? 0 : idx - needed_before;
    size_t after = MIN(AROUND_INSTRUCTIONS - (idx - start), end - idx);
    end = idx + after;

    for (size_t i = start; i <= end; i++) {
        disasm_instruction_t *curr = &section->instructions[i];

        // ternareee
        uint64_t addr = curr->addr < inst->addr ?
            s_ctx->regs->rip - (inst->addr - curr->addr):
            s_ctx->regs->rip + (curr->addr - inst->addr);

        basic_instruction _inst = {
            .addr = addr,
            .name = curr->inst_name,
            .args = curr->inst_args,
            .symbol_name = curr->closest_symbol ? curr->closest_symbol->name : 0,
            .symbol_offset = curr->closest_symbol_offset,
        };

        if (curr->has_branch_meta) {
            _inst.jump_target = curr->branch_meta.resolved_addr;
            _inst.pretty_target = curr->branch_meta.pretty_target;
        }

        print_instruction(s_ctx->regs->rip, &_inst);
        printf("\n");
    }

    return 0;
}

static void print_disassembly(state_ctx *ctx) {
    proc_map *current = find_current_map(ctx);
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
    size_t inst_read = 0;
    while (inst_read < AROUND_INSTRUCTIONS + 1) {
        const size_t data_len = 15;
        uint8_t data[data_len];
        struct iovec remote_inst = { (void*) rip, data_len };
        struct iovec local_inst = { &data, data_len };

        process_vm_readv(pid, &local_inst, 1, &remote_inst, 1, 0);

        uint64_t jump_target;
        size_t shift = __disasm_read_first_instruction(data, data_len, buffer, 256, (void *) rip, &jump_target, NULL);
        if (shift == 0)
            break;

        __disasm_color_instruction(buffer, name, args);

        basic_instruction _inst = {
            .addr = rip,
            .name = name,
            .args = args,
            .jump_target = jump_target,
        };

        print_instruction(_rip, &_inst);
        printf(CRESET "\n");

        rip += shift;
        inst_read++;
    }

    return inst_read;
}
