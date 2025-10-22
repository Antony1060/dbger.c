#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<sys/types.h>
#include<sys/ptrace.h>
#include<sys/user.h>
#include<sys/uio.h>
#include<xed/xed-interface.h>

#include "ansi.h"
#include "util.h"
#include "state.h"
#include "maps.h"

const size_t AROUND_INSTRUCTIONS = 12;

static size_t print_forward_disassembly(pid_t pid, uint64_t rip);

static void print_regs(state_ctx *ctx) {
    #define printreg(reg) printf("\t" GRN #reg HBLK ": " BLU "0x%llx " HBLK "(" CYN "%lld" HBLK ") " CRESET "\n", ctx->regs->reg, ctx->regs->reg);

    printreg(rax);
    printreg(rbx);
    printreg(rcx);
    printreg(rdx);
    printreg(rsi);
    printreg(rdi);
    printreg(rip);
    printreg(rsp);
    printreg(rbp);
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

static void print_rich_instruction(disasm_instruction_t *inst, bool current, uint64_t rip) {
    if (current)
        printf(HBLK " => ");
    else
        printf("    ");
    printf(HYEL "0x%.16lx", rip);

    if (inst->closest_symbol) {
        printf(WHT " <" GRN "%s" HBLU "+0x%.2lx" WHT ">", inst->closest_symbol->name, inst->closest_symbol_offset);
    }

    printf(WHT ": " BLU "%s" CRESET "\t " HGRN "%s" CRESET, inst->inst_name, inst->inst_args);

    if (inst->has_branch_meta) {
        disasm_branch_meta_t *branch = &inst->branch_meta;

        if (branch->pretty_target[0])
            printf(" %s", branch->pretty_target);

        printf(HBLK "    # 0x%lx", branch->resolved_addr);
    }

    printf(CRESET);
}

// TODO: support non-PIE binaries
static int print_rich_disassembly(state_ctx *s_ctx, proc_map *map) {
    uint64_t map_offset = s_ctx->regs->rip - map->addr_start + map->offset;

    disasm_ctx_t *ctx = s_ctx->d_ctx;
    disasm_section_t *section = 0;
    size_t section_idx;
    for (section_idx = 0; section_idx < ctx->n_sections; section_idx++) {
        disasm_section_t *curr = &ctx->sections[section_idx];

        if (map_offset >= curr->code_start && map_offset <= curr->code_start + curr->size) {
            section = curr;
            break;
        }
    }

    if (!section)
        return -1;

    disasm_instruction_t *inst = 0;
    size_t idx = find_instruction_in_section(section, map_offset, &inst);
    if (!inst)
        return -1;

    // find instructions around this one
    size_t around_half = AROUND_INSTRUCTIONS / 2;
    size_t end = min(section->n_instructions - 1, idx + AROUND_INSTRUCTIONS);
    size_t needed_before = AROUND_INSTRUCTIONS - min(end - idx, around_half);
    size_t start = needed_before > idx ? 0 : idx - needed_before;
    size_t after = min(AROUND_INSTRUCTIONS - (idx - start), end - idx);
    end = idx + after;

    for (size_t i = start; i <= end; i++) {
        disasm_instruction_t *curr = &section->instructions[i];
        uint64_t rip = curr->addr < inst->addr ?
            s_ctx->regs->rip - (inst->addr - curr->addr):
            s_ctx->regs->rip + (curr->addr - inst->addr);
        print_rich_instruction(curr, i == idx, rip);
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

static size_t print_forward_disassembly(pid_t pid, uint64_t rip) {
    char buffer[256];
    char name[32];
    char args[256];

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

        if (inst_read == 0)
            printf(HBLK " => ");
        else
            printf("    ");

        printf(HYEL "0x%.16lx" WHT ": " BLU "%s" CRESET "\t " HGRN "%s" CRESET, rip, name, args);

        if (jump_target) {
            printf(HBLK "    # 0x%lx", jump_target);
        }

        printf(CRESET "\n");

        rip += shift;
        inst_read++;
    }

    return inst_read;
}
