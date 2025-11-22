#include<stdio.h>
#include<stdint.h>
#include<unistd.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<sys/uio.h>

#include<disasm/disasm.h>

#include "disassembly.h"

// TODO: better error handling
int open_and_disasm(disasm_ctx_t *ctx, void **_elf_data, size_t *stat_size, const char *target_pathname) {
    int target_fd;
    if ((target_fd = open(target_pathname, O_RDONLY)) < 0)
        return -1;

    struct stat target_fd_stat;
    if (fstat(target_fd, &target_fd_stat) < 0)
        return -1;

    void *elf_data = mmap(0, target_fd_stat.st_size, PROT_READ, MAP_PRIVATE, target_fd, 0);
    if (elf_data == MAP_FAILED)
        return -1;

    if (close(target_fd) < 0)
        return -1;

    if (disasm_from_elf(ctx, elf_data) < 0) {
        fprintf(stderr, "Failed to disassemble\n");
        return -1;
    }

    *_elf_data = elf_data;
    *stat_size = target_fd_stat.st_size;

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

void instruction_convert_from_disasm(disasm_instruction_t *inst, uint64_t addr, basic_instruction *_inst) {
    _inst->addr = addr;
    _inst->size = inst->inst_size;
    _inst->name = inst->inst_name;
    _inst->args = inst->inst_args;
    _inst->symbol_name = inst->closest_symbol ? inst->closest_symbol->name : 0;
    _inst->symbol_offset = inst->closest_symbol_offset;

    if (inst->has_branch_meta) {
        _inst->jump_target = inst->branch_meta.resolved_addr;
        _inst->pretty_target = inst->branch_meta.pretty_target;
    }
}

ssize_t find_rich_instruction_in_map(state_ctx *s_ctx, uint64_t addr, proc_map *map, disasm_section_t **section, disasm_instruction_t **_inst) {
    uint64_t current_addr = addr - map->addr_start + map->offset;

    // in case its not a dynamic (PIE) binary,
    //  RIP is the same as the mapping start and the instruction address
    //  (I think)
    if (s_ctx->d_ctx->elf_header.e_type == 0x2) {
        current_addr = addr;
    }

    disasm_ctx_t *ctx = s_ctx->d_ctx;
    size_t section_idx;
    for (section_idx = 0; section_idx < ctx->n_sections; section_idx++) {
        disasm_section_t *curr = &ctx->sections[section_idx];

        if (current_addr >= curr->code_start && current_addr <= curr->code_start + curr->size) {
            *section = curr;
            break;
        }
    }

    if (!*section)
        return -1;

    disasm_instruction_t *inst = 0;
    size_t idx = find_instruction_in_section(*section, current_addr, &inst);
    if (!inst)
        return -1;

    *_inst = inst;

    return (ssize_t) idx;
}

int disassemble_remote_at_addr(pid_t pid, uint64_t addr, basic_instruction *_inst, char* work_buf, char *work_name, char *work_args) {
    const size_t data_len = 15;
    uint8_t data[data_len];
    struct iovec remote_inst = { (void*) addr, data_len };
    struct iovec local_inst = { &data, data_len };

    process_vm_readv(pid, &local_inst, 1, &remote_inst, 1, 0);

    uint64_t jump_target;
    size_t shift = __disasm_read_first_instruction(data, data_len, work_buf, 256, (void *) addr, &jump_target, NULL);
    if (shift == 0)
        return -1;

    __disasm_color_instruction(work_buf, work_name, work_args);

    _inst->addr = addr;
    _inst->size = shift;
    _inst->name = work_name;
    _inst->args = work_args;
    _inst->jump_target = jump_target;

    return 0;
}
