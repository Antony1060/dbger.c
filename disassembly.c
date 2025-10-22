#include<stdio.h>
#include<stdint.h>
#include<fcntl.h>
#include<sys/mman.h>
#include<sys/stat.h>

#include<disasm/disasm.h>

#include "disassembly.h"

// TODO: better error handling
int open_and_disasm(disasm_ctx_t **_ctx, void **_elf_data, size_t *stat_size, const char *target_pathname) {
    int target_fd;
    if ((target_fd = open(target_pathname, O_RDONLY)) < 0)
        return -1;

    struct stat target_fd_stat;
    if (fstat(target_fd, &target_fd_stat) < 0)
        return -1;

    void *elf_data = mmap(0, target_fd_stat.st_size, PROT_READ, MAP_PRIVATE, target_fd, 0);
    if (elf_data == MAP_FAILED)
        return -1;

    disasm_ctx_t *ctx;
    if (disasm_from_elf(&ctx, elf_data) < 0) {
        fprintf(stderr, "Failed to disassemble\n");
        return -1;
    }

    *_ctx = ctx;
    *_elf_data = elf_data;
    *stat_size = target_fd_stat.st_size;

    return 0;
}

