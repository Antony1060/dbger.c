#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<errno.h>
#include<string.h>
#include<ctype.h>

#include<disasm.h>

#include "ansi.h"

#define PRINT_RAW_INST 0

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

#define MIN_ELF_SIZE 64

void print_section(disasm_section_t *section) {
    printf("\n\n" HBLK "disassembly of section " CRESET "%s" HBLK ": " CRESET "\n", section->name);

    for (size_t i = 0; i < section->n_instructions; i++) {
        disasm_instruction_t *inst = &section->instructions[i];

        if (inst->closest_symbol && inst->closest_symbol_offset == 0) {
            printf("\n" HCYN "%s" HBLK ":" CRESET "\n", inst->closest_symbol->name);
        }

        printf("\t" HYEL "%p", (void *) inst->addr);

        if (inst->closest_symbol) {
            printf(WHT " <" HBLU "+0x%.2lx" WHT ">", inst->closest_symbol_offset);
        }

        printf(HBLK ":\t");

#if PRINT_RAW_INST
        printf(BWHT);
        for (size_t b = 0; b < 15; b++) {
            if (b != 0)
                printf(" ");
            if (b < inst->inst_size)
                printf("%.2x", inst->inst_raw[b]);
            else
                printf("  ");
        }
        printf(CRESET "\t");
#endif // PRINT_RAW_INST

        printf(BLU "%s" CRESET "\t " HGRN "%s" CRESET, inst->inst_name, inst->inst_args);

        if (inst->has_branch_meta) {
            disasm_branch_meta_t *branch = &inst->branch_meta;

            if (branch->pretty_target[0])
                printf(" %s", branch->pretty_target);

            printf(HBLK "    # 0x%lx", branch->resolved_addr);
        }

        printf(CRESET "\n");
    }
}

void print_disassembly(disasm_ctx_t *ctx, char *target_section) {
    for (size_t i = 0; i < ctx->n_sections; i++) {
        disasm_section_t *section = &ctx->sections[i];

        if (!target_section || !strcmp(target_section, section->name))
            print_section(section);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf...>\n", argv[0]);
        return 1;
    }

    char *target_section = 0;

    if (argc >= 3) {
        target_section = argv[2];
        for (char *begin = target_section; *begin != '\0'; begin++) {
            *begin = tolower(*begin);
        }
    }

    int fd;
    if ((fd = open(argv[1], O_RDONLY)) < 0)
        errquit("open(..)");

    struct stat fd_stat;
    if (fstat(fd, &fd_stat) < 0)
        errquit("stat(fd)");

    off_t file_size = fd_stat.st_size;

    if (file_size < MIN_ELF_SIZE) {
        fprintf(stderr, "file is smaller than %d bytes\n", MIN_ELF_SIZE);
        return 1;
    }

    void *elf_data = mmap(0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (elf_data == MAP_FAILED)
        errquit("mmap(..)");

    disasm_ctx_t *ctx;

    if (disasm_from_elf(&ctx, elf_data) < 0) {
        fprintf(stderr, "Failed to disassemble\n");
        return 1;
    }

    print_disassembly(ctx, target_section);

    disasm_free(ctx);

    munmap(elf_data, file_size);

    return 0;
}
