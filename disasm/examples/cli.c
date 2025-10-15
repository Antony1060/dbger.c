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

    char *symbol_name_map[section->size];
    memset(symbol_name_map, 0, section->size * sizeof(*symbol_name_map));
    for (size_t i = 0; i < section->n_symbols; i++) {
        disasm_symbol_t *sym = &section->symbols[i];

        if (sym->addr < section->code_start || sym->addr >= section->code_start + section->size)
            fprintf(stderr, "symbol error: out of bounds %lu (%lu, %lu)", sym->addr, section->code_start, section->size);

        symbol_name_map[sym->addr - section->code_start] = sym->name;
    }

    for (size_t i = 0; i < section->n_instructions; i++) {
        disasm_instruction_t *inst = &section->instructions[i];

        if (symbol_name_map[inst->addr - section->code_start]) {
            printf("\n" HCYN "%s" HBLK ":" CRESET "\n", symbol_name_map[inst->addr - section->code_start]);
        }

        printf("\t" HYEL "%p" HBLK ":\t" BLU "%s" CRESET "\t " HGRN "%s" CRESET, (void *) inst->addr, inst->inst_name, inst->inst_args);

        if (inst->has_branch_meta) {
            disasm_branch_meta_t *branch = &inst->branch_meta;

            if (branch->pretty_target[0])
                printf(" %s", branch->pretty_target);

            printf(HBLK "    # 0x%lx", branch->resolved_addr);
        }
        
#if PRINT_RAW_INST
        printf("\t" HYEL "%ld:", inst->inst_size);

        for (size_t b = 0; b < inst->inst_size; b++)
            printf("%.2x", inst->inst_raw[b]);
#endif // PRINT_RAW_INST

        printf(CRESET "\n");
    }
}

void print_disassembly(disasm_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->n_sections; i++) {
        disasm_section_t *section = &ctx->sections[i];

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

    print_disassembly(ctx);

    disasm_free(ctx);

    munmap(elf_data, file_size);

    return 0;
}
