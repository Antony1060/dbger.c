#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdbool.h>
#include<sys/mman.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<errno.h>
#include<string.h>
#include<elf.h>
#include<ctype.h>
#include<xed/xed-interface.h>

#include "ansi.c"

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

#define MIN_ELF_SIZE 64

typedef struct elf_ident_s {
    union {
        uint32_t value;
        uint8_t bytes[4];
    } ei_magic;
    uint8_t ei_class;
    uint8_t ei_data;
    uint8_t ei_version;
    uint8_t ei_osabi;
    uint8_t ei_abiversion;
    uint8_t ei_pad[7];
} elf_ident_t;

bool validate_elf_header(Elf64_Ehdr *header) {
    elf_ident_t elf_ident = *((elf_ident_t *)header);
    
    /*printf("ei_magic (int): %x\n", elf_ident.ei_magic.value);
    printf("ei_magic (bytes):");

    for (int i = 0; i < 4; i++) {
        printf(" %c (0x%x)", elf_ident.ei_magic.bytes[i], elf_ident.ei_magic.bytes[i]);
    }
    printf("\n");

    printf("ei_class: %x\n", elf_ident.ei_class);
    printf("ei_data: %x\n", elf_ident.ei_data);
    printf("ei_version: %x\n", elf_ident.ei_version);
    printf("ei_osabi: %x\n", elf_ident.ei_osabi);
    printf("ei_abiversion: %x\n", elf_ident.ei_abiversion);

    printf("e_type: %x\n", header->e_type);
    printf("e_machine: %x\n", header->e_machine);
    printf("e_version: %x\n", header->e_version);*/

    if (elf_ident.ei_magic.value != 0x464c457f)
        return false;

    // TODO: support more than 64-bit x86_64 static executables
    if (header->e_version != 1 || (header->e_type != 2 && header->e_type != 3) || header->e_machine != 0x3e)
        return false;

    return true;
}

void print_strtab(Elf64_Shdr *strtab_header, void *elf_data, void *shstrtab) {
    char* sh_name = (char*) (shstrtab + strtab_header->sh_name);
    printf("strtab %s:\n", sh_name);
    char* data = (char*) (elf_data + strtab_header->sh_offset);
    for (uint64_t i = 0; i < strtab_header->sh_size; i++) {
        if (isprint(data[i]))
            printf("%c", data[i]);
        else if (data[i] == '\0')
            printf("\n");
        else
            printf("\\x%x", data[i]);
    }

    printf("\n");
}

size_t read_first_instruction(uint8_t *code, size_t code_len, char* buffer, size_t len, void *ip, uint64_t* jump_target) {
    size_t b_read;
    size_t ciel = code_len > 15 ? 15 : code_len;

    xed_decoded_inst_t xedd;
    for (b_read = 1; b_read <= ciel; b_read++) {
        xed_error_enum_t xed_error;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

        xed_error = xed_decode(&xedd, (const xed_uint8_t *) code, b_read);
        if (xed_error == XED_ERROR_NONE)
            break;
    }

    xed_category_enum_t category = xed_decoded_inst_get_category(&xedd);

    *jump_target = 0;

    if (category == XED_CATEGORY_COND_BR || category == XED_CATEGORY_UNCOND_BR || category == XED_CATEGORY_CALL) {
        xed_int64_t disp = xed_decoded_inst_get_branch_displacement(&xedd);
        xed_uint64_t target = ((const xed_uint64_t) ip) + b_read + disp;

        *jump_target = target;
    }

    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, buffer, len, (const xed_uint64_t) ip, 0, 0)) {
        return 0;
    }

    return b_read;
}

void color_instruction(char* buffer, char* new_buffer) {
    size_t len = strlen(buffer);

    char inst[32];
    char params[256 - 32];
    int inst_len = 0;
    int params_len = 0;

    bool inst_done = 0;
    for (size_t i = 0; i < len; i++) {
        char c = buffer[i];
        if (!inst_done) {
            if (c != ' ')
                inst[inst_len++] = c;
            else
                inst_done = true;
            continue;
        }

        params[params_len++] = c;
    }

    sprintf(new_buffer, BLU "%.*s" CRESET "\t " HGRN "%.*s" CRESET, inst_len, inst, params_len, params);
}

void print_disassembly(uint8_t *code, size_t n, void* start_addr, void* strtab, Elf64_Sym **sym_table, size_t sym_table_len) {
    char buffer[256];
    char formatted_buffer[256];
    void *ip = start_addr;
    
    while (n != 0) {
        uint64_t jump_target;
        size_t shift = read_first_instruction(code, n, buffer, 256, ip, &jump_target);
        if (shift == 0) {
            fprintf(stderr, "failed to decode instructions");
            exit(1);
        }

        uint64_t table_idx = ((uint64_t) ip) - (uint64_t) start_addr;
        // table_idx should always be within bounds of sym_table
        if (table_idx < sym_table_len && sym_table[table_idx] != 0) {
            char *sym_name = (char *) strtab + sym_table[table_idx]->st_name;
            printf("\n" HCYN "%s" HBLK ":" CRESET "\n", sym_name);
        }

        color_instruction(buffer, formatted_buffer);

        printf("\t" HYEL "%p" HBLK ":\t" HGRN "%s" CRESET, ip, formatted_buffer);

        if (jump_target) {
            uint64_t target_table_idx = jump_target - (uint64_t) start_addr;
            if (target_table_idx < sym_table_len && sym_table[target_table_idx] != 0) {
                char *sym_name = (char *) strtab + sym_table[target_table_idx]->st_name; 
                printf(" <" GRN "%s" CRESET ">", sym_name);
            }
        }

        printf("\n");

        n -= shift;
        code += shift;
        ip += shift;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <elf...>\n", argv[0]);
        return 1;
    }

    xed_tables_init();

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

    Elf64_Ehdr *elf_header = (Elf64_Ehdr *) elf_data;

    if (!validate_elf_header(elf_header)) {
        fprintf(stderr, "ELF header is invalid\n");
        return 1;
    }

    Elf64_Shdr *elf_shdr =  (Elf64_Shdr *) (elf_data + elf_header->e_shoff);
    
    Elf64_Shdr *elf_shstrtab = elf_shdr + elf_header->e_shstrndx;
    void *elf_shstrtab_data = (elf_data + elf_shstrtab->sh_offset);

    // assume one string table, I'm actually not sure if there can be multiple
    Elf64_Shdr *elf_strtab;
    Elf64_Shdr *elf_symtab;

    Elf64_Shdr *elf_text;
        
    for (int i = 0; i < elf_header->e_shnum; i++) {
        Elf64_Shdr shdr = elf_shdr[i];

        if (shdr.sh_type == SHT_NULL)
            continue;

        char* name = elf_shstrtab_data + shdr.sh_name;
    
        if (shdr.sh_type == SHT_SYMTAB) {
            fprintf(stderr, "symtab found at: %p\n", &shdr); 
            elf_symtab = elf_shdr + i;
        }

        if (shdr.sh_type == SHT_STRTAB && i != elf_header->e_shstrndx) {
            fprintf(stderr, "strtab found at: %p\n", &shdr);
            elf_strtab = elf_shdr + i;
        }

        if (shdr.sh_flags & SHF_EXECINSTR && !strcmp(name, ".text")) {
            fprintf(stderr, ".text found at: %p\n", &shdr);
            elf_text = elf_shdr + i;
        }
    }

    if (elf_symtab == NULL) {
        fprintf(stderr, "no symbol table found\n");
        return 1;
    }

    if (elf_strtab == NULL) {
        fprintf(stderr, "no string table found\n");
        return 1;
    }

    void *elf_strtab_data = (elf_data + elf_strtab->sh_offset);
    
    uint64_t symtab_sz = (elf_symtab->sh_size) / sizeof(Elf64_Sym);

    uint64_t code_begin = elf_text->sh_addr;
    uint64_t code_end = code_begin + elf_text->sh_size;

    Elf64_Sym *sym_table[elf_text->sh_size];
    memset(sym_table, 0, elf_text->sh_size * sizeof(*sym_table));

    for (uint64_t i = 1; i < symtab_sz; i++) {
        Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + elf_symtab->sh_offset)) + i;

        // assume executable code is in between (elf_text.sh_addr) and (elf_text.sh_addr + elf_text.sh_size)
        if (sym->st_value < code_begin || sym->st_value >= code_end)
           continue; 

        uint64_t idx = sym->st_value - code_begin;
        sym_table[idx] = sym;
    }
    
    void* code = elf_data + elf_text->sh_offset;
    print_disassembly((uint8_t *) code, elf_text->sh_size, (void *) code_begin, elf_strtab_data, sym_table, elf_text->sh_size);

    munmap(elf_data, file_size);

    return 0;
}
