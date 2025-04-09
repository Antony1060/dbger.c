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

//
//  THIS. IS. NOT. GOOD. CODE. PLEASE. READ. IT. WITH. CAUTION. THANK. YOU.
//      I. AM. LOSING. MY. MIND. HELP. 
//

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

static char* PLT_STUB_NAME = "__resolver_stub";

typedef struct sym_table_entry_s {
    size_t last_dist;
    // most of the time sym->st_name, but sometimes I need a custom name
    char *name;
} sym_table_entry_t;

typedef struct sym_table_s {
    sym_table_entry_t *items;
    size_t length;
    uint64_t start_addr;
} sym_table_t;

typedef struct plt_data_s {
    bool is_plt;
    Elf64_Shdr *rela_plt;
    Elf64_Shdr *dynsym;
    void *dynstr_data;

    Elf64_Shdr *gnu_version;
    Elf64_Shdr *gnu_version_r;
} plt_data_t;

bool validate_elf_header(Elf64_Ehdr *header) {
    elf_ident_t elf_ident = *((elf_ident_t *)header);
    
    if (elf_ident.ei_magic.value != 0x464c457f)
        return false;

    // TODO: support more than 64-bit x86_64 executables
    if (header->e_version != 1 || (header->e_type != 2 && header->e_type != 3) || header->e_machine != 0x3e)
        return false;

    return true;
}

uint64_t find_jump_target_after_rip(xed_decoded_inst_t *xedd, void *ip, size_t inst_len) {
    size_t memop_len = xed_decoded_inst_number_of_memory_operands(xedd); 
    for (size_t i = 0; i < memop_len; i++) {
        xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, i);
    
        return (uint64_t) ip + inst_len + disp;
    }
    return 0;
}

uint64_t find_jump_target(xed_decoded_inst_t *xedd, void *ip, size_t inst_len) {
    xed_category_enum_t category = xed_decoded_inst_get_category(xedd);
    
    if (category != XED_CATEGORY_COND_BR && category != XED_CATEGORY_UNCOND_BR && category != XED_CATEGORY_CALL)
        return 0;
   
    const xed_inst_t *inst = xed_decoded_inst_inst(xedd);
    uint32_t operands_len = xed_inst_noperands(inst);

    for (uint32_t i = 0; i < operands_len; i++) {
        const xed_operand_t *op = xed_inst_operand(inst, i);
        xed_operand_enum_t op_name = xed_operand_name(op);

        switch (op_name) {
            case XED_OPERAND_PTR:
            case XED_OPERAND_ABSBR:
            case XED_OPERAND_RELBR:
                xed_int64_t disp = xed_decoded_inst_get_branch_displacement(xedd);
                xed_uint64_t target = ((const xed_uint64_t) ip) + inst_len + disp;
                
                return target;
           default:
                break;
        }

        if (xed_operand_is_register(op_name)) {
            xed_reg_enum_t reg = xed_decoded_inst_get_reg(xedd, op_name);
            
            // we can figure out the correct address for RIP
            if (reg == XED_REG_RIP) {
                return find_jump_target_after_rip(xedd, ip, inst_len);
            }
        }

        // TODO: memory operands
    }

    return 0;
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

    *jump_target = find_jump_target(&xedd, ip, b_read);

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

Elf64_Vernaux *walk_versions(Elf64_Verneed *verneed_head, Elf64_Half idx) {
    // idc, this is how we walk a linked list now
    while (true) {
        Elf64_Vernaux *vnas = ((void *) verneed_head) + verneed_head->vn_aux;
        for (Elf64_Half i = 0; i < verneed_head->vn_cnt; i++) {
            Elf64_Vernaux vna = vnas[i];

            if (vna.vna_other == idx)
                return vnas + i;
        }
       
        if (!verneed_head->vn_next)
           break;

        verneed_head = ((void *) verneed_head) + verneed_head->vn_next;
    } 

    return 0;
}

void write_full_dynamic_symbol(char* buffer, void *elf_data, Elf64_Rela *rela, plt_data_t plt_data) {
    uint64_t dynsym_idx = ELF64_R_SYM(rela->r_info);
    
    Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + plt_data.dynsym->sh_offset)) + dynsym_idx;

    char *name = plt_data.dynstr_data + sym->st_name;
    char *version = 0;

    if (plt_data.gnu_version && plt_data.gnu_version_r) {
        Elf64_Half *versions = elf_data + plt_data.gnu_version->sh_offset;

        Elf64_Half version_index = versions[dynsym_idx];

        Elf64_Verneed *vns = elf_data + plt_data.gnu_version_r->sh_offset;

        Elf64_Vernaux *vna = walk_versions(vns, version_index);

        version = plt_data.dynstr_data + vna->vna_name;
    }   

    if (version)
        sprintf(buffer, "%s@%s", name, version);
    else
        sprintf(buffer, "%s", name);
}

void print_disassembly(void *elf_data, uint8_t *code, size_t n, void* start_addr, sym_table_t *sym_table, sym_table_t *plt_sym_table, plt_data_t plt_data) {
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
        if (table_idx < sym_table->length) {
            sym_table_entry_t entry = sym_table->items[table_idx];

            if (entry.name != 0 && entry.last_dist == 0) {
                printf("\n" HCYN "%s" HBLK ":" CRESET "\n", entry.name);
            }
        }

        color_instruction(buffer, formatted_buffer);

        printf("\t" HYEL "%p" HBLK ":\t" HGRN "%s" CRESET, ip, formatted_buffer);

        if (jump_target) {
            uint64_t target_table_idx = jump_target - sym_table->start_addr;
            if (target_table_idx < sym_table->length && sym_table->items[target_table_idx].name != 0) {
                sym_table_entry_t target_entry = sym_table->items[target_table_idx];
                printf(" <" GRN "%s", target_entry.name);
                
                if (target_entry.last_dist != 0) {
                    printf(HBLU "+0x%lx", target_entry.last_dist);
                }

                printf(CRESET ">");
            } else if (plt_sym_table) {
                target_table_idx = jump_target - plt_sym_table->start_addr;
                if (target_table_idx < plt_sym_table->length && plt_sym_table->items[target_table_idx].name != 0) {
                    sym_table_entry_t target_entry = plt_sym_table->items[target_table_idx];
                    printf(" <" HBLU "plt" HBLK ":" GRN "%s", target_entry.name);
                
                    if (target_entry.last_dist != 0) {
                        printf(HBLU "+0x%lx", target_entry.last_dist);
                    }

                    printf(CRESET ">");
                }
            }
    
            // if we're logging a plt table, it's nice to show that a jump is going to a GOT (like objdump -d -j .plt shows)
            if (plt_data.is_plt) {
                // 🍝
                
                size_t rela_len = plt_data.rela_plt->sh_size / sizeof (Elf64_Rela);
                for (size_t i = 0; i < rela_len; i++) {
                    Elf64_Rela *rela = ((Elf64_Rela *) (elf_data + plt_data.rela_plt->sh_offset)) + i;
                    
                    if (rela->r_offset != jump_target)
                        continue;
                    
                    char buf[256];
                    write_full_dynamic_symbol(buf, elf_data, rela, plt_data);

                    printf(" <" HBLU "got" HBLK ":" GRN "%s" CRESET ">", buf);
                }
            }

            printf(HBLK "    # 0x%lx", jump_target);
        }

        printf(CRESET "\n");

        n -= shift;
        code += shift;
        ip += shift;
    }
}

void handle_exec_section(void *elf_data, Elf64_Shdr *section, void *elf_strtab_data, Elf64_Shdr *elf_symtab, bool do_print, plt_data_t plt_data, sym_table_t *plt_sym_table, sym_table_t *sym_table) {
    uint64_t symtab_sz = (elf_symtab->sh_size) / sizeof(Elf64_Sym);
    uint64_t code_begin = section->sh_addr;
    uint64_t code_end = code_begin + section->sh_size;

    sym_table->start_addr = code_begin;

    // fill symbol table
    memset(sym_table->items, 0, sym_table->length * sizeof(*sym_table->items));

    if (!plt_data.is_plt) {
        for (uint64_t i = 1; i < symtab_sz; i++) {
            Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + elf_symtab->sh_offset)) + i;

            // assume executable code is in between (elf_text.sh_addr) and (elf_text.sh_addr + elf_text.sh_size)
            if (sym->st_value < code_begin || sym->st_value >= code_end)
                continue;

            uint64_t idx = sym->st_value - code_begin;
            sym_table_entry_t val = { 0, elf_strtab_data + sym->st_name };
            sym_table->items[idx] = val;
        }
    } else {
        sym_table_entry_t stub_val = { 0, PLT_STUB_NAME };
        sym_table->items[0] = stub_val;
        for (size_t i = 1; i < section->sh_size / 16; i++) {
            uint64_t addr = code_begin + (i * 16);
            
            Elf64_Rela *rela = ((Elf64_Rela *) (elf_data + plt_data.rela_plt->sh_offset)) + (i - 1);
            uint64_t dynsym_idx = ELF64_R_SYM(rela->r_info);

            Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + plt_data.dynsym->sh_offset)) + dynsym_idx;

            uint64_t idx = addr - code_begin;
            sym_table_entry_t val = { 0, plt_data.dynstr_data + sym->st_name };
            sym_table->items[idx] = val;
        }
    }

    // patch up symbol table
    sym_table_entry_t last = {0};
    for (size_t i = 0; i < section->sh_size; i++) {
        sym_table_entry_t curr = sym_table->items[i];

        if ((curr.name != 0 || last.name == 0) && last.name != curr.name) {
            last = curr;
            continue;
        }

        last.last_dist++;
        sym_table->items[i] = last;
    }

    void* code = elf_data + section->sh_offset;

    if (do_print)
        print_disassembly(elf_data, (uint8_t *) code, section->sh_size, (void *) code_begin, sym_table, plt_sym_table, plt_data);
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

    Elf64_Shdr *elf_rela_plt;
    Elf64_Shdr *elf_dynsym;
    Elf64_Shdr *elf_dynstr;
    
    Elf64_Shdr *elf_gnu_version;
    Elf64_Shdr *elf_gnu_version_r;

    Elf64_Shdr *elf_execs[elf_header->e_shnum];
    size_t elf_execs_cnt = 0;
        
    for (uint64_t i = 0; i < elf_header->e_shnum; i++) {
        Elf64_Shdr shdr = elf_shdr[i];

        if (shdr.sh_type == SHT_NULL)
            continue;

        char* name = elf_shstrtab_data + shdr.sh_name;
   
        Elf64_Shdr *addr = (Elf64_Shdr *) elf_shdr + i;

        if (shdr.sh_type == SHT_SYMTAB) {
            fprintf(stderr, "symtab found at: %p\n", addr); 
            elf_symtab = addr;
        }

        if (shdr.sh_type == SHT_STRTAB && i != elf_header->e_shstrndx) {
            fprintf(stderr, "strtab found at: %p\n", addr);
            elf_strtab = addr;
        }

        if (shdr.sh_type == SHT_RELA && !strcmp(name, ".rela.plt")) {
            fprintf(stderr, ".rela.plt found at: %p\n", addr);
            elf_rela_plt = addr;
        }

        if (shdr.sh_type == SHT_DYNSYM) {
            fprintf(stderr, "dynsym found at: %p\n", addr);
            elf_dynsym = addr;
        }

        if (shdr.sh_type == SHT_STRTAB && !strcmp(name, ".dynstr")) {
            fprintf(stderr, ".dynstr found at: %p\n", addr);
            elf_dynstr = addr;
        }

        if (!strcmp(name, ".gnu.version")) {
            fprintf(stderr, ".gnu.version found at: %p\n", addr);
            elf_gnu_version = addr;
        }

        if (!strcmp(name, ".gnu.version_r")) {
            fprintf(stderr, ".gnu.version_r found at: %p\n", addr);
            elf_gnu_version_r = addr;
        }
        
        if (shdr.sh_flags & SHF_EXECINSTR) {
            fprintf(stderr, "found exec section '%s' at: %p\n", name, addr);
            elf_execs[elf_execs_cnt++] = addr;
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

    sym_table_t *plt_sym_table;

    for (size_t i = 0; i < elf_execs_cnt; i++) {
        Elf64_Shdr *shdr = elf_execs[i];

        char* name = elf_shstrtab_data + shdr->sh_name;

        plt_data_t plt_data = {0};
        if (!strcmp(name, ".plt")) {
            plt_data.is_plt = 1;
            plt_data.rela_plt = elf_rela_plt;
            plt_data.dynsym = elf_dynsym;
            plt_data.dynstr_data = (elf_data + elf_dynstr->sh_offset);

            plt_data.gnu_version = elf_gnu_version;
            plt_data.gnu_version_r = elf_gnu_version_r;
        }

        sym_table_t *sym_table = malloc(sizeof(sym_table_t));
        sym_table->items = malloc(shdr->sh_size * sizeof(*sym_table->items));
        sym_table->length = shdr->sh_size;

        bool should_print = !target_section || !strcmp(name, target_section);

        if (should_print)
            printf("\n\n" HBLK "disassembly of section " CRESET "%s" HBLK ": " CRESET "\n", name);

        handle_exec_section(elf_data, shdr, elf_strtab_data, elf_symtab, should_print, plt_data, plt_sym_table, sym_table);

        if (plt_data.is_plt) {
            plt_sym_table = sym_table;
        } else {
            free(sym_table->items);
            free(sym_table);
        }
    }

    if (plt_sym_table) {
        free(plt_sym_table->items);
        free(plt_sym_table);
    }
    munmap(elf_data, file_size);

    return 0;
}
