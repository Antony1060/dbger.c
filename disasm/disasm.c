#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<elf.h>
#include<xed/xed-interface.h>
#include<assert.h>

#include "disasm.h"
#include "ansi.h"

#define MIN_ELF_SIZE 64

#define errquit(...) return 1

// only supports 64-bit for now
static_assert((sizeof(disasm_elf_header_t) == 64), "elf_header is not 64 bytes");

static Elf64_Shdr def_symtab = {
    .sh_type = SHT_SYMTAB,
};

static char* PLT_STUB_NAME = "__resolver_stub";

typedef struct {
    size_t last_dist;
    size_t out_sym_idx;
    // most of the time sym->st_name, but sometimes I need a custom name
    char *name;
} sym_table_entry_t;

typedef struct {
    sym_table_entry_t *items;
    size_t length;
    uint64_t start_addr;
} sym_table_t;

typedef struct {
    bool is_plt;
    Elf64_Shdr *rela_plt;
    Elf64_Shdr *dynsym;
    void *dynstr_data;

    Elf64_Shdr *gnu_version;
    Elf64_Shdr *gnu_version_r;
} plt_data_t;

static bool validate_elf_header(disasm_elf_header_t *header) {
    if (header->e_ident.ei_magic.value != 0x464c457f)
        return false;

    // TODO: support more than 64-bit x86_64 executables
    if (header->e_version != 1 || (header->e_type != 2 && header->e_type != 3) || header->e_machine != 0x3e)
        return false;

    return true;
}

static uint64_t find_jump_target_after_rip(xed_decoded_inst_t *xedd, void *ip, size_t inst_len) {
    size_t memop_len = xed_decoded_inst_number_of_memory_operands(xedd);
    for (size_t i = 0; i < memop_len; i++) {
        xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd, i);

        return (uint64_t) ip + inst_len + disp;
    }
    return 0;
}

static uint64_t find_jump_target(xed_decoded_inst_t *xedd, void *ip, size_t inst_len, xed_category_enum_t *_category) {
    xed_category_enum_t category = xed_decoded_inst_get_category(xedd);

    if(_category)
        *_category = category;

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

size_t __disasm_read_first_instruction(uint8_t *code, size_t code_len, char* buffer, size_t len, void *ip, uint64_t* jump_target, xed_category_enum_t* category) {
    size_t b_read;
    size_t ciel = code_len > 15 ? 15 : code_len;

    xed_decoded_inst_t xedd;
    // TODO: maybe move out
    xed_chip_features_t chip_features;
    xed_get_chip_features(&chip_features, XED_CHIP_ALL);
    xed_modify_chip_features(&chip_features, XED_ISA_SET_CET, 1);
    for (b_read = 1; b_read <= ciel; b_read++) {
        xed_error_enum_t xed_error;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

        xed_error = xed_decode_with_features(&xedd, (const xed_uint8_t *) code, b_read, &chip_features);
        if (xed_error == XED_ERROR_NONE)
            break;
    }

    *jump_target = find_jump_target(&xedd, ip, b_read, category);

    if (!xed_format_context(XED_SYNTAX_INTEL, &xedd, buffer, len, (const xed_uint64_t) ip, 0, 0)) {
        return 0;
    }

    return b_read;
}

void __disasm_color_instruction(char* buffer, char* name, char* args) {
    size_t len = strlen(buffer);

    int inst_len = 0;
    int params_len = 0;

    bool inst_done = 0;
    for (size_t i = 0; i < len; i++) {
        char c = buffer[i];
        if (!inst_done) {
            if (c != ' ')
                name[inst_len++] = c;
            else
                inst_done = true;
            continue;
        }

        args[params_len++] = c;
    }

    name[inst_len] = '\0';
    args[params_len] = '\0';
}

static Elf64_Vernaux *walk_versions(Elf64_Verneed *verneed_head, Elf64_Half idx) {
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

static void write_full_dynamic_symbol(char* buffer, void *elf_data, Elf64_Rela *rela, plt_data_t plt_data) {
    uint64_t dynsym_idx = ELF64_R_SYM(rela->r_info);

    Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + plt_data.dynsym->sh_offset)) + dynsym_idx;

    char *name = plt_data.dynstr_data + sym->st_name;
    char *version = 0;

    if (plt_data.gnu_version && plt_data.gnu_version_r) {
        Elf64_Half *versions = elf_data + plt_data.gnu_version->sh_offset;

        Elf64_Half version_index = versions[dynsym_idx];

        Elf64_Verneed *vns = elf_data + plt_data.gnu_version_r->sh_offset;

        Elf64_Vernaux *vna = walk_versions(vns, version_index);

        if (vna)
            version = plt_data.dynstr_data + vna->vna_name;
    }

    if (version)
        sprintf(buffer, "%s@%s", name, version);
    else
        sprintf(buffer, "%s", name);
}

static int code_disassemble(disasm_section_t* section, void *elf_data, uint8_t *code, size_t n, void* start_addr, sym_table_t *sym_table, sym_table_t *plt_table, plt_data_t plt_data) {
    char buffer[256];
    void *ip = start_addr;

    size_t capacity = 1;
    section->instructions = malloc(sizeof(*section->instructions) * capacity);
    section->n_instructions = 0;
    while (n != 0) {
        uint64_t jump_target;
        xed_category_enum_t category;
        size_t shift = __disasm_read_first_instruction(code, n, buffer, 256, ip, &jump_target, &category);
        if (shift == 0) {
            return -1;
        }

        sym_table_entry_t *inst_sym = NULL;
        uint64_t inst_table_idx = (uint64_t) ip - sym_table->start_addr;
        if (inst_table_idx < sym_table->length && sym_table->items[inst_table_idx].name != 0)
            inst_sym = &sym_table->items[inst_table_idx];

        section->instructions[section->n_instructions] = (disasm_instruction_t) {
            .addr = (uintptr_t) ip,
            .inst_raw = code,
            .inst_size = shift,
            .inst_name = malloc(32),
            .inst_args = malloc(256),
            .closest_symbol = inst_sym ? &section->symbols[inst_sym->out_sym_idx] : NULL,
            .closest_symbol_offset = inst_sym ? inst_sym->last_dist : 0,
            .is_branch_like = category == XED_CATEGORY_COND_BR || category == XED_CATEGORY_UNCOND_BR || category == XED_CATEGORY_CALL,
            .has_branch_meta = jump_target != 0,
            .branch_meta = {0}
        };

        disasm_instruction_t* inst = &section->instructions[section->n_instructions];
        __disasm_color_instruction(buffer, inst->inst_name, inst->inst_args);

        if (jump_target) {
            disasm_branch_meta_t* branch = &inst->branch_meta;
            branch->pretty_target = malloc(256);
            branch->pretty_target[0] = '\0';
            uint64_t target_table_idx = jump_target - sym_table->start_addr;
            if (target_table_idx < sym_table->length && sym_table->items[target_table_idx].name != 0) {
                sym_table_entry_t target_entry = sym_table->items[target_table_idx];
                int w = sprintf(branch->pretty_target, "<" GRN "%s", target_entry.name);

                if (target_entry.last_dist != 0) {
                    w += sprintf(branch->pretty_target + w, HBLU "+0x%lx", target_entry.last_dist);
                }

                sprintf(branch->pretty_target + w, CRESET ">");

                branch->symbol = &section->symbols[target_entry.out_sym_idx];
                branch->symbol_offset = target_entry.last_dist;
            } else if (plt_table) {
                target_table_idx = jump_target - plt_table->start_addr;
                if (target_table_idx < plt_table->length && plt_table->items[target_table_idx].name != 0) {
                    sym_table_entry_t target_entry = plt_table->items[target_table_idx];
                    int w = sprintf(branch->pretty_target, "<" HBLU "plt" HBLK ":" GRN "%s", target_entry.name);

                    if (target_entry.last_dist != 0) {
                        w += sprintf(branch->pretty_target + w, HBLU "+0x%lx", target_entry.last_dist);
                    }

                    sprintf(branch->pretty_target + w, CRESET ">");

                    branch->is_plt = 1;
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

                    sprintf(branch->pretty_target, "<" HBLU "got" HBLK ":" GRN "%s" CRESET ">", buf);
                    branch->is_got = 1;

                    break;
                }
            }

            branch->resolved_addr = (uintptr_t) jump_target;
        }

        n -= shift;
        code += shift;
        ip += shift;

        section->n_instructions++;
        if (section->n_instructions >= capacity) {
            capacity *= 2;
            section->instructions = realloc(section->instructions, sizeof(disasm_instruction_t) * capacity);
        }
    }

    return 0;
}

static int handle_exec_section(disasm_section_t* out_section, void *elf_data, Elf64_Shdr *section, void *elf_strtab_data, Elf64_Shdr *elf_symtab, sym_table_t *plt_table, plt_data_t plt_data, sym_table_t *sym_table) {
    uint64_t symtab_sz = (elf_symtab->sh_size) / sizeof(Elf64_Sym);
    uint64_t code_begin = section->sh_addr;
    uint64_t code_end = code_begin + section->sh_size;

    sym_table->start_addr = code_begin;

    out_section->code_start = code_begin;
    out_section->size = code_end - code_begin;

    // fill symbol table
    memset(sym_table->items, 0, sym_table->length * sizeof(*sym_table->items));

    size_t sym_cnt = 0;
    if (!plt_data.is_plt) {
        for (uint64_t i = 1; i < symtab_sz; i++) {
            Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + elf_symtab->sh_offset)) + i;

            // assume executable code is in between (sh_addr) and (sh_addr + sh_size)
            if (sym->st_value < code_begin || sym->st_value >= code_end)
                continue;

            uint64_t idx = sym->st_value - code_begin;
            sym_table_entry_t val = { 0, 0, elf_strtab_data + sym->st_name };
            sym_table->items[idx] = val;

            sym_cnt++;
        }
    } else {
        sym_table_entry_t stub_val = { 0, 0, PLT_STUB_NAME };
        sym_table->items[0] = stub_val;
        sym_cnt++;
        for (size_t i = 1; i < section->sh_size / 16; i++) {
            uint64_t addr = code_begin + (i * 16);

            Elf64_Rela *rela = ((Elf64_Rela *) (elf_data + plt_data.rela_plt->sh_offset)) + (i - 1);
            uint64_t dynsym_idx = ELF64_R_SYM(rela->r_info);

            Elf64_Sym *sym = ((Elf64_Sym *) (elf_data + plt_data.dynsym->sh_offset)) + dynsym_idx;

            uint64_t idx = addr - code_begin;
            sym_table_entry_t val = { 0, 0, plt_data.dynstr_data + sym->st_name };
            sym_table->items[idx] = val;

            sym_cnt++;
        }
    }

    out_section->symbols = malloc(sizeof(*out_section->symbols) * sym_cnt);
    out_section->n_symbols = 0;

    // patch up symbol table and fill output
    sym_table_entry_t last = {0};
    for (size_t i = 0; i < section->sh_size; i++) {
        sym_table_entry_t* curr = &sym_table->items[i];

        if ((curr->name != 0 || last.name == 0) && last.name != curr->name) {
            curr->out_sym_idx = out_section->n_symbols;
            out_section->symbols[out_section->n_symbols++] = (disasm_symbol_t) {
                .name = curr->name,
                .addr = code_begin + i
            };
            last = *curr;
            continue;
        }

        last.last_dist++;
        sym_table->items[i] = last;
    }

    void* code = elf_data + section->sh_offset;

    if (code_disassemble(out_section, elf_data, (uint8_t *) code, section->sh_size, (void *) code_begin, sym_table, plt_table, plt_data) < 0)
        return -1;

    return 0;
}

// TODO: better error handling, currently anything < 0 is an error
// the parser will (unsafely) start assuming the elf is valid and try parsing whatever bytes after *elf_data
//  the returned context will also reference memory from elf_data, so it must exist as long as the output is used (TODO?)
__attribute__((used))
int disasm_from_elf(disasm_ctx_t** out, void *elf_data) {
    static bool xed_init = 0;
    if (!xed_init) {
        xed_tables_init();
        xed_init = 1;
    }

    disasm_elf_header_t *elf_header = (disasm_elf_header_t *) elf_data;

    if (!validate_elf_header(elf_header)) {
        return -1;
    }

    Elf64_Shdr *elf_shdr =  (Elf64_Shdr *) (elf_data + elf_header->e_shoff);

    Elf64_Shdr *elf_shstrtab = elf_shdr + elf_header->e_shstrndx;
    void *elf_shstrtab_data = (elf_data + elf_shstrtab->sh_offset);

    // assume one string table, I'm actually not sure if there can be multiple
    Elf64_Shdr *elf_strtab = 0;
    Elf64_Shdr *elf_symtab = 0;

    Elf64_Shdr *elf_rela_plt = 0;
    Elf64_Shdr *elf_dynsym = 0;
    Elf64_Shdr *elf_dynstr = 0;

    Elf64_Shdr *elf_gnu_version = 0;
    Elf64_Shdr *elf_gnu_version_r = 0;

    Elf64_Shdr *elf_execs[elf_header->e_shnum];
    size_t elf_execs_cnt = 0;

    for (uint64_t i = 0; i < elf_header->e_shnum; i++) {
        Elf64_Shdr shdr = elf_shdr[i];

        if (shdr.sh_type == SHT_NULL)
            continue;

        char* name = elf_shstrtab_data + shdr.sh_name;

        Elf64_Shdr *addr = (Elf64_Shdr *) elf_shdr + i;

        if (shdr.sh_type == SHT_SYMTAB) {
            //fprintf(stderr, "symtab found at: %p\n", addr);
            elf_symtab = addr;
        }

        if (shdr.sh_type == SHT_STRTAB && i != elf_header->e_shstrndx) {
            //fprintf(stderr, "strtab found at: %p\n", addr);
            elf_strtab = addr;
        }

        if (shdr.sh_type == SHT_RELA && !strcmp(name, ".rela.plt")) {
            //fprintf(stderr, ".rela.plt found at: %p\n", addr);
            elf_rela_plt = addr;
        }

        if (shdr.sh_type == SHT_DYNSYM) {
            //fprintf(stderr, "dynsym found at: %p\n", addr);
            elf_dynsym = addr;
        }

        if (shdr.sh_type == SHT_STRTAB && !strcmp(name, ".dynstr")) {
            //fprintf(stderr, ".dynstr found at: %p\n", addr);
            elf_dynstr = addr;
        }

        if (!strcmp(name, ".gnu.version")) {
            //fprintf(stderr, ".gnu.version found at: %p\n", addr);
            elf_gnu_version = addr;
        }

        if (!strcmp(name, ".gnu.version_r")) {
            //fprintf(stderr, ".gnu.version_r found at: %p\n", addr);
            elf_gnu_version_r = addr;
        }

        if (shdr.sh_flags & SHF_EXECINSTR) {
            //fprintf(stderr, "found exec section '%s' at: %p\n", name, addr);
            elf_execs[elf_execs_cnt++] = addr;
        }
    }

    if (elf_symtab == NULL) {
        elf_symtab = &def_symtab;
    }

    if (elf_strtab == NULL) {
        return -1;
    }

    *out = malloc(sizeof(**out));

    disasm_ctx_t* ctx = *out;
    ctx->elf_header = *elf_header;
    ctx->sections = malloc(sizeof(*ctx->sections) * elf_execs_cnt);
    ctx->n_sections = elf_execs_cnt;
    sym_table_t *plt_table = NULL;

    void *elf_strtab_data = (elf_data + elf_strtab->sh_offset);

    bool is_binary_dynamic_compatible = elf_header->e_type == 3 && elf_rela_plt && elf_dynsym && elf_dynstr;

    for (size_t i = 0; i < elf_execs_cnt; i++) {
        Elf64_Shdr *shdr = elf_execs[i];

        char* name = elf_shstrtab_data + shdr->sh_name;

        plt_data_t plt_data = {0};
        if (!strcmp(name, ".plt") && is_binary_dynamic_compatible) {
            plt_data.is_plt = 1;
            plt_data.rela_plt = elf_rela_plt;
            plt_data.dynsym = elf_dynsym;
            plt_data.dynstr_data = (elf_data + elf_dynstr->sh_offset);

            plt_data.gnu_version = elf_gnu_version;
            plt_data.gnu_version_r = elf_gnu_version_r;
        }

        sym_table_t *sym_table = malloc(sizeof(*sym_table));
        sym_table->items = malloc(shdr->sh_size * sizeof(*sym_table->items));
        sym_table->length = shdr->sh_size;

        ctx->sections[i] = (disasm_section_t) {0};
        ctx->sections[i].name = name;

        if (handle_exec_section(&ctx->sections[i], elf_data, shdr, elf_strtab_data, elf_symtab, plt_table, plt_data, sym_table) < 0) {
            free(sym_table->items);
            free(sym_table);
            return -1;
        }

        if (plt_data.is_plt) {
            plt_table = sym_table;
        } else {
            free(sym_table->items);
            free(sym_table);
        }
    }

    if (plt_table) {
        free(plt_table->items);
        free(plt_table);
    }

    return 0;
}

void free_instruction(disasm_instruction_t *inst) {
    free(inst->inst_name);
    free(inst->inst_args);

    if (inst->has_branch_meta) {
        free(inst->branch_meta.pretty_target);
    }
}

void free_section(disasm_section_t *section) {
    free(section->symbols);

    for (size_t i = 0; i < section->n_instructions; i++)
        free_instruction(&section->instructions[i]);

    free(section->instructions);
}

__attribute__((used))
void disasm_free(disasm_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->n_sections; i++)
        free_section(&ctx->sections[i]);

    free(ctx->sections);
    free(ctx);
}

