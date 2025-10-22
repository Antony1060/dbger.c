#ifndef __DBGER_DISASSEMBLY
#define __DBGER_DISASSEMBLY

int open_and_disasm(disasm_ctx_t **_ctx, void **_elf_data, size_t *stat_size, const char *target_pathname);

#endif // __DBGER_DISASSEMBLY
