#ifndef __DBGER_MAPS
#define __DBGER_MAPS

enum {
    MAP_PERM_READ = 1 << 0,
    MAP_PERM_WRITE = 1 << 1,
    MAP_PERM_EXEC = 1 << 2,
    MAP_PERM_SHARED = 1 << 3,
    MAP_PERM_PRIVATE = 1 << 4
};

typedef struct {
    uint64_t addr_start; 
    uint64_t addr_end; 
    int perms;
    uint64_t offset;
    // dev
    // inode
    char *pathname;
} proc_map;

int proc_map_from_pid(proc_map **out_maps, int pid);

void free_proc_maps(proc_map *maps, int sz);

#endif // __DBGER_MAPS
