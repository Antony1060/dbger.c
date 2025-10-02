#ifndef __DBGER_MAPS
#define __DBGER_MAPS

#include<fcntl.h>
#include<sys/mman.h>
#include<sys/stat.h>

// idk
enum {
    MAP_PERM_READ = 1 << 0,
    MAP_PERM_WRITE = 1 << 1,
    MAP_PERM_EXECUTE = 1 << 2,
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

static int read_pid_file(char **content, int pid) {
    char file_name[64];
    snprintf(file_name, 64, "/proc/%d/maps", pid);

    int fd;
    if ((fd = open(file_name, O_RDONLY)) < 0)
        return -1;

    int buf_size = 4096;
    char *map_content = malloc(buf_size);
    int r = 0;
    int r_curr = 0;
    while ((r_curr = read(fd, map_content + r, buf_size - r)) > 0) {
        r += r_curr;
    }

    *content = (char *) map_content;

    return r;
}

int proc_map_from_pid(proc_map **out_maps, int pid) {
    char *maps_content;
    int maps_size;
    if ((maps_size = read_pid_file(&maps_content, pid)) < 0)
        return -1;

    int size = 0;
    int capacity = 4;
    proc_map *maps = malloc(sizeof(*maps) * capacity);

    int curr = 0;
    while (true) {
        proc_map map = {0};
        sscanf(maps_content + curr, "%lx-%lx", &map.addr_start, &map.addr_end);

        while (maps_content[curr++] != ' ');

        while (maps_content[curr++] != ' ') {
            char c = maps_content[curr - 1];
            switch (c) {
                case 'r':
                    map.perms |= MAP_PERM_READ;
                    break;
                case 'w':
                    map.perms |= MAP_PERM_WRITE;
                    break;
                case 'x':
                    map.perms |= MAP_PERM_EXECUTE;
                    break;
                case 's':
                    map.perms |= MAP_PERM_SHARED;
                    break;
                case 'p':
                    map.perms |= MAP_PERM_PRIVATE;
                    break;
            } 
        }

        sscanf(maps_content + curr, "%lx", &map.offset);

        // after offset
        while (maps_content[curr++] != ' ');

        // after dev
        while (maps_content[curr++] != ' ');

        // after inode
        while (maps_content[curr++] != ' ');

        // pathname
        while (maps_content[curr++] == ' ');
        curr--;

        map.pathname = malloc(256);
        map.pathname[0] = '\0';
        int i = 0;
        while (maps_content[curr++] != '\n') {
            map.pathname[i] = maps_content[curr - 1];
            i++;
        }

        maps[size++] = map;
        if (size >= capacity) {
            capacity *= 2;
            maps = realloc(maps, sizeof(*maps) * capacity);
        }

        if (curr >= maps_size)
           break; 
    }

    free(maps_content);

    *out_maps = maps;
    return size;
}

void free_proc_maps(proc_map *maps, int sz) {
    for (int i = 0; i < sz; i++)
        free(maps[i].pathname);

    free(maps);
}

#endif // __DBGER_MAPS
