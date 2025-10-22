#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdbool.h>
#include<unistd.h>
#include<fcntl.h>
#include<string.h>

#include "maps.h"

static int read_pid_file(char **content, pid_t pid) {
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

    if (close(fd) < 0)
        return -1;

    *content = (char *) map_content;

    return r;
}

int proc_maps_from_pid(proc_map_array *out_maps, pid_t pid) {
    char *maps_content;
    int maps_size;
    if ((maps_size = read_pid_file(&maps_content, pid)) < 0)
        return -1;

    size_t size = 0;
    size_t capacity = 4;
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
                    map.perms |= MAP_PERM_EXEC;
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
        int i = 0;
        while (maps_content[curr++] != '\n') {
            map.pathname[i] = maps_content[curr - 1];
            i++;
        }
        map.pathname[i] = '\0';

        maps[size++] = map;
        if (size >= capacity) {
            capacity *= 2;
            maps = realloc(maps, sizeof(*maps) * capacity);
        }

        if (curr >= maps_size)
           break;
    }

    free(maps_content);

    *out_maps = (proc_map_array) {
        .length = size,
        .items = maps,
    };

    return 0;
}

void free_proc_maps(proc_map_array *maps) {
    for (size_t i = 0; i < maps->length; i++)
        free(maps->items[i].pathname);

    free(maps->items);
}

void __print_maps(proc_map_array *maps) {
    for (size_t i = 0; i < maps->length; i++) {
        proc_map map = maps->items[i];

        fprintf(stderr, "%s (%lx-%lx) (%b)\n", map.pathname, map.addr_start, map.addr_end, map.perms);
    }
}
