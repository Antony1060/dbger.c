#ifndef __DBGER_UTIL
#define __DBGER_UTIL

#include<errno.h>
#include<string.h>

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

static inline size_t min(size_t a, size_t b) {
    return (a < b ? a : b);
}

static inline int strncmp_min(const char *first, const char *second) {
    return strncmp(first, second, min(strlen(first), strlen(second)) + 1);
}

#endif // __DBGER_UTIL
