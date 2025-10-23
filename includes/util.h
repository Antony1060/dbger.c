#ifndef __DBGER_UTIL
#define __DBGER_UTIL

#include<errno.h>
#include<string.h>

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

#define MIN(_a, _b) ({ \
        __typeof__(_a) a = (_a); \
        __typeof__(_b) b = (_b); \
        a < b ? a : b; \
    })

static inline int strncmp_min(const char *first, const char *second) {
    return strncmp(first, second, MIN(strlen(first), strlen(second)) + 1);
}

#endif // __DBGER_UTIL
