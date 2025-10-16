#ifndef __DBGER_UTIL
#define __DBGER_UTIL

#include<errno.h>
#include<string.h>

#define errquit(s) do { \
    fprintf(stderr, "ERROR: "s": %s (%s)\n", strerror(errno), strerrorname_np(errno)); \
    exit(1); \
} while(0);

#endif // __DBGER_UTIL
