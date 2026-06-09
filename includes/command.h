#include "state.h"

typedef enum {
    TRACE_CONTINUE,
    TRACE_INST_STEP,
    TRACE_EXIT
} trace_next;

int handle_input(state_ctx *ctx, trace_next *outcome);
