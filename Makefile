CFLAGS=-ggdb -Wall -Wextra -Werror

BUILD_DIR=./build

DISASM_DIR=./disasm
DISASM_LIB_DIR=$(DISASM_DIR)/build
DISASM_INCLUDES_DIR=$(DISASM_DIR)

.PHONY: default
default: all

clean:
	rm -rf $(BUILD_DIR)

all: $(BUILD_DIR)/dbger

$(BUILD_DIR)/dbger: dbger.c ansi.c maps.c $(DISASM_DIR)/build/libdisasm.a $(DISASM_DIR)/disasm.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(DISASM_INCLUDES_DIR) -L$(DISASM_LIB_DIR) dbger.c -l:libdisasm.a -lxed -o $(BUILD_DIR)/dbger
