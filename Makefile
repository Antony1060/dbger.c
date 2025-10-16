CFLAGS=-ggdb -Wall -Wextra -Werror -D_GNU_SOURCE

BUILD_DIR=./build

DISASM_DIR=./disasm
DISASM_LIB_DIR=$(DISASM_DIR)/build

SRC=$(wildcard *.c)
OBJ=$(SRC:%.c=$(BUILD_DIR)/%.o)
TARGET=./dbger

.PHONY: default
default: all

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

all: $(TARGET)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I. -c $< -o $@

$(TARGET): $(OBJ) $(DISASM_DIR)/build/libdisasm.a $(DISASM_DIR)/disasm.h
	$(CC) -L$(DISASM_LIB_DIR) $(OBJ) -l:libdisasm.a -lxed -o $(TARGET)
