CFLAGS=-ggdb -fPIC -Wall -Wextra -Werror

BUILD_DIR=./build

.PHONY: default
default: all

clean:
	rm -rf $(BUILD_DIR)

all: $(BUILD_DIR)/libdisasm.so $(BUILD_DIR)/libdisasm.a

$(BUILD_DIR)/libdisasm.so: $(BUILD_DIR)/disasm.o
	$(CC) -shared -lxed $(BUILD_DIR)/disasm.o -o $(BUILD_DIR)/libdisasm.so

$(BUILD_DIR)/libdisasm.a: $(BUILD_DIR)/disasm.o
	ar rcs $(BUILD_DIR)/libdisasm.a $(BUILD_DIR)/disasm.o

$(BUILD_DIR)/disasm.o: disasm.c disasm.h ansi.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c disasm.c -o $(BUILD_DIR)/disasm.o

examples: $(BUILD_DIR)/examples

$(BUILD_DIR)/examples: all disasm.h
	$(MAKE) -C examples all
