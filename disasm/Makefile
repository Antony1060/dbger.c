CFLAGS=-ggdb -fPIC -Wall -Wextra -Werror

BUILD_DIR=./build

.PHONY: default
default: $(BUILD_DIR)/disasm.so #$(BUILD_DIR)/disasm.a

clean:
	rm -rf $(BUILD_DIR)

$(BUILD_DIR)/disasm.so: $(BUILD_DIR)/disasm.o
	$(CC) -lxed -shared $(BUILD_DIR)/disasm.o -o $(BUILD_DIR)/libdisasm.so


$(BUILD_DIR)/disasm.o: disasm.c disasm.h ansi.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c disasm.c -o $(BUILD_DIR)/disasm.o

examples: $(BUILD_DIR)/examples

$(BUILD_DIR)/examples: $(BUILD_DIR)/disasm.so disasm.h
	$(MAKE) -C examples all
