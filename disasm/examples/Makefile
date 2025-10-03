CFLAGS=-ggdb -Wall -Wextra -Werror

BUILD_DIR=../build/examples
LIB_DIR=../build
INCLUDES_DIR=..

all: $(BUILD_DIR)/cli

$(BUILD_DIR)/cli: cli.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INCLUDES_DIR) -L$(LIB_DIR) cli.c -l:libdisasm.a -lxed -o $(BUILD_DIR)/cli
