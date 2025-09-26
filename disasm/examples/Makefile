CFLAGS=-ggdb -Wall -Wextra -Werror

BUILD_DIR=../build/examples
LIB_DIR=../build
INCLUDES_DIR=..

all: $(BUILD_DIR)/cli

$(BUILD_DIR)/cli: cli.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -L$(LIB_DIR) -I$(INCLUDES_DIR) -lxed -o $(BUILD_DIR)/cli cli.c -l:libdisasm.a

