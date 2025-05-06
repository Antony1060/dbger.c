CFLAGS=-ggdb -Wall -Wextra -Werror -lxed

main: main.c disasm.c ansi.c
	$(CC) $(CFLAGS) main.c -o main

disasm.o: disasm.c ansi.c
	$(CC) $(CFLAGS) disasm.c -o disasm.o
