.PHONY = default
default:
	gcc -ggdb -Wall -Wextra -Werror -lxed dbger.c -o dbger
