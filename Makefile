.PHONY = default
default:
	gcc -Wall -Wextra -Werror -lxed dbger.c -o dbger
