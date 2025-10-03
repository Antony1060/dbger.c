.PHONY = default
default:
	gcc -ggdb -Wall -Wextra -Werror dbger.c -lxed -o dbger
