## dbger 
A very basic implementation of an x86 debugger, not meant to be actaully used. Still work in progress.

## Build
```sh
# disassembler
cc -Wall -Wextra -Werror -lxed disasm.c -o disasm

# debugger
cc -Wall -Wextra -Werror -lxed dbger.c -o dbger
```

## Run
```sh
./disasm <elf...>

./dbger <command...>
```
