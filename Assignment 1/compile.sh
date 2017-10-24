#!/bin/bash

echo '######### NASM #########'
echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o

echo '[+] Done!'

echo '######### GCC #########'
echo '[+] Assembling with Gcc ... '
gcc $1.c -o $1.c_bin