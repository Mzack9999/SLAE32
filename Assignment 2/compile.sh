#!/bin/bash

echo '######### GCC #########'
echo '[+] Assembling native c implementation with Gcc ... '
gcc ReverseShellTcp.c -o ReverseShellTcp.c_bin
echo '[+] Done!'
echo

echo '######### NASM #########'
echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'