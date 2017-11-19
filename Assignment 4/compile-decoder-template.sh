#!/bin/bash

echo '######### NASM #########'

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o decoder.template.nasm.o decoder.template.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o decoder.template.nasm.bin decoder.template.nasm.o
echo '[+] Done!'

rm -rf decoder.template.nasm.o