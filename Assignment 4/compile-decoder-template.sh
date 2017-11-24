#!/bin/bash

echo '######### NASM #########'

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o decoder.template.nasm.o decoder.template.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o decoder.template.nasm.bin decoder.template.nasm.o
echo '[+] Done!'

rm -rf decoder.template.nasm.o

echo '[+] Objdump ...'
mycode=`objdump -d ./decoder.template.nasm.bin |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'`
echo $mycode