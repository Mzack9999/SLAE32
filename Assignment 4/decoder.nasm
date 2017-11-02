
; Filename: Decoder.nasm
; Author:  SLAE-935
;
; Purpose: decode bytecode in chunks of 8 bytes preserving the status

global _start			

section .text

_start:

    mov ebx,0xfdb6e7fb ; initial key
    push ebx
    xor edx,edx ; i = 0
    push edx
    pop edx ; begin for loop
    pop ebx
    jmp short 0x47 ; getPC
    pop edi ; edi=buff addr
    xor ecx,ecx
    cmp edx,ecx
    jz 0x36 ; skip copy if i==0
    xor ecx,ecx
    mov cl,0xc ; words to copy
    push ebx
    push edx
    mov esi,edx
    imul esi,ecx
    shl esi,0x2
    add esi,edi ; esi=edi+(i*ecx*4)
    mov ebx,ecx ; copy loop
    sub bl,0x1
    shl ebx,0x2 ; ebx=(ecx-1)*4
    mov edx,[esi+ebx] ; tmp=src
    mov [edi+ebx],edx ; dst=tmp
    loop 0x24
    pop edx ; edx=i
    pop ebx ; ebx=key
    xor ecx,ecx
    mov cl,0xc ; words to decode
    xor [edi+ecx*4-0x4],ebx ; decode loop
    loop 0x3a
    add ebx,[edi] ; modify key
    push ebx ; store for next loop
    inc edx ; i++
    push edx ; store for next loop
    jmp short 0x4c ; call decoded buffer
    call 0xd