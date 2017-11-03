
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
    jmp short get_pc ; getPC
    pop edi ; edi=buff addr
    xor ecx,ecx
    cmp edx,ecx
copy_init:
    jz decode_init ; skip copy if i==0
    xor ecx,ecx
    mov cl,0xc ; words to copy
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
    xor ecx,ecx
decode_init:
    mov cl,0xc ; words to decode
decode_loop:
    xor [edi+ecx*4-0x4],ebx ; decode loop
    loop decode_loop
    add ebx,[edi] ; modify key
    push ebx ; store for next loop
    inc edx ; i++
    push edx ; store for next loop
    jmp EncodedShellcode ; call decoded buffer

get_pc:
    call 0xd

EncodedShellcode: db 0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,x01jump_to_decode_stub,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,x02jump_to_decode_stub
