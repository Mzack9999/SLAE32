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
another part instead is put somewhere else, and have much more space available. The egg hunting tecnique consists in a two staged payload, the first, smaller, searches for a particular pattern in memory,
with which the second larger part is identified and executed. As from the paper mentioned earlier the pattern is usually 4 bytes long, and repeated twice, so that the egg-hunter won't transfer execution
to its own code.

## Implementation