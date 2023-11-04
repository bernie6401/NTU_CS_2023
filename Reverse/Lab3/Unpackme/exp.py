from pwn import *

r = process(['./unpackme'])

print(r.recv(13))
# raw_input()
r.sendline(b'askdlfjl')

r.interactive()