from pwn import *

r = remote('chal1.eof.ais3.org', 10002)

n = int(r.recvline().decode().split(',')[0].split('=')[-1])
flag_ct = int(r.recvline()[:-1].decode().split(' ')[-1])

log.info(f'{n=}')
log.info(f'{flag_ct=}')

dummy = 2**64
new_ct = flag_ct * pow(dummy, 3, n) % n

print(new_ct)
r.sendlineafter(b'Any message for me?', str(new_ct).encode())
print(r.recvuntil(b'New Message: '))
c1 = int(r.recvline()[:-1])

r.sendlineafter(b'Any message for me?', str(new_ct).encode())
print(r.recvuntil(b'New Message: '))
c2 = int(r.recvline()[:-1])

r.sendlineafter(b'Any message for me?', str(new_ct).encode())
print(r.recvuntil(b'New Message: '))
c3 = int(r.recvline()[:-1])

log.info(f'{c1=}\n{c2=}\n{c3=}')

r.close()