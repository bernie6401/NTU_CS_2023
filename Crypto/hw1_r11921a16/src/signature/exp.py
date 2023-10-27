from pwn import *
from Crypto.Util.number import *
from hashlib import sha256
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key, Private_key, Signature

# r = process(["python", "./signature_416666d57b34123f.py"])
r = remote('10.113.184.121', 10033)

# Receive Some Info from Server
msg = 'a'
E = SECP256k1
G, n = E.generator, E.order
r.recvuntil(b'P = (')
x, y = r.recvline().decode().strip().rstrip(')').split(', ')
r.recvlines(3)
r.sendline(b'1')
r.sendlineafter(b'What do you want?', msg.encode())
r.recvuntil(b'sig = (')
r1, s1 = r.recvline().decode().strip().rstrip(')').split(', ')
r.recvlines(3)
r.sendline(b'1')
r.sendlineafter(b'What do you want?', msg.encode())
r.recvuntil(b'sig = (')
r2, s2 = r.recvline().decode().strip().rstrip(')').split(', ')

log.info(f'x = {x}\ny = {y}')
log.info(f'r1 = {r1}\ns1 = {s1}')
log.info(f'r2 = {r2}\ns2 = {s2}')

# Calculte Private Key - d
hash_msg = sha256(msg.encode()).digest()
inv_s1 = inverse(int(s1), n)
inv_s2 = inverse(int(s2), n)
hash_msg_decimal = bytes_to_long(hash_msg)
r1 = int(r1)
r2 = int(r2)
d = inverse(1337 * r1 * inv_s1 - r2 * inv_s2, n) * (hash_msg_decimal * inv_s2 - 1337 * hash_msg_decimal * inv_s1)
k1 = inv_s1 * (hash_msg_decimal + d * r1)
k2 = inv_s2 * (hash_msg_decimal + d * r2)
assert k2 % n == k1 * 1337 % n

# Forgery Signature & Send it
k = randint(1, n)
pubkey = Public_key(G, d*G)
prikey = Private_key(pubkey, d)
flag_msg = 'Give me the FLAG.'
flag_msg_h = sha256(flag_msg.encode()).digest()
sig = prikey.sign(bytes_to_long(flag_msg_h), k)
r.recvlines(3)
r.sendline(b'2')
r.sendlineafter(b'r: ', sig.r.digits().encode())
r.sendlineafter(b's: ', sig.s.digits().encode())
flag = r.recvline().strip().decode()

log.info(f'Flag: {flag}')

r.close()