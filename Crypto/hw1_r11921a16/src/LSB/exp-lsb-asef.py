from pwn import remote
from Crypto.Util.number import long_to_bytes, inverse
from math import log
proc = remote("edu-ctf.zoolab.org", 10005)
n, e, enc = proc.recvlines(3)
n = int(n.decode())
e = int(e.decode())
enc = int(enc.decode())
print(f"n is {n}")
print(f"e is {e}")
mult = inverse(pow(3, e, n), n)
msg = enc
pt = []

pow_3_inv_tbl = [ pow(3, -i, n) for i in range(int(log(n, 3))) ]

for i in range(int(log(n, 3))):
    proc.sendline(str(msg).encode())
    res = int(proc.recvline().strip())
    sub = 0
    for idx, p in enumerate(pt):
        sub = (sub + ((p * pow_3_inv_tbl[i-idx]) % n)) % n
    pt.append((res - sub) %3)
    if i % 100 == 0:
        print(long_to_bytes(int("".join([str(p) for p in pt][::-1]), 3)))
    msg = (msg * mult) % n
    
print(long_to_bytes(int("".join([str(p) for p in pt][::-1]), 3)))