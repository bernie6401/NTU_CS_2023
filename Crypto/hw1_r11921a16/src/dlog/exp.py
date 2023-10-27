from pwn import *
from Crypto.Util.number import *
from sage.all import *

smooth_prime = 2
while True:
    bitLen = smooth_prime.bit_length()
    if bitLen > 1024:
        smooth_prime = 2
    if bitLen == 1024:
        if isPrime(smooth_prime + 1):
            print(smooth_prime+1)
            smooth_prime = smooth_prime + 1
            break
    smooth_prime *= getPrime(10)

r = remote("10.113.184.121", 10032)
# r = process(["python", "dlog_bfc156b3a0eec196.py"])

g = 2
r.recvuntil(b": ")
r.sendline(str(smooth_prime).encode())
r.recvuntil(b'give me a number: ')
r.sendline(str(g).encode())
r.recvuntil(b'The hint about my secret: ')
hint = r.recvline()

print(f'Smooth Prime is: {smooth_prime}')
print("g = 2")
print(f'hint = {hint.decode().strip()}')

flag = discrete_log(Mod(hint, smooth_prime), Mod(g, smooth_prime))
print(f"Flag = {long_to_bytes(flag).decode()}")

r.close()