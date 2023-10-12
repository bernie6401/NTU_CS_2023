from sage.all import *
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes
from pwn import *

# NIST P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

def solveDL():
    b = randint(1, p)
    E = EllipticCurve(Zmod(p), [a, b])
    G = E.gen(0)
    order = E.order()
    # print(order)
    factors = prime_factors(order)
    # print(factors)
    valid = []
    for factor in factors:
        if factor <= 2**40:
            valid.append(factor)
    prime = valid[-1]
    new_G = G * int(order / prime)
    tmp_point = new_G.xy()
    tmp_x, tmp_y = str(tmp_point[0]), str(tmp_point[1])

    try:
        r = remote('10.113.184.121', 10034)
        r.recvline()
        r.sendlineafter(b'Gx: ', tmp_x.encode())
        r.sendlineafter(b'Gy: ', tmp_y.encode())
        hint = r.recvline().decode().strip()
        ct_x, ct_y = hint.rstrip(')').lstrip('(').split(', ')
        r.close()
    except Exception as e:
        r.close()
        print(e)
        return None, None

    # print(f'Position (ct_x, ct_y) = ({ct_x}, {ct_y})')
    new_hint = E(int(ct_x), int(ct_y))
    aprt_of_flag = discrete_log(new_hint, new_G, operation='+')
    print(f"Flag' found: {aprt_of_flag}")
    return (aprt_of_flag, prime)
    
def getDLs():
    dlogs = []
    primes = []
    for i in range(1, 16):
        log, prime = solveDL()
        if log != None:
            dlogs.append(log)
            primes.append(prime)
        print(f"counter: {i}")
    return dlogs, primes

dlogs, primes = getDLs()
print(f"dlogs: {dlogs}")
print(f"primes: {primes}")
super_secret = CRT_list(dlogs, primes)
print(f'Flag: {long_to_bytes(super_secret).decode()}')