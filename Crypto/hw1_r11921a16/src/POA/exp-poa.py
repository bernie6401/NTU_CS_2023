#!/usr/bin/env python3

import sys
from pwn import *
from tqdm import trange

p = remote('edu-ctf.zoolab.org',10004)
# p = process(['python', './POA_4af88990ab364609.py'])

ct = p.readline()[:-1].decode()
print(ct)
ct = bytes.fromhex(ct)
iv, ct1, ct2 = ct[:16], ct[16:32], ct[32:48]
flag = bytearray(32) 
index = 31

count1 = 0
_iv, _ct1, _ct2 = bytearray(ct[:16]), bytearray(ct[16:32]), bytearray(ct[32:48])
for i in trange(15, -1, -1):
    count2 = count1
    count1 = 0
    for j in range(256):
        _ct1[i] = j
        p.sendline(bytearray.hex(_ct1+_ct2).encode())
        reply = p.readline()[:-1].decode()
        if reply == 'Well received :)':
            count1 += 1
            if j != ct1[i]:
                flag[index] = ct1[i] ^ _ct1[i] ^ 128

    if abs(count1 - count2) == 1:
        flag[index] = 128
    _ct1[i] = 0 ^ flag[index] ^ ct1[i]
    index -= 1

_iv, _ct1, _ct2 = bytearray(ct[:16]), bytearray(ct[16:32]), bytearray(ct[32:48])
for i in trange(15, -1, -1):
    for j in range(256):
        _iv[i] = j
        p.sendline(bytearray.hex(_iv+_ct1).encode())
        reply = p.readline()[:-1].decode()
        if reply == 'Well received :)':
            flag[index] = _iv[i] ^ iv[i] ^ 128
            break
    _iv[i] = 0 ^ flag[index] ^ iv[i]
    index -= 1

print(bytes(flag))