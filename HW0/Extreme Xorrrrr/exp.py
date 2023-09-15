from Crypto.Util.number import *
from functools import reduce


def chinese_remainder(m, a):
    sum = 0
    prod = reduce(lambda acc, b: acc*b, m)
    for n_i, a_i in zip(m, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod
 
def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

def de_xor(nums):
    result = []
    tmp = 0
    for i in range(len(nums)):
        tmp ^= nums[i]
    for i in range(len(nums)):
        result.append(tmp ^ nums[i])
    
    return result

def xorrrrr(nums):
    n = len(nums)
    result = [0] * n
    for i in range(1, n):
        result = [ result[j] ^ nums[(j+i) % n] for j in range(n)]
    return result

hint = [3867643078, 3287416726, 901811051, 2873881227, 2270268909, 1555321936, 1419723682, 135531391, 1648732744, 2346142192, 1505498859, 2103436123, 4202619523, 2326904236, 1938136472, 366121018, 773968139, 2415223764, 490067400, 1902082872]
muls = [784927, 1022769, 932825, 746975, 815007, 613147, 537543, 852211, 618443, 866769, 910981, 825227, 838133, 1027271, 776063, 1038141, 571529, 664495, 1025729, 593197]
mods = [2286703839, 2358297603, 3964421567, 3907762623, 2849800663, 2382674777, 2503252379, 2798053355, 3995552795, 2910773165, 3724203063, 2416156797, 2179309517, 3641528223, 2846518171, 2688752197, 4248246955, 2871652981, 2639686887, 4182550363]

Real_hint = de_xor(hint)
Real_muls = de_xor(muls)
Real_mods = de_xor(mods)

assert hint == xorrrrr(Real_hint)
assert muls == xorrrrr(Real_muls)
assert mods == xorrrrr(Real_mods)

count = 4
while(True):
    m = [Real_mods[i] for i in range(count)]
    a = [Real_hint[i]*inverse(Real_muls[i], Real_mods[i]) for i in range(count)]
    crt_result = chinese_remainder(m, a)
    if 'flag' in long_to_bytes(crt_result).decode("cp437"):
        print('Count = ', count)
        print(long_to_bytes(crt_result).decode("cp437"))
        break
    count += 1