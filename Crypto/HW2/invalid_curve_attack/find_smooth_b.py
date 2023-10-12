from sage.all import *

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 56

factor_element_max_digit = 21
while(factor_element_max_digit > 20):
    try:
        b += 1
        E = EllipticCurve(Zmod(p), [a, b])
        order = E.gen(0).order()
        tmp = str(factor(order)).split(' * ')
        factor_element_max_digit = len(tmp[-1])
        if factor_element_max_digit < 30:
            print("It might be a candidate:", b, "\n", factor(order))
    except:
        print(b)