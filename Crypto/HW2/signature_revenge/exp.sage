from Crypto.Util.number import *
from hashlib import sha256, md5
from ecdsa import SECP256k1
# from ecdsa.ecdsa import Public_key, Private_key
from secret import FLAG
from sage.all import *
import os

E = SECP256k1
G, n = E.generator, E.order
P = (70427896289635684269185763735464004880272487387417064603929487585697794861713, 83106938517126976838986116917338443942453391221542116900720022828358221631968)
sig1 = (26150478759659181410183574739595997895638116875172347795980556499925372918857, 50639168022751577246163934860133616960953696675993100806612269138066992704236)
sig2 = (8256687378196792904669428303872036025324883507048772044875872623403155644190, 90323515158120328162524865800363952831516312527470472160064097576156608261906)
h1 = bytes_to_long(sha256(b"https://www.youtube.com/watch?v=IBnrn2pnPG8").digest())
h2 = bytes_to_long(sha256(b"https://www.youtube.com/watch?v=1H2cyhWYXrE").digest())

r1, s1 = sig1
r2, s2 = sig2
s1_inv = inverse(s1, n)
s2_inv = inverse(s2, n)
r2_inv = inverse(r2, n)

b_matrix_t = -s1_inv * s2 * r1 * r2_inv
b_matrix_u = s1_inv * r1 * h2 * r2_inv - s1_inv * h1
b_matrix_K = 2**128
dommy = 1/(10**39)
b_matrix = [
    [n, 0, 0],
    [b_matrix_t, dommy, 0],
    [b_matrix_u, 0, b_matrix_K]
]
shortest_vector = matrix(b_matrix).LLL()
v = shortest_vector[0]
k1 = -v[0]
k2 = v[1]
tmp1 = long_to_bytes(k1)
tmp2 = long_to_bytes(k2)
log.info(f'k1 = {tmp1}\nk2 = {tmp2}')
assert tmp1[len(tmp1)//2:] == tmp2[:len(tmp2)//2]
