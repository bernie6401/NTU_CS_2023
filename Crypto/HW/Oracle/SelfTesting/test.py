from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from random import randbytes
from tqdm import trange
import pdb


def unpad(c):
    length = c[-1]
    for char in c[-length:]:
        if char != length:
            raise ValueError
    return c[:-length]

def asymmetric_encryption(message, N, e):
    # encrypt message with RSA
    # message must be 16 bytes
    # padding 100 bytes random value
    padded_message = b'\x01' * 100 + message
    return pow(bytes_to_long(padded_message), e, N)

def symmetric_encryption(message, key, iv):
    # ecrypt message with AES + CBC Mode
    # message can be arbitrary length
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(message)
    iv = cipher.iv
    return iv, ct

def compute_know_part(padding_idx, known_key):
    if known_key == '':
        return b''
    known_part = b''
    for i in range(len(known_key)//2):
        known_part += bytes([int(known_key[i*2:i*2+2], 16) ^ padding_idx])
    
    return known_part

def construct_payload_and_verify(i, known_part, enc_self_key, encrypted_key):
    candidate = []
    for byte in range(256): # 每一個byte要猜最多256次
        # 自己控制
        self_pt = b'\x00' * (15-i) + bytes([byte]) + known_part
        log.info(f"self pt = {self_pt}")
        _, self_ct = symmetric_encryption(self_pt, self_key, self_iv)

        # 連線oracle並驗證
        # r = remote("10.113.184.121", 10031)
        r = process(['python', 'Alice_efe9e435de6947a4.py'])
        r.sendlineafter(b'key: ', str(enc_self_key).encode())
        r.sendlineafter(b'iv: ', str(encrypted_key).encode())
        r.sendlineafter(b'ciphertext: ', self_ct.hex().encode())#enc_png.hex().encode()
        res = r.recvline().decode().strip()
        # log.info(f'key = {enc_self_key}, iv = {encrypted_key}, ct = {self_ct.hex()}')
        print(res)

        if 'OK! Got it.' in res:
            tmp = hex(byte ^ (i+1))[2:]
            if len(tmp) < 2:
                tmp = '0' + tmp
            candidate.append(tmp)
        r.close()
    if len(candidate) == 0:
        raise ValueError
    return candidate


test_iv = b'\x04\x03\x02\xf2' * 4#randbytes(16)#
self_iv = b'\x00' * 16
self_key = b'\x00' * 16
N = 93157624457739630671880388225844849100057633796052268458531287779667852123078046218882249140554400294818788781148341255692346829158401522349942104889920889115624592803842436575129311626508007002262278665442945772634277313692189010022998247726927520910102479827264989670228381218440410115787601354095026723019
e = 65537
enc_self_key = asymmetric_encryption(self_key, N, e)
# enc_self_key = 37692732586243414244883385425379946391696634879223592672040101660442004916125798082823600075186581672337156127696672833847322087996261612548939529008027557560467439263930519707084876333020997934464342162152484396727606477460996731055824908832770220980454538043357986040244817387314504850711866917200927564444
# encrypted_iv = 28060362061254273087769335816395964510183930994036626719561071633381050819069795104058887993575549810027699089556809928861189949404010506687164988600530508530672600226708063848890769746404344111395226274976233567243366300590382964293031453948459819500359885099487252423837865226227937543483406510739568981209
known_key = ''
encrypted_iv = asymmetric_encryption(test_iv, N, e)

# for i in range(16):
#     known_part = compute_know_part(i+1, known_key)
#     for byte in range(256):
#         self_pt = b'\x00' * (15-i) + bytes([byte]) + known_part
#         print(self_pt)
#         _, self_ct = symmetric_encryption(self_pt, self_key, self_iv)
#         r = process(['python', 'Alice_efe9e435de6947a4.py'])
#         # r = remote("10.113.184.121", 10031)
#         r.sendlineafter(b'key: ', str(enc_self_key).encode())
#         r.sendlineafter(b'iv: ', str(encrypted_iv).encode())
#         r.sendlineafter(b'ciphertext: ', self_ct.hex().encode())
#         res = r.recvline().decode().strip()
#         if 'OK! Got it.' in res and byte != 240:#res == 'OK! Got it.'
#             print(res)
#             tmp = hex(byte ^ (i+1))[2:]
#             breakpoint()
#             if len(tmp) < 2:
#                 tmp = '0' + tmp
#             known_key = tmp + known_key
#             print(known_key)
#             print()
#             import time
#             time.sleep(2)
#             break
#         r.close()

real_iv = ''
i = 0
known_part = compute_know_part(i+1, real_iv)
candidate = construct_payload_and_verify(i, known_part, enc_self_key, encrypted_iv)
i += 1
breakpoint()
while(len(real_iv) != 32): # iv共有16bytes
    for candidate_tmp in candidate:
        known_part = compute_know_part(i+1, candidate_tmp + real_iv)
        
        try:
            candidate = construct_payload_and_verify(i, known_part, enc_self_key, encrypted_iv)
            breakpoint()
            i += 1
            real_iv = candidate_tmp + real_iv
            break
        except:
            breakpoint()
            pass

print(test_iv.hex())
print(known_key)