from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from random import randbytes


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
    # candidate = []
    for byte in range(256): # 每一個byte要猜最多256次
        # 自己控制
        self_pt = b'\x00' * (15-i) + bytes([byte]) + known_part
        log.info(f"self pt = {self_pt}")
        _, self_ct = symmetric_encryption(self_pt, self_key, self_iv)

        # 連線oracle並驗證
        r = remote("10.113.184.121", 10031)
        r.sendlineafter(b'key: ', str(enc_self_key).encode())
        r.sendlineafter(b'iv: ', str(encrypted_key).encode())
        r.sendlineafter(b'ciphertext: ', self_ct.hex().encode())#enc_png.hex().encode()
        res = r.recvline().decode().strip()
        # log.info(f'key = {enc_self_key}, iv = {encrypted_key}, ct = {self_ct.hex()}')
        print(res)

        if res == 'OK! Got it.':
            tmp = hex(byte ^ (i+1))[2:]
            if len(tmp) < 2:
                tmp = '0' + tmp
            return tmp
        r.close()


# 題目給的資訊
enc_png = open('./encrypted_flag_d6fbfd5306695c4a.not_png', 'rb').read()
N = 69214008498642035761243756357619851816607540327248468473247478342523127723748756926949706235406640562827724567100157104972969498385528097714986614165867074449238186426536742677816881849038677123630836686152379963670139334109846133566156815333584764063197379180877984670843831985941733688575703811651087495223
e = 65537
encrypted_key = 65690013242775728459842109842683020587149462096059598501313133592635945234121561534622365974927219223034823754673718159579772056712404749324225325531206903216411508240699572153162745754564955215041783396329242482406426376133687186983187563217156659178000486342335478915053049498619169740534463504372971359692
encrypted_iv = 35154524936059729204581782839781987236407179504895959653768093617367549802652967862418906182387861924584809825831862791349195432705129622783580000716829283234184762744224095175044663151370869751957952842383581513986293064879608592662677541628813345923397286253057417592725291925603753086190402107943880261658

# 自己控制的資訊
self_iv = b'\x00' * 16
self_key = b'\x00' * 16
enc_self_key = asymmetric_encryption(self_key, N, e)


# Try to POA Key
real_key = ''
for i in range(16): # iv共有16bytes
    known_part = compute_know_part(i+1, real_key)
    real_key = construct_payload_and_verify(i, known_part, enc_self_key, encrypted_key) + real_key

# Try to POA IV
real_iv = ''
for i in range(16): # iv共有16bytes
    known_part = compute_know_part(i+1, real_iv)
    real_iv = construct_payload_and_verify(i, known_part, enc_self_key, encrypted_iv) + real_iv

# Final Testing
test_key = pow(int(real_key, 16), e, N)
test_iv = pow(int(real_iv, 16), e, N)
r = remote("10.113.184.121", 10031)
r.sendlineafter(b'key: ', str(test_key).encode())
r.sendlineafter(b'iv: ', str(test_iv).encode())
r.sendlineafter(b'ciphertext: ', enc_png.hex().encode())
assert r.recvline().decode().strip() == 'OK! Got it.'

# Final Decrypt Flag Image
# real_key = '49276d5f345f357472306e395f6b3379'
# real_iv = '4ba3cb1c134651c3bb5cd6e381c2909b'
real_iv = bytes.fromhex(real_iv)
real_key = bytes.fromhex(real_key)
cipher = AES.new(real_key, AES.MODE_CBC, real_iv)
pt = unpad(cipher.decrypt(enc_png))
open("./decrypted_flag.png", "wb").write(pt)