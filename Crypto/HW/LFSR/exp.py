from tqdm import trange
import numpy as np
from functools import reduce

class LFSR:
    def __init__(self, tap, state):
        self._tap = tap
        self._state = state

    def getbit(self):
        f = sum([self._state[i] for i in self._tap]) & 1
        x = self._state[0]
        self._state = self._state[1:] + [f]
        return x
    
def verification(taps, key):
    randomness = LFSR(taps, key)
    output = []
    for _ in range(256 + 64):
        for __ in range(70):
            randomness.getbit()
        output.append(randomness.getbit())
    
    return output[:256], output[256:]

def get_flag(cipher_flag, output):
    flag = ""
    plaintext_hex = ''
    for idx, i in enumerate(range(len(cipher_flag))):
        flag += str(output[i] ^ cipher_flag[i])
        if (idx+1) % 8 == 0:
            plaintext_hex += hex(int(flag, 2))[2:]
            flag = ""
    return bytes.fromhex(plaintext_hex).decode("cp437")

def special_dot(m1, m2):
    mr = np.empty((m1.shape[0], m2.shape[1]), dtype = np.int64)
    for i in range(mr.shape[0]):
        for j in range(mr.shape[1]):
            mr[i, j] = reduce(lambda x, y: x ^ y, (m1[i, :] & m2[:, j]))
    return mr

if __name__ == '__main__':
    f = [0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0]
    # f = [0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1]
    # Initialization
    taps = [0, 2, 17, 19, 23, 37, 41, 53]
    init_state_size = 64
    cipher_text_xor_flag, cipher_text = f[:len(f)-70], f[len(f)-70:]
    cipher_text = np.array(cipher_text[:init_state_size]).reshape((len(cipher_text[:init_state_size]), 1))

    # Create companion Matrix
    a = np.eye(init_state_size-1, dtype = 'int')    # 創造對角矩陣
    b = np.zeros((init_state_size-1, 1), dtype=int) # 創造最左邊全為0的行
    c = np.array([1 if i in taps else 0 for i in range(init_state_size)])   # 創造最後一列的taps
    comp_matrix = np.vstack([np.hstack([b, a]), c]) # 全部組合起來

    # 做內積的運算
    _comp_matrix = comp_matrix  # _comp_matrix代表會變動的companion matrix
    start_count = 257
    arr_merge = True
    for i in trange(71*(len(cipher_text_xor_flag)+len(cipher_text))):   # 總共跑71 * (256 + 64) = 22720
        _comp_matrix = special_dot(comp_matrix, _comp_matrix)   # 因為是在mod 2底下處理，所以不是普通的dot運算，乘法對應到AND，加法對應到XOR
        if i == 71 * start_count - init_state_size - 1:
            if arr_merge:
                real_comp_matrix = _comp_matrix[-1]
                arr_merge = False
            else:
                real_comp_matrix = np.vstack([real_comp_matrix, _comp_matrix[-1]])
            start_count += 1
    
    inv_real_comp_matrix = np.linalg.inv(real_comp_matrix)
    tmp = inv_real_comp_matrix.dot(cipher_text)
    init_state = [1 if tmp[i] > 0 else 0 for i in range(len(tmp))]

    output, check = verification(taps, init_state)

    fd = open('./Crypto/HW/LFSR/tmp_state.txt', 'w')
    fd.write(f"real_comp_matrix = \n{real_comp_matrix}\n\ninv_real_comp_matrix = \n{inv_real_comp_matrix}\n\ntmp = \n{tmp}\n\ninit_state = \n{init_state}\n\noutput[256:] = \n{check}\n\nverify_state = \n{cipher_text.reshape(1, len(cipher_text)).tolist()[0]}")
    fd.close()

    assert check == cipher_text.reshape(1, len(cipher_text)).tolist()[0]

    get_flag(cipher_text_xor_flag, output)