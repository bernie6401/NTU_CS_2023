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
        flag += str(output[i] ^^ cipher_flag[i])
        if (idx+1) % 8 == 0:
            plaintext_hex += hex(int(flag, 2))[2:]
            flag = ""
    return bytes.fromhex(plaintext_hex).decode("cp437")

if __name__ == '__main__':
    f = [0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0]

    # Initialization
    taps = [0, 2, 17, 19, 23, 37, 41, 53]
    init_state_size = 64
    cipher_text_xor_flag, cipher_text = f[:len(f)-70], f[len(f)-70:]
    cipher_text = Matrix(np.array(cipher_text[:init_state_size]).reshape((init_state_size, 1)).tolist())

    # Create companion Matrix
    a = np.eye(init_state_size-1, dtype = int)    # 創造對角矩陣
    b = np.zeros((init_state_size-1, 1), dtype=int) # 創造最左邊全為0的行
    c = np.array([1 if i in taps else 0 for i in range(init_state_size)])   # 創造最後一列的taps
    comp_matrix = Matrix(np.vstack([np.hstack([b, a]), c]).tolist()) # 全部組合起來

    # 做內積的運算
    _comp_matrix = comp_matrix  # _comp_matrix代表會變動的companion matrix
    real_comp_matrix = np.empty(init_state_size, dtype=int)
    count = 256
    arr_merge = True
    for i in trange(71*319+6+1):
        _comp_matrix = comp_matrix * _comp_matrix % 2   # 因為是在mod 2底下處理，所以不是普通的dot運算，乘法對應到AND，加法對應到XOR
        if i == 71 * count + 5:
            real_comp_matrix = np.vstack([real_comp_matrix, _comp_matrix[-1]])
            count += 1

    # 計算在模2情況下的反矩陣
    inv_real_comp_matrix = Matrix(IntegerModRing(2), real_comp_matrix[1:]).inverse()

    # 算出initial state
    init_state = inv_real_comp_matrix * cipher_text % 2
    init_state = list(init_state.numpy().reshape(1, init_state_size)[0])
    print("Initial State = ", init_state)

    output, check = verification(taps, init_state)

    assert list(cipher_text.numpy().reshape(1, 64)[0]) == check

    # 如果assert通過，代表找到正確的initial state然後就可以反算flag
    print(get_flag(cipher_text_xor_flag, output))