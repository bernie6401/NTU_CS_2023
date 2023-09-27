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
    mr = np.empty((m1.shape[0], m2.shape[1]), dtype = int)
    for i in range(mr.shape[0]):
        for j in range(mr.shape[1]):
            mr[i, j] = reduce(lambda x, y: x ^ y, (m1[i, :] & m2[:, j]))
    return mr

def modMatInv(A,p):       # Finds the inverse of matrix A mod p
  n=len(A)
  A=np.matrix(A)
  adj=np.zeros(shape=(n,n))
  for i in range(0,n):
    for j in range(0,n):
      adj[i][j]=((-1)**(i+j)*int(round(np.linalg.det(minor(A,j,i)))))%p
  return (modInv(int(round(np.linalg.det(A))),p)*adj)%p

def modInv(a,p):          # Finds the inverse of a mod p, if it exists
  for i in range(1,p):
    if (i*a)%p==1:
      return i
  raise ValueError(str(a)+" has no inverse mod "+str(p))

def minor(A,i,j):    # Return matrix A with the ith row and jth column deleted
  A=np.array(A)
  minor=np.zeros(shape=(len(A)-1,len(A)-1))
  p=0
  for s in range(0,len(minor)):
    if p==i:
      p=p+1
    q=0
    for t in range(0,len(minor)):
      if q==j:
        q=q+1
      minor[s][t]=A[p][q]
      q=q+1
    p=p+1
  return minor


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
    tmp_comp_matrix = c
    real_comp_matrix = c
    count = 256
    arr_merge = True
    for i in trange(71*319+6+1):   # 總共跑71 * (256 + 64) = 22720
        _comp_matrix = special_dot(comp_matrix, _comp_matrix)   # 因為是在mod 2底下處理，所以不是普通的dot運算，乘法對應到AND，加法對應到XOR
        if i == 71 * count + 6:
            real_comp_matrix = np.vstack([real_comp_matrix, _comp_matrix[-1]])
            count += 1
        tmp_comp_matrix = np.vstack([tmp_comp_matrix, _comp_matrix[-1]])

    np.save('./test_numpy', tmp_comp_matrix)

    inv_real_comp_matrix = modMatInv(real_comp_matrix[1:], 2)
    assert special_dot(np.array(inv_real_comp_matrix, dtype=int), np.array(real_comp_matrix, dtype=int)) == np.eye(init_state_size, dtype = 'int')
    init_state = special_dot(inv_real_comp_matrix, cipher_text)
    output, check = verification(taps, init_state)
    assert check == cipher_text.reshape(1, len(cipher_text)).tolist()[0]
    get_flag(cipher_text_xor_flag, output)