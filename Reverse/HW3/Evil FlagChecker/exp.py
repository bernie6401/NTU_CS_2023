from string import *
from tqdm import trange


def ror(n, rotations, width):
    if rotations.bit_length() < 32:
        rotations = '0' * (32 - rotations.bit_length()) + bin(rotations)[2:]
        tmp = rotations[-width:] + rotations[:-width]
        return int(tmp, 2)
    tmp = int(bin(rotations << (n-width))[-n:-n+width] + bin(rotations >> width)[2:], 2)
    return tmp


candidates = printable
targets = [0xED, 0x03, 0x81, 0x69, 0x7B, 0x84, 0xA6, 0xA0, 0x5B, 0x2B, 0xB6, 0xE6, 0x5C, 0x57, 0xC9, 0x99, 0xE8, 0xB2, 0x20, 0x72, 0x38, 0xF1, 0x58]
len = len(targets)
iv = 0xE0C92EAB
flag = ''
for byte in trange(len):
    iv_xor = int(hex(iv)[2:][-2:], 16)
    for candidate in candidates:
        cipher = iv_xor ^ ord(candidate)
        if cipher == targets[byte]:
            flag += candidate
            iv = ror(32, iv, 3)
            iv = len + (cipher ^ iv) - byte
            break
    # print(flag)

print(flag)
# from z3 import *

# target = [0xED, 0x03, 0x81, 0x69, 0x7B, 0x84, 0xA6, 0xA0, 0x5B, 0x2B, 0xB6, 0xE6, 0x5C, 0x57, 0xC9, 0x99, 0xE8, 0xB2, 0x20, 0x72, 0x38, 0xF1, 0x58]
# len = len(target)
# iv = 0xE0C92EAB
# # 起手式 - 開一個Solver
# s = Solver()

# # 建立符號 - 以此HW來說就是建立23個符號對應每一個flag字元
# bvs = [BitVec(f'bt_{i}', 8) for i in range(len)]

# # 加上constraint - 以此lab來說每一個flag字元都應該限制在空白到0x7f之間
# for bv in bvs:
#     s.add(And(bv >= 0x20, bv <= 0x7f))

# for i in range(len):
#     iv = f'int(hex(iv)[2:][-2:], 16)'
#     bvs_formula = f'(({eval(iv)}) ^ bvs[{i}])'
#     s.add(eval(bvs_formula) == target[i])
#     RotateRight = f'int(bin({iv_formula} << (32-3))[-32:-29] + bin({iv_formula} >> 3)[2:], 2)'
#     iv_formula = f'{int(hex(iv)[2:][-2:], 16)}'
#     iv_formula = f'{len} + ({iv_formula} ^ {iv}) - {i}'
#     print(f'iv_formula = {iv_formula}')

# # 如果有解的話就會做以下操作
# if s.check() == sat:
#     print('Find ~~~')
#     print(s.model())

#     flag = ""
#     for bv in bvs:
#         flag += chr(s.model()[bv].as_long())

#     print(flag)

# import angr
# import claripy

# # 建立一個project
# root = 'Reverse/HW3/Evil FlagChecker/'
# proj = angr.Project(root + 'test.exe')

# # 建立Claripy Symbol
# sym_arg = claripy.BVS('sym_arg', 8 * 23) # 就像z3一樣要建立symbol

# # 建立初始的state
# state = proj.factory.entry_state(stdin=sym_arg)
# simgr = proj.factory.simulation_manager(state)

# # 有了proj/symbol/initial state之後就要開始讓他跑起來
# # simgr.explore(find = lambda s: b'Good!' in s.posix.dumps(1))
# simgr.explore(find = lambda s: b"Good!" in s.posix.dumps(1), avoid=lambda s: b"No no no..." in s.posix.dumps(1))

# if len(simgr.found) > 0:
#     print(simgr.found[0].solver.eval(sym_arg, cast_to=bytes))
# else:
#     print("NONONONO")