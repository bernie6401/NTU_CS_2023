root = "./"
dll = ['kernel32.dll.txt', 'msvcrt.dll.txt', 'user32.dll.txt']
kernel32_function_hash = [0x5F00766C, 0x6D555364, 0x42B4FA0, 0xC473C85A]
msvcrt_function_hash = [0xCD841E17]
user32_function_hash = [0x416f607]

dll_dict = [open(root + i, 'rb').readlines() for i in dll]
dll_func_hash_dict = [kernel32_function_hash, msvcrt_function_hash, user32_function_hash]


def __ROL4__(v, b, bit_size):
    return (v << b) | (v >> (bit_size - b)) & (2**(bit_size) - 1)

for i in range(len(dll_dict)):
    for j in range(len(dll_dict[i])):
        name = dll_dict[i][j].strip()
        hash = 0
        for k in range(len(name)):
            hash += __ROL4__(hash, 11, 32) + 1187 + name[k]
            hash = hash & (2**(32) - 1)
        if hash in dll_func_hash_dict[i]:
            print("[+] " + dll[i] + " Function    - " + hex(hash) + " is " + name.decode())