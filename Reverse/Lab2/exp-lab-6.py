kernel32_dll = open('./kernel32.dll.txt', 'rb').readlines()
msvcrt_dll = open('./msvcrt.dll.txt', 'rb').readlines()
user32_dll = open('./user32.dll.txt', 'rb').readlines()
kernel32_function_hash = [0x5F00766C, 0x6D555364, 0x42B4FA0, 0xC473C85A]
msvcrt_function_hash = 0xCD841E17
user32_function_hash = 0x416f607


def __ROL4__(v, b, bit_size):
    return (v << b) | (v >> (bit_size - b)) & (2**(bit_size) - 1)

# kernel32 Function Hash Compare
for function_hash in kernel32_function_hash:
    for i in range(len(kernel32_dll)):
        name = kernel32_dll[i].strip()
        hash = 0
        for j in range(len(name)):
            hash += __ROL4__(hash, 11, 32) + 1187 + name[j]
            hash = hash & (2**(32) - 1)
        if hash == function_hash:
            print("[+] kernel32 Function    - " + hex(function_hash) + " is " + name.decode())
            break

# msvcrt Function Hash Compare
for i in range(len(msvcrt_dll)):
    name = msvcrt_dll[i].strip()
    hash = 0
    for j in range(len(name)):
        hash += __ROL4__(hash, 11, 32) + 1187 + name[j]
        hash = hash & (2**(32) - 1)
    if hash == msvcrt_function_hash:
        print("[+] msvcrt Function      - " + hex(msvcrt_function_hash) + " is " + name.decode())
        break

# user32 Function Hash Compare
for i in range(len(user32_dll)):
    name = user32_dll[i].strip()
    hash = 0
    for j in range(len(name)):
        hash += __ROL4__(hash, 11, 32) + 1187 + name[j]
        hash = hash & (2**(32) - 1)
    if hash == user32_function_hash:
        print("[+] user32 Function      - " + hex(user32_function_hash) + " is " + name.decode())
        break
print("Flag = FLAG{" + name.decode() + "}")