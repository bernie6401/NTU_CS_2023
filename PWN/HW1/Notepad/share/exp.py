from pwn import *
from subprocess import *

cmd_dic = {1:'Login', 2:'Register', 3:'New Note', 4:'Edit Note', 5:'Show Note'}
def dealing_cmd(r, cmd, note_name=b'test', content_len=b'5', content=b'test\n', offset=b'0'):
    r.recvlines(7)
    if cmd == 1 or cmd == 2:
        r.sendline(str(cmd).encode())
        r.sendlineafter(b'Username: ', b'sbk')
        r.sendlineafter(b'Password: ', b'sbk')
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
        r.sendlineafter(b'Offset: ', b'\n')
        # log.info(f'Command {cmd_dic[cmd]} Successful')
        log.critical(f'Content: {r.recvline()}')
'''#########
Dealing Connection and PoW
#########'''
r = remote('10.113.184.121', 10044)
r.recvuntil(b'sha256(')
prefix = r.recvuntil(b' + ').strip().decode().split(' ')[0]
difficulty = r.recvline().strip().decode().split('(')[-1].split(')')[0]

log.info(f"PoW's prefix = {prefix}, difficulty = {difficulty}")

p = Popen(f"python ../pow_solver.py {prefix} {difficulty}", stdin=PIPE, stdout=PIPE, universal_newlines=True, shell=True)
pow_result = p.stdout.readline().strip()
log.info(f'PoW Result = {pow_result}')
r.sendline(pow_result.encode())
r.recvuntil(b'Your service is running on port ')
init_port = r.recvuntil(b'.').decode().split('.')[0]
log.info(f'Receive Port = {init_port}')
r.close()

'''#########
Dealing Exploit
#########'''
r = remote('10.113.184.121', init_port)
dealing_cmd(r, 2)
dealing_cmd(r, 1)
# dealing_cmd(r, 3)
# dealing_cmd(r, 5)
r.interactive()