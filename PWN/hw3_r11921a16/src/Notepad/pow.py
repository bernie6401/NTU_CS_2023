from pwn import *
from subprocess import *


'''#########
Dealing Connection and PoW
#########'''
r = remote('10.113.184.121', 10044)
r.recvuntil(b'sha256(')
prefix = r.recvuntil(b' + ').strip().decode().split(' ')[0]
difficulty = r.recvline().strip().decode().split('(')[-1].split(')')[0]

log.info(f"PoW's prefix = {prefix}, difficulty = {difficulty}")

p = Popen(f"python ./pow_solver.py {prefix} {difficulty}", stdin=PIPE, stdout=PIPE, universal_newlines=True, shell=True)
pow_result = p.stdout.readline().strip()
log.info(f'PoW Result = {pow_result}')
r.sendline(pow_result.encode())
r.recvuntil(b'Your service is running on port ')
init_port = r.recvuntil(b'.').decode().split('.')[0]
log.success(f'Receive Port = {init_port}')
r.close()