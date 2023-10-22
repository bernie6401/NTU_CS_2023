; Modify register value
add rax, 0x87
sub rbx, 0x63
mov r8, rcx
mov rcx, rdx
mov rdx, r8



; MEM[RSP+0x0:RSP+0x4] += 0xdeadbeef
mov r8d, dword [rsp]
add r8d, 0xdeadbeef
mov dword [rsp], r8d

; MEM[RSP+0x4:RSP+0x8] -= 0xfaceb00c
mov r8d, dword [rsp+4]
sub r8d, 0xfaceb00c
mov dword [rsp+4], r8d

; MEM[RSP+0x8:RSP+0xc], MEM[RSP+0xc:RSP+0x10] = MEM[RSP+0xc:RSP+0x10], MEM[RSP+0x8:RSP+0xc]
mov r8d, dword [rsp+8]
mov r9d, dword [rsp+0xc]
mov dword [rsp+8], r9d
mov dword [rsp+0xc], r8d