; if a >= b:
;     EAX = a
; else:
;     EAX = b
    mov     eax, DWORD [rsp]
    cmp     eax, DWORD [rsp+4]
    jl      L2
    mov     eax, DWORD [rsp]
    jmp     L3
L2:
    mov     eax, DWORD [rsp+4]


; if c < d:
;     EBX = c
; else:
;     EBX = d
L3:
	mov     edi, DWORD [esp+0x8]
	mov 	esi, DWORD [esp+0xc]
    cmp     edi, esi
    jae     L4
    mov     ebx, DWORD [esp+0x8]
    jmp     L5
L4:
    mov     ebx, DWORD [esp+0xc]


; if c is an odd number:
;     ECX = c // 8
; else:
;     ECX = c * 4
L5:
	mov     edi, DWORD [esp+0x8]
	and     edi, 1
	cmp     edi, 1
	jne     L6
	mov     ecx, dword [esp+0x8]
	sar     ecx, 3
	jmp     L7
L6:
	mov     ecx, dword [esp+0x8]
	sal     ecx, 2
	
L7: