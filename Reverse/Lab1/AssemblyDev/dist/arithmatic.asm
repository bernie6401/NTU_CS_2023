mov r8d, dword [rsp] ; 
mov r9d, dword [rsp + 4] ; 
mov r10d, dword [rsp + 8] ;

; EAX = a + b
mov eax, r8d
add eax, r9d

; EBX = a - b
mov ecx, r8d
sub ecx, r9d
mov ebx, ecx

; ECX = -c
mov ecx, r10d
neg ecx

; EDX = 9 * a + 7
mov edx, DWORD [rsp]
sal edx, 3
add edx, DWORD [rsp]
add edx, 7
