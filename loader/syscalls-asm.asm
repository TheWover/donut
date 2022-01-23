.code

EXTERN SW2_GetSyscallNumber: PROC

NtCreateSection PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 032956E27h
    mov rdx, qword ptr [rsp + 060h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtCreateSection ENDP

NtMapViewOfSection PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 0035E220Dh
    mov rdx, qword ptr [rsp + 078h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtMapViewOfSection ENDP

NtUnmapViewOfSection PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 09ACEB842h
    mov rdx, r8
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtUnmapViewOfSection ENDP

NtContinue PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 0F2989153h
    mov rdx, r8
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtContinue ENDP

NtClose PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 0349DD6D1h
    mov rdx, rdx
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtClose ENDP

NtWaitForSingleObject PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 0E3BDE123h
    mov rdx, r9
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtWaitForSingleObject ENDP

NtProtectVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 00B911517h
    mov rdx, qword ptr [rsp + 050h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtProtectVirtualMemory ENDP

NtGetContextThread PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 01CB74215h
    mov rdx, r8
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtGetContextThread ENDP

NtAllocateVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 031A5474Bh
    mov rdx, qword ptr [rsp + 058h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtAllocateVirtualMemory ENDP

NtFreeVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 087907FEFh
    mov rdx, qword ptr [rsp + 048h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtFreeVirtualMemory ENDP

NtCreateFile PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 0249DFE2Ah
    mov rdx, qword ptr [rsp + 080h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtCreateFile ENDP

NtQueryVirtualMemory PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 055CF2B39h
    mov rdx, qword ptr [rsp + 058h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtQueryVirtualMemory ENDP

NtCreateThreadEx PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 034297693h
    mov rdx, qword ptr [rsp + 080h]
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtCreateThreadEx ENDP

NtFlushInstructionCache PROC
    push rcx
    push rdx
    push r8
    push r9
    mov ecx, 0FFACC9F7h
    mov rdx, r9
    sub rsp, 028h
    call SW2_GetSyscallNumber
    add rsp, 028h
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10, rcx
    syscall
    ret
NtFlushInstructionCache ENDP

end
