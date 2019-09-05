;
;  Copyright © 2019 TheWover, Odzhan. All Rights Reserved.
;
;  Redistribution and use in source and binary forms, with or without
;  modification, are permitted provided that the following conditions are
;  met:
;
;  1. Redistributions of source code must retain the above copyright
;  notice, this list of conditions and the following disclaimer.
;
;  2. Redistributions in binary form must reproduce the above copyright
;  notice, this list of conditions and the following disclaimer in the
;  documentation and/or other materials provided with the distribution.
;
;  3. The name of the author may not be used to endorse or promote products
;  derived from this software without specific prior written permission.
;
;  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
;  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
;  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
;  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
;  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
;  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
;  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
;  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
;  POSSIBILITY OF SUCH DAMAGE.
;
;
; void call_api(FARPROC api, int param_cnt, WCHAR param[]);

%define DONUT_MAX_PARAM 8
%define DONUT_MAX_NAME  256

struc HOME_SPACE
    ._rcx  resq 1
    ._rdx  resq 1
    ._r8   resq 1
    ._r9   resq 1
endstruc

struc _ds
    .hs:   resq HOME_SPACE_size

    .arg4  resq 1
    .arg5  resq 1
    .arg6  resq 1
    .arg7  resq 1

    ._rdi  resq 1
    ._rsi  resq 1
    ._rbp  resq 1
    ._rbx  resq 1
    ._rsp  resq 1
endstruc

  %ifndef BIN
    global call_api
    global _call_api
  %endif
  
call_api:
_call_api:
    bits   32
    
    ; int3
    
    xor    eax, eax                  ; 
    dec    eax                       ; 
    jns    L2                        ; if SF=0, goto x64
    
    mov    eax, [esp+ 4]             ; eax = api address
    mov    ecx, [esp+ 8]             ; ecx = param_cnt
    mov    edx, [esp+12]             ; edx = params
L1:
    push   edx                       ; save params[i] on stack
    add    edx, DONUT_MAX_NAME * 2   ; advance to next element
    sub    ecx, 1                    ; subtract one from param_cnt
    jnz    L1
    call   eax                       ; call api
    ret

L2:
    bits   64
    
    sub    rsp, ((_ds_size & -16) + 16) - 8
    
    mov    [rsp+_ds._rbp], rbp
    mov    [rsp+_ds._rbx], rbx
    mov    [rsp+_ds._rdi], rdi
    mov    [rsp+_ds._rsi], rsi
    
    mov    rsi, rsp              ; rsi = rsp after allocation
    mov    rdi, rcx              ; rdi = api to call
    mov    eax, DONUT_MAX_NAME * 2
    
    mov    rcx, r8               ; rcx = param[0]
    lea    rdx, [rcx+rax]        ; rdx = param[1]
    lea    r8,  [rdx+rax]        ; r8  = param[2]
    lea    r9,  [r8+rax]         ; r9  = param[3]
    
    lea    rbx, [r9+rax]
    mov    [rsp+_ds.arg4], rbx   ; param[4]
    add    rbx, rax
    mov    [rsp+_ds.arg5], rbx   ; param[5]
    add    rbx, rax
    mov    [rsp+_ds.arg6], rbx   ; param[6]
    add    rbx, rax
    mov    [rsp+_ds.arg7], rbx   ; param[7]
    call   rdi
    
    mov    rsp, rsi              ; restore rsp after allocation
    mov    rsi, [rsp+_ds._rsi]
    mov    rdi, [rsp+_ds._rdi]
    mov    rbx, [rsp+_ds._rbx]
    mov    rbp, [rsp+_ds._rbp]
    
    add    rsp, ((_ds_size & -16) + 16) - 8
    ret
    