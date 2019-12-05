
// Target architecture : X86 64

#define DECODE_SIZE 353

char DECODE[] = {
  /* 0000 */ "\x56"                 /* push   rsi                               */
  /* 0001 */ "\x53"                 /* push   rbx                               */
  /* 0002 */ "\x57"                 /* push   rdi                               */
  /* 0003 */ "\x55"                 /* push   rbp                               */
  /* 0004 */ "\xeb\x0a"             /* jmp    0x10                              */
  /* 0006 */ "\x5d"                 /* pop    rbp                               */
  /* 0007 */ "\x31\xc0"             /* xor    eax, eax                          */
  /* 0009 */ "\xb0\x9b"             /* mov    al, 0x9b                          */
  /* 000B */ "\x48\x01\xe8"         /* add    rax, rbp                          */
  /* 000E */ "\xff\xe0"             /* jmp    rax                               */
  /* 0010 */ "\xe8\xf1\xff\xff\xff" /* call   6                                 */
  /* 0015 */ "\x56"                 /* push   rsi                               */
  /* 0016 */ "\x53"                 /* push   rbx                               */
  /* 0017 */ "\x57"                 /* push   rdi                               */
  /* 0018 */ "\x55"                 /* push   rbp                               */
  /* 0019 */ "\x41\x89\xc0"         /* mov    r8d, eax                          */
  /* 001C */ "\xeb\x72"             /* jmp    0x90                              */
  /* 001E */ "\x41\x59"             /* pop    r9                                */
  /* 0020 */ "\x6a\x60"             /* push   0x60                              */
  /* 0022 */ "\x41\x5b"             /* pop    r11                               */
  /* 0024 */ "\x65\x49\x8b\x03"     /* mov    rax, qword ptr gs:[r11]           */
  /* 0028 */ "\x48\x8b\x40\x18"     /* mov    rax, qword ptr [rax + 0x18]       */
  /* 002C */ "\x48\x8b\x78\x10"     /* mov    rdi, qword ptr [rax + 0x10]       */
  /* 0030 */ "\xeb\x03"             /* jmp    0x35                              */
  /* 0032 */ "\x48\x8b\x3f"         /* mov    rdi, qword ptr [rdi]              */
  /* 0035 */ "\x48\x8b\x5f\x30"     /* mov    rbx, qword ptr [rdi + 0x30]       */
  /* 0039 */ "\x48\x85\xdb"         /* test   rbx, rbx                          */
  /* 003C */ "\x74\x4b"             /* je     0x89                              */
  /* 003E */ "\x8b\x73\x3c"         /* mov    esi, dword ptr [rbx + 0x3c]       */
  /* 0041 */ "\x44\x01\xde"         /* add    esi, r11d                         */
  /* 0044 */ "\x8b\x4c\x33\x28"     /* mov    ecx, dword ptr [rbx + rsi + 0x28] */
  /* 0048 */ "\x67\xe3\xe7"         /* jecxz  0x32                              */
  /* 004B */ "\x48\x8d\x74\x0b\x0c" /* lea    rsi, qword ptr [rbx + rcx + 0xc]  */
  /* 0050 */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 0051 */ "\x41\xff\xd1"         /* call   r9                                */
  /* 0054 */ "\x50"                 /* push   rax                               */
  /* 0055 */ "\x41\x5a"             /* pop    r10                               */
  /* 0057 */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 0058 */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 0059 */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 005A */ "\x91"                 /* xchg   eax, ecx                          */
  /* 005B */ "\x67\xe3\xd4"         /* jecxz  0x32                              */
  /* 005E */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 005F */ "\x92"                 /* xchg   eax, edx                          */
  /* 0060 */ "\x48\x01\xda"         /* add    rdx, rbx                          */
  /* 0063 */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 0064 */ "\x95"                 /* xchg   eax, ebp                          */
  /* 0065 */ "\x48\x01\xdd"         /* add    rbp, rbx                          */
  /* 0068 */ "\xad"                 /* lodsd  eax, dword ptr [rsi]              */
  /* 0069 */ "\x96"                 /* xchg   eax, esi                          */
  /* 006A */ "\x48\x01\xde"         /* add    rsi, rbx                          */
  /* 006D */ "\x48\x8b\x44\x8d\xfc" /* mov    rax, qword ptr [rbp + rcx*4 - 4]  */
  /* 0072 */ "\x41\xff\xd1"         /* call   r9                                */
  /* 0075 */ "\x44\x01\xd0"         /* add    eax, r10d                         */
  /* 0078 */ "\x44\x39\xc0"         /* cmp    eax, r8d                          */
  /* 007B */ "\xe0\xf0"             /* loopne 0x6d                              */
  /* 007D */ "\x75\xb3"             /* jne    0x32                              */
  /* 007F */ "\x0f\xb7\x04\x4e"     /* movzx  eax, word ptr [rsi + rcx*2]       */
  /* 0083 */ "\x8b\x04\x82"         /* mov    eax, dword ptr [rdx + rax*4]      */
  /* 0086 */ "\x48\x01\xc3"         /* add    rbx, rax                          */
  /* 0089 */ "\x48\x93"             /* xchg   rax, rbx                          */
  /* 008B */ "\x5d"                 /* pop    rbp                               */
  /* 008C */ "\x5f"                 /* pop    rdi                               */
  /* 008D */ "\x5b"                 /* pop    rbx                               */
  /* 008E */ "\x5e"                 /* pop    rsi                               */
  /* 008F */ "\xc3"                 /* ret                                      */
  /* 0090 */ "\xe8\x89\xff\xff\xff" /* call   0x1e                              */
  /* 0095 */ "\x52"                 /* push   rdx                               */
  /* 0096 */ "\x56"                 /* push   rsi                               */
  /* 0097 */ "\x96"                 /* xchg   eax, esi                          */
  /* 0098 */ "\x48\x01\xde"         /* add    rsi, rbx                          */
  /* 009B */ "\x31\xc0"             /* xor    eax, eax                          */
  /* 009D */ "\x99"                 /* cdq                                      */
  /* 009E */ "\xac"                 /* lodsb  al, byte ptr [rsi]                */
  /* 009F */ "\x08\xc0"             /* or     al, al                            */
  /* 00A1 */ "\x74\x09"             /* je     0xac                              */
  /* 00A3 */ "\x0c\x20"             /* or     al, 0x20                          */
  /* 00A5 */ "\x01\xc2"             /* add    edx, eax                          */
  /* 00A7 */ "\xc1\xca\x08"         /* ror    edx, 8                            */
  /* 00AA */ "\xeb\xf2"             /* jmp    0x9e                              */
  /* 00AC */ "\x92"                 /* xchg   eax, edx                          */
  /* 00AD */ "\x5e"                 /* pop    rsi                               */
  /* 00AE */ "\x5a"                 /* pop    rdx                               */
  /* 00AF */ "\xc3"                 /* ret                                      */
  /* 00B0 */ "\x48\x99"             /* cqo                                      */
  /* 00B2 */ "\xb2\xb1"             /* mov    dl, 0xb1                          */
  /* 00B4 */ "\x48\x01\xd0"         /* add    rax, rdx                          */
  /* 00B7 */ "\x48\x83\xec\x78"     /* sub    rsp, 0x78                         */
  /* 00BB */ "\x54"                 /* push   rsp                               */
  /* 00BC */ "\x5b"                 /* pop    rbx                               */
  /* 00BD */ "\x48\x8d\x7b\x48"     /* lea    rdi, qword ptr [rbx + 0x48]       */
  /* 00C1 */ "\x48\xab"             /* stosq  qword ptr [rdi], rax              */
  /* 00C3 */ "\xb8\x39\x81\x4f\x45" /* mov    eax, 0x454f8139                   */
  /* 00C8 */ "\xff\xd5"             /* call   rbp                               */
  /* 00CA */ "\x48\xab"             /* stosq  qword ptr [rdi], rax              */
  /* 00CC */ "\xb8\xd7\x0e\xf5\xe0" /* mov    eax, 0xe0f50ed7                   */
  /* 00D1 */ "\xff\xd5"             /* call   rbp                               */
  /* 00D3 */ "\x48\xab"             /* stosq  qword ptr [rdi], rax              */
  /* 00D5 */ "\xb8\x57\x6d\x60\x46" /* mov    eax, 0x46606d57                   */
  /* 00DA */ "\xff\xd5"             /* call   rbp                               */
  /* 00DC */ "\x48\xab"             /* stosq  qword ptr [rdi], rax              */
  /* 00DE */ "\xb8\xb1\x64\x4a\x3f" /* mov    eax, 0x3f4a64b1                   */
  /* 00E3 */ "\xff\xd5"             /* call   rbp                               */
  /* 00E5 */ "\x48\xab"             /* stosq  qword ptr [rdi], rax              */
  /* 00E7 */ "\x31\xc0"             /* xor    eax, eax                          */
  /* 00E9 */ "\x48\x8b\x4b\x48"     /* mov    rcx, qword ptr [rbx + 0x48]       */
  /* 00ED */ "\xff\x53\x58"         /* call   qword ptr [rbx + 0x58]            */
  /* 00F0 */ "\x89\x43\x44"         /* mov    dword ptr [rbx + 0x44], eax       */
  /* 00F3 */ "\x31\xd2"             /* xor    edx, edx                          */
  /* 00F5 */ "\x48\x89\x53\x30"     /* mov    qword ptr [rbx + 0x30], rdx       */
  /* 00F9 */ "\x48\x89\x53\x28"     /* mov    qword ptr [rbx + 0x28], rdx       */
  /* 00FD */ "\x48\x89\x53\x38"     /* mov    qword ptr [rbx + 0x38], rdx       */
  /* 0101 */ "\x48\x8d\x4b\x38"     /* lea    rcx, qword ptr [rbx + 0x38]       */
  /* 0105 */ "\x48\x89\x4b\x20"     /* mov    qword ptr [rbx + 0x20], rcx       */
  /* 0109 */ "\x4d\x31\xc9"         /* xor    r9, r9                            */
  /* 010C */ "\x6a\x07"             /* push   7                                 */
  /* 010E */ "\x41\x58"             /* pop    r8                                */
  /* 0110 */ "\x92"                 /* xchg   eax, edx                          */
  /* 0111 */ "\x48\x8b\x4b\x48"     /* mov    rcx, qword ptr [rbx + 0x48]       */
  /* 0115 */ "\xff\x53\x68"         /* call   qword ptr [rbx + 0x68]            */
  /* 0118 */ "\x6a\x40"             /* push   0x40                              */
  /* 011A */ "\x41\x59"             /* pop    r9                                */
  /* 011C */ "\x6a\x30"             /* push   0x30                              */
  /* 011E */ "\x41\x58"             /* pop    r8                                */
  /* 0120 */ "\x49\xc1\xe0\x08"     /* shl    r8, 8                             */
  /* 0124 */ "\x8b\x53\x38"         /* mov    edx, dword ptr [rbx + 0x38]       */
  /* 0127 */ "\x31\xc9"             /* xor    ecx, ecx                          */
  /* 0129 */ "\xff\x53\x60"         /* call   qword ptr [rbx + 0x60]            */
  /* 012C */ "\x48\x89\x43\x3c"     /* mov    qword ptr [rbx + 0x3c], rax       */
  /* 0130 */ "\x31\xd2"             /* xor    edx, edx                          */
  /* 0132 */ "\x48\x89\x53\x30"     /* mov    qword ptr [rbx + 0x30], rdx       */
  /* 0136 */ "\x48\x89\x53\x28"     /* mov    qword ptr [rbx + 0x28], rdx       */
  /* 013A */ "\x48\x8d\x4b\x38"     /* lea    rcx, qword ptr [rbx + 0x38]       */
  /* 013E */ "\x48\x89\x4b\x20"     /* mov    qword ptr [rbx + 0x20], rcx       */
  /* 0142 */ "\x50"                 /* push   rax                               */
  /* 0143 */ "\x41\x59"             /* pop    r9                                */
  /* 0145 */ "\x6a\x07"             /* push   7                                 */
  /* 0147 */ "\x41\x58"             /* pop    r8                                */
  /* 0149 */ "\x8b\x53\x44"         /* mov    edx, dword ptr [rbx + 0x44]       */
  /* 014C */ "\x48\x8b\x4b\x48"     /* mov    rcx, qword ptr [rbx + 0x48]       */
  /* 0150 */ "\xff\x53\x68"         /* call   qword ptr [rbx + 0x68]            */
  /* 0153 */ "\x48\x8b\x43\x3c"     /* mov    rax, qword ptr [rbx + 0x3c]       */
  /* 0157 */ "\x48\x83\xc4\x78"     /* add    rsp, 0x78                         */
  /* 015B */ "\x5d"                 /* pop    rbp                               */
  /* 015C */ "\x5f"                 /* pop    rdi                               */
  /* 015D */ "\x5b"                 /* pop    rbx                               */
  /* 015E */ "\x5e"                 /* pop    rsi                               */
  /* 015F */ "\xff\xe0"             /* jmp    rax                               */
};
