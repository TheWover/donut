/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// locate address of API in export table using Maru hash function 
LPVOID FindExport(PDONUT_INSTANCE inst, LPVOID base, ULONG64 api_hash, ULONG64 iv){
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    DWORD                   i, j, cnt, rva;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    PCHAR                   api, dll, p;
    LPVOID                  addr=NULL;
    ULONG64                 dll_hash;
    CHAR                    buf[MAX_PATH], dll_name[64], api_name[128];
    
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    // if no export table, return NULL
    if (rva==0) return NULL;
    
    exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
    cnt = exp->NumberOfNames;
    
    // if no api names, return NULL
    if (cnt==0) return NULL;
    
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
    dll = RVA2VA(PCHAR, base, exp->Name);
    
    // get hash of DLL string converted to lowercase
    for(i=0;dll[i]!=0;i++) {
      buf[i] = dll[i] | 0x20;
    }
    buf[i] = 0;
    dll_hash = maru(buf, iv);

    do {
      // calculate hash of api string
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // xor with DLL hash and compare with hash to find
      if ((maru(api, iv) ^ dll_hash) == api_hash) {
        // return address of function
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
        
        // is this a forward reference?
        if ((PBYTE)addr >= (PBYTE)exp &&
            (PBYTE)addr <  (PBYTE)exp + 
            dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
        {
          DPRINT("%016llx is forwarded to %s", 
            api_hash, (char*)addr);
            
          // copy DLL name to buffer
          p=(char*)addr;
          
          for(i=0; p[i] != 0 && i < sizeof(dll_name)-4; i++) {
            dll_name[i] = p[i];
            if(p[i] == '.') break;
          }

          dll_name[i+1] = 'd';
          dll_name[i+2] = 'l';
          dll_name[i+3] = 'l';
          dll_name[i+4] = 0;
          
          p += i + 1;
          
          // copy API name to buffer
          for(i=0; p[i] != 0 && i < sizeof(api_name)-1;i++) {
            api_name[i] = p[i];
          }
          api_name[i] = 0;
          
          DPRINT("Trying to load %s", dll_name);
          HMODULE hModule = inst->api.LoadLibrary(dll_name);
          
          if(hModule != NULL) {
            DPRINT("Calling GetProcAddress(%s)", api_name);
            addr = inst->api.GetProcAddress(hModule, api_name);
          } else addr = NULL;
        }
        return addr;
      }
    } while (--cnt && addr == NULL);
    
    return addr;
}

// search all modules in the PEB for API
LPVOID xGetProcAddress(PDONUT_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV) {
    PPEB                  peb;
    PPEB_LDR_DATA         ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    LPVOID                addr = NULL;
     
    #if defined(_WIN64)
      peb = (PPEB) __readgsqword(0x60);
    #else
      peb = (PPEB) __readfsdword(0x30);
    #endif

    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && addr == NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      // search the export table for api
      addr = FindExport(inst, dte->DllBase, ulHash, ulIV);  
    }
    return addr;
}
