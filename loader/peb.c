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

// find a DLL with a certain export, used by xGetProcAddress and FindExport
LPVOID FindReference(PDONUT_INSTANCE inst, LPVOID original_dll, PCHAR dll_name, PCHAR api_name) {
  PPEB                    peb;
  PPEB_LDR_DATA           ldr;
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PLDR_DATA_TABLE_ENTRY   dte;
  PIMAGE_DATA_DIRECTORY   dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  LPVOID                  addr = NULL, base;
  DWORD                   rva, cnt;
  PDWORD                  adr;
  PDWORD                  sym;
  PWORD                   ord;
  PCHAR                   api;

  peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
  ldr = (PPEB_LDR_DATA)peb->Ldr;
  
  // for each DLL loaded
  for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
       dte->DllBase != NULL && addr == NULL;
       dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
  {
    base = dte->DllBase;
    // if this is the dll with the reference, continue
    if (base == original_dll) continue;

    addr = xGetProcAddress(inst, base, api_name, 0);
  }
  if (addr == NULL) {
    // we did not find the reference, use GetProcAddress
    HMODULE hModule = xGetLibAddress(inst, dll_name);
    
    if(hModule != NULL) {
      DPRINT("Calling GetProcAddress(%s)", api_name);
      addr = inst->api.GetProcAddress(hModule, api_name);
    } else addr = NULL;
  }
  
  return addr;
}

// search for an export in a DLL
LPVOID xGetProcAddress(PDONUT_INSTANCE inst, LPVOID base, PCHAR api_name, DWORD ordinal) {
  PIMAGE_DOS_HEADER       dos;
  PIMAGE_NT_HEADERS       nt;
  PIMAGE_DATA_DIRECTORY   dir;
  PIMAGE_EXPORT_DIRECTORY exp;
  LPVOID                  addr = NULL;
  DWORD                   rva, cnt;
  PDWORD                  adr;
  PDWORD                  sym;
  PWORD                   ord;
  PCHAR                   api;
  CHAR                    dll_name[64];
  CHAR                    new_api[64];
  DWORD                   i;
  PCHAR                   p;

  if (base == NULL) return NULL;

  dos = (PIMAGE_DOS_HEADER)base;
  nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
  dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
  rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  
  // if no export table, return NULL
  if (rva==0) return NULL;
  
  exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
  adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
  sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
  ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);

  if (api_name != NULL) {
    // exported by name
    cnt = exp->NumberOfNames;
    // if no api names, return NULL
    if (cnt==0) return NULL;
  
    do {
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // check if the export name matches the API we are looking for
      if (!_strcmp(api, api_name)) {
        // get the address of the API
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
      }
    } while (--cnt && addr == NULL);
  } else {
    // exported by ordinal
    addr = RVA2VA(PVOID, base, adr[ordinal  - exp->Base]);
  }

  // is this a forward reference?
  if ((PBYTE)addr >= (PBYTE)exp &&
      (PBYTE)addr <  (PBYTE)exp + 
      dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
  {
    //DPRINT("%s is forwarded to %s", api_name, (char*)addr);
      
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
    for(i=0; p[i] != 0 && i < sizeof(new_api)-1;i++) {
      new_api[i] = p[i];
    }
    new_api[i] = 0;

    addr = FindReference(inst, base, dll_name, new_api);
  }
  return addr;
}

// find a DLL by name, load it if not found
LPVOID xGetLibAddress(PDONUT_INSTANCE inst, PCHAR search) {
    PPEB                    peb;
    PPEB_LDR_DATA           ldr;
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PLDR_DATA_TABLE_ENTRY   dte;
    PIMAGE_EXPORT_DIRECTORY exp;
    LPVOID                  addr = NULL, base;
    DWORD                   rva;
    PCHAR                   name;
    CHAR                    dll_name[64];
    DWORD                   i;
    int                     correct = -1;

    for(i=0; search[i] != 0 && i < 64; i++) {
      dll_name[i] = search[i];
    }
    dll_name[i] = 0;
    // make sure the name ends with '.dll'
    if (dll_name[i-4] != '.') {
      dll_name[i++] = '.';
      dll_name[i++] = 'd';
      dll_name[i++] = 'l';
      dll_name[i++] = 'l';
      dll_name[i++] = 0;
    }

    DPRINT("Searching for DLL in PEB: %s", dll_name);

    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         correct != 0 && dte->DllBase != NULL && addr == NULL;
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      base = dte->DllBase;
      dos  = (PIMAGE_DOS_HEADER)base;
      nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
      rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      if (rva == 0) continue;

      exp  = RVA2VA(PIMAGE_EXPORT_DIRECTORY, base, rva);
      name = RVA2VA(PCHAR, base, exp->Name);

      correct = stricmp(dll_name, name);

      if (correct == 0) {
        addr = base;
      }
    }

    DPRINT("Address of DLL: %p", addr);

    // if the DLL was not found, load it
    if (addr == NULL) {
      addr = inst->api.LoadLibraryA(dll_name);
      DPRINT("Dll not found. Loaded %s via LoadLibrary at 0x%p", dll_name, addr);
    }
    return addr;
}

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
          //DPRINT("%016llx is forwarded to %s", api_hash, (char*)addr);
            
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

          addr = FindReference(inst, base, dll_name, api_name);
        }
        return addr;
      }
    } while (--cnt && addr == NULL);
    
    return addr;
}

// search all modules in the PEB for API
LPVOID xGetProcAddressByHash(PDONUT_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV) {
    PPEB                  peb;
    PPEB_LDR_DATA         ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    LPVOID                addr = NULL;
     
    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
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
