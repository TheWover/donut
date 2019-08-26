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

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

typedef struct _IMAGE_RELOC {
    WORD offset :12;
    WORD type   :4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef BOOL (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef VOID (WINAPI *Start_t)(VOID);

typedef void (__cdecl *call_stub_t)(FARPROC api, int param_cnt, WCHAR param[DONUT_MAX_PARAM][DONUT_MAX_NAME]);

// same as strcmp
int xstrcmp(char *s1, char *s2) {
    while(*s1 && (*s1==*s2))s1++,s2++;
    return (int)*(unsigned char*)s1 - *(unsigned char*)s2;
}

// In-Memory execution of unmanaged DLL file. YMMV with EXE files requiring subsystem..
VOID RunPE(PDONUT_INSTANCE inst) {
    PIMAGE_DOS_HEADER        dos, doshost;
    PIMAGE_NT_HEADERS        nt, nthost;
    PIMAGE_SECTION_HEADER    sh;
    PIMAGE_THUNK_DATA        oft, ft;
    PIMAGE_IMPORT_BY_NAME    ibn;
    PIMAGE_IMPORT_DESCRIPTOR imp;
    PIMAGE_EXPORT_DIRECTORY  exp;
    PIMAGE_RELOC             list;
    PIMAGE_BASE_RELOCATION   ibr;
    DWORD                    rva;
    PDWORD                   adr;
    PDWORD                   sym;
    PWORD                    ord;
    PBYTE                    ofs;
    PCHAR                    str, name;
    HMODULE                  dll;
    ULONG_PTR                ptr;
    DllMain_t                DllMain;        // DLL
    Start_t                  Start;          // EXE
    call_stub_t              CallApi;        // DLL function
    LPVOID                   cs = NULL, base, host;
    DWORD                    i, cnt;
    PDONUT_MODULE            mod;
    FARPROC                  api=NULL;       // DLL export
    
    // write shellcode to stack. msvc sux!!
    #include "call_api_bin.h"

    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }
    
    base = mod->data;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    
    // before doing anything. check compatibility between exe/dll and host process.
    host    = inst->api.GetModuleHandle(NULL);
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost  = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);
    
    if(nt->FileHeader.Machine != nthost->FileHeader.Machine) {
      DPRINT("Host process and payload are not compatiable...cannot load.");
      return;
    }
    
    DPRINT("Allocating %" PRIi32 " (0x%" PRIx32 ") bytes of RWX memory for file", 
      nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfImage);
    
    cs = inst->api.VirtualAlloc(
      NULL, nt->OptionalHeader.SizeOfImage + 4096, 
      MEM_COMMIT | MEM_RESERVE, 
      PAGE_EXECUTE_READWRITE);
      
    if(cs == NULL) return;
    
    DPRINT("Copying each section to RWX memory %p", cs);
    sh = IMAGE_FIRST_SECTION(nt);
      
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      Memcpy((PBYTE)cs + sh[i].VirtualAddress,
          (PBYTE)base + sh[i].PointerToRawData,
          sh[i].SizeOfRawData);
    }
    
    DPRINT("Processing the Import Table");
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);
      
    // For each DLL
    for (;imp->Name!=0; imp++) {
      name = RVA2VA(PCHAR, cs, imp->Name);
      
      DPRINT("Loading %s", name);
      dll = inst->api.LoadLibraryA(name);
      
      // Resolve the API for this library
      oft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk);
      ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);
        
      // For each API
      for (;; oft++, ft++) {
        // No API left?
        if (oft->u1.AddressOfData == 0) break;
        
        PULONG_PTR func = (PULONG_PTR)&ft->u1.Function;
        
        // Resolve by ordinal?
        if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
          *func = (ULONG_PTR)inst->api.GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
        } else {
          // Resolve by name
          ibn   = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
          *func = (ULONG_PTR)inst->api.GetProcAddress(dll, ibn->Name);
        }
      }
    }
    
    DPRINT("Applying Relocations");
    rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    ibr  = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
    ofs  = (PBYTE)cs - nt->OptionalHeader.ImageBase;
    
    while(ibr->VirtualAddress != 0) {
      list = (PIMAGE_RELOC)(ibr + 1);

      while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
        if(list->type == IMAGE_REL_TYPE) {
          *(ULONG_PTR*)((PBYTE)cs + ibr->VirtualAddress + list->offset) += (ULONG_PTR)ofs;
        } else if(list->type != IMAGE_REL_BASED_ABSOLUTE) {
          DPRINT("ERROR: Unrecognized Relocation type %08lx.", (DWORD)list->type);
          goto pe_cleanup;
        }
        list++;
      }
      ibr = (PIMAGE_BASE_RELOCATION)list;
    }

    if(mod->type == DONUT_MODULE_DLL) {
      // call exported api?
      if(mod->method[0] != 0) {
        DPRINT("Resolving address of %s", (char*)mod->method);
        
        rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        
        if(rva != 0) {
          exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, cs, rva);
          cnt = exp->NumberOfNames;
          
          DPRINT("IMAGE_EXPORT_DIRECTORY.NumberOfNames : %i", cnt);
          
          if(cnt != 0) {
            adr = RVA2VA(PDWORD,cs, exp->AddressOfFunctions);
            sym = RVA2VA(PDWORD,cs, exp->AddressOfNames);
            ord = RVA2VA(PWORD, cs, exp->AddressOfNameOrdinals);
        
            do {
              str = RVA2VA(PCHAR, cs, sym[cnt-1]);
              if(!xstrcmp(str, (char*)mod->method)) {
                api = RVA2VA(FARPROC, cs, adr[ord[cnt-1]]);
                break;
              }
            } while (--cnt);
            
            if(api != NULL) {
              CallApi = inst->api.VirtualAlloc(
                NULL, 
                sizeof(CALL_API_BIN), 
                MEM_COMMIT | MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE);
                
              if(CallApi != NULL) {
                DPRINT("Calling %s via code stub.", (char*)mod->method);
                Memcpy((void*)CallApi, (void*)CALL_API_BIN, sizeof(CALL_API_BIN));
                CallApi(api, mod->param_cnt, mod->param);
                DPRINT("Erasing code stub");
                Memset(CallApi, 0, sizeof(CALL_API_BIN));
                inst->api.VirtualFree(CallApi, 0, MEM_DECOMMIT | MEM_RELEASE);
              }
            } else {
              DPRINT("Unable to resolve API");
              goto pe_cleanup;
            }
          }
        }
      } else {
        DPRINT("Executing entrypoint of DLL\n\n");
        DllMain = RVA2VA(DllMain_t, cs, nt->OptionalHeader.AddressOfEntryPoint);
        DllMain(host, DLL_PROCESS_ATTACH, NULL);
      }
    } else {
      // The problem with executing EXE files:
      // 1) They use subsystems either GUI or CUI
      // 2) They call ExitProcess ...will need to review support of this later.
      DPRINT("Executing entrypoint of EXE\n\n");
      Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);
      Start();
    }
pe_cleanup:
    // if memory allocated
    if(cs != NULL) {
      // DPRINT("Erasing %" PRIi32 " bytes of memory at %p", 
      //   nt->OptionalHeader.SizeOfImage, cs);
      // erase from memory (disabled for now)
      // Memset(cs, 0, nt->OptionalHeader.SizeOfImage);
      // release
      DPRINT("Releasing memory");
      inst->api.VirtualFree(cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    }
}
