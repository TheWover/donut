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

typedef BOOL  (WINAPI *DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
typedef VOID  (WINAPI *Start_t)(PPEB);
typedef VOID  (WINAPI *DllParam_t)(PVOID);
typedef VOID  (WINAPI *DllVoid_t)(VOID);

// for setting the command line...
typedef CHAR**  (WINAPI *p_acmdln_t)(VOID);
typedef WCHAR** (WINAPI *p_wcmdln_t)(VOID);

BOOL SetCommandLineW(PDONUT_INSTANCE inst, PCWSTR NewCommandLine);
BOOL IsExitAPI(PDONUT_INSTANCE inst, PCHAR name);

// In-Memory execution of unmanaged DLL file. YMMV with EXE files requiring subsystem..
VOID RunPE(PDONUT_INSTANCE inst, PDONUT_MODULE mod) {
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK         *callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    DWORD                       rva;
    PDWORD                      adr;
    PDWORD                      sym;
    PWORD                       ord;
    PBYTE                       ofs;
    PCHAR                       str, name;
    HMODULE                     dll;
    ULONG_PTR                   ptr;
    DllMain_t                   DllMain;            // DLL
    Start_t                     Start;              // EXE
    DllParam_t                  DllParam = NULL;    // DLL function accepting one string parameter
    DllVoid_t                   DllVoid  = NULL;    // DLL function that accepts no parametersd
    LPVOID                      cs = NULL, base, host;
    DWORD                       i, cnt;
    HANDLE                      hThread;
    WCHAR                       buf[DONUT_MAX_NAME+1];
    DWORD                       size_of_img;
    
    base = mod->data;
    dos  = (PIMAGE_DOS_HEADER)base;
    nt   = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    
    // before doing anything. check compatibility between exe/dll and host process.
    host    = inst->api.GetModuleHandle(NULL);
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost  = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);
    
    if(nt->FileHeader.Machine != nthost->FileHeader.Machine) {
      DPRINT("Host process %08lx and file %08lx are not compatible...cannot load.", 
        nthost->FileHeader.Machine, nt->FileHeader.Machine);
      return;
    }
    
    DPRINT("Allocating %" PRIi32 " (0x%" PRIx32 ") bytes of RWX memory for file", 
      nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.SizeOfImage);
    
    cs = inst->api.VirtualAlloc(
      NULL, nt->OptionalHeader.SizeOfImage + 4096, 
      MEM_COMMIT | MEM_RESERVE, 
      PAGE_EXECUTE_READWRITE);
      
    if(cs == NULL) return;
    
    DPRINT("Copying Headers");
    Memcpy(cs, base, nt->OptionalHeader.SizeOfHeaders);
    
    DPRINT("Copying each section to RWX memory %p", cs);
    sh = IMAGE_FIRST_SECTION(nt);
      
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      Memcpy((PBYTE)cs + sh[i].VirtualAddress,
          (PBYTE)base + sh[i].PointerToRawData,
          sh[i].SizeOfRawData);
    }
    
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Applying Relocations");
      
      ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
      ofs = (PBYTE)cs - nt->OptionalHeader.ImageBase;
      
      while(ibr->VirtualAddress != 0) {
        list = (PIMAGE_RELOC)(ibr + 1);

        while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
          if(list->type == IMAGE_REL_TYPE) {
            *(ULONG_PTR*)((PBYTE)cs + ibr->VirtualAddress + list->offset) += (ULONG_PTR)ofs;
          } else if(list->type != IMAGE_REL_BASED_ABSOLUTE) {
            DPRINT("ERROR: Unrecognized Relocation type %08lx.", list->type);
            goto pe_cleanup;
          }
          list++;
        }
        ibr = (PIMAGE_BASE_RELOCATION)list;
      }
    }
    
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing the Import Table");
      
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
          
          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)inst->api.GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
          } else {
            // Resolve by name
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);

            // run entrypoint as thread?
            if(mod->thread != 0) {
              // if this is an exit-related API, replace it with RtlExitUserThread
              if(IsExitAPI(inst, ibn->Name)) {
                DPRINT("Replacing %s!%s with ntdll!RtlExitUserThread", name, ibn->Name);
                ft->u1.Function = (ULONG_PTR)inst->api.RtlExitUserThread;
                continue;
              }
            }
            ft->u1.Function = (ULONG_PTR)inst->api.GetProcAddress(dll, ibn->Name);
          }
        }
      }
    }
    
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    
    if(rva != 0) {
      DPRINT("Processing Delayed Import Table");
      
      del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);
      
      // For each DLL
      for (;del->DllNameRVA != 0; del++) {
        name = RVA2VA(PCHAR, cs, del->DllNameRVA);
        
        DPRINT("Loading %s", name);
        dll = inst->api.LoadLibraryA(name);
        
        if(dll == NULL) continue;
        
        // Resolve the API for this library
        oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
        ft  = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);
          
        // For each API
        for (;; oft++, ft++) {
          // No API left?
          if (oft->u1.AddressOfData == 0) break;

          // Resolve by ordinal?
          if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
            ft->u1.Function = (ULONG_PTR)inst->api.GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
          } else {
            // Resolve by name
            ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
            ft->u1.Function = (ULONG_PTR)inst->api.GetProcAddress(dll, ibn->Name);
          }
        }
      }
    }

    /** 
      Execute TLS callbacks. These are only called when the process starts, not when a thread begins, ends
      or when the process ends. TLS is not fully supported.
    */
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if(rva != 0) {
      DPRINT("Processing TLS directory");
      
      tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);
      
      // address of callbacks is absolute. requires relocation information
      callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
      DPRINT("AddressOfCallBacks : %p", callbacks);
      
      // DebugBreak();
      
      if(callbacks) {
        while(*callbacks != NULL) {
          // call function
          DPRINT("Calling %p", *callbacks);
          (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
          callbacks++;
        }
      }
    }
      
    size_of_img = nt->OptionalHeader.SizeOfImage;
    Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);
      
    if(mod->type == DONUT_MODULE_DLL) {
      DPRINT("Executing entrypoint of DLL\n\n");
      DllMain = RVA2VA(DllMain_t, cs, nt->OptionalHeader.AddressOfEntryPoint);
      DllMain(cs, DLL_PROCESS_ATTACH, NULL);
      
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
              if(!_strcmp(str, mod->method)) {
                DllParam = RVA2VA(DllParam_t, cs, adr[ord[cnt-1]]);
                break;
              }
            } while (--cnt);
            
            DPRINT("Wiping Headers from memory");
            Memset(cs,   0, nt->OptionalHeader.SizeOfHeaders);
            Memset(base, 0, nt->OptionalHeader.SizeOfHeaders);
      
            // resolved okay?
            if(DllParam != NULL) {
              DPRINT("Invoking %s", mod->method);
              // pass parameters/command line to function?
              if(mod->param[0] != 0) {
                if(mod->unicode) {
                  ansi2unicode(inst, mod->param, buf);
                }
                DllParam((mod->unicode) ? (PVOID)buf : (PVOID)mod->param);
              } else {
                // execute DLL function with no parameters
                DllVoid = (DllVoid_t)DllParam;
                DllVoid();
              }
            } else {
              DPRINT("Unable to resolve API");
              goto pe_cleanup;
            }
          }
        }
      }
    } else {

      // set the command line
      if(mod->param[0] != 0) {
        ansi2unicode(inst, mod->param, buf);
        DPRINT("Setting command line: %ws", buf);
        SetCommandLineW(inst, buf);
      }
      
      DPRINT("Wiping Headers from memory");
      Memset(cs,   0, nt->OptionalHeader.SizeOfHeaders);
      Memset(base, 0, nt->OptionalHeader.SizeOfHeaders);
    
      if(mod->thread != 0) {
        // Create a new thread for this process.
        // Since we replaced exit-related API with RtlExitUserThread in IAT, once an exit-related API is called, the
        // thread will simply terminate and return back here. Of course, this doesn't work
        // if the exit-related API is resolved dynamically.
        DPRINT("Creating thread for entrypoint of EXE : %p\n\n", (PVOID)Start);
        hThread = inst->api.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);
        
        if(hThread != NULL) {
          // wait for thread to terminate
          inst->api.WaitForSingleObject(hThread, INFINITE);
          DPRINT("Process terminated");
        }
      } else {
        // if ExitProces is called, this will terminate the host process.
        DPRINT("Executing entrypoint");
        Start(NtCurrentTeb()->ProcessEnvironmentBlock);
      }
    }
pe_cleanup:
    // if memory allocated
    if(cs != NULL) {
      // release
      DPRINT("Releasing memory");
      inst->api.VirtualFree(cs, 0, MEM_DECOMMIT | MEM_RELEASE);
    }
}

// check each exit-related api with name provided
// return TRUE if found, else FALSE
BOOL IsExitAPI(PDONUT_INSTANCE inst, PCHAR name) {
    PCHAR str;
    CHAR  api[128];
    INT   i;
    
    str = inst->exit_api;
    
    for(;;) {
      // store string until null byte or semi-colon encountered
      for(i=0; str[i] != '\0' && str[i] !=';' && i<128; i++) api[i] = str[i];
      // nothing stored? end
      if(i == 0) break;
      // skip name plus one for separator
      str += (i + 1);
      // store null terminator
      api[i] = '\0';
      // if equal, return TRUE
      if(!_strcmp(api, name)) return TRUE;
    } 
    return FALSE;
}

// returns TRUE if ptr is heap memory
BOOL IsHeapPtr(PDONUT_INSTANCE inst, LPVOID ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD                    res;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    res = inst->api.VirtualQuery(ptr, &mbi, sizeof(mbi));
    if(res != sizeof(mbi)) return FALSE;

    return ((mbi.State   == MEM_COMMIT    ) &&
            (mbi.Type    == MEM_PRIVATE   ) && 
            (mbi.Protect == PAGE_READWRITE));
}

// Set the command line for host process.
//
// This replaces kernelbase!BaseUnicodeCommandLine and kernelbase!BaseAnsiCommandLine
// that kernelbase!KernelBaseDllInitialize reads from NtCurrentPeb()->ProcessParameters->CommandLine 
//
// BOOL KernelBaseDllInitialize(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
//
// Only tested on windows 10, but should work with at least windows 7
BOOL SetCommandLineW(PDONUT_INSTANCE inst, PCWSTR CommandLine) {
    PIMAGE_DOS_HEADER            dos;
    PIMAGE_NT_HEADERS            nt;
    PIMAGE_SECTION_HEADER        sh;
    DWORD                        i, cnt;
    PULONG_PTR                   ds;
    HMODULE                      m;
    ANSI_STRING                  ansi;
    PANSI_STRING                 mbs;
    PUNICODE_STRING              wcs;
    PPEB                         peb;
    PPEB_LDR_DATA                ldr;
    PLDR_DATA_TABLE_ENTRY        dte;
    PRTL_USER_PROCESS_PARAMETERS upp;
    BOOL                         bSet = FALSE;
    CHAR                         **argv;
    WCHAR                        **wargv;
    p_acmdln_t                   p_acmdln;
    p_wcmdln_t                   p_wcmdln;
    CHAR                         sym[128];
    PCHAR                        str;
    INT                          fptr, atype;
    PVOID                        addr, wcmd, acmd;
    
    peb = (PPEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    upp = peb->ProcessParameters;

    DPRINT("Obtaining handle for %s", inst->kernelbase);
    m   = inst->api.GetModuleHandle(inst->kernelbase);
    dos = (PIMAGE_DOS_HEADER)m;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, m, dos->e_lfanew);  
    sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
          nt->FileHeader.SizeOfOptionalHeader);
          
    // locate the .data segment, save VA and number of pointers
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if(*(PDWORD)sh[i].Name == *(PDWORD)inst->dataname) {
        ds  = RVA2VA(PULONG_PTR, m, sh[i].VirtualAddress);
        cnt = sh[i].Misc.VirtualSize / sizeof(ULONG_PTR);
        break;
      }
    }
    
    DPRINT("Searching %i pointers", cnt);
    
    wcmd = inst->api.GetCommandLineW();
    
    for(i=0; i<cnt; i++) {
      wcs = (PUNICODE_STRING)&ds[i];
      // skip if not equal
      if(wcs->Buffer != wcmd) continue;
      DPRINT("BaseUnicodeCommandLine found at %p:%p : %ws", &ds[i], wcs->Buffer, wcs->Buffer);
      // overwrite buffer for GetCommandLineW
      inst->api.RtlCreateUnicodeString(wcs, CommandLine);
      DPRINT("GetCommandLineW() : %ws", GetCommandLineW());
      break;
    }
    
    acmd = inst->api.GetCommandLineA();
    
    for(i=0; i<cnt; i++) {
      mbs = (PANSI_STRING)&ds[i];
      // skip if not equal
      if(mbs->Buffer != acmd) continue;
      DPRINT("BaseAnsiCommandLine found at %p:%p : %ws", &ds[i], mbs->Buffer, mbs->Buffer);
      inst->api.RtlUnicodeStringToAnsiString(&ansi, wcs, TRUE);
      Memcpy(&ds[i], &ansi, sizeof(ANSI_STRING));
      DPRINT("GetCommandLineA() : %s", GetCommandLineA());
      break;
    }
    
    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      // check for exported symbols and patch according to string type
      str = (PCHAR)inst->cmd_syms;
      
      for(;;) {
        // reset flags
        atype = 1; fptr = 0;
        // store string until null byte or semi-colon encountered
        for(i=0; str[i] != '\0' && str[i] !=';' && i<128; i++) {
          // w indicates unicode type
          if(str[i] == 'w') atype = 0;
          // p indicates function pointer
          if(str[i] == 'p') fptr  = 1;
          // store byte
          sym[i] = str[i];
        }
        // nothing stored? end loop for this DLL
        if(i == 0) break;
        // skip name plus one for separator
        str += (i + 1);
        // store null terminator
        sym[i] = '\0';
        // see if it can be resolved for current module
        addr = inst->api.GetProcAddress(dte->DllBase, sym);
        // nothing resolve? get the next symbol from list
        if(addr == NULL) continue;
        // is this ansi?
        if(atype) {
          argv = (PCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_acmdln = (p_acmdln_t)addr;
            argv = p_acmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(argv != NULL && IsHeapPtr(inst, *argv)) {
            DPRINT("Setting %ws!%s \"%s\" to \"%s\"", 
              dte->BaseDllName.Buffer, sym, *argv, ansi.Buffer);
            *argv = ansi.Buffer;
          }
        } else {
          wargv = (PWCHAR*)addr;
          // pointer?
          if(fptr != 0) {
            p_wcmdln = (p_wcmdln_t)addr;
            wargv = p_wcmdln();
          }
          // anything to patch?
          DPRINT("Checking %s", sym);
          if(wargv != NULL && IsHeapPtr(inst, *wargv)) {
            DPRINT("Setting %ws!%s \"%ws\" to \"%ws\"", 
              dte->BaseDllName.Buffer, sym, *wargv, wcs->Buffer);
            *wargv = wcs->Buffer;
          }
        }
      }
    }
    return TRUE;
}
