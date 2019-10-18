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
typedef void (WINAPI *DllFunction_t)(char param[]);

void HookGetmainargs(PDONUT_INSTANCE, PULONG_PTR, char**, int, char*);
void HookWgetmainargs(PDONUT_INSTANCE, PULONG_PTR, wchar_t**, int, char*);
void HookGetCommandLineA(PDONUT_INSTANCE, PULONG_PTR, char*, char*);
void HookGetCommandLineW(PDONUT_INSTANCE, PULONG_PTR, wchar_t*, char*);

// same as strcmp
int xstrcmp(char *s1, char *s2) {
    while(*s1 && (*s1==*s2))s1++,s2++;
    return (int)*(unsigned char*)s1 - *(unsigned char*)s2;
}

//convert wide strings argv to ansi strings argv
void wargv2argv(PDONUT_INSTANCE inst, WCHAR **wargv, int argc, char*** argv){
    HANDLE hHeap = inst->api.GetProcessHeap();
    char **new_argv = (char**) inst->api.HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (argc * sizeof(char*)));
    for(DWORD i=0; i<argc; i++){
        new_argv[i] = (char*) inst->api.HeapAlloc(hHeap, HEAP_ZERO_MEMORY, DONUT_MAX_NAME-1);
        inst->api.WideCharToMultiByte(CP_ACP, 0, wargv[i], -1, new_argv[i], DONUT_MAX_NAME-1, NULL, NULL);
    }
    *argv = new_argv;
}

// In-Memory execution of unmanaged DLL file. YMMV with EXE files requiring subsystem..
VOID RunPE(PDONUT_INSTANCE inst) {
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
    DllMain_t                   DllMain;        // DLL
    Start_t                     Start;          // EXE
    DllFunction_t               DllFunction = NULL;    // DLL function
    LPVOID                      cs = NULL, base, host;
    DWORD                       i, cnt;
    PDONUT_MODULE               mod;
    HANDLE                      hThread;
    WCHAR                       buf[DONUT_MAX_NAME+1];

    wchar_t                     **wargv = NULL;
    char                        **argv = NULL;
    int                         argc = 0;
    PULONG_PTR                  main_arg_pointer = NULL;
    PULONG_PTR                  wmain_arg_pointer = NULL;
    PULONG_PTR                  getcommandlinea_pointer = NULL;
    PULONG_PTR                  getcommandlinew_pointer = NULL;
    char                        *asm_hook_getmainargs = NULL;
    char                        *asm_hook_wgetmainargs = NULL;
    char                        *asm_hook_GetCommandLineA = NULL;
    char                        *asm_hook_GetCommandLineW = NULL;

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
      DPRINT("Host process and payload are not compatible...cannot load.");
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
      
      ibr  = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
      ofs  = (PBYTE)cs - nt->OptionalHeader.ImageBase;
      
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
            ibn   = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);

            // run entrypoint as thread?
            if(mod->thread != 0) {
              // if this is ExitProcess, replace it with RtlExitUserThread
              if(!xstrcmp(ibn->Name, inst->exit)) {
                DPRINT("Replacing ExitProcess with RtlExitUserThread");
                ft->u1.Function = (ULONG_PTR)inst->api.RtlExitUserThread;
                continue;
              }
            }
            ft->u1.Function = (ULONG_PTR)inst->api.GetProcAddress(dll, ibn->Name);

            //save function pointers to hook
            if (!xstrcmp(inst->getmainargs, ibn->Name)) {
              DPRINT("Found %s at address %p", ibn->Name, (PVOID)&ft->u1.Function);
              main_arg_pointer = (PULONG_PTR)&ft->u1.Function;
            }
            if (!xstrcmp(inst->wgetmainargs, ibn->Name)) {
              DPRINT("Found %s at address %p", ibn->Name, (PVOID)&ft->u1.Function);
              wmain_arg_pointer = (PULONG_PTR)&ft->u1.Function;
            }
            if (!xstrcmp(inst->getcommandlinea, ibn->Name)) {
              DPRINT("Found %s at address %p", ibn->Name, (PVOID)&ft->u1.Function);
              getcommandlinea_pointer = (PULONG_PTR)&ft->u1.Function;
            }
            if (!xstrcmp(inst->getcommandlinew, ibn->Name)) {
              DPRINT("Found %s at address %p", ibn->Name, (PVOID)&ft->u1.Function);
              getcommandlinew_pointer = (PULONG_PTR)&ft->u1.Function;
            }
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
    
    if(mod->type == DONUT_MODULE_DLL) {
      DPRINT("Executing entrypoint of DLL\n\n");
      DllMain = RVA2VA(DllMain_t, cs, nt->OptionalHeader.AddressOfEntryPoint);
      DllMain(host, DLL_PROCESS_ATTACH, NULL);
      
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
              if(!xstrcmp(str, mod->method)) {
                DllFunction = RVA2VA(DllFunction_t, cs, adr[ord[cnt-1]]);
                break;
              }
            } while (--cnt);
            
            if(DllFunction != NULL) {
              DPRINT("Invoking %s", mod->method);
              DllFunction(mod->param);
            } else {
              DPRINT("Unable to resolve API");
              goto pe_cleanup;
            }
          }
        }
      }
    } else {
      //DebugBreak();
      
      // set the command line for EXE files
      if(mod->type == DONUT_MODULE_EXE) {
        if(mod->param[0] != 0) {
          DPRINT("Hooking command line functions");
          ansi2unicode(inst, mod->param, buf);
          wargv = inst->api.CommandLineToArgvW(buf, &argc);
          wargv2argv(inst, wargv, argc, &argv);
          if (main_arg_pointer != NULL)
          {
              DPRINT("Hooking __getmainargs");
              asm_hook_getmainargs = inst->api.VirtualAlloc(NULL, DONUT_ASM_SIZE,  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
              HookGetmainargs(inst, main_arg_pointer, argv, argc, asm_hook_getmainargs);
          }
          if (wmain_arg_pointer != NULL)
          {
              DPRINT("Hooking __wgetmainargs");
              asm_hook_wgetmainargs = inst->api.VirtualAlloc(NULL, DONUT_ASM_SIZE,  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
              HookWgetmainargs(inst, wmain_arg_pointer, wargv, argc, asm_hook_wgetmainargs);
          }
          if (getcommandlinea_pointer != NULL)
          {
              DPRINT("Hooking GetCommandLineA");
              asm_hook_GetCommandLineA = inst->api.VirtualAlloc(NULL, DONUT_ASM_SIZE,  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
              HookGetCommandLineA(inst, getcommandlinea_pointer, mod->param, asm_hook_GetCommandLineA);
          }
          if (getcommandlinew_pointer != NULL)
          {
              DPRINT("Hooking GetCommandLineW");
              asm_hook_GetCommandLineW = inst->api.VirtualAlloc(NULL, DONUT_ASM_SIZE,  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
              HookGetCommandLineW(inst, getcommandlinew_pointer, buf, asm_hook_GetCommandLineW);
          }
        }
      }
    
      //inst->api.AllocConsole();
      
      Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);
      
      if(mod->thread != 0) {
        // Create a new thread for this process.
        // Since we replaced ExitProcess with RtlExitUserThread in IAT, once ExitProcess is called, the
        // thread will simply terminate and return back here. Of course, this doesn't work
        // if ExitProcess is resolved dynamically.
        DPRINT("Creating thread for entrypoint of EXE : %p\n\n", (PVOID)Start);
        hThread = inst->api.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);
        
        if(hThread != NULL) {
          // wait for thread to terminate
          inst->api.WaitForSingleObject(hThread, INFINITE);
          DPRINT("Process terminated");
        }
      } else {
        // if ExitProces is called, this will terminate the host process.
        Start();
      }
    }
pe_cleanup:
    // if memory allocated
    if(cs != NULL) {
      DPRINT("Erasing %" PRIi32 " bytes of memory at %p", 
         nt->OptionalHeader.SizeOfImage, cs);
      // erase from memory
      Memset(cs, 0, nt->OptionalHeader.SizeOfImage);
      // release
      DPRINT("Releasing memory");
      inst->api.VirtualFree(cs, 0, MEM_DECOMMIT | MEM_RELEASE);
      if(asm_hook_getmainargs != NULL) inst->api.VirtualFree(asm_hook_getmainargs, 0, MEM_DECOMMIT | MEM_RELEASE);
      if(asm_hook_wgetmainargs != NULL) inst->api.VirtualFree(asm_hook_wgetmainargs, 0, MEM_DECOMMIT | MEM_RELEASE);
      if(asm_hook_GetCommandLineA != NULL) inst->api.VirtualFree(asm_hook_GetCommandLineA, 0, MEM_DECOMMIT | MEM_RELEASE);
      if(asm_hook_GetCommandLineW != NULL) inst->api.VirtualFree(asm_hook_GetCommandLineW, 0, MEM_DECOMMIT | MEM_RELEASE);
      if(argv != NULL) inst->api.HeapFree(inst->api.GetProcessHeap(), 0, argv);
    }
}

void HookGetmainargs(PDONUT_INSTANCE inst, PULONG_PTR main_arg_pointer, char **argv_hooked, int argc, char *code){
    #ifdef _WIN64
         Memcpy((void *)code, (void *)inst->hooked_getmainargs64_asm, DONUT_ASM_SIZE);
        *((int *)(code + 2)) = argc;
        *((char ***)(code + 8)) = argv_hooked;
    #else
        Memcpy((void *)code, (void *)inst->hooked_getmainargs32_asm, DONUT_ASM_SIZE);
        *((int *)(code + 6)) = argc;
        *((char ***)(code + 16)) = argv_hooked;
    #endif
    *main_arg_pointer = (ULONG_PTR)code;
}

void HookWgetmainargs(PDONUT_INSTANCE inst, PULONG_PTR wmain_arg_pointer, wchar_t **wargv_hooked, int argc, char *code){
    #ifdef _WIN64
        Memcpy((void *)code, (void *)inst->hooked_wgetmainargs64_asm, DONUT_ASM_SIZE);
        *((int *)(code + 2)) = argc;
        *((wchar_t ***)(code + 8)) = wargv_hooked;
    #else
        Memcpy((void *)code, (void *)inst->hooked_wgetmainargs32_asm, DONUT_ASM_SIZE);
        *((int *)(code + 6)) = argc;
        *((wchar_t ***)(code + 16)) = wargv_hooked;
    #endif
    *wmain_arg_pointer = (ULONG_PTR)code;
}

void HookGetCommandLineA(PDONUT_INSTANCE inst, PULONG_PTR getcommandlinea_pointer, char *commandline, char *code){
    DPRINT("code = %p", (PVOID)code);
    #ifdef _WIN64
        Memcpy((void *)code, (void *)inst->hooked_GetCommandLineA64_asm, DONUT_ASM_SIZE);
        *((char **)(code + 2)) = (char *)commandline;
    #else
        Memcpy((void *)code, (void *)inst->hooked_GetCommandLineA32_asm, DONUT_ASM_SIZE);
        *((char **)(code + 1)) = (char *)commandline;
    #endif
    *getcommandlinea_pointer = (ULONG_PTR)code;
}

void HookGetCommandLineW(PDONUT_INSTANCE inst, PULONG_PTR getcommandlinew_pointer, wchar_t *wcommandline, char *code){
    #ifdef _WIN64
        Memcpy((void *)code, (void *)inst->hooked_GetCommandLineW64_asm, DONUT_ASM_SIZE);
        *((wchar_t **)(code + 2)) = (wchar_t *)wcommandline;
    #else
        Memcpy((void *)code, (void *)inst->hooked_GetCommandLineW32_asm, DONUT_ASM_SIZE);
        *((wchar_t **)(code + 1)) = (wchar_t *)wcommandline;
    #endif
    *getcommandlinew_pointer = (ULONG_PTR)code;
}

