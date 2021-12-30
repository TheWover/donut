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
VOID run(Start_t Start);

// In-Memory execution of unmanaged DLL file. YMMV with EXE files requiring subsystem..
VOID RunPE(PDONUT_INSTANCE inst, PDONUT_MODULE mod) {
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_SECTION_HEADER       shcp = NULL;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_EXPORT_DIRECTORY     exp;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK         *callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    IMAGE_NT_HEADERS            ntc;
    DWORD                       rva, size;
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
    LPVOID                      base, host;
    DWORD                       i, cnt;
    HANDLE                      hThread;
    WCHAR                       buf[DONUT_MAX_NAME+1];
    PVOID                       baseAddress;
    SIZE_T                      numBytes;
    DWORD                       newprot, oldprot;
    NTSTATUS                    status;
    HANDLE                      hSection;
    LARGE_INTEGER               liSectionSize;
    PVOID                       cs = NULL;
    SIZE_T                      viewSize = 0;
    PVOID                       ba;
    SIZE_T                      rs;
    CLIENT_ID                   cid;
    BOOL                        has_reloc;
    
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
    
    liSectionSize.QuadPart = nt->OptionalHeader.SizeOfImage;

    // check if the binary has relocation information
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    has_reloc = size == 0? FALSE : TRUE;
    if (!has_reloc)
    {
      DPRINT("No relocation information present, setting the base to: 0x%p", (PVOID)nt->OptionalHeader.ImageBase);
      cs = (PVOID)nt->OptionalHeader.ImageBase;
    }

    DPRINT("Creating section to store PE.");
    if (inst->decoy[0] == 0) {
      status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &liSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
      DPRINT("NTSTATUS: 0x%lx", status);
      if(!NT_SUCCESS(status)) return;
    }
    else {
      DPRINT("Decoy file path: %ls", inst->decoy);
      // implement module overloading by creating a MEM_IMAGE section backed by the decoy file
      HANDLE hDecoy;
      OBJECT_ATTRIBUTES obj_attr;
      IO_STATUS_BLOCK status_block;
      UNICODE_STRING path;
      inst->api.RtlInitUnicodeString(&path, inst->decoy);
      // init the object attributes
      InitializeObjectAttributes(
          &obj_attr,
          &path,
          OBJ_CASE_INSENSITIVE,
          NULL,
          NULL
      );
      status = NtCreateFile(&hDecoy, GENERIC_READ, &obj_attr, &status_block, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

      if (!NT_SUCCESS(status) || hDecoy == INVALID_HANDLE_VALUE || hDecoy == 0) {
        DPRINT("Error opening decoy file: %d", inst->api.GetLastError());
        return;
      }
      DPRINT("File handle: %p", hDecoy);
      
      status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hDecoy);

      NtClose(hDecoy);

      DPRINT("NTSTATUS: 0x%lx", status);
      if(!NT_SUCCESS(status)) return;
    }
    
    DPRINT("Mapping local view of section to store PE.");
    status = NtMapViewOfSection(hSection, NtCurrentProcess(), &cs, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
    DPRINT("NTSTATUS: 0x%lx", status);
    if(!NT_SUCCESS(status)) return;
    
    if(cs == NULL) return;
    DPRINT("Mapped at 0x%p", cs);

    //system("pause");

    // if module overloading, set everything to RW because they will start out otherwise
    if (inst->decoy[0] != 0) {
      ba = cs;
      rs = viewSize;
      status = NtProtectVirtualMemory(NtCurrentProcess(), &ba, &rs, PAGE_READWRITE, &oldprot);
      DPRINT("NTSTATUS: 0x%lx", status);
      if(!NT_SUCCESS(status)) return;
    }

    DPRINT("Copying Headers");
    Memcpy(cs, base, nt->OptionalHeader.SizeOfHeaders);
    
    DPRINT("Copying each section to memory %p", cs);
    sh = IMAGE_FIRST_SECTION(nt);
      
    for(i=0; i<nt->FileHeader.NumberOfSections; i++) {
      Memcpy((PBYTE)cs + sh[i].VirtualAddress,
          (PBYTE)base + sh[i].PointerToRawData,
          sh[i].SizeOfRawData);
    }
    
    rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    ofs  = (PBYTE)cs - nt->OptionalHeader.ImageBase;

    if (size != 0 && ofs != 0) {
      DPRINT("Applying Relocations");
      
      ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
      
      while (ibr->SizeOfBlock != 0 && (PBYTE)ibr < ((PBYTE)cs + rva + size)) {
        list = (PIMAGE_RELOC)(ibr + 1);
  
        while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
          PULONG_PTR address = (PULONG_PTR)((PBYTE)cs + ibr->VirtualAddress + list->offset);
          if (list->type == IMAGE_REL_BASED_DIR64) {
            *address += (ULONG_PTR)ofs;
          } else if (list->type == IMAGE_REL_BASED_HIGHLOW) {
            *address += (DWORD)(ULONG_PTR)ofs;
          } else if (list->type == IMAGE_REL_BASED_HIGH) {
            *address += HIWORD(ofs);
          } else if (list->type == IMAGE_REL_BASED_LOW) {
            *address += LOWORD(ofs);
          } else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
            DPRINT("ERROR: Unrecognized Relocation type %08lx.", list->type);
            goto pe_cleanup;
          }
          list++;
        }
        ibr = (PIMAGE_BASE_RELOCATION)list;
      }
    }
    
    rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    
    if(size != 0) {
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
      
    Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);

    // copy relevant headers before they are wiped
    ntc = *nt;

    shcp = NULL;
    rs = ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID)&shcp, 0, &rs, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DPRINT("NTSTATUS: 0x%lx", status);
    if (!NT_SUCCESS(status)) return;

    Memcpy(shcp, sh, ntc.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    if(inst->headers == 1)
    {
      // if no decoy is specified, just wipe the headers
      if (inst->decoy[0] == 0)
      {
        DPRINT("Wiping Headers from memory");
        Memset(cs,   0, nt->OptionalHeader.SizeOfHeaders);
        Memset(base, 0, nt->OptionalHeader.SizeOfHeaders);
      }
      else {
        DPRINT("Overwriting PE headers with the decoy module's.");
        Memcpy(base, cs, nt->OptionalHeader.SizeOfHeaders);
      }
    }

    if (inst->decoy[0] == 0) {
      DPRINT("Ummapping temporary local view of section to persist changes.");
      status = NtUnmapViewOfSection(NtCurrentProcess(), cs);
      DPRINT("NTSTATUS: 0x%lx", status);
      if(!NT_SUCCESS(status)) return;

      // if no reloc information is present, make sure we use the preferred address
      if (has_reloc)
        cs = NULL;

      viewSize = 0;

      DPRINT("Mapping writecopy local view of section to execute PE.");
      status = NtMapViewOfSection(hSection, NtCurrentProcess(), &cs, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY);
      DPRINT("NTSTATUS: 0x%lx", status);
      if(!NT_SUCCESS(status)) return;
    }

    // start everything out as WC
    // this is because some sections are padded and you can end up with extra RWX memory if you don't pre-mark the padding as WC
    DPRINT("Pre-marking module as WC to avoid padding between PE sections staying RWX.")
    status = NtProtectVirtualMemory(NtCurrentProcess(), &cs, &viewSize, PAGE_WRITECOPY, &oldprot);
    DPRINT("NTSTATUS: 0x%lx", status);
    if(!NT_SUCCESS(status)) return;

    DPRINT("Setting permissions for each PE section");
    // done with binary manipulation, mark section permissions appropriately
    for (i = 0; i < ntc.FileHeader.NumberOfSections; i++)
    {
      BOOL isRead = (shcp[i].Characteristics & IMAGE_SCN_MEM_READ) ? TRUE : FALSE;
      BOOL isWrite = (shcp[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? TRUE : FALSE;
      BOOL isExecute = (shcp[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

      if (isWrite & isExecute)
        continue; // do nothing, already WCX
      else if (isRead & isExecute)
          newprot = PAGE_EXECUTE_READ;
      else if (isRead & isWrite & !isExecute)
      {
        if (inst->decoy[0] == 0)
          newprot = PAGE_WRITECOPY; // must use WC because RW is incompatible with permissions of initial view (WCX)
        else
          newprot = PAGE_READWRITE;
      }
      else if (!isRead & !isWrite & isExecute)
          newprot = PAGE_EXECUTE;
      else if (isRead & !isWrite & !isExecute)
          newprot = PAGE_READONLY;

      baseAddress = (PBYTE)cs + shcp[i].VirtualAddress;
      if (i < (ntc.FileHeader.NumberOfSections - 1))
        numBytes = ((PBYTE)cs + shcp[i+1].VirtualAddress) - ((PBYTE)cs + shcp[i].VirtualAddress);
      else
        numBytes = shcp[i].SizeOfRawData;

      oldprot = 0;

      DPRINT("Section offset: 0x%X", shcp[i].VirtualAddress);
      DPRINT("Section absolute address: 0x%p", baseAddress);
      DPRINT("Section size: 0x%lX", numBytes);
      DPRINT("Section protections: 0x%X", newprot);
      
      status = NtProtectVirtualMemory(NtCurrentProcess(), &baseAddress, &numBytes, newprot, &oldprot);
      DPRINT("NTSTATUS: 0x%lx", status);
      if (!NT_SUCCESS(status)) return;
    }

    // declare variables and set permissions of module header
    DPRINT("Setting permissions of module headers to READONLY (%d bytes)", ntc.OptionalHeader.BaseOfCode);
    oldprot = 0;
    numBytes = ntc.OptionalHeader.BaseOfCode;
    status = NtProtectVirtualMemory(NtCurrentProcess(), &cs, &numBytes, PAGE_READONLY, &oldprot);
    DPRINT("NTSTATUS: 0x%lx", status);
    if (!NT_SUCCESS(status)) return;

    DPRINT("Flushing instructionCache");
    status = NtFlushInstructionCache(NtCurrentProcess(), NULL, 0);
    DPRINT("NTSTATUS: 0x%lx", status);
    if (!NT_SUCCESS(status)) return;

    /** 
      Execute TLS callbacks. These are only called when the process starts, not when a thread begins, ends
      or when the process ends. TLS is not fully supported.
    */
    rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

    if(rva != 0) {
      DPRINT("Processing TLS directory");
      
      tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);
      
      // address of callbacks is absolute. requires relocation information
      callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

      // DebugBreak();
      
      if(callbacks) {
        while(*callbacks != NULL) {
          // call function
          DPRINT("Calling 0x%p", *callbacks);
          (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
          callbacks++;
        }
      }
    }

    //system("pause");

    if(mod->type == DONUT_MODULE_DLL) {
      DPRINT("Executing entrypoint of DLL\n\n");
      DllMain = RVA2VA(DllMain_t, cs, ntc.OptionalHeader.AddressOfEntryPoint);
      DllMain(cs, DLL_PROCESS_ATTACH, NULL);
      
      // call exported api?
      if(mod->method[0] != 0) {
        DPRINT("Resolving address of %s", (char*)mod->method);
        
        rva = ntc.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exp = RVA2VA(PIMAGE_EXPORT_DIRECTORY, cs, rva);
        
        if(rva != 0) {
          cnt = exp->NumberOfNames;
          
          DPRINT("IMAGE_EXPORT_DIRECTORY.NumberOfNames : %i", cnt);
          
          if(cnt != 0) {
            adr = RVA2VA(PDWORD,cs, exp->AddressOfFunctions);
            sym = RVA2VA(PDWORD,cs, exp->AddressOfNames);
            ord = RVA2VA(PWORD, cs, exp->AddressOfNameOrdinals);

            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfFunctions : 0x%X", *adr);
            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfNames : 0x%X", *sym);
            DPRINT("IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals : 0x%X", *ord);
        
            do {
              str = RVA2VA(PCHAR, cs, sym[cnt-1]);
              if(!_strcmp(str, mod->method)) {
                DllParam = RVA2VA(DllParam_t, cs, adr[ord[cnt-1]]);
                break;
              }
            } while (--cnt);
      
            // resolved okay?
            if(DllParam != NULL) {
              DPRINT("Invoking %s", mod->method);
              // pass parameters/command line to function?
              if(mod->args[0] != 0) {
                if(mod->unicode) {
                  ansi2unicode(inst, mod->args, buf);
                }
                DllParam((mod->unicode) ? (PVOID)buf : (PVOID)mod->args);
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
      if(mod->args[0] != 0) {
        ansi2unicode(inst, mod->args, buf);
        DPRINT("Setting command line: %ws", buf);
        SetCommandLineW(inst, buf);
      }

      if(mod->thread != 0) {
        // Create a new thread for this process.
        // Since we replaced exit-related API with RtlExitUserThread in IAT, once an exit-related API is called, the
        // thread will simply terminate and return back here. Of course, this doesn't work
        // if the exit-related API is resolved dynamically.
        // The creaed thread has a valid start address
        DPRINT("Creating thread for entrypoint of EXE : %p", (PVOID)Start);
        status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)run, (PVOID)Start, 0, 0, 0, 0, NULL);
        
        if(NT_SUCCESS(status)) {
          // wait for thread to terminate
          status = NtWaitForSingleObject(hThread, FALSE, NULL);
          DPRINT("NTSTATUS: 0x%lx", status);
          if (!NT_SUCCESS(status)) return;
          DPRINT("Process terminated");
        }
      } else {
        // if ExitProces is called, this will terminate the host process.
        run(Start);
      }
    }
pe_cleanup:
    // if memory allocated
    if(cs != NULL) {
      // release
      DPRINT("Releasing memory");
      rs = 0;
      status = NtFreeVirtualMemory(NtCurrentProcess(), (PVOID)&shcp, &rs, MEM_RELEASE);
      DPRINT("NTSTATUS: 0x%lx", status);
      if (!NT_SUCCESS(status)) return;
      status = NtUnmapViewOfSection(NtCurrentProcess(), cs);
      DPRINT("NTSTATUS: 0x%lx", status);
      if (!NT_SUCCESS(status)) return;
      NtClose(hSection);
    }
}

// helper function to create threads with a valid start address
VOID run(Start_t Start) {
  DPRINT("Executing entrypoint\n\n");
  Start(NtCurrentTeb()->ProcessEnvironmentBlock);
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
    NTSTATUS                 status;
    
    if(ptr == NULL) return FALSE;
    
    // query the pointer
    status = NtQueryVirtualMemory(NtCurrentProcess(), ptr, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(status)) return FALSE;

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
      DPRINT("BaseAnsiCommandLine found at %p:%p : %s", &ds[i], mbs->Buffer, mbs->Buffer);
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
