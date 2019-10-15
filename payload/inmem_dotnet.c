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

BOOL LoadAssembly(PDONUT_INSTANCE inst, PDONUT_ASSEMBLY pa) {
    PDONUT_MODULE   mod;
    HRESULT         hr = S_OK;
    BSTR            domain;
    SAFEARRAYBOUND  sab;
    SAFEARRAY       *sa;
    DWORD           i;
    BOOL            loaded=FALSE, loadable;
    PBYTE           p;
    WCHAR           buf[DONUT_MAX_NAME];
    
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
        DPRINT("ICLRMetaHost::GetRuntime(\"%s\")", mod->runtime);
        ansi2unicode(inst, mod->runtime, buf);
        
        hr = pa->icmh->lpVtbl->GetRuntime(
          pa->icmh, buf, 
          (REFIID)&inst->xIID_ICLRRuntimeInfo, (LPVOID)&pa->icri);
        
        if(SUCCEEDED(hr)) {
          DPRINT("ICLRRuntimeInfo::IsLoadable");
          hr = pa->icri->lpVtbl->IsLoadable(pa->icri, &loadable);
        
          if(SUCCEEDED(hr) && loadable) {
            DPRINT("ICLRRuntimeInfo::GetInterface");
          
            hr = pa->icri->lpVtbl->GetInterface(
              pa->icri, 
              (REFCLSID)&inst->xCLSID_CorRuntimeHost, 
              (REFIID)&inst->xIID_ICorRuntimeHost, 
              (LPVOID)&pa->icrh);
              
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
      DPRINT("Domain is %s", mod->domain);
      ansi2unicode(inst, mod->domain, buf);
      domain = inst->api.SysAllocString(buf);
      
      DPRINT("ICorRuntimeHost::CreateDomain(\"%ws\")", buf);
      
      hr = pa->icrh->lpVtbl->CreateDomain(
        pa->icrh, domain, NULL, &pa->iu);
        
      inst->api.SysFreeString(domain);
      
      if(SUCCEEDED(hr)) {
        DPRINT("IUnknown::QueryInterface");
        
        hr = pa->iu->lpVtbl->QueryInterface(
          pa->iu, (REFIID)&inst->xIID_AppDomain, (LPVOID)&pa->ad);
          
        if(SUCCEEDED(hr)) {
          sab.lLbound   = 0;
          sab.cElements = mod->len;
          sa = inst->api.SafeArrayCreate(VT_UI1, 1, &sab);
          
          if(sa != NULL) {
            DPRINT("Copying %" PRIi64 " bytes of assembly to safe array", mod->len);
            
            for(i=0, p=sa->pvData; i<mod->len; i++) {
              p[i] = mod->data[i];
            }

            DPRINT("AppDomain::Load_3");
            
            hr = pa->ad->lpVtbl->Load_3(
              pa->ad, sa, &pa->as);
            
            loaded = hr == S_OK;
            
            DPRINT("HRESULT : %08lx", hr);
            
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
    return loaded;
}
    
BOOL RunAssembly(PDONUT_INSTANCE inst, PDONUT_ASSEMBLY pa) {
    SAFEARRAY     *sav=NULL, *args=NULL;
    VARIANT       arg, ret, vtPsa, v1={0}, v2;
    DWORD         i;
    PDONUT_MODULE mod;
    HRESULT       hr;
    BSTR          cls, method;
    ULONG         cnt;
    OLECHAR       str[1]={0};
    LONG          ucnt, lcnt;
    WCHAR         **argv, buf[DONUT_MAX_NAME+1];
    int           argc;
    
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }
    
    DPRINT("Type is %s", 
      mod->type == DONUT_MODULE_NET_DLL ? "DLL" : "EXE");
    
    // if this is a program
    if(mod->type == DONUT_MODULE_NET_EXE) {
      // get the entrypoint
      DPRINT("MethodInfo::EntryPoint");
      hr = pa->as->lpVtbl->EntryPoint(pa->as, &pa->mi);
      
      if(SUCCEEDED(hr)) {
        // get the parameters for entrypoint
        DPRINT("MethodInfo::GetParameters");
        hr = pa->mi->lpVtbl->GetParameters(pa->mi, &args);
        
        if(SUCCEEDED(hr)) {
          DPRINT("SafeArrayGetLBound");
          hr = inst->api.SafeArrayGetLBound(args, 1, &lcnt);
          
          DPRINT("SafeArrayGetUBound");
          hr = inst->api.SafeArrayGetUBound(args, 1, &ucnt);
          cnt = ucnt - lcnt + 1;
          DPRINT("Number of parameters for entrypoint : %i", cnt);
          
          // does Main require string[] args?
          if(cnt != 0) {
            // create a 1 dimensional array for Main parameters
            sav = inst->api.SafeArrayCreateVector(VT_VARIANT, 0, 1);
            // if user specified their own parameters, add to string array
            if(mod->param[0] != 0) {
              ansi2unicode(inst, mod->param, buf);
              argv = inst->api.CommandLineToArgvW(buf, &argc);
              // create 1 dimensional array for strings[] args
              vtPsa.vt     = (VT_ARRAY | VT_BSTR);
              vtPsa.parray = inst->api.SafeArrayCreateVector(VT_BSTR, 0, argc);
              
              // add each string parameter
              for(i=0; i<argc; i++) {  
                DPRINT("Adding \"%ws\" as parameter %i", argv[i], (i + 1));
                inst->api.SafeArrayPutElement(vtPsa.parray, 
                    &i, inst->api.SysAllocString(argv[i]));
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
      ansi2unicode(inst, mod->cls, buf);
      cls = inst->api.SysAllocString(buf);
      if(cls == NULL) return FALSE;
      DPRINT("Class: SysAllocString(\"%ws\")", buf);
      
      ansi2unicode(inst, mod->method, buf);
      method = inst->api.SysAllocString(buf);
      DPRINT("Method: SysAllocString(\"%ws\")", buf);
      
      if(method != NULL) {
        DPRINT("Assembly::GetType_2");
        hr = pa->as->lpVtbl->GetType_2(pa->as, cls, &pa->type);
        
        if(SUCCEEDED(hr)) {
          sav = NULL;
          DPRINT("Parameters: %s", mod->param);
          
          if(mod->param[0] != 0) {
            ansi2unicode(inst, mod->param, buf);
            argv = inst->api.CommandLineToArgvW(buf, &argc);
            DPRINT("SafeArrayCreateVector(%li argument(s))", argc);
            
            sav = inst->api.SafeArrayCreateVector(VT_VARIANT, 0, argc);
          
            if(sav != NULL) {
              for(i=0; i<argc; i++) {
                DPRINT("Adding \"%ws\" as argument %i", argv[i], (i+1));
                
                V_BSTR(&arg) = inst->api.SysAllocString(argv[i]);
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
