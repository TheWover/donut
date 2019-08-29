
// code to implement hooking ProcessExit from unmanaged code
// https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal?view=netframework-4.8
//
#include <windows.h>
#include <oleauto.h>
#include <mscoree.h>
#include <comdef.h>
#include <propvarutil.h>
#include <metahost.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>

#import "mscorlib.tlb" raw_interfaces_only
#import "shdocvw.dll"

#pragma comment(lib, "mscoree.lib")

void my_function(void *evt) {
  printf("Received event\n");
}

void rundotnet(void *code, size_t len) {
    HRESULT                     hr;
    ICLRMetaHost               *icmh;
    ICLRRuntimeInfo            *icri;
    ICorRuntimeHost            *icrh;
    IUnknownPtr                 iu;
    mscorlib::_AppDomainPtr     ad;
    mscorlib::_AssemblyPtr      as, as1, as2;
    mscorlib::_MethodInfoPtr    mi;
    mscorlib::_EventInfoPtr     nfo;
    mscorlib::_TypePtr          evt, ptr, type, mars, del, _void;
    mscorlib::_DelegatePtr      delegate;
    mscorlib::_ParameterInfoPtr param;
    mscorlib::_EventHandlerPtr  handler;
    VARIANT                     v1, v2, v_ptr, v_type, ret;
    SAFEARRAY                  *sa, *sa2, *sav;
    SAFEARRAYBOUND              sab;
    BOOL                        loadable;
    LONG                        idx;
    
    printf("CoCreateInstance(ICorRuntimeHost).\n");

    hr = CLRCreateInstance(
       CLSID_CLRMetaHost, 
       IID_ICLRMetaHost, 
       (LPVOID*)&icmh);
      
    if(SUCCEEDED(hr)) {
      printf("ICLRMetaHost::GetRuntime\n");
      
      hr = icmh->GetRuntime(
          L"v4.0.30319", 
          IID_ICLRRuntimeInfo, (LPVOID*)&icri);
        
      if(SUCCEEDED(hr)) {
        printf("ICLRRuntimeInfo::IsLoadable\n");
        hr = icri->IsLoadable(&loadable);
        
        if(SUCCEEDED(hr) && loadable) {
          printf("ICLRRuntimeInfo::GetInterface\n");
          
          hr = icri->GetInterface( 
              CLSID_CorRuntimeHost, 
              IID_ICorRuntimeHost, 
              (LPVOID*)&icrh);
        } else return;
      } else return;
    } else return;
    
    printf("ICorRuntimeHost::Start()\n");
    hr = icrh->Start();
    if(SUCCEEDED(hr)) {
      printf("ICorRuntimeHost::GetDefaultDomain()\n");
      hr = icrh->GetDefaultDomain(&iu);
      if(SUCCEEDED(hr)) {
        printf("IUnknown::QueryInterface()\n");
        hr = iu->QueryInterface(IID_PPV_ARGS(&ad));
        if(SUCCEEDED(hr)) { 
          BSTR str1 = SysAllocString(L"System.Runtime.InteropServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
          
          BSTR str2 = SysAllocString(L"mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089");
          
          hr = ad->Load_2(str1, &as1); // load interop services
          hr = ad->Load_2(str2, &as2); // load mscorlib
          
          // SAFEARRAY(_Type*)
          sav = SafeArrayCreateVector(VT_UNKNOWN, 0, 2);
          
          // add System.IntPtr
          BSTR str4 = SysAllocString(L"System.IntPtr");
          as2->GetType_2(str4, &ptr);
          //DumpMethods(ptr);
          idx = 0;
          hr = SafeArrayPutElement(sav, &idx, ptr);
          
          // add System.Type
          BSTR str5 = SysAllocString(L"System.Type");
          as2->GetType_2(str5, &type);
          idx = 1;
          SafeArrayPutElement(sav, &idx, type);

          BSTR str6 = SysAllocString(L"GetDelegateForFunctionPointer");
          BSTR str3 = SysAllocString(L"System.Runtime.InteropServices.Marshal");
          hr = as1->GetType_2(str3, &mars);

          hr = mars->GetMethod(str6,
            (mscorlib::BindingFlags)
            (mscorlib::BindingFlags_Static | mscorlib::BindingFlags_Public), 
            NULL, // Binder
            sav,  // SAFEARRAY(_Type*)
            NULL, // Modifiers
            &mi); // MethodInfo
            
          printf("\nGetMethod(GetDelegateForFunctionPointer) HRESULT : %08lx MethodInfoPtr : %p\n", hr, (void*)mi);

          BSTR str9 = SysAllocString(L"ProcessExit");
          BSTR strA = SysAllocString(L"System.AppDomain");
          
          hr = as2->GetType_2(strA, &evt);
          printf("GetType_2(System.AppDomain) HRESULT : %08lx TypePtr : %p\n", hr, (void*)evt);
          
          hr = evt->GetEvent(str9, 
              (mscorlib::BindingFlags)
              (mscorlib::BindingFlags_Instance | mscorlib::BindingFlags_Public),
              &nfo);
          
          printf("GetEvent(ProcessExit) HRESULT : %08lx EventInfoPtr : %p\n", hr, (void*)nfo);
          
          hr = nfo->get_EventHandlerType(&evt);
          printf("EventHandlerType(ProcessExit) : HRESULT : %08lx TypePtr : %p\n", hr, (void*)evt);
          
          BSTR type_name, base_name;
          mscorlib::_TypePtr base_type, ref_type;
          
          evt->get_name(&type_name);
          evt->get_BaseType(&base_type);
          base_type->get_name(&base_name);
          
          wprintf(L"Event Type : %s\nBase Type  : %s\n", type_name, base_name);
          
          printf("my_function = %p\n", (void*)my_function);
          
          // SAFEARRAY(VARIANT)
          sav = SafeArrayCreateVector(VT_VARIANT, 0, 2);
          
          VariantClear(&v_ptr);
          V_BYREF(&v_ptr) = (PVOID)my_function;
          V_VT(&v_ptr)    = VT_INT;
          
          idx = 0;
          SafeArrayPutElement(sav, &idx, &v_ptr);
          
          BSTR strZ = SysAllocString(L"System.MultiDelegate");
          hr = as2->GetType_2(strZ, &type);
          printf("System.Delegate = %lx, %p\n", hr, (void*)type);
          
          idx = 1;
          V_VT(&v_type) = VT_UNKNOWN;
          V_UNKNOWN(&v_type) = type;
          SafeArrayPutElement(sav, &idx, &type);
          
          v1.vt    = VT_EMPTY;
          VariantClear(&ret);
          
          printf("Calling GetDelegateForFunctionPointer\n");
          hr = mi->Invoke_3(
                v1,
                sav,      // arguments to method
                &ret);    // return value from method

          printf("Invoke_3(GetDelegateForFunctionPointer) HRESULT : %08lx : %x : %p\n", hr, V_VT(&ret), V_BYREF(&ret));
                    
          /**if(hr != S_OK) {
            printf("Failed to obtain delegate\n");
            return;
          }*/

          printf("Delegate : %p\n", ret.punkVal);
          
          hr = ret.punkVal->QueryInterface(IID_IUnknown, (void**)&handler);
          printf("HRESULT : %08lx : %p\n", hr, (void*)handler);
          
          hr = ad->add_ProcessExit(handler);
          printf("HRESULT : %08lx\n", hr);
          
          sab.lLbound   = 0;
          sab.cElements = len;
          printf("SafeArrayCreate()\n");
          sa = SafeArrayCreate(VT_UI1, 1, &sab);
          
          if(sa != NULL) {
            CopyMemory(sa->pvData, code, len);
            printf("AppDomain::Load_3()\n");
            hr = ad->Load_3(sa, &as);
            if(SUCCEEDED(hr)) {
              printf("Assembly::get_EntryPoint()\n");
              hr = as->get_EntryPoint(&mi);
              if(SUCCEEDED(hr)) {
                v1.vt    = VT_NULL;
                v1.plVal = NULL;
                printf("MethodInfo::Invoke_3()\n");
                hr = mi->Invoke_3(v1, NULL, &v2);
                mi->Release();
              }
              as->Release();
            }
            SafeArrayDestroy(sa);
          }
          ad->Release();
        }
        iu->Release();
      }
      icrh->Stop();
    }
    icrh->Release();
}

int main(int argc, char *argv[])
{
    void *mem;
    struct stat fs;
    FILE *fd;
    
    if(argc != 2) {
      printf("usage: rundotnet <.NET assembly>\n");
      return 0;
    }
    
    // 1. get the size of file
    stat(argv[1], &fs);
    
    if(fs.st_size == 0) {
      printf("file is empty.\n");
      return 0;
    }
    
    // 2. try open assembly
    fd = fopen(argv[1], "rb");
    if(fd == NULL) {
      printf("unable to open \"%s\".\n", argv[1]);
      return 0;
    }
    // 3. allocate memory 
    mem = malloc(fs.st_size);
    if(mem != NULL) {
      // 4. read file into memory
      fread(mem, 1, fs.st_size, fd);
      // 5. run the program from memory
      rundotnet(mem, fs.st_size);
      // 6. free memory
      free(mem);
    }
    // 7. close assembly
    fclose(fd);
    
    return 0;
}