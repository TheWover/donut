



#include <windows.h>
#include <oleauto.h>
#include <metahost.h>
#include <mscoree.h>
#include <comdef.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#pragma comment(lib, "mscoree.lib")

#import "mscorlib.tlb" raw_interfaces_only				\
    high_property_prefixes("_get","_put","_putref")		\
rename("ReportEvent", "InteropServices_ReportEvent")

void rundotnet(void *code, size_t len) {
    HRESULT                  hr;
    ICorRuntimeHost          *icrh;
    IUnknownPtr              iu;
    mscorlib::_AppDomainPtr  ad;
    mscorlib::_AssemblyPtr   as;
    mscorlib::_MethodInfoPtr mi;
	  VARIANT                  v1, v2;
    SAFEARRAY                *sa;
    SAFEARRAYBOUND           sab;
    
    printf("Creating CLR host.\n");
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    
    hr = CoCreateInstance(
      CLSID_CorRuntimeHost, 
      NULL, 
      CLSCTX_ALL,
      IID_ICorRuntimeHost, 
      (LPVOID*)&icrh);
      
    if(FAILED(hr)) return;
    
    printf("Starting CLR host.\n");
    hr = icrh->Start();
    if(SUCCEEDED(hr)) {
      printf("Obtaining default domain.\n");
      hr = icrh->GetDefaultDomain(&iu);
      if(SUCCEEDED(hr)) {
        printf("Querying interface.\n");
        hr = iu->QueryInterface(IID_PPV_ARGS(&ad));
        if(SUCCEEDED(hr)) {
          sab.lLbound   = 0;
          sab.cElements = len;
          sa = SafeArrayCreate(VT_UI1, 1, &sab);
          if(sa != NULL) {
            CopyMemory(sa->pvData, code, len);
            hr = ad->Load_3(sa, &as);
            if(SUCCEEDED(hr)) {
              hr = as->get_EntryPoint(&mi);
              if(SUCCEEDED(hr)) {
                v1.vt    = VT_NULL;
                v1.plVal = NULL;
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
    
    // 1. try open assembly
    fd = fopen(argv[1], "rb");
    if(fd == NULL) {
      printf("unable to open \"%s\".\n", argv[1]);
      return 0;
    }
    // 2. get the size of file
    stat(argv[1], &fs);
    
    if(fs.st_size == 0) {
      printf("file is empty.\n");
      fclose(fd);
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
