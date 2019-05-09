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

#include <windows.h>
#include <oleauto.h>
#include <mscoree.h>
#include <comdef.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>

#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only

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
    
    printf("CorBindToRuntime(ICorRuntimeHost).\n");    
    hr = CorBindToRuntime(
      NULL,  // load latest runtime version available
      NULL,  // load workstation build
      CLSID_CorRuntimeHost,
      IID_ICorRuntimeHost,
      (LPVOID*)&icrh);
      
    if(FAILED(hr)) return;
    
    printf("ICorRuntimeHost::Start()\n");
    hr = icrh->Start();
    if(SUCCEEDED(hr)) {
      printf("ICorRuntimeHost::GetDefaultDomain()\n");
      hr = icrh->GetDefaultDomain(&iu);
      if(SUCCEEDED(hr)) {
        printf("IUnknown::QueryInterface()\n");
        hr = iu->QueryInterface(IID_PPV_ARGS(&ad));
        if(SUCCEEDED(hr)) {
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
