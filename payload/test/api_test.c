
#define UNICODE
#include <windows.h>

#include "donut.h"
#pragma comment(lib, "user32.lib")

void call_api(FARPROC api, int param_cnt, WCHAR param[DONUT_MAX_PARAM][DONUT_MAX_NAME]);
typedef VOID (WINAPI *_DonutApiW)(PWCHAR,PWCHAR,PWCHAR,PWCHAR);

int main(void) {
    HMODULE    m;
    _DonutApiW DonutApiW;
    WCHAR      param[4][DONUT_MAX_NAME]={L"arg0",L"arg1",L"arg2",L"arg3"};
    
    WCHAR msg[4096];
    
    _snwprintf(msg, ARRAYSIZE(msg), 
      L"param[0] : %ws\r"
      L"param[1] : %ws\r"
      L"param[2] : %ws\r"
      L"param[3] : %ws\r", 
      param[0], param[1], param[2], param[3]);
      
    MessageBox(NULL, msg, L"Donut Test", MB_OK);
    
    m = LoadLibrary(L"call_api_dll.dll");
    
    if(m != NULL) {
      DonutApiW = (_DonutApiW)GetProcAddress(m, "DonutApiW");
      if(DonutApiW != NULL) {
        call_api((FARPROC)DonutApiW, 4, param);
      }
    }
    return 0;
}

