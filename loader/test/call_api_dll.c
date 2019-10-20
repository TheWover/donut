#define WIN32_LEAN_AND_MEAN
#define UNICODE

#include <windows.h>
#include "donut.h"

#pragma comment(lib, "user32.lib")

__declspec(dllexport)
VOID APIENTRY DonutApiW(PWCHAR arg0, PWCHAR arg1, PWCHAR arg2, PWCHAR arg3) {
    WCHAR msg[4096];
    
    _snwprintf(msg, ARRAYSIZE(msg), 
      L"param[0] : %s\r"
      L"param[1] : %s\r"
      L"param[2] : %s\r"
      L"param[3] : %s\r", 
      arg0, arg1, arg2, arg3);
      
    MessageBox(NULL, msg, L"Donut Test", MB_OK);
}

__declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
