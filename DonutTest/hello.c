#define UNICODE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <windows.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")

__declspec(dllexport)
VOID WINAPI RunProcess(PWCHAR proc1, PWCHAR proc2) {
    PROCESS_INFORMATION pi;
    STARTUPINFO         si;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    CreateProcess(NULL, proc1, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    CreateProcess(NULL, proc2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

__declspec(dllexport)
VOID WINAPI DonutApiW(PWCHAR arg0, PWCHAR arg1, PWCHAR arg2, PWCHAR arg3) {
    WCHAR msg[4096];
    
    _snwprintf(msg, ARRAYSIZE(msg), 
      L"param[0] : %ws\r"
      L"param[1] : %ws\r"
      L"param[2] : %ws\r"
      L"param[3] : %ws\r", 
      arg0, arg1, arg2, arg3);
      
    MessageBox(NULL, msg, L"Donut Test", MB_OK);
}

__declspec(dllexport)
BOOL WINAPI DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      MessageBox(NULL, L"Hello, World!", L"Hello, World!", 0);
      break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
