/**
  Copyright © 2019 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef UTIL_H
#define UTIL_H

#pragma warning(disable : 4005)
#pragma warning(disable : 4311)

#define UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <dbghelp.h>

#include "../NTlib/nttpp.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winspool.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dbghelp.lib")

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

#if !defined (__GNUC__)
/**
 *
 * Returns TRUE if process token is elevated
 *
 */
BOOL IsElevated(VOID) {
    HANDLE          hToken;
    BOOL            bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD           dwSize;
      
    if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
      if (GetTokenInformation (hToken, TokenElevation, &te,
          sizeof(TOKEN_ELEVATION), &dwSize)) {
        bResult = te.TokenIsElevated;
      }
      CloseHandle(hToken);
    }
    return bResult;
}
#endif

// display error message for last error code
VOID xstrerror (PWCHAR fmt, ...){
    PWCHAR  error=NULL;
    va_list arglist;
    WCHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    _vsnwprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPWSTR)&error, 0, NULL))
    {
      wprintf(L"  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      wprintf(L"  [ %s error : %08lX\n", buffer, dwError);
    }
}

// enable or disable a privilege in current process token
BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult)return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValueW(NULL, szPrivilege, &luid);
    
    if (bResult) {
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = bEnable?SE_PRIVILEGE_ENABLED:SE_PRIVILEGE_REMOVED;

      // adjust token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
    return bResult;
}

DWORD name2pid(LPWSTR ImageName) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          dwPid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if (lstrcmpi(ImageName, pe32.szExeFile)==0) {
          dwPid = pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return dwPid;
}

PWCHAR pid2name(DWORD pid) {
    HANDLE         hSnap;
    BOOL           bResult;
    PROCESSENTRY32 pe32;
    PWCHAR         name=L"N/A";
    
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnap != INVALID_HANDLE_VALUE) {
      pe32.dwSize = sizeof(PROCESSENTRY32);
      
      bResult = Process32First(hSnap, &pe32);
      while (bResult) {
        if (pe32.th32ProcessID == pid) {
          name = pe32.szExeFile;
          break;
        }
        bResult = Process32Next(hSnap, &pe32);
      }
      CloseHandle(hSnap);
    }
    return name;
}

/**
  read a shellcode from disk into memory
*/
DWORD readpic(PWCHAR path, LPVOID *pic){
    HANDLE hf;
    DWORD  len, rd=0;
    
    // 1. open the file
    hf = CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf != INVALID_HANDLE_VALUE){
      // get file size
      len = GetFileSize(hf, 0);
      // allocate memory
      *pic = malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *pic, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

#endif