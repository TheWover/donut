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
#include <stdio.h>
#include <tlhelp32.h>

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

BOOL injectPIC(LPVOID code, DWORD codeLen) {
    LPVOID  cs;
    DWORD   t;
    
    // 1. allocate read-write (RW) memory for payload
    printf("  [ allocating memory for payload.\n");
    cs=VirtualAlloc(NULL, codeLen, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (cs == NULL) {
      printf("  [ unable to allocate memory.\n");
      return FALSE;
    }
    
    printf("  [ writing code to 0x%p.\n", cs);
    // 2. copy the payload to remote memory
    memcpy(cs, code, codeLen);
    //WriteProcessMemory(hp, cs, code, codeLen, &wr); 
    VirtualProtect(cs, codeLen, PAGE_EXECUTE_READ, &t);
    
    printf("  [ press any key to continue.\n");
    getchar();
    
    // 3. execute payload in remote process
    printf("  [ jumping to shellcode.\n");
    void (*function)();
    function = (void (*)())cs;
    function(); // invoke the shellcode and block until complete

    printf("  [ shellcode completed execution.\n");
    printf("  [ press any key to continue.\n");
    getchar();

    return TRUE;
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

    if (argc != 2){
      printf("\n  [ usage: inject <loader.bin>\n");
      return 0;
    }
    
    // pic
    code_len = getdata(argv[1], &code);
    if(code_len == 0) {
      printf("  [ unable to read payload.\n");
      return 0;
    }
    injectPIC(code, code_len);
    free(code);
    return 0;
}
