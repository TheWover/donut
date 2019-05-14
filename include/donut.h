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

#ifndef DONUT_H
#define DONUT_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif
#else
#define LINUX
#include <unistd.h>
#include <sys/types.h>
#include "pe.h"
#endif

#ifndef PAYLOAD_H

#if defined(DEBUG)
 #define DPRINT(...) { \
   fprintf(stderr, "DEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
   fprintf(stderr, "\n"); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#endif

#if !defined(NOCRYPTO)
#include "hash.h"        // api hashing
#include "encrypt.h"     // symmetric encryption of instance+module
#endif

#if !defined(WINDOWS)
#define strnicmp(x,y,z) strncasecmp(x,y,z)
typedef uint64_t ULONG64, *PULONG64;
typedef uint32_t DWORD, *PDWORD;
typedef uint16_t WORD, *PWORD;
typedef uint8_t  BYTE, *PBYTE;

typedef char     CHAR, *PCHAR;
typedef size_t SIZE_T;

typedef struct _GUID {
  DWORD Data1;
  WORD  Data2;
  WORD  Data3;
  BYTE  Data4[8];
} GUID;
#endif

#define DONUT_ERROR_SUCCESS             0
#define DONUT_ERROR_ASSEMBLY_NOT_FOUND  1
#define DONUT_ERROR_ASSEMBLY_EMPTY      2
#define DONUT_ERROR_ASSEMBLY_ACCESS     3
#define DONUT_ERROR_ASSEMBLY_INVALID    4
#define DONUT_ERROR_ASSEMBLY_PARAMS     5
#define DONUT_ERROR_NO_MEMORY           6
#define DONUT_ERROR_INVALID_ARCH        7
#define DONUT_ERROR_INVALID_URL         8
#define DONUT_ERROR_URL_LENGTH          9
#define DONUT_ERROR_INVALID_PARAMETER  10
#define DONUT_ERROR_RANDOM             11

// don't change values below
#define DONUT_KEY_LEN                  CIPHER_KEY_LEN
#define DONUT_BLK_LEN                  CIPHER_BLK_LEN

// target architecture
#define DONUT_ARCH_X86                 0  // x86
#define DONUT_ARCH_X64                 1  // amd64

// module type
#define DONUT_MODULE_DLL               0  // requires class and method
#define DONUT_MODULE_EXE               1  // executes Main if no class and method provided

// instance type
#define DONUT_INSTANCE_PIC             0  // self-contained
#define DONUT_INSTANCE_URL             1  // download from remote server

// apparently C# can support 2^16 or 65,536 parameters
// we support up to eight for now :)
#define DONUT_MAX_PARAM     8        // maximum number of parameters passed to method
#define DONUT_MAX_NAME    256        // maximum length of string for domain, class, method and parameter names
#define DONUT_MAX_DLL       8        // maximum number of DLL supported by instance
#define DONUT_MAX_URL     256
#define DONUT_MAX_MODNAME   8

#define DONUT_RUNTIME_NET2 "v2.0.50727"
#define DONUT_RUNTIME_NET4 "v4.0.30319"

#define NTDLL_DLL    "ntdll.dll"
#define KERNEL32_DLL "kernel32.dll"
#define ADVAPI32_DLL "advapi32.dll"
#define CRYPT32_DLL  "crypt32.dll"
#define MSCOREE_DLL  "mscoree.dll"
#define OLE32_DLL    "ole32.dll"
#define OLEAUT32_DLL "oleaut32.dll"
#define WININET_DLL  "wininet.dll"
#define COMBASE_DLL  "combase.dll"

typedef struct _API_IMPORT {
    const char *module;
    const char *name;
} API_IMPORT, *PAPI_IMPORT;

typedef struct _DONUT_CRYPT {
    BYTE    mk[DONUT_KEY_LEN];   // master key
    BYTE    ctr[DONUT_BLK_LEN];  // counter + nonce
} DONUT_CRYPT, *PDONUT_CRYPT;
    
// everything required for a module goes into the following structure
typedef struct _DONUT_MODULE {
    DWORD   type;                                   // DONUT_MODULE_EXE or DONUT_MODULE_DLL
    WCHAR   runtime[DONUT_MAX_NAME];                // runtime version
    WCHAR   domain[DONUT_MAX_NAME];                 // domain name to use
    WCHAR   cls[DONUT_MAX_NAME];                    // name of class and optional namespace
    WCHAR   method[DONUT_MAX_NAME];                 // name of method to invoke
    DWORD   param_cnt;                              // number of parameters
    WCHAR   param[DONUT_MAX_PARAM][DONUT_MAX_NAME]; // string parameters
    CHAR    sig[DONUT_MAX_NAME];                    // random string to verify decryption
    ULONG64 mac;                                    // to verify decryption was ok
    DWORD   len;                                    // size of .NET assembly
    BYTE    data[4];                                // .NET assembly file
} DONUT_MODULE, *PDONUT_MODULE;

// everything required for an instance goes into the following structure
typedef struct _DONUT_INSTANCE {
    uint32_t    len;                          // total size of instance
    DONUT_CRYPT key;                          // decrypts instance
    // everything from here is encrypted
    
    int         dll_cnt;                      // the number of DLL to load before resolving API
    char        dll_name[DONUT_MAX_DLL][32];  // a list of DLL strings to load
    uint64_t    iv;                           // the 64-bit initial value for maru hash
    int         api_cnt;                      // the 64-bit hashes of API required for instance to work

    union {
      uint64_t  hash[48];                     // holds up to 48 api hashes
      void     *addr[48];                     // holds up to 48 api addresses
      // include prototypes only if header included from payload.h
      #ifdef PAYLOAD_H
      struct {
        // imports from kernel32.dll
        LoadLibraryA_t             LoadLibraryA;
        GetProcAddress_t           GetProcAddress;
        VirtualAlloc_t             VirtualAlloc;             
        VirtualFree_t              VirtualFree;  
        
        // imports from oleaut32.dll
        SafeArrayCreate_t          SafeArrayCreate;          
        SafeArrayCreateVector_t    SafeArrayCreateVector;    
        SafeArrayPutElement_t      SafeArrayPutElement;      
        SafeArrayDestroy_t         SafeArrayDestroy;         
        SysAllocString_t           SysAllocString;           
        SysFreeString_t            SysFreeString;            
        
        // imports from wininet.dll
        InternetCrackUrl_t         InternetCrackUrl;         
        InternetOpen_t             InternetOpen;             
        InternetConnect_t          InternetConnect;          
        InternetSetOption_t        InternetSetOption;        
        InternetReadFile_t         InternetReadFile;         
        InternetCloseHandle_t      InternetCloseHandle;      
        HttpOpenRequest_t          HttpOpenRequest;          
        HttpSendRequest_t          HttpSendRequest;          
        HttpQueryInfo_t            HttpQueryInfo;
        
        // imports from mscoree.dll
        CorBindToRuntime_t         CorBindToRuntime;
        CLRCreateInstance_t        CLRCreateInstance;
      };
      #endif
    } api;
    
    // GUID required to load .NET assembly
    GUID xCLSID_CLRMetaHost;
    GUID xIID_ICLRMetaHost;  
    GUID xIID_ICLRRuntimeInfo;
    GUID xCLSID_CorRuntimeHost;
    GUID xIID_ICorRuntimeHost;
    GUID xIID_AppDomain;
    
    int type;  // DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL 
    
    struct {
      char url[DONUT_MAX_URL]; // staging server hosting donut module
      char req[16];            // just a buffer for "GET"
    } http;

    uint8_t     sig[DONUT_MAX_NAME];          // string to hash
    uint64_t    mac;                          // to verify decryption ok
    
    DONUT_CRYPT mod_key;       // used to decrypt module
    uint64_t    mod_len;       // total size of module
    
    union {
      PDONUT_MODULE p;         // for URL
      DONUT_MODULE  x;         // for PIC
    } module;
} DONUT_INSTANCE, *PDONUT_INSTANCE;
    
typedef struct _DONUT_CONFIG {
    int             arch;                    // target architecture for shellcode
    
    char            domain[DONUT_MAX_NAME];  // name of domain to create for assembly
    char            *cls;                    // name of class and optional namespace
    char            *method;                 // name of method to execute
    char            *param;                  // string parameters passed to method, separated by comma or semi-colon
    char            *file;                   // assembly to create module from
    
    char            url[DONUT_MAX_URL];      // points to root path of where module will be on remote http server
    char            runtime[DONUT_MAX_NAME]; // runtime version to use. v4.0.30319 is used by default
    char            modname[DONUT_MAX_NAME]; // name of module written to disk
    
    int             mod_type;                // DONUT_MODULE_DLL or DONUT_MODULE_EXE
    int             mod_len;                 // size of DONUT_MODULE
    PDONUT_MODULE   mod;                     // points to donut module
    
    int             inst_type;               // DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL
    int             inst_len;                // size of DONUT_INSTANCE
    PDONUT_INSTANCE inst;                    // points to donut instance
    
    int             pic_len;                 // size of shellcode
    void*           pic;                     // points to PIC/shellcode
} DONUT_CONFIG, *PDONUT_CONFIG;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DLL
#define EXPORT_FUNC __declspec(dllexport)
#else
#define EXPORT_FUNC
#endif

// public functions
EXPORT_FUNC int DonutCreate(PDONUT_CONFIG);
EXPORT_FUNC int DonutDelete(PDONUT_CONFIG);

#ifdef __cplusplus
}
#endif

#endif
