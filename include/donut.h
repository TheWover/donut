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

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>
#include <limits.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#ifndef LOADER_H
#include "mmap.h"
#endif
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#define strcasecmp stricmp
#endif
#else
#define LINUX
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <wchar.h>
#include "pe.h"
#endif

#ifndef LOADER_H

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

#include "hash.h"        // api hashing
#include "encrypt.h"     // symmetric encryption of instance+module
#include "format.h"      // output format for loader
#include "aplib.h"       // aPLib compression for both windows + linux

#ifndef MAX_PATH
 #define MAX_PATH 260
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

#define DONUT_KEY_LEN                    16
#define DONUT_BLK_LEN                    16

#define DONUT_ERROR_OK                   0
#define DONUT_ERROR_FILE_NOT_FOUND       1
#define DONUT_ERROR_FILE_EMPTY           2
#define DONUT_ERROR_FILE_ACCESS          3
#define DONUT_ERROR_FILE_INVALID         4
#define DONUT_ERROR_NET_PARAMS           5
#define DONUT_ERROR_NO_MEMORY            6
#define DONUT_ERROR_INVALID_ARCH         7
#define DONUT_ERROR_INVALID_URL          8
#define DONUT_ERROR_URL_LENGTH           9
#define DONUT_ERROR_INVALID_PARAMETER   10
#define DONUT_ERROR_RANDOM              11
#define DONUT_ERROR_DLL_FUNCTION        12
#define DONUT_ERROR_ARCH_MISMATCH       13
#define DONUT_ERROR_DLL_PARAM           14
#define DONUT_ERROR_BYPASS_INVALID      15
#define DONUT_ERROR_INVALID_FORMAT      16
#define DONUT_ERROR_INVALID_ENGINE      17
#define DONUT_ERROR_COMPRESSION         18
#define DONUT_ERROR_INVALID_ENTROPY     19
#define DONUT_ERROR_MIXED_ASSEMBLY      20
#define DONUT_ERROR_HEADERS_INVALID     21
#define DONUT_ERROR_DECOY_INVALID       22

// target architecture
#define DONUT_ARCH_ANY                  -1  // for vbs and js files
#define DONUT_ARCH_X86                   1  // x86
#define DONUT_ARCH_X64                   2  // AMD64
#define DONUT_ARCH_X84                   3  // x86 + AMD64

// module type
#define DONUT_MODULE_NET_DLL             1  // .NET DLL. Requires class and method
#define DONUT_MODULE_NET_EXE             2  // .NET EXE. Executes Main if no class and method provided
#define DONUT_MODULE_DLL                 3  // Unmanaged DLL, function is optional
#define DONUT_MODULE_EXE                 4  // Unmanaged EXE
#define DONUT_MODULE_VBS                 5  // VBScript
#define DONUT_MODULE_JS                  6  // JavaScript or JScript

// format type
#define DONUT_FORMAT_BINARY              1
#define DONUT_FORMAT_BASE64              2
#define DONUT_FORMAT_C                   3
#define DONUT_FORMAT_RUBY                4
#define DONUT_FORMAT_PYTHON              5
#define DONUT_FORMAT_POWERSHELL          6
#define DONUT_FORMAT_CSHARP              7
#define DONUT_FORMAT_HEX                 8

// compression engine
#define DONUT_COMPRESS_NONE              1
#define DONUT_COMPRESS_APLIB             2
#define DONUT_COMPRESS_LZNT1             3  // COMPRESSION_FORMAT_LZNT1
#define DONUT_COMPRESS_XPRESS            4  // COMPRESSION_FORMAT_XPRESS

// entropy level
#define DONUT_ENTROPY_NONE               1  // don't use any entropy
#define DONUT_ENTROPY_RANDOM             2  // use random names
#define DONUT_ENTROPY_DEFAULT            3  // use random names + symmetric encryption

// misc options
#define DONUT_OPT_EXIT_THREAD            1  // after the main shellcode ends, return to the caller which eventually calls RtlExitUserThread
#define DONUT_OPT_EXIT_PROCESS           2  // after the main shellcode ends, call RtlExitUserProcess to terminate host process

// instance type
#define DONUT_INSTANCE_EMBED             1  // Module is embedded
#define DONUT_INSTANCE_HTTP              2  // Module is downloaded from remote HTTP/HTTPS server
#define DONUT_INSTANCE_DNS               3  // Module is downloaded from remote DNS server

// AMSI/WLDP level
#define DONUT_BYPASS_NONE                1  // Disables bypassing AMSI/WDLP
#define DONUT_BYPASS_ABORT               2  // If bypassing AMSI/WLDP fails, the loader stops running
#define DONUT_BYPASS_CONTINUE            3  // If bypassing AMSI/WLDP fails, the loader continues running

// Preserve PE headers options
#define DONUT_HEADERS_OVERWRITE          1  // Overwrite PE headers
#define DONUT_HEADERS_KEEP               2  // Preserve PE headers

#define DONUT_MAX_NAME                 256  // maximum length of string for domain, class, method and parameter names
#define DONUT_MAX_DLL                    8  // maximum number of DLL supported by instance
#define DONUT_MAX_MODNAME                8
#define DONUT_SIG_LEN                    8  // 64-bit string to verify decryption ok
#define DONUT_VER_LEN                   32
#define DONUT_DOMAIN_LEN                 8

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
#define USER32_DLL   "user32.dll"
#define SHLWAPI_DLL  "shlwapi.dll"
#define SHELL32_DLL  "shell32.dll"

// Per the ECMA spec, the section data looks like this:
// taken from https://github.com/dotnet/coreclr/
//
typedef struct tagMDSTORAGESIGNATURE {
    ULONG       lSignature;             // "Magic" signature.
    USHORT      iMajorVer;              // Major file version.
    USHORT      iMinorVer;              // Minor file version.
    ULONG       iExtraData;             // Offset to next structure of information 
    ULONG       iVersionString;         // Length of version string
    BYTE        pVersion[0];            // Version string
} MDSTORAGESIGNATURE, *PMDSTORAGESIGNATURE;

// 
typedef struct _file_info_t {
    int      fd;
    uint32_t len, zlen;
    uint8_t  *data, *zdata;
    
    // the following are set for unmanaged or .NET PE/DLL files
    int      type;    
    int      arch;
    char     ver[DONUT_VER_LEN];       
} file_info;

typedef struct _API_IMPORT {
    const char *module;
    const char *name;
} API_IMPORT, *PAPI_IMPORT;

typedef struct _DONUT_CRYPT {
    uint8_t  mk[DONUT_KEY_LEN];   // master key
    uint8_t  ctr[DONUT_BLK_LEN];  // counter + nonce
} DONUT_CRYPT, *PDONUT_CRYPT;

// everything required for a module goes in the following structure
typedef struct _DONUT_MODULE {
    int      type;                            // EXE/DLL/JS/VBS
    int      thread;                          // run entrypoint of unmanaged EXE as a thread
    int      compress;                        // indicates engine used for compression
    
    char     runtime[DONUT_MAX_NAME];         // runtime version for .NET EXE/DLL
    char     domain[DONUT_MAX_NAME];          // domain name to use for .NET EXE/DLL
    char     cls[DONUT_MAX_NAME];             // name of class and optional namespace for .NET EXE/DLL
    char     method[DONUT_MAX_NAME];          // name of method to invoke for .NET DLL or api for unmanaged DLL
    
    char     args[DONUT_MAX_NAME];            // string arguments for both managed and unmanaged DLL/EXE
    int      unicode;                         // convert param to unicode for unmanaged DLL function
    
    char     sig[DONUT_SIG_LEN];              // string to verify decryption
    uint64_t mac;                             // hash of sig, to verify decryption was ok
    
    uint32_t zlen;                            // compressed size of EXE/DLL/JS/VBS file
    uint32_t len;                             // real size of EXE/DLL/JS/VBS file
    uint8_t  data[4];                         // data of EXE/DLL/JS/VBS file
} DONUT_MODULE, *PDONUT_MODULE;

// everything required for an instance goes into the following structure
typedef struct _DONUT_INSTANCE {
    uint32_t    len;                          // total size of instance
    DONUT_CRYPT key;                          // decrypts instance if encryption enabled

    uint64_t    iv;                           // the 64-bit initial value for maru hash

    union {
      uint64_t  hash[64];                     // holds up to 64 api hashes
      void     *addr[64];                     // holds up to 64 api addresses
      // include prototypes only if header included from loader.h
      #ifdef LOADER_H
      struct {
        // imports from kernel32.dll or kernelbase.dll
        LoadLibraryA_t                   LoadLibraryA;
        GetProcAddress_t                 GetProcAddress;        
        GetModuleHandleA_t               GetModuleHandleA;  
        Sleep_t                          Sleep;
        MultiByteToWideChar_t            MultiByteToWideChar;
        GetUserDefaultLCID_t             GetUserDefaultLCID;
        CreateThread_t                   CreateThread;
        CreateFileA_t                    CreateFileA;
        GetCurrentThread_t               GetCurrentThread;
        GetCurrentProcess_t              GetCurrentProcess;
        GetCommandLineA_t                GetCommandLineA;
        GetCommandLineW_t                GetCommandLineW;
        HeapAlloc_t                      HeapAlloc;
        HeapReAlloc_t                    HeapReAlloc;
        GetProcessHeap_t                 GetProcessHeap;
        HeapFree_t                       HeapFree;
        GetLastError_t                   GetLastError;
        
        // imports from shell32.dll
        CommandLineToArgvW_t             CommandLineToArgvW;
        
        // imports from oleaut32.dll
        SafeArrayCreate_t                SafeArrayCreate;          
        SafeArrayCreateVector_t          SafeArrayCreateVector;    
        SafeArrayPutElement_t            SafeArrayPutElement;      
        SafeArrayDestroy_t               SafeArrayDestroy;
        SafeArrayGetLBound_t             SafeArrayGetLBound;        
        SafeArrayGetUBound_t             SafeArrayGetUBound;        
        SysAllocString_t                 SysAllocString;           
        SysFreeString_t                  SysFreeString;
        LoadTypeLib_t                    LoadTypeLib;
        
        // imports from wininet.dll
        InternetCrackUrl_t               InternetCrackUrl;         
        InternetOpen_t                   InternetOpen;             
        InternetConnect_t                InternetConnect;          
        InternetSetOption_t              InternetSetOption;        
        InternetReadFile_t               InternetReadFile;         
        InternetCloseHandle_t            InternetCloseHandle;      
        InternetQueryDataAvailable_t     InternetQueryDataAvailable;      
        HttpOpenRequest_t                HttpOpenRequest;          
        HttpSendRequest_t                HttpSendRequest;          
        HttpQueryInfo_t                  HttpQueryInfo;
        
        // imports from mscoree.dll
        CorBindToRuntime_t               CorBindToRuntime;
        CLRCreateInstance_t              CLRCreateInstance;
        
        // imports from ole32.dll
        CoInitializeEx_t                 CoInitializeEx;
        CoCreateInstance_t               CoCreateInstance;
        CoUninitialize_t                 CoUninitialize;
        
        // imports from ntdll.dll
        RtlEqualUnicodeString_t          RtlEqualUnicodeString;
        RtlEqualString_t                 RtlEqualString;
        RtlUnicodeStringToAnsiString_t   RtlUnicodeStringToAnsiString;
        RtlInitUnicodeString_t           RtlInitUnicodeString;
        RtlExitUserThread_t              RtlExitUserThread;
        RtlExitUserProcess_t             RtlExitUserProcess;
        RtlCreateUnicodeString_t         RtlCreateUnicodeString;
        RtlGetCompressionWorkSpaceSize_t RtlGetCompressionWorkSpaceSize;
        RtlDecompressBuffer_t            RtlDecompressBuffer;
        AddVectoredExceptionHandler_t    AddVectoredExceptionHandler;
        RemoveVectoredExceptionHandler_t RemoveVectoredExceptionHandler;
       // RtlFreeUnicodeString_t         RtlFreeUnicodeString;
       // RtlFreeString_t                RtlFreeString;
      };
      #endif
    } api;
    
    int         exit_opt;                     // 1 to call RtlExitUserProcess and terminate the host process
    int         entropy;                      // indicates entropy level
    uint64_t    oep;                          // original entrypoint
    
    // everything from here is encrypted
    int         api_cnt;                      // the 64-bit hashes of API required for instance to work
    char        dll_names[DONUT_MAX_NAME];    // a list of DLL strings to load, separated by semi-colon
    
    char        dataname[8];                  // ".data"
    char        kernelbase[12];               // "kernelbase"
    char        amsi[8];                      // "amsi"
    char        clr[4];                       // "clr"
    char        wldp[8];                      // "wldp"
    char        ntdll[8];                     // "ntdll"
    
    char        cmd_syms[DONUT_MAX_NAME];     // symbols related to command line
    char        exit_api[DONUT_MAX_NAME];     // exit-related API
    
    int         bypass;                       // indicates behaviour of byassing AMSI/WLDP/ETW
    int         headers;                      // indicates whether to overwrite PE headers
    char        wldpQuery[32];                // WldpQueryDynamicCodeTrust
    char        wldpIsApproved[32];           // WldpIsClassInApprovedList
    char        amsiInit[16];                 // AmsiInitialize
    char        amsiScanBuf[16];              // AmsiScanBuffer
    char        amsiScanStr[16];              // AmsiScanString
    char        etwEventWrite[16];            // EtwEventWrite
    char        etwEventUnregister[20];       // EtwEventUnregister
    
    char        wscript[8];                   // WScript
    char        wscript_exe[12];              // wscript.exe

    wchar_t     decoy[MAX_PATH];            // path of decoy module

    GUID        xIID_IUnknown;
    GUID        xIID_IDispatch;
    
    // GUID required to load .NET assemblies
    GUID        xCLSID_CLRMetaHost;
    GUID        xIID_ICLRMetaHost;  
    GUID        xIID_ICLRRuntimeInfo;
    GUID        xCLSID_CorRuntimeHost;
    GUID        xIID_ICorRuntimeHost;
    GUID        xIID_AppDomain;
    
    // GUID required to run VBS and JS files
    GUID        xCLSID_ScriptLanguage;         // vbs or js
    GUID        xIID_IHost;                    // wscript object
    GUID        xIID_IActiveScript;            // engine
    GUID        xIID_IActiveScriptSite;        // implementation
    GUID        xIID_IActiveScriptSiteWindow;  // basic GUI stuff
    GUID        xIID_IActiveScriptParse32;     // parser
    GUID        xIID_IActiveScriptParse64;
    
    int         type;                       // DONUT_INSTANCE_EMBED, DONUT_INSTANCE_HTTP 
    char        server[DONUT_MAX_NAME];     // staging server hosting donut module
    char        username[DONUT_MAX_NAME];   // username for web server
    char        password[DONUT_MAX_NAME];   // password for web server
    char        http_req[8];                // just a buffer for "GET"

    uint8_t     sig[DONUT_MAX_NAME];        // string to hash
    uint64_t    mac;                        // to verify decryption ok
    
    DONUT_CRYPT mod_key;       // used to decrypt module
    uint64_t    mod_len;       // total size of module
    
    union {
      PDONUT_MODULE p;         // Memory allocated for module downloaded via DNS or HTTP
      DONUT_MODULE  x;         // Module is embedded
    } module;
} DONUT_INSTANCE, *PDONUT_INSTANCE;

typedef struct _DONUT_CONFIG {
    uint32_t        len, zlen;                // original length of input file and compressed length
    // general / misc options for loader
    int             arch;                     // target architecture
    int             bypass;                   // bypass option for AMSI/WDLP
    int             headers;                  // preserve PE headers option
    int             compress;                 // engine to use when compressing file via RtlCompressBuffer
    int             entropy;                  // entropy/encryption level
    int             format;                   // output format for loader
    int             exit_opt;                 // return to caller or invoke RtlExitUserProcess to terminate the host process
    int             thread;                   // run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API
    uint64_t        oep;                      // original entrypoint of target host file
    
    // files in/out
    char            input[DONUT_MAX_NAME];    // name of input file to read and load in-memory
    char            output[DONUT_MAX_NAME];   // name of output file to save loader
    
    // .NET stuff
    char            runtime[DONUT_MAX_NAME];  // runtime version to use for CLR
    char            domain[DONUT_MAX_NAME];   // name of domain to create for .NET DLL/EXE
    char            cls[DONUT_MAX_NAME];      // name of class with optional namespace for .NET DLL
    char            method[DONUT_MAX_NAME];   // name of method or DLL function to invoke for .NET DLL and unmanaged DLL
    
    // command line for DLL/EXE
    char            args[DONUT_MAX_NAME];    // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
    int             unicode;                  // param is passed to DLL function without converting to unicode

    // module overloading stuff
    char            decoy[2056];                  // path of decoy module
    
    // HTTP/DNS staging information
    char            server[DONUT_MAX_NAME];   // points to root path of where module will be stored on remote HTTP server or DNS server
    char            auth[DONUT_MAX_NAME];     // username and password for web server
    char            modname[DONUT_MAX_NAME];  // name of module written to disk for http stager
    
    // DONUT_MODULE
    int             mod_type;                 // VBS/JS/DLL/EXE
    int             mod_len;                  // size of DONUT_MODULE
    DONUT_MODULE    *mod;                     // points to DONUT_MODULE
    
    // DONUT_INSTANCE
    int             inst_type;                // DONUT_INSTANCE_EMBED or DONUT_INSTANCE_HTTP
    int             inst_len;                 // size of DONUT_INSTANCE
    DONUT_INSTANCE  *inst;                    // points to DONUT_INSTANCE
    
    // shellcode generated from configuration
    int             pic_len;                  // size of loader/shellcode
    void*           pic;                      // points to loader/shellcode
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
EXPORT_FUNC const char* DonutError(int);

#ifdef __cplusplus
}
#endif

#endif
