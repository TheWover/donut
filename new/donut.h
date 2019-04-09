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

#if defined(_MSC_VER)

  #ifdef DLL
    #pragma warning( push ) 
    #pragma warning( disable : 4100 )
  #endif

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4255)
#pragma warning(disable : 4668)
#include <windows.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#else
  #include <openssl/pem.h>
  #include <openssl/evp.h>
  #include <openssl/rsa.h>
  #include <openssl/rand.h>
#endif

#ifndef SWAP32
  #ifdef _MSC_VER
    #define SWAP32(x) _byteswap_ulong(x)
  #else
    #define SWAP32(x) __builtin_bswap32(x)
  #endif
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#endif

#include "hash.h"        // api hashing
#include "encrypt.h"     // symmetric encryption of instance+module

#if !defined(_WIN32) && !defined(_WIN64)
typedef uint64_t ULONG64, *PULONG64;
typedef uint32_t DWORD, *PDWORD;
typedef uint16_t WORD, *PWORD;
typedef uint8_t  BYTE, *PBYTE;

typedef uint16_t WCHAR, *PWCHAR;
typedef char     CHAR, *PCHAR;

typedef void VOID;
typedef size_t SIZE_T;

typedef struct _GUID {
  DWORD Data1;
  WORD  Data2;
  WORD  Data3;
  BYTE  Data4[8];
} GUID;
#endif

#define DONUT_ERROR_SUCCESS            0
#define DONUT_ERROR_ASSEMBLY_NOT_FOUND 1
#define DONUT_ERROR_ASSEMBLY_EMPTY     2 // zero sized file
#define DONUT_ERROR_NO_MEMORY          3
#define DONUT_ERROR_NO_PRIVATE_KEY     4
#define DONUT_ERROR_NO_PUBLIC_KEY      5
#define DONUT_ERROR_DECODE_KEY         6
#define DONUT_ERROR_IMPORT_KEY         7
#define DONUT_ERROR_HASH               8
#define DONUT_ERROR_SIGN               9
#define DONUT_ERROR_PAYLOAD_MISSING   10 // not found
#define DONUT_ERROR_PAYLOAD_INVALID   11 // zero-size
#define DONUT_ERROR_PAYLOAD_ACCESS    12 // unable to open payload

// don't change values below
#define DONUT_SIG_LEN            (2048/8)   // 2048-bit signature
#define DONUT_KEY_LEN             CIPHER_KEY_LEN
#define DONUT_BLK_LEN             CIPHER_BLK_LEN
#define DONUT_PUBKEY_LEN             512

// target architecture
#define DONUT_ARCH_X86                 0
#define DONUT_ARCH_AMD64               1

// module type
#define DONUT_MODULE_DLL               0
#define DONUT_MODULE_EXE               1

// apparently C# can support 2^16 or 65,536 parameters
// we support up to eight for now :)
#define DONUT_MAX_PARAM     8        // maximum number of parameters passed to method
#define DONUT_MAX_NAME     32        // maximum length of string for class, method and parameter names
#define DONUT_MAX_DLL       8        // maximum number of DLL supported by instance
#define DONUT_MAX_URL     128
#define DONUT_MAX_RES_NAME 16

#define DONUT_RUNTIME_NET2 "v2.0.50727"
#define DONUT_RUNTIME_NET4 "v4.0.30319"

typedef enum _DONUT_INSTANCE_TYPE {
    DONUT_INSTANCE_PIC = 0,          // self-contained
    DONUT_INSTANCE_URL = 1,          // download from remote server
    DONUT_INSTANCE_DLL = 2           // load from resource section
} DONUT_INSTANCE_TYPE;

// based on imports we need, the max length of dll string is 12 bytes
// the max is set to 16 for alignmemt
#define DONUT_MAX_DLL_STR_LEN 16

#define KERNEL32_DLL "kernel32.dll"
#define ADVAPI32_DLL "advapi32.dll"
#define CRYPT32_DLL  "crypt32.dll"
#define MSCOREE_DLL  "mscoree.dll"
#define OLEAUT32_DLL "oleaut32.dll"
#define WININET_DLL  "wininet.dll"

typedef struct _API_IMPORT {
    const char *module;
    const char *name;
} API_IMPORT, *PAPI_IMPORT;

typedef struct _DONUT_CRYPT {
    BYTE        key[DONUT_KEY_LEN];  // 128-bit key
    BYTE        ctr[DONUT_BLK_LEN];  // 128-bit counter + nonce
} DONUT_CRYPT, *PDONUT_CRYPT;
    
// everything required for a module goes in the following structure
// it is encrypted and then signed with RSA key
// upon deploying to system, signature is verified before decrypting with static key in
// a donut instance
typedef struct _DONUT_MODULE {
    DWORD   type;                                   // EXE or DLL
    BYTE    modsig[DONUT_SIG_LEN];                  // RSA signature 
    WCHAR   runtime[DONUT_MAX_NAME];                // runtime version
    WCHAR   cls[DONUT_MAX_NAME];                    // name of class and optional namespace
    WCHAR   method[DONUT_MAX_NAME];                 // name of method
    DWORD   param_cnt;                              // number of parameters
    WCHAR   param[DONUT_MAX_PARAM][DONUT_MAX_NAME]; // string parameters passed to method
    DWORD   len;                                    // size of .NET assembly
    BYTE    data[4];                                // .NET assembly
} DONUT_MODULE, *PDONUT_MODULE;

// everything required for the loader goes in the following structure
// it contains everything that might be used to identify a payload 
// it is encrypted with static key
typedef struct _DONUT_INSTANCE {
    DWORD       dwLen;                     // total length of instance, not including the Key
    DONUT_CRYPT Key;                       // decrypts instance data
    // everything from this point is encrypted
    DWORD       DllCount;                  // how many DLL to load before resolving API
    CHAR        szDll[DONUT_MAX_DLL][32];  // list of DLL strings to load
    DWORD       Reserved1;
    ULONG64     ulIV;                      // 64-bit initial value for maru hash
    DWORD       ApiCount;                  // 64-bit hashes of API required for instance to work
    DWORD       Reserved2;
    
    union {
      ULONG64   hash[48];
      VOID     *addr[48];
      // include prototypes only if header included from payload.h
      #ifdef PAYLOAD_H
      struct {
        // imports from kernel32.dll
        LoadLibraryA_t             LoadLibraryA;
        
        VirtualAlloc_t             VirtualAlloc;             
        VirtualFree_t              VirtualFree;              
        LocalFree_t                LocalFree;                
        FindResource_t             FindResource;             
        LoadResource_t             LoadResource;             
        LockResource_t             LockResource;             
        SizeofResource_t           SizeofResource;           
        
        // imports from mscoree.dll
        CLRCreateInstance_t        CLRCreateInstance;        
        
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
        
        // imports from advapi32.dll
        CryptAcquireContext_t      CryptAcquireContext;      
        CryptCreateHash_t          CryptCreateHash;          
        CryptHashData_t            CryptHashData;            
        CryptVerifySignature_t     CryptVerifySignature;     
        CryptDestroyHash_t         CryptDestroyHash;         
        CryptDestroyKey_t          CryptDestroyKey;          
        CryptReleaseContext_t      CryptReleaseContext;      
        
        // imports from crypt32.dll
        CryptStringToBinaryA_t     CryptStringToBinaryA;     
        CryptDecodeObjectEx_t      CryptDecodeObjectEx;      
        CryptImportPublicKeyInfo_t CryptImportPublicKeyInfo; 
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
    
    DONUT_INSTANCE_TYPE dwType; // PIC, DLL or URL 
    
    union {
      // module is stored remotely
      struct {
        CHAR url[DONUT_MAX_URL];
        CHAR req[16];         // just a buffer for "GET"
      } http;
      
      // module is stored in resource section
      struct {
        CHAR name[DONUT_MAX_RES_NAME];
        CHAR type[DONUT_MAX_RES_NAME];
      } resource;
    } TypeInfo;
    
    // public key to verify signature of a module
    // requires 4*(DONUT_SIG_LEN/3) bytes plus extra for header/footer
    CHAR pubkey[DONUT_PUBKEY_LEN];
    
    DONUT_CRYPT ModuleKey;     // used to decrypt module
    SIZE_T      ModuleLen;     // total size of module including signature
    
    union {
      PDONUT_MODULE p;         // for URL or DLL
      DONUT_MODULE  x;         // for PIC
    } Assembly;
} DONUT_INSTANCE, *PDONUT_INSTANCE;
    
typedef struct _DONUT_CONFIG {
    int            arch;        // target architecture for shellcode
    int            type;
    char           modname[32]; // name of module written to disk
    char           *cls;        // name of class and optional namespace
    char           *method;     // name of method to execute
    char           *param;      // string parameters passed to method, separated by comma or semi-colon
    char           *file;       // assembly to create module from
    char           *url;        // points to root path of where module will be on remote http server
    
    char           *privkey;    // pointer to private key PEM file
    char           *pubkey;     // pointer to public key PEM file
    
    int             modlen;     // size of DONUT_MODULE
    PDONUT_MODULE   mod;        // pointer to donut module
    
    int             instlen;
    PDONUT_INSTANCE inst;       // pointer to donut instance
    
    int             payloadlen;
    void*           payload;    // points to PIC
} DONUT_CONFIG, *PDONUT_CONFIG;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DLL
#define EXPORT_FUNC __declspec(dllexport)
#else
#define EXPORT_FUNC
#endif

EXPORT_FUNC int CreatePayload(PDONUT_CONFIG);
EXPORT_FUNC int CreateInstance(PDONUT_CONFIG);
EXPORT_FUNC int CreateModule(PDONUT_CONFIG);
EXPORT_FUNC int SignModule(PDONUT_CONFIG);
EXPORT_FUNC int GenRandom(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif
