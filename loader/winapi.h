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

#ifndef WINAPI_H
#define WINAPI_H

#include <windows.h>

    typedef void (WINAPI *Sleep_t)(DWORD dwMilliseconds);

    typedef int (WINAPI *MultiByteToWideChar_t)(
          UINT                              CodePage,
          DWORD                             dwFlags,
          LPCCH                             lpMultiByteStr,
          int                               cbMultiByte,
          LPWSTR                            lpWideCharStr,
          int                               cchWideChar);

    typedef int (WINAPI *WideCharToMultiByte_t)(
          UINT                               CodePage,
          DWORD                              dwFlags,
          LPCWCH                             lpWideCharStr,
          int                                cchWideChar,
          LPSTR                              lpMultiByteStr,
          int                                cbMultiByte,
          LPCCH                              lpDefaultChar,
          LPBOOL                             lpUsedDefaultChar);

    typedef LPWSTR* (WINAPI *CommandLineToArgvW_t)(LPCWSTR lpCmdLine, int* pNumArgs);
  
    // imports from shlwapi.dll
    typedef LSTATUS (WINAPI *SHGetValueA_t)(
        HKEY                hkey,
        LPCSTR              pszSubKey,
        LPCSTR              pszValue,
        DWORD               *pdwType,
        void                *pvData,
        DWORD               *pcbData);

    // imports from mscoree.dll
    typedef HRESULT (WINAPI *CLRCreateInstance_t)(
        REFCLSID            clsid,  
        REFIID              riid,  
        LPVOID              *ppInterface);  

    typedef HRESULT (WINAPI *CorBindToRuntime_t) (  
        LPCWSTR             pwszVersion,   
        LPCWSTR             pwszBuildFlavor,      
        REFCLSID            rclsid,   
        REFIID              riid,   
        LPVOID FAR          *ppv);  

    // imports from ole32.dll
    typedef HRESULT (WINAPI *CoInitializeEx_t)(
        LPVOID              pvReserved,
        DWORD               dwCoInit);

    typedef void (WINAPI *CoUninitialize_t)(void);

    typedef HRESULT (WINAPI *CoCreateInstance_t)(
        REFCLSID            rclsid,
        LPUNKNOWN           pUnkOuter,
        DWORD               dwClsContext,
        REFIID              riid,
        LPVOID              *ppv);
        
    typedef HRESULT (WINAPI *CreateStdDispatch_t)(
        IUnknown           *punkOuter,
        void               *pvThis,
        ITypeInfo          *ptinfo,
        IUnknown           **ppunkStdDisp);

    typedef HRESULT (WINAPI *CreateErrorInfo_t)(
        ICreateErrorInfo **pperrinfo);

    typedef HRESULT (WINAPI *CreateDispTypeInfo_t)(
        INTERFACEDATA      *pidata,
        LCID               lcid,
        ITypeInfo          **pptinfo);

    typedef HRESULT (WINAPI *GetErrorInfo_t)(
        ULONG              dwReserved,
        IErrorInfo         **pperrinfo);

    typedef HRESULT (WINAPI *LoadTypeLib_t)(
        LPCOLESTR          szFile,
        ITypeLib           **pptlib);

    typedef HRESULT (WINAPI *LoadTypeLibEx_t)(
        LPCOLESTR          szFile,
        REGKIND            regkind,
        ITypeLib           **pptlib);

    typedef LCID (WINAPI *GetUserDefaultLCID_t)(VOID);
    
    // imports from oleaut32.dll
    typedef HRESULT (WINAPI *SafeArrayGetLBound_t)(
        SAFEARRAY           *psa,
        UINT                nDim,
        LONG                *plLbound);

    typedef HRESULT (WINAPI *SafeArrayGetUBound_t)(
        SAFEARRAY           *psa,
        UINT                nDim,
        LONG                *plUbound);
        
    typedef SAFEARRAY* (WINAPI *SafeArrayCreate_t)(
        VARTYPE             vt,
        UINT                cDims,
        SAFEARRAYBOUND      *rgsabound);

    typedef SAFEARRAY* (WINAPI *SafeArrayCreateVector_t)(
        VARTYPE             vt,
        LONG                lLbound,
        ULONG               cElements);

    typedef HRESULT (WINAPI *SafeArrayPutElement_t)(
        SAFEARRAY           *psa,
        LONG                *rgIndices,
        void                *pv);

    typedef HRESULT (WINAPI *SafeArrayDestroy_t)(
        SAFEARRAY           *psa);

    typedef BSTR (WINAPI *SysAllocString_t)(
      const OLECHAR         *psz);

    typedef void (WINAPI *SysFreeString_t)(
      BSTR                  bstrString);

    // imports from kernel32.dll
    typedef HMODULE (WINAPI *LoadLibraryA_t)(
      LPCSTR                lpLibFileName);

    typedef FARPROC (WINAPI *GetProcAddress_t)(
      HMODULE               hModule,
      LPCSTR                lpProcName);

    typedef BOOL (WINAPI *AllocConsole_t)(void);
    
    typedef BOOL (WINAPI *AttachConsole_t)(
      DWORD                 dwProcessId);

    typedef BOOL (WINAPI *SetConsoleCtrlHandler_t)(
      PHANDLER_ROUTINE      HandlerRoutine,
      BOOL                  Add);

    typedef HANDLE (WINAPI *GetStdHandle_t)(
      DWORD                 nStdHandle);

    typedef BOOL (WINAPI *SetStdHandle_t)(
      DWORD                 nStdHandle,
      HANDLE                hHandle);

    typedef HANDLE (WINAPI *CreateFileA_t)(
      LPCSTR                lpFileName,
      DWORD                 dwDesiredAccess,
      DWORD                 dwShareMode,
      LPSECURITY_ATTRIBUTES lpSecurityAttributes,
      DWORD                 dwCreationDisposition,
      DWORD                 dwFlagsAndAttributes,
      HANDLE                hTemplateFile);

    typedef HANDLE (WINAPI *CreateEventA_t)(
      LPSECURITY_ATTRIBUTES lpEventAttributes,
      BOOL                  bManualReset,
      BOOL                  bInitialState,
      LPCSTR                lpName);

    typedef BOOL  (WINAPI *CloseHandle_t)(HANDLE hObject);

    typedef BOOL  (WINAPI *SetEvent_t)(HANDLE hEvent);

    typedef DWORD (WINAPI *GetCurrentThreadId_t)(VOID);

    typedef DWORD (WINAPI *GetCurrentProcessId_t)(VOID);

    typedef HHOOK (WINAPI *SetWindowsHookExA_t)(
      int                     idHook,
      HOOKPROC                lpfn,
      HINSTANCE               hmod,
      DWORD                   dwThreadId);
      
    typedef BOOL (WINAPI *CreateProcessA_t)(
        LPCSTR                lpApplicationName,
        LPSTR                 lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL                  bInheritHandles,
        DWORD                 dwCreationFlags,
        LPVOID                lpEnvironment,
        LPCSTR                lpCurrentDirectory,
        LPSTARTUPINFOA        lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);

    typedef DWORD (WINAPI *WaitForSingleObject_t)(
        HANDLE                hHandle,
        DWORD                 dwMilliseconds);

    // imports from wininet.dll
    typedef BOOL (WINAPI *InternetCrackUrl_t)(
      LPCSTR                  lpszUrl,
      DWORD                   dwUrlLength,
      DWORD                   dwFlags,
      LPURL_COMPONENTS        lpUrlComponents);

    typedef HINTERNET (WINAPI *InternetOpen_t)(
      LPCSTR                lpszAgent,
      DWORD                 dwAccessType,
      LPCSTR                lpszProxy,
      LPCSTR                lpszProxyBypass,
      DWORD                 dwFlags);

    typedef HINTERNET (WINAPI *InternetConnect_t)(
      HINTERNET             hInternet,
      LPCSTR                lpszServerName,
      INTERNET_PORT         nServerPort,
      LPCSTR                lpszUserName,
      LPCSTR                lpszPassword,
      DWORD                 dwService,
      DWORD                 dwFlags,
      DWORD_PTR             dwContext);

    typedef HINTERNET (WINAPI *HttpOpenRequest_t)(
      HINTERNET             hConnect,
      LPCSTR                lpszVerb,
      LPCSTR                lpszObjectName,
      LPCSTR                lpszVersion,
      LPCSTR                lpszReferrer,
      LPCSTR                *lplpszAcceptTypes,
      DWORD                 dwFlags,
      DWORD_PTR             dwContext);

    typedef BOOL (WINAPI *InternetSetOption_t)(
      HINTERNET             hInternet,
      DWORD                 dwOption,
      LPVOID                lpBuffer,
      DWORD                 dwBufferLength);

    typedef BOOL (WINAPI *HttpSendRequest_t)(
      HINTERNET             hRequest,
      LPCSTR                lpszHeaders,
      DWORD                 dwHeadersLength,
      LPVOID                lpOptional,
      DWORD                 dwOptionalLength);

    typedef BOOL (WINAPI *HttpQueryInfo_t)(
      HINTERNET             hRequest,
      DWORD                 dwInfoLevel,
      LPVOID                lpBuffer,
      LPDWORD               lpdwBufferLength,
      LPDWORD               lpdwIndex);

    typedef BOOL (WINAPI *InternetReadFile_t)(
      HINTERNET             hFile,
      LPVOID                lpBuffer,
      DWORD                 dwNumberOfBytesToRead,
      LPDWORD               lpdwNumberOfBytesRead);

    typedef BOOL (WINAPI *InternetCloseHandle_t)(
      HINTERNET             hInternet);

    typedef BOOL (WINAPI *CryptAcquireContext_t)(
      HCRYPTPROV            *phProv,
      LPCSTR                szContainer,
      LPCSTR                szProvider,
      DWORD                 dwProvType,
      DWORD                 dwFlags);

    typedef void (WINAPI *GetSystemInfo_t)(
      LPSYSTEM_INFO         lpSystemInfo);

    typedef SIZE_T (WINAPI *VirtualQuery_t)(
      LPCVOID                   lpAddress,
      PMEMORY_BASIC_INFORMATION lpBuffer,
      SIZE_T                    dwLength);
      
    typedef BOOL (WINAPI *VirtualProtect_t)(
      LPVOID                    lpAddress,
      SIZE_T                    dwSize,
      DWORD                     flNewProtect,
      PDWORD                    lpflOldProtect);

    typedef HMODULE (WINAPI *GetModuleHandleA_t)(
      LPCSTR                    lpModuleName);

    typedef HMODULE (WINAPI *LoadLibraryExA_t)(
      LPCSTR                    lpLibFileName,
      HANDLE                    hFile,
      DWORD                     dwFlags);

    typedef HMODULE (WINAPI *LoadLibraryExW_t)(
      LPCWSTR                   lpLibFileName,
      HANDLE                    hFile,
      DWORD                     dwFlags);

    typedef BOOL (WINAPI *CryptStringToBinaryA_t)(
      LPCSTR                pszString,
      DWORD                 cchString,
      DWORD                 dwFlags,
      BYTE                  *pbBinary,
      DWORD                 *pcbBinary,
      DWORD                 *pdwSkip,
      DWORD                 *pdwFlags);

    typedef BOOL (WINAPI *CryptDecodeObjectEx_t)(
      DWORD                 dwCertEncodingType,
      LPCSTR                lpszStructType,
      const BYTE            *pbEncoded,
      DWORD                 cbEncoded,
      DWORD                 dwFlags,
      PCRYPT_DECODE_PARA    pDecodePara,
      void                  *pvStructInfo,
      DWORD                 *pcbStructInfo);

    typedef BOOL (WINAPI *CryptImportPublicKeyInfo_t)(
      HCRYPTPROV            hCryptProv,
      DWORD                 dwCertEncodingType,
      PCERT_PUBLIC_KEY_INFO pInfo,
      HCRYPTKEY             *phKey);

    typedef BOOL (WINAPI *CryptCreateHash_t)(
      HCRYPTPROV            hProv,
      ALG_ID                Algid,
      HCRYPTKEY             hKey,
      DWORD                 dwFlags,
      HCRYPTHASH            *phHash);

    typedef BOOL (WINAPI *CryptHashData_t)(
      HCRYPTHASH            hHash,
      const BYTE            *pbData,
      DWORD                 dwDataLen,
      DWORD                 dwFlags);

    typedef BOOL (WINAPI *CryptVerifySignature_t)(
      HCRYPTHASH            hHash,
      const BYTE            *pbSignature,
      DWORD                 dwSigLen,
      HCRYPTKEY             hPubKey,
      LPCSTR                szDescription,
      DWORD                 dwFlags);

    typedef BOOL (WINAPI *CryptDestroyHash_t)(
      HCRYPTHASH            hHash);

    typedef BOOL (WINAPI *CryptDestroyKey_t)(
      HCRYPTKEY             hKey);

    typedef BOOL (WINAPI *CryptReleaseContext_t)(
      HCRYPTPROV            hProv,
      DWORD                 dwFlags);

    typedef LPVOID (WINAPI *VirtualAlloc_t)(
      LPVOID                lpAddress,
      SIZE_T                dwSize,
      DWORD                 flAllocationType,
      DWORD                 flProtect);

    typedef BOOL (WINAPI *VirtualFree_t)(
      LPVOID                lpAddress,
      SIZE_T                dwSize,
      DWORD                 dwFreeType);

    typedef HLOCAL (WINAPI *LocalFree_t)(
      HLOCAL                hMem);      
      
    typedef HRSRC (WINAPI *FindResource_t)(
      HMODULE               hModule,
      LPCSTR                lpName,
      LPCSTR                lpType);

    typedef HGLOBAL (WINAPI *LoadResource_t)(
      HMODULE               hModule,
      HRSRC                 hResInfo);

    typedef LPVOID (WINAPI *LockResource_t)(
      HGLOBAL               hResData);
       
    typedef DWORD (WINAPI *SizeofResource_t)(
      HMODULE               hModule,
      HRSRC                 hResInfo);

    typedef void (WINAPI *RtlZeroMemory_t)(
      LPVOID                Destination,
      SIZE_T                Length);
      
    typedef BOOL (WINAPI *RtlEqualUnicodeString_t)(
      PUNICODE_STRING       String1,
      PUNICODE_STRING       String2,
      BOOLEAN               CaseInSensitive);

    typedef BOOL (WINAPI *RtlEqualString_t)(
      const ANSI_STRING *   String1,
      const ANSI_STRING *   String2,
      BOOLEAN               CaseInSensitive);
      
    typedef NTSTATUS (WINAPI *RtlUnicodeStringToAnsiString_t)(
      PANSI_STRING          DestinationString,
      PUNICODE_STRING       SourceString,
      BOOLEAN               AllocateDestinationString);

    typedef void (WINAPI *RtlInitUnicodeString_t)(
      PUNICODE_STRING       DestinationString,
      PCWSTR                SourceString);
          
    typedef void (WINAPI *RtlExitUserThread_t)(UINT uExitCode);

    typedef void (WINAPI *RtlExitUserProcess_t)(NTSTATUS ExitStatus);
    
    typedef HANDLE (WINAPI *CreateThread_t)(
      LPSECURITY_ATTRIBUTES  lpThreadAttributes,
      SIZE_T                 dwStackSize,
      LPTHREAD_START_ROUTINE lpStartAddress,
      LPVOID                 lpParameter,
      DWORD                  dwCreationFlags,
      LPDWORD                lpThreadId);
    
    typedef BOOL (WINAPI *RtlCreateUnicodeString_t)(
      PUNICODE_STRING        DestinationString,
      PCWSTR                 SourceString);

    typedef NTSTATUS (WINAPI *RtlGetCompressionWorkSpaceSize_t)(
      USHORT                 CompressionFormatAndEngine,
      PULONG                 CompressBufferWorkSpaceSize,
      PULONG                 CompressFragmentWorkSpaceSize);

    typedef NTSTATUS (WINAPI *RtlCompressBuffer_t)(
      USHORT                 CompressionFormatAndEngine,
      PUCHAR                 UncompressedBuffer,
      ULONG                  UncompressedBufferSize,
      PUCHAR                 CompressedBuffer,
      ULONG                  CompressedBufferSize,
      ULONG                  UncompressedChunkSize,
      PULONG                 FinalCompressedSize,
      PVOID                  WorkSpace);
  
    typedef NTSTATUS (WINAPI *RtlDecompressBuffer_t)(
      USHORT                 CompressionFormat,
      PUCHAR                 UncompressedBuffer,
      ULONG                  UncompressedBufferSize,
      PUCHAR                 CompressedBuffer,
      ULONG                  CompressedBufferSize,
      PULONG                 FinalUncompressedSize);
 #endif
 
 