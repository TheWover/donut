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

#ifndef PAYLOAD_H
#define PAYLOAD_H

#if !defined(_MSC_VER)
#define __out_ecount_full(x)
#define __out_ecount_full_opt(x)
#include <inttypes.h>
void Memset(void *mem, unsigned char b, unsigned int len);
#endif

#include <windows.h>
#include <wincrypt.h>
#include <oleauto.h>
#include <objbase.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

#if defined(DEBUG)
#include <stdio.h>
 #define DPRINT(...) { \
   fprintf(stderr, "\nDEBUG: %s:%d:%s(): ", __FILE__, __LINE__, __FUNCTION__); \
   fprintf(stderr, __VA_ARGS__); \
 }
#else
 #define DPRINT(...) // Don't do anything in release builds
#endif

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

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

    typedef DWORD (WINAPI *GetCurrentProcessId_t)(VOID);

    // imports from wininet.dll
    typedef BOOL (WINAPI *InternetCrackUrl_t)(
      LPCSTR                lpszUrl,
      DWORD                 dwUrlLength,
      DWORD                 dwFlags,
      LPURL_COMPONENTS      lpUrlComponents);

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

    // forward references
    typedef struct _ICLRMetaHost           ICLRMetaHost;
    typedef struct _ICLRRuntimeInfo        ICLRRuntimeInfo;
    typedef struct _ICorRuntimeHost        ICorRuntimeHost;
    typedef struct _ICorConfiguration      ICorConfiguration;
    typedef struct _IGCThreadControl       IGCThreadControl;
    typedef struct _IGCHostControl         IGCHostControl;
    typedef struct _IDebuggerThreadControl IDebuggerThreadControl;
    typedef struct _AppDomain              IAppDomain;
    typedef struct _Assembly               IAssembly;
    typedef struct _Type                   IType;
    typedef struct _Binder                 IBinder;
    typedef struct _MethodInfo             IMethodInfo;
    typedef struct _IAmsiStream            IAmsiStream;
    typedef struct _IAntimalware           IAntimalware;
    typedef struct _IAntimalwareProvider   IAntimalwareProvider;

    typedef void *HDOMAINENUM;
    
    typedef HRESULT ( __stdcall *CLRCreateInstanceFnPtr )( 
        REFCLSID clsid,
        REFIID riid,
        LPVOID *ppInterface);

    typedef HRESULT ( __stdcall *CreateInterfaceFnPtr )( 
        REFCLSID clsid,
        REFIID riid,
        LPVOID *ppInterface);


    typedef HRESULT ( __stdcall *CallbackThreadSetFnPtr )( void);

    typedef HRESULT ( __stdcall *CallbackThreadUnsetFnPtr )( void);

    typedef void ( __stdcall *RuntimeLoadedCallbackFnPtr )( 
        ICLRRuntimeInfo *pRuntimeInfo,
        CallbackThreadSetFnPtr pfnCallbackThreadSet,
        CallbackThreadUnsetFnPtr pfnCallbackThreadUnset);
        
    #undef DUMMY_METHOD
    #define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IBinder *This)
    
    typedef struct _BinderVtbl {
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
          IBinder * This,
          /* [in] */ REFIID riid,
          /* [iid_is][out] */ void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
          IBinder * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
          IBinder * This);
          
        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(BindToMethod);
        DUMMY_METHOD(BindToField);
        DUMMY_METHOD(SelectMethod);
        DUMMY_METHOD(SelectProperty);
        DUMMY_METHOD(ChangeType);
        DUMMY_METHOD(ReorderArgumentArray);
    } BinderVtbl;
    
    typedef struct _Binder {
      BinderVtbl *lpVtbl;
    } Binder;
    
    #undef DUMMY_METHOD
    #define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAppDomain *This)

    typedef struct _AppDomainVtbl {
        BEGIN_INTERFACE

        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
          IAppDomain * This,
          /* [in] */ REFIID riid,
          /* [iid_is][out] */ void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
          IAppDomain * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
          IAppDomain * This);

        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);
        
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(InitializeLifetimeService);
        DUMMY_METHOD(GetLifetimeService);
        DUMMY_METHOD(Evidence);
        DUMMY_METHOD(add_DomainUnload);
        DUMMY_METHOD(remove_DomainUnload);
        DUMMY_METHOD(add_AssemblyLoad);
        DUMMY_METHOD(remove_AssemblyLoad);
        DUMMY_METHOD(add_ProcessExit);
        DUMMY_METHOD(remove_ProcessExit);
        DUMMY_METHOD(add_TypeResolve);
        DUMMY_METHOD(remove_TypeResolve);
        DUMMY_METHOD(add_ResourceResolve);
        DUMMY_METHOD(remove_ResourceResolve);
        DUMMY_METHOD(add_AssemblyResolve);
        DUMMY_METHOD(remove_AssemblyResolve);
        DUMMY_METHOD(add_UnhandledException);
        DUMMY_METHOD(remove_UnhandledException);
        DUMMY_METHOD(DefineDynamicAssembly);
        DUMMY_METHOD(DefineDynamicAssembly_2);
        DUMMY_METHOD(DefineDynamicAssembly_3);
        DUMMY_METHOD(DefineDynamicAssembly_4);
        DUMMY_METHOD(DefineDynamicAssembly_5);
        DUMMY_METHOD(DefineDynamicAssembly_6);
        DUMMY_METHOD(DefineDynamicAssembly_7);
        DUMMY_METHOD(DefineDynamicAssembly_8);
        DUMMY_METHOD(DefineDynamicAssembly_9);
        DUMMY_METHOD(CreateInstance);
        DUMMY_METHOD(CreateInstanceFrom);
        DUMMY_METHOD(CreateInstance_2);
        DUMMY_METHOD(CreateInstanceFrom_2);
        DUMMY_METHOD(CreateInstance_3);
        DUMMY_METHOD(CreateInstanceFrom_3);
        DUMMY_METHOD(Load);
        DUMMY_METHOD(Load_2);
        
        HRESULT (STDMETHODCALLTYPE *Load_3)(
          IAppDomain *This,
          SAFEARRAY  *rawAssembly,
          IAssembly  **pRetVal);
          
        DUMMY_METHOD(Load_4);
        DUMMY_METHOD(Load_5);
        DUMMY_METHOD(Load_6);
        DUMMY_METHOD(Load_7);
        DUMMY_METHOD(ExecuteAssembly);
        DUMMY_METHOD(ExecuteAssembly_2);
        DUMMY_METHOD(ExecuteAssembly_3);
        DUMMY_METHOD(FriendlyName);
        DUMMY_METHOD(BaseDirectory);
        DUMMY_METHOD(RelativeSearchPath);
        DUMMY_METHOD(ShadowCopyFiles);
        DUMMY_METHOD(GetAssemblies);
        DUMMY_METHOD(AppendPrivatePath);
        DUMMY_METHOD(ClearPrivatePath);
        DUMMY_METHOD(SetShadowCopyPath);
        DUMMY_METHOD(ClearShadowCopyPath);
        DUMMY_METHOD(SetCachePath);
        DUMMY_METHOD(SetData);
        DUMMY_METHOD(GetData);
        DUMMY_METHOD(SetAppDomainPolicy);
        DUMMY_METHOD(SetThreadPrincipal);
        DUMMY_METHOD(SetPrincipalPolicy);
        DUMMY_METHOD(DoCallBack);
        DUMMY_METHOD(DynamicDirectory);

        END_INTERFACE
    } AppDomainVtbl;

    typedef struct _AppDomain {
      AppDomainVtbl *lpVtbl;
    } AppDomain;

    #undef DUMMY_METHOD
    #define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IAssembly *This)
    
    typedef struct _AssemblyVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
          IAssembly * This,
          REFIID riid,
          void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
          IAssembly * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
          IAssembly * This);
    
        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        
        DUMMY_METHOD(Invoke);
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(CodeBase);
        DUMMY_METHOD(EscapedCodeBase);
        DUMMY_METHOD(GetName);
        DUMMY_METHOD(GetName_2);
        DUMMY_METHOD(FullName);
        
        HRESULT (STDMETHODCALLTYPE *EntryPoint)(
          IAssembly   *This,
          IMethodInfo **pRetVal);
        
        HRESULT (STDMETHODCALLTYPE *GetType_2)(
          IAssembly   *This,
          BSTR        name,
          IType       **pRetVal);
        
        DUMMY_METHOD(GetType_3);
        DUMMY_METHOD(GetExportedTypes);
        DUMMY_METHOD(GetTypes);
        DUMMY_METHOD(GetManifestResourceStream);
        DUMMY_METHOD(GetManifestResourceStream_2);
        DUMMY_METHOD(GetFile);
        DUMMY_METHOD(GetFiles);
        DUMMY_METHOD(GetFiles_2);
        DUMMY_METHOD(GetManifestResourceNames);
        DUMMY_METHOD(GetManifestResourceInfo);
        DUMMY_METHOD(Location);
        DUMMY_METHOD(Evidence);
        DUMMY_METHOD(GetCustomAttributes);
        DUMMY_METHOD(GetCustomAttributes_2);
        DUMMY_METHOD(IsDefined);
        DUMMY_METHOD(GetObjectData);
        DUMMY_METHOD(add_ModuleResolve);
        DUMMY_METHOD(remove_ModuleResolve);
        DUMMY_METHOD(GetType_4);
        DUMMY_METHOD(GetSatelliteAssembly);
        DUMMY_METHOD(GetSatelliteAssembly_2);
        DUMMY_METHOD(LoadModule);
        DUMMY_METHOD(LoadModule_2);
        DUMMY_METHOD(CreateInstance);
        DUMMY_METHOD(CreateInstance_2);
        DUMMY_METHOD(CreateInstance_3);
        DUMMY_METHOD(GetLoadedModules);
        DUMMY_METHOD(GetLoadedModules_2);
        DUMMY_METHOD(GetModules);
        DUMMY_METHOD(GetModules_2);
        DUMMY_METHOD(GetModule);
        DUMMY_METHOD(GetReferencedAssemblies);
        DUMMY_METHOD(GlobalAssemblyCache);

        END_INTERFACE
    } AssemblyVtbl;
    
    typedef enum _BindingFlags {
        BindingFlags_Default              = 0,
        BindingFlags_IgnoreCase           = 1,
        BindingFlags_DeclaredOnly         = 2,
        BindingFlags_Instance             = 4,
        BindingFlags_Static               = 8,
        BindingFlags_Public               = 16,
        BindingFlags_NonPublic            = 32,
        BindingFlags_FlattenHierarchy     = 64,
        BindingFlags_InvokeMethod         = 256,
        BindingFlags_CreateInstance       = 512,
        BindingFlags_GetField             = 1024,
        BindingFlags_SetField             = 2048,
        BindingFlags_GetProperty          = 4096,
        BindingFlags_SetProperty          = 8192,
        BindingFlags_PutDispProperty      = 16384,
        BindingFlags_PutRefDispProperty   = 32768,
        BindingFlags_ExactBinding         = 65536,
        BindingFlags_SuppressChangeType   = 131072,
        BindingFlags_OptionalParamBinding = 262144,
        BindingFlags_IgnoreReturn         = 16777216
    } BindingFlags;

    typedef struct _Assembly {
        AssemblyVtbl *lpVtbl;
    } Assembly;
    
    #undef DUMMY_METHOD
    #define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IType *This)
    
    typedef struct _TypeVtbl {
        BEGIN_INTERFACE
      
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )(
          IType * This,
          REFIID riid,
          void **ppvObject);

        ULONG ( STDMETHODCALLTYPE *AddRef )(
          IType * This);

        ULONG ( STDMETHODCALLTYPE *Release )(
          IType * This);
          
        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);
        
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(MemberType);
        DUMMY_METHOD(name);
        DUMMY_METHOD(DeclaringType);
        DUMMY_METHOD(ReflectedType);
        DUMMY_METHOD(GetCustomAttributes);
        DUMMY_METHOD(GetCustomAttributes_2);
        DUMMY_METHOD(IsDefined);
        DUMMY_METHOD(Guid);
        DUMMY_METHOD(Module);
        DUMMY_METHOD(Assembly);
        DUMMY_METHOD(TypeHandle);
        DUMMY_METHOD(FullName);
        DUMMY_METHOD(Namespace);
        DUMMY_METHOD(AssemblyQualifiedName);
        DUMMY_METHOD(GetArrayRank);
        DUMMY_METHOD(BaseType);
        DUMMY_METHOD(GetConstructors);
        DUMMY_METHOD(GetInterface);
        DUMMY_METHOD(GetInterfaces);
        DUMMY_METHOD(FindInterfaces);
        DUMMY_METHOD(GetEvent);
        DUMMY_METHOD(GetEvents);
        DUMMY_METHOD(GetEvents_2);
        DUMMY_METHOD(GetNestedTypes);
        DUMMY_METHOD(GetNestedType);
        DUMMY_METHOD(GetMember);
        DUMMY_METHOD(GetDefaultMembers);
        DUMMY_METHOD(FindMembers);
        DUMMY_METHOD(GetElementType);
        DUMMY_METHOD(IsSubclassOf);
        DUMMY_METHOD(IsInstanceOfType);
        DUMMY_METHOD(IsAssignableFrom);
        DUMMY_METHOD(GetInterfaceMap);
        DUMMY_METHOD(GetMethod);
        DUMMY_METHOD(GetMethod_2);
        DUMMY_METHOD(GetMethods);
        DUMMY_METHOD(GetField);
        DUMMY_METHOD(GetFields);
        DUMMY_METHOD(GetProperty);
        DUMMY_METHOD(GetProperty_2);
        DUMMY_METHOD(GetProperties);
        DUMMY_METHOD(GetMember_2);
        DUMMY_METHOD(GetMembers);
        DUMMY_METHOD(InvokeMember);
        DUMMY_METHOD(UnderlyingSystemType);
        DUMMY_METHOD(InvokeMember_2);
        
        HRESULT (STDMETHODCALLTYPE *InvokeMember_3)(
          IType        *This,
          BSTR         name,
          BindingFlags invokeAttr,
          IBinder      *Binder,
          VARIANT      Target,
          SAFEARRAY    *args,
          VARIANT      *pRetVal);
  
        DUMMY_METHOD(GetConstructor);
        DUMMY_METHOD(GetConstructor_2);
        DUMMY_METHOD(GetConstructor_3);
        DUMMY_METHOD(GetConstructors_2);
        DUMMY_METHOD(TypeInitializer);
        DUMMY_METHOD(GetMethod_3);
        DUMMY_METHOD(GetMethod_4);
        DUMMY_METHOD(GetMethod_5);
        DUMMY_METHOD(GetMethod_6);
        DUMMY_METHOD(GetMethods_2);
        DUMMY_METHOD(GetField_2);
        DUMMY_METHOD(GetFields_2);
        DUMMY_METHOD(GetInterface_2);
        DUMMY_METHOD(GetEvent_2);
        DUMMY_METHOD(GetProperty_3);
        DUMMY_METHOD(GetProperty_4);
        DUMMY_METHOD(GetProperty_5);
        DUMMY_METHOD(GetProperty_6);
        DUMMY_METHOD(GetProperty_7);
        DUMMY_METHOD(GetProperties_2);
        DUMMY_METHOD(GetNestedTypes_2);
        DUMMY_METHOD(GetNestedType_2);
        DUMMY_METHOD(GetMember_3);
        DUMMY_METHOD(GetMembers_2);
        DUMMY_METHOD(Attributes);
        DUMMY_METHOD(IsNotPublic);
        DUMMY_METHOD(IsPublic);
        DUMMY_METHOD(IsNestedPublic);
        DUMMY_METHOD(IsNestedPrivate);
        DUMMY_METHOD(IsNestedFamily);
        DUMMY_METHOD(IsNestedAssembly);
        DUMMY_METHOD(IsNestedFamANDAssem);
        DUMMY_METHOD(IsNestedFamORAssem);
        DUMMY_METHOD(IsAutoLayout);
        DUMMY_METHOD(IsLayoutSequential);
        DUMMY_METHOD(IsExplicitLayout);
        DUMMY_METHOD(IsClass);
        DUMMY_METHOD(IsInterface);
        DUMMY_METHOD(IsValueType);
        DUMMY_METHOD(IsAbstract);
        DUMMY_METHOD(IsSealed);
        DUMMY_METHOD(IsEnum);
        DUMMY_METHOD(IsSpecialName);
        DUMMY_METHOD(IsImport);
        DUMMY_METHOD(IsSerializable);
        DUMMY_METHOD(IsAnsiClass);
        DUMMY_METHOD(IsUnicodeClass);
        DUMMY_METHOD(IsAutoClass);
        DUMMY_METHOD(IsArray);
        DUMMY_METHOD(IsByRef);
        DUMMY_METHOD(IsPointer);
        DUMMY_METHOD(IsPrimitive);
        DUMMY_METHOD(IsCOMObject);
        DUMMY_METHOD(HasElementType);
        DUMMY_METHOD(IsContextful);
        DUMMY_METHOD(IsMarshalByRef);
        DUMMY_METHOD(Equals_2);
        
        END_INTERFACE
    } TypeVtbl;
    
 typedef struct ICLRRuntimeInfoVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ICLRRuntimeInfo * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ICLRRuntimeInfo * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ICLRRuntimeInfo * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetVersionString )( 
            ICLRRuntimeInfo * This,
            /* [size_is][out] */ 
            __out_ecount_full_opt(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD *pcchBuffer);
        
        HRESULT ( STDMETHODCALLTYPE *GetRuntimeDirectory )( 
            ICLRRuntimeInfo * This,
            /* [size_is][out] */ 
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD *pcchBuffer);
        
        HRESULT ( STDMETHODCALLTYPE *IsLoaded )( 
            ICLRRuntimeInfo * This,
            /* [in] */ HANDLE hndProcess,
            /* [retval][out] */ BOOL *pbLoaded);
        
        HRESULT ( STDMETHODCALLTYPE *LoadErrorString )( 
            ICLRRuntimeInfo * This,
            /* [in] */ UINT iResourceID,
            /* [size_is][out] */ 
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD *pcchBuffer,
            /* [lcid][in] */ LONG iLocaleID);
        
        HRESULT ( STDMETHODCALLTYPE *LoadLibrary )( 
            ICLRRuntimeInfo * This,
            /* [in] */ LPCWSTR pwzDllName,
            /* [retval][out] */ HMODULE *phndModule);
        
        HRESULT ( STDMETHODCALLTYPE *GetProcAddress )( 
            ICLRRuntimeInfo * This,
            /* [in] */ LPCSTR pszProcName,
            /* [retval][out] */ LPVOID *ppProc);
        
        HRESULT ( STDMETHODCALLTYPE *GetInterface )( 
            ICLRRuntimeInfo * This,
            /* [in] */ REFCLSID rclsid,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID *ppUnk);
        
        HRESULT ( STDMETHODCALLTYPE *IsLoadable )( 
            ICLRRuntimeInfo * This,
            /* [retval][out] */ BOOL *pbLoadable);
        
        HRESULT ( STDMETHODCALLTYPE *SetDefaultStartupFlags )( 
            ICLRRuntimeInfo * This,
            /* [in] */ DWORD dwStartupFlags,
            /* [in] */ LPCWSTR pwzHostConfigFile);
        
        HRESULT ( STDMETHODCALLTYPE *GetDefaultStartupFlags )( 
            ICLRRuntimeInfo * This,
            /* [out] */ DWORD *pdwStartupFlags,
            /* [size_is][out] */ 
            __out_ecount_full_opt(*pcchHostConfigFile)  LPWSTR pwzHostConfigFile,
            /* [out][in] */ DWORD *pcchHostConfigFile);
        
        HRESULT ( STDMETHODCALLTYPE *BindAsLegacyV2Runtime )( 
            ICLRRuntimeInfo * This);
        
        HRESULT ( STDMETHODCALLTYPE *IsStarted )( 
            ICLRRuntimeInfo * This,
            /* [out] */ BOOL *pbStarted,
            /* [out] */ DWORD *pdwStartupFlags);
        
        END_INTERFACE
    } ICLRRuntimeInfoVtbl;

    typedef struct _ICLRRuntimeInfo {
        ICLRRuntimeInfoVtbl *lpVtbl;
    } ICLRRuntimeInfo;
    
    typedef struct _Type {
        TypeVtbl *lpVtbl;
    } Type;
    
    typedef struct ICLRMetaHostVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ICLRMetaHost * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ICLRMetaHost * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ICLRMetaHost * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetRuntime )( 
            ICLRMetaHost * This,
            /* [in] */ LPCWSTR pwzVersion,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID *ppRuntime);
        
        HRESULT ( STDMETHODCALLTYPE *GetVersionFromFile )( 
            ICLRMetaHost * This,
            /* [in] */ LPCWSTR pwzFilePath,
            /* [size_is][out] */ 
            __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
            /* [out][in] */ DWORD *pcchBuffer);
        
        HRESULT ( STDMETHODCALLTYPE *EnumerateInstalledRuntimes )( 
            ICLRMetaHost * This,
            /* [retval][out] */ IEnumUnknown **ppEnumerator);
        
        HRESULT ( STDMETHODCALLTYPE *EnumerateLoadedRuntimes )( 
            ICLRMetaHost * This,
            /* [in] */ HANDLE hndProcess,
            /* [retval][out] */ IEnumUnknown **ppEnumerator);
        
        HRESULT ( STDMETHODCALLTYPE *RequestRuntimeLoadedNotification )( 
            ICLRMetaHost * This,
            /* [in] */ RuntimeLoadedCallbackFnPtr pCallbackFunction);
        
        HRESULT ( STDMETHODCALLTYPE *QueryLegacyV2RuntimeBinding )( 
            ICLRMetaHost * This,
            /* [in] */ REFIID riid,
            /* [retval][iid_is][out] */ LPVOID *ppUnk);
        
        HRESULT ( STDMETHODCALLTYPE *ExitProcess )( 
            ICLRMetaHost * This,
            /* [in] */ INT32 iExitCode);
        
        END_INTERFACE
    } ICLRMetaHostVtbl;

    typedef struct _ICLRMetaHost
    {
      ICLRMetaHostVtbl *lpVtbl;
    } ICLRMetaHost;
    
    typedef struct ICorRuntimeHostVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ICorRuntimeHost * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ICorRuntimeHost * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ICorRuntimeHost * This);
        
        HRESULT ( STDMETHODCALLTYPE *CreateLogicalThreadState )( 
            ICorRuntimeHost * This);
        
        HRESULT ( STDMETHODCALLTYPE *DeleteLogicalThreadState )( 
            ICorRuntimeHost * This);
        
        HRESULT ( STDMETHODCALLTYPE *SwitchInLogicalThreadState )( 
            ICorRuntimeHost * This,
            /* [in] */ DWORD *pFiberCookie);
        
        HRESULT ( STDMETHODCALLTYPE *SwitchOutLogicalThreadState )( 
            ICorRuntimeHost * This,
            /* [out] */ DWORD **pFiberCookie);
        
        HRESULT ( STDMETHODCALLTYPE *LocksHeldByLogicalThread )( 
            ICorRuntimeHost * This,
            /* [out] */ DWORD *pCount);
        
        HRESULT ( STDMETHODCALLTYPE *MapFile )( 
            ICorRuntimeHost * This,
            /* [in] */ HANDLE hFile,
            /* [out] */ HMODULE *hMapAddress);
        
        HRESULT ( STDMETHODCALLTYPE *GetConfiguration )( 
            ICorRuntimeHost * This,
            /* [out] */ ICorConfiguration **pConfiguration);
        
        HRESULT ( STDMETHODCALLTYPE *Start )( 
            ICorRuntimeHost * This);
        
        HRESULT ( STDMETHODCALLTYPE *Stop )( 
            ICorRuntimeHost * This);
        
        HRESULT ( STDMETHODCALLTYPE *CreateDomain )( 
            ICorRuntimeHost * This,
            /* [in] */ LPCWSTR pwzFriendlyName,
            /* [in] */ IUnknown *pIdentityArray,
            /* [out] */ IUnknown **pAppDomain);
        
        HRESULT ( STDMETHODCALLTYPE *GetDefaultDomain )( 
            ICorRuntimeHost * This,
            /* [out] */ IUnknown **pAppDomain);
        
        HRESULT ( STDMETHODCALLTYPE *EnumDomains )( 
            ICorRuntimeHost * This,
            /* [out] */ HDOMAINENUM *hEnum);
        
        HRESULT ( STDMETHODCALLTYPE *NextDomain )( 
            ICorRuntimeHost * This,
            /* [in] */ HDOMAINENUM hEnum,
            /* [out] */ IUnknown **pAppDomain);
        
        HRESULT ( STDMETHODCALLTYPE *CloseEnum )( 
            ICorRuntimeHost * This,
            /* [in] */ HDOMAINENUM hEnum);
        
        HRESULT ( STDMETHODCALLTYPE *CreateDomainEx )( 
            ICorRuntimeHost * This,
            /* [in] */ LPCWSTR pwzFriendlyName,
            /* [in] */ IUnknown *pSetup,
            /* [in] */ IUnknown *pEvidence,
            /* [out] */ IUnknown **pAppDomain);
        
        HRESULT ( STDMETHODCALLTYPE *CreateDomainSetup )( 
            ICorRuntimeHost * This,
            /* [out] */ IUnknown **pAppDomainSetup);
        
        HRESULT ( STDMETHODCALLTYPE *CreateEvidence )( 
            ICorRuntimeHost * This,
            /* [out] */ IUnknown **pEvidence);
        
        HRESULT ( STDMETHODCALLTYPE *UnloadDomain )( 
            ICorRuntimeHost * This,
            /* [in] */ IUnknown *pAppDomain);
        
        HRESULT ( STDMETHODCALLTYPE *CurrentDomain )( 
            ICorRuntimeHost * This,
            /* [out] */ IUnknown **pAppDomain);
        
        END_INTERFACE
    } ICorRuntimeHostVtbl;

    typedef struct _ICorRuntimeHost {
        ICorRuntimeHostVtbl *lpVtbl;
    } ICorRuntimeHost;
    
    #undef DUMMY_METHOD
    #define DUMMY_METHOD(x) HRESULT ( STDMETHODCALLTYPE *dummy_##x )(IMethodInfo *This)
    
    typedef struct _MethodInfoVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IMethodInfo *This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IMethodInfo *This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IMethodInfo *This);
            
        DUMMY_METHOD(GetTypeInfoCount);
        DUMMY_METHOD(GetTypeInfo);
        DUMMY_METHOD(GetIDsOfNames);
        DUMMY_METHOD(Invoke);
        
        DUMMY_METHOD(ToString);
        DUMMY_METHOD(Equals);
        DUMMY_METHOD(GetHashCode);
        DUMMY_METHOD(GetType);
        DUMMY_METHOD(MemberType);
        DUMMY_METHOD(name);
        DUMMY_METHOD(DeclaringType);
        DUMMY_METHOD(ReflectedType);
        DUMMY_METHOD(GetCustomAttributes);
        DUMMY_METHOD(GetCustomAttributes_2);
        DUMMY_METHOD(IsDefined);
        
        HRESULT ( STDMETHODCALLTYPE *GetParameters)(
            IMethodInfo *This,
            SAFEARRAY   **pRetVal);
        
        DUMMY_METHOD(GetMethodImplementationFlags);
        DUMMY_METHOD(MethodHandle);
        DUMMY_METHOD(Attributes);
        DUMMY_METHOD(CallingConvention);
        DUMMY_METHOD(Invoke_2);
        DUMMY_METHOD(IsPublic);
        DUMMY_METHOD(IsPrivate);
        DUMMY_METHOD(IsFamily);
        DUMMY_METHOD(IsAssembly);
        DUMMY_METHOD(IsFamilyAndAssembly);
        DUMMY_METHOD(IsFamilyOrAssembly);
        DUMMY_METHOD(IsStatic);
        DUMMY_METHOD(IsFinal);
        DUMMY_METHOD(IsVirtual);
        DUMMY_METHOD(IsHideBySig);
        DUMMY_METHOD(IsAbstract);
        DUMMY_METHOD(IsSpecialName);
        DUMMY_METHOD(IsConstructor);
        
        HRESULT ( STDMETHODCALLTYPE *Invoke_3 )(
            IMethodInfo *This,
            VARIANT     obj,
            SAFEARRAY   *parameters,
            VARIANT     *ret);
        
        DUMMY_METHOD(returnType);
        DUMMY_METHOD(ReturnTypeCustomAttributes);
        DUMMY_METHOD(GetBaseDefinition);
        
        END_INTERFACE
    } MethodInfoVtbl;
    
    typedef struct _MethodInfo {
        MethodInfoVtbl *lpVtbl;
    } MethodInfo;
    
    typedef struct ICorConfigurationVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            ICorConfiguration * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            ICorConfiguration * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            ICorConfiguration * This);
        
        HRESULT ( STDMETHODCALLTYPE *SetGCThreadControl )( 
            ICorConfiguration * This,
            /* [in] */ IGCThreadControl *pGCThreadControl);
        
        HRESULT ( STDMETHODCALLTYPE *SetGCHostControl )( 
            ICorConfiguration * This,
            /* [in] */ IGCHostControl *pGCHostControl);
        
        HRESULT ( STDMETHODCALLTYPE *SetDebuggerThreadControl )( 
            ICorConfiguration * This,
            /* [in] */ IDebuggerThreadControl *pDebuggerThreadControl);
        
        HRESULT ( STDMETHODCALLTYPE *AddDebuggerSpecialThread )( 
            ICorConfiguration * This,
            /* [in] */ DWORD dwSpecialThreadId);
        
        END_INTERFACE
    } ICorConfigurationVtbl;

    typedef struct _ICorConfiguration
    {
       ICorConfigurationVtbl *lpVtbl;
    }ICorConfiguration;
    
    typedef struct IGCThreadControlVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IGCThreadControl * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IGCThreadControl * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IGCThreadControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *ThreadIsBlockingForSuspension )( 
            IGCThreadControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *SuspensionStarting )( 
            IGCThreadControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *SuspensionEnding )( 
            IGCThreadControl * This,
            DWORD Generation);
        
        END_INTERFACE
    } IGCThreadControlVtbl;

    typedef struct _IGCThreadControl
    {
        IGCThreadControlVtbl *lpVtbl;
    }IGCThreadControl;

    typedef struct IGCHostControlVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IGCHostControl * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IGCHostControl * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IGCHostControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *RequestVirtualMemLimit )( 
            IGCHostControl * This,
            /* [in] */ SIZE_T sztMaxVirtualMemMB,
            /* [out][in] */ SIZE_T *psztNewMaxVirtualMemMB);
        
        END_INTERFACE
    } IGCHostControlVtbl;

    typedef struct _IGCHostControl
    {
        IGCHostControlVtbl *lpVtbl;
    } IGCHostControl;
    
    typedef struct IDebuggerThreadControlVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDebuggerThreadControl * This,
            /* [in] */ REFIID riid,
            /* [iid_is][out] */ 
            __RPC__deref_out  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDebuggerThreadControl * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDebuggerThreadControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *ThreadIsBlockingForDebugger )( 
            IDebuggerThreadControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *ReleaseAllRuntimeThreads )( 
            IDebuggerThreadControl * This);
        
        HRESULT ( STDMETHODCALLTYPE *StartBlockingForDebugger )( 
            IDebuggerThreadControl * This,
            DWORD dwUnused);
        
        END_INTERFACE
    } IDebuggerThreadControlVtbl;

    typedef struct _IDebuggerThreadControl {
       IDebuggerThreadControlVtbl *lpVtbl;
    } IDebuggerThreadControl;
    
    
    // AMSI stuff
    
typedef enum tagAMSI_RESULT {
    // No detection found. Result likely not going to change after future definition update.
    // a.k.a. known good
    AMSI_RESULT_CLEAN        = 0,
    // No detection found. Result might change after future definition update.
    AMSI_RESULT_NOT_DETECTED = 1,
    // Detection found. It is recommended to abort executing the content if it is executable, e.g. a script.
    // Return result of 1 - 32767 is estimated risk level that an antimalware provider might indicate.
    // The large the result, the riskier to continue.
    // Any return result equal to or larger than 32768 is consider malware and should be blocked.
    // These values are provider specific, and may indicate malware family or ID.
    // An application should use AmsiResultIsMalware() to determine whether the content should be blocked.
    AMSI_RESULT_DETECTED     = 32768,
} AMSI_RESULT;

typedef enum tagAMSI_ATTRIBUTE {
    // Name/version/GUID string of the calling application.
    AMSI_ATTRIBUTE_APP_NAME     = 0,
    // LPWSTR, filename, URL, script unique id etc.
    AMSI_ATTRIBUTE_CONTENT_NAME = 1,
    // ULONGLONG, size of the input. Mandatory.
    AMSI_ATTRIBUTE_CONTENT_SIZE = 2,
    // PVOID, memory address if content is fully loaded in memory. Mandatory unless
    // Read() is implemented instead to support on-demand content retrieval.
    AMSI_ATTRIBUTE_CONTENT_ADDRESS = 3,
    // PVOID, session is used to associate different scan calls, e.g. if the contents
    // to be scanned belong to the sample original script. Return nullptr if content
    // is self-contained. Mandatory.
    AMSI_ATTRIBUTE_SESSION = 4,
} AMSI_ATTRIBUTE;

    typedef struct IAmsiStreamVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAmsiStream * This,
            REFIID riid,
            void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAmsiStream * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAmsiStream * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetAttribute )( 
            IAmsiStream * This,
            AMSI_ATTRIBUTE attribute,
            ULONG dataSize,
            unsigned char *data,
            ULONG *retData);
        
        HRESULT ( STDMETHODCALLTYPE *Read )( 
            IAmsiStream * This,
            ULONGLONG position,
            ULONG size,
            unsigned char *buffer,
            ULONG *readSize);
        
        END_INTERFACE
    } IAmsiStreamVtbl;

    typedef struct _IAmsiStream {
        IAmsiStreamVtbl *lpVtbl;
    } AmsiStream;
    
    typedef struct IAntimalwareProviderVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAntimalwareProvider * This,
            REFIID riid,
            void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAntimalwareProvider * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAntimalwareProvider * This);
        
        HRESULT ( STDMETHODCALLTYPE *Scan )( 
            IAntimalwareProvider * This,
            IAmsiStream *stream,
            AMSI_RESULT *result);
        
        void ( STDMETHODCALLTYPE *CloseSession )( 
            IAntimalwareProvider * This,
            ULONGLONG session);
        
        HRESULT ( STDMETHODCALLTYPE *DisplayName )( 
            IAntimalwareProvider * This,
            LPWSTR *displayName);
        
        END_INTERFACE
    } IAntimalwareProviderVtbl;

    typedef struct _IAntimalwareProvider {
        IAntimalwareProviderVtbl *lpVtbl;
    } AntimalwareProvider;
    
    typedef struct IAntimalwareVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
            IAntimalware *This,
            REFIID riid, 
            void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAntimalware * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAntimalware * This);
        
        HRESULT ( STDMETHODCALLTYPE *Scan )( 
            IAntimalware * This,
            IAmsiStream *stream,
            AMSI_RESULT *result,
            IAntimalwareProvider **provider);
        
        void ( STDMETHODCALLTYPE *CloseSession )( 
            IAntimalware * This,
            ULONGLONG session);
        
        END_INTERFACE
    } IAntimalwareVtbl;

    typedef struct _IAntimalware {
        IAntimalwareVtbl *lpVtbl;
    } Antimalware;


typedef void *PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

// PEB defined by rewolf
// http://blog.rewolf.pl/blog/?p=573
typedef struct _PEB_LDR_DATA {
  ULONG      Length;
  BOOL       Initialized;
  LPVOID     SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY     InLoadOrderLinks;
  LIST_ENTRY     InMemoryOrderLinks;
  LIST_ENTRY     InInitializationOrderLinks;
  LPVOID         DllBase;
  LPVOID         EntryPoint;
  ULONG          SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
  BYTE                         InheritedAddressSpace;
  BYTE                         ReadImageFileExecOptions;
  BYTE                         BeingDebugged;
  BYTE                         _SYSTEM_DEPENDENT_01;

  LPVOID                       Mutant;
  LPVOID                       ImageBaseAddress;

  PPEB_LDR_DATA                Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  LPVOID                       SubSystemData;
  LPVOID                       ProcessHeap;
  LPVOID                       FastPebLock;
  LPVOID                       _SYSTEM_DEPENDENT_02;
  LPVOID                       _SYSTEM_DEPENDENT_03;
  LPVOID                       _SYSTEM_DEPENDENT_04;
  union {
    LPVOID                     KernelCallbackTable;
    LPVOID                     UserSharedInfoPtr;
  };  
  DWORD                        SystemReserved;
  DWORD                        _SYSTEM_DEPENDENT_05;
  LPVOID                       _SYSTEM_DEPENDENT_06;
  LPVOID                       TlsExpansionCounter;
  LPVOID                       TlsBitmap;
  DWORD                        TlsBitmapBits[2];
  LPVOID                       ReadOnlySharedMemoryBase;
  LPVOID                       _SYSTEM_DEPENDENT_07;
  LPVOID                       ReadOnlyStaticServerData;
  LPVOID                       AnsiCodePageData;
  LPVOID                       OemCodePageData;
  LPVOID                       UnicodeCaseTableData;
  DWORD                        NumberOfProcessors;
  union
  {
    DWORD                      NtGlobalFlag;
    LPVOID                     dummy02;
  };
  LARGE_INTEGER                CriticalSectionTimeout;
  LPVOID                       HeapSegmentReserve;
  LPVOID                       HeapSegmentCommit;
  LPVOID                       HeapDeCommitTotalFreeThreshold;
  LPVOID                       HeapDeCommitFreeBlockThreshold;
  DWORD                        NumberOfHeaps;
  DWORD                        MaximumNumberOfHeaps;
  LPVOID                       ProcessHeaps;
  LPVOID                       GdiSharedHandleTable;
  LPVOID                       ProcessStarterHelper;
  LPVOID                       GdiDCAttributeList;
  LPVOID                       LoaderLock;
  DWORD                        OSMajorVersion;
  DWORD                        OSMinorVersion;
  WORD                         OSBuildNumber;
  WORD                         OSCSDVersion;
  DWORD                        OSPlatformId;
  DWORD                        ImageSubsystem;
  DWORD                        ImageSubsystemMajorVersion;
  LPVOID                       ImageSubsystemMinorVersion;
  union
  {
    LPVOID                     ImageProcessAffinityMask;
    LPVOID                     ActiveProcessAffinityMask;
  };
  #ifdef _WIN64
  LPVOID                       GdiHandleBuffer[64];
  #else
  LPVOID                       GdiHandleBuffer[32];
  #endif  
  LPVOID                       PostProcessInitRoutine;
  LPVOID                       TlsExpansionBitmap;
  DWORD                        TlsExpansionBitmapBits[32];
  LPVOID                       SessionId;
  ULARGE_INTEGER               AppCompatFlags;
  ULARGE_INTEGER               AppCompatFlagsUser;
  LPVOID                       pShimData;
  LPVOID                       AppCompatInfo;
  PUNICODE_STRING              CSDVersion;
  LPVOID                       ActivationContextData;
  LPVOID                       ProcessAssemblyStorageMap;
  LPVOID                       SystemDefaultActivationContextData;
  LPVOID                       SystemAssemblyStorageMap;
  LPVOID                       MinimumStackCommit;  
} PEB, *PPEB;

#include "donut.h"

typedef struct tagHAMSICONTEXT {
  DWORD        Signature;          // "AMSI" or 0x49534D41
  PWCHAR       AppName;            // set by AmsiInitialize
  IAntimalware *Antimalware;       // set by AmsiInitialize
  DWORD        SessionCount;       // increased by AmsiOpenSession
} _HAMSICONTEXT, *_PHAMSICONTEXT;

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

    BOOL DownloadModule(PDONUT_INSTANCE);
    
    BOOL LoadAssembly(PDONUT_INSTANCE, PDONUT_ASSEMBLY);
    BOOL RunAssembly(PDONUT_INSTANCE,  PDONUT_ASSEMBLY);
    VOID FreeAssembly(PDONUT_INSTANCE, PDONUT_ASSEMBLY);
    BOOL DisableAMSI(PDONUT_INSTANCE);
    
    LPVOID xGetProcAddress(PDONUT_INSTANCE, ULONGLONG, ULONGLONG);

#endif
