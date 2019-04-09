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

#if !defined(SPECK) && !defined(CHASKEY) && !defined(CHAM) && !defined(NOEKEON)
#define SPECK
#endif

#define UNICODE
#include <windows.h>
#include <oleauto.h>
#include <stdint.h>

    // imports from mscoree.dll
    typedef HRESULT (WINAPI *CLRCreateInstance_t)(
        REFCLSID        clsid,  
        REFIID          riid,  
        LPVOID          *ppInterface);  

    // imports from OLEAUT32.dll
    typedef SAFEARRAY* (WINAPI *SafeArrayCreate_t)(
        VARTYPE         vt,
        UINT            cDims,
        SAFEARRAYBOUND  *rgsabound);

    typedef SAFEARRAY* (WINAPI *SafeArrayCreateVector_t)(
        VARTYPE         vt,
        LONG            lLbound,
        ULONG           cElements);

    typedef HRESULT (WINAPI *SafeArrayPutElement_t)(
        SAFEARRAY       *psa,
        LONG            *rgIndices,
        void            *pv);

    typedef HRESULT (WINAPI *SafeArrayDestroy_t)(
        SAFEARRAY       *psa);

    typedef BSTR (WINAPI *SysAllocString_t)(
      const OLECHAR     *psz);

    typedef void (WINAPI *SysFreeString_t)(
      BSTR              bstrString);

    // imports from kernel32.dll
    typedef HMODULE (WINAPI *LoadLibraryA_t)(
      LPCSTR            lpLibFileName);

    // forward references
    typedef struct _AppDomain IAppDomain;
    typedef struct _Assembly  IAssembly;
    typedef struct _Type      IType;
    typedef struct _Binder    IBinder;

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
        DUMMY_METHOD(EntryPoint);
        
        HRESULT (STDMETHODCALLTYPE *GetType_2)(
          IAssembly *This,
          BSTR      name,
          IType     **pRetVal);
        
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
    
    typedef struct _Type {
        TypeVtbl *lpVtbl;
    } Type;
    
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

#define ROTR(v,n)(((v)>>(n))|((v)<<(32-(n))))

#if defined(SPECK)

// SPECK-64/128
#define CIPHER_BLK_LEN   8    // 64-bits
#define CIPHER_KEY_LEN  16    // 128-bits
#define ENCRYPT         speck

#elif defined(CHAM)

// CHAM-128/128
#define CIPHER_BLK_LEN  16    // 128-bits
#define CIPHER_KEY_LEN  16    // 128-bits
#define ENCRYPT         cham

#elif defined(CHASKEY)

// CHASKEY-128/128
#define CIPHER_BLK_LEN  16    // 128-bits
#define CIPHER_KEY_LEN  16    // 128-bits
#define ENCRYPT         chaskey

#elif defined(NOEKEON)

// NOEKEON-128/128
#define CIPHER_BLK_LEN  16    // 128-bits
#define CIPHER_KEY_LEN  16    // 128-bits
#define ENCRYPT         noekeon

#endif

typedef struct _DONUT_CRYPT {
    BYTE      key[CIPHER_KEY_LEN];
    BYTE      ctr[CIPHER_BLK_LEN];
} DONUT_CRYPT, *PDONUT_CRYPT;

typedef struct _DONUT_DATA {
    // DLL strings
    CHAR      xmscoree[32];
    CHAR      xoleaut32[32];
    
    // API strings
    CHAR      xLoadLibraryA[32];
    CHAR      xCLRCreateInstance[32];
    CHAR      xSafeArrayCreate[32];
    CHAR      xSafeArrayCreateVector[32];
    CHAR      xSafeArrayPutElement[32];
    CHAR      xSafeArrayDestroy[32];
    CHAR      xSysAllocString[32];
    CHAR      xSysFreeString[32];
    
    // GUID
    GUID      xCLSID_CLRMetaHost;
    GUID      xIID_ICLRMetaHost;  
    GUID      xIID_ICLRRuntimeInfo;
    GUID      xCLSID_CorRuntimeHost;
    GUID      xIID_ICorRuntimeHost;
    GUID      xIID_AppDomain;
    
    // assembly parameters
    WCHAR     xRUNTIME[32];
    WCHAR     xCLASS[32];
    WCHAR     xMETHOD[32];
    WCHAR     xPARAM[32];
    
    DWORD     assembly_len;
    BYTE      assembly[ANYSIZE_ARRAY];
} DONUT_DATA, *PDONUT_DATA;

typedef struct _DONUT_CFG {
    DONUT_CRYPT ctx;
    DWORD       data_len;
    DONUT_DATA  data;
} DONUT_CFG, *PDONUT_CFG;

#endif