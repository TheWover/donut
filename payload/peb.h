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

#ifndef PEB_H
#define PEB_H

#include <windows.h>

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

#endif