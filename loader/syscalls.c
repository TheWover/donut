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

#include "syscalls.h"

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

BOOL SW2_PopulateSyscallList(PSYSCALL_LIST SyscallList)
{
    // Return early if the list is already populated.
    if (SyscallList->Count) return TRUE;

    PSW2_PEB Peb = (PSW2_PEB)READ_MEMLOC(PEB_OFFSET);
    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = SW2_RVA2VA(PIMAGE_EXPORT_DIRECTORY, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SyscallList->Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SyscallList->Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SyscallList->Count - 1; i++)
    {
        for (DWORD j = 0; j < SyscallList->Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW2_GetSyscallNumber(DWORD FunctionHash, PSYSCALL_LIST SyscallList)
{
    // Check that the SyscallList was allocated
    if (SyscallList == NULL) return -1;
    // Ensure SyscallList is populated.
    if (!SW2_PopulateSyscallList(SyscallList)) return -1;

    for (DWORD i = 0; i < SyscallList->Count; i++)
    {
        if (FunctionHash == SyscallList->Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

#if defined(_MSC_VER) && defined (_M_IX86)

__declspec(naked) NTSTATUS NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x20] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x32956E27
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN ULONG InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x2c] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x035E220D
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x0c] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x9ACEB842
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtContinue(
    IN PCONTEXT ContextRecord,
    IN BOOLEAN TestAlert,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0xc1] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0xF2989153
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtClose(
    IN HANDLE Handle,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x08] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x349DD6D1
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtWaitForSingleObject(
    IN HANDLE ObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER TimeOut OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x10] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0xE3BDE123
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x18] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x0B911517
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x0c] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x1CB74215
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x1c] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x31A5474B
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x14] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x87907FEF
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x30] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x249DFE2A
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x1c] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x55CF2B39
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x30] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0x34297693
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

__declspec(naked) NTSTATUS NtFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN ULONG Length,
    IN PSYSCALL_LIST SyscallList) {
  __asm {
    mov eax, dword ptr[esp + 0x10] // hex((1+(NUM_PARAMS-1))*4)
    push eax
    push 0xFFACC9F7
    call SW2_GetSyscallNumber
    add esp, 8
    call DoSysenter
    ret
  }
}

#elif defined(__GNUC__)

__declspec(naked) NTSTATUS NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x32956E27\n"
        "mov rdx, qword ptr [rsp + 0x60]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x20]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x32956E27\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN ULONG InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x035E220D\n"
        "mov rdx, qword ptr [rsp + 0x78]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x2c]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x035E220D\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x9ACEB842\n"
        "mov rdx, r8\n"
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x0c]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x9ACEB842\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtContinue(
    IN PCONTEXT ContextRecord,
    IN BOOLEAN TestAlert,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0xF2989153\n"
        "mov rdx, r8\n"
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0xc1]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0xF2989153\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtClose(
    IN HANDLE Handle,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x349DD6D1\n"
        "mov rdx, rdx\n"
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x08]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x349DD6D1\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtWaitForSingleObject(
    IN HANDLE ObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER TimeOut OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0xE3BDE123\n"
        "mov rdx, r9\n"
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x10]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0xE3BDE123\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x0B911517\n"
        "mov rdx, qword ptr [rsp + 0x50]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x18]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x0B911517\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x1CB74215\n"
        "mov rdx, r8\n"
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x0c]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x1CB74215\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x31A5474B\n"
        "mov rdx, qword ptr [rsp + 0x58]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x1c]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x31A5474B\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x87907FEF\n"
        "mov rdx, qword ptr [rsp + 0x48]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x14]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x87907FEF\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x249DFE2A\n"
        "mov rdx, qword ptr [rsp + 0x80]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x30]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x249DFE2A\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x55CF2B39\n"
        "mov rdx, qword ptr [rsp + 0x58]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x1c]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x55CF2B39\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0x34297693\n"
        "mov rdx, qword ptr [rsp + 0x80]\n" // (4+5+(NUM_PARAMS-4-1))*8
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x30]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0x34297693\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

__declspec(naked) NTSTATUS NtFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN ULONG Length,
    IN PSYSCALL_LIST SyscallList) {
#if defined(_WIN64)
    asm(
        "push rcx\n"
        "push rdx\n"
        "push r8\n"
        "push r9\n"
        "mov ecx, 0xFFACC9F7\n"
        "mov rdx, r9\n"
        "sub rsp, 0x28\n"
        "call SW2_GetSyscallNumber\n"
        "add rsp, 0x28\n"
        "pop r9\n"
        "pop r8\n"
        "pop rdx\n"
        "pop rcx\n"
        "mov r10, rcx\n"
        "syscall\n"
        "ret\n"
    );
#else
    asm(
        "mov eax, dword ptr[esp + 0x10]\n" // hex((1+(NUM_PARAMS-1))*4)
        "push eax\n"
        "push 0xFFACC9F7\n"
        "call SW2_GetSyscallNumber\n"
        "add esp, 8\n"
        "call DoSysenter\n"
        "ret\n"
    );
#endif
}

#endif

#if defined(_M_IX86)
__declspec(naked) VOID DoSysenter(VOID) {
 #if defined(_MSC_VER)
    __asm {
        mov edx, esp
        int 0x2e
        ret
    };
 #elif defined(__GNUC__)
    asm(
        "mov edx, esp\n"
        "sysenter\n"
        "ret\n"
    );
 #endif
}
#endif
