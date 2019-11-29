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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#else
#define LINUX
#include <unistd.h>
#include <dlfcn.h>
#endif

#define DONUT_ERROR_SUCCESS              0
#define DONUT_ERROR_FILE_NOT_FOUND       1
#define DONUT_ERROR_FILE_EMPTY           2
#define DONUT_ERROR_FILE_ACCESS          3
#define DONUT_ERROR_FILE_INVALID         4
#define DONUT_ERROR_NET_PARAMS           5
#define DONUT_ERROR_NO_MEMORY            6
#define DONUT_ERROR_INVALID_ARCH         7
#define DONUT_ERROR_INVALID_URL          8
#define DONUT_ERROR_URL_LENGTH           9
#define DONUT_ERROR_INVALID_PARAMETER   10
#define DONUT_ERROR_RANDOM              11
#define DONUT_ERROR_DLL_FUNCTION        12
#define DONUT_ERROR_ARCH_MISMATCH       13
#define DONUT_ERROR_DLL_PARAM           14
#define DONUT_ERROR_BYPASS_INVALID      15
#define DONUT_ERROR_NORELOC             16
#define DONUT_ERROR_INVALID_ENCODING    17
#define DONUT_ERROR_INVALID_ENGINE      18
#define DONUT_ERROR_COMPRESSION         19
#define DONUT_ERROR_INVALID_ENTROPY     20

// target architecture
#define DONUT_ARCH_ANY                  -1  // just for vbs,js and xsl files
#define DONUT_ARCH_X86                   1  // x86
#define DONUT_ARCH_X64                   2  // AMD64
#define DONUT_ARCH_X84                   3  // AMD64 + x86

// module type
#define DONUT_MODULE_NET_DLL             1  // .NET DLL. Requires class and method
#define DONUT_MODULE_NET_EXE             2  // .NET EXE. Executes Main if no class and method provided
#define DONUT_MODULE_DLL                 3  // Unmanaged DLL, function is optional
#define DONUT_MODULE_EXE                 4  // Unmanaged EXE
#define DONUT_MODULE_VBS                 5  // VBScript
#define DONUT_MODULE_JS                  6  // JavaScript or JScript

// format type
#define DONUT_FORMAT_BINARY              1
#define DONUT_FORMAT_BASE64              2
#define DONUT_FORMAT_RUBY                3
#define DONUT_FORMAT_C                   4
#define DONUT_FORMAT_PYTHON              5
#define DONUT_FORMAT_POWERSHELL          6
#define DONUT_FORMAT_CSHARP              7
#define DONUT_FORMAT_HEX                 8

// compression engine
#define DONUT_COMPRESS_NONE              1
#define DONUT_COMPRESS_APLIB             2
#define DONUT_COMPRESS_LZNT1             3  // COMPRESSION_FORMAT_LZNT1
#define DONUT_COMPRESS_XPRESS            4  // COMPRESSION_FORMAT_XPRESS
#define DONUT_COMPRESS_XPRESS_HUFF       5  // COMPRESSION_FORMAT_XPRESS_HUFF

// entropy level
#define DONUT_ENTROPY_NONE               1  // don't use any entropy
#define DONUT_ENTROPY_RANDOM             2  // use random names
#define DONUT_ENTROPY_DEFAULT            3  // use random names + symmetric encryption

// misc options
#define DONUT_OPT_EXIT_THREAD            1  // return to the caller which calls RtlExitUserThread
#define DONUT_OPT_EXIT_PROCESS           2  // call RtlExitUserProcess to terminate host process

// instance type
#define DONUT_INSTANCE_EMBED             1  // Self-contained
#define DONUT_INSTANCE_HTTP              2  // Download from remote HTTP/HTTPS server
#define DONUT_INSTANCE_DNS               3  // Download from remote DNS server

// AMSI/WLDP options
#define DONUT_BYPASS_NONE                1  // Disables bypassing AMSI/WDLP
#define DONUT_BYPASS_ABORT               2  // If bypassing AMSI/WLDP fails, the loader stops running
#define DONUT_BYPASS_CONTINUE            3  // If bypassing AMSI/WLDP fails, the loader continues running

#define DONUT_MAX_NAME                 256  // maximum length of string for domain, class, method and parameter names
#define DONUT_MAX_DLL                    8  // maximum number of DLL supported by instance
#define DONUT_MAX_MODNAME                8
#define DONUT_SIG_LEN                    8  // 64-bit string to verify decryption ok
#define DONUT_VER_LEN                   32
#define DONUT_DOMAIN_LEN                 8
    
typedef struct _DONUT_CONFIG {
    uint32_t        len, zlen;                // original length of input file and compressed length
    // general / misc options for loader
    int             arch;                     // target architecture
    int             bypass;                   // bypass option for AMSI/WDLP
    int             compress;                 // engine to use when compressing file via RtlCompressBuffer
    int             entropy;                  // entropy/encryption level
    int             format;                   // output format for loader
    int             exit_opt;                 // return to caller or invoke RtlExitUserProcess to terminate the host process
    int             thread;                   // run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API
    uint64_t        oep;                      // original entrypoint of target host file
    
    // files in/out
    char            input[DONUT_MAX_NAME];    // name of input file to read and load in-memory
    char            output[DONUT_MAX_NAME];   // name of output file to save loader
    
    // .NET stuff
    char            runtime[DONUT_MAX_NAME];  // runtime version to use for CLR
    char            domain[DONUT_MAX_NAME];   // name of domain to create for .NET DLL/EXE
    char            cls[DONUT_MAX_NAME];      // name of class with optional namespace for .NET DLL
    char            method[DONUT_MAX_NAME];   // name of method or DLL function to invoke for .NET DLL and unmanaged DLL
    
    // command line for DLL/EXE
    char            param[DONUT_MAX_NAME];    // command line to use for unmanaged DLL/EXE and .NET DLL/EXE
    int             unicode;                  // param is converted to UNICODE before being passed to DLL function
    
    // HTTP staging information
    char            server[DONUT_MAX_NAME];   // points to root path of where module will be stored on remote http server
    char            modname[DONUT_MAX_NAME];  // name of module written to disk for http stager
    
    // DONUT_MODULE
    int             mod_type;                 // VBS/JS/DLL/EXE
    int             mod_len;                  // size of DONUT_MODULE
    void            *mod;                     // points to DONUT_MODULE
    
    // DONUT_INSTANCE
    int             inst_type;                // DONUT_INSTANCE_PIC or DONUT_INSTANCE_HTTP
    int             inst_len;                 // size of DONUT_INSTANCE
    void            *inst;                    // points to DONUT_INSTANCE
    
    // shellcode generated from configuration
    int             pic_len;                  // size of loader/shellcode
    void*           pic;                      // points to loader/shellcode
} DONUT_CONFIG, *PDONUT_CONFIG;

// function pointers
typedef int (__cdecl *DonutCreate_t)(PDONUT_CONFIG);
typedef int (__cdecl *DonutDelete_t)(PDONUT_CONFIG);
typedef const char* (__cdecl *DonutError_t)(int);

#ifdef __cplusplus
extern "C" {
#endif

// prototypes
int DonutCreate(PDONUT_CONFIG);
int DonutCreateWrapper(const char *);
int DonutDelete(PDONUT_CONFIG);
const char* DonutError(int);

#ifdef __cplusplus
}
#endif

#endif
