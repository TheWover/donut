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

#define DONUT_ERROR_SUCCESS            0
#define DONUT_ERROR_ASSEMBLY_NOT_FOUND 1
#define DONUT_ERROR_ASSEMBLY_EMPTY     2
#define DONUT_ERROR_ASSEMBLY_ACCESS    3
#define DONUT_ERROR_NO_MEMORY          4
#define DONUT_ERROR_INVALID_ARCH       5
#define DONUT_ERROR_URL_LENGTH         6
#define DONUT_ERROR_INVALID_PARAMETER  7
#define DONUT_ERROR_RANDOM             8

// target architecture
#define DONUT_ARCH_X86                 0
#define DONUT_ARCH_AMD64               1

// module type
#define DONUT_MODULE_DLL               0
#define DONUT_MODULE_EXE               1

// apparently C# can support 2^16 or 65,536 parameters
// we support up to eight for now :)
#define DONUT_MAX_PARAM      8        // maximum number of parameters passed to method
#define DONUT_MAX_NAME      32        // maximum length of string for domain, class, method and parameter names
#define DONUT_MAX_DLL        8        // maximum number of DLL supported by instance
#define DONUT_MAX_URL      128
#define DONUT_MAX_RES_NAME  16
#define DONUT_MAX_MODNAME    8

typedef enum _DONUT_INSTANCE_TYPE {
    DONUT_INSTANCE_PIC = 0,          // self-contained
    DONUT_INSTANCE_URL = 1,          // download from remote server
} DONUT_INSTANCE_TYPE;
    
typedef struct _DONUT_CONFIG {
    int    arch;                    // target architecture for shellcode
    int    type;                    // URL or PIC
    char   modname[DONUT_MAX_NAME]; // name of module written to disk
    char   domain[DONUT_MAX_NAME];  // name of domain to create for assembly
    char   *cls;                    // name of class and optional namespace
    char   *method;                 // name of method to execute
    char   *param;                  // string parameters passed to method, separated by comma or semi-colon
    char   *file;                   // assembly to create module from
    char   url[DONUT_MAX_URL];      // points to root path of where module will be on remote http server
    char   runtime[DONUT_MAX_NAME]; // runtime version to use. v4.0.30319 is used by default
    
    int    mod_len;                 // size of DONUT_MODULE
    void   *mod;                    // points to encrypted DONUT_MODULE
    
    int    inst_len;                // size of DONUT_INSTANCE
    void   *inst;                   // points to encrypted DONUT_INSTANCE
    
    int    pic_len;                 // size of shellcode
    void   *pic;                    // points to PIC/shellcode
} DONUT_CONFIG, *PDONUT_CONFIG;

#ifdef __cplusplus
extern "C" {
#endif

int CreatePayload(PDONUT_CONFIG);
int FreePayload(PDONUT_CONFIG);

#ifdef __cplusplus
}
#endif

#endif
