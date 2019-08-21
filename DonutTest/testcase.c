

// just some simple test cases to use with donut library

#include "donut.h"

typedef struct _test_case_t {
  int  arch;
  int  bypass;
  int  inst_type;
  char *domain;
  char *cls;
  char *method;
  char *param;
  char *file;
  char *url;
  char *runtime;
  int  err;               // expected result based on test case
} test_case;

test_case tests[] = {
  // nothing supplied
  {0,0,0,"","","","","","","",DONUT_ERROR_INVALID_PARAMETER},
  // requesting x86 shellcode for x64 DLL
  {DONUT_ARCH_X86,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","cls","method","param","hello_amd64.dll","","",DONUT_ERROR_ARCH_MISMATCH},
  // requesting x64 shellcode for x86 DLL
  {DONUT_ARCH_X64,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","","","","hello_x86.dll","","",DONUT_ERROR_ARCH_MISMATCH},
  // supplying parameters for unmanaged DLL, but not function name
  {DONUT_ARCH_X64,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","","","calc.exe,notepad.exe","hello_amd64.dll","","",DONUT_ERROR_DLL_PARAM},
  // supplying function name that can't be found in DLL
  {DONUT_ARCH_X64,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","","NoMethod","calc.exe,notepad.exe","hello_amd64.dll","","",DONUT_ERROR_DLL_FUNCTION},
  // supplying file that isn't recognized
  {DONUT_ARCH_ANY,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"","","","","/dev/null","","",DONUT_ERROR_FILE_INVALID},
  // .NET DLL assembly with no method provided
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","TestClass","","","class1.dll","","",DONUT_ERROR_NET_PARAMS},
  // .NET DLL assembly with no class provided
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","","RunProcess","calc.exe,notepad.exe","class1.dll","","",DONUT_ERROR_NET_PARAMS},
  // .NET DLL with good parameters
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_PIC,"domain","TestClass","RunProcess","calc.exe,notepad.exe","class1.dll","","",DONUT_ERROR_SUCCESS},
  // invalid URL
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_URL,"domain","TestClass","RunProcess","calc.exe,notepad.exe","class1.dll","http:","",DONUT_ERROR_INVALID_URL},
  // invalid URL length
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_URL,"domain","TestClass","RunProcess","calc.exe,notepad.exe","class1.dll","http://","",DONUT_ERROR_URL_LENGTH},
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_URL,"domain","TestClass","RunProcess","calc.exe,notepad.exe","class1.dll","https://","",DONUT_ERROR_URL_LENGTH},
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_URL,"domain","TestClass","RunProcess","calc.exe,notepad.exe","class1.dll","https://a","",DONUT_ERROR_SUCCESS},
  {DONUT_ARCH_X84,DONUT_BYPASS_CONTINUE,DONUT_INSTANCE_URL,"domain","TestClass","RunProcess","calc.exe,notepad.exe","class1.dll",
  "https://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "",DONUT_ERROR_URL_LENGTH},
};

int main(void)
{
    DONUT_CONFIG c;
    int          err, i;
    
    for(i=0; i<sizeof(tests)/sizeof(test_case); i++) {
      memset(&c, 0, sizeof(c));
    
      c.arch      = tests[i].arch;
      c.bypass    = tests[i].bypass;
      c.inst_type = tests[i].inst_type;
      
      strncpy(c.domain , tests[i].domain,  sizeof(c.domain)  - 1);
      strncpy(c.cls    , tests[i].cls,     sizeof(c.cls)     - 1);
      strncpy(c.method , tests[i].method,  sizeof(c.method)  - 1);
      strncpy(c.param  , tests[i].param,   sizeof(c.param)   - 1);
      strncpy(c.file   , tests[i].file,    sizeof(c.file)    - 1);
      strncpy(c.url    , tests[i].url,     sizeof(c.url)     - 1);
      strncpy(c.runtime, tests[i].runtime, sizeof(c.runtime) - 1);
      
      printf("Test Case # %2i ", (i+1));
      err = DonutCreate(&c);
      DonutDelete(&c);
      
      printf("returned %2i : %s\n", 
        err, err == tests[i].err ? "OK" : "FAILED");
    }
    return 0;
}
