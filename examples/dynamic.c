
// dynamic example (doesn't work with .NET DLL)
// odzhan

#include "donut.h"

int main(int argc, char *argv[]) {
    DONUT_CONFIG  c;
    int           err;

    // function pointers
    DonutCreate_t _DonutCreate;
    DonutDelete_t _DonutDelete;
    DonutError_t  _DonutError;
    
    // need at least a file
    if(argc != 2) {
      printf("  [ usage: donut_dynamic <file>\n");
      return 0;
    }
    
    // try load donut.dll or donut.so
    #if defined(WINDOWS)
      HMODULE m = LoadLibrary("donut.dll");
      if(m != NULL) {
        _DonutCreate = (DonutCreate_t)GetProcAddress(m, "DonutCreate");
        _DonutDelete = (DonutDelete_t)GetProcAddress(m, "DonutDelete");
        _DonutError  = (DonutError_t) GetProcAddress(m, "DonutError");
        
        if(_DonutCreate == NULL || _DonutDelete == NULL || _DonutError == NULL) {
          printf("  [ Unable to resolve Donut API.\n");
          return 0;
        }
      } else {
        printf("  [ Unable to load donut.dll.\n");
        return 0;
      }
    #else
      void *m = dlopen("donut.so", RTLD_LAZY);
      if(m != NULL) {
        _DonutCreate = (DonutCreate_t)dlsym(m, "DonutCreate");
        _DonutDelete = (DonutDelete_t)dlsym(m, "DonutDelete");
        _DonutError  = (DonutError_t) dlsym(m, "DonutError");
        
        if(_DonutCreate == NULL || _DonutDelete == NULL || _DonutError == NULL) {
          printf("  [ Unable to resolve Donut API.\n");
          return 0;
        }
      } else {
        printf("  [ Unable to load donut.so.\n");
        return 0;
      }
    #endif
  
    memset(&c, 0, sizeof(c));
    
    // copy input file
    lstrcpyn(c.input, argv[1], DONUT_MAX_NAME-1);
    
    // default settings
    c.inst_type = DONUT_INSTANCE_EMBED;   // file is embedded
    c.arch      = DONUT_ARCH_X84;         // dual-mode (x86+amd64)
    c.bypass    = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails
    c.format    = DONUT_FORMAT_BINARY;    // default output format
    c.compress  = DONUT_COMPRESS_NONE;    // compression is disabled by default
    c.entropy   = DONUT_ENTROPY_DEFAULT;  // enable random names + symmetric encryption by default
    c.exit_opt  = DONUT_OPT_EXIT_THREAD;  // default behaviour is to exit the thread
    c.thread    = 1;                      // run entrypoint as a thread
    c.unicode   = 0;                      // command line will not be converted to unicode for unmanaged DLL function
    
    // generate the shellcode
    err = _DonutCreate(&c);
    if(err != DONUT_ERROR_SUCCESS) {
      printf("  [ Error : %s\n", _DonutError(err));
      return 0;
    } 
    
    printf("  [ loader saved to %s\n", c.output);
    
    _DonutDelete(&c);
    return 0;
}
