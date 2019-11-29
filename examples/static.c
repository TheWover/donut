
// static example (doesn't work with .NET DLL)
// odzhan

#include "donut.h"

int main(int argc, char *argv[]) {
    DONUT_CONFIG c;
    int          err;
    
    // need at least a file
    if(argc != 2) {
      printf("  [ usage: donut_static <file>\n");
      return 0;
    }
    
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
    err = DonutCreate(&c);
    if(err != DONUT_ERROR_SUCCESS) {
      printf("  [ Error : %s\n", DonutError(err));
      return 0;
    } 
    
    printf("  [ loader saved to %s\n", c.output);
    
    DonutDelete(&c);
    return 0;
}
