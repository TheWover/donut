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

char* get_param (int argc, char *argv[], int *i) {
    int n=*i;
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
    
    if(CreatePayload(&c)) {
      if(c.type == DONUT_INSTANCE_URL) {
        printf("  [ module written to %s\n", c.modname);
        printf("  [ make it accessible at %s\n", c.url);
      }
    }
    return 0;
}
