

// test unit for decode.asm
// odzhan

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <fcntl.h>

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS
#include <windows.h>
#include "mmap.h"
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "crypt32.lib")
#endif
#else
#define LINUX
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#endif

#include "decode.h"

uint32_t hash_string(const char *str) {
    char     c;
    uint32_t h = 0;
    
    do {
      c = *str++;
      if(c == 0) break;
      h += (c | 0x20);
      h = (h << 32-8) | (h >> 8);
    } while(c != 0);
    
    return h;
}

void bin2hex(void *bin, int len) {
    int i;
    uint8_t *p=(uint8_t*)bin;
    
    for(i=0; i<8; i++) printf(" %02x", p[i]);
}

int main(int argc, char *argv[]) {
    struct stat fs;
    int         in;
    FILE        *out;
    char        *infile, *outfile;
    DWORD       inlen, outlen;
    PVOID       outbuf, inbuf;
    
    if(argc != 3) {
      printf("\nusage: encode <infile> <outfile>\n");
      return 0;
    }
    
    infile  = argv[1];
    outfile = argv[2];
    
    if(stat(infile, &fs) != 0) {
      printf("unable to access %s\n", infile);
      return -1;
    }
    
    in = open(infile, O_RDONLY);
    if(in < 0) {
      printf("unable to open %s.\n", infile);
      return -1;
    }
    
    out = fopen(outfile, "wb");
    if(out < 0) {
      printf("unable to open %s for writing.\n", outfile);
      close(in);
      return -1;
    }
    
    inlen = fs.st_size;
    inbuf = mmap(NULL, inlen, PROT_READ, MAP_PRIVATE, in, 0);
    
    if(inbuf != NULL) {
      outlen = 0;
      if(CryptBinaryToString(inbuf, inlen, 
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outlen)) 
      {
        outbuf = calloc(1, outlen + DECODE_SIZE + 8);
        if(outbuf != NULL) {
          if(CryptBinaryToString(inbuf, inlen, 
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, outbuf, &outlen))
          {
            fwrite(DECODE, 1, DECODE_SIZE, out);
            fwrite(outbuf, 1, outlen, out);
          } else {
            printf("CryptBinaryToString failed.\n");
          }
          free(outbuf);
        } else {
          printf("unable to allocate memory.\n");
        }
      } else {
        printf("unable to obtain length\n");
      }
      munmap(inbuf, inlen);
    } else {
      printf("unable to map\n");
    }
    fclose(out);
    close(in);    
    return 0;
}
