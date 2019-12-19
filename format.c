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

#include "format.h"

/**
  Encoding: base64
  Author  : Odzhan
  
  Encoding: c, python, ruby, c#, powershell and hex
  Author  : BITAM Salim https://github.com/soolidsnake
*/

// calculate length of buffer required for base64 encoding
#define B64_LEN(N) (((4 * (N / 3)) + 4) & -4)

static const char b64_tbl[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  
// Compact implementation of base64 encoding.
// The main encoding loop is inspired by Qkumba AKA Peter Ferrie.
// This uses a lookup table and accounts for unaligned input.
//
// odzhan
//
static int b64_encode(
  const void *src, uint32_t inlen, 
  void *dst, uint32_t *outlen) 
{
    uint32_t i, len, x;
    uint8_t  *in = (uint8_t*)src, *out = (uint8_t*)dst;
    
    // check arguments
    if(outlen == NULL) return 0;
    
    // calculate length of buffer required for encoded string
    len = B64_LEN(inlen);
    
    // return the length?
    if(out == NULL) {
      *outlen = len;
      return 1;
    }
    
    // can buffer contain string?
    if(len > *outlen) return 0;
    
    // main encoding loop
    while(inlen != 0) {
      // load 3 bytes or whatever remains
      for(x=i=0; i<3; i++) {
        // add byte from input or zero
        x |= ((i < inlen) ? *in++ : 0); 
        x <<= 8;
      }
      // increase by 1
      inlen++;
      // encode 3 bytes
      for(i=4; inlen && i>0; i--) {
        x = ROTL32(x, 6);
        *out++ = b64_tbl[x % 64];
        --inlen;
      }
    }
    // if required, add padding
    while(i!=0) { *out++ = '='; i--; }
    // add null terminator
    *out = 0;
    // calculate output length by subtracting 2 pointers
    *outlen = (uint32_t)(out - (uint8_t*)dst);
    return 1;
}

int base64_template(void *pic, uint32_t pic_len, FILE *fd) {
    uint32_t outlen;
    void     *base64;
    
    DPRINT("Calculating length of base64 encoding");
    if(b64_encode(NULL, pic_len, NULL, &outlen)) {
      DPRINT("Required length is %"PRId32, outlen);
      base64 = calloc(1, outlen + 1);
      if(base64 == NULL) {
        return DONUT_ERROR_NO_MEMORY;
      }
      DPRINT("Encoding shellcode");
      if(b64_encode(pic, pic_len, base64, &outlen)) {
        DPRINT("Writing %"PRId32 " bytes to file", outlen);
        fwrite(base64, 1, outlen, fd);
      }
    }
    // if on windows, copy base64 string to clipboard
    #if defined(WINDOWS)
      LPTSTR  strCopy;
      HGLOBAL hCopy;
      
      DPRINT("Opening clipboard");
      if(OpenClipboard(NULL)) {
        DPRINT("Empying contents");
        EmptyClipboard();
        
        DPRINT("Allocating memory");
        hCopy = GlobalAlloc(GMEM_MOVEABLE, outlen);
        if(hCopy != NULL) {
          strCopy = GlobalLock(hCopy);
          // copy base64 string to memory
          CopyMemory(strCopy, base64, outlen);
          GlobalLock(hCopy);
          DPRINT("Setting clipboard data");
          // copy to clipboard
          SetClipboardData(CF_TEXT, hCopy);
          GlobalFree(hCopy);
        }
        CloseClipboard();              
      }
    #endif
    DPRINT("Freeing memory");
    free(base64);
    return DONUT_ERROR_SUCCESS;
}

int c_ruby_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j;
    uint8_t *p = (uint8_t*)pic;
    
    fprintf(fd, "unsigned char buf[] = \n");
    
    for(j=0; j < pic_len; j++) {
      if(j % 16 == 0) fputc('\"', fd);
      
      fprintf(fd, "\\x%02x", p[j]);

      if(j % 16 == 15){
        fprintf(fd, "\"\n");
      }
    }
    if(j % 16 != 15) fputc('\"', fd);

    fputc(';', fd);
    
    return DONUT_ERROR_SUCCESS;
}

int py_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j;
    uint8_t *p = (uint8_t*)pic;

    fprintf(fd, "buf   = \"\"\n");

    for(j=0; j < pic_len; j++){
      if(j % 16 == 0) {
        fprintf(fd, "buff += \"");
      }
      fprintf(fd, "\\x%02x", p[j]);

      if(j % 16 == 15) {
        fprintf(fd, "\"\n");
      }
    }
    if(j % 16 != 15) {
      fputc('\"', fd);
    }
    return DONUT_ERROR_SUCCESS;
}

int powershell_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j;
    uint8_t *p = (uint8_t*)pic;
    
    fprintf(fd, "[Byte[]] $buf = ");

    for(j=0; j < pic_len; j++){
      fprintf(fd, "0x%02x", p[j]);
      if(j < pic_len-1) fputc(',', fd);
    }
    return DONUT_ERROR_SUCCESS;
}

int csharp_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j;
    uint8_t *p = (uint8_t*)pic;

    fprintf(fd, "byte[] my_buf = new byte[%" PRId32"] {\n", pic_len);

    for(j=0; j < pic_len; j++){
      fprintf(fd, "0x%02x", p[j]);
      if(j < pic_len-1) fputc(',', fd);
    }
    fprintf(fd, "};");
    
    return DONUT_ERROR_SUCCESS;
}

int hex_template(void * pic, uint32_t pic_len, FILE* fd){
    uint32_t j;
    uint8_t *p = (uint8_t*)pic;
    
    for(j=0; j < pic_len; j++){
      fprintf(fd, "\\x%02x", p[j]);
    }
    return DONUT_ERROR_SUCCESS;
}

