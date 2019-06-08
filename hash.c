/**
  BSD 3-Clause License

  Copyright (c) 2017 Odzhan. All rights reserved.

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

#include "hash.h"

// SPECK-64/128
static uint64_t speck(void *mk, uint64_t p) {
    uint32_t k[4], i, t;
    union {
      uint32_t w[2];
      uint64_t q;
    } x;
    
    // copy 64-bit plaintext to local buffer
    x.q = p;
    
    // copy 128-bit master key to local buffer
    for(i=0;i<4;i++) k[i]=((uint32_t*)mk)[i];
    
    for(i=0;i<27;i++) {
      // encrypt 64-bit plaintext
      x.w[0] = (ROTR32(x.w[0], 8) + x.w[1]) ^ k[0];
      x.w[1] =  ROTR32(x.w[1],29) ^ x.w[0];
      
      // create next 32-bit subkey
      t = k[3];
      k[3] = (ROTR32(k[1], 8) + k[0]) ^ i;
      k[0] =  ROTR32(k[0],29) ^ k[3];
      k[1] = k[2]; k[2] = t;
    }
    // return 64-bit ciphertext
    return x.q;
}

uint64_t maru(const void *input, uint64_t iv) {
    uint64_t h;
    uint32_t len, idx, end;
    const char *api = (const char*)input;
    
    union {
      uint8_t  b[MARU_BLK_LEN];
      uint32_t w[MARU_BLK_LEN/4];
    } m;
    
    // set H to initial value
    h = iv;
    
    for(idx=0, len=0, end=0;!end;) {
      // end of string or max len?
      if(api[len] == 0 || len == MARU_MAX_STR) {
        // zero remainder of M
        Memset(&m.b[idx], 0, MARU_BLK_LEN - idx);
        // store the end bit
        m.b[idx] = 0x80;
        // have we space in M for api length?
        if(idx >= MARU_BLK_LEN - 4) {
          // no, update H with E
          h ^= MARU_CRYPT(&m, h);
          // zero M
          Memset(&m, 0, MARU_BLK_LEN);
        }
        // store total length in bits
        m.w[(MARU_BLK_LEN/4)-1] = (len * 8);
        idx = MARU_BLK_LEN;
        end++;
      } else {    
        // store character from api string
        m.b[idx] = (uint8_t)api[len]; 
        idx++; len++;
      }
      if(idx == MARU_BLK_LEN) {
        // update H with E
        h ^= MARU_CRYPT(&m, h);
        // reset idx
        idx = 0;
      }
    }  
    return h;
}

#ifdef TEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    
    uint64_t ulDllHash, ulApiHash, iv;
    char     *api, *dll;
    
    if(argc != 4) {
      printf("\nusage: maru <iv> <dll> <api>\n");
      return 0;
    }
    
    // convert hexadecimal IV to binary
    iv  = strtoull(argv[1], NULL, 16);
    dll = argv[2];
    api = argv[3];
    
    printf("\nIV  : %p\n", (void*)iv);
    
    ulDllHash = maru(dll, iv);
    printf("DLL : %p\n", (void*)ulDllHash);
    
    ulApiHash = maru(api, iv) + ulDllHash;
    printf("API : %p\n", (void*)ulApiHash);
    
    return 0;
}
#endif
