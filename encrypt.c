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

#include "encrypt.h"

static void chaskey(void *mk, void *p) {
    uint32_t i,*w=p,*k=mk;

    // add 128-bit master key
    for(i=0;i<4;i++) w[i]^=k[i];
    
    // apply 16 rounds of permutation
    for(i=0;i<16;i++) {
      w[0] += w[1],
      w[1]  = ROTR32(w[1], 27) ^ w[0],
      w[2] += w[3],
      w[3]  = ROTR32(w[3], 24) ^ w[2],
      w[2] += w[1],
      w[0]  = ROTR32(w[0], 16) + w[3],
      w[3]  = ROTR32(w[3], 19) ^ w[0],
      w[1]  = ROTR32(w[1], 25) ^ w[2],
      w[2]  = ROTR32(w[2], 16);
    }
    // add 128-bit master key
    for(i=0;i<4;i++) w[i]^=k[i];
}

// encrypt/decrypt data in counter mode
void donut_encrypt(void *mk, void *ctr, void *data, size_t len) {
    uint8_t  x[CIPHER_BLK_LEN], 
             *p=(uint8_t*)data,
             *c=(uint8_t*)ctr;
    int      i, r;
    
    while(len) {
      // copy counter+nonce to local buffer
      for(i=0;i<CIPHER_BLK_LEN;i++) 
        x[i] = c[i];
      
      // donut_encrypt x
      ENCRYPT(mk, &x);
      
      // XOR plaintext with ciphertext
      r = len > CIPHER_BLK_LEN ? CIPHER_BLK_LEN : len;
      
      for(i=0;i<r;i++) 
        p[i] ^= x[i];
      
      // update length + position
      len -= r; p += r;
      
      // update counter
      for(i=CIPHER_BLK_LEN;i>0;i--)
        if(++c[i-1]) break;
    }
}

#ifdef TEST

#include <stdio.h>
#include <string.h>
#include <stdint.h>

// 128-bit master key
uint8_t key[16] =
{ 0x56, 0x09, 0xe9, 0x68, 0x5f, 0x58, 0xe3, 0x29,
  0x40, 0xec, 0xec, 0x98, 0xc5, 0x22, 0x98, 0x2f };
  
// 128-bit plain text
uint8_t plain[16]=
{ 0xb8, 0x23, 0x28, 0x26, 0xfd, 0x5e, 0x40, 0x5e,
  0x69, 0xa3, 0x01, 0xa9, 0x78, 0xea, 0x7a, 0xd8 };
  
// 128-bit cipher text
uint8_t cipher[16] =
{ 0xd5, 0x60, 0x8d, 0x4d, 0xa2, 0xbf, 0x34, 0x7b,
  0xab, 0xf8, 0x77, 0x2f, 0xdf, 0xed, 0xde, 0x07 };

int main(void) {
    uint8_t data[16];
    int     equ;

    memcpy(data, plain, 16);
    chaskey(key, data);
    equ = (memcmp(data, cipher, 16)==0);
    printf("Chaskey test : %s\n", equ ? "OK" : "FAILED");
    return 0;
}

#endif

