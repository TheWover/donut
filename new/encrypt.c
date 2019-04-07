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

#if defined(CHAM)
void cham(void *mk, void *p){
    uint32_t rk[8],*w=p,*k=mk,i,t;

    // create sub keys from 128-bit key
    for(i=0;i<4;i++) {
      t=k[i]^ROTR32(k[i],31),
      rk[i]=t^ROTR32(k[i],24),
      rk[(i+4)^1]=t^ROTR32(k[i],21);
    }
    // encrypt 128-bits
    for(i=0;i<80;i++) {
      t=w[3],w[0]^=i,w[3]=rk[i&7],
      w[3]^=ROTR32(w[1],(i&1)?24:31),
      w[3]+=w[0],
      w[3]=ROTR32(w[3],(i&1)?31:24),
      w[0]=w[1],w[1]=w[2],w[2]=t;
    }
}
#elif defined(CHASKEY)
void chaskey(void *mk, void *p) {
    uint32_t i,*w=p,*k=mk;

    // add key
    for(i=0;i<4;i++) w[i]^=k[i];
    // apply permutation
    for(i=0;i<16;i++) {
      w[0]+=w[1],
      w[1]=ROTR32(w[1],27)^w[0],
      w[2]+=w[3],
      w[3]=ROTR32(w[3],24)^w[2],
      w[2]+=w[1],
      w[0]=ROTR32(w[0],16)+w[3],
      w[3]=ROTR32(w[3],19)^w[0],
      w[1]=ROTR32(w[1],25)^w[2],
      w[2]=ROTR32(w[2],16);
    }
    // add key
    for(i=0;i<4;i++) w[i]^=k[i];
}
#elif defined(NOEKEON)
void noekeon(void *mk, void *p) {
    uint32_t t,*k=mk,*w=p;
    uint8_t  rc=128;

    // perform 16 rounds of encryption
    for(;;) {
      w[0]^=rc;t=w[0]^w[2];t^=ROTR32(t,8)^ROTR32(t,24);
      w[1]^=t;w[3]^=t;w[0]^=k[0];w[1]^=k[1];
      w[2]^=k[2];w[3]^=k[3];t=w[1]^w[3];
      t^=ROTR32(t,8)^ROTR32(t,24);w[0]^=t;w[2]^=t;
      if(rc==212)break;
      rc=((rc<<1)^((-(rc>>7))&27));
      w[1]=ROTR32(w[1],31);w[2]=ROTR32(w[2],27);w[3]=ROTR32(w[3],30);
      w[1]^=~(w[3]|w[2]);t=w[3];w[3]=w[0]^(w[2]&w[1]);w[0]=t;
      w[2]^=w[0]^w[1]^w[3];w[1]^=~(w[3]|w[2]);w[0]^=w[2]&w[1];
      w[1]=ROTR32(w[1],1);w[2]=ROTR32(w[2],5);w[3]=ROTR32(w[3],2);
    }
}
#elif defined(AES)
uint32_t M(uint32_t x) {
    uint32_t t=x&0x80808080;
    return((x^t)<<1)^((t>>7)*0x1b);
}
// SubByte
uint8_t S(uint8_t x) {
    uint8_t i,y,c;
    if(x) {
      for(c=i=0,y=1;--i;y=(!c&&y==x)?c=1:y,y^=M(y));
      x=y;
      for(i=0;i<4;i++) {
        x^=y=(y<<1)|(y>>7);
      }
    }
    return x^99;
}
void aes(void *mk, void *data) {
    uint32_t c=1,i,w,x[4],k[4],*s=(uint32_t*)data;

    // copy 128-bit plain text + 128-bit master key to x
    for(i=0;i<4;i++) {
      x[i]=s[i], k[i]=((uint32_t*)mk)[i];
    }
    for(;;) {
      // 1st part of ExpandKey
      w=k[3];
      for(i=0;i<4;i++) {
        w=(w&-256)|S(w&255), w=R(w,8);
      }
      // AddConstant, AddRoundKey, 2nd part of ExpandKey
      w=R(w, 8)^c;
      for(i=0;i<4;i++) {
        ((uint32_t*)s)[i]=x[i]^k[i], w=k[i]^=w;
      }
      // if round 11, stop
      if(c==108)break; 
      // update constant
      c=M(c);
      // SubBytes and ShiftRows
      for(i=0;i<AES_BLK_LEN;i++) {
        ((uint8_t*)x)[(i%4)+(((i/4)-(i%4))%4)*4]=S(((uint8_t*)s)[i]);
      }
      // if not round 11, MixColumns
      if(c!=108) {
        for(i=0;i<4;i++) {
          w=x[i],x[i]=R(w,8)^R(w,16)^R(w,24)^M(R(w,8)^w);
        }
      }
    }
}
#endif

// encrypt/decrypt data in counter mode
void encrypt(void *mk, void *ctr, void *data, size_t len) {
    uint8_t  x[CIPHER_BLK_LEN], 
             *p=(uint8_t*)data,
             *c=(uint8_t*)ctr;
    int      i, r;
    
    while(len) {
      // copy counter+nonce to local buffer
      for(i=0;i<CIPHER_BLK_LEN;i++) 
        x[i] = c[i];
      
      // encrypt x
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

