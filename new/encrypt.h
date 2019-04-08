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

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdint.h>

#if !defined(AES) && !defined(CHASKEY) && !defined(CHAM) && !defined(NOEKEON)
#define CHASKEY
#endif

#ifndef ROTR32
#define ROTR32(v,n)(((v)>>(n))|((v)<<(32-(n))))
#endif

// at the moment, all ciphers support a 128-bit block with 128-bit key
#define CIPHER_BLK_LEN (128/8)
#define CIPHER_KEY_LEN (128/8)

#if defined(CHAM)
  // CHAM-128/128
  #define ENCRYPT cham
#elif defined(CHASKEY)
  // CHASKEY-128/128
  #define ENCRYPT chaskey
#elif defined(NOEKEON)
  // NOEKEON-128/128
  #define ENCRYPT noekeon
#elif defined(AES)
  // AES-128/128
  #define ENCRYPT aes
#endif

#ifdef __cplusplus
extern "C" {
#endif

void encrypt(void *mk, void *ctr, void *data, size_t len);

#define decrypt(mk,ctr,data,len) encrypt(mk,ctr,data,len)

#ifdef __cplusplus
}
#endif

#endif
