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

#ifndef MARU_H
#define MARU_H

#include <stdint.h>
#include <string.h>

void *Memset (void *ptr, int value, size_t num);

#define MARU_MAX_STR  64
#define MARU_BLK_LEN  16
#define MARU_HASH_LEN  8
#define MARU_IV_LEN    MARU_HASH_LEN
#define MARU_CRYPT     speck

#ifndef ROTR32
#define ROTR32(v,n)(((v)>>(n))|((v)<<(32-(n))))
#endif

#ifndef ROTL32
#define ROTL32(v,n)(((v)<<(n))|((v)>>(32-(n))))
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint64_t maru(const void *api, uint64_t iv);

#ifdef __cplusplus
}
#endif

#endif
