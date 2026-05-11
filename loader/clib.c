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

#include <inttypes.h>
#include <stddef.h>

#if defined(USE_CRT) && USE_CRT
#include <string.h>
#endif

// functions to replace intrinsic C library functions

#ifndef USE_CRT

#include <stddef.h>

#ifdef _MSC_VER
#pragma function(memcpy)
#pragma function(memset)
#pragma function(memcmp)
#endif

void *memcpy(void *dst, const void *src, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    while (len--)
        *d++ = *s++;

    return dst;
}

void *memset(void *dst, int value, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    unsigned char v = (unsigned char)value;

    while (len--)
        *d++ = v;

    return dst;
}

int memcmp(const void *a, const void *b, size_t len)
{
    const unsigned char *p1 = (const unsigned char *)a;
    const unsigned char *p2 = (const unsigned char *)b;

    while (len--)
    {
        if (*p1 != *p2)
            return (int)*p1 - (int)*p2;

        p1++;
        p2++;
    }

    return 0;
}

#endif


void *Memset(void *ptr, int value, uint32_t num)
{
    memset(ptr, value, (size_t)num);
    return NULL;
}

void *Memcpy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return NULL;
}

int compare(const char *s1, const char *s2) 
{
    while(*s1 && *s2) {
      if(*s1 != *s2) {
        return 0;
      }
      s1++; s2++;
    }
    return *s2 == 0;
}

const char* _strstr(const char *s1, const char *s2) {
    while (*s1) {
      if((*s1 == *s2) && compare(s1, s2)) return s1;
      s1++;
    }
    return NULL;
}

int _strcmp(const char *str1, const char *str2) {
    while (*str1 && *str2) {
      if(*str1 != *str2) break;
      str1++; str2++;
    }
    return (int)*str1 - (int)*str2;
}

/*  Note by TheWover:
    A bug was introduced when merging the loader changes by S4ntiagoP that,
      while replacing strcmpcase with stricmp broke MSVC compilation.

    A suggestion was made by dismantl: https://github.com/S4ntiagoP/donut/pull/2/files

    This suggestion was integrated. Git did not allow merging their PR into the source repo.
    So I am crediting them via comment instead.

*/

int stricmp(const char *str1, const char *str2) {
    while (*str1 && *str2) {
      if ((*str1 | 0x20) != (*str2 | 0x20)) break;
      str1++; str2++;
    }
    return (int)*str1 - (int)*str2;
}
