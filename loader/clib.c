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

// functions to replace intrinsic C library functions

// funnily enough, MSVC still tries to replace this
// with memset hence the use of assembly..
void *Memset (void *ptr, int value, size_t num) {

    #ifdef _MSC_VER
    __stosb(ptr, value, num);
    #else
    unsigned char *p = (unsigned char*)ptr;
    
    while(num--) {
      *p = (unsigned char)value;
      p++;
    }
    #endif
    return ptr;
}

void *Memcpy (void *destination, const void *source, size_t num) {
    unsigned char *out = (unsigned char*)destination;
    unsigned char *in  = (unsigned char*)source;
    
    while(num--) {
      *out = *in;
      out++; in++;
    }
    return destination;
}

int Memcmp(const void *ptr1, const void *ptr2, size_t num) {
    register const unsigned char *s1 = (const unsigned char*)ptr1;
    register const unsigned char *s2 = (const unsigned char*)ptr2;

    while (num-- > 0) {
      if (*s1++ != *s2++)
        return s1[-1] < s2[-1] ? -1 : 1;
    }
    return 0;
}
