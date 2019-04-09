
// MSVC automatically optimizes some for loops with memset
// 
#include "clib.h"

#pragma function(memset)
void* memset(void *buf, int c, size_t len) {
    uint8_t *p = (uint8_t*)buf;
    while(len--) {
      *p++ = (uint8_t)c;
    }
    return buf;
}