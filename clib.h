
#ifndef CLIB_H
#define CLIB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma intrinsic(memset)
void* __fastcall memset(void*, int, size_t);

#ifdef __cplusplus
}
#endif

#endif
