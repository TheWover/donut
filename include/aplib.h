/*
 * aPLib compression library  -  the smaller the better :)
 *
 * ELF 64-bit format header file
 *
 * Copyright (c) 1998-2014 Joergen Ibsen
 * All Rights Reserved
 *
 * http://www.ibsensoftware.com/
 */

#ifndef APLIB_H_INCLUDED
#define APLIB_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR ((unsigned int) (-1))
#endif

unsigned int aP_pack(const void *source,
                     void *destination,
                     unsigned int length,
                     void *workmem,
                     int (*callback)(unsigned int, unsigned int, unsigned int, void *),
                     void *cbparam);

unsigned int aP_workmem_size(unsigned int inputsize);

unsigned int aP_max_packed_size(unsigned int inputsize);

unsigned int aP_depack_asm(const void *source, void *destination);

unsigned int aP_depack_asm_fast(const void *source, void *destination);

unsigned int aP_depack_asm_safe(const void *source,
                                unsigned int srclen,
                                void *destination,
                                unsigned int dstlen);

unsigned int aP_crc32(const void *source, unsigned int length);

unsigned int aPsafe_pack(const void *source,
                         void *destination,
                         unsigned int length,
                         void *workmem,
                         int (*callback)(unsigned int, unsigned int, unsigned int, void *),
                         void *cbparam);

unsigned int aPsafe_check(const void *source);

unsigned int aPsafe_get_orig_size(const void *source);

unsigned int aPsafe_depack(const void *source,
                           unsigned int srclen,
                           void *destination,
                           unsigned int dstlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* APLIB_H_INCLUDED */
