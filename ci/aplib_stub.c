#include "aplib.h"

unsigned int aP_pack(const void *source, void *destination, unsigned int length,
                     void *workmem,
                     int (*callback)(unsigned int, unsigned int, unsigned int, void *),
                     void *cbparam) {
  (void)source;
  (void)destination;
  (void)length;
  (void)workmem;
  (void)callback;
  (void)cbparam;
  return APLIB_ERROR;
}

unsigned int aP_workmem_size(unsigned int inputsize) {
  (void)inputsize;
  return 0;
}

unsigned int aP_max_packed_size(unsigned int inputsize) {
  return inputsize;
}

unsigned int aP_depack_asm(const void *source, void *destination) {
  (void)source;
  (void)destination;
  return APLIB_ERROR;
}

unsigned int aP_depack_asm_fast(const void *source, void *destination) {
  (void)source;
  (void)destination;
  return APLIB_ERROR;
}

unsigned int aP_depack_asm_safe(const void *source, unsigned int srclen,
                                void *destination, unsigned int dstlen) {
  (void)source;
  (void)srclen;
  (void)destination;
  (void)dstlen;
  return APLIB_ERROR;
}

unsigned int aP_crc32(const void *source, unsigned int length) {
  (void)source;
  (void)length;
  return 0;
}

unsigned int aPsafe_pack(const void *source, void *destination, unsigned int length,
                         void *workmem,
                         int (*callback)(unsigned int, unsigned int, unsigned int, void *),
                         void *cbparam) {
  return aP_pack(source, destination, length, workmem, callback, cbparam);
}

unsigned int aPsafe_check(const void *source) {
  (void)source;
  return APLIB_ERROR;
}

unsigned int aPsafe_get_orig_size(const void *source) {
  (void)source;
  return APLIB_ERROR;
}

unsigned int aPsafe_depack(const void *source, unsigned int srclen,
                           void *destination, unsigned int dstlen) {
  return aP_depack_asm_safe(source, srclen, destination, dstlen);
}
