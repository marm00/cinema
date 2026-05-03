#ifndef CIN_COMMON_H
#define CIN_COMMON_H

#include "os.h"
#include <assert.h>
#include <limits.h>
#include <stdint.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))
#define align(a, b) (((a) + (b) - 1) & (~((b) - 1)))
#define CIN_PTR ((uint32_t)__SIZEOF_POINTER__)
#define align_size(T) max(CIN_PTR, __alignof(T))
#define align_to_size(n) align((n), CIN_PTR)
#define block_bytes(n) ((n) * (CIN_PTR * 8))
#define align_to_block(n) align((n), block_bytes(1))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define kilobytes(n) ((n) << 10)
#define megabytes(n) ((n) << 20)
#define gigabytes(n) ((n) << 30)
#define cin_ispow2(n) ((n) && ((n) & ((n) - 1)) == 0)
#define cin_strlen(str) (sizeof((str)) / sizeof(*(str)) - 1)

static inline uint32_t log2_floor(uint32_t n) {
  assert(n > 0U && "0 is undefined behavior");
  return 31U - (uint32_t)__builtin_clz(n);
}

static inline uint32_t log2_ceil(uint32_t n) {
  assert(n > 1U && "1 is not divisible by 2");
  return 32U - (uint32_t)__builtin_clz(n - 1U);
}

static inline uint32_t pow2(uint32_t exponent) {
  assert(exponent <= 31U);
  return 1U << exponent;
}

static inline uint32_t rand_between(uint32_t min, uint32_t max) {
  assert(max >= min);
  const uint32_t range = max - min + 1;
  assert(range);
  const uint32_t upper = UINT_MAX - (UINT_MAX % range);
  uint32_t random;
  do os_random(&random);
  while (random >= upper);
  return min + (random % range);
}

#endif