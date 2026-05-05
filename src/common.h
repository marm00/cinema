#ifndef CIN_COMMON_H
#define CIN_COMMON_H

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

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

static inline int32_t lcps_from(const uint8_t *a, const uint8_t *b, int32_t start) {
  a += start;
  b += start;
  int32_t matching = start;
  while (*a && *b && *(a++) == *(b++)) ++matching;
  return matching;
}

static inline int32_t lcps(const uint8_t *a, const uint8_t *b) {
  return lcps_from(a, b, 0);
}

static inline bool cin_isloweralpha(char c) {
  return c <= 'z' && c >= 'a';
}

static inline char cin_lower(char c) {
  // NOTE: Might want to use LCMapString on Windows
  return (char)tolower(c);
}

static inline bool cin_lower_isalpha(char *out) {
  *out = cin_lower(*out);
  return cin_isloweralpha(*out);
}

static inline bool cin_isnum(char c) {
  return c <= '9' && c >= '0';
}

static inline bool cin_isnum_1based(char c) {
  return c <= '9' && c >= '1';
}

static inline bool cin_wisloweralpha(wchar_t c) {
  return c <= L'z' && c >= L'a';
}

static inline bool cin_wisnum(wchar_t c) {
  return c <= L'9' && c >= L'0';
}

static inline bool cin_wisnum_1based(wchar_t c) {
  return c <= L'9' && c >= L'1';
}

static inline void cin_getnum(const char **p, int64_t *out) {
  *out = 0;
  while (cin_isnum(**p)) {
    *out *= 10;
    *out += **p - '0';
    ++*p;
  }
}

static inline bool cin_iscontinuatioon(char c) {
  return ((uint8_t)c & 0xC0) == 0x80;
}

static inline void cin_sleep(long millis) {
#ifdef _WIN32
  Sleep((DWORD)millis);
#else
  ssize_t nanos = millis * 1000 * 1000;
  struct timespec duration = {
      .tv_sec = nanos / (1000 * 1000 * 1000),
      .tv_nsec = nanos % (1000 * 1000 * 1000)};
  nanosleep(&duration, 0);
#endif
}

#endif