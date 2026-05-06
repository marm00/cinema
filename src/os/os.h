#ifndef CIN_OS_H
#define CIN_OS_H

#include <stdbool.h>
#include <stdint.h>

extern struct Cin_System {
  size_t page_size;
  uint32_t alloc_type;
  int32_t threads;
} cin_system;

void *os_alloc(size_t bytes);
bool init_os(void);
void os_random(uint32_t *out);
void os_sleep(long millis);

#ifdef _WIN32
// https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
// A path can have 248 "characters" (260 - 12 = 248)
// with 12 reserved for 8.3 file name.
// This refers to a WCHAR sequence (UTF-16 code units),
// i.e., wchar_t, such that max bytes = (248 * 2) = 496
// of UTF-16 data or (260 * 2) = 520 upper bound
// This is different from the full storage since
// a surrogate pair character can hold 2 wchar_t or
// (260 * 2 * 2) = 1040 bytes, exceeding the bound
// if many/all characters need 2 code units
// The cFileName from winapi uses a wchar_t buffer of
// 260 (MAX_PATH) so surrogate pairs get truncated
#define CIN_MAX_PATH MAX_PATH
#define CIN_MAX_PATH_BYTES (MAX_PATH * 4)
#else
#define CIN_MAX_PATH PATH_MAX
#define CIN_MAX_PATH_BYTES CIN_MAX_PATH
#endif

#endif