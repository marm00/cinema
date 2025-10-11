// Copyright (c) 2025 marm00

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "cJSON.h"
#include "libsais.h"

#if defined(CIN_OPENMP)
#include <omp.h>
#endif

typedef enum {
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} Cin_Log_Level;

static const Cin_Log_Level GLOBAL_LOG_LEVEL = LOG_DEBUG;
static const char *LOG_LEVELS[LOG_TRACE + 1] = {"ERROR", "WARNING", "INFO", "DEBUG", "TRACE"};

#define CIN_ARRAY_CAP 256
#define CIN_TABLE_CAP 64
#define CIN_ARRAY_GROWTH 2

#define array_ensure_capacity(a, total)                                      \
  do {                                                                       \
    if ((total) > (a)->capacity) {                                           \
      if (!(a)->capacity) (a)->capacity = CIN_ARRAY_CAP;                     \
      while ((total) > (a)->capacity) (a)->capacity *= CIN_ARRAY_GROWTH;     \
      (a)->items = realloc((a)->items, (a)->capacity * sizeof(*(a)->items)); \
      assert((a)->items && "Memory limit exceeded");                         \
    }                                                                        \
  } while (0)

#define array_free(a) free((a).items)

#define array_alloc(a, cap)                           \
  do {                                                \
    (a)->count = 0;                                   \
    (a)->capacity = (cap);                            \
    (a)->items = malloc((cap) * sizeof(*(a)->items)); \
    assert((a)->items && "Memory limit exceeded");    \
  } while (0)

#define array_nalloc(a, cap, ncap)               \
  do {                                           \
    array_alloc((a), (cap));                     \
    for (size_t i = 0; i < (a)->capacity; ++i) { \
      array_alloc(&(a)->items[i], (ncap));       \
    }                                            \
  } while (0)

#define array_reserve(a, n) array_ensure_capacity((a), (a)->count + (n))

#define array_resize(a, total)           \
  do {                                   \
    array_ensure_capacity((a), (total)); \
    (a)->count = (total);                \
  } while (0)

#define array_grow(a, n)     \
  do {                       \
    array_reserve((a), (n)); \
    (a)->count += (n);       \
  } while (0)

#define array_ngrow(a, n, ncap)                           \
  do {                                                    \
    array_reserve((a), (n));                              \
    for (size_t i = (a)->count; i < (a)->capacity; ++i) { \
      array_alloc(&(a)->items[i], (ncap));                \
    }                                                     \
    (a)->count += (n);                                    \
  } while (0)

#define array_push(a, item)            \
  do {                                 \
    array_reserve((a), 1);             \
    (a)->items[(a)->count++] = (item); \
  } while (0)

#define array_set(a, new_items, n)                              \
  do {                                                          \
    array_resize((a), (n));                                     \
    memcpy((a)->items, (new_items), (n) * sizeof(*(a)->items)); \
  } while (0)

#define warray_set(a, new_items, n)        \
  do {                                     \
    array_resize((a), (n));                \
    wmemcpy((a)->items, (new_items), (n)); \
  } while (0)

#define sarray_set(a, new_items)        \
  do {                                  \
    size_t n = sizeof((new_items)) - 1; \
    array_set((a), (new_items), n);     \
  } while (0)

#define array_extend(a, new_items, n)                                        \
  do {                                                                       \
    array_reserve((a), (n));                                                 \
    memcpy((a)->items + (a)->count, (new_items), (n) * sizeof(*(a)->items)); \
    (a)->count += (n);                                                       \
  } while (0)

#define warray_extend(a, new_items, n)                  \
  do {                                                  \
    array_reserve((a), (n));                            \
    wmemcpy((a)->items + (a)->count, (new_items), (n)); \
    (a)->count += (n);                                  \
  } while (0)

#define sarray_extend(a, new_items)     \
  do {                                  \
    size_t n = sizeof((new_items)) - 1; \
    array_extend((a), (new_items), n);  \
  } while (0);

#define array_splice(a, i, new_items, n)                              \
  do {                                                                \
    assert((i) <= (a)->count);                                        \
    array_reserve((a), (n));                                          \
    memmove((a)->items + (i) + (n),                                   \
            (a)->items + (i),                                         \
            ((a)->count - (i)) * sizeof(*(a)->items));                \
    memcpy((a)->items + (i), (new_items), (n) * sizeof(*(a)->items)); \
    (a)->count += (n);                                                \
  } while (0)

#define warray_splice(a, i, new_items, n)                                 \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((a), (n));                                              \
    wmemmove((a)->items + (i) + (n), (a)->items + (i), (a)->count - (i)); \
    wmemcpy((a)->items + (i), (new_items), (n));                          \
    (a)->count += (n);                                                    \
  } while (0)

#define array_insert(a, i, new_item)                     \
  do {                                                   \
    assert((i) <= (a)->count);                           \
    array_reserve((a), 1);                               \
    if ((i) < (a)->count) {                              \
      memmove((a)->items + (i) + 1,                      \
              (a)->items + (i),                          \
              ((a)->count - (i)) * sizeof(*(a)->items)); \
    }                                                    \
    (a)->items[(i)] = (new_item);                        \
    (a)->count++;                                        \
  } while (0)

#define warray_insert(a, i, new_item)                                     \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((a), 1);                                                \
    if ((i) < (a)->count) {                                               \
      wmemmove((a)->items + (i) + 1, (a)->items + (i), (a)->count - (i)); \
    }                                                                     \
    (a)->items[(i)] = (new_item);                                         \
    (a)->count++;                                                         \
  } while (0)

#define table_calloc(t, cap)                         \
  do {                                               \
    assert((t)->capacity == 0);                      \
    assert((cap) > 0);                               \
    assert((cap) % 2 == 0);                          \
    (t)->items = calloc((cap), sizeof(*(t)->items)); \
    (t)->capacity = (cap);                           \
    (t)->count = 0;                                  \
  } while (0)

#define table_double(t)                                      \
  do {                                                       \
    assert((t)->capacity > 0);                               \
    assert((t)->capacity % 2 == 0);                          \
    (t)->capacity <<= 1;                                     \
    (t)->items = calloc((t)->capacity, sizeof(*(t)->items)); \
    (t)->count = 0;                                          \
  } while (0)

#define table_free(t) free((t).items)

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
#define CIN_MAX_PATH_BYTES MAX_PATH * 4
#define CIN_MAX_WRITABLE_PATH MAX_PATH - 12
#define CIN_MAX_WRITABLE_PATH_BYTES (MAX_PATH - 12) * 4
#define CIN_COMMAND_PROMPT_LIMIT 8191
#define CIN_MAX_LOG_MESSAGE 1024

typedef struct Console_Message {
  wchar_t *items;
  DWORD count;
  DWORD capacity;
  struct Console_Message *prev;
  struct Console_Message *next;
} Console_Message;

#define CM_INIT_CAP 64

static Console_Message *create_console_message(void) {
  Console_Message *msg = malloc(sizeof(Console_Message));
  assert(msg);
#if defined(NDEBUG)
  wchar_t *items = malloc(CM_INIT_CAP * sizeof(wchar_t));
#else
  wchar_t *items = calloc(CM_INIT_CAP, sizeof(wchar_t));
#endif
  assert(items);
  msg->next = NULL;
  msg->prev = NULL;
  msg->items = items;
  msg->count = 0;
  msg->capacity = CM_INIT_CAP;
  return msg;
}

typedef struct REPL {
  Console_Message *msg;
  HANDLE out;
  HANDLE in;
  DWORD msg_index;
  COORD home;
  CONSOLE_CURSOR_INFO cursor_info;
  DWORD dwSize_X;
  DWORD _filled;
  DWORD in_mode;
  BOOL viewport_bound;
} REPL;

static REPL repl = {0};

#define CIN_SPACE 0x20
#define PREFIX_TOKEN L'>'
#define PREFIX 2
#define PREFIX_STR L"\r> "
#define PREFIX_ABS L">"
#define PREFIX_STRLEN (sizeof(PREFIX_STR) / sizeof(*(PREFIX_STR))) - 1
#define PREFIX_ABSLEN (sizeof(PREFIX_ABS) / sizeof(*(PREFIX_ABS))) - 1
#define WCRLF L"\r\n"
#define WCRLF_LEN 2
#define WCR L"\r"
#define WCR_LEN 1
#define CR "\r"
#define CR_LEN 1

static struct Console_Preview {
  wchar_t *items;
  DWORD count;
  DWORD capacity;
  DWORD len;
  COORD pos;
} preview = {0};

static struct Console_WWrite_Buffer {
  wchar_t *items;
  size_t count;
  size_t capacity;
} wwrite_buf = {0};

static struct Console_Write_Buffer {
  char *items;
  size_t count;
  size_t capacity;
} write_buf = {0};

static inline void wswrite(const wchar_t *str) {
  assert(wcslen(str) <= SIZE_MAX && "Corrupted string");
  WriteConsoleW(repl.out, str, (DWORD)wcslen(str), NULL, NULL);
}

static inline void wwrite(const wchar_t *str, DWORD len) {
  WriteConsoleW(repl.out, str, len, NULL, NULL);
}

static void wwritef(const wchar_t *format, ...) {
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
  int32_t len_i32 = _vscwprintf(format, args);
  assert(len_i32 >= 0);
  size_t len = (size_t)len_i32;
  va_end(args);
  array_resize(&wwrite_buf, len + 1);
  _vsnwprintf_s(wwrite_buf.items, len + 1, len, format, args_dup);
  va_end(args_dup);
  WriteConsoleW(repl.out, wwrite_buf.items, (DWORD)len, NULL, NULL);
}

static void wvwritef(const wchar_t *format, va_list args) {
  va_list args_dup;
  va_copy(args_dup, args);
  int32_t len_i32 = _vscwprintf(format, args_dup);
  assert(len_i32 >= 0);
  size_t len = (size_t)len_i32;
  va_end(args_dup);
  array_resize(&wwrite_buf, len + 1);
  _vsnwprintf_s(wwrite_buf.items, len + 1, len, format, args);
  WriteConsoleW(repl.out, wwrite_buf.items, (DWORD)len, NULL, NULL);
}

static inline void swrite(const char *str) {
  assert(strlen(str) <= SIZE_MAX && "Corrupted string");
  WriteConsoleA(repl.out, str, (DWORD)strlen(str), NULL, NULL);
}

static inline void write(const char *str, DWORD len) {
  WriteConsoleA(repl.out, str, len, NULL, NULL);
}

static void writef(const char *format, ...) {
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
  int32_t len_i32 = _vscprintf(format, args);
  assert(len_i32 >= 0);
  size_t len = (size_t)len_i32;
  va_end(args);
  array_resize(&write_buf, len + 1);
  _vsnprintf_s(write_buf.items, len + 1, len, format, args_dup);
  va_end(args_dup);
  WriteConsoleA(repl.out, write_buf.items, (DWORD)len, NULL, NULL);
}

static void vwritef(const char *format, va_list args) {
  va_list args_dup;
  va_copy(args_dup, args);
  int32_t len_i32 = _vscprintf(format, args_dup);
  assert(len_i32 >= 0);
  size_t len = (size_t)len_i32;
  va_end(args_dup);
  array_resize(&write_buf, len + 1);
  _vsnprintf_s(write_buf.items, len + 1, len, format, args);
  WriteConsoleA(repl.out, write_buf.items, (DWORD)len, NULL, NULL);
}

static inline void hide_cursor(void) {
  repl.cursor_info.bVisible = false;
  SetConsoleCursorInfo(repl.out, &repl.cursor_info);
}

static inline void show_cursor(void) {
  repl.cursor_info.bVisible = true;
  SetConsoleCursorInfo(repl.out, &repl.cursor_info);
}

static inline SHORT index_x(DWORD index, DWORD dwSize_X) {
  assert(index % dwSize_X <= SHRT_MAX);
  return (SHORT)(index % dwSize_X);
}

static inline SHORT index_x_repl(DWORD index) {
  return index_x(PREFIX + index, repl.dwSize_X);
}

static inline SHORT index_y(DWORD index, DWORD dwSize_X) {
  assert(index / dwSize_X <= SHRT_MAX);
  return (SHORT)(index / dwSize_X);
}

static inline SHORT index_y_repl(DWORD index) {
  return repl.home.Y + index_y(PREFIX + index, repl.dwSize_X);
}

static inline COORD index_to_cursor(DWORD index, DWORD dwSize_X) {
  return (COORD){.X = index_x(index, dwSize_X), .Y = index_y(index, dwSize_X)};
}

static inline COORD index_to_cursor_repl(DWORD index) {
  return (COORD){.X = index_x_repl(index), .Y = index_y_repl(index)};
}

static inline DWORD cursor_to_index(COORD cursor, DWORD dwSize_X) {
  assert(cursor.X >= 0);
  assert(cursor.Y >= 0);
  return (DWORD)cursor.X + ((DWORD)cursor.Y * dwSize_X);
}

static inline COORD curr_cursor(void) {
  return index_to_cursor_repl(repl.msg_index);
}

static inline COORD tail_cursor(void) {
  return index_to_cursor_repl(repl.msg->count);
}

static inline void cursor_home(void) {
  SetConsoleCursorPosition(repl.out, repl.home);
}

static inline void cursor_curr(void) {
  SetConsoleCursorPosition(repl.out, curr_cursor());
}

static inline void cursor_tail(void) {
  SetConsoleCursorPosition(repl.out, tail_cursor());
}

static inline void clear_tail(DWORD count) {
  FillConsoleOutputCharacterW(repl.out, CIN_SPACE, count, tail_cursor(), &repl._filled);
}

static inline void clear_full(void) {
  FillConsoleOutputCharacterW(repl.out, CIN_SPACE, repl.msg->count, repl.home, &repl._filled);
}

static inline void clear_preview(SHORT pos) {
  assert(pos >= 0);
  assert((DWORD)pos < repl.dwSize_X);
  preview.pos.X = pos;
  DWORD leftover = preview.len - (DWORD)pos;
  FillConsoleOutputCharacterW(repl.out, CIN_SPACE, leftover, preview.pos, &repl._filled);
}

static inline void set_preview_pos(SHORT y) {
  assert(y > 0);
  preview.pos.X = 0;
  preview.pos.Y = y;
}

static inline bool ctrl_on(PINPUT_RECORD input) {
  return input->Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED);
}

static inline BOOL GetConsoleScreenBufferInfo_safe(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo) {
  if (!GetConsoleScreenBufferInfo(hConsoleOutput, lpConsoleScreenBufferInfo)) return FALSE;
  SHORT cur_y = lpConsoleScreenBufferInfo->dwCursorPosition.Y;
  SHORT max_y = lpConsoleScreenBufferInfo->dwSize.Y - 1;
  DWORD max_x = (DWORD)lpConsoleScreenBufferInfo->dwSize.X;
  if (cur_y < max_y) return TRUE;
  HANDLE fresh_buffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE,
                                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                  NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
  if (fresh_buffer == INVALID_HANDLE_VALUE) return FALSE;
  if (!SetConsoleScreenBufferSize(fresh_buffer, lpConsoleScreenBufferInfo->dwSize)) return FALSE;
  if (!SetConsoleActiveScreenBuffer(fresh_buffer)) return FALSE;
  repl.out = fresh_buffer;
  repl.dwSize_X = max_x;
  SetConsoleCursorPosition(repl.out, (COORD){.X = 0, .Y = 0});
  repl.home.Y = 0;
  preview.pos.Y = 1;
  SHORT msg_tail = index_y_repl(repl.msg->count) + 1;
  if (msg_tail >= max_y) {
    repl.msg_index = 0;
    repl.msg->count = 0;
    wwritef(L"WARNING: Input message too large (tail at line %hd >= console"
            " screen buffer height limit %hd). Cinema resolved this by fully"
            " clearing your input. Your console terminal supports roughly"
            " %lu characters (cells)." WCRLF,
            msg_tail, max_y, max_x * (DWORD)max_y);
  }
  wwritef(L"WARNING: Console screen buffer height limit reached (%hd>=%hd)."
          " Cinema resolved this by activating a fresh buffer. The content of"
          " the previous buffer will be available once Cinema is closed."
          " If you want to prevent this situation in the future, increase"
          " the screen buffer size (height) of your console." WCRLF,
          cur_y, max_y);
  if (!GetConsoleScreenBufferInfo(repl.out, lpConsoleScreenBufferInfo)) return FALSE;
  repl.home.Y = lpConsoleScreenBufferInfo->dwCursorPosition.Y;
  SHORT preview_shift = (SHORT)((repl.msg->count + PREFIX) / max_x) + 1;
  set_preview_pos(repl.home.Y + preview_shift);
  if (!FlushConsoleInputBuffer(repl.in)) return FALSE;
  return TRUE;
}

#define CIN_PREVIEW_CAP 256

static wchar_t preview_buf[CIN_PREVIEW_CAP];

static void update_preview(void) {

}

static void log_preview(void) {
  // TODO: dynamic msg
  wchar_t *msg2 = L"123456789012345678922012345678904567890123456789012348888555";
  assert(wcslen(msg2) <= SIZE_MAX && "Corrupted string");
  DWORD msg_len = (DWORD)wcslen(msg2);
  preview.len = min(msg_len, repl.dwSize_X);
  assert(wmemchr(msg2, PREFIX_TOKEN, preview.len) == NULL);
  // set cursor to scroll down (and prep next write if < repl.dwSize_X)
  SetConsoleCursorPosition(repl.out, preview.pos);
  if (msg_len < repl.dwSize_X) {
    wwrite(msg2, msg_len);
  } else if (msg_len > repl.dwSize_X) {
    array_ensure_capacity(&preview, repl.dwSize_X);
    assert(msg_len > 3);
    wmemcpy(preview.items, msg2, repl.dwSize_X - 3);
    preview.items[repl.dwSize_X - 3] = '.';
    preview.items[repl.dwSize_X - 2] = '.';
    preview.items[repl.dwSize_X - 1] = '.';
    WriteConsoleOutputCharacterW(repl.out, preview.items, preview.len, preview.pos, &repl._filled);
  } else {
    WriteConsoleOutputCharacterW(repl.out, msg2, preview.len, preview.pos, &repl._filled);
  }
  FillConsoleOutputAttribute(repl.out, FOREGROUND_INTENSITY, preview.len, preview.pos, &repl._filled);
  cursor_curr();
}

static inline void rewrite_post_log(void) {
  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  GetConsoleScreenBufferInfo_safe(repl.out, &buffer_info);
  repl.dwSize_X = (DWORD)buffer_info.dwSize.X;
  assert(repl.msg->count + PREFIX <= SHRT_MAX && "SHORT overflow");
  assert(buffer_info.dwCursorPosition.Y < SHRT_MAX && "SHORT overflow");
  SHORT tail_x = buffer_info.dwCursorPosition.X;
  if (repl.msg->count + PREFIX > (DWORD)tail_x) {
    DWORD leftover = repl.msg->count + PREFIX - (DWORD)tail_x;
    FillConsoleOutputCharacterW(repl.out, CIN_SPACE, leftover, buffer_info.dwCursorPosition, &repl._filled);
  }
  repl.home.Y += buffer_info.dwCursorPosition.Y - repl.home.Y + 1;
  SHORT y_diff = preview.pos.Y - repl.home.Y;
  if (y_diff == -1 && preview.len > (DWORD)tail_x) {
    clear_preview(tail_x);
  } else if (y_diff == 0) {
    DWORD x = min(repl.msg->count + PREFIX, repl.dwSize_X);
    if (preview.len > x && x < repl.dwSize_X) {
      clear_preview((SHORT)x);
    }
  } else if (y_diff > 0) {
    SHORT x = index_x_repl(repl.msg->count);
    if (preview.len > (DWORD)x) {
      clear_preview(x);
    }
  }
  wwrite(WCRLF, WCRLF_LEN);
  wwrite(PREFIX_STR, PREFIX_STRLEN);
  wwrite(repl.msg->items, repl.msg->count);
  SHORT preview_offset = (SHORT)((repl.msg->count + PREFIX) / repl.dwSize_X) + 1;
  SHORT preview_line = repl.home.Y + preview_offset;
  set_preview_pos(preview_line);
  log_preview();
  show_cursor();
}

static CRITICAL_SECTION log_lock;

static void log_message(Cin_Log_Level level, const char *message, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  EnterCriticalSection(&log_lock);
  hide_cursor();
  cursor_home();
  writef(CR "[%s] ", LOG_LEVELS[level]);
  va_list args;
  va_start(args, message);
  vwritef(message, args);
  rewrite_post_log();
  va_end(args);
  LeaveCriticalSection(&log_lock);
}

typedef struct UTF16_Buffer {
  wchar_t *items;
  size_t count;
  size_t capacity;
} UTF16_Buffer;

typedef struct UTF8_Buffer {
  uint8_t *items;
  size_t count;
  size_t capacity;
} UTF8_Buffer;

static UTF16_Buffer utf16_buf_raw = {0};
static UTF16_Buffer utf16_buf_norm = {0};
static UTF8_Buffer utf8_buf = {0};

static inline int32_t utf16_to_utf8(const wchar_t *wstr) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
  assert(utf8_buf.items);
  assert(wstr);
  // because cchWideChar is set to -1, the output is null-terminated (and len includes it)
  // n_bytes represents the char count needed
  int32_t n_bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  assert(n_bytes);
  array_resize(&utf8_buf, (size_t)n_bytes);
  return WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char *)utf8_buf.items, n_bytes, NULL, NULL);
}

static inline int32_t utf8_to_utf16_raw(const char *str) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
  assert(utf16_buf_raw.items);
  assert(str);
  // because cbMultiByte is set to -1, the output is null-terminated (and len includes it)
  // n_chars represents the wchar_t count needed
  int32_t n_chars = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  assert(n_chars);
  array_resize(&utf16_buf_raw, (size_t)n_chars);
  return MultiByteToWideChar(CP_UTF8, 0, str, -1, utf16_buf_raw.items, n_chars);
}

static inline int32_t utf16_norm(const wchar_t *str) {
  // n_chars represents the possibly updated wchar_t count needed
  int32_t n_chars = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE,
                                  str, -1, NULL, 0, NULL, NULL, 0);
  assert(n_chars);
  array_resize(&utf16_buf_norm, (size_t)n_chars);
  return LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, str,
                       -1, utf16_buf_norm.items, n_chars, NULL, NULL, 0);
}

static inline int32_t utf8_to_utf16_norm(const char *str) {
  int32_t len = utf8_to_utf16_raw(str);
  assert(len);
  return utf16_norm(utf16_buf_raw.items);
}

static void log_wmessage(Cin_Log_Level level, const wchar_t *wmessage, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  EnterCriticalSection(&log_lock);
  hide_cursor();
  cursor_home();
  writef(CR "[%s] ", LOG_LEVELS[level]);
  va_list args;
  va_start(args, wmessage);
  wvwritef(wmessage, args);
  rewrite_post_log();
  va_end(args);
  LeaveCriticalSection(&log_lock);
}

static void log_last_error(const char *message, ...) {
  static const DWORD dw_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                FORMAT_MESSAGE_FROM_SYSTEM |
                                FORMAT_MESSAGE_IGNORE_INSERTS;
  EnterCriticalSection(&log_lock);
  LPVOID buffer;
  DWORD code = GetLastError();
  if (!FormatMessageA(dw_flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&buffer, 0, NULL)) {
    log_message(LOG_ERROR, "Failed to log GLE=%d - error with GLE=%d", code, GetLastError());
    return;
  }
  // remove trailing \r\n
  char *str = (char *)buffer;
  size_t len = strlen(str);
  assert(len >= 2);
  assert(str[len - 1] == '\n');
  assert(str[len - 2] == '\r');
  str[--len] = '\0';
  str[--len] = '\0';
  hide_cursor();
  cursor_home();
  writef(CR "[%s] ", LOG_LEVELS[LOG_ERROR]);
  va_list args;
  va_start(args, message);
  vwritef(message, args);
  va_end(args);
  writef(" - Code %lu: %s", code, (char *)buffer);
  rewrite_post_log();
  LocalFree(buffer);
  LeaveCriticalSection(&log_lock);
}

typedef struct Hash_Table_I32 {
  int32_t *keys;
  int32_t *values;
  int32_t len;
  int32_t a;
  int32_t shift;
  int32_t universe_len;
} Hash_Table_I32;

static Hash_Table_I32 *hash_table_i32(const int32_t *universe, int32_t universe_len) {
  // universal integer hashing with 50% load factor,
  // open addressing with linear probing
  Hash_Table_I32 *table = malloc(sizeof(Hash_Table_I32));
  int32_t len = 1;
  while (len < universe_len * 2) {
    len <<= 1;
  }
  table->shift = 32 - __builtin_clz((unsigned int)len - 1);
  table->a = (rand() * 2) | 1;
  table->keys = malloc((size_t)len * sizeof(int32_t));
  table->values = malloc((size_t)len * sizeof(int32_t));
  for (int32_t i = 0; i < len; ++i) {
    table->keys[i] = -1;
    table->values[i] = -1;
  }
  for (int32_t i = 0; i < universe_len; ++i) {
    int32_t hash = (table->a * universe[i]) >> table->shift;
    while (table->keys[hash] != -1) {
      hash = (hash + 1) & (len - 1);
    }
    table->keys[hash] = universe[i];
  }
  table->len = len;
  return table;
}

static int32_t hash_i32(const Hash_Table_I32 *table, const int32_t value) {
  int32_t hash = (table->a * value) >> table->shift;
  while (table->keys[hash] != value) {
    hash = (hash + 1) & (table->len - 1);
  }
  return hash;
}

static int **rmqa(const int *a, const int n) {
  // sparse table for range minimum query over a
  int log_n = 32 - __builtin_clz((unsigned int)(n - 1));
  int *data = malloc((size_t)n * (size_t)log_n * sizeof(int));
  int **m = malloc((size_t)n * sizeof(int *));
  for (int i = 0; i < n; ++i) {
    m[i] = data + i * log_n;
    m[i][0] = a[i];
  }
#if defined(CIN_OPENMP)
#pragma omp parallel for if (n >= (1 << 16))
#endif
  for (int k = 1; k < log_n; ++k) {
    int step = 1 << (k - 1);
    int limit = n - (1 << k) + 1;
    for (int i = 0; i < limit; ++i) {
      m[i][k] = min(m[i][k - 1], m[i + step][k - 1]);
    }
  }
  return m;
}

static int rmq(int **m, const int left, const int right) {
  int length = right - left + 1;
  int k = 31 - __builtin_clz((unsigned int)length);
  int right_start = right - (1 << k) + 1;
  return min(m[left][k], m[right_start][k]);
}

typedef struct RMQPosition {
  int32_t value;
  int32_t index;
} RMQPosition;

static RMQPosition **rmqa_positional(const int32_t *a, const int32_t n) {
  RMQPosition **m = malloc((size_t)n * sizeof(RMQPosition *));
  int log_n = 31 - __builtin_clz((unsigned int)n);
  for (int i = 0; i < n; ++i) {
    m[i] = malloc((size_t)log_n * sizeof(RMQPosition));
  }
  for (int i = 0; i < n; ++i) {
    m[i][0] = (RMQPosition){.value = a[i], .index = i};
  }
  for (int k = 1; k < log_n; ++k) {
    for (int i = 0; i + (1 << k) - 1 < n; ++i) {
      RMQPosition left = m[i][k - 1];
      RMQPosition right = m[i + (1 << (k - 1))][k - 1];
      m[i][k] = left.value < right.value ? left : right;
    }
  }
  return m;
}

static RMQPosition rmq_positional(RMQPosition **m, const int left, const int right) {
  int length = right - left + 1;
  int k = 31 - __builtin_clz((unsigned int)length);
  int right_start = right - (1 << k) + 1;
  RMQPosition min_left = m[left][k];
  RMQPosition min_right = m[right_start][k];
  return min_left.value < min_right.value ? min_left : min_right;
}

typedef void *radix_v;

typedef enum {
  RADIX_LEAF,
  RADIX_INTERNAL
} RadixNodeType;

typedef struct RadixNode {
  RadixNodeType type;
  radix_v v;
} RadixNode;

typedef struct RadixLeaf {
  RadixNode base;
  const uint8_t *key;
  size_t len;
} RadixLeaf;

typedef struct RadixInternal {
  RadixNode base;
  size_t critical;
  uint8_t bitmask;
  RadixNode *child[2];
} RadixInternal;

typedef struct RadixTree {
  RadixNode *root;
} RadixTree;

static inline int32_t radix_bit(const uint8_t *key, size_t len, size_t critical, uint8_t bitmask) {
  return critical < len && key[critical] & bitmask;
}

static inline void radix_critical(const uint8_t *k1, size_t len1,
                                  const uint8_t *k2, size_t len2,
                                  size_t *critical, uint8_t *bitmask) {
  size_t max_len = max(len1, len2);
  for (size_t i = 0; i < max_len; ++i) {
    uint8_t b1 = (i < len1) ? k1[i] : 0;
    uint8_t b2 = (i < len2) ? k2[i] : 0;
    if (b1 != b2) {
      uint8_t diff = b1 ^ b2;
      *critical = i;
      *bitmask = 0x80;
      while ((*bitmask & diff) == 0) {
        *bitmask >>= 1;
      }
      return;
    }
  }
  *critical = max_len;
  *bitmask = 0x80;
}

static inline RadixLeaf *radix_leaf(const uint8_t *key, size_t len, radix_v v) {
  RadixLeaf *leaf = malloc(sizeof(RadixLeaf));
  assert(leaf);
  leaf->base.type = RADIX_LEAF;
  leaf->base.v = v;
  uint8_t *dup = malloc(len + 1);
  assert(dup);
  memcpy(dup, key, len);
  dup[len] = '\0';
  leaf->key = dup;
  leaf->len = len;
  return leaf;
}

static inline RadixInternal *radix_internal(size_t critical, uint8_t bitmask) {
  RadixInternal *node = malloc(sizeof(RadixInternal));
  assert(node);
  node->base.type = RADIX_INTERNAL;
  node->base.v = NULL;
  node->critical = critical;
  node->bitmask = bitmask;
  node->child[0] = NULL;
  node->child[1] = NULL;
  return node;
}

static inline int32_t radix_compare(const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2) {
  size_t min_len = min(len1, len2);
  int32_t cmp = memcmp(k1, k2, min_len);
  if (cmp != 0) return cmp;
  if (len1 < len2) return -1;
  if (len1 > len2) return 1;
  return 0;
}

static inline void radix_update(RadixInternal *internal) {
  RadixNode *bit0 = internal->child[0];
  RadixNode *bit1 = internal->child[1];
  if (bit0 && bit1) {
    RadixLeaf *leaf0 = (RadixLeaf *)bit0;
    RadixLeaf *leaf1 = (RadixLeaf *)bit1;
    while (leaf0->base.type == RADIX_INTERNAL) {
      RadixInternal *int0 = (RadixInternal *)leaf0;
      leaf0 = (RadixLeaf *)(int0->child[0] ? int0->child[0] : int0->child[1]);
    }
    while (leaf1->base.type == RADIX_INTERNAL) {
      RadixInternal *int1 = (RadixInternal *)leaf1;
      leaf1 = (RadixLeaf *)(int1->child[0] ? int1->child[0] : int1->child[1]);
    }
    if (radix_compare(leaf0->key, leaf0->len, leaf1->key, leaf1->len) < 0) {
      internal->base.v = internal->child[0]->v;
    } else {
      internal->base.v = internal->child[1]->v;
    }
  } else if (bit0) {
    internal->base.v = bit0->v;
  } else if (bit1) {
    internal->base.v = bit1->v;
  }
}

static inline RadixTree *radix_tree(void) {
  RadixTree *tree = malloc(sizeof(RadixTree));
  assert(tree);
  tree->root = NULL;
  return tree;
}

static inline void radix_insert(RadixTree *tree, const uint8_t *key, size_t len, radix_v v) {
  assert(tree);
  assert(key);
  if (!tree->root) {
    tree->root = (RadixNode *)radix_leaf(key, len, v);
    return;
  }
  RadixNode **parent = &tree->root;
  RadixNode *node = tree->root;
  while (node->type == RADIX_INTERNAL) {
    RadixInternal *internal = (RadixInternal *)node;
    int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    parent = &internal->child[bit];
    node = internal->child[bit];
    if (!node) {
      *parent = (RadixNode *)radix_leaf(key, len, v);
      radix_update(internal);
      RadixNode *curr = tree->root;
      if (curr && curr->type == RADIX_INTERNAL) {
        // set lexicographical minimum
        radix_update((RadixInternal *)curr);
      }
      return;
    }
  }
  // split leaf node
  RadixLeaf *leaf = (RadixLeaf *)node;
  if (len == leaf->len && memcmp(key, leaf->key, len) == 0) {
    leaf->base.v = v;
    return;
  }
  size_t critical;
  uint8_t bitmask;
  radix_critical(key, len, leaf->key, leaf->len, &critical, &bitmask);
  RadixInternal *new_internal = radix_internal(critical, bitmask);
  int32_t new_bit = radix_bit(key, len, critical, bitmask);
  int32_t old_bit = radix_bit(leaf->key, leaf->len, critical, bitmask);
  RadixLeaf *new_leaf = radix_leaf(key, len, v);
  new_internal->child[new_bit] = (RadixNode *)new_leaf;
  new_internal->child[old_bit] = (RadixNode *)leaf;
  radix_update(new_internal);
  *parent = (RadixNode *)new_internal;
}

static inline radix_v radix_query(RadixTree *tree, const uint8_t *pattern, size_t len) {
  assert(tree);
  assert(tree->root);
  assert(pattern);
  assert(len > 0);
  RadixNode *node = tree->root;
  while (node) {
    if (node->type == RADIX_LEAF) {
      RadixLeaf *leaf = (RadixLeaf *)node;
      if (leaf->len >= len && memcmp(leaf->key, pattern, len) == 0) {
        return leaf->base.v;
      }
      return NULL;
    }
    RadixInternal *internal = (RadixInternal *)node;
    int32_t bit = radix_bit(pattern, len, internal->critical, internal->bitmask);
    node = internal->child[bit];
  }
  return NULL;
}

// TODO: probably change to byte-by-byte
static int32_t lcps(const uint8_t *a, const uint8_t *b) {
  static const int32_t CHUNK_SIZE = 1 << 3;
  const uint8_t *start = a;
  while ((((uintptr_t)a & 7) != 0 || ((uintptr_t)b & 7) != 0) &&
         *a == *b && *a != '\0') {
    a++;
    b++;
  }
  while (((uintptr_t)a & 7) == 0 && ((uintptr_t)b & 7) == 0) {
    uint64_t wa = *(const uint64_t *)a;
    uint64_t wb = *(const uint64_t *)b;
    if (wa != wb || (wa - 0x0101010101010101ULL) & (~wa & 0x8080808080808080ULL)) {
      break;
    }
    a += CHUNK_SIZE;
    b += CHUNK_SIZE;
  }
  while (*a == *b && *a != '\0') {
    a++;
    b++;
  }
  return (int32_t)(a - start);
}

static inline bool cin_lower_isalpha(char *out) {
  if (*out <= 'Z' && *out >= 'A') {
    *out += ('a' - 'A');
    return true;
  }
  return *out <= 'z' && *out >= 'a';
}

static inline wchar_t cin_wlower(wchar_t c) {
  if (c <= L'Z' && c >= 'A') return c + (L'a' - L'A');
  if (c < 128) return c;
  wchar_t unicode = c;
  LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, &c, 1, &unicode, 1, NULL, NULL, 0);
  return unicode;
}

typedef struct Conf_Key {
  char *items;
  size_t count;
  size_t capacity;
} Conf_Key;

typedef struct Conf_Root {
  Conf_Key null;
} Conf_Root;

typedef struct Conf_Media {
  Conf_Key directories;
  Conf_Key patterns;
  Conf_Key urls;
  Conf_Key tags;
} Conf_Media;

typedef struct Conf_Layout {
  Conf_Key name;
  Conf_Key screen;
} Conf_Layout;

typedef enum {
  CONF_SCOPE_ROOT,
  CONF_SCOPE_MEDIA,
  CONF_SCOPE_LAYOUT
} Conf_Scope_Type;

typedef struct Conf_Scope {
  Conf_Scope_Type type;
  union {
    Conf_Root root;
    Conf_Media media;
    Conf_Layout layout;
  };
} Conf_Scope;

typedef struct Conf_Scopes {
  Conf_Scope *items;
  size_t count;
  size_t capacity;
} Conf_Scopes;

typedef struct Conf_Buf {
  char *items;
  size_t count;
  size_t capacity;
} Conf_Buf;

static struct {
  Conf_Scopes scopes;
  size_t line;
  Conf_Buf buf;
  size_t len;
  size_t k_len;
  char *v;
  bool error;
} conf_parser = {0};

#define CIN_STRERROR_BYTES 95
#define CONF_LINE_CAP 512
#define CONF_SCOPES_CAP 16

static inline Conf_Scope *conf_scope(void) {
  assert(conf_parser.scopes.count > 0);
  return &conf_parser.scopes.items[conf_parser.scopes.count - 1];
}

static inline void conf_enter_scope(Conf_Scope_Type type) {
  Conf_Scope scope = {0};
  scope.type = type;
  array_push(&conf_parser.scopes, scope);
}

static inline void conf_error_log(size_t row, size_t col, const char *allowed) {
  // TODO: replace with log
  writef("Skipping line %zu due to unexpected token at position %zu. Allowed: %s.\r\n", row + 1, col + 1, allowed);
}

static inline bool conf_kcmp(char *k, Conf_Scope_Type type, Conf_Key *out, bool unique) {
  if (memcmp(k, conf_parser.buf.items, conf_parser.k_len) != 0) return false;
  assert(&conf_scope()->type);
  size_t v_len = conf_parser.len - (size_t)(conf_parser.v - conf_parser.buf.items);
  if (conf_scope()->type != type) {
    conf_parser.error = true;
    char *scope_msg;
    switch (conf_scope()->type) {
    case CONF_SCOPE_ROOT:
      scope_msg = "above any [table]";
      break;
    case CONF_SCOPE_LAYOUT:
      scope_msg = "under a [layout] table";
      break;
    case CONF_SCOPE_MEDIA:
      scope_msg = "under a [media] table";
      break;
    default:
      assert(false && "Unexpected type");
      break;
    }
    conf_parser.buf.items[conf_parser.k_len] = '\0';
    log_message(LOG_ERROR, "Unexpected key on line %zu: '%s' is not allowed %s",
                conf_parser.line, conf_parser.buf.items, scope_msg);
  } else if (unique) {
    if (out->count > 0) {
      log_message(LOG_WARNING, "Overwriting existing value on line %zu for key '%s': %s => %s",
                  conf_parser.line, k, out->items, conf_parser.v);
    }
    array_set(out, conf_parser.v, v_len);
  } else {
    if (out->count > 0) {
      assert(out->items[out->count - 1] == '\0');
      out->items[out->count - 1] = ',';
      array_push(out, ' ');
    }
    array_extend(out, conf_parser.v, v_len);
  }
  return true;
}

static inline bool conf_kget(void) {
  switch (conf_parser.k_len) {
  case 11:
    if (conf_kcmp("directories", CONF_SCOPE_MEDIA, &conf_scope()->media.directories, false)) return true;
    break;
  case 8:
    if (conf_kcmp("patterns", CONF_SCOPE_MEDIA, &conf_scope()->media.patterns, false)) return true;
    break;
  case 6:
    if (conf_kcmp("screen", CONF_SCOPE_LAYOUT, &conf_scope()->layout.screen, false)) return true;
    break;
  case 4:
    if (conf_kcmp("urls", CONF_SCOPE_MEDIA, &conf_scope()->media.urls, false)) return true;
    if (conf_kcmp("tags", CONF_SCOPE_MEDIA, &conf_scope()->media.tags, false)) return true;
    if (conf_kcmp("name", CONF_SCOPE_LAYOUT, &conf_scope()->layout.name, true)) return true;
    break;
  default:
    break;
  }
  return false;
}

static inline bool conf_scmp(char *s, Conf_Scope_Type type) {
  if (memcmp(s, conf_parser.buf.items + 1, conf_parser.k_len) != 0) return false;
  conf_enter_scope(type);
  return true;
}

static inline bool conf_sget(void) {
  switch (conf_parser.k_len) {
  case 6:
    if (conf_scmp("layout", CONF_SCOPE_LAYOUT)) return true;
    break;
  case 5:
    if (conf_scmp("media", CONF_SCOPE_MEDIA)) return true;
    break;
  default:
    break;
  }
  return false;
}

static bool parse_config(const char *filename) {
  bool ok = false;
  FILE *file;
  int32_t err = fopen_s(&file, filename, "rt");
  if (err) {
    char err_buf[CIN_STRERROR_BYTES];
    strerror_s(err_buf, CIN_STRERROR_BYTES, err);
    log_message(LOG_ERROR, "Failed to open config file '%s': %s", filename, err_buf);
    goto end;
  }
  array_alloc(&conf_parser.buf, CONF_LINE_CAP);
  array_alloc(&conf_parser.scopes, CONF_SCOPES_CAP);
  conf_enter_scope(CONF_SCOPE_ROOT);
  conf_parser.line = 1;
  while (fgets(conf_parser.buf.items, (int32_t)conf_parser.buf.capacity, file)) {
    conf_parser.len = strlen(conf_parser.buf.items);
    if (!conf_parser.len) {
      // TODO: handle
      assert(false);
      goto end;
    }
    assert(conf_parser.buf.capacity > 1);
    if (conf_parser.buf.items[conf_parser.len - 1] == '\n') {
      conf_parser.buf.items[conf_parser.len - 1] = '\0';
    } else if (!feof(file)) {
      // buffer too small, collect remainder and grow
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
      conf_parser.buf.count = conf_parser.len;
      int32_t c;
      while ((c = fgetc(file)) != '\n' && c != EOF) {
        array_push(&conf_parser.buf, (char)c);
      }
      array_push(&conf_parser.buf, '\0');
      conf_parser.len = conf_parser.buf.count - 1;
    }
    assert(conf_parser.buf.items[conf_parser.len] == '\0');
    assert(conf_parser.buf.items[conf_parser.len - 1] != '\n');
    char first = cin_lower_isalpha(&conf_parser.buf.items[0]) ? 'a' : conf_parser.buf.items[0];
    switch (first) {
    case 'a': {
      // expect abc=def123 or zyx  = wvu123
      char *p = conf_parser.buf.items + 1;
      while (cin_lower_isalpha(p)) ++p;
      conf_parser.k_len = (size_t)(p - conf_parser.buf.items);
      while (*p == ' ') ++p;
      if (*p != '=') {
        log_message(LOG_ERROR, "Token on line %zu at position %zu must be '=', not '%c'",
                    conf_parser.line, (size_t)(p - conf_parser.buf.items) + 1, *p);
        goto end;
      }
      ++p;
      while (*p == ' ') ++p;
      if (!*p) {
        conf_parser.buf.items[conf_parser.k_len] = '\0';
        log_message(LOG_ERROR, "Token on line %zu at position %zu must not be empty."
                               " Set the value for key '%s = ...'",
                    conf_parser.line, (size_t)(p - conf_parser.buf.items), conf_parser.buf.items);
        goto end;
      }
      conf_parser.v = p;
      if (!conf_kget()) {
        conf_parser.buf.items[conf_parser.k_len] = '\0';
        log_message(LOG_ERROR, "Unknown key '%s' on line %zu, please check for typos",
                    conf_parser.buf.items, conf_parser.line);
        goto end;
      } else if (conf_parser.error) {
        goto end;
      }
    } break;
    case '[': {
      // expect abc]
      char *p = conf_parser.buf.items + 1;
      while (cin_lower_isalpha(p)) ++p;
      conf_parser.k_len = (size_t)(p - conf_parser.buf.items) - 1;
      if (*p != ']') {
        conf_parser.buf.items[conf_parser.k_len + 1] = '\0';
        log_message(LOG_ERROR, "Line %zu wrongly creates a new scope '%s',"
                               " close it with ']' at position %zu",
                    conf_parser.line, conf_parser.buf.items, conf_parser.k_len + 2);
        goto end;
      }
      if (!conf_sget()) {
        conf_parser.buf.items[conf_parser.k_len + 2] = '\0';
        log_message(LOG_ERROR, "Scope '%s' at line %zu is unknown, please check for typos",
                    conf_parser.buf.items, conf_parser.line);
        goto end;
      }
    } break;
    case '#':
      break;
    case '\0':
      break;
    default:
      log_message(LOG_ERROR, "Line %zu starts with unexpected token '%d'. Only letters,"
                             " #, [, and empty lines are allowed here.",
                  conf_parser.line, conf_parser.buf.items[0]);
      goto end;
    }
    conf_parser.buf.items[0] = '\0';
    conf_parser.buf.count = 0;
    ++conf_parser.line;
  }
  ok = true;
end:
  fclose(file);
  return ok;
}

static char *read_json(const char *filename) {
  if (filename == NULL || filename[0] == '\0') {
    log_message(LOG_ERROR, "Invalid filename provided (empty string)");
    return NULL;
  }
  FILE *file;
  int result = fopen_s(&file, filename, "rb");
  if (result != 0) {
    char err_buf[CIN_STRERROR_BYTES];
    strerror_s(err_buf, CIN_STRERROR_BYTES, result);
    log_message(LOG_ERROR, "Failed to open config file '%s': %s", filename, err_buf);
    return NULL;
  }
  // Move pointer to get size in bytes and back
  fseek(file, 0, SEEK_END);
  long filesize = ftell(file);
  rewind(file);
  if (filesize < 0L) {
    log_message(LOG_ERROR, "Failed to get valid file position");
    fclose(file);
    return NULL;
  }
  // Buffer for file + null terminator
  char *json_content = (char *)malloc((size_t)filesize + 1L);
  if (json_content == NULL) {
    char err_buf[CIN_STRERROR_BYTES];
    _strerror_s(err_buf, CIN_STRERROR_BYTES, NULL);
    log_message(LOG_ERROR, "Failed to allocate memory for file '%s' with size '%ld': %s",
                filename, filesize + 1, err_buf);
    fclose(file);
    return NULL;
  }
  // Read into buffer with null terminator
  fread(json_content, 1, (size_t)filesize, file);
  json_content[filesize] = '\0';
  fclose(file);
  return json_content;
}

static cJSON *parse_json(const char *filename) {
  char *json_string = read_json(filename);
  if (json_string == NULL) {
    return NULL;
  }
  cJSON *json = cJSON_Parse(json_string);
  if (json == NULL) {
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
      log_message(LOG_ERROR, "JSON parsing error in file '%s' for contents: %s", filename, error_ptr);
    }
  }
  free(json_string);
  return json;
}

static int setup_int(const cJSON *json, const char *key, int default_val) {
  int result = default_val;
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  if (cJSON_IsNumber(option)) {
    result = option->valueint;
  } else {
    log_message(LOG_WARNING, "Defaulting '%s' to '%d': did not find number in JSON", key, default_val);
  }
  return result;
}

static double parse_percentage(const char *input, double default_val) {
  if (input == NULL || input[0] == '\0') {
    log_message(LOG_WARNING, "Defaulting percentage to '%f': empty input", input);
    return default_val;
  }
  int chars_read = 0;
  int int_result;
  int success = sscanf_s(input, "%d%n", &int_result, &chars_read);
  if (success == 1 && input[chars_read] == '\0') {
    return (double)int_result;
  }
  double double_result;
  chars_read = 0;
  success = sscanf_s(input, "%lf%n", &double_result, &chars_read);
  if (success == 1 && input[chars_read] == '\0') {
    return double_result;
  }
  log_message(LOG_WARNING, "Defaulting percentage '%s' to '%f': failed to parse", input, default_val);
  return default_val;
}

static int setup_screen_value(const cJSON *json, const char *key, int default_val, int monitor_dimension) {
  int result = default_val;
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  if (cJSON_IsNumber(option)) {
    result = option->valueint;
  } else if (cJSON_IsString(option)) {
    double percentage = parse_percentage(option->valuestring, (double)default_val);
    if (percentage >= 0 && percentage <= 100) {
      result = (int)(percentage * monitor_dimension / 100 + 0.5);
    } else {
      log_message(LOG_WARNING, "Defaulting '%s' to '%d': percentage '%f' is out of bounds",
                  key, default_val, percentage);
      result = default_val;
    }
  } else {
    log_message(LOG_WARNING, "Defaulting '%s' to '%d': did not find number in JSON", key, default_val);
  }
  return result;
}

static bool setup_bool(const cJSON *json, const char *key, int default_val) {
  if (default_val != 0 && default_val != 1) {
    log_message(LOG_WARNING, "Default value '%d' invalid for '%s'; defaulting to '0'", default_val, key);
    default_val = 0;
  }
  int result = default_val;
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  if (cJSON_IsBool(option)) {
    result = cJSON_IsTrue(option) ? true : false;
  } else {
    log_message(LOG_WARNING, "Defaulting '%s' to '%d': did not find boolean in JSON", key, default_val);
  }
  return result;
}

// TODO: remove this function
static wchar_t *setup_wstring(const cJSON *json, const char *key, const wchar_t *default_val) {
  if (default_val == NULL) {
    log_message(LOG_DEBUG, "Passed NULL as default value for setup_wstring");
  }
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  wchar_t *result = NULL;
  if (cJSON_IsString(option) && option->valuestring) {
    result = malloc(sizeof(wchar_t) * CIN_MAX_PATH);
    utf8_to_utf16_raw(option->valuestring);
    if (result == NULL) {
      log_wmessage(LOG_WARNING, L"Failed to convert JSON string '%s' for key '%s' to UTF-16",
                   option->valuestring, key);
    }
  }
  if (result == NULL) {
    if (default_val != NULL) {
      log_wmessage(LOG_WARNING, L"Defaulting '%s' to '%ls': did not find valid string in JSON",
                   key, default_val);
      result = _wcsdup(default_val);
    } else {
      log_message(LOG_WARNING, "Returning NULL for '%s': did not find valid string in JSON or default", key);
    }
  }
  return result;
}

typedef struct Local_Collection {
  // Each byte represents a UTF-8 unit
  uint8_t *text;
  // using int32_t because of libsais,
  // unsigned variants are pointless
  int32_t bytes;
  int32_t max_bytes;
  size_t bytes_mul32;
  size_t doc_mul32;
  // Document boundaries are encapsulated in the GSA
  // because the lexicographical sort puts \0 entries
  // at the top; the first doc_count entries
  // represent the start/end positions of each doc
  int32_t doc_count;
} Local_Collection;

static Local_Collection locals = {0};
static int32_t *gsa = NULL;
static int32_t *lcp = NULL;
static int32_t *suffix_to_doc = NULL;
static uint16_t *dedup_counters = NULL;

static void locals_append(const uint8_t *utf8, int len) {
  // Geometric growth with clamp, based on 260 max path
  static const int locals_init = 1 << 15;
  static const int locals_clamp = 1 << 26;
  void *dst = NULL;
  if (locals.max_bytes - locals.bytes >= len) {
    dst = locals.text + locals.bytes;
  } else {
    int32_t cap = locals.max_bytes;
    if (cap <= 0) {
      cap = locals_init;
    }
    while (cap - locals.bytes < len) {
      cap = cap < locals_clamp ? cap * 2 : cap + locals_clamp;
    }
    locals.max_bytes = cap;
    uint8_t *units = realloc(locals.text, (size_t)locals.max_bytes);
    if (units != NULL) {
      locals.text = units;
      dst = locals.text + locals.bytes;
    }
  }
  if (dst == NULL) {
    log_message(LOG_ERROR, "Failed to reallocate memory");
  } else {
    memcpy(dst, utf8, (size_t)len);
    locals.bytes += len;
    locals.doc_count++;
  }
}

static inline uint64_t fnv1a_hash(const uint8_t *str, size_t len) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < len; ++i) {
    hash ^= str[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

typedef struct RobinHoodBucket {
  uint64_t hash;
  size_t k_offset;
  int32_t v;
  int32_t filled;
} RobinHoodBucket;

typedef struct RobinHoodMap {
  RobinHoodBucket *items;
  size_t count;
  size_t capacity;
  size_t mask;
} RobinHoodMap;

#define RH_LOAD_FACTOR 85

static inline void rh_double(RobinHoodMap *map) {
  size_t prev_cap = map->capacity;
  RobinHoodBucket *prev_buckets = map->items;
  table_double(map);
  map->mask = map->capacity - 1;
  for (size_t i = 0; i < prev_cap; ++i) {
    if (prev_buckets[i].filled) {
      size_t home = prev_buckets[i].hash & map->mask;
      size_t dist = 0;
      RobinHoodBucket bucket = prev_buckets[i];
      while (map->items[home].filled) {
        size_t cur_dist = (home - (map->items[home].hash & map->mask)) & map->mask;
        if (cur_dist < dist) {
          RobinHoodBucket tmp = map->items[home];
          map->items[home] = bucket;
          bucket = tmp;
          dist = cur_dist;
        }
        home = (home + 1) & map->mask;
        ++dist;
      }
      map->items[home] = bucket;
      ++map->count;
    }
  }
  free(prev_buckets);
}

static inline int32_t rh_insert(RobinHoodMap *map, uint8_t *k_arena, size_t k_offset, size_t len, int32_t v) {
  // robin hood hashing (without tombstones) with fnv-1a
  uint8_t *k = k_arena + k_offset;
  if (map->count >= (map->capacity * RH_LOAD_FACTOR) / 100) {
    rh_double(map);
  }
  uint64_t hash = fnv1a_hash(k, len);
  size_t i = hash & map->mask;
  size_t dist = 0;
  RobinHoodBucket candidate = {.hash = hash, .v = v, .k_offset = k_offset, .filled = 1};
  while (map->items[i].filled) {
    uint8_t *i_k = k_arena + map->items[i].k_offset;
    if (map->items[i].hash == hash && strcmp((char *)i_k, (char *)k) == 0) {
      log_message(LOG_DEBUG, "Found duplicate key '%s' in hashmap", k);
      return map->items[i].v;
    }
    size_t cur_dist = (i - (map->items[i].hash & map->mask)) & map->mask;
    if (cur_dist < dist) {
      // evict rich to house poor
      RobinHoodBucket tmp = map->items[i];
      map->items[i] = candidate;
      candidate = tmp;
      dist = cur_dist;
    }
    i = (i + 1) & map->mask;
    ++dist;
  }
  map->items[i] = candidate;
  ++map->count;
  return -1;
}

typedef struct DirectoryNode {
  int32_t *items;
  size_t count;
  size_t capacity;
} DirectoryNode;

typedef struct DirectoryPath {
  wchar_t path[CIN_MAX_PATH];
  size_t len;
} DirectoryPath;

typedef struct TagDirectories {
  int32_t *items;
  size_t count;
  size_t capacity;
} TagDirectories;

typedef struct TagPatternItems {
  int32_t *items;
  size_t count;
  size_t capacity;
} TagPatternItems;

typedef struct TagUrlItems {
  int32_t *items;
  size_t count;
  size_t capacity;
} TagUrlItems;

typedef struct TagItems {
  TagDirectories *directories;
  TagPatternItems *pattern_items;
  TagUrlItems *url_items;
} TagItems;

typedef struct Cin_Screen {
  int32_t offset;
  int32_t len;
} Cin_Screen;

typedef struct Cin_Layout {
  Cin_Screen *items;
  size_t count;
  size_t capacity;
} Cin_Layout;

static struct {
  DirectoryPath *items;
  size_t abs_count;
  size_t count;
  size_t capacity;
} dir_stack = {0};

static struct {
  uint8_t *items;
  size_t count;
  size_t capacity;
} dir_string_arena = {0};

static struct {
  DirectoryNode *items;
  size_t count;
  size_t capacity;
} dir_node_arena = {0};

static struct {
  uint8_t *items;
  size_t count;
  size_t capacity;
} screen_arena = {0};

#define CIN_DIRECTORIES_CAP 64
#define CIN_DIRECTORY_ITEMS_CAP 64
#define CIN_DIRECTORY_STRINGS_CAP (CIN_DIRECTORIES_CAP * CIN_MAX_PATH_BYTES)
#define CIN_PATTERN_ITEMS_CAP 64
#define CIN_URLS_CAP 64
#define CIN_LAYOUT_SCREENS_CAP 8

static RobinHoodMap dir_map = {0};
static RobinHoodMap pat_map = {0};
static RobinHoodMap url_map = {0};
static RadixTree *tag_tree = NULL;
static RadixTree *layout_tree = NULL;

static void setup_directory(const char *path, TagDirectories *tag_dirs) {
  int32_t len_utf16 = utf8_to_utf16_norm(path);
  assert(len_utf16);
  size_t len = (size_t)len_utf16;
  DirectoryPath root_dir = {.len = len};
  wmemcpy(root_dir.path, utf16_buf_norm.items, len);
  array_push(&dir_stack, root_dir);
  while (dir_stack.count > 0) {
    DirectoryPath dir = dir_stack.items[--dir_stack.count];
    log_wmessage(LOG_DEBUG, L"Path: %ls", dir.path);
    assert(dir.path);
    assert(dir.len > 0);
    assert(dir.path[dir.len - 1] == L'\0');
    int32_t bytes_i32 = utf16_to_utf8(dir.path);
    assert(bytes_i32 > 0);
    size_t bytes = (size_t)bytes_i32;
    array_reserve(&dir_string_arena, bytes + 1);
    uint8_t *k_arena = dir_string_arena.items;
    size_t k_offset = dir_string_arena.count;
    memcpy(k_arena + k_offset, utf8_buf.items, bytes);
    size_t node_tail = dir_node_arena.count;
    // TODO: if an unmatched directory is inserted, its next occurence
    // will think that the current node_tail is correct, when it is not
    int32_t dup_index = rh_insert(&dir_map, k_arena, k_offset, bytes, (int32_t)node_tail);
    if (dup_index >= 0) {
      // NOTE: When the key is already in the hash, we have access to an index
      // into the dynamic nodes arena. Lazy evaluation: the terminator but must
      // be calculated (e.g., using the document ids to retrieve file names and
      // recognize depth reduction)
      DirectoryNode *dup_node = &dir_node_arena.items[dup_index];
      assert(dup_node >= dir_node_arena.items);
      assert(dup_node < dir_node_arena.items + dir_node_arena.count);
      for (DirectoryNode *p = dup_node; p < dir_node_arena.items + dir_node_arena.count; ++p) {
        // log_message(LOG_INFO, "count=%llu", p->count);
      }
      if (tag_dirs) {
        array_push(tag_dirs, dup_index);
      }
      continue;
    }
    if (--dir.len + 2 >= CIN_MAX_PATH) {
      // We have to append 2 chars \ and * for the correct pattern
      log_wmessage(LOG_ERROR, L"Directory name too long: %ls", dir.path);
      continue;
    }
    dir.path[dir.len++] = L'\\';
    dir.path[dir.len++] = L'*';
    dir.path[dir.len] = L'\0';
    WIN32_FIND_DATAW data;
    HANDLE search = FindFirstFileExW(dir.path, FindExInfoBasic, &data,
                                     FindExSearchNameMatch, NULL,
                                     FIND_FIRST_EX_LARGE_FETCH);
    // We can now drop the 2 chars \ and * to restore the root,
    // but choose to only drop * so that \ remains as a separator
    // for the next file or directory, instead of adding later.
    --dir.len;
    dir.path[dir.len] = L'\0';
    if (search == INVALID_HANDLE_VALUE) {
      log_last_error("Failed to match directory '%ls'", dir.path);
      continue;
    }
    // Commit the new directory
    dir_string_arena.count += bytes;
    array_grow(&dir_node_arena, 1);
    DirectoryNode *node = &dir_node_arena.items[node_tail];
    assert(node);
    array_alloc(node, CIN_DIRECTORY_ITEMS_CAP);
    if (tag_dirs) {
      array_push(tag_dirs, (int32_t)node_tail);
    }
    do {
      if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        continue; // skip junction
      }
      size_t file_len = utf16_norm(data.cFileName);
      wchar_t *file = utf16_buf_norm.items;
      bool is_dir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
      if (is_dir && (file[0] == L'.') && (!file[1] || (file[1] == L'.' && !file[2]))) {
        continue; // skip dot entry
      }
      size_t path_len = dir.len + file_len;
      if (path_len >= CIN_MAX_PATH) {
        continue; // skip absolute path (+ NUL) if silently truncated
      }
      if (is_dir) {
        DirectoryPath nested_path = {.len = path_len};
        wmemcpy(nested_path.path, dir.path, dir.len);
        wmemcpy(nested_path.path + dir.len, file, file_len);
        assert(nested_path.path[nested_path.len - 1] == L'\0');
        assert(nested_path.len > 0);
        ++dir_stack.abs_count;
        array_ensure_capacity(&dir_stack, dir_stack.abs_count);
        array_push(&dir_stack, nested_path);
      } else {
        wmemcpy(dir.path + dir.len, file, file_len);
        int32_t utf8_len = utf16_to_utf8(dir.path);
        array_push(node, locals.doc_count);
        locals_append(utf8_buf.items, utf8_len);
      }
    } while (FindNextFileW(search, &data) != 0);
    if (GetLastError() != ERROR_NO_MORE_FILES) {
      log_last_error("Failed to find next file");
    }
    FindClose(search);
  }
  assert(dir_stack.count == 0);
}

static inline void setup_pattern(const char *pattern, TagPatternItems *tag_pattern_items) {
  // Processes all files (not directories) that match the pattern
  // https://support.microsoft.com/en-us/office/examples-of-wildcard-characters-939e153f-bd30-47e4-a763-61897c87b3f4
  // TODO: explain allowed patterns (e.g., wildcards) in readme/json examples
  int32_t len_utf16 = utf8_to_utf16_norm(pattern);
  assert(len_utf16);
  assert(utf16_buf_norm.items[len_utf16 - 1] == L'\0');
  wchar_t *separator = wcsrchr(utf16_buf_norm.items, L'\\');
  if (separator == NULL || *(separator + 1) == L'\0') {
    log_message(LOG_ERROR, "Not a valid pattern: '%s', end properly with '\\...'", pattern);
    return;
  }
  size_t dir_len = (size_t)(separator - utf16_buf_norm.items) + 1;
  if (dir_len > CIN_MAX_PATH) {
    log_message(LOG_ERROR, "Pattern '%s' is too long (max=%d)", pattern, CIN_MAX_PATH);
    return;
  }
  wchar_t prev_tail = utf16_buf_norm.items[dir_len];
  utf16_buf_norm.items[dir_len] = L'\0';
  static wchar_t abs_buf[CIN_MAX_PATH];
  DWORD abs_len = GetFullPathNameW(utf16_buf_norm.items, CIN_MAX_PATH, abs_buf, NULL);
  if (abs_len == 0 || abs_len > CIN_MAX_PATH) {
    log_wmessage(LOG_ERROR, L"Pattern '%ls' full path '%ls' is empty or too long (max=%d)",
                 pattern, abs_buf, CIN_MAX_PATH);
    return;
  }
  log_wmessage(LOG_INFO, L"pattern: %ls", abs_buf);
  if (abs_buf[abs_len - 1] != L'\\') {
    abs_buf[abs_len++] = L'\\';
    abs_buf[abs_len] = L'\0';
  }
  utf16_buf_norm.items[dir_len] = prev_tail;
  WIN32_FIND_DATAW data;
  HANDLE search = FindFirstFileExW(utf16_buf_norm.items, FindExInfoBasic, &data,
                                   FindExSearchNameMatch, NULL,
                                   FIND_FIRST_EX_LARGE_FETCH);
  if (search == INVALID_HANDLE_VALUE) {
    log_last_error("Failed to match pattern '%ls'", utf16_buf_norm.items);
    return;
  }
  static const DWORD file_mask = FILE_ATTRIBUTE_DIRECTORY |
                                 FILE_ATTRIBUTE_REPARSE_POINT |
                                 FILE_ATTRIBUTE_DEVICE;
  do {
    if (data.dwFileAttributes & file_mask) {
      continue; // skip directories
    }
    size_t file_len = utf16_norm(data.cFileName);
    wchar_t *file = utf16_buf_norm.items;
    int32_t path_len = (int32_t)(abs_len + file_len);
    if (path_len >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(abs_buf + abs_len, file, file_len);
    int32_t len = utf16_to_utf8(abs_buf);
    // TODO: Because we sequentially parse the config, it is technically possible
    // that a directory was setup which contains files that match the current pattern.
    // This means that the locals array can contain duplicates in that case. While not
    // a big deal, it can probably be addressed without having to hash every file in
    // the directory setup, by using some pattern heuristics (e.g., directory hash)
    size_t tail_offset = (size_t)locals.bytes;
    int32_t tail_doc = locals.doc_count;
    locals_append(utf8_buf.items, len);
    int32_t dup_doc = rh_insert(&pat_map, locals.text, tail_offset, (size_t)len, tail_doc);
    if (dup_doc >= 0) {
      locals.bytes -= len;
      --locals.doc_count;
      if (tag_pattern_items) {
        array_push(tag_pattern_items, dup_doc);
      }
    } else {
      if (tag_pattern_items) {
        array_push(tag_pattern_items, tail_doc);
      }
    }
  } while (FindNextFileW(search, &data) != 0);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    log_last_error("Failed to find next file");
  }
  FindClose(search);
}

static inline void setup_url(const char *url, TagUrlItems *tag_url_items) {
  int32_t len_utf16 = utf8_to_utf16_norm(url);
  assert(len_utf16);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  size_t tail_offset = (size_t)locals.bytes;
  int32_t tail_doc = locals.doc_count;
  locals_append(utf8_buf.items, len_utf8);
  int32_t dup_doc = rh_insert(&url_map, locals.text, tail_offset, (size_t)len_utf8, tail_doc);
  if (dup_doc >= 0) {
    locals.bytes -= len_utf8;
    --locals.doc_count;
    if (tag_url_items) {
      array_push(tag_url_items, dup_doc);
    }
  } else {
    if (tag_url_items) {
      array_push(tag_url_items, tail_doc);
    }
  }
}

static inline void setup_tag(const char *tag, TagItems *tag_items) {
  int32_t len_utf16 = utf8_to_utf16_norm(tag);
  assert(len_utf16);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  assert(len_utf8);
  radix_insert(tag_tree, utf8_buf.items, (size_t)len_utf8, tag_items);
}

static inline void setup_screen(const char *geometry, size_t bytes, Cin_Layout *layout) {
  Cin_Screen screen = {.offset = (int32_t)screen_arena.count, .len = (int32_t)bytes - 1};
  array_extend(&screen_arena, geometry, bytes);
  array_push(layout, screen);
}

static inline void setup_layout(const char *name, Cin_Layout *layout) {
  int32_t len_utf16 = utf8_to_utf16_norm(name);
  assert(len_utf16);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  assert(len_utf8);
  radix_insert(layout_tree, utf8_buf.items, (size_t)len_utf8, layout);
}

#define FOREACH_PART(k, part, bytes)                                                                   \
  for (char *_left = (k)->items, *_right = (k)->items + (k)->count, *part = _left, *_comma = NULL;     \
       _left < _right;                                                                                 \
       _left = _comma ? _comma + 1 : _right, _left += _comma ? strspn(_left, " \t") : 0, part = _left) \
    if ((_comma = memchr(_left, ',', (size_t)(_right - _left))),                                       \
        (bytes = _comma ? (size_t)(_comma - _left + 1) : (size_t)(_right - _left)),                    \
        _comma ? (_comma[0] = '\0', 1) : (_left[bytes - 1] = '\0', 1), 1)

static bool init_config(const char *filename) {
  if (!parse_config(filename)) return false;
  array_alloc(&utf16_buf_raw, CIN_MAX_PATH);
  array_alloc(&utf16_buf_norm, CIN_MAX_PATH);
  array_alloc(&utf8_buf, CIN_MAX_PATH_BYTES);
  table_calloc(&dir_map, CIN_DIRECTORIES_CAP);
  table_calloc(&pat_map, CIN_PATTERN_ITEMS_CAP);
  table_calloc(&url_map, CIN_URLS_CAP);
  dir_map.mask = dir_map.capacity - 1;
  pat_map.mask = pat_map.capacity - 1;
  url_map.mask = url_map.capacity - 1;
  array_alloc(&dir_node_arena, CIN_DIRECTORIES_CAP);
  array_alloc(&dir_string_arena, CIN_DIRECTORY_STRINGS_CAP);
  tag_tree = radix_tree();
  layout_tree = radix_tree();
  Conf_Root *root = &conf_parser.scopes.items[0].root;
  size_t bytes;
  for (size_t i = 1; i < conf_parser.scopes.count; ++i) {
    Conf_Scope *scope = &conf_parser.scopes.items[i];
    log_message(LOG_DEBUG, "[Scope %zu: %zu]", i, scope->type);
    switch (scope->type) {
    case CONF_SCOPE_LAYOUT: {
      if (!scope->layout.name.count) {
        log_message(LOG_ERROR, "Layout at [scope] number %zu does not have a name key,"
                               " please supply it: 'name = value'",
                    i);
        return false;
      }
      if (!scope->layout.screen.count) {
        log_message(LOG_ERROR, "Layout at [scope] number %zu does not have any screen"
                               " keys, please supply with: 'screen = 0:0'",
                    i);
        return false;
      }
      Cin_Layout *layout = malloc(sizeof(Cin_Layout));
      array_alloc(layout, CIN_LAYOUT_SCREENS_CAP);
      log_message(LOG_DEBUG, "Name: %s", scope->layout.name.items);
      FOREACH_PART(&scope->layout.screen, part, bytes) {
        log_message(LOG_DEBUG, "Screen: %s, len=%d", part, bytes);
        setup_screen(part, bytes, layout);
      }
      setup_layout(scope->layout.name.items, layout);
      array_free(scope->layout.name);
      array_free(scope->layout.screen);
    } break;
    case CONF_SCOPE_MEDIA: {
      TagItems *tag_items = NULL;
      TagDirectories *tag_directories = NULL;
      TagPatternItems *tag_pattern_items = NULL;
      TagUrlItems *tag_url_items = NULL;
      if (scope->media.tags.count) {
        tag_items = calloc(1, sizeof(TagItems));
        if (scope->media.directories.count) {
          tag_items->directories = malloc(sizeof(*tag_items->directories));
          array_alloc(tag_items->directories, CIN_DIRECTORIES_CAP);
          tag_directories = tag_items->directories;
        }
        if (scope->media.patterns.count) {
          tag_items->pattern_items = malloc(sizeof(*tag_items->pattern_items));
          array_alloc(tag_items->pattern_items, scope->media.patterns.count);
          tag_pattern_items = tag_items->pattern_items;
        }
        if (scope->media.urls.count) {
          tag_items->url_items = malloc(sizeof(*tag_items->url_items));
          array_alloc(tag_items->url_items, scope->media.urls.count);
          tag_url_items = tag_items->url_items;
        }
      }
      FOREACH_PART(&scope->media.directories, part, bytes) {
        log_message(LOG_DEBUG, "Directory: %s", part);
        setup_directory(part, tag_directories);
      }
      FOREACH_PART(&scope->media.patterns, part, bytes) {
        log_message(LOG_DEBUG, "Pattern: %s", part);
        setup_pattern(part, tag_pattern_items);
      }
      FOREACH_PART(&scope->media.urls, part, bytes) {
        log_message(LOG_DEBUG, "URL: %s", part);
        setup_url(part, tag_url_items);
      }
      FOREACH_PART(&scope->media.tags, part, bytes) {
        log_message(LOG_DEBUG, "Tag: %s", part);
        setup_tag(part, tag_items);
      }
      // NOTE: Each tag corresponding to this media scope now points to the same
      // TagItems address. In it, 'patterns' and 'urls' contain document ids (possibly
      // with duplicates). Its 'directories' is a TagDirectories struct, where each
      // item is an index into a global DirectoryNode arena (possibly with duplicates)
      // - these nodes contain a list of unique document ids. Given example directory
      // A:\b\c\, the node arena must be traversed starting there up to an index where
      // the first document in the list does not start with A:\b\c\ (so we simulate
      // a correct recursive directory traversal, lazily, i.e., when tag is requested)
      array_free(scope->media.directories);
      array_free(scope->media.patterns);
      array_free(scope->media.urls);
      array_free(scope->media.tags);
    } break;
    default:
      assert(false && "Unexpected scope");
      break;
    }
  }
  table_free(dir_map);
  table_free(pat_map);
  table_free(url_map);
  array_free(dir_string_arena);
  array_free(dir_stack);
  array_free(conf_parser.scopes);
  array_free(conf_parser.buf);
  if (locals.bytes < locals.max_bytes) {
    uint8_t *tight = realloc(locals.text, (size_t)locals.bytes);
    if (tight != NULL) {
      locals.text = tight;
      locals.max_bytes = locals.bytes;
      locals.bytes_mul32 = (size_t)locals.bytes * sizeof(int32_t);
      locals.doc_mul32 = (size_t)locals.doc_count * sizeof(int32_t);
    }
  }
  log_message(LOG_INFO, "Setup media library with %d items (%d bytes)",
              locals.doc_count, locals.bytes);
  return true;
}

static void document_listing(const uint8_t *pattern, int32_t pattern_len) {
  int32_t left = locals.doc_count;
  int32_t right = locals.bytes - 1;
  int32_t l_lcp = lcps(pattern, locals.text + gsa[left]);
  int32_t r_lcp = lcps(pattern, locals.text + gsa[right]);
  if (l_lcp < pattern_len &&
      (locals.text[gsa[left] + l_lcp] == '\0' ||
       pattern[l_lcp] < locals.text[gsa[left] + l_lcp])) {
    // pattern = abc, left = abd
    // l_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[l_lcp] = c, text[left + l_lcp] = d, c < d
    log_message(LOG_DEBUG, "Pattern is smaller than first suffix");
    return;
  }
  if (r_lcp < pattern_len &&
      locals.text[gsa[right] + r_lcp] != '\0' &&
      pattern[r_lcp] > locals.text[gsa[right] + r_lcp]) {
    // pattern = abd, right = abc
    // r_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[r_lcp] = d, text[right + r_lcp] = c, d > c
    log_message(LOG_DEBUG, "Pattern is larger than last suffix");
    return;
  }
  int32_t tmp_right = right;
  int32_t tmp_r_lcp = r_lcp;
  bool found = false;
  while (left < right) {
    int32_t mid = left + ((right - left) >> 1);
    int32_t t_lcp = lcps(pattern, locals.text + gsa[mid]);
    if (t_lcp == pattern_len) {
      found = true;
      right = mid;
      r_lcp = t_lcp;
    } else if (locals.text[gsa[mid] + t_lcp] == '\0') {
      left = mid + 1;
      l_lcp = t_lcp;
    } else if (pattern[t_lcp] < locals.text[gsa[mid] + t_lcp]) {
      right = mid;
      r_lcp = t_lcp;
    } else {
      left = mid + 1;
      l_lcp = t_lcp;
    }
  }
  if (!found && lcps(pattern, locals.text + gsa[left]) < pattern_len) {
    log_message(LOG_DEBUG, "No suffix has pattern as prefix");
    return;
  }
  int32_t l_bound = left;
  int32_t r_bound = left;
  right = tmp_right;
  l_lcp = pattern_len;
  r_lcp = tmp_r_lcp;
  while (left < right) {
    int32_t mid = left + ((right - left + 1) >> 1);
    int32_t t_lcp = lcps(pattern, locals.text + gsa[mid]);
    if (t_lcp == pattern_len) {
      left = mid;
      l_lcp = pattern_len;
    } else if (locals.text[gsa[mid] + t_lcp] == '\0') {
      right = mid - 1;
      r_lcp = t_lcp;
    } else {
      right = mid - 1;
      r_lcp = t_lcp;
    }
    r_bound = left;
  }
  log_message(LOG_DEBUG, "Boundaries are [%d, %d] or [%s, %s]", l_bound, r_bound,
              locals.text + gsa[l_bound], locals.text + gsa[r_bound]);
  static uint16_t dedup_counter = 1;
  for (int32_t i = l_bound; i <= r_bound; ++i) {
    int32_t doc = suffix_to_doc[i];
    if (dedup_counters[doc] != dedup_counter) {
      dedup_counters[doc] = dedup_counter;
      log_message(LOG_TRACE, "gsa[%7d] = %-25.25s (%7d)| (%7d) = %-30.30s counter=%d", i, locals.text + gsa[i], gsa[i], doc, locals.text + doc, dedup_counter);
    }
  }
  if (++dedup_counter == 0) {
    memset(dedup_counters, 0, (size_t)locals.bytes * sizeof(uint16_t));
    dedup_counter = 1;
  }
}

static bool init_document_listing(void) {
  gsa = malloc(locals.bytes_mul32);
#if defined(LIBSAIS_OPENMP)
  int32_t result = libsais_gsa_omp(locals.text, gsa, locals.bytes, 0, NULL, 0);
#else
  int32_t result = libsais_gsa(locals.text, gsa, locals.bytes, 0, NULL);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build SA");
    return false;
  }
  int32_t *plcp = malloc(locals.bytes_mul32);
#if defined(LIBSAIS_OPENMP)
  result = libsais_plcp_gsa_omp(locals.text, gsa, plcp, locals.bytes, 0);
#else
  result = libsais_plcp_gsa(locals.text, gsa, plcp, locals.bytes);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build PLCP array");
    return false;
  }
  lcp = malloc(locals.bytes_mul32);
#if defined(LIBSAIS_OPENMP)
  result = libsais_lcp_omp(plcp, gsa, lcp, locals.bytes, 0);
#else
  result = libsais_lcp(plcp, gsa, lcp, locals.bytes);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build LCP array");
    return false;
  }
  free(plcp);
  suffix_to_doc = malloc(locals.bytes_mul32);
  dedup_counters = calloc((size_t)locals.bytes, sizeof(uint16_t));
  suffix_to_doc[0] = 0;
  for (int32_t i = 1; i < locals.doc_count; ++i) {
    suffix_to_doc[i] = gsa[i - 1] + 1;
  }
  // TODO: there is probably a faster approach than
  // binary search, but with omp it is very fast
#if defined(CIN_OPENMP)
#pragma omp parallel for if (locals.bytes >= (1 << 16))
#endif
  for (int32_t i = locals.doc_count; i < locals.bytes; ++i) {
    int32_t left = 0;
    int32_t right = locals.doc_count - 1;
    int32_t curr = gsa[i];
    while (left < right) {
      int32_t mid = left + ((right - left + 1) >> 1);
      if (suffix_to_doc[mid] <= curr) {
        left = mid;
      } else {
        right = mid - 1;
      }
    }
    suffix_to_doc[i] = suffix_to_doc[left];
  }
  return true;
}

static bool setup_layouts(const cJSON *layouts) {
  if (layouts == NULL) {
    return false;
  }
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics
  int monitor_width = GetSystemMetrics(SM_CXSCREEN);
  int monitor_height = GetSystemMetrics(SM_CYSCREEN);
  if (monitor_width == 0 || monitor_height == 0) {
    log_message(LOG_ERROR, "Failed to scan monitor for screen dimensions.");
    return false;
  }
  log_message(LOG_INFO, "Monitor dimensions: %dx%d", monitor_width, monitor_height);
  const cJSON *layout = layouts->child;
  while (layout != NULL) {
    log_message(LOG_DEBUG, "Processing layout '%s'", layout->string);
    if (!cJSON_IsArray(layout)) {
      log_message(LOG_ERROR, "Layout '%s' is not an Array", layout->string);
      return false;
    }
    const cJSON *screen = layout->child;
    int i = 0;
    while (screen != NULL) {
      log_message(LOG_DEBUG, "Adding screen %d", i);
      int left = setup_screen_value(screen, "left", 0, monitor_width);
      int top = setup_screen_value(screen, "top", 0, monitor_height);
      int width = setup_screen_value(screen, "width", 0, monitor_width);
      int height = setup_screen_value(screen, "height", 0, monitor_height);
      log_message(LOG_DEBUG, "left=%d top=%d width=%d height=%d", left, top, width, height);
      screen = screen->next;
      ++i;
    }
    layout = layout->next;
  }
  return true;
}

// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-transactnamedpipe
// TODO: find better upper bound for transaction (pending 64kb writes can scale very fast, files are maxed to 260)
#define PIPE_WRITE_BUFFER 65536
#define PIPE_READ_BUFFER 1024
#define WRITES_CAPACITY 32

typedef struct {
  OVERLAPPED ovl;
  bool is_write;
} Overlapped_Ctx;

typedef struct Overlapped_Write {
  Overlapped_Ctx ovl_context;
  char buffer[PIPE_WRITE_BUFFER];
  size_t bytes;
  int64_t request_id;
} Overlapped_Write;

typedef struct Pending_Writes {
  Overlapped_Write **items;
  size_t count;
  size_t capacity;
} Pending_Writes;

typedef struct Instance {
  // NOTE: currently, we use a single overlapped read per instance
  // (unlike multiple writes). This could lead to gaps in incoming
  // data if the OS buffer does not preserve it fully for the next
  // read. If that is observed, switch to multiple reads as well
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE pipe;
  Overlapped_Ctx ovl_context;
  CHAR read_buffer[PIPE_READ_BUFFER];
  Pending_Writes pending_writes;
  int64_t request_id;
} Instance;

static bool create_process(Instance *instance, const wchar_t *pipe_name, const wchar_t *file_name) {
  static wchar_t command[CIN_COMMAND_PROMPT_LIMIT];
  swprintf(command, CIN_COMMAND_PROMPT_LIMIT,
           L"mpv"
           L" \"%ls\"" // filename
           L" --input-ipc-server=%ls",
           file_name,
           pipe_name);
  log_wmessage(LOG_INFO, command);
  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
  if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      // mpv binary not found
      // TODO: link to somewhere to get the binary
      // TODO: check for yt-dlp binary for streams
      log_last_error("Failed to find mpv binary");
    } else {
      log_last_error("Failed to start mpv even though it was found");
    }
    return false;
  };
  instance->si = si;
  instance->pi = pi;
  return true;
}

static bool create_pipe(Instance *instance, const wchar_t *name) {
  // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
  // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
  static const int FOUND_TIMEOUT = 20000;
  static const int UNFOUND_TIMEOUT = 20000;
  static const int UNFOUND_WAIT = 50;
  int unfound_duration = 0;
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  for (;;) {
    // hPipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    hPipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
      break;
    }
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      // Wait for the IPC server to start with timeout
      unfound_duration += UNFOUND_WAIT;
      if (unfound_duration >= UNFOUND_TIMEOUT) {
        log_message(LOG_ERROR, "Failed to find pipe in time: %dms/%dms", unfound_duration, UNFOUND_TIMEOUT);
        return false;
      }
      log_message(LOG_DEBUG, "Failed to find pipe. Trying again in %dms...", UNFOUND_WAIT);
      Sleep(UNFOUND_WAIT);
    } else {
      // Unlikely error, try to resolve by waiting
      log_last_error("Could not connect to pipe - Waiting for %dms", FOUND_TIMEOUT);
      if (!WaitNamedPipeW(name, FOUND_TIMEOUT)) {
        log_last_error("Failed to connect to pipe");
        return false;
      }
    }
  }
  instance->pipe = hPipe;
  log_message(LOG_TRACE, "Successfully created pipe (HANDLE) %p", (void *)instance->pipe);
  return true;
}

static bool overlap_read(Instance *instance) {
  log_message(LOG_TRACE, "Initializing read on PID %lu", instance->pi.dwProcessId);
  ZeroMemory(&instance->ovl_context.ovl, sizeof(OVERLAPPED));
  if (!ReadFile(instance->pipe, instance->read_buffer, (PIPE_READ_BUFFER)-1, NULL, &instance->ovl_context.ovl)) {
    if (GetLastError() != ERROR_IO_PENDING) {
      log_last_error("Failed to initialize read");
      return false;
    }
  }
  // Read is queued for iocp
  return true;
}

static cJSON *mpv_command(const char *command, int64_t request_id) {
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    goto end;
  }
  cJSON *cmd_array = cJSON_CreateArray();
  if (cmd_array == NULL) {
    goto end;
  }
  cJSON *cmd_element = cJSON_CreateString(command);
  if (cmd_element == NULL) {
    goto end;
  }
  cJSON_AddItemToArray(cmd_array, cmd_element);
  cJSON_AddItemToObject(json, "command", cmd_array);
  // NOTE: precision loss when request_id is extremely
  // large (unrealistic), but mostly a problem if the data type
  // changes from int64_t to something else
  cJSON *cmd_id = cJSON_CreateNumber((double)request_id);
  cJSON_AddItemToObject(json, "request_id", cmd_id);
  return json;
end:
  cJSON_Delete(json);
  return NULL;
}

static bool overlap_write(Instance *instance, cJSON *command) {
  // TODO: dont use cjson, use static buffer
  log_message(LOG_TRACE, "Initializing write on PID %lu", instance->pi.dwProcessId);
  char *command_str = cJSON_PrintUnformatted(command);
  cJSON_Delete(command);
  if (command_str == NULL) {
    log_message(LOG_ERROR, "Failed to cJSON_PrintUnformatted the mpv command.");
    return false;
  }
  size_t len = strlen(command_str);
  Overlapped_Write *write = calloc(1, sizeof(*write));
  if (write == NULL) {
    log_message(LOG_ERROR, "Failed to allocate memory.");
    return false;
  }
  if (len >= sizeof(write->buffer)) {
    log_message(LOG_ERROR, "Message len '%d' bigger than buffer '%d'", len, sizeof(write->buffer));
    return false;
  }
  // shift \0 up to insert \n
  // and include \0 in len (bytes)
  command_str[len++] = '\n';
  command_str[len++] = '\0';
  memcpy(write->buffer, command_str, len);
  write->ovl_context.is_write = true;
  write->bytes = len;
  write->request_id = instance->request_id - 1;
  log_message(LOG_DEBUG, "Writing message: %.*s", len - 2, write->buffer);
  free(command_str);
  if (!WriteFile(instance->pipe, write->buffer, (DWORD)len, NULL, &write->ovl_context.ovl)) {
    switch (GetLastError()) {
    case ERROR_IO_PENDING:
      // iocp will free write
      log_message(LOG_TRACE, "Pending write call, handled by iocp.");
      return true;
    case ERROR_INVALID_HANDLE:
      // Code 6: The handle is invalid
      log_message(LOG_DEBUG, "\t(ERR_START)\n\t%.*s\n\t(ERR_END)\n", (int)len - 2, write->buffer);
      break;
    }
    log_last_error("Failed to initialize write");
    free(write);
    return false;
  }
  log_message(LOG_TRACE, "Write call completed immediately.");
  return true;
}

static bool create_instance(Instance *instance, const wchar_t *name, const wchar_t *file_name, HANDLE *iocp) {
  if (name == NULL || file_name == NULL) {
    return false;
  }
  instance->ovl_context.is_write = false;
  instance->request_id = 0;
  Pending_Writes pending_writes = {
      .items = malloc(sizeof(Overlapped_Write *) * WRITES_CAPACITY),
      .count = 0,
      .capacity = WRITES_CAPACITY};
  instance->pending_writes = pending_writes;
  if (!create_process(instance, name, file_name)) {
    return false;
  }
  if (!create_pipe(instance, name)) {
    return false;
  }
  // Does not create a new iocp if pointer is invalid since Existing is provided
  if (CreateIoCompletionPort(instance->pipe, iocp, (ULONG_PTR)instance, 0) == NULL) {
    log_last_error("Failed to associate pipe with iocp");
    return false;
  }
  if (!overlap_read(instance)) {
    return false;
  }
  return true;
}

static bool process_layout(size_t count, Instance *instances, const wchar_t *file_name, HANDLE *iocp) {
  static const wchar_t PIPE_PREFIXW[] = L"\\\\.\\pipe\\cinema_mpv_";
  static const int PIPE_NAME_BUFFER = 32;
  if (count <= 0) {
    log_message(LOG_TRACE, "Count of %d, nothing to process.", count);
    return false;
  }
  wchar_t pipe_name[PIPE_NAME_BUFFER];
  for (size_t i = 0; i < count; ++i) {
    swprintf(pipe_name, PIPE_NAME_BUFFER, L"%ls%d", PIPE_PREFIXW, i);
    if (!create_instance(&instances[i], pipe_name, file_name, iocp)) {
      free(instances);
      log_message(LOG_ERROR, "Failed to create instance");
      return false;
    }
  }
  return true;
}

static Overlapped_Write *find_write(Instance *instance, int64_t request_id) {
  // Uses binary search over sorted dynamic array.
  // The request_id should always find a pair in this scenario
  // as the incoming request_id was sent as a targeted response.
  if (instance == NULL) {
    log_message(LOG_ERROR, "Tried to find '%" PRId64 "' on NULL instance", request_id);
    return NULL;
  }
  if (instance->pending_writes.count == 0) {
    log_message(LOG_ERROR, "Tried to find '%" PRId64 "' without pending writes", request_id);
    return NULL;
  }
  if (instance->pending_writes.items == NULL) {
    log_message(LOG_ERROR, "Tried to find '%" PRId64 "' on NULL items", request_id);
    return NULL;
  }
  size_t left = 0;
  size_t right = instance->pending_writes.count - 1;
  while (left <= right) {
    size_t middle = left + ((right - left) >> 1);
    int64_t mid_val = instance->pending_writes.items[middle]->request_id;
    if (mid_val < request_id) {
      left = middle + 1;
    } else if (mid_val > request_id) {
      if (middle == 0) {
        break;
      }
      right = middle - 1;
    } else {
      return instance->pending_writes.items[middle];
    }
  }
  log_message(LOG_ERROR, "Tried to find '%" PRId64 "' but could not find it", request_id);
  return NULL;
}

static DWORD WINAPI iocp_listener(LPVOID lp_param) {
  HANDLE iocp = (HANDLE)lp_param;
  for (;;) {
    DWORD bytes;
    ULONG_PTR completion_key;
    OVERLAPPED *ovl;
    if (!GetQueuedCompletionStatus(iocp, &bytes, &completion_key, &ovl, INFINITE)) {
      log_last_error("Failed to dequeue packet");
      // TODO: when observed, resolve instead of break
      // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus#remarks
      break;
    }
    log_message(LOG_TRACE, "Processing dequeued completion packet from successful I/O operation");
    Instance *instance = (Instance *)completion_key;
    Overlapped_Ctx *ctx = (Overlapped_Ctx *)ovl;
    if (ctx->is_write) {
      Overlapped_Write *write = (Overlapped_Write *)ctx;
      Pending_Writes *pending = &instance->pending_writes;
      if (pending->count >= pending->capacity) {
        pending->capacity = pending->capacity * 2;
        pending->items = realloc(pending->items, sizeof(Overlapped_Write *) * pending->capacity);
        if (pending->items == NULL) {
          log_message(LOG_ERROR, "Failed to reallocate memory of pending writes");
          break;
        }
      }
      pending->items[pending->count++] = write;
      if (write->bytes != bytes) {
        log_message(LOG_ERROR, "Expected '%ld' bytes but received '%ld'", write->bytes, bytes);
        // TODO: when observed, resolve instead of break
        break;
      }
    } else {
      cJSON *json = cJSON_Parse(instance->read_buffer);
      if (json == NULL) {
        // TODO: when observed, resolve instead of break
        log_message(LOG_ERROR, "Failed to parse instance read buffer as JSON");
        break;
      }
      cJSON *request_id = cJSON_GetObjectItemCaseSensitive(json, "request_id");
      if (cJSON_IsNumber(request_id)) {
        Overlapped_Write *write = find_write(instance, request_id->valueint);
        log_message(LOG_DEBUG, "Written to pipe    (%p): %.*s", (void *)instance->pipe, strlen(write->buffer) - 1, write->buffer);
        // TODO: free the write struct and prune pending_writes
        // TODO: handle different return cases beyond request_id
      }
      // TODO: read each line (separated by \n character) separately
      // TODO: Currently, embedded 0 bytes terminate the current line, but you should not rely on this.
      instance->read_buffer[bytes] = '\0'; // TODO: handle buffer gracefully
      log_message(LOG_DEBUG, "Got data from pipe (%p): %.*s", (void *)instance->pipe, strlen(instance->read_buffer) - 1, instance->read_buffer);
      log_message(LOG_DEBUG, "END data from pipe (%p)", (void *)instance->pipe);
      cJSON_Delete(json);
      if (!overlap_read((Instance *)completion_key)) {
        // TODO: when observed, resolve instead of break
        break;
      }
    }
  }
  return 0;
}

#define CIN_NUL 0x00
#define CIN_BACK 0x08
#define CIN_ENTER 0x0D
#define CIN_CONTROL_BACK 0x7F
#define CIN_ESCAPE 0x1B
#define CIN_VK_0 0x30
#define CIN_VK_9 0x39
#define CIN_VK_A 0x41
#define CIN_VK_Z 0x5A

// https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
#define ESC "\x1b"
#define CSI "\x1b["

static inline bool bounded_console(HANDLE console) {
  assert(console);
  SHORT prev_bot = 0;
  SHORT next_bot = 0;
  CONSOLE_CURSOR_INFO cursor_info = {0};
  GetConsoleCursorInfo(console, &cursor_info);
  BOOL prev_vis = cursor_info.bVisible;
  cursor_info.bVisible = false;
  SetConsoleCursorInfo(console, &cursor_info);
  CONSOLE_SCREEN_BUFFER_INFO info = {0};
  GetConsoleScreenBufferInfo(console, &info);
  prev_bot = info.srWindow.Bottom;
  COORD prev_pos = info.dwCursorPosition;
  COORD next_pos = {.X = 0, .Y = prev_bot + 1};
  SetConsoleCursorPosition(console, next_pos);
  GetConsoleScreenBufferInfo(console, &info);
  SetConsoleCursorPosition(console, prev_pos);
  cursor_info.bVisible = prev_vis;
  SetConsoleCursorInfo(console, &cursor_info);
  next_bot = info.srWindow.Bottom;
  return prev_bot == next_bot;
}

#define viewport_warning L"Large inputs can cause minor scrollback issues in your terminal. " \
                         "If this is bothersome, you can use vanilla cmd.exe "                \
                         "(Command Prompt), which works perfectly." WCRLF

static inline bool init_repl(void) {
  if (!SetConsoleCP(CP_UTF8)) goto code_page;
  if (!SetConsoleOutputCP(CP_UTF8)) goto code_page;
  if ((repl.in = GetStdHandle(STD_INPUT_HANDLE)) == INVALID_HANDLE_VALUE) goto handle_in;
  if (!GetConsoleMode(repl.in, &repl.in_mode)) goto handle_in;
  if (!SetConsoleMode(repl.in, repl.in_mode | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT)) goto handle_in;
  if ((repl.out = GetStdHandle(STD_OUTPUT_HANDLE)) == INVALID_HANDLE_VALUE) goto handle_out;
  if ((repl.viewport_bound = bounded_console(repl.out))) wswrite(viewport_warning);
  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  if (!GetConsoleScreenBufferInfo_safe(repl.out, &buffer_info)) goto handle_out;
  repl.dwSize_X = (DWORD)buffer_info.dwSize.X;
  if (!GetConsoleCursorInfo(repl.out, &repl.cursor_info)) goto handle_out;
  if (!WriteConsoleW(repl.out, PREFIX_STR, PREFIX_STRLEN, NULL, NULL)) goto handle_out;
  repl.msg = create_console_message();
  repl.msg_index = 0;
  repl.home = (COORD){.X = PREFIX, .Y = buffer_info.dwCursorPosition.Y};
  repl._filled = 0;
  return true;
code_page:
  wswrite(L"Failed to modify console code page" WCRLF);
  return false;
handle_in:
  wswrite(L"Failed to setup console input handle" WCRLF);
  return false;
handle_out:
  wswrite(L"Failed to setup console output handle" WCRLF);
  return false;
}

static inline bool resize_console(void) {
  static struct Console_Buffer {
    CHAR_INFO *items;
    DWORD count;
    DWORD capacity;
  } console_buffer = {0};
  // NOTE: There are two important cases for when this event gets triggered:
  // either the cursor is automatically repositioned to the tail of
  // the user input / preview, OR it is not. The former seems way more likely,
  // but to support the latter, we just generalize and assume the latter.
  // A "benefit" of this is that we can use the preview before starting REPL.
  // TODO: update note, check types
  EnterCriticalSection(&log_lock);
  bool ok = false;
  hide_cursor();
  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  if (!GetConsoleScreenBufferInfo_safe(repl.out, &buffer_info)) {
    log_last_error("Failed to read console output region");
    goto cleanup;
  }
  assert(buffer_info.dwCursorPosition.Y < buffer_info.dwSize.Y - 1);
  DWORD buf_dwSize_X = (DWORD)buffer_info.dwSize.X;
  if (buf_dwSize_X == repl.dwSize_X) {
    ok = true;
    goto cleanup;
  }
  bool bottom_up = buf_dwSize_X > repl.dwSize_X;
  COORD upper_cursor = buffer_info.dwCursorPosition;
  DWORD upper_bound = cursor_to_index(buffer_info.dwCursorPosition, buf_dwSize_X);
  COORD lower_cursor = {.X = 0, .Y = repl.home.Y};
  DWORD lower_bound = cursor_to_index(lower_cursor, buf_dwSize_X);
  assert(upper_bound > 0);
  if (bottom_up && lower_bound >= upper_bound) {
    lower_bound = upper_bound / 2;
    lower_cursor = index_to_cursor(lower_bound, buf_dwSize_X);
  }
  SHORT rows = upper_cursor.Y - lower_cursor.Y + 1;
  assert(rows > 0);
  assert(rows <= SHRT_MAX);
  SHORT cols = (SHORT)buf_dwSize_X;
  COORD buffer_size = {.X = cols, .Y = rows};
  DWORD buffer_count = (DWORD)cols * (DWORD)rows;
  array_resize(&console_buffer, buffer_count);
  COORD region_start = {.X = 0, .Y = 0};
  SMALL_RECT region = {
      .Left = 0,
      .Top = lower_cursor.Y,
      .Right = cols - 1,
      .Bottom = upper_cursor.Y};
  if (!ReadConsoleOutputW(repl.out, console_buffer.items, buffer_size, region_start, &region)) {
    log_last_error("Failed to read console output region");
    goto cleanup;
  }
  bool match = false;
  if (bottom_up) {
    for (;;) {
      for (SHORT i = 0; i < rows; ++i) {
        SHORT row = rows - 1 - i;
        assert(row >= 0);
        DWORD head = (DWORD)row * buf_dwSize_X;
        if (console_buffer.items[head].Char.UnicodeChar == PREFIX_TOKEN) {
          repl.home.Y = lower_cursor.Y + row;
          match = true;
          goto outer;
        }
      }
      if (lower_bound == 0) goto outer;
      upper_bound = lower_bound;
      upper_cursor = lower_cursor;
      lower_bound /= 2;
      lower_cursor = index_to_cursor(lower_bound, buf_dwSize_X);
      rows = upper_cursor.Y - lower_cursor.Y + 1;
      buffer_size.Y = rows;
      buffer_count = (DWORD)cols * (DWORD)rows;
      array_resize(&console_buffer, buffer_count);
      region.Left = 0;
      region.Top = lower_cursor.Y;
      region.Right = cols - 1;
      region.Bottom = upper_cursor.Y;
      if (!ReadConsoleOutputW(repl.out, console_buffer.items, buffer_size, region_start, &region)) {
        log_last_error("Failed to read console output region");
        goto cleanup;
      }
    }
  outer:;
  } else {
    for (DWORD i = 0; i < (DWORD)rows; ++i) {
      if (console_buffer.items[i * buf_dwSize_X].Char.UnicodeChar == PREFIX_TOKEN) {
        repl.home.Y = lower_cursor.Y + (SHORT)i;
        match = true;
        break;
      }
    }
  }
  assert(match && "Failed to find prefix token in console output. viewport_bound?");
  SHORT msg_shift = (SHORT)((repl.msg->count + PREFIX) / buf_dwSize_X);
  preview.pos.Y = repl.home.Y + msg_shift + 1;
  assert(preview.pos.X == 0);
  if (preview.len > buf_dwSize_X) {
    preview.pos.X = 0;
    ++preview.pos.Y;
    DWORD leftover = preview.len - buf_dwSize_X;
    FillConsoleOutputCharacterW(repl.out, CIN_SPACE, leftover, preview.pos, &repl._filled);
    --preview.pos.Y;
  }
  repl.dwSize_X = buf_dwSize_X;
  log_preview();
  ok = true;
cleanup:
  show_cursor();
  LeaveCriticalSection(&log_lock);
  return ok;
}

static inline bool evaluate_input(void) {
  return true;
}

typedef enum {
  CIN_TIMER_RESIZE,
  CIN_TIMER_EVALUATE,
  _CIN_TIMER_END
} Console_Timer_Type;

typedef struct Console_Timer_Ctx {
  PTP_TIMER timer;
  LONGLONG millis;
  bool (*f)(void);
} Console_Timer_Ctx;

static Console_Timer_Ctx console_timers[_CIN_TIMER_END];

static VOID CALLBACK console_timer_callback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer) {
  (void)Instance;
  (void)Timer;
  Console_Timer_Ctx *ctx = (Console_Timer_Ctx *)Context;
  bool ok = ctx->f();
  assert(ok);
}

static inline bool register_console_timer(Console_Timer_Type type, bool (*f)(void), LONGLONG millis) {
  Console_Timer_Ctx *ctx = &console_timers[type];
  ctx->millis = millis;
  ctx->f = f;
  ctx->timer = CreateThreadpoolTimer(console_timer_callback, ctx, NULL);
  if (ctx->timer == NULL) {
    log_last_error("Failed to register console timer");
    return false;
  }
  return true;
}

static inline void reset_console_timer(Console_Timer_Type type) {
  Console_Timer_Ctx *ctx = &console_timers[type];
  LARGE_INTEGER t;
  FILETIME ft;
  t.QuadPart = ctx->millis * -10000LL;
  ft.dwHighDateTime = (DWORD)t.HighPart;
  ft.dwLowDateTime = (DWORD)t.LowPart;
  SetThreadpoolTimer(ctx->timer, &ft, 0, 0);
}

static inline bool init_timers(void) {
  if (!register_console_timer(CIN_TIMER_RESIZE, resize_console, 100LL)) return false;
  // if (!register_console_timer(CIN_TIMER_EVALUATE, evaluate_input, 2000LL)) return false;
  return true;
}

#define COMMAND_ALPHABET 26

typedef void (*patricia_fn)(void);

typedef struct PatriciaNode {
  struct PatriciaNode *edges[COMMAND_ALPHABET];
  const char *suffix;
  size_t len;
  patricia_fn fn;
  int32_t min;
} PatriciaNode;

static inline PatriciaNode *patricia_node(const char *suffix, size_t len) {
  PatriciaNode *node = calloc(1, sizeof(PatriciaNode));
  assert(node);
  node->suffix = suffix;
  node->len = len;
  return node;
}

static inline size_t patricia_lcp(const char *a, const char *b, size_t max) {
  size_t i = 0;
  while (i < max && a[i] && a[i] == b[i]) i++;
  return i;
}

static inline patricia_fn patricia_query(PatriciaNode *root, const char *pattern) {
  assert(root);
  assert(strlen(pattern) > 0);
  assert((*pattern >= 'a' && *pattern <= 'z'));
  PatriciaNode *node = root;
  const char *p = pattern;
  while (*p) {
    assert((*p >= 'a' && *p <= 'z'));
    int32_t i = *p - 'a';
    PatriciaNode *edge = node->edges[i];
    if (edge == NULL) {
      return NULL;
    }
    size_t common = patricia_lcp(p, edge->suffix, edge->len);
    if (p[common] == '\0') {
      return edge->fn;
    }
    if (common < edge->len) {
      return NULL;
    }
    p += common;
    node = edge;
  }
  return node->fn;
}

static inline void patricia_insert(PatriciaNode *root, const char *str, patricia_fn fn) {
  assert(root);
  assert(strlen(str) > 0);
  assert((*str >= 'a' && *str <= 'z'));
  PatriciaNode *node = root;
  const char *p = str;
  while (*p) {
    assert((*p >= 'a' && *p <= 'z'));
    int32_t i = *p - 'a';
    PatriciaNode *edge = node->edges[i];
    if (edge == NULL) {
      edge = patricia_node(p, strlen(p));
      edge->fn = fn;
      node->edges[i] = edge;
      if ((node->min == -1) || i < node->min) {
        // update parent lexicographical minimum
        node->min = i;
        node->fn = fn;
      }
      return;
    }
    size_t common = patricia_lcp(p, edge->suffix, edge->len);
    if (common == edge->len) {
      p += common;
      if (*p == '\0') {
        edge->min = -1;
        edge->fn = fn;
        return;
      }
      node = edge;
    } else {
      PatriciaNode *split = patricia_node(edge->suffix, common);
      edge->suffix += common;
      edge->len -= common;
      node->edges[i] = split;
      split->edges[edge->suffix[0] - 'a'] = edge;
      p += common;
      if (*p == '\0') {
        split->min = -1;
        split->fn = fn;
      } else {
        PatriciaNode *remainder = patricia_node(p, strlen(p));
        remainder->fn = fn;
        int32_t edge_i = edge->suffix[0] - 'a';
        int32_t next_i = *p - 'a';
        split->edges[next_i] = remainder;
        // update internal node lexicographical minimum
        if (next_i < edge_i) {
          split->min = next_i;
          split->fn = fn;
        } else {
          split->min = edge_i;
          split->fn = edge->fn;
        }
      }
      return;
    }
  }
}

static void cmd_help(void) {
  log_message(LOG_INFO, "Help");
}

static void init_commands(void) {
  PatriciaNode *root = patricia_node(NULL, 0);
  patricia_insert(root, "help", cmd_help);
  patricia_fn fn = patricia_query(root, "h");
  if (fn == NULL) {
    log_message(LOG_INFO, "Pattern not found.");
  } else {
    fn();
  }
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
#if !defined(_WIN32)
  printf("Error: Your operating system is not supported, Windows-only currently.\n");
  return 1;
#endif
  if (!init_repl()) exit(1);
  InitializeCriticalSectionAndSpinCount(&log_lock, 0);
  if (!init_timers()) exit(1);
  if (!init_config("cinema.conf")) exit(1);
  // init_commands();
  if (!init_document_listing()) exit(1);
  // uint8_t pattern[] = "twitch.tv";
  // document_listing(pattern, (int32_t)strlen((const char *)pattern));
  // exit(1);
  // NOTE: It seems impossible to reach outside the bounds of the viewport
  // within Windows Terminal using a custom ReadConsoleInput approach. Virtual
  // terminal sequences and related APIs are bound to the viewport. So,
  // we must use the built-in cooked input mode with ReadConsole, OR modify
  // the cmd.exe approach using screen clear tricks and partial writes,
  // but even then the scroll space will surely become confusing at some
  // point. We accept the scrollback issues and support relative consoles.
  // TODO: support bounded viewport (excluding scrollback) maybe VT100
  // size_t visible_lines = repl.screen_info.srWindow.Bottom - repl.screen_info.srWindow.Top;
  Console_Message *msg_tail = NULL;
  for (;;) {
    show_cursor();
    INPUT_RECORD input;
    DWORD read;
    if (!ReadConsoleInputW(repl.in, &input, 1, &read)) {
      log_last_error("Failed to read console input");
      break;
    }
    wchar_t c = input.Event.KeyEvent.uChar.UnicodeChar;
    wchar_t vk = input.Event.KeyEvent.wVirtualKeyCode;
    if (!input.Event.KeyEvent.bKeyDown && (!c || vk != VK_MENU)) continue;
    switch (input.EventType) {
    case KEY_EVENT:
      hide_cursor();
      break;
    case WINDOW_BUFFER_SIZE_EVENT:
      reset_console_timer(CIN_TIMER_RESIZE);
      continue;
    default:
      continue;
    }
    switch (vk) {
    case VK_RETURN: {
      clear_full();
      cursor_home();
      assert(repl.msg->items);
      DWORD i = repl.msg->count;
      while (i && iswspace(repl.msg->items[i - 1])) --i;
      bool empty = !i;
      bool dup = !empty && msg_tail && repl.msg->count == msg_tail->count &&
                 !wcsncmp(repl.msg->items, msg_tail->items, repl.msg->count);
      if (empty || dup) {
        if (msg_tail) repl.msg->prev = msg_tail;
        repl.msg->next = NULL;
        repl.msg_index = 0;
        repl.msg->count = 0;
      } else {
        // commit to history
        if (msg_tail) {
          msg_tail->next = repl.msg;
          repl.msg->prev = msg_tail;
        }
        repl.msg->next = NULL;
        msg_tail = repl.msg;
        repl.msg = create_console_message();
        repl.msg->prev = msg_tail;
        repl.msg_index = 0;
        repl.msg->count = 0;
      }
    } break;
    case VK_ESCAPE: {
      clear_full();
      cursor_home();
      repl.msg_index = 0;
      repl.msg->count = 0;
    } break;
    case VK_HOME:
      cursor_home();
      repl.msg_index = 0;
      continue;
    case VK_END:
      repl.msg_index = repl.msg->count;
      cursor_curr();
      continue;
    case VK_BACK: {
      if (!repl.msg_index) continue;
      DWORD left = repl.msg_index - 1;
      if (ctrl_on(&input)) {
        while (left && repl.msg->items[left] == CIN_SPACE) --left;
        while (left && repl.msg->items[left - 1] != CIN_SPACE) --left;
      }
      if (repl.msg_index < repl.msg->count) {
        wmemmove(&repl.msg->items[left], &repl.msg->items[repl.msg_index], repl.msg->count - repl.msg_index);
      }
      DWORD deleted = repl.msg_index - left;
      repl.msg->count -= deleted;
      repl.msg_index = left;
      cursor_curr();
      DWORD leftover = repl.msg->count - repl.msg_index;
      clear_tail(deleted);
      if (leftover) {
        wwrite(repl.msg->items + repl.msg_index, leftover);
        cursor_curr();
      }
    } break;
    case VK_DELETE: {
      if (repl.msg_index == repl.msg->count) continue;
      DWORD right = repl.msg_index;
      if (ctrl_on(&input)) {
        while (right < repl.msg->count && repl.msg->items[right] != CIN_SPACE) ++right;
        while (right < repl.msg->count && repl.msg->items[++right] == CIN_SPACE);
      } else {
        ++right;
      }
      DWORD leftover = repl.msg->count - right;
      DWORD deleted = right - repl.msg_index;
      repl.msg->count -= deleted;
      clear_tail(deleted);
      if (leftover) {
        wmemmove(&repl.msg->items[repl.msg_index], &repl.msg->items[right], leftover);
        wwrite(repl.msg->items + repl.msg_index, leftover);
        cursor_curr();
      }
    } break;
    case VK_UP: {
      if (!repl.msg->prev) continue;
      DWORD prev_count = repl.msg->count;
      array_resize(repl.msg, repl.msg->prev->count);
      wmemcpy(repl.msg->items, repl.msg->prev->items, repl.msg->prev->count);
      repl.msg_index = repl.msg->count;
      repl.msg->next = repl.msg->prev->next;
      repl.msg->prev = repl.msg->prev->prev;
      if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
      cursor_home();
      wwrite(repl.msg->items, repl.msg->count);
    } break;
    case VK_DOWN: {
      if (repl.msg->next) {
        DWORD prev_count = repl.msg->count;
        repl.msg->capacity = repl.msg->next->capacity;
        repl.msg->count = repl.msg->next->count;
        wmemcpy(repl.msg->items, repl.msg->next->items, repl.msg->next->count);
        if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
        cursor_home();
        wwrite(repl.msg->items, repl.msg->count);
        repl.msg->prev = repl.msg->next->prev;
        repl.msg->next = repl.msg->next->next;
        repl.msg_index = repl.msg->count;
      } else {
        clear_full();
        cursor_home();
        repl.msg->prev = msg_tail;
        repl.msg->count = 0;
        repl.msg_index = 0;
      }
    } break;
    case VK_PRIOR: {
      if (!repl.msg->prev) continue;
      Console_Message *head = repl.msg->prev;
      while (head->prev) head = head->prev;
      DWORD prev_count = repl.msg->count;
      array_resize(repl.msg, head->count);
      wmemcpy(repl.msg->items, head->items, head->count);
      repl.msg_index = repl.msg->count;
      repl.msg->next = head->next;
      head = head->prev;
      if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
      cursor_home();
      wwrite(repl.msg->items, repl.msg->count);
    } break;
    case VK_NEXT: {
      if (msg_tail) {
        DWORD prev_count = repl.msg->count;
        repl.msg->capacity = msg_tail->capacity;
        repl.msg->count = msg_tail->count;
        wmemcpy(repl.msg->items, msg_tail->items, msg_tail->count);
        if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
        cursor_home();
        wwrite(repl.msg->items, repl.msg->count);
        repl.msg->prev = msg_tail->prev;
        repl.msg->next = msg_tail->next;
        repl.msg_index = repl.msg->count;
      } else {
        clear_full();
        cursor_home();
        repl.msg->count = 0;
        repl.msg_index = 0;
      }
    } break;
    case VK_LEFT:
      if (repl.msg_index) {
        --repl.msg_index;
        if (ctrl_on(&input)) {
          while (repl.msg_index && repl.msg->items[repl.msg_index] == CIN_SPACE) --repl.msg_index;
          while (repl.msg_index && repl.msg->items[repl.msg_index - 1] != CIN_SPACE) --repl.msg_index;
        }
        cursor_curr();
      }
      continue;
    case VK_RIGHT:
      if (repl.msg_index < repl.msg->count) {
        if (ctrl_on(&input)) {
          while (repl.msg_index < repl.msg->count && repl.msg->items[repl.msg_index] != CIN_SPACE) ++repl.msg_index;
          while (repl.msg_index < repl.msg->count && repl.msg->items[++repl.msg_index] == CIN_SPACE);
        } else {
          ++repl.msg_index;
        }
        cursor_curr();
      }
      continue;
    case VK_TAB:
      continue;
    default:
      if (!c || c == PREFIX_TOKEN) continue;
      c = cin_wlower(c);
      assert(repl.msg_index <= repl.msg->count);
      if (repl.msg_index == repl.msg->count) {
        wwrite(&c, 1);
        array_push(repl.msg, c);
        ++repl.msg_index;
      } else {
        array_insert(repl.msg, repl.msg_index, c);
        wwrite(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
        ++repl.msg_index;
        cursor_curr();
      }
      log_wmessage(LOG_ERROR, L"char=%hu (%lc), v=%hu (%lc), pressed=%d, ctrl=%d",
                   c, c, vk, vk ? vk : L' ', input.Event.KeyEvent.bKeyDown, ctrl_on(&input));
      break;
    }
    SHORT preview_offset = (SHORT)((repl.msg->count + PREFIX) / repl.dwSize_X) + 1;
    SHORT preview_line = repl.home.Y + preview_offset;
    SHORT y_diff = preview_line - preview.pos.Y;
    if (y_diff < 0) {
      clear_preview((SHORT)(repl.dwSize_X - preview.len));
    } else if (y_diff == 1) {
      DWORD tail_x = (repl.msg->count + PREFIX) % repl.dwSize_X;
      if (preview.len > tail_x) {
        clear_preview((SHORT)tail_x);
      }
    }
    set_preview_pos(preview_line);
    update_preview();
    log_preview();
  }
  if (!SetConsoleMode(repl.in, repl.in_mode)) {
    log_last_error("Failed to reset in console mode");
    return 1;
  }
  if (repl.viewport_bound) {
    // TODO: enable if using virtual terminal sequences if viewport_bound
    // if (!SetConsoleMode(repl.out, console_mode_out)) {
    //   log_last_error( "Failed to reset out console mode");
    //   return 1;
    // }
  }
  return 0;

  wchar_t *name = L"D:\\Test\\0_561mb.mp4";
  if (name == NULL) {
    log_message(LOG_ERROR, "No valid 'path' found in config");
    return 1;
  }

  HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  DWORD listener_id;
  HANDLE listener = CreateThread(NULL, 0, iocp_listener, (LPVOID)iocp, 0, &listener_id);
  if (listener == NULL) {
    log_last_error("Failed to create listener thread");
    return 1;
  }

  size_t count = 1;
  Instance *pipes = malloc(count * sizeof(Instance));
  if (pipes == NULL) {
    log_message(LOG_ERROR, "Failed to allocate memory for count=%d", count);
    return false;
  }

  process_layout(count, pipes, name, iocp);
  free(name);
  for (size_t i = 0; i < count; ++i) {
    log_message(LOG_INFO, "Instance[%zu] Process ID: %lu", i, (unsigned long)pipes[i].pi.dwProcessId);
  }

  Sleep(2000);
  cJSON *command = mpv_command("loadfile", pipes[0].request_id++);
  cJSON *command_array = cJSON_GetObjectItem(command, "command");
  cJSON *command_arg = cJSON_CreateString("D:\\Test\\video ❗.mp4");
  cJSON_AddItemToArray(command_array, command_arg);
  overlap_write(&pipes[0], command);

  Sleep(2000);
  // normalizing backslash probably not worth
  cJSON *command2 = mpv_command("normalize-path", pipes[0].request_id++);
  cJSON *command_array2 = cJSON_GetObjectItem(command2, "command");
  cJSON *command_arg2 = cJSON_CreateString("D:/Test/video ❗.mp4");
  cJSON_AddItemToArray(command_array2, command_arg2);
  overlap_write(&pipes[0], command2);

  Sleep(2000);

  // https://mpv.io/manual/stable/#json-ipc
  // mpv file.mkv --input-ipc-server=\\.\pipe\mpvsocket
  // echo loadfile "filepath" replace >\\.\pipe\mpvsocket
  // ipc commands:
  // https://mpv.io/manual/stable/#list-of-input-commands
  // https://mpv.io/manual/stable/#commands-with-named-arguments
  // these commands can also be async

  // TODO: subtitles conf
  // TODO: urls
  // TODO: substring search with SA/LCP
  // TODO: tag lookup with circular buffer and exclusion window
  return 0;
}
