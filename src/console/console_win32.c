#include <windows.h>

#include "console.h"
#include "console_win32.h"

UTF16_Buffer utf16_buf_raw = {0};
UTF16_Buffer utf16_buf_norm = {0};
static UTF16_Buffer wwrite_buf = {0};

int32_t utf16_to_utf8(const wchar_t *wstr) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
  assert(utf8_buf.items);
  assert(wstr);
  // because cchWideChar is set to -1, the output is null-terminated (and len includes it)
  // n_bytes represents the char count needed
  const int32_t n_bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  assert(n_bytes);
  array_resize(&arena_console, &utf8_buf, (uint32_t)n_bytes);
  return WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char *)utf8_buf.items, n_bytes, NULL, NULL);
}

int32_t utf8_to_utf16_raw(const char *str) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
  assert(utf16_buf_raw.items);
  assert(str);
  // because cbMultiByte is set to -1, the output is null-terminated (and len includes it)
  // n_chars represents the wchar_t count needed
  const int32_t n_chars = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  assert(n_chars);
  array_resize(&arena_console, &utf16_buf_raw, (uint32_t)n_chars);
  return MultiByteToWideChar(CP_UTF8, 0, str, -1, utf16_buf_raw.items, n_chars);
}

int32_t utf8_to_utf16_nraw(const char *str, int32_t len) {
  assert(utf16_buf_raw.items);
  assert(str);
  // process len bytes, with n_chars not including null terminator
  const int32_t n_chars = MultiByteToWideChar(CP_UTF8, 0, str, len, NULL, 0);
  assert(n_chars);
  array_resize(&arena_console, &utf16_buf_raw, (uint32_t)n_chars);
  return MultiByteToWideChar(CP_UTF8, 0, str, len, utf16_buf_raw.items, n_chars);
}

int32_t utf16_norm(const wchar_t *str) {
  // n_chars represents the possibly updated wchar_t count needed
  const int32_t n_chars = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE,
                                        str, -1, NULL, 0, NULL, NULL, 0);
  assert(n_chars);
  array_resize(&arena_console, &utf16_buf_norm, (uint32_t)n_chars);
  return LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, str,
                       -1, utf16_buf_norm.items, n_chars, NULL, NULL, 0);
}

int32_t utf8_to_utf16_norm(const char *str) {
  const int32_t len = utf8_to_utf16_raw(str);
  assert(len);
  return utf16_norm(utf16_buf_raw.items);
}

void cin_write(const char *str, uint32_t len) {
  assert(len);
  const int32_t len_i32 = utf8_to_utf16_nraw(str, (int32_t)len);
  assert(len_i32 > 0);
  wchar_t *utf16_str = utf16_buf_raw.items;
  WriteConsoleW(repl.out, utf16_str, (uint32_t)len_i32, NULL, NULL);
}

void cin_wwrite(const wchar_t *str, uint32_t len) {
  WriteConsoleW(repl.out, str, len, NULL, NULL);
}

void cin_wswrite(const wchar_t *str) {
  assert(wcslen(str) <= SIZE_MAX && "Corrupted string");
  const size_t len = wcslen(str);
  WriteConsoleW(repl.out, str, (uint32_t)len, NULL, NULL);
}

void cin_wwritef(const wchar_t *format, ...) {
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
  const int32_t len_i32 = _vscwprintf(format, args);
  assert(len_i32 >= 0);
  const uint32_t len = (uint32_t)len_i32;
  va_end(args);
  array_resize(&arena_console, &wwrite_buf, len + 1);
  _vsnwprintf_s(wwrite_buf.items, len + 1, len, format, args_dup);
  va_end(args_dup);
  WriteConsoleW(repl.out, wwrite_buf.items, len, NULL, NULL);
}

void cin_wvwritef(const wchar_t *format, va_list args) {
  va_list args_dup;
  va_copy(args_dup, args);
  const int32_t len_i32 = _vscwprintf(format, args_dup);
  assert(len_i32 >= 0);
  const uint32_t len = (uint32_t)len_i32;
  va_end(args_dup);
  array_resize(&arena_console, &wwrite_buf, len + 1);
  _vsnwprintf_s(wwrite_buf.items, len + 1, len, format, args);
  WriteConsoleW(repl.out, wwrite_buf.items, len, NULL, NULL);
}

bool term_get_cursor(COORD *cursor) {
  CONSOLE_SCREEN_BUFFER_INFO info;
  GetConsoleScreenBufferInfo(repl.out, &info);
  cursor->X = info.dwCursorPosition.X - info.srWindow.Left;
  cursor->Y = info.dwCursorPosition.Y - info.srWindow.Top + 1;
  return true;
}

COORD term_get_size(COORD *size) {
  COORD size_change = {0};
  const short prev_x = size->X;
  const short prev_y = size->Y;
  CONSOLE_SCREEN_BUFFER_INFO info;
  GetConsoleScreenBufferInfo(repl.out, &info);
  size->X = info.srWindow.Right - info.srWindow.Left + 1;
  size->Y = info.srWindow.Bottom - info.srWindow.Top + 1;
  size_change.X = size->X - prev_x;
  size_change.Y = size->Y - prev_y;
  return size_change;
}
