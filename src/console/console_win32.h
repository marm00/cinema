#ifndef CIN_CONSOLE_WIN32_H
#define CIN_CONSOLE_WIN32_H

#include <stdint.h>
#include <windows.h>

#include "base/array.h"

array_define(UTF16_Buffer, wchar_t);
extern UTF16_Buffer utf16_buf_raw;
extern UTF16_Buffer utf16_buf_norm;
int32_t utf16_to_utf8(const wchar_t *wstr);
int32_t utf8_to_utf16_raw(const char *str);
int32_t utf8_to_utf16_nraw(const char *str, int32_t len);
int32_t utf16_norm(const wchar_t *str);
int32_t utf8_to_utf16_norm(const char *str);
void cin_wwrite(const wchar_t *str, uint32_t len);
void cin_wswrite(const wchar_t *str);
void cin_wwritef(const wchar_t *format, ...);
void cin_wvwritef(const wchar_t *format, va_list args);

#endif