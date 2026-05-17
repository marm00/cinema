#ifndef CIN_OS_WIN32_H
#define CIN_OS_WIN32_H

#include <wchar.h>
#include <windows.h>

#include "os.h"

extern wchar_t exe_wpath_mpv[CIN_MAX_PATH];
extern wchar_t exe_wpath_ytdlp[CIN_MAX_PATH];
extern wchar_t exe_wpath_chatterino[CIN_MAX_PATH];

bool find_exe(const wchar_t *dir, const wchar_t *exe, wchar_t *buf);
bool init_executables(void);

#endif