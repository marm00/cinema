#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "base/core.h"
#include "console/console_win32.h"
#include "console/log.h"
#include "os.h"
#include "os_win32.h"

#ifdef CIN_OPENMP
#include <omp.h>
#endif

struct Cin_System cin_system = {
    .page_size = 4096,
    .alloc_type = MEM_RESERVE | MEM_COMMIT,
    .threads = 1};

void *os_alloc(size_t bytes) {
  void *chunk = VirtualAlloc(NULL, bytes, cin_system.alloc_type, PAGE_READWRITE);
  if (!chunk) {
    uint32_t code = GetLastError();
    printf("Cinema crashed with code %u trying to allocate memory with VirtualAlloc", code);
    // https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes
    cin_exit(1);
  }
  return chunk;
}

bool init_os(void) {
  SYSTEM_INFO system;
  GetSystemInfo(&system);
  cin_system.page_size = (size_t)system.dwPageSize;
  cin_system.threads = (int32_t)system.dwNumberOfProcessors;
  HANDLE token;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &luid)) {
      TOKEN_PRIVILEGES p = {.PrivilegeCount = 1,
                            .Privileges[0] = {.Luid = luid, .Attributes = SE_PRIVILEGE_ENABLED}};
      AdjustTokenPrivileges(token, FALSE, &p, sizeof(p), NULL, NULL);
      if (GetLastError() == ERROR_SUCCESS) {
        cin_system.alloc_type |= MEM_LARGE_PAGES;
        cin_system.page_size = GetLargePageMinimum();
      }
    }
    CloseHandle(token);
  }
#ifdef CIN_OPENMP
  omp_set_num_threads(cin_system.threads);
#endif
  return true;
}

void os_random(uint32_t *out) {
  uint32_t random;
  rand_s(&random);
  *out = random;
}

void os_sleep(long millis) {
  Sleep((DWORD)millis);
}

wchar_t exe_wpath_mpv[CIN_MAX_PATH] = {0};
wchar_t exe_wpath_ytdlp[CIN_MAX_PATH] = {0};
wchar_t exe_wpath_chatterino[CIN_MAX_PATH] = {0};

bool find_exe(const wchar_t *dir, const wchar_t *exe, wchar_t *buf) {
  const wchar_t extension[] = L".exe";
  if (SearchPathW(NULL, exe, extension, CIN_MAX_PATH, buf, NULL)) return true;
  wchar_t reg_key[CIN_MAX_PATH];
  swprintf_s(reg_key, CIN_MAX_PATH,
             L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\%s%s",
             exe, wcsstr(exe, L".exe") ? L"" : L".exe");
  HKEY roots[] = {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER};
  for (size_t i = 0; i < 2; ++i) {
    HKEY hk;
    if (RegOpenKeyExW(roots[i], reg_key, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
      DWORD type, sz = CIN_MAX_PATH * sizeof(wchar_t);
      LSTATUS st = RegQueryValueExW(hk, NULL, NULL, &type, (BYTE *)buf, &sz);
      RegCloseKey(hk);
      if (st == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
        if (type == REG_EXPAND_SZ) ExpandEnvironmentStringsW(buf, buf, CIN_MAX_PATH);
        return true;
      }
    }
  }
  const wchar_t *paths[] = {
      L"C:\\Program Files\\",
      L"C:\\Program Files (x86)\\",
      L"%LOCALAPPDATA%\\Programs\\",
      NULL};
  const size_t dir_len = wcslen(dir);
  const size_t exe_len = wcslen(exe);
  wchar_t exe_expanded[CIN_MAX_PATH] = {0};
  for (size_t i = 0; paths[i]; ++i) {
    size_t buf_offset = 0;
    uint32_t path_len = ExpandEnvironmentStringsW(paths[i], exe_expanded, CIN_MAX_PATH);
    assert(path_len > 1);
    if (path_len <= 1) continue;
    --path_len;
    wmemcpy(buf + buf_offset, exe_expanded, path_len);
    buf_offset += path_len;
    wmemcpy(buf + buf_offset, dir, dir_len);
    buf_offset += dir_len;
    buf[buf_offset++] = L'\\';
    wmemcpy(buf + buf_offset, exe, exe_len);
    buf_offset += exe_len;
    wmemcpy(buf + buf_offset, extension, cin_strlen(extension));
    buf_offset += cin_strlen(extension);
    buf[buf_offset] = L'\0';
    const uint32_t attrs = GetFileAttributesW(buf);
    if (attrs != INVALID_FILE_ATTRIBUTES) return true;
  }
  log_wmessage(LOG_ERROR, L"Failed to find executable '%s'. "
                          L"Please install it in a standard directory or add it to your environment variables "
                          L"or copy it next to cinema or specify the path in cinema.conf.",
               exe);
  wmemset(buf, L'\0', CIN_MAX_PATH);
  return false;
}

bool init_executables(void) {
  if (*exe_path_mpv) {
    int32_t len = utf8_to_utf16_raw(exe_path_mpv);
    wmemcpy(exe_wpath_mpv, utf16_buf_raw.items, (size_t)len);
  } else if (!find_exe(L"mpv", L"mpv", exe_wpath_mpv)) {
    return false;
  }
  if (*exe_path_ytdlp) {
    int32_t len = utf8_to_utf16_raw(exe_path_ytdlp);
    wmemcpy(exe_wpath_ytdlp, utf16_buf_raw.items, (size_t)len);
  } else if (!find_exe(L"mpv", L"yt-dlp", exe_wpath_ytdlp)) {
    return false;
  }
  if (*exe_path_chatterino) {
    int32_t len = utf8_to_utf16_raw(exe_path_chatterino);
    wmemcpy(exe_wpath_chatterino, utf16_buf_raw.items, (size_t)len);
  } else {
    find_exe(L"Chatterino", L"chatterino", exe_wpath_chatterino);
  }
  return true;
}