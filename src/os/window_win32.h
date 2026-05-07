#ifndef CIN_WINDOW_WIN32_h
#define CIN_WINDOW_WIN32_h

#include <stdint.h>
#include <windows.h>

typedef struct Window_Data {
  union {
    DWORD pid;
    wchar_t *name;
    struct {
      DWORD *pids;
      DWORD count;
    };
  };
  HWND hwnd;
} Window_Data;

int32_t CALLBACK enum_windows_proc_pid(HWND hwnd, LPARAM lParam);
HWND find_window_by_pid(uint32_t pid);
int32_t CALLBACK enum_windows_proc_name(HWND hwnd, LPARAM lParam);
HWND find_window_by_name(wchar_t *name);
int32_t CALLBACK enum_windows_proc_console(HWND hwnd, LPARAM lParam);
HWND find_window_of_console(void);

#endif