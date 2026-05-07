#include "window_win32.h"
#include "base/array.h"
#include "io/io.h"
#include "window.h"

bool cin_iswindow(HWND window) {
  return IsWindow(window);
}

bool cin_isvisible(HWND window) {
  return IsWindowVisible(window);
}

int32_t cin_getwindow(HWND window, RECT *out_rect) {
  return GetWindowRect(window, out_rect);
}

int32_t cin_movewindow(HWND window, RECT rect) {
  const int32_t x = (int32_t)rect.left;
  const int32_t y = (int32_t)rect.top;
  const int32_t cx = (int32_t)rect.right;
  const int32_t cy = (int32_t)rect.bottom;
  return SetWindowPos(window, HWND_TOPMOST, x, y, cx, cy, SWP_SHOWWINDOW);
}

int32_t CALLBACK enum_windows_proc_pid(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  DWORD pid;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid == data->pid && IsWindow(hwnd)) {
    data->hwnd = hwnd;
    return FALSE;
  }
  return TRUE;
}

HWND find_window_by_pid(uint32_t pid) {
  Window_Data data = {.pid = pid, .hwnd = NULL};
  EnumWindows(enum_windows_proc_pid, (LPARAM)&data);
  return data.hwnd;
}

int32_t CALLBACK enum_windows_proc_name(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  wchar_t *pattern = data->name;
  wchar_t query[MAX_CLASS_NAME];
  GetClassNameW(hwnd, query, sizeof(query));
  if (wcscmp(pattern, query) == 0) {
    data->hwnd = hwnd;
    return FALSE;
  }
  return TRUE;
}

HWND find_window_by_name(wchar_t *name) {
  Window_Data data = {.name = name, .hwnd = NULL};
  EnumWindows(enum_windows_proc_name, (LPARAM)&data);
  return data.hwnd;
}

int32_t CALLBACK enum_windows_proc_console(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  DWORD pid;
  GetWindowThreadProcessId(hwnd, &pid);
  for (uint32_t i = 0; i < data->count; i++) {
    if (pid == data->pids[i]) {
      if (IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == NULL) {
        data->hwnd = hwnd;
        return FALSE;
      }
    }
  }
  return TRUE;
}

HWND find_window_of_console(void) {
  array_struct(DWORD) pids = {0};
  DWORD dwProcessCount = 16;
  array_init(&arena_iocp_thread, &pids, dwProcessCount);
  DWORD actual_count = GetConsoleProcessList(pids.items, dwProcessCount);
  array_resize(&arena_iocp_thread, &pids, actual_count);
  if (actual_count > dwProcessCount) {
    dwProcessCount = actual_count;
    actual_count = GetConsoleProcessList(pids.items, dwProcessCount);
  }
  Window_Data data = {.pids = pids.items, .count = actual_count, .hwnd = NULL};
  EnumWindows(enum_windows_proc_console, (LPARAM)&data);
  array_free_items(&arena_iocp_thread, &pids);
  return data.hwnd;
}