#include "console/console_win32.h"
#include "io.h"
#include "os/os_win32.h"
#include "os/window_win32.h"

bool create_pipe(Instance *instance, const wchar_t *name) {
  // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
  // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
  static const int FOUND_TIMEOUT = 20000;
  static const int UNFOUND_TIMEOUT = 20000;
  static const int UNFOUND_WAIT = 50;
  log_wmessage(LOG_DEBUG, L"Creating pipe: %s", name);
  int unfound_duration = 0;
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  for (;;) {
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
      os_sleep(UNFOUND_WAIT);
    } else {
      // Unlikely error, try to resolve by waiting
      log_last_error("Could not connect to pipe - Waiting for %dms", FOUND_TIMEOUT);
      if (!WaitNamedPipeW(name, FOUND_TIMEOUT)) {
        log_last_error("Failed to connect to pipe");
        return false;
      }
    }
  }
  instance->socket = hPipe;
  log_message(LOG_TRACE, "Successfully created pipe (HANDLE) %p", (void *)instance->socket);
  return true;
}

bool overlap_read(Instance *instance) {
  memset(&instance->ovl_ctx.ovl, 0, sizeof(OVERLAPPED));
  char *start = instance->buf_tail->buf + instance->buf_tail->bytes;
  const uint32_t to_read = (uint32_t)(sizeof(instance->buf_tail->buf) - instance->buf_tail->bytes);
  if (instance->socket && !ReadFile(instance->socket, start, to_read, NULL, &instance->ovl_ctx.ovl)) {
    if (GetLastError() != ERROR_IO_PENDING) {
      log_last_error("Failed to initialize read");
      return false;
    }
  }
  // Read is queued for iocp
  return true;
}

bool internal_write(Instance *instance, Overlapped_Write *msg, int32_t bytes) {
  (void)bytes;
  bool ok = true;
  if (instance->socket && !WriteFile(instance->socket, msg->buf, (DWORD)msg->bytes, NULL, &msg->ovl_ctx.ovl)) {
    switch (GetLastError()) {
    case ERROR_IO_PENDING:
      // iocp will free write
      log_message(LOG_TRACE, "Pending write call, handled by iocp.");
      return true;
    case ERROR_INVALID_HANDLE:
      // Code 6: The handle is invalid
      break;
    case ERROR_NO_DATA:
      // trying to initialize a write after quit
      break;
    default:
      break;
    }
    log_last_error("Failed to initialize write");
    assert(false);
    ok = false;
  }
  return ok;
}

void copy_clipboard(void) {
  if (!OpenClipboard(NULL)) {
    log_last_error("Failed to open clipboard");
    return;
  }
  EmptyClipboard();
  const int32_t len_utf16 = utf8_to_utf16_nraw(clipboard.items, (int32_t)clipboard.count);
  assert(len_utf16 > 0);
  HGLOBAL hglb = GlobalAlloc(GMEM_MOVEABLE, array_bytes(&utf16_buf_raw));
  if (!hglb) {
    log_last_error("Failed to allocate global memory for clipboard");
    CloseClipboard();
    return;
  }
  LPWSTR lpwstr = GlobalLock(hglb);
  wmemcpy(lpwstr, utf16_buf_raw.items, (size_t)len_utf16);
  GlobalUnlock(hglb);
  SetClipboardData(CF_UNICODETEXT, hglb);
  CloseClipboard();
}

static DWORD WINAPI iocp_listener(LPVOID lp_param) {
  HANDLE iocp = (HANDLE)lp_param;
  for (;;) {
    DWORD bytes;
    ULONG_PTR completion_key;
    OVERLAPPED *ovl;
    if (!GetQueuedCompletionStatus(iocp, &bytes, &completion_key, &ovl, INFINITE)) {
      // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus#remarks
      log_last_error("Failed to dequeue packet");
    }
    Instance *instance = (Instance *)completion_key;
    Overlapped_Context *ctx = (Overlapped_Context *)ovl;
    if (ctx->type != MPV_READ) {
      Overlapped_Write *msg = (Overlapped_Write *)ctx;
      if (msg->bytes != bytes) {
        log_message(LOG_ERROR, "Expected '%zu' bytes but received '%ld': %s", msg->bytes, bytes, msg->buf);
      }
    } else {
      if (bytes) {
        iocp_process(instance, (size_t)bytes);
      }
      overlap_read(instance);
    }
  }
  return 0;
}

bool iocp_start(void) {
  cin_io.iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (!cin_io.iocp) {
    log_last_error("Failed to create iocp");
    return false;
  }
  if (!CreateThread(NULL, 0, iocp_listener, (LPVOID)cin_io.iocp, 0, NULL)) {
    log_last_error("Failed to create iocp listener");
    return false;
  }
  return true;
}

void mpv_spawn_internal(Instance *instance, char *mpv_flags[], char *socket_name) {
  const int32_t mpv_buf_len = snprintf(NULL, 0, "%s %s %s %s %s %s",
                                       mpv_flags[0], mpv_flags[1], mpv_flags[2], mpv_flags[3], mpv_flags[4],
                                       *exe_path_ytdlp ? mpv_flags[5] : "") +
                              1;
  char mpv_command[mpv_buf_len];
  snprintf(mpv_command, (size_t)mpv_buf_len, "%s %s %s %s %s %s",
           mpv_flags[0], mpv_flags[1], mpv_flags[2], mpv_flags[3], mpv_flags[4],
           *exe_path_ytdlp ? mpv_flags[5] : "");
  utf8_to_utf16_raw(mpv_command);
  wchar_t mpv_command_utf16[mpv_buf_len];
  wmemcpy(mpv_command_utf16, utf16_buf_raw.items, (size_t)mpv_buf_len);
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessW(exe_wpath_mpv, mpv_command_utf16, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      log_last_error("Failed to find mpv executable");
    } else if (GetLastError() == ERROR_PATH_NOT_FOUND) {
      log_last_error("Failed to find mpv path");
    } else {
      log_last_error("Failed to start mpv executable even though it was found");
    }
    cin_exit(1);
  }
  instance->si = si;
  instance->pi = pi;
  const int32_t socket_name_len = utf8_to_utf16_raw(socket_name);
  assert(socket_name_len);
  wmemcpy(mpv_command_utf16, utf16_buf_raw.items, (size_t)socket_name_len);
  const bool ok_pipe = create_pipe(instance, mpv_command_utf16);
  assert(ok_pipe);
  instance->ovl_ctx.type = MPV_READ;
  const bool ok_iocp = CreateIoCompletionPort(instance->socket, cin_io.iocp, (ULONG_PTR)instance, 0) != NULL;
  assert(ok_iocp);
  instance->buf_head = arena_bump_T1(&arena_io, Read_Buffer);
  instance->buf_tail = instance->buf_head;
  const bool ok_read = overlap_read(instance);
  assert(ok_read);
}

void chat_kill(void) {
  PostMessageW(chat.window, WM_CLOSE, 0, 0);
}

size_t chat_spawn(const Cin_Layout *layout) {
  RECT chat_rect = layout->chat_rect;
  const int32_t x = (int32_t)chat_rect.left;
  const int32_t y = (int32_t)chat_rect.top;
  const int32_t cx = (int32_t)chat_rect.right;
  const int32_t cy = (int32_t)chat_rect.bottom;
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  si.dwFlags = STARTF_USEPOSITION | STARTF_USESIZE | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_NORMAL;
  si.dwX = (uint32_t)x;
  si.dwXSize = (uint32_t)cx;
  si.dwY = (uint32_t)y;
  si.dwYSize = (uint32_t)cy;
  si.cb = sizeof(si);
  // since STARTUPINFOW is ignored, manually reposition after
  if (!CreateProcessW(exe_wpath_chatterino, L"chatterino", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      log_last_error("Failed to find chatterino executable");
    } else {
      log_last_error("Failed to start chatterino executable even though it was found");
    }
  }
  return pi.dwProcessId;
}

HWND chat_get_window(size_t pid, char *name) {
  (void)name;
  return find_window_by_pid((uint32_t)pid);
}

int32_t term_read(uint8_t *buf, const int32_t n, bool peek) {
  int32_t chars_read = 0;
  assert(n > 0);
  DWORD _read = 0;
  if (!peek) {
    if (ReadFile(repl.in, buf, (DWORD)n, &_read, NULL)) {
      chars_read = (int32_t)_read;
    } else {
      log_last_error("Failed to read from terminal");
    }
  } else {
    for (int32_t i = 0; i < n; ++i) {
      DWORD code = WaitForSingleObject(repl.in, TERM_READ_WAIT_MS);
      if (code != WAIT_OBJECT_0) break;
      if (!ReadFile(repl.in, buf + i, 1, &_read, NULL)) {
        log_last_error("Failed to read %d from terminal", n);
        break;
      }
      if (!_read) break;
      ++chars_read;
    }
  }
  return chars_read;
}