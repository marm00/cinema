#include "io.h"

bool create_pipe(Instance *instance, const wchar_t *name) {
  // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
  // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
  static const int FOUND_TIMEOUT = 20000;
  static const int UNFOUND_TIMEOUT = 20000;
  static const int UNFOUND_WAIT = 50;
  log_wmessage(LOG_ERROR, L"creating pipe: %s", name);
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
