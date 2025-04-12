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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "cJSON.h"

#define MAX_FILENAME 260
#define COMMAND_LINE_LIMIT 32768 // likely way smaller in practice
#define MAX_LOG_MESSAGE 1024

typedef struct {
  int left;
  int top;
  int width;
  int height;
} Screen;

typedef struct {
  wchar_t filename[MAX_FILENAME];
  int volume;
  int loop;
  int alwaysontop;
  int noborder;
  int showmode;
  int fullscreen;
} MpvArgs;

typedef enum {
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} LogLevel;

static const char *level_to_str(LogLevel level) {
  switch (level) {
  case LOG_ERROR:
    return "ERROR";
  case LOG_WARNING:
    return "WARNING";
  case LOG_INFO:
    return "INFO";
  case LOG_DEBUG:
    return "DEBUG";
  case LOG_TRACE:
    return "TRACE";
  default:
    return "LOG";
  }
}

static LogLevel GLOBAL_LOG_LEVEL = LOG_TRACE;

static char *utf16_to_utf8(const wchar_t *wstr) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
  int convert_result = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  if (convert_result <= 0) {
    return NULL;
  }
  char *str = malloc(convert_result);
  if (str == NULL) {
    return NULL;
  }
  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, convert_result, NULL, NULL);
  return str;
}

static wchar_t *utf8_to_utf16(const char *utf8_str) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
  int convert_result = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);
  if (convert_result <= 0) {
    return NULL;
  }
  wchar_t *wide_str = malloc(convert_result * sizeof(wchar_t));
  if (wide_str == NULL) {
    return NULL;
  }
  MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, wide_str, convert_result);
  return wide_str;
}

static void log_message(LogLevel level, const char *location, const char *message, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  // Process variadic args
  va_list args;
  va_start(args, message);
  fprintf(stderr, "[%s] [%s] ", level_to_str(level), location);
  vfprintf(stderr, message, args);
  fprintf(stderr, "\n");
  va_end(args);
}

static void log_wmessage(LogLevel level, const char *location, const wchar_t *wmessage, ...) {
  if (level > GLOBAL_LOG_LEVEL)
    return;
  va_list args;
  va_start(args, wmessage);
  wchar_t formatted_wmsg[MAX_LOG_MESSAGE];
  vswprintf(formatted_wmsg, MAX_LOG_MESSAGE, wmessage, args);
  char *message_utf8 = utf16_to_utf8(formatted_wmsg);
  fprintf(stderr, "[%s] [%s] %s\n", level_to_str(level), location, message_utf8);
  free(message_utf8);
  va_end(args);
}

static void log_last_error(const char *location, const char *message, ...) {
  static const char *log_level = "ERROR";
  static const DWORD dw_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                FORMAT_MESSAGE_FROM_SYSTEM |
                                FORMAT_MESSAGE_IGNORE_INSERTS;
  LPVOID buffer;
  DWORD code = GetLastError();
  if (!FormatMessage(dw_flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                     (LPTSTR)&buffer, 0, NULL)) {
    log_message(LOG_ERROR, location, "Failed to log GLE=%d - error with GLE=%d", code, GetLastError());
    return;
  }
  va_list args;
  va_start(args, message);
  fprintf(stderr, "[%s] [%s] ", log_level, location);
  vfprintf(stderr, message, args);
  va_end(args);
  fprintf(stderr, " - Code %d: %s", code, (char *)buffer);
  LocalFree(buffer);
}

static char *read_json(const char *filename) {
  if (filename == NULL || filename[0] == '\0') {
    log_message(LOG_ERROR, "json", "Invalid filename provided (empty string)");
    return NULL;
  }
  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    log_message(LOG_ERROR, "json", "Failed to open config file '%s': %s", filename, strerror(errno));
    return NULL;
  }
  // Move pointer to get size in bytes and back
  fseek(file, 0, SEEK_END);
  long filesize = ftell(file);
  rewind(file);
  // Buffer for file + null terminator
  char *json_content = (char *)malloc(filesize + 1);
  if (json_content == NULL) {
    log_message(LOG_ERROR, "json", "Failed to allocate memory for file '%s' with size '%ld': %s",
                filename, filesize + 1, strerror(errno));
    fclose(file);
    return NULL;
  }
  // Read into buffer with null terminator
  fread(json_content, 1, filesize, file);
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
      log_message(LOG_ERROR, "json", "JSON parsing error in file '%s' for contents: %s", filename, error_ptr);
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
    log_message(LOG_WARNING, "json", "Defaulting '%s' to '%d': did not find number in JSON", key, default_val);
  }
  return result;
}

static double parse_percentage(const char *input, double default_val) {
  if (input == NULL || input[0] == '\0') {
    log_message(LOG_WARNING, "json", "Defaulting percentage to '%f': empty input", input);
    return default_val;
  }
  int chars_read = 0;
  int int_result;
  int success = sscanf(input, "%d%n", &int_result, &chars_read);
  if (success == 1 && input[chars_read] == '\0') {
    return (double)int_result;
  }
  double double_result;
  chars_read = 0;
  success = sscanf(input, "%lf%n", &double_result, &chars_read);
  if (success == 1 && input[chars_read] == '\0') {
    return double_result;
  }
  log_message(LOG_WARNING, "json", "Defaulting percentage '%s' to '%f': failed to parse", input, default_val);
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
      log_message(LOG_WARNING, "json", "Defaulting '%s' to '%d': percentage '%f' is out of bounds",
                  key, default_val, percentage);
      result = default_val;
    }
  } else {
    log_message(LOG_WARNING, "json", "Defaulting '%s' to '%d': did not find number in JSON", key, default_val);
  }
  return result;
}

static int setup_bool(const cJSON *json, const char *key, int default_val) {
  if (default_val != 0 && default_val != 1) {
    log_message(LOG_WARNING, "json", "Default value '%d' invalid for '%s'; defaulting to '0'", default_val, key);
    default_val = 0;
  }
  int result = default_val;
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  if (cJSON_IsBool(option)) {
    result = cJSON_IsTrue(option) ? 1 : 0;
  } else {
    log_message(LOG_WARNING, "json", "Defaulting '%s' to '%d': did not find boolean in JSON", key, default_val);
  }
  return result;
}

static wchar_t *setup_wstring(const cJSON *json, const char *key, const wchar_t *default_val) {
  if (default_val == NULL) {
    log_message(LOG_DEBUG, "json", "Passed NULL as default value for setup_wstring");
  }
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  wchar_t *result = NULL;
  if (cJSON_IsString(option) && option->valuestring) {
    result = utf8_to_utf16(option->valuestring);
    if (result == NULL) {
      log_wmessage(LOG_WARNING, "json", L"Failed to convert JSON string '%s' for key '%s' to UTF-16",
                   option->valuestring, key);
    }
  }
  if (result == NULL) {
    if (default_val != NULL) {
      log_wmessage(LOG_WARNING, "json", L"Defaulting '%s' to '%ls': did not find valid string in JSON",
                   key, default_val);
      result = _wcsdup(default_val);
    } else {
      log_message(LOG_WARNING, "json", "Returning NULL for '%s': did not find valid string in JSON or default", key);
    }
  }
  return result;
}

static int setup_mpv(const cJSON *json_mpv, MpvArgs *settings) {
  if (json_mpv == NULL || settings == NULL) {
    return 0;
  }
  settings->volume = setup_int(json_mpv, "volume", 100);
  settings->loop = setup_int(json_mpv, "loop", 0);
  settings->alwaysontop = setup_bool(json_mpv, "alwaysontop", 1);
  settings->noborder = setup_bool(json_mpv, "noborder", 0);
  settings->showmode = setup_int(json_mpv, "showmode", 0);
  settings->fullscreen = setup_bool(json_mpv, "fullscreen", 0);
  return 1;
}

static int setup_layouts(const cJSON *layouts) {
  if (layouts == NULL) {
    return 0;
  }
  // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics
  int monitor_width = GetSystemMetrics(SM_CXSCREEN);
  int monitor_height = GetSystemMetrics(SM_CYSCREEN);
  if (monitor_width == 0 || monitor_height == 0) {
    log_message(LOG_ERROR, "layouts", "Failed to scan monitor for screen dimensions.");
    return 0;
  }
  log_message(LOG_INFO, "layouts", "Monitor dimensions: %dx%d", monitor_width, monitor_height);
  const cJSON *layout = layouts->child;
  while (layout != NULL) {
    log_message(LOG_DEBUG, "layouts", "Processing layout '%s'", layout->string);
    if (!cJSON_IsArray(layout)) {
      log_message(LOG_ERROR, "layouts", "Layout '%s' is not an Array", layout->string);
      return 0;
    }
    const cJSON *screen = layout->child;
    int i = 0;
    while (screen != NULL) {
      log_message(LOG_DEBUG, "layouts", "Adding screen %d", i);
      int left = setup_screen_value(screen, "left", 0, monitor_width);
      int top = setup_screen_value(screen, "top", 0, monitor_height);
      int width = setup_screen_value(screen, "width", 0, monitor_width);
      int height = setup_screen_value(screen, "height", 0, monitor_height);
      log_message(LOG_DEBUG, "layouts", "left=%d top=%d width=%d height=%d", left, top, width, height);
      screen = screen->next;
      ++i;
    }
    layout = layout->next;
  }
  return 1;
}

// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-transactnamedpipe
#define PIPE_WRITE_BUFFER 65536
#define PIPE_READ_BUFFER 1024

typedef struct {
  OVERLAPPED ovl;
  bool is_write;
} OverlappedContext;

typedef struct OverlappedWrite {
  OverlappedContext ovl_context;
  char buffer[PIPE_WRITE_BUFFER];
  size_t bytes;
  int64_t request_id;
} OverlappedWrite;

typedef struct {
  // NOTE: currently, we use a single overlapped read per instance
  // (unlike multiple writes). This could lead to gaps in incoming
  // data if the OS buffer does not preserve it fully for the next
  // read. If that is observed, switch to multiple reads as well
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HANDLE pipe;
  OverlappedContext ovl_context;
  CHAR read_buffer[PIPE_READ_BUFFER];
} Instance;

static bool create_process(Instance *instance, const wchar_t *name, MpvArgs *args) {
  static wchar_t command[COMMAND_LINE_LIMIT];
  swprintf(command, COMMAND_LINE_LIMIT,
           L"mpv"
           L" --terminal=no"
           L" --no-config" // TODO: default --config-dir
           L" --volume=%d"
           L" --loop=inf"
           L"%ls"      // alwaysontop
           L"%ls"      // noborder
           L"%ls"      // fullscreen (fs)
           L" \"%ls\"" // filename
           L" --input-ipc-server=%ls",
           args->volume,
           //  args->loop,
           (args->alwaysontop ? L" --ontop" : L""),
           (args->noborder ? L" --border=no" : L""),
           (args->fullscreen ? L" --fullscreen=yes" : L""),
           args->filename,
           name);
  log_wmessage(LOG_INFO, "instance", command);
  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
  if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    log_last_error("instance", "CreateProcessW failed");
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
        log_message(LOG_ERROR, "pipe", "Failed to find pipe in time: %dms/%dms", unfound_duration, UNFOUND_TIMEOUT);
        return false;
      }
      log_message(LOG_DEBUG, "pipe", "Failed to find pipe. Trying again in %dms...", UNFOUND_WAIT);
      Sleep(UNFOUND_WAIT);
    } else {
      // Unlikely error, try to resolve by waiting
      log_last_error("pipe", "Could not connect to pipe - Waiting for %dms", FOUND_TIMEOUT);
      if (!WaitNamedPipeW(name, FOUND_TIMEOUT)) {
        log_last_error("pipe", "Failed to connect to pipe");
        return false;
      }
    }
  }
  instance->pipe = hPipe;
  log_message(LOG_TRACE, "pipe", "Successfully created pipe (HANDLE) %p", (void *)instance->pipe);
  return true;
}

static bool overlap_read(Instance *instance) {
  log_message(LOG_TRACE, "read", "Initializing read on PID %lu", instance->pi.dwProcessId);
  ZeroMemory(&instance->ovl_context.ovl, sizeof(OVERLAPPED));
  if (!ReadFile(instance->pipe, instance->read_buffer, (PIPE_READ_BUFFER)-1, NULL, &instance->ovl_context.ovl)) {
    if (GetLastError() != ERROR_IO_PENDING) {
      log_last_error("read", "Failed to initialize read");
      return false;
    }
  }
  // Read is queued for iocp
  return true;
}

static bool overlap_write(Instance *instance, const char *message) {
  log_message(LOG_TRACE, "write", "Initializing write on PID %lu", instance->pi.dwProcessId);
  size_t len = strlen(message);
  if (len <= 0) {
    return false;
  }
  OverlappedWrite *write = malloc(sizeof(*write));
  if (write == NULL) {
    log_message(LOG_ERROR, "write", "Failed to allocate memory.");
    return false;
  }
  // Message needs to be UTF-8
  if (len >= sizeof(write->buffer)) {
    log_message(LOG_ERROR, "write", "Message len '%d' bigger than buffer '%d'", len, sizeof(write->buffer));
    return false;
  }
  memcpy(write->buffer, message, len);
  write->ovl_context.is_write = true;
  write->bytes = len;
  write->request_id = 0; // TODO: increment request id
  // Remove \n when logging
  log_message(LOG_DEBUG, "write", "Writing message: %.*s", len - 1, message);
  if (!WriteFile(instance->pipe, write->buffer, (DWORD)len, NULL, &write->ovl_context.ovl)) {
    if (GetLastError() == ERROR_IO_PENDING) {
      // iocp will free write
      log_message(LOG_TRACE, "write", "Pending write call, handled by iocp.");
      return true;
    }
    log_last_error("write", "Failed to initialize write");
    free(write);
    return false;
  }
  log_message(LOG_TRACE, "write", "Write call completed immediately.");
  free(write);
  return true;
}

static bool create_instance(Instance *instance, const wchar_t *name, MpvArgs *args, HANDLE *iocp) {
  instance->ovl_context.is_write = false;
  if (name == NULL || args == NULL) {
    return false;
  }
  if (!create_process(instance, name, args)) {
    return false;
  }
  if (!create_pipe(instance, name)) {
    return false;
  }
  // Does not create a new iocp if pointer is invalid since Existing is provided
  if (CreateIoCompletionPort(instance->pipe, iocp, (ULONG_PTR)instance, 0) == NULL) {
    log_last_error("iocp", "Failed to associate pipe with iocp");
    return false;
  }
  if (!overlap_read(instance)) {
    return false;
  }
  return true;
}

static bool process_layout(size_t count, Instance *instances, MpvArgs *args, HANDLE *iocp) {
  static const wchar_t PIPE_PREFIXW[] = L"\\\\.\\pipe\\cinema_mpv_";
  static const int PIPE_NAME_BUFFER = 32;
  if (count <= 0) {
    log_message(LOG_TRACE, "layout", "Count of %d, nothing to process.", count);
    return false;
  }
  wchar_t pipe_name[PIPE_NAME_BUFFER];
  for (size_t i = 0; i < count; ++i) {
    swprintf(pipe_name, PIPE_NAME_BUFFER, L"%ls%d", PIPE_PREFIXW, i);
    if (!create_instance(&instances[i], pipe_name, args, iocp)) {
      free(instances);
      log_message(LOG_ERROR, "layout", "Failed to create instance");
      return false;
    }
  }
  return true;
}

DWORD WINAPI iocp_listener(LPVOID lp_param) {
  HANDLE iocp = (HANDLE)lp_param;
  for (;;) {
    DWORD bytes;
    ULONG_PTR completion_key;
    OVERLAPPED *ovl;
    if (!GetQueuedCompletionStatus(iocp, &bytes, &completion_key, &ovl, INFINITE)) {
      log_last_error("listener", "Failed to dequeue packet");
      // TODO: resolve instead of break
      // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus#remarks
      break;
    }
    log_message(LOG_TRACE, "listener", "Processing dequeued completion packet from successful I/O operation");
    Instance *pState = (Instance *)completion_key;
    OverlappedContext *ctx = (OverlappedContext *)ovl;
    if (ctx->is_write) {
      // TODO: check if bytes equals ovl->bytes for write
      OverlappedWrite *write = (OverlappedWrite *)ctx;
      fprintf(stderr, "expected: %ld\n", write->bytes);
      fprintf(stderr, "written: %ld\n", bytes);
    } else {
      pState->read_buffer[bytes] = '\0'; // TODO: handle buffer gracefully
      fprintf(stderr, "Got data from pipe (%p): %s", (void *)pState->pipe, pState->read_buffer);
      if (!overlap_read((Instance *)completion_key)) {
        // TODO: resolve instead of break
        break;
      }
    }
  }
  return 0;
}

int main() {
#ifndef _WIN32
  log_message(LOG_ERROR, "main", "Error: Your operating system is not supported, Windows-only currently.");
  return 1;
#endif
  SetConsoleOutputCP(CP_UTF8); // Enable UTF-8 console output for Windows
  char *config_filename = "config.json";
  cJSON *json = parse_json(config_filename);
  if (json == NULL) {
    return 1;
  }
  char *string = cJSON_Print(json);
  if (string == NULL) {
    log_message(LOG_ERROR, "main", "Failed to print cJSON items from config tree with cJSON_Print.");
  } else {
    // log_message(LOG_INFO, "main", string);
  }

  wchar_t *name = setup_wstring(json, "path", NULL);
  if (name == NULL) {
    log_message(LOG_ERROR, "main", "No valid 'path' found in config");
    return 1;
  }
  cJSON *json_mpv = cJSON_GetObjectItemCaseSensitive(json, "mpv");
  if (!cJSON_IsObject(json_mpv)) {
    log_message(LOG_ERROR, "main", "No 'mpv' object found in config");
    return 1;
  }

  MpvArgs args;
  wcsncpy(args.filename, name, (sizeof(args.filename) / sizeof(wchar_t)) - 1);
  free(name);
  args.filename[(sizeof(args.filename) / sizeof(wchar_t)) - 1] = L'\0';
  if (!setup_mpv(json_mpv, &args)) {
    log_message(LOG_ERROR, "main", "Failed to setup mpv with JSON config");
    return 1;
  }

  HANDLE iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  DWORD listener_id;
  HANDLE listener = CreateThread(NULL, 0, iocp_listener, (LPVOID)iocp, 0, &listener_id);
  if (listener == NULL) {
    log_last_error("main", "Failed to create listener thread");
    return 1;
  }

  size_t count = 1;
  Instance *pipes = malloc(count * sizeof(Instance));
  if (pipes == NULL) {
    log_message(LOG_ERROR, "main", "Failed to allocate memory for count=%d", count);
    return false;
  }

  process_layout(count, pipes, &args, iocp);
  for (size_t i = 0; i < count; ++i) {
    log_message(LOG_INFO, "main", "Instance[%zu] Process ID: %lu", i, (unsigned long)pipes[i].pi.dwProcessId);
  }

  overlap_write(&pipes[0], "{\"command\":[\"loadfile\",\"D:\\\\Test\\\\video.mp4\"]}\n");
  Sleep(2000);
  overlap_write(&pipes[0], "{\"command\":[\"loadfile\",\"D:\\\\Test\\\\video.mp4\"]}\n");
  Sleep(2000);
  // overlap_write(&pipes[1], "{\"command\":[\"loadfile\",\"D:\\\\Test\\\\video ❗.mp4\"]}\n");
  // overlap_write(&pipes[2], "{\"command\":[\"loadfile\",\"D:\\\\Test\\\\video ❗.mp4\"]}\n");

  // TODO: supply and read by request_id in iocp worker thread

  // https://mpv.io/manual/stable/#json-ipc
  // mpv file.mkv --input-ipc-server=\\.\pipe\mpvsocket
  // echo loadfile "filepath" replace >\\.\pipe\mpvsocket
  // ipc commands:
  // https://mpv.io/manual/stable/#list-of-input-commands
  // https://mpv.io/manual/stable/#commands-with-named-arguments
  // these commands can also be async
  return 0;
}