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

#include <inttypes.h>
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

#define CIN_MAX_PATH MAX_PATH // 260 win default
// TODO: find better upper bound for command line
#define COMMAND_LINE_LIMIT 32768
#define MAX_LOG_MESSAGE 1024

typedef struct {
  int left;
  int top;
  int width;
  int height;
} Screen;

typedef enum {
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} Log_Level;

static const char *level_to_str(Log_Level level) {
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

static Log_Level GLOBAL_LOG_LEVEL = LOG_INFO;

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

static void log_message(Log_Level level, const char *location, const char *message, ...) {
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

static void log_wmessage(Log_Level level, const char *location, const wchar_t *wmessage, ...) {
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
  if (!FormatMessage(dw_flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&buffer, 0, NULL)) {
    log_message(LOG_ERROR, location, "Failed to log GLE=%d - error with GLE=%d", code, GetLastError());
    return;
  }
  va_list args;
  va_start(args, message);
  fprintf(stderr, "[%s] [%s] ", log_level, location);
  vfprintf(stderr, message, args);
  va_end(args);
  fprintf(stderr, " - Code %lu: %s", code, (char *)buffer);
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

static bool setup_bool(const cJSON *json, const char *key, int default_val) {
  if (default_val != 0 && default_val != 1) {
    log_message(LOG_WARNING, "json", "Default value '%d' invalid for '%s'; defaulting to '0'", default_val, key);
    default_val = 0;
  }
  int result = default_val;
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  if (cJSON_IsBool(option)) {
    result = cJSON_IsTrue(option) ? true : false;
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

typedef struct Cin_Strings {
  // Each byte represents a UTF-8 unit
  unsigned char *units;
  size_t count;
  size_t capacity;
} Cin_Strings;

typedef struct Cin_String {
  // Length-prefixed UTF-8 string in block
  uint32_t off;
  uint16_t len;
} Cin_String;

static Cin_Strings cin_strings = {0};

static Cin_String cin_strings_append(const char *utf8, size_t len) {
  // Geometric growth with clamp, based on 260 max path
  static const size_t cin_strings_init = 1 << 15;
  static const size_t cin_strings_clamp = 1 << 26;
  void *dst = NULL;
  if (cin_strings.capacity - cin_strings.count >= len) {
    dst = cin_strings.units + cin_strings.count;
  } else {
    size_t cap = cin_strings.capacity;
    if (cap <= 0) {
      cap = cin_strings_init;
    }
    while (cap - cin_strings.count < len) {
      cap = cap < cin_strings_clamp ? cap * 2 : cap + cin_strings_clamp;
    }
    cin_strings.capacity = cap;
    unsigned char *units = realloc(cin_strings.units, cin_strings.capacity);
    if (units != NULL) {
      cin_strings.units = units;
      dst = cin_strings.units + cin_strings.count;
    }
  }
  Cin_String cin_string = {0};
  if (dst == NULL) {
    log_message(LOG_ERROR, "cin_strings", "Failed to reallocate memory");
  } else {
    memcpy(dst, utf8, len);
    cin_string.off = (uint32_t)cin_strings.count;
    cin_string.len = (uint16_t)len;
    cin_strings.count += len;
  }
  return cin_string;
}

static cJSON *setup_entry_collection(cJSON *entry, const char *name) {
  // Returns array pointer or NULL, converts string to array
  cJSON *key = cJSON_GetObjectItemCaseSensitive(entry, name);
  cJSON *result = NULL;
  if (key == NULL) {
    log_message(LOG_DEBUG, "media_library", "Could not find key \"%s\"", name);
  } else if (cJSON_IsArray(key)) {
    result = key;
  } else if (cJSON_IsString(key)) {
    cJSON *str = cJSON_Duplicate(key, false);
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToArray(arr, str);
    if (cJSON_GetArraySize(arr) == 1) {
      cJSON_ReplaceItemInObjectCaseSensitive(entry, name, arr);
      result = arr;
    } else {
      log_message(LOG_WARNING, "media_library",
                  "Failed to convert string to array for \"%s\": %s",
                  name, cJSON_Print(key));
      if (arr != NULL) {
        cJSON_Delete(arr);
      }
      if (str != NULL) {
        cJSON_Delete(str);
      }
    }
  } else {
    log_message(LOG_WARNING, "media_library", "Unexpected type for \"%s\": %s",
                name, cJSON_Print(key));
  }
  return result;
}

static bool setup_directory(wchar_t *path, size_t len) {
  // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfileexw
  // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilew
  // TODO: explain "directory" & recursive in readme
  // TODO: note that we support up to CIN_MAX_PATH, not NTFS max of 32000+
  if (len + 2 >= CIN_MAX_PATH) {
    // We have to append 2 chars \ and * for the correct pattern
    return false;
  }
  path[len++] = L'\\';
  path[len++] = L'*';
  path[len] = L'\0';
  WIN32_FIND_DATAW data;
  HANDLE search = FindFirstFileExW(path, FindExInfoBasic, &data,
                                   FindExSearchNameMatch, NULL,
                                   FIND_FIRST_EX_LARGE_FETCH);
  // We can now drop the 2 chars \ and * to restore the root,
  // but choose to only drop * so that \ remains as a separator
  // for the next file or directory, instead of adding later.
  len--;
  path[len] = L'\0';
  if (search == INVALID_HANDLE_VALUE) {
    log_last_error("directories", "Failed to match directory '%ls'", path);
    return false;
  }
  bool ok = true;
  do {
    if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
      continue; // skip junction
    }
    const wchar_t *file = data.cFileName;
    bool is_dir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    if (is_dir && (file[0] == L'.') && (!file[1] || (file[1] == L'.' && !file[2]))) {
      continue; // skip dot entry
    }
    size_t file_len = wcslen(file);
    if (len + file_len + 1 >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(path + len, file, file_len + 1);
    if (is_dir) {
      if (!setup_directory(path, len + file_len)) {
        ok = false;
      }
    } else {
      char *temp_utf8 = utf16_to_utf8(path);
      printf("=directory - %s\n", temp_utf8);
      free(temp_utf8);
    }
  } while (FindNextFileW(search, &data) != 0);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    log_last_error("directories", "Failed to find next file");
    ok = false;
  }
  FindClose(search);
  return ok;
}

static bool setup_pattern(const wchar_t *pattern) {
  // Processes all files (not directories) that match the pattern
  // https://support.microsoft.com/en-us/office/examples-of-wildcard-characters-939e153f-bd30-47e4-a763-61897c87b3f4
  // TODO: explain allowed patterns (e.g., wildcards) in readme/json examples
  wchar_t *separator = wcsrchr(pattern, L'\\');
  if (separator == NULL || *(separator + 1) == L'\0') {
    return false;
  }
  wchar_t dir_buf[CIN_MAX_PATH];
  size_t dir_len = (size_t)(separator - pattern) + 1;
  if (dir_len > CIN_MAX_PATH) {
    return false;
  }
  wmemcpy(dir_buf, pattern, dir_len);
  dir_buf[dir_len] = L'\0';
  wchar_t abs_buf[CIN_MAX_PATH];
  DWORD abs_dword = GetFullPathNameW(dir_buf, CIN_MAX_PATH, abs_buf, NULL);
  if (abs_dword == 0 || abs_dword > CIN_MAX_PATH) {
    return false;
  }
  // abs_len is essentially the same as abs_dword,
  // we can safely add backslash here
  size_t abs_len = wcslen(abs_buf);
  if (abs_buf[abs_len - 1] != L'\\') {
    abs_buf[abs_len++] = L'\\';
    abs_buf[abs_len] = L'\0';
  }
  WIN32_FIND_DATAW data;
  HANDLE search = FindFirstFileExW(pattern, FindExInfoBasic, &data,
                                   FindExSearchNameMatch, NULL,
                                   FIND_FIRST_EX_LARGE_FETCH);
  if (search == INVALID_HANDLE_VALUE) {
    log_last_error("directories", "Failed to match pattern '%ls'", pattern);
    return false;
  }
  static const DWORD file_mask = FILE_ATTRIBUTE_DIRECTORY |
                                 FILE_ATTRIBUTE_REPARSE_POINT |
                                 FILE_ATTRIBUTE_DEVICE;
  bool ok = true;
  do {
    if (data.dwFileAttributes & file_mask) {
      continue; // skip directories
    }
    const wchar_t *file = data.cFileName;
    size_t file_len = wcslen(file);
    if (abs_len + file_len + 1 >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(abs_buf + abs_len, file, file_len + 1);
    char *temp_utf8 = utf16_to_utf8(abs_buf);
    printf("=pattern - %s\n", temp_utf8);
    free(temp_utf8);
  } while (FindNextFileW(search, &data) != 0);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    log_last_error("directories", "Failed to find next file");
    ok = false;
  }
  FindClose(search);
  return ok;
}

static bool setup_url(const char *url) {
  printf("=url - %s\n", url);
  return true;
}

static bool setup_tag(const char *tag) {
  printf("=tag - %s\n", tag);
  return true;
}

static bool setup_media_library(const cJSON *json) {
  cJSON *lib = cJSON_GetObjectItemCaseSensitive(json, "media_library");
  if (lib == NULL || !cJSON_IsArray(lib)) {
    log_message(LOG_ERROR, "media_library", "Could not find media_library array in JSON");
    return false;
  }
  cJSON *entry = NULL;
  cJSON_ArrayForEach(entry, lib) {
    cJSON *cursor = NULL;
    cJSON *directories = setup_entry_collection(entry, "directories");
    cJSON_ArrayForEach(cursor, directories) {
      wchar_t *root = utf8_to_utf16(cursor->valuestring);
      size_t len = wcslen(root);
      if (len > 0 && len + 1 < CIN_MAX_PATH) {
        wchar_t buf[CIN_MAX_PATH];
        wmemcpy(buf, root, len + 1); // include NUL
        setup_directory(buf, len);
        cin_strings_append(cursor->valuestring, strlen(cursor->valuestring));
      }
      free(root);
    }
    cJSON *patterns = setup_entry_collection(entry, "patterns");
    cJSON_ArrayForEach(cursor, patterns) {
      wchar_t *pattern = utf8_to_utf16(cursor->valuestring);
      size_t len = wcslen(pattern);
      if (len > 0 && len + 1 < CIN_MAX_PATH) {
        setup_pattern(pattern);
        cin_strings_append(cursor->valuestring, strlen(cursor->valuestring));
      }
      free(pattern);
    }
    cJSON *urls = setup_entry_collection(entry, "urls");
    cJSON_ArrayForEach(cursor, urls) {
      if (cursor->valuestring != NULL && strlen(cursor->valuestring) > 0) {
        setup_url(cursor->valuestring);
        cin_strings_append(cursor->valuestring, strlen(cursor->valuestring));
      }
    }
    cJSON *tags = setup_entry_collection(entry, "tags");
    cJSON_ArrayForEach(cursor, tags) {
      if (cursor->valuestring != NULL && strlen(cursor->valuestring) > 0) {
        setup_tag(cursor->valuestring);
        cin_strings_append(cursor->valuestring, strlen(cursor->valuestring));
      }
    }
    log_message(LOG_INFO, "media_library", "Processing entry: %s", cJSON_PrintUnformatted(entry));
  }
  if (cin_strings.count < cin_strings.capacity) {
    unsigned char *tight = realloc(cin_strings.units, cin_strings.count);
    if (tight != NULL) {
      cin_strings.units = tight;
    }
    cin_strings.capacity = cin_strings.count;
  }
  printf("\n");
  printf("count=%zu|capacity=%zu\t", cin_strings.count, cin_strings.capacity);
  for (size_t i = 0; i < cin_strings.count; ++i) {
    printf("%c", cin_strings.units[i]);
  }
  printf("\n\n");
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
    log_message(LOG_ERROR, "layouts", "Failed to scan monitor for screen dimensions.");
    return false;
  }
  log_message(LOG_INFO, "layouts", "Monitor dimensions: %dx%d", monitor_width, monitor_height);
  const cJSON *layout = layouts->child;
  while (layout != NULL) {
    log_message(LOG_DEBUG, "layouts", "Processing layout '%s'", layout->string);
    if (!cJSON_IsArray(layout)) {
      log_message(LOG_ERROR, "layouts", "Layout '%s' is not an Array", layout->string);
      return false;
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
  return true;
}

// https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-transactnamedpipe
// TODO: find better upper bound for transaction (pending 64kb writes can scale very fast)
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

typedef struct {
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
} Instance;

static bool create_process(Instance *instance, const wchar_t *pipe_name, const wchar_t *file_name) {
  static wchar_t command[COMMAND_LINE_LIMIT];
  swprintf(command, COMMAND_LINE_LIMIT,
           L"mpv"
           L" \"%ls\"" // filename
           L" --input-ipc-server=%ls",
           file_name,
           pipe_name);
  log_wmessage(LOG_INFO, "instance", command);
  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
  if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      // mpv binary not found
      // TODO: link to somewhere to get the binary
      // TODO: check for yt-dlp binary for streams
      log_last_error("instance", "Failed to find mpv binary");
    } else {
      log_last_error("instance", "Failed to start mpv even though it was found");
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
  static int current_id = 0; // TODO: request id should probably be unique to instance
  log_message(LOG_TRACE, "write", "Initializing write on PID %lu", instance->pi.dwProcessId);
  size_t len = strlen(message);
  if (len <= 0) {
    return false;
  }
  Overlapped_Write *write = malloc(sizeof(*write));
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
  write->request_id = current_id++; // TODO: add request_id here or on json message creation
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

static bool create_instance(Instance *instance, const wchar_t *name, const wchar_t *file_name, HANDLE *iocp) {
  if (name == NULL || file_name == NULL) {
    return false;
  }
  instance->ovl_context.is_write = false;
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
    log_last_error("iocp", "Failed to associate pipe with iocp");
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
    log_message(LOG_TRACE, "layout", "Count of %d, nothing to process.", count);
    return false;
  }
  wchar_t pipe_name[PIPE_NAME_BUFFER];
  for (size_t i = 0; i < count; ++i) {
    swprintf(pipe_name, PIPE_NAME_BUFFER, L"%ls%d", PIPE_PREFIXW, i);
    if (!create_instance(&instances[i], pipe_name, file_name, iocp)) {
      free(instances);
      log_message(LOG_ERROR, "layout", "Failed to create instance");
      return false;
    }
  }
  return true;
}

Overlapped_Write *find_write(Instance *instance, int64_t request_id) {
  // Uses binary search over sorted dynamic array.
  // The request_id should always find a pair in this scenario
  // as the incoming request_id was sent as a targeted response.
  if (instance == NULL) {
    log_message(LOG_ERROR, "find_write", "Tried to find '%" PRId64 "' on NULL instance", request_id);
    return NULL;
  }
  if (instance->pending_writes.count == 0) {
    log_message(LOG_ERROR, "find_write", "Tried to find '%" PRId64 "' without pending writes", request_id);
    return NULL;
  }
  if (instance->pending_writes.items == NULL) {
    log_message(LOG_ERROR, "find_write", "Tried to find '%" PRId64 "' on NULL items", request_id);
    return NULL;
  }
  ptrdiff_t left = 0;
  ptrdiff_t right = instance->pending_writes.count - 1;
  while (left <= right) {
    ptrdiff_t middle = left + ((right - left) >> 1);
    int64_t mid_val = instance->pending_writes.items[middle]->request_id;
    if (mid_val < request_id) {
      left = middle + 1;
    } else if (mid_val > request_id) {
      right = middle - 1;
    } else {
      return instance->pending_writes.items[middle];
    }
  }
  log_message(LOG_ERROR, "find_write", "Tried to find '%" PRId64 "' but could not find it", request_id);
  return NULL;
}

DWORD WINAPI iocp_listener(LPVOID lp_param) {
  HANDLE iocp = (HANDLE)lp_param;
  for (;;) {
    DWORD bytes;
    ULONG_PTR completion_key;
    OVERLAPPED *ovl;
    if (!GetQueuedCompletionStatus(iocp, &bytes, &completion_key, &ovl, INFINITE)) {
      log_last_error("listener", "Failed to dequeue packet");
      // TODO: when observed, resolve instead of break
      // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus#remarks
      break;
    }
    log_message(LOG_TRACE, "listener", "Processing dequeued completion packet from successful I/O operation");
    Instance *instance = (Instance *)completion_key;
    Overlapped_Ctx *ctx = (Overlapped_Ctx *)ovl;
    if (ctx->is_write) {
      Overlapped_Write *write = (Overlapped_Write *)ctx;
      Pending_Writes *array = &instance->pending_writes;
      if (array->count >= array->capacity) {
        array->capacity = array->capacity * 2;
        array->items = realloc(array->items, sizeof(Overlapped_Write *) * array->capacity);
        if (array->items == NULL) {
          log_message(LOG_ERROR, "listener", "Failed to reallocate memory of pending writes");
          break;
        }
      }
      array->items[array->count++] = write;
      fprintf(stderr, "Request id %lld\n", write->request_id);
      if (write->bytes != bytes) {
        log_message(LOG_ERROR, "listener", "Expected '%ld' bytes but received '%ld'", write->bytes, bytes);
        // TODO: when observed, resolve instead of break
        break;
      }
    } else {
      find_write(instance, 0);
      // TODO: parse JSON (and match request_id)
      // TODO: Currently, embedded 0 bytes terminate the current line, but you should not rely on this.
      instance->read_buffer[bytes] = '\0'; // TODO: handle buffer gracefully
      fprintf(stderr, "Got data from pipe (%p): %s", (void *)instance->pipe, instance->read_buffer);
      if (!overlap_read((Instance *)completion_key)) {
        // TODO: when observed, resolve instead of break
        break;
      }
    }
  }
  return 0;
}

int main(int argc, char **argv) {
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

  setup_media_library(json);
  return 0;

  wchar_t *name = setup_wstring(json, "path", NULL);
  if (name == NULL) {
    log_message(LOG_ERROR, "main", "No valid 'path' found in config");
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

  process_layout(count, pipes, name, iocp);
  free(name);
  for (size_t i = 0; i < count; ++i) {
    log_message(LOG_INFO, "main", "Instance[%zu] Process ID: %lu", i, (unsigned long)pipes[i].pi.dwProcessId);
  }

  Sleep(2000);
  overlap_write(&pipes[0], "{\"command\":[\"loadfile\",\"D:\\\\Test\\\\video ❗.mp4\"], \"request_id\": 0}\n");
  // overlap_write(&pipes[0], "{\"command\":[\"loadfile\",\"D:\\\\Test\\\\ast_recursive.png\"], \"request_id\": 0}\n");
  // overlap_write(&pipes[0], "{\"command\":[\"loadfile\",\"https://twitch.tv/bwipolol\"], \"request_id\": 0}\n");
  // overlap_write(&pipes[0], "{\"command\":[\"loadfile\",\"https://www.youtube.com/watch?v=ZA-tUyM_y7s\"], \"request_id\": 0}\n");

  Sleep(2000);
  // overlap_write(&pipes[0], "{\"command\":[\"get_property_string\", \"width\"], \"request_id\": 1}\n");
  // Sleep(2000);
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

  // TODO: subtitles conf
  return 0;
}
