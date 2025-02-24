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
  wchar_t filename[MAX_FILENAME];
  int volume;
  int loop;
  int alwaysontop;
  int noborder;
  int showmode;
} FFplayArgs;

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

static int setup_ffplay(const cJSON *json_ffplay, FFplayArgs *settings) {
  if (json_ffplay == NULL || settings == NULL) {
    return 0;
  }
  settings->volume = setup_int(json_ffplay, "volume", 100);
  settings->loop = setup_int(json_ffplay, "loop", 0);
  settings->alwaysontop = setup_bool(json_ffplay, "alwaysontop", 1);
  settings->noborder = setup_bool(json_ffplay, "noborder", 0);
  settings->showmode = setup_int(json_ffplay, "showmode", 0);
  return 1;
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
    log_message(LOG_INFO, "main", string);
  }

  wchar_t *name = setup_wstring(json, "path", NULL);
  if (name == NULL) {
    log_message(LOG_ERROR, "main", "No valid 'path' found in config");
    return 1;
  }
  cJSON *json_ffplay = cJSON_GetObjectItemCaseSensitive(json, "ffplay");
  if (!cJSON_IsObject(json_ffplay)) {
    log_message(LOG_ERROR, "main", "No 'ffplay' object found in config");
    return 1;
  }

  FFplayArgs args;
  wcsncpy(args.filename, name, (sizeof(args.filename) / sizeof(wchar_t)) - 1);
  free(name);
  args.filename[(sizeof(args.filename) / sizeof(wchar_t)) - 1] = L'\0';
  if (!setup_ffplay(json_ffplay, &args)) {
    log_message(LOG_ERROR, "main", "Failed to setup ffplay with JSON config");
    return 1;
  }

  wchar_t command[COMMAND_LINE_LIMIT];
  swprintf(command, sizeof(command),
           L"ffplay"
           " -volume %d"
           " -loop %d"
           " -showmode %d"
           "%s"        // alwaysontop
           "%s"        // noborder
           " \"%ls\"", // filename
           args.volume,
           args.loop,
           args.showmode,
           (args.alwaysontop ? " -alwaysontop" : ""),
           (args.noborder ? " -noborder" : ""),
           args.filename);
  log_wmessage(LOG_INFO, "main", command);

  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
  if (!CreateProcessW(NULL,    // No module name (use command line)
                      command, // Command line
                      NULL,    // Process handle not inheritable
                      NULL,    // Thread handle not inheritable
                      FALSE,   // Set handle inheritance to FALSE
                      0,       // No creation flags
                      NULL,    // Use parent's environment block
                      NULL,    // Use parent's starting directory
                      &si,     // Pointer to STARTUPINFO structure
                      &pi)     // Pointer to PROCESS_INFORMATION structure
  ) {
    log_wmessage(LOG_ERROR, "main", L"CreateProcessW failed: %lu", GetLastError());
  };

  log_wmessage(LOG_INFO, "main", L"Playing: %ls (PID: %lu)", args.filename, pi.dwProcessId);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return 0;
}