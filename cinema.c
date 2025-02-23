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

#ifdef _WIN32
#include <windows.h>
#endif

#include "cJSON.h"

#define MAX_FILENAME 260
#define COMMAND_LINE_LIMIT 32768 // likely way smaller in practice
typedef struct {
  char filename[MAX_FILENAME];
  int volume;
  int loop;
  int alwaysontop;
  int noborder;
} FFplayArgs;

char *read_json(const char *filename) {
  if (filename == NULL || filename[0] == '\0') {
    fprintf(stderr, "Invalid filename provided (empty string)\n");
    return NULL;
  }
  FILE *file = fopen(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Failed to open config file '%s': %s\n", filename, strerror(errno));
    return NULL;
  }
  // Move pointer to get size in bytes and back
  fseek(file, 0, SEEK_END);
  long filesize = ftell(file);
  rewind(file);
  // Buffer for file + null terminator
  char *json_content = (char *)malloc(filesize + 1);
  if (json_content == NULL) {
    fprintf(stderr, "Failed to allocate memory for file '%s' with size '%ld': %s\n",
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

cJSON *parse_json(const char *filename) {
  char *json_string = read_json(filename);
  if (json_string == NULL) {
    return NULL;
  }
  cJSON *json = cJSON_Parse(json_string);
  if (json == NULL) {
    const char *error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL) {
      fprintf(stderr, "JSON parsing error in file '%s' for contents: %s\n", filename, error_ptr);
    }
  }
  free(json_string);
  return json;
}

int setup_ffplay(const cJSON *json_args, FFplayArgs *settings) {
  if (json_args == NULL || settings == NULL) {
    return 0;
  }
  cJSON *vol = cJSON_GetObjectItemCaseSensitive(json_args, "volume");
  if (cJSON_IsNumber(vol)) {
    settings->volume = vol->valueint;
  } else {
    settings->volume = 100;
  }
  cJSON *loop = cJSON_GetObjectItemCaseSensitive(json_args, "loop");
  if (cJSON_IsNumber(loop)) {
    settings->loop = loop->valueint;
  } else {
    settings->loop = 0;
  }
  cJSON *alwaysontop = cJSON_GetObjectItemCaseSensitive(json_args, "alwaysontop");
  if (cJSON_IsBool(alwaysontop)) {
    settings->alwaysontop = cJSON_IsTrue(alwaysontop) ? 1 : 0;
  } else {
    fprintf(stderr, "Expected boolean type for JSON key 'alwaysontop', defaulting to false\n");
    settings->alwaysontop = 0;
  }
  cJSON *noborder = cJSON_GetObjectItemCaseSensitive(json_args, "noborder");
  if (cJSON_IsBool(noborder)) {
    settings->noborder = cJSON_IsTrue(noborder) ? 1 : 0;
  } else {
    fprintf(stderr, "Expected boolean type for JSON key 'noborder', defaulting to false\n");
    settings->noborder = 0;
  }
  return 1;
}

int main() {
#ifndef _WIN32
  fprintf(stderr, "Error: Your operating system is not supported, Windows-only currently.\n");
  return 1;
#endif
  char *config_filename = "config.json";
  cJSON *json = parse_json(config_filename);
  if (json == NULL) {
    return 1;
  }
  char *string = cJSON_Print(json);
  if (string == NULL) {
    fprintf(stderr, "Failed to print cJSON items from config tree with cJSON_Print.\n");
  } else {
    printf("%s\n", string);
  }

  cJSON *path = cJSON_GetObjectItemCaseSensitive(json, "path");
  char *name = NULL;
  if (cJSON_IsString(path) && (path->valuestring != NULL)) {
    name = path->valuestring;
  } else {
    fprintf(stderr, "No 'path' object found in config\n");
    return 1;
  }

  cJSON *json_ffplay = cJSON_GetObjectItemCaseSensitive(json, "ffplay");
  if (!cJSON_IsObject(json_ffplay)) {
    fprintf(stderr, "No 'ffplay' object found in config\n");
    return 1;
  }

  FFplayArgs args;
  strncpy(args.filename, name, sizeof(args.filename) - 1);
  args.filename[sizeof(args.filename) - 1] = '\0';
  setup_ffplay(json_ffplay, &args);

  char command[COMMAND_LINE_LIMIT];
  snprintf(command, sizeof(command),
           "ffplay"
           " -volume %d"
           " -loop %d"
           " %s"  // alwaysontop
           " %s"  // noborder
           " %s", // filename
           args.volume,
           args.loop,
           (args.alwaysontop ? "-alwaysontop" : ""),
           (args.noborder ? "-noborder" : ""),
           args.filename);
  STARTUPINFO si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
  if (!CreateProcess(NULL,    // No module name (use command line)
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
    printf("Failed to start ffplay.\n");
  };
  printf("Playing: %s (PID: %lu)\n", args.filename, pi.dwProcessId);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return 0;
}