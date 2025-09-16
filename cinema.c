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

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "cJSON.h"
#include "libsais.h"

#if defined(CIN_OPENMP)
#include <omp.h>
#endif

typedef enum {
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} Cin_Log_Level;

static const Cin_Log_Level GLOBAL_LOG_LEVEL = LOG_TRACE;

#define CIN_ARRAY_CAP 256
#define CIN_ARRAY_GROWTH 2

#define array_ensure_capacity(a, total)                                      \
  do {                                                                       \
    if ((total) > (a)->capacity) {                                           \
      if (!(a)->capacity) (a)->capacity = CIN_ARRAY_CAP;                     \
      while ((total) > (a)->capacity) (a)->capacity *= CIN_ARRAY_GROWTH;     \
      (a)->items = realloc((a)->items, (a)->capacity * sizeof(*(a)->items)); \
      assert((a)->items && "Memory limit exceeded");                         \
    }                                                                        \
  } while (0)

#define array_reserve(a, n) array_ensure_capacity((a), (a)->count + (n))

#define array_resize(a, total)           \
  do {                                   \
    array_ensure_capacity((a), (total)); \
    (a)->count = (total);                \
  } while (0)

#define array_grow(a, n)     \
  do {                       \
    array_reserve((a), (n)); \
    (a)->count += (n);       \
  } while (0)

#define array_push(a, item)            \
  do {                                 \
    array_reserve((a), 1);             \
    (a)->items[(a)->count++] = (item); \
  } while (0)

#define array_extend(a, new_items, n)                                        \
  do {                                                                       \
    array_reserve((a), (n));                                                 \
    memcpy((a)->items + (a)->count, (new_items), (n) * sizeof(*(a)->items)); \
    (a)->count += (n);                                                       \
  } while (0)

#define warray_extend(a, new_items, n)                  \
  do {                                                  \
    array_reserve((a), (n));                            \
    wmemcpy((a)->items + (a)->count, (new_items), (n)); \
    (a)->count += (n);                                  \
  } while (0)

#define array_splice(a, i, new_items, n)                              \
  do {                                                                \
    assert((i) <= (a)->count);                                        \
    array_reserve((a), (n));                                          \
    memmove((a)->items + (i) + (n),                                   \
            (a)->items + (i),                                         \
            ((a)->count - (i)) * sizeof(*(a)->items));                \
    memcpy((a)->items + (i), (new_items), (n) * sizeof(*(a)->items)); \
    (a)->count += (n);                                                \
  } while (0)

#define warray_splice(a, i, new_items, n)                                 \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((a), (n));                                              \
    wmemmove((a)->items + (i) + (n), (a)->items + (i), (a)->count - (i)); \
    wmemcpy((a)->items + (i), (new_items), (n));                          \
    (a)->count += (n);                                                    \
  } while (0)

#define array_insert(a, i, new_item)                     \
  do {                                                   \
    assert((i) <= (a)->count);                           \
    array_reserve((a), 1);                               \
    if ((i) < (a)->count) {                              \
      memmove((a)->items + (i) + 1,                      \
              (a)->items + (i),                          \
              ((a)->count - (i)) * sizeof(*(a)->items)); \
    }                                                    \
    (a)->items[(i)] = (new_item);                        \
    (a)->count++;                                        \
  } while (0)

#define warray_insert(a, i, new_item)                                     \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((a), 1);                                                \
    if ((i) < (a)->count) {                                               \
      wmemmove((a)->items + (i) + 1, (a)->items + (i), (a)->count - (i)); \
    }                                                                     \
    (a)->items[(i)] = (new_item);                                         \
    (a)->count++;                                                         \
  } while (0)

// https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
// A path can have 248 "characters" (260 - 12 = 248)
// with 12 reserved for 8.3 file name.
// This refers to a WCHAR sequence (UTF-16 code units),
// i.e., wchar_t, such that max bytes = (248 * 2) = 496
// of UTF-16 data or (260 * 2) = 520 upper bound
// This is different from the full storage since
// a surrogate pair character can hold 2 wchar_t or
// (260 * 2 * 2) = 1040 bytes, exceeding the bound
// if many/all characters need 2 code units
// The cFileName from winapi uses a wchar_t buffer of
// 260 (MAX_PATH) so surrogate pairs get truncated
#define CIN_MAX_PATH MAX_PATH
#define CIN_MAX_PATH_BYTES MAX_PATH * 4
#define CIN_MAX_WRITABLE_PATH MAX_PATH - 12
#define CIN_MAX_WRITABLE_PATH_BYTES (MAX_PATH - 12) * 4
#define CIN_COMMAND_PROMPT_LIMIT 8191
#define CIN_MAX_LOG_MESSAGE 1024

static const char *level_to_str(Cin_Log_Level level) {
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

static CRITICAL_SECTION log_lock;

static void log_message(Cin_Log_Level level, const char *location, const char *message, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  EnterCriticalSection(&log_lock);
  // Process variadic args
  va_list args;
  va_start(args, message);
  fprintf(stderr, "[%s] [%s] ", level_to_str(level), location);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  vfprintf(stderr, message, args);
#pragma clang diagnostic pop
  fprintf(stderr, "\n");
  va_end(args);
  LeaveCriticalSection(&log_lock);
}

static int utf16_to_utf8(const wchar_t *wstr, char *buf, int len) {
  if (buf == NULL || wstr == NULL) {
    return -1;
  }
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
  int n_bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, len, NULL, 0, NULL, NULL);
  if (n_bytes <= 0) {
    return -1;
  }
  n_bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, len, buf, n_bytes, NULL, NULL);
  if (n_bytes <= 0) {
    return -1;
  }
  return n_bytes;
}

static int utf8_to_utf16(const char *utf8_str, wchar_t *buf, int len) {
  if (buf == NULL || utf8_str == NULL) {
    return -1;
  }
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
  int n_chars = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);
  if (n_chars <= 0 || n_chars > len) {
    return -1;
  }
  return MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, buf, len);
}

static int utf8_to_utf16_norm(const char *str, wchar_t *buf) {
  // uses winapi to lowercase the string, and ensures it is not empty
  int len = utf8_to_utf16(str, buf, CIN_MAX_PATH);
  if (len <= 1) {
    log_message(LOG_DEBUG, "normalize", "Converted '%s' to empty string.", str);
    return 0;
  }
  DWORD lower = CharLowerBuffW(buf, (DWORD)(len - 1)); // ignore \0
  if ((DWORD)(len - 1) != lower) {
    log_message(LOG_ERROR, "normalize", "Processed unexpected n (%d != %d)", lower, len);
    return 0;
  }
  return len;
}

static void log_wmessage(Cin_Log_Level level, const char *location, const wchar_t *wmessage, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  EnterCriticalSection(&log_lock);
  va_list args;
  va_start(args, wmessage);
  wchar_t formatted_wmsg[CIN_MAX_LOG_MESSAGE];
  vswprintf(formatted_wmsg, CIN_MAX_LOG_MESSAGE, wmessage, args);
  static char buf[CIN_MAX_PATH_BYTES];
  utf16_to_utf8(formatted_wmsg, buf, -1);
  fprintf(stderr, "[%s] [%s] %s\n", level_to_str(level), location, buf);
  va_end(args);
  LeaveCriticalSection(&log_lock);
}

static void log_last_error(const char *location, const char *message, ...) {
  EnterCriticalSection(&log_lock);
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  vfprintf(stderr, message, args);
#pragma clang diagnostic pop
  va_end(args);
  fprintf(stderr, " - Code %lu: %s", code, (char *)buffer);
  LocalFree(buffer);
  LeaveCriticalSection(&log_lock);
}

typedef struct Hash_Table_I32 {
  int32_t *keys;
  int32_t *values;
  int32_t len;
  int32_t a;
  int32_t shift;
  int32_t universe_len;
} Hash_Table_I32;

static Hash_Table_I32 *hash_table_i32(const int32_t *universe, int32_t universe_len) {
  // universal integer hashing with 50% load factor,
  // open addressing with linear probing
  Hash_Table_I32 *table = malloc(sizeof(Hash_Table_I32));
  int32_t len = 1;
  while (len < universe_len * 2) {
    len <<= 1;
  }
  table->shift = 32 - __builtin_clz((unsigned int)len - 1);
  table->a = (rand() * 2) | 1;
  table->keys = malloc((size_t)len * sizeof(int32_t));
  table->values = malloc((size_t)len * sizeof(int32_t));
  for (int32_t i = 0; i < len; ++i) {
    table->keys[i] = -1;
    table->values[i] = -1;
  }
  for (int32_t i = 0; i < universe_len; ++i) {
    int32_t hash = (table->a * universe[i]) >> table->shift;
    while (table->keys[hash] != -1) {
      hash = (hash + 1) & (len - 1);
    }
    table->keys[hash] = universe[i];
  }
  table->len = len;
  return table;
}

static int32_t hash_i32(const Hash_Table_I32 *table, const int32_t value) {
  int32_t hash = (table->a * value) >> table->shift;
  while (table->keys[hash] != value) {
    hash = (hash + 1) & (table->len - 1);
  }
  return hash;
}

static int **rmqa(const int *a, const int n) {
  // sparse table for range minimum query over a
  int log_n = 32 - __builtin_clz((unsigned int)(n - 1));
  int *data = malloc((size_t)n * (size_t)log_n * sizeof(int));
  int **m = malloc((size_t)n * sizeof(int *));
  for (int i = 0; i < n; ++i) {
    m[i] = data + i * log_n;
    m[i][0] = a[i];
  }
#if defined(CIN_OPENMP)
#pragma omp parallel for if (n >= (1 << 16))
#endif
  for (int k = 1; k < log_n; ++k) {
    int step = 1 << (k - 1);
    int limit = n - (1 << k) + 1;
    for (int i = 0; i < limit; ++i) {
      m[i][k] = min(m[i][k - 1], m[i + step][k - 1]);
    }
  }
  return m;
}

static int rmq(int **m, const int left, const int right) {
  int length = right - left + 1;
  int k = 31 - __builtin_clz((unsigned int)length);
  int right_start = right - (1 << k) + 1;
  return min(m[left][k], m[right_start][k]);
}

typedef struct RMQPosition {
  int32_t value;
  int32_t index;
} RMQPosition;

static RMQPosition **rmqa_positional(const int32_t *a, const int32_t n) {
  RMQPosition **m = malloc((size_t)n * sizeof(RMQPosition *));
  int log_n = 31 - __builtin_clz((unsigned int)n);
  for (int i = 0; i < n; ++i) {
    m[i] = malloc((size_t)log_n * sizeof(RMQPosition));
  }
  for (int i = 0; i < n; ++i) {
    m[i][0] = (RMQPosition){.value = a[i], .index = i};
  }
  for (int k = 1; k < log_n; ++k) {
    for (int i = 0; i + (1 << k) - 1 < n; ++i) {
      RMQPosition left = m[i][k - 1];
      RMQPosition right = m[i + (1 << (k - 1))][k - 1];
      m[i][k] = left.value < right.value ? left : right;
    }
  }
  return m;
}

static RMQPosition rmq_positional(RMQPosition **m, const int left, const int right) {
  int length = right - left + 1;
  int k = 31 - __builtin_clz((unsigned int)length);
  int right_start = right - (1 << k) + 1;
  RMQPosition min_left = m[left][k];
  RMQPosition min_right = m[right_start][k];
  return min_left.value < min_right.value ? min_left : min_right;
}

static int32_t lcps(const uint8_t *a, const uint8_t *b) {
  static const int32_t CHUNK_SIZE = 1 << 3;
  const uint8_t *start = a;
  while ((((uintptr_t)a & 7) != 0 || ((uintptr_t)b & 7) != 0) &&
         *a == *b && *a != '\0') {
    a++;
    b++;
  }
  while (((uintptr_t)a & 7) == 0 && ((uintptr_t)b & 7) == 0) {
    uint64_t wa = *(const uint64_t *)a;
    uint64_t wb = *(const uint64_t *)b;
    if (wa != wb || (wa - 0x0101010101010101ULL) & (~wa & 0x8080808080808080ULL)) {
      break;
    }
    a += CHUNK_SIZE;
    b += CHUNK_SIZE;
  }
  while (*a == *b && *a != '\0') {
    a++;
    b++;
  }
  return (int32_t)(a - start);
}

#define CIN_STRERROR_BYTES 95

static char *read_json(const char *filename) {
  if (filename == NULL || filename[0] == '\0') {
    log_message(LOG_ERROR, "json", "Invalid filename provided (empty string)");
    return NULL;
  }
  FILE *file;
  int result = fopen_s(&file, filename, "rb");
  if (result != 0) {
    char err_buf[CIN_STRERROR_BYTES];
    strerror_s(err_buf, CIN_STRERROR_BYTES, result);
    log_message(LOG_ERROR, "json", "Failed to open config file '%s': %s", filename, err_buf);
    return NULL;
  }
  // Move pointer to get size in bytes and back
  fseek(file, 0, SEEK_END);
  long filesize = ftell(file);
  rewind(file);
  if (filesize < 0L) {
    log_message(LOG_ERROR, "json", "Failed to get valid file position");
    fclose(file);
    return NULL;
  }
  // Buffer for file + null terminator
  char *json_content = (char *)malloc((size_t)filesize + 1L);
  if (json_content == NULL) {
    char err_buf[CIN_STRERROR_BYTES];
    _strerror_s(err_buf, CIN_STRERROR_BYTES, NULL);
    log_message(LOG_ERROR, "json", "Failed to allocate memory for file '%s' with size '%ld': %s",
                filename, filesize + 1, err_buf);
    fclose(file);
    return NULL;
  }
  // Read into buffer with null terminator
  fread(json_content, 1, (size_t)filesize, file);
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
  int success = sscanf_s(input, "%d%n", &int_result, &chars_read);
  if (success == 1 && input[chars_read] == '\0') {
    return (double)int_result;
  }
  double double_result;
  chars_read = 0;
  success = sscanf_s(input, "%lf%n", &double_result, &chars_read);
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

// TODO: remove this function
static wchar_t *setup_wstring(const cJSON *json, const char *key, const wchar_t *default_val) {
  if (default_val == NULL) {
    log_message(LOG_DEBUG, "json", "Passed NULL as default value for setup_wstring");
  }
  cJSON *option = cJSON_GetObjectItemCaseSensitive(json, key);
  wchar_t *result = NULL;
  if (cJSON_IsString(option) && option->valuestring) {
    result = malloc(sizeof(wchar_t) * CIN_MAX_PATH);
    utf8_to_utf16(option->valuestring, result, CIN_MAX_PATH);
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
typedef struct Local_Collection {
  // Each byte represents a UTF-8 unit
  uint8_t *text;
  // using int32_t because of libsais,
  // unsigned variants are pointless
  int32_t bytes;
  int32_t max_bytes;
  size_t bytes_mul32;
  size_t doc_mul32;
  // Document boundaries are encapsulated in the GSA
  // because the lexicographical sort puts \0 entries
  // at the top; the first doc_count entries
  // represent the start/end positions of each doc
  int32_t doc_count;
} Local_Collection;

static Local_Collection locals = {0};
static int32_t *gsa = NULL;
static int32_t *lcp = NULL;
static int32_t *suffix_to_doc = NULL;
static uint16_t *dedup_counters = NULL;

static void locals_append(const char *utf8, int len) {
  // Geometric growth with clamp, based on 260 max path
  static const int locals_init = 1 << 15;
  static const int locals_clamp = 1 << 26;
  void *dst = NULL;
  if (locals.max_bytes - locals.bytes >= len) {
    dst = locals.text + locals.bytes;
  } else {
    int32_t cap = locals.max_bytes;
    if (cap <= 0) {
      cap = locals_init;
    }
    while (cap - locals.bytes < len) {
      cap = cap < locals_clamp ? cap * 2 : cap + locals_clamp;
    }
    locals.max_bytes = cap;
    uint8_t *units = realloc(locals.text, (size_t)locals.max_bytes);
    if (units != NULL) {
      locals.text = units;
      dst = locals.text + locals.bytes;
    }
  }
  if (dst == NULL) {
    log_message(LOG_ERROR, "locals", "Failed to reallocate memory");
  } else {
    memcpy(dst, utf8, (size_t)len);
    locals.bytes += len;
    locals.doc_count++;
  }
}

// TODO: parallelize
static char utf8_buf[CIN_MAX_PATH_BYTES];

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
  if (path[len - 1] == L'\0') {
    len--;
  }
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
    wchar_t *file = data.cFileName;
    CharLowerW(file);
    bool is_dir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    if (is_dir && (file[0] == L'.') && (!file[1] || (file[1] == L'.' && !file[2]))) {
      continue; // skip dot entry
    }
    size_t file_len = wcslen(file) + 1; // add \0
    size_t path_len = len + file_len;
    if (path_len >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(path + len, file, file_len);
    if (is_dir) {
      if (!setup_directory(path, path_len)) {
        ok = false;
      }
    } else {
      int utf8_len = utf16_to_utf8(path, utf8_buf, (int)path_len);
      locals_append(utf8_buf, utf8_len);
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
  size_t dir_len = (size_t)(separator - pattern) + 1;
  if (dir_len > CIN_MAX_PATH) {
    return false;
  }
  wchar_t dir_buf[CIN_MAX_PATH];
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
    wchar_t *file = data.cFileName;
    CharLowerW(file);
    size_t file_len = wcslen(file) + 1; // add \0
    size_t path_len = abs_len + file_len;
    if (path_len >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(abs_buf + abs_len, file, file_len);
    int len = utf16_to_utf8(abs_buf, utf8_buf, (int)path_len);
    locals_append(utf8_buf, len);
  } while (FindNextFileW(search, &data) != 0);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    log_last_error("directories", "Failed to find next file");
    ok = false;
  }
  FindClose(search);
  return ok;
}

static bool setup_url(const wchar_t *url) {
  int len = utf16_to_utf8(url, utf8_buf, -1);
  locals_append(utf8_buf, len);
  return true;
}

static bool setup_tag(const wchar_t *tag) {
  utf16_to_utf8(tag, utf8_buf, -1);
  // locals_append(utf8_buf, len);
  return true;
}

static void document_listing(const uint8_t *pattern, int32_t pattern_len) {
  int32_t left = locals.doc_count;
  int32_t right = locals.bytes - 1;
  int32_t l_lcp = lcps(pattern, locals.text + gsa[left]);
  int32_t r_lcp = lcps(pattern, locals.text + gsa[right]);
  if (l_lcp < pattern_len &&
      (locals.text[gsa[left] + l_lcp] == '\0' ||
       pattern[l_lcp] < locals.text[gsa[left] + l_lcp])) {
    // pattern = abc, left = abd
    // l_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[l_lcp] = c, text[left + l_lcp] = d, c < d
    log_message(LOG_DEBUG, "documents", "Pattern is smaller than first suffix");
    return;
  }
  if (r_lcp < pattern_len &&
      locals.text[gsa[right] + r_lcp] != '\0' &&
      pattern[r_lcp] > locals.text[gsa[right] + r_lcp]) {
    // pattern = abd, right = abc
    // r_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[r_lcp] = d, text[right + r_lcp] = c, d > c
    log_message(LOG_DEBUG, "documents", "Pattern is larger than last suffix");
    return;
  }
  int32_t tmp_right = right;
  int32_t tmp_r_lcp = r_lcp;
  bool found = false;
  while (left < right) {
    int32_t mid = left + ((right - left) >> 1);
    int32_t t_lcp = lcps(pattern, locals.text + gsa[mid]);
    if (t_lcp == pattern_len) {
      found = true;
      right = mid;
      r_lcp = t_lcp;
    } else if (locals.text[gsa[mid] + t_lcp] == '\0') {
      left = mid + 1;
      l_lcp = t_lcp;
    } else if (pattern[t_lcp] < locals.text[gsa[mid] + t_lcp]) {
      right = mid;
      r_lcp = t_lcp;
    } else {
      left = mid + 1;
      l_lcp = t_lcp;
    }
  }
  if (!found && lcps(pattern, locals.text + gsa[left]) < pattern_len) {
    log_message(LOG_DEBUG, "documents", "No suffix has pattern as prefix");
    return;
  }
  int32_t l_bound = left;
  int32_t r_bound = left;
  right = tmp_right;
  l_lcp = pattern_len;
  r_lcp = tmp_r_lcp;
  while (left < right) {
    int32_t mid = left + ((right - left + 1) >> 1);
    int32_t t_lcp = lcps(pattern, locals.text + gsa[mid]);
    if (t_lcp == pattern_len) {
      left = mid;
      l_lcp = pattern_len;
    } else if (locals.text[gsa[mid] + t_lcp] == '\0') {
      right = mid - 1;
      r_lcp = t_lcp;
    } else {
      right = mid - 1;
      r_lcp = t_lcp;
    }
    r_bound = left;
  }
  log_message(LOG_DEBUG, "documents", "Boundaries are [%d, %d] or [%s, %s]", l_bound, r_bound,
              locals.text + gsa[l_bound], locals.text + gsa[r_bound]);
  static uint16_t dedup_counter = 1;
  for (int32_t i = l_bound; i <= r_bound; ++i) {
    int32_t doc = suffix_to_doc[i];
    if (dedup_counters[doc] != dedup_counter) {
      dedup_counters[doc] = dedup_counter;
      log_message(LOG_TRACE, "documents", "gsa[%7d] = %-25.25s (%7d)| (%7d) = %-30.30s counter=%d", i, locals.text + gsa[i], gsa[i], doc, locals.text + doc, dedup_counter);
    }
  }
  if (++dedup_counter == 0) {
    memset(dedup_counters, 0, (size_t)locals.bytes * sizeof(uint16_t));
    dedup_counter = 1;
  }
}

static bool setup_locals(const cJSON *json) {
  // TODO: deduplicate while setting up
  cJSON *lib = cJSON_GetObjectItemCaseSensitive(json, "media_library");
  if (lib == NULL || !cJSON_IsArray(lib)) {
    log_message(LOG_ERROR, "media_library", "Could not find media_library array in JSON");
    return false;
  }
  cJSON *entry = NULL;
  // TODO: parallelize with openmp
  static wchar_t buf[CIN_MAX_PATH];
  cJSON_ArrayForEach(entry, lib) {
    cJSON *cursor = NULL;
    cJSON *directories = setup_entry_collection(entry, "directories");
    cJSON_ArrayForEach(cursor, directories) {
      int len = utf8_to_utf16_norm(cursor->valuestring, buf);
      if (len) {
        setup_directory(buf, (size_t)len);
      }
    }
    cJSON *patterns = setup_entry_collection(entry, "patterns");
    cJSON_ArrayForEach(cursor, patterns) {
      int len = utf8_to_utf16_norm(cursor->valuestring, buf);
      if (len) {
        setup_pattern(buf);
      }
    }
    cJSON *urls = setup_entry_collection(entry, "urls");
    cJSON_ArrayForEach(cursor, urls) {
      int len = utf8_to_utf16_norm(cursor->valuestring, buf);
      if (len) {
        setup_url(buf);
      }
    }
    // TODO: put tags in separate structure
    // cJSON *tags = setup_entry_collection(entry, "tags");
    // cJSON_ArrayForEach(cursor, tags) {
    //   if (cursor->valuestring != NULL && strlen(cursor->valuestring) > 0) {
    //     setup_tag(cursor->valuestring);
    //     locals_append(cursor->valuestring, strlen(cursor->valuestring));
    //   }
    // }
    log_message(LOG_INFO, "media_library", "Processing entry: %s", cJSON_PrintUnformatted(entry));
  }
  if (locals.bytes < locals.max_bytes) {
    uint8_t *tight = realloc(locals.text, (size_t)locals.bytes);
    if (tight != NULL) {
      locals.text = tight;
    }
    locals.max_bytes = locals.bytes;
    locals.bytes_mul32 = (size_t)locals.bytes * sizeof(int32_t);
    locals.doc_mul32 = (size_t)locals.doc_count * sizeof(int32_t);
  }
  log_message(LOG_INFO, "media_library", "Setup media library with %d items (%d bytes)",
              locals.doc_count, locals.bytes);
  return true;
}

static bool setup_substring_search(void) {
  gsa = malloc(locals.bytes_mul32);
#if defined(LIBSAIS_OPENMP)
  int32_t result = libsais_gsa_omp(locals.text, gsa, locals.bytes, 0, NULL, 0);
#else
  int32_t result = libsais_gsa(locals.text, gsa, locals.bytes, 0, NULL);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "media_library", "Failed to build SA");
    return false;
  }
  int32_t *plcp = malloc(locals.bytes_mul32);
#if defined(LIBSAIS_OPENMP)
  result = libsais_plcp_gsa_omp(locals.text, gsa, plcp, locals.bytes, 0);
#else
  result = libsais_plcp_gsa(locals.text, gsa, plcp, locals.bytes);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "media_library", "Failed to build PLCP array");
    return false;
  }
  lcp = malloc(locals.bytes_mul32);
#if defined(LIBSAIS_OPENMP)
  result = libsais_lcp_omp(plcp, gsa, lcp, locals.bytes, 0);
#else
  result = libsais_lcp(plcp, gsa, lcp, locals.bytes);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "media_library", "Failed to build LCP array");
    return false;
  }
  free(plcp);
  suffix_to_doc = malloc(locals.bytes_mul32);
  dedup_counters = calloc((size_t)locals.bytes, sizeof(uint16_t));
  suffix_to_doc[0] = 0;
  for (int32_t i = 1; i < locals.doc_count; ++i) {
    suffix_to_doc[i] = gsa[i - 1] + 1;
  }
  // TODO: there is probably a faster approach than
  // binary search, but with omp it is very fast
#if defined(CIN_OPENMP)
#pragma omp parallel for if (locals.bytes >= (1 << 16))
#endif
  for (int32_t i = locals.doc_count; i < locals.bytes; ++i) {
    int32_t left = 0;
    int32_t right = locals.doc_count - 1;
    int32_t curr = gsa[i];
    while (left < right) {
      int32_t mid = left + ((right - left + 1) >> 1);
      if (suffix_to_doc[mid] <= curr) {
        left = mid;
      } else {
        right = mid - 1;
      }
    }
    suffix_to_doc[i] = suffix_to_doc[left];
  }
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
// TODO: find better upper bound for transaction (pending 64kb writes can scale very fast, files are maxed to 260)
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

typedef struct Instance {
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
  int64_t request_id;
} Instance;

static bool create_process(Instance *instance, const wchar_t *pipe_name, const wchar_t *file_name) {
  static wchar_t command[CIN_COMMAND_PROMPT_LIMIT];
  swprintf(command, CIN_COMMAND_PROMPT_LIMIT,
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

static cJSON *mpv_command(const char *command, int64_t request_id) {
  cJSON *json = cJSON_CreateObject();
  if (json == NULL) {
    goto end;
  }
  cJSON *cmd_array = cJSON_CreateArray();
  if (cmd_array == NULL) {
    goto end;
  }
  cJSON *cmd_element = cJSON_CreateString(command);
  if (cmd_element == NULL) {
    goto end;
  }
  cJSON_AddItemToArray(cmd_array, cmd_element);
  cJSON_AddItemToObject(json, "command", cmd_array);
  // NOTE: precision loss when request_id is extremely
  // large (unrealistic), but mostly a problem if the data type
  // changes from int64_t to something else
  cJSON *cmd_id = cJSON_CreateNumber((double)request_id);
  cJSON_AddItemToObject(json, "request_id", cmd_id);
  return json;
end:
  cJSON_Delete(json);
  return NULL;
}

static bool overlap_write(Instance *instance, cJSON *command) {
  // TODO: dont use cjson, use static buffer
  log_message(LOG_TRACE, "write", "Initializing write on PID %lu", instance->pi.dwProcessId);
  char *command_str = cJSON_PrintUnformatted(command);
  cJSON_Delete(command);
  if (command_str == NULL) {
    log_message(LOG_ERROR, "write", "Failed to cJSON_PrintUnformatted the mpv command.");
    return false;
  }
  size_t len = strlen(command_str);
  Overlapped_Write *write = calloc(1, sizeof(*write));
  if (write == NULL) {
    log_message(LOG_ERROR, "write", "Failed to allocate memory.");
    return false;
  }
  if (len >= sizeof(write->buffer)) {
    log_message(LOG_ERROR, "write", "Message len '%d' bigger than buffer '%d'", len, sizeof(write->buffer));
    return false;
  }
  // shift \0 up to insert \n
  // and include \0 in len (bytes)
  command_str[len++] = '\n';
  command_str[len++] = '\0';
  memcpy(write->buffer, command_str, len);
  write->ovl_context.is_write = true;
  write->bytes = len;
  write->request_id = instance->request_id - 1;
  log_message(LOG_DEBUG, "write", "Writing message: %.*s", len - 2, write->buffer);
  free(command_str);
  if (!WriteFile(instance->pipe, write->buffer, (DWORD)len, NULL, &write->ovl_context.ovl)) {
    switch (GetLastError()) {
    case ERROR_IO_PENDING:
      // iocp will free write
      log_message(LOG_TRACE, "write", "Pending write call, handled by iocp.");
      return true;
    case ERROR_INVALID_HANDLE:
      // Code 6: The handle is invalid
      log_message(LOG_DEBUG, "write", "\t(ERR_START)\n\t%.*s\n\t(ERR_END)\n", (int)len - 2, write->buffer);
      break;
    }
    log_last_error("write", "Failed to initialize write");
    free(write);
    return false;
  }
  log_message(LOG_TRACE, "write", "Write call completed immediately.");
  return true;
}

static bool create_instance(Instance *instance, const wchar_t *name, const wchar_t *file_name, HANDLE *iocp) {
  if (name == NULL || file_name == NULL) {
    return false;
  }
  instance->ovl_context.is_write = false;
  instance->request_id = 0;
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

static Overlapped_Write *find_write(Instance *instance, int64_t request_id) {
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
  size_t left = 0;
  size_t right = instance->pending_writes.count - 1;
  while (left <= right) {
    size_t middle = left + ((right - left) >> 1);
    int64_t mid_val = instance->pending_writes.items[middle]->request_id;
    if (mid_val < request_id) {
      left = middle + 1;
    } else if (mid_val > request_id) {
      if (middle == 0) {
        break;
      }
      right = middle - 1;
    } else {
      return instance->pending_writes.items[middle];
    }
  }
  log_message(LOG_ERROR, "find_write", "Tried to find '%" PRId64 "' but could not find it", request_id);
  return NULL;
}

static DWORD WINAPI iocp_listener(LPVOID lp_param) {
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
      Pending_Writes *pending = &instance->pending_writes;
      if (pending->count >= pending->capacity) {
        pending->capacity = pending->capacity * 2;
        pending->items = realloc(pending->items, sizeof(Overlapped_Write *) * pending->capacity);
        if (pending->items == NULL) {
          log_message(LOG_ERROR, "listener", "Failed to reallocate memory of pending writes");
          break;
        }
      }
      pending->items[pending->count++] = write;
      if (write->bytes != bytes) {
        log_message(LOG_ERROR, "listener", "Expected '%ld' bytes but received '%ld'", write->bytes, bytes);
        // TODO: when observed, resolve instead of break
        break;
      }
    } else {
      cJSON *json = cJSON_Parse(instance->read_buffer);
      if (json == NULL) {
        // TODO: when observed, resolve instead of break
        log_message(LOG_ERROR, "listener", "Failed to parse instance read buffer as JSON");
        break;
      }
      cJSON *request_id = cJSON_GetObjectItemCaseSensitive(json, "request_id");
      if (cJSON_IsNumber(request_id)) {
        Overlapped_Write *write = find_write(instance, request_id->valueint);
        log_message(LOG_DEBUG, "listener", "Written to pipe    (%p): %.*s", (void *)instance->pipe, strlen(write->buffer) - 1, write->buffer);
        // TODO: free the write struct and prune pending_writes
        // TODO: handle different return cases beyond request_id
      }
      // TODO: read each line (separated by \n character) separately
      // TODO: Currently, embedded 0 bytes terminate the current line, but you should not rely on this.
      instance->read_buffer[bytes] = '\0'; // TODO: handle buffer gracefully
      log_message(LOG_DEBUG, "listener", "Got data from pipe (%p): %.*s", (void *)instance->pipe, strlen(instance->read_buffer) - 1, instance->read_buffer);
      log_message(LOG_DEBUG, "listener", "END data from pipe (%p)", (void *)instance->pipe);
      cJSON_Delete(json);
      if (!overlap_read((Instance *)completion_key)) {
        // TODO: when observed, resolve instead of break
        break;
      }
    }
  }
  return 0;
}

#define CIN_NUL 0x00
#define CIN_BACK 0x08
#define CIN_ENTER 0x0D
#define CIN_CONTROL_BACK 0x7F
#define CIN_ESCAPE 0x1B
#define CIN_SPACE 0x20
#define CIN_VK_0 0x30
#define CIN_VK_9 0x39
#define CIN_VK_A 0x41
#define CIN_VK_Z 0x5A

// https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
#define ESC "\x1b"
#define CSI "\x1b["

typedef struct Console_Message {
  struct Console_Message *next;
  struct Console_Message *prev;
  wchar_t *items;
  size_t count;
  size_t capacity;
} Console_Message;

// TODO: change to found upper bound
static const size_t CM_INIT_CAP = 256;

static Console_Message *create_console_message() {
  Console_Message *msg = malloc(sizeof(Console_Message));
  assert(msg);
#if defined(NDEBUG)
  wchar_t *items = malloc(CM_INIT_CAP * sizeof(wchar_t));
#else
  wchar_t *items = calloc(CM_INIT_CAP, sizeof(wchar_t));
#endif
  assert(items);
  msg->next = NULL;
  msg->prev = NULL;
  msg->items = items;
  msg->count = 0;
  msg->capacity = CM_INIT_CAP;
  return msg;
}

int main(int argc, char **argv) {
#ifndef _WIN32
  log_message(LOG_ERROR, "main", "Error: Your operating system is not supported, Windows-only currently.");
  return 1;
#endif
  InitializeCriticalSectionAndSpinCount(&log_lock, 0);
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
  setup_locals(json);
  setup_substring_search();
  uint8_t pattern[] = "test";
  // document_listing(pattern, (int32_t)strlen((const char *)pattern));

  if (!SetConsoleCP(CP_UTF8)) {
    log_last_error("input", "Failed to set console code page");
    return 1;
  }
  if (!SetConsoleOutputCP(CP_UTF8)) {
    log_last_error("input", "Failed to set console output code page");
    return 1;
  }
  HANDLE console_in = GetStdHandle(STD_INPUT_HANDLE);
  if (console_in == INVALID_HANDLE_VALUE) {
    log_last_error("input", "Failed to get stdin handle");
    return 1;
  }
  DWORD console_mode_in;
  if (!GetConsoleMode(console_in, &console_mode_in)) {
    log_last_error("input", "Failed to get in console mode");
    return 1;
  }
  if (!SetConsoleMode(console_in, console_mode_in | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT)) {
    log_last_error("input", "Failed to set in console mode");
    return 1;
  }
  HANDLE console_out = GetStdHandle(STD_OUTPUT_HANDLE);
  if (console_out == INVALID_HANDLE_VALUE) {
    log_last_error("input", "Failed to get stdout handle");
    return 1;
  }
  DWORD console_mode_out;
  if (!GetConsoleMode(console_out, &console_mode_out)) {
    log_last_error("input", "Failed to get out console mode");
    return 1;
  }
  if (!SetConsoleMode(console_out, console_mode_out | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_WRAP_AT_EOL_OUTPUT | DISABLE_NEWLINE_AUTO_RETURN)) {
    log_last_error("input", "Failed to set out console mode");
    return 1;
  }
  CONSOLE_SCREEN_BUFFER_INFO console_info = {0};
  COORD console_cursor = {0};
  DWORD read = 0;
  INPUT_RECORD input = {0};
  wchar_t c = 0;
  wchar_t vk = 0;
  Console_Message *msg = create_console_message();
  Console_Message *msg_tail = NULL;
  size_t msg_index = 0;
  size_t prev_count = 0;
  wchar_t prefix[32];
  size_t prefix_len = 0;
  int16_t prev_up = 0;
  int16_t prev_right = 0;
  int16_t next_up = 0;
  int16_t next_right = 0;
  int16_t curr_up = 0;
  int16_t curr_right = 0;
  CONSOLE_CURSOR_INFO cursor_info = {0};
  if (!GetConsoleScreenBufferInfo(console_out, &console_info)) {
    log_last_error("input", "Failed to get console screen buffer info");
    return 1;
  }
  if (!GetConsoleCursorInfo(console_out, &cursor_info)) {
    log_last_error("input", "Failed to get console cursor info");
    return 1;
  }
  int16_t home_y = console_info.dwCursorPosition.Y;
  int16_t console_width = console_info.dwSize.X;
  assert(console_width);
  WriteConsoleW(console_out, L"\r> ", wcslen(L"\r> "), NULL, NULL);
  static const int PREFIX = 2;
  for (;;) {
    if (!ReadConsoleInputW(console_in, &input, 1, &read)) {
      log_last_error("input", "Failed to read console input");
      return 1;
    }
    c = input.Event.KeyEvent.uChar.UnicodeChar;
    vk = input.Event.KeyEvent.wVirtualKeyCode;
    bool pressed = input.Event.KeyEvent.bKeyDown;
    bool ctrl = input.Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED);
    bool alt = input.Event.KeyEvent.dwControlKeyState & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED);
    if (!pressed && (!c || vk != VK_MENU)) {
      continue;
    }
    switch (input.EventType) {
    case KEY_EVENT:
      // wprintf(L"\rchar=%zu, v=%zu, pressed=%d, alt=%d, ctrl=%d\r\n", c, vk, pressed, alt, ctrl);
      break;
    case FOCUS_EVENT:
      break;
    case WINDOW_BUFFER_SIZE_EVENT:
      console_width = input.Event.WindowBufferSizeEvent.dwSize.X;
      break;
    default:
      log_message(LOG_ERROR, "input", "\rUnsupported event: 0x%.4x", input.EventType);
      break;
    }
    bool move_cursor = false;
    switch (vk) {
    case VK_BACK:
      if (msg_index) {
        if (ctrl) {
          size_t i = msg_index;
          while (i && msg->items[--i] == CIN_SPACE) {
          }
          while (i && msg->items[i - 1] != CIN_SPACE) {
            --i;
          }
          if (i < msg_index) {
            wmemmove(&msg->items[i], &msg->items[msg_index], msg->count - msg_index);
            msg->count -= (msg_index - i);
            msg_index = i;
          }
        } else {
          wmemmove(&msg->items[msg_index - 1], &msg->items[msg_index], msg->count - msg_index);
          msg_index--;
          msg->count--;
        }
      }
      break;
    case VK_RETURN:
      // TODO: besides empty, also ignore duplicates
      bool empty = true;
      for (size_t i = 0; i < msg->count; ++i) {
        if (msg->items[i] != CIN_SPACE) {
          empty = false;
          break;
        }
      }
      if (!empty) {
        if (msg_tail) {
          msg_tail->next = msg;
          msg->prev = msg_tail;
        }
        msg->next = NULL;
        msg_tail = msg;
        msg = create_console_message();
        msg->prev = msg_tail;
      }
      msg_index = 0;
      msg->count = 0;
      break;
    case VK_ESCAPE:
      msg_index = 0;
      msg->count = 0;
      break;
    case VK_DELETE:
      if (msg_index < msg->count) {
        if (ctrl) {
          size_t i = msg_index;
          while (i < msg->count && msg->items[i] != CIN_SPACE) {
            ++i;
          }
          while (i < msg->count && msg->items[++i] == CIN_SPACE) {
          }
          wmemmove(&msg->items[msg_index], &msg->items[i], msg->count - i);
          msg->count -= (i - msg_index);
        } else {
          wmemmove(&msg->items[msg_index], &msg->items[msg_index + 1], msg->count - msg_index);
          msg->count--;
        }
      }
      break;
    case VK_UP:
      if (msg->prev) {
        array_resize(msg, msg->prev->count);
        wmemcpy(msg->items, msg->prev->items, msg->prev->count);
        msg_index = msg->count;
        msg->next = msg->prev->next;
        msg->prev = msg->prev->prev;
      } else {
        continue;
      }
      break;
    case VK_DOWN:
      if (msg->next) {
        msg->capacity = msg->next->capacity;
        msg->count = msg->next->count;
        wmemcpy(msg->items, msg->next->items, msg->next->count);
        msg->prev = msg->next->prev;
        msg->next = msg->next->next;
      } else if (msg->count) {
        msg->prev = msg_tail;
        msg->count = 0;
      } else {
        continue;
      }
      msg_index = msg->count;
      break;
    case VK_LEFT:
      if (msg_index) {
        if (ctrl) {
          while (msg_index && msg->items[--msg_index] == CIN_SPACE) {
          }
          while (msg_index && msg->items[msg_index - 1] != CIN_SPACE) {
            --msg_index;
          }
        } else {
          --msg_index;
        }
        SetConsoleCursorPosition(console_out, (COORD){.X = (msg_index + PREFIX) % console_width, .Y = home_y + ((msg_index + PREFIX) / console_width)});
      }
      continue;
    case VK_RIGHT:
      if (msg_index < msg->count) {
        if (ctrl) {
          while (msg_index < msg->count && msg->items[msg_index] != CIN_SPACE) {
            ++msg_index;
          }
          while (msg_index < msg->count && msg->items[++msg_index] == CIN_SPACE) {
          }
        } else {
          ++msg_index;
        }
        SetConsoleCursorPosition(console_out, (COORD){.X = (msg_index + PREFIX) % console_width, .Y = home_y + ((msg_index + PREFIX) / console_width)});
      }
      continue;
    default:
      if (!c) {
        // likely modifier key (shift, ctrl)
        continue;
      }
      // wprintf(L"\rchar=%zu, v=%zu, pressed=%d, alt=%d, ctrl=%d\r\n", c, vk, pressed, alt, ctrl);
      if (vk >= CIN_VK_0 && vk <= CIN_VK_9) {
      } else if (vk >= CIN_VK_A && vk <= CIN_VK_Z) {
      } else {
        // exit(1);
      }
      warray_insert(msg, msg_index, c);
      ++msg_index;
      break;
    }
    size_t visible_lines = console_info.srWindow.Bottom - console_info.srWindow.Top;
    // TODO: PowerShell behaves differently when a new line is added

    // NOTE: Console virtual terminal sequences are constrained to the current
    // viewport into the console buffer (currently visible row/cols).
    // Because of this, you cannot go up/down beyond the amount of lines currently
    // visible, which means you cannot reach any of the output (e.g., to clear)
    // above or below the visible rows. You can probably work around this with some
    // viewport/scrolling commands, but it seems better to just use other APIs.
    next_up = (msg->count + PREFIX) / console_width;
    next_right = (msg->count + PREFIX) % console_width;
    cursor_info.bVisible = false;
    SetConsoleCursorInfo(console_out, &cursor_info);
    SetConsoleCursorPosition(console_out, (COORD){.X = PREFIX, .Y = home_y});
    size_t original_count = msg->count;
    if (next_right == 0 && next_up >= prev_up) {
      // TODO: fix when delete/insert/backspace/arrow at last index cursor pos
      // wchar_t *tmp2 = L" \b";
      // warray_extend(msg, tmp2, wcslen(tmp2));
    }
    if (msg->count < prev_count) {
      DWORD q;
      FillConsoleOutputCharacterW(console_out, L' ', prev_count - msg->count,
                                  (COORD){.X = next_right, .Y = home_y + next_up}, &q);
    }
    WriteConsoleW(console_out, msg->items, msg->count, NULL, NULL);
    if (msg_index < msg->count) {
      // TODO: fix line wrapping backwards
      SetConsoleCursorPosition(console_out,
                               (COORD){.X = (msg_index + PREFIX) % console_width, .Y = home_y + next_up});
    }
    cursor_info.bVisible = true;
    SetConsoleCursorInfo(console_out, &cursor_info);
    msg->count = original_count;
    prev_count = original_count;
    prev_up = next_up;
    prev_right = next_right;
  }
  if (!SetConsoleMode(console_in, console_mode_in)) {
    log_last_error("input", "Failed to reset in console mode");
    return 1;
  }
  if (!SetConsoleMode(console_out, console_mode_out)) {
    log_last_error("input", "Failed to reset out console mode");
    return 1;
  }
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
  cJSON *command = mpv_command("loadfile", pipes[0].request_id++);
  cJSON *command_array = cJSON_GetObjectItem(command, "command");
  cJSON *command_arg = cJSON_CreateString("D:\\Test\\video ❗.mp4");
  cJSON_AddItemToArray(command_array, command_arg);
  overlap_write(&pipes[0], command);

  Sleep(2000);
  // normalizing backslash probably not worth
  cJSON *command2 = mpv_command("normalize-path", pipes[0].request_id++);
  cJSON *command_array2 = cJSON_GetObjectItem(command2, "command");
  cJSON *command_arg2 = cJSON_CreateString("D:/Test/video ❗.mp4");
  cJSON_AddItemToArray(command_array2, command_arg2);
  overlap_write(&pipes[0], command2);

  Sleep(2000);

  // https://mpv.io/manual/stable/#json-ipc
  // mpv file.mkv --input-ipc-server=\\.\pipe\mpvsocket
  // echo loadfile "filepath" replace >\\.\pipe\mpvsocket
  // ipc commands:
  // https://mpv.io/manual/stable/#list-of-input-commands
  // https://mpv.io/manual/stable/#commands-with-named-arguments
  // these commands can also be async

  // TODO: subtitles conf
  // TODO: urls
  // TODO: substring search with SA/LCP
  // TODO: tag lookup with circular buffer and exclusion window
  return 0;
}
