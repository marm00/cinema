// Copyright (c) 2025-2026 marm00

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

#ifdef _WIN32
#include <wchar.h>
#include <windows.h>
#pragma comment(lib, "user32")
#pragma comment(lib, "advapi32")
#else
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <glob.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#endif

#include "src/arena.h"
#include "src/array.h"
#include "src/cache.h"
#include "src/common.h"
#include "src/config.c"
#include "src/console.c"
#include "src/log.c"
#include "src/misc.c"
#include "src/os.c"


#ifdef CIN_OPENMP
#include <omp.h>
#endif

static Arena arena_io = {0};
static Arena arena_iocp_thread = {0};

#define CIN_IO_ARENA_CAP megabytes(2)
#define CIN_READ_SIZE kilobytes(16)
#define CIN_WRITE_SIZE align_to_block(CIN_MAX_PATH_BYTES) + block_bytes(2)

typedef enum {
  MPV_READ,
  MPV_WRITE,
  MPV_LOADFILE,
  MPV_WINDOW_ID,
  MPV_SET_GEOMETRY,
  MPV_GET_PATH,
  MPV_QUIT
} MPV_Packet;

typedef struct Overlapped_Context {
#ifdef _WIN32
  OVERLAPPED ovl;
#endif
  MPV_Packet type;
} Overlapped_Context;

typedef struct Overlapped_Write {
  Overlapped_Context ovl_ctx;
  char buf[CIN_WRITE_SIZE];
  size_t bytes;
  cache_node_struct_members(Overlapped_Write);
} Overlapped_Write;

typedef struct Read_Buffer {
  char buf[CIN_READ_SIZE];
  size_t bytes;
  struct Read_Buffer *next;
} Read_Buffer;

typedef struct Instance {
  Read_Buffer *buf_head;
  Read_Buffer *buf_tail;
#ifdef _WIN32
  Overlapped_Context ovl_ctx;
  HANDLE socket;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
#else
  int32_t socket;
#endif
  HWND window;
  RECT rect;
  Playlist *playlist;
  bool full_screen;
  bool autoplay_mpv;
  bool locked;
  cache_node_struct_members(Instance);
} Instance;

cache_define(Write_Cache, Overlapped_Write);
cache_define(Instance_Cache, Instance);

static struct {
  Write_Cache writes;
  Instance_Cache instances;
#ifdef _WIN32
  HANDLE iocp;
#endif
} cin_io = {0};

#ifdef _WIN32
static bool create_pipe(Instance *instance, const wchar_t *name) {
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
      cin_sleep(UNFOUND_WAIT);
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

static bool overlap_read(Instance *instance) {
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
#endif

#define CIN_WRITE_CMD_LEFT "{async:true,request_id:%" PRId64 ",command:[\"%s\""
#define CIN_WRITE_CMD_MID ",\"%s\""
#define CIN_WRITE_CMD_RIGHT "]}\n"
#define CIN_WRITE_CMD_0ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_RIGHT)
#define CIN_WRITE_CMD_1ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_MID CIN_WRITE_CMD_RIGHT)
#define CIN_WRITE_CMD_2ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_MID CIN_WRITE_CMD_MID CIN_WRITE_CMD_RIGHT)

static bool overlap_write(Instance *instance, MPV_Packet type, const char *cmd, const char *arg1, const char *arg2) {
  Overlapped_Write *msg = NULL;
  cache_get_zero(&arena_io, &cin_io.writes, msg);
  msg->ovl_ctx.type = type;
  const int64_t request_id = (int64_t)(uintptr_t)msg;
  int32_t bytes = 0;
  if (arg1 && arg2) bytes = snprintf(msg->buf, sizeof(msg->buf), CIN_WRITE_CMD_2ARG, request_id, cmd, arg1, arg2);
  else if (arg1) bytes = snprintf(msg->buf, sizeof(msg->buf), CIN_WRITE_CMD_1ARG, request_id, cmd, arg1);
  else bytes = snprintf(msg->buf, sizeof(msg->buf), CIN_WRITE_CMD_0ARG, request_id, cmd);
  assert(bytes > 0);
  assert((size_t)bytes < sizeof(msg->buf) - 1);
  msg->bytes = (size_t)bytes;
  log_message(LOG_DEBUG, "Writing message (%p) (%zu bytes): %.*s",
              instance, msg->bytes, msg->bytes - 1, msg->buf);
#ifdef _WIN32
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
    return false;
  }
#else
  const ssize_t write_result = write(instance->socket, msg->buf, msg->bytes);
  if (write_result < 0) {
    log_last_error("Failed to write to file descriptor %d", instance->socket);
  } else if (write_result < (ssize_t)msg->bytes) {
    log_message(LOG_ERROR, "Expected '%zu' bytes but received '%ld': %s", msg->bytes, bytes, msg->buf);
  }
#endif
  log_message(LOG_TRACE, "Write call completed immediately.");
  return true;
}

#ifdef _WIN32

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

static int32_t CALLBACK enum_windows_proc_pid(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  DWORD pid;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid == data->pid && IsWindow(hwnd)) {
    data->hwnd = hwnd;
    return FALSE;
  }
  return TRUE;
}

static HWND find_window_by_pid(uint32_t pid) {
  Window_Data data = {.pid = pid, .hwnd = NULL};
  EnumWindows(enum_windows_proc_pid, (LPARAM)&data);
  return data.hwnd;
}

static int32_t CALLBACK enum_windows_proc_name(HWND hwnd, LPARAM lParam) {
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

static HWND find_window_by_name(wchar_t *name) {
  Window_Data data = {.name = name, .hwnd = NULL};
  EnumWindows(enum_windows_proc_name, (LPARAM)&data);
  return data.hwnd;
}

static int32_t CALLBACK enum_windows_proc_console(HWND hwnd, LPARAM lParam) {
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

static HWND find_window_of_console(void) {
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
#else
typedef struct _XDisplay Display;
typedef unsigned long XID;
typedef XID Window;
typedef XID Drawable;
typedef int Status;
typedef int Bool;
typedef struct _XErrorEvent XErrorEvent;

static_assert(sizeof(Window) == sizeof(HWND), "Changed types");

typedef Display *(*fn_XOpenDisplay)(const char *);
typedef int (*fn_XCloseDisplay)(Display *);
typedef Window (*fn_XDefaultRootWindow)(Display *);
typedef Status (*fn_XQueryTree)(Display *, Window, Window *, Window *, Window **, unsigned int *);
typedef int (*fn_XFetchName)(Display *, Window, char **);
typedef Status (*fn_XGetGeometry)(Display *, Drawable, Window *, int *, int *, unsigned int *, unsigned int *, unsigned int *, unsigned int *);
typedef int (*fn_XMoveResizeWindow)(Display *, Window, int, int, unsigned int, unsigned int);
typedef Bool (*fn_XTranslateCoordinates)(Display *, Window, Window, int, int, int *, int *, Window *);
typedef int (*fn_XSetErrorHandler)(int (*handler)(Display *, XErrorEvent *));
typedef int (*fn_XFlush)(Display *);
typedef int (*fn_XSync)(Display *, Bool);
typedef int (*fn_XFree)(void *);

static void *pxlib;
static Display *pxdisplay;

static fn_XOpenDisplay pXOpenDisplay;
static fn_XCloseDisplay pXCloseDisplay;
static fn_XDefaultRootWindow pXDefaultRootWindow;
static fn_XQueryTree pXQueryTree;
static fn_XFetchName pXFetchName;
static fn_XGetGeometry pXGetGeometry;
static fn_XMoveResizeWindow pXMoveResizeWindow;
static fn_XTranslateCoordinates pXTranslateCoordinates;
static fn_XSetErrorHandler pXSetErrorHandler;
static fn_XFlush pXFlush;
static fn_XSync pXSync;
static fn_XFree pXFree;

static int xerror_handler(Display *d, XErrorEvent *e) {
  (void)d;
  (void)e;
  return 0;
}

#define XLOAD(symbol)                                                      \
  do {                                                                     \
    assert(pxlib);                                                         \
    *(void **)(&p##symbol) = dlsym(pxlib, #symbol);                        \
    if (!p##symbol) {                                                      \
      log_message(LOG_DEBUG, "Failed to load %s: %s", #symbol, dlerror()); \
      return false;                                                        \
    }                                                                      \
  } while (0)

static bool init_xlib(void) {
  if (!(pxlib = dlopen("libX11.so.6", RTLD_LAZY)) &&
      !(pxlib = dlopen("libX11.so", RTLD_LAZY))) {
    log_last_error("Failed to dlopen X11");
    return false;
  }
  XLOAD(XOpenDisplay);
  XLOAD(XCloseDisplay);
  XLOAD(XDefaultRootWindow);
  XLOAD(XQueryTree);
  XLOAD(XFetchName);
  XLOAD(XGetGeometry);
  XLOAD(XMoveResizeWindow);
  XLOAD(XTranslateCoordinates);
  XLOAD(XSetErrorHandler);
  XLOAD(XFlush);
  XLOAD(XSync);
  XLOAD(XFree);
  pxdisplay = pXOpenDisplay(NULL);
  if (!pxdisplay) {
    log_message(LOG_ERROR, "Failed to open default display");
    return false;
  }
  pXSetErrorHandler(xerror_handler);
  return true;
}

#undef XLOAD

static Window find_window_by_name(Display *dsp, Window curr, const char *name) {
  const size_t name_len = strlen(name);
  array_struct(Window) queue = {0};
  array_push(&arena_console, &queue, curr);
  Window result = 0;
  uint32_t i = 0;
  while (i < queue.count) {
    curr = queue.items[i++];
    Window root;
    Window parent;
    Window *children = NULL;
    uint32_t nchildren;
    if (!pXQueryTree(dsp, curr, &root, &parent, &children, &nchildren)) {
      log_last_error("Failed to query X11 window tree");
    } else {
      for (uint32_t j = 0; j < nchildren; ++j) {
        Window child = children[j];
        char *child_name = NULL;
        pXFetchName(dsp, child, &child_name);
        if (child_name) {
          log_message(LOG_TRACE, "Named child window: %s", child_name);
          const bool match = strncmp(child_name, name, name_len) == 0;
          pXFree(child_name);
          if (match) {
            log_message(LOG_DEBUG, "Child window is a match: %s", name);
            array_clear(&queue);
            result = child;
            break;
          }
        }
        array_push(&arena_console, &queue, child);
      }
    }
    if (children) pXFree(children);
  }
  array_free_items(&arena_console, &queue);
  return result;
}
#endif

static bool cin_iswindow(HWND window) {
#ifdef _WIN32
  return IsWindow(window);
#else
  if (!pxlib || !window) return false;
  Window root;
  int x, y;
  unsigned int w, h, bw, d;
  Status status = pXGetGeometry(pxdisplay, window, &root, &x, &y, &w, &h, &bw, &d);
  return status != 0;
#endif
}

static inline bool cin_isvisible(HWND window) {
#ifdef _WIN32
  return IsWindowVisible(window);
#else
  // NOTE: does not check window map state
  return cin_iswindow(window);
#endif
}

static int32_t cin_getwindow(HWND window, RECT *out_rect) {
#ifdef _WIN32
  return GetWindowRect(window, out_rect);
#else
  if (!pxlib || !window) return 0;
  pXSetErrorHandler(xerror_handler);
  Window root;
  int x, y;
  unsigned int w, h, bw, d;
  Status status = pXGetGeometry(pxdisplay, window, &root, &x, &y, &w, &h, &bw, &d);
  if (status) {
    int screen_x, screen_y;
    Window child;
    status = pXTranslateCoordinates(pxdisplay, window, root, 0, 0, &screen_x, &screen_y, &child);
    if (status) {
      out_rect->left = screen_x - (int)bw;
      out_rect->top = screen_y - (int)bw;
      out_rect->right = screen_x + (int)w + (int)bw;
      out_rect->bottom = screen_y + (int)h + (int)bw;
    } else {
      log_message(LOG_ERROR, "Failed to translate window geometry");
    }
  } else {
    log_message(LOG_ERROR, "Failed to get window geometry");
  }
  pXFlush(pxdisplay);
  pXSetErrorHandler(NULL);
  return status;
#endif
}

static int32_t cin_movewindow(HWND window, RECT rect) {
  const int32_t x = (int32_t)rect.left;
  const int32_t y = (int32_t)rect.top;
  const int32_t cx = (int32_t)rect.right;
  const int32_t cy = (int32_t)rect.bottom;
#ifdef _WIN32
  return SetWindowPos(window, HWND_TOPMOST, x, y, cx, cy, SWP_SHOWWINDOW);
#else
  assert(cx >= 0);
  assert(cy >= 0);
  int res = pXMoveResizeWindow(pxdisplay, window, x, y, (uint32_t)cx, (uint32_t)cy);
  pXSync(pxdisplay, false);
  return res;
#endif
}

static inline void playlist_setup_shuffle(Playlist *playlist) {
  const uint32_t n = playlist->count;
  assert(n);
  const uint32_t fy = n - 1;
  array_shuffle_fisher_yates(playlist, int32_t, fy, 1);
  playlist->next_index = 0;
}

static inline void playlist_shuffle(Playlist *playlist) {
  const uint32_t n = playlist->count;
  uint32_t s = 0;
  uint32_t fy = 0;
  if (n > 2) {
    s = n - 1;
    static const uint32_t SATTOLO_FACTOR = 5;
    const uint32_t remainder = s / SATTOLO_FACTOR;
    assert(playlist->targets);
    const uint32_t tail = max(playlist->targets, remainder);
    const uint32_t clamped_tail = min(tail, s);
    const uint32_t diff = s - clamped_tail;
    const uint32_t clamped_diff = max(1, diff);
    fy = s - clamped_diff;
    assert(fy >= 1);
    assert(s > fy);
  }
  array_shuffle_fisher_yates(playlist, int32_t, fy, 1);
  array_shuffle_sattolo(playlist, int32_t, s, fy);
  playlist->next_index = 0;
}

static inline void playlist_set(Instance *instance, Playlist *playlist) {
  Playlist *prev = instance->playlist;
  Playlist *next = playlist;
  ++next->targets;
  instance->playlist = next;
  if (prev) {
    assert(prev->targets > 0);
    --prev->targets;
    const bool prev_empty = prev->targets == 0;
    const bool prev_not_default = prev != &media.default_playlist;
    const bool prev_from_search = !prev->from_tag;
    if (prev_empty && prev_not_default && prev_from_search) {
      assert(prev != next);
      Table_Key key = {.strings = media.search_patterns.items,
                       .pos = prev->search_pos,
                       .len = prev->search_len};
      table_delete(&media.search_table, &key);
      array_free_items(&arena_docs, prev);
      cache_put(&media.playlists, prev);
    }
  }
}

static inline void playlist_set_default(Instance *instance) {
  playlist_set(instance, &media.default_playlist);
}

static bool cin_idle = false;

static inline void playlist_play_core(Instance *instance, const char *arg) {
  if (instance->locked || cin_idle) return;
  assert(instance->playlist);
  Playlist *playlist = instance->playlist;
  const uint32_t index = instance->playlist->next_index;
  char *url = (char *)docs.items + playlist->items[index];
  assert(url);
  assert(*url);
  overlap_write(instance, MPV_LOADFILE, "loadfile", url, arg);
  if (++instance->playlist->next_index == instance->playlist->count) {
    playlist_shuffle(instance->playlist);
  }
}

static inline void playlist_insert(Instance *instance) {
  playlist_play_core(instance, "insert-next");
}

static inline void playlist_play(Instance *instance) {
  if (instance->autoplay_mpv) {
    playlist_insert(instance);
    overlap_write(instance, MPV_WRITE, "playlist-next", NULL, NULL);
  } else {
    playlist_play_core(instance, NULL);
  }
}

#define CIN_MPVKEY_LEFT "\""
#define CIN_MPVKEY_RIGHT "\":"
#define CIN_MPVKEY(str) (CIN_MPVKEY_LEFT str CIN_MPVKEY_RIGHT)
#define CIN_MPVVAL(buf, lit) (strncmp((buf), (lit), cin_strlen((lit))) == 0)
#define CIN_MPVKEY_REQUEST CIN_MPVKEY("request_id")
#define CIN_MPVKEY_EVENT CIN_MPVKEY("event")
#define CIN_MPVKEY_DATA CIN_MPVKEY("data")
#define CIN_MPVKEY_REASON CIN_MPVKEY("reason")

#ifndef _WIN32
static int32_t listener_pipe[2];
static pthread_mutex_t listener_lock = PTHREAD_MUTEX_INITIALIZER;
static array_struct(struct pollfd) listener_pfds = {0};
static array_struct(Instance *) listener_pfds_to_instances = {0};
#endif

static inline void mpv_kill(Instance *instance) {
  assert(instance->playlist);
  --instance->playlist->targets;
#ifndef _WIN32
  close(instance->socket);
#endif
  Read_Buffer *buf_head = instance->buf_head;
  Read_Buffer *buf_tail = instance->buf_tail;
  Instance *next = instance->next;
  memset(instance, 0, sizeof(Instance));
  playlist_set_default(instance);
  instance->buf_head = buf_head;
  instance->buf_tail = buf_tail;
  instance->next = next;
}

static size_t mpv_supply = 0;
static size_t mpv_demand = 0;

static inline void mpv_lock(void) {
  mpv_supply = 0;
  mpv_demand = 0;
#ifdef _WIN32
  LockSetForegroundWindow(LSFW_LOCK);
#endif
}

static inline void mpv_unlock(void) {
#ifdef _WIN32
  LockSetForegroundWindow(LSFW_UNLOCK);
#endif
}

// NOTE: voidtools Everything supports pipe '|' as search separator and '"' for spaces
#define CIN_CLIPBOARD_SEPARATOR '|'
#define CIN_CLIPBOARD_ENCLOSER '"'

static inline void iocp_parse(Instance *instance, const char *buf_start, size_t buf_offset) {
  const char *buf = buf_start + buf_offset;
  char *p = NULL;
  if ((p = (char *)strstr(buf, CIN_MPVKEY_EVENT))) {
    p += cin_strlen(CIN_MPVKEY_EVENT);
    assert(*p == '\"');
    ++p;
    if (CIN_MPVVAL(p, "end-file")) {
      if ((p = strstr(p, CIN_MPVKEY_REASON))) {
        p += cin_strlen(CIN_MPVKEY_REASON);
        assert(*p == '\"');
        ++p;
        if (CIN_MPVVAL(p, "quit")) mpv_kill(instance);
        // NOTE: When a file fails to load, especially with offline twitch streams,
        // the instance becomes idle. We choose to resolve this by trying the next
        // entry in the playlist. Maybe make this an option instead.
        else if (CIN_MPVVAL(p, "error")) playlist_play(instance);
      }
    } else if (CIN_MPVVAL(p, "file-loaded")) {
      if (instance->autoplay_mpv) playlist_insert(instance);
    }
  } else if ((p = (char *)strstr(buf, CIN_MPVKEY_REQUEST))) {
    p += cin_strlen(CIN_MPVKEY_REQUEST);
    assert(cin_isnum(*p));
    int64_t req_id = *p - '0';
    while (cin_isnum(*++p)) req_id = (req_id * 10) + (*p - '0');
    Overlapped_Write *msg = (Overlapped_Write *)(uintptr_t)req_id;
    assert(msg);
    assert(msg->bytes);
    log_message(LOG_DEBUG, "Recovered original write: %p (%zu bytes)", msg, msg->bytes);
    switch (msg->ovl_ctx.type) {
    case MPV_WINDOW_ID: {
      if (++mpv_supply == mpv_demand) mpv_unlock();
      char *data = (char *)strstr(buf, CIN_MPVKEY_DATA);
      if (!data) {
        // NOTE: If the request was delivered before mpv managed to create
        // the window, it will return something like "error: property
        // unavailable": retry.
        static const long GET_WINDOW_DELAY = 200;
        cin_sleep(GET_WINDOW_DELAY);
        overlap_write(instance, MPV_WINDOW_ID, "get_property", "window-id", NULL);
        break;
      }
      assert(data);
      data += cin_strlen(CIN_MPVKEY_DATA);
      assert(cin_isnum(*data));
      intptr_t window_id = 0;
      for (; cin_isnum(*data); ++data) window_id = (window_id * 10) + *data - '0';
      assert(cin_iswindow((HWND)window_id));
      assert(cin_isvisible((HWND)window_id));
      instance->window = (HWND)window_id;
      cin_getwindow(instance->window, &instance->rect);
    } break;
    case MPV_QUIT:
      mpv_kill(instance);
      break;
    case MPV_GET_PATH: {
      char *data = (char *)strstr(buf, CIN_MPVKEY_DATA);
      assert(data);
      data += cin_strlen(CIN_MPVKEY_DATA);
      assert(*data == '"');
      ++data;
      char *tail = strchr(data, '"');
      assert(tail);
      const int32_t len = (int32_t)(tail - data);
      assert(len >= 0);
      array_push(&arena_iocp_thread, &clipboard, CIN_CLIPBOARD_ENCLOSER);
      char prev = '\0';
      for (uint32_t i = 0; i < (uint32_t)len; ++i) {
        const char curr = data[i];
        if (prev != '\\' || curr != '\\') {
          array_push(&arena_iocp_thread, &clipboard, curr);
        }
        prev = curr;
      }
      array_push(&arena_iocp_thread, &clipboard, CIN_CLIPBOARD_ENCLOSER);
      array_push(&arena_iocp_thread, &clipboard, CIN_CLIPBOARD_SEPARATOR);
      if (++clipboard.supply == clipboard.demand) {
        clipboard.supply = 0;
        clipboard.demand = 0;
        if (clipboard.count) clipboard.items[clipboard.count - 1] = '\0';
        cin_write_safe(clipboard.items, clipboard.count - 1);
#ifdef _WIN32
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
#endif
      }
    } break;
    default:
      break;
    }
    cache_put(&cin_io.writes, msg);
  }
}

static inline void iocp_process(Instance *instance, size_t bytes) {
  assert(!memchr(instance->buf_tail->buf, '\0', instance->buf_tail->bytes));
  assert(sizeof(instance->buf_tail->buf) - instance->buf_tail->bytes >= bytes);
  char *lf = memchr(instance->buf_tail->buf + instance->buf_tail->bytes, '\n', bytes);
  instance->buf_tail->bytes += bytes;
  if (lf) {
    bool multi = instance->buf_tail != instance->buf_head;
    assert((lf - instance->buf_tail->buf) >= 0);
    size_t tail_pos = (size_t)(lf - instance->buf_tail->buf);
    char *buf = instance->buf_head->buf;
    size_t len = instance->buf_head->bytes;
    if (multi) {
      for (Read_Buffer *b = instance->buf_head->next; b; b = b->next) {
        assert(!memchr(b->buf, '\0', b->bytes));
        len += b->bytes;
      }
      char *contiguous_buf = arena_bump_T(&arena_iocp_thread, char, (uint32_t)len);
      size_t offset = 0;
      for (Read_Buffer *b = instance->buf_head; b != instance->buf_tail; b = b->next) {
        assert(b);
        memcpy(contiguous_buf + offset, b->buf, b->bytes);
        offset += b->bytes;
        b->bytes = 0;
      }
      memcpy(contiguous_buf + offset, instance->buf_tail, instance->buf_tail->bytes);
      instance->buf_tail->bytes -= tail_pos;
      instance->buf_tail->bytes -= 1;
      tail_pos += offset;
      buf = contiguous_buf;
    }
    size_t buf_offset = 0;
    for (;;) {
      *lf = '\0';
      ++tail_pos;
      log_message(LOG_DEBUG, "Message (%p): %.*s", instance, tail_pos, buf + buf_offset);
      iocp_parse(instance, buf, buf_offset);
      if (tail_pos >= len) break;
      lf = memchr(buf + tail_pos, '\n', len - tail_pos);
      if (!lf) break;
      buf_offset = tail_pos;
      assert((lf - buf) >= 0);
      tail_pos = (size_t)(lf - buf);
    }
    const size_t remainder = tail_pos < len ? len - tail_pos : 0;
    memcpy(instance->buf_head, buf + tail_pos, remainder);
    instance->buf_head->bytes = remainder;
    instance->buf_tail = instance->buf_head;
    if (multi) arena_free_pos(&arena_iocp_thread, (uint8_t *)buf, (uint32_t)len);
  } else {
    if (instance->buf_tail->next) instance->buf_tail->next->bytes = 0;
    else instance->buf_tail->next = arena_bump_T1(&arena_iocp_thread, Read_Buffer);
    instance->buf_tail = instance->buf_tail->next;
  }
}

#ifdef _WIN32
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
#else
static void *mpv_listener(void *arg) {
  (void)arg;
  struct pollfd root_pfd = {.fd = listener_pipe[0], .events = POLLIN};
  array_push(&arena_iocp_thread, &listener_pfds, root_pfd);
  for (;;) {
    const int32_t poll_result = poll(listener_pfds.items, (nfds_t)listener_pfds.count, -1);
    if (poll_result == 0) {
      log_message(LOG_ERROR, "Listener thread timed out polling");
      assert(false);
      break;
    } else if (poll_result < 0) {
      log_last_error("Listener thread failed poll");
      assert(false);
      break;
    }
    if (listener_pfds.items[0].revents & POLLIN) {
      char _val;
      read(listener_pipe[0], &_val, 1);
      pthread_mutex_lock(&listener_lock);
      const uint32_t next_index = listener_pfds.count - 1;
      // main thread has added 1 or more instances
      // map so next poll includes them
      assert(listener_pfds_to_instances.count >= next_index);
      Instance *instance = listener_pfds_to_instances.items[next_index];
      assert(instance);
      assert(instance->socket);
      struct pollfd new_pfd = {.fd = instance->socket, .events = POLLIN};
      array_push(&arena_iocp_thread, &listener_pfds, new_pfd);
      pthread_mutex_unlock(&listener_lock);
    }
    const uint32_t nfds = listener_pfds.count;
    int32_t w = -1;
    for (uint32_t i = 1; i < nfds; ++i) {
      struct pollfd pfd = listener_pfds.items[i];
      Instance *instance = listener_pfds_to_instances.items[i - 1];
      if (instance->socket) {
        if (pfd.revents & POLLIN) {
          char *start = instance->buf_tail->buf + instance->buf_tail->bytes;
          const size_t to_read = sizeof(instance->buf_tail->buf) - instance->buf_tail->bytes;
          const ssize_t bytes = read(pfd.fd, start, to_read);
          if (bytes > 0) {
            iocp_process(instance, (size_t)bytes);
          } else {
            // socket has been terminated, mpv likely closed manually
          }
        }
        if (w >= 0) {
          listener_pfds.items[w] = listener_pfds.items[i];
          listener_pfds_to_instances.items[w - 1] = listener_pfds_to_instances.items[i - 1];
          ++w;
        }
      } else {
        if (w < 0) w = (int32_t)i;
        --listener_pfds.count;
        --listener_pfds_to_instances.count;
      }
    }
  }
  return 0;
}
#endif
static inline bool init_repl(void) {
#ifdef _WIN32
  if (!SetConsoleCP(CP_UTF8)) goto code_page;
  if (!SetConsoleOutputCP(CP_UTF8)) goto code_page;
  if ((repl.in = GetStdHandle(STD_INPUT_HANDLE)) == INVALID_HANDLE_VALUE) goto handle_in;
  if (!GetConsoleMode(repl.in, &repl.in_mode)) goto handle_in;
  DWORD new_in_mode = repl.in_mode;
  new_in_mode &= ~(DWORD)ENABLE_LINE_INPUT;
  new_in_mode &= ~(DWORD)ENABLE_ECHO_INPUT;
  new_in_mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
  if (!SetConsoleMode(repl.in, new_in_mode)) goto handle_in;
  if ((repl.out = GetStdHandle(STD_OUTPUT_HANDLE)) == INVALID_HANDLE_VALUE) goto handle_out;
  if (!GetConsoleMode(repl.out, &repl.out_mode)) goto handle_out;
  DWORD new_out_mode = repl.out_mode;
  new_out_mode |= ENABLE_PROCESSED_OUTPUT;
  new_out_mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  if (!SetConsoleMode(repl.out, new_out_mode)) goto handle_out;
#else
  tcgetattr(STDIN_FILENO, &repl.modes);
  struct termios tmp = repl.modes;
  tmp.c_lflag &= (tcflag_t)~ICANON;
  tmp.c_lflag &= (tcflag_t)~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &tmp);
#endif
  if (!arena_chunk_init(&arena_console, CIN_ARENA_CAP)) goto memory;
  repl.msg = create_console_message();
  repl.msg_index = 0;
  term_get_info(&repl.cursor, &repl.size);
  repl.cursor.X = HOME_X;
  repl.home = repl.cursor;
#ifdef _WIN32
  array_init(&arena_console, &wwrite_buf, CIN_MAX_PATH);
  array_init(&arena_console, &utf16_buf_raw, CIN_MAX_PATH);
  array_init(&arena_console, &utf16_buf_norm, CIN_MAX_PATH);
#endif
  array_init(&arena_console, &write_buf, CIN_MAX_PATH);
  array_init(&arena_console, &preview, CIN_MAX_PATH);
  array_init(&arena_console, &utf8_buf, CIN_MAX_PATH_BYTES);
  cin_swrite(PREFIX_STR);
  return true;
#ifdef _WIN32
code_page:
  cin_swrite("Failed to modify console code page" CRLF);
  return false;
handle_in:
  cin_swrite("Failed to setup console input handle" CRLF);
  return false;
handle_out:
  cin_swrite("Failed to setup console output handle" CRLF);
#endif
memory:
  cin_swrite("Failed to allocate memory for repl/console" CRLF);
  return false;
}

#define COMMAND_NUMBERS_CAP 8
#define COMMAND_ERROR_MESSAGE "ERROR: "
#define COMMAND_ERROR_MESSAGE_LEN cin_strlen(COMMAND_ERROR_MESSAGE)

typedef void (*cmd_validator)(void);
typedef void (*cmd_executor)(void);

array_define(Command_Numbers, size_t);
array_define(Command_Help, char);
array_define(Command_Targets, char);

static struct CommandContext {
  Patricia_Node *trie;
  Cin_Layout *layout;
  Cin_Layout *queued_layout;
  Tag_Items *tag;
  cmd_executor executor;
  Command_Numbers numbers;
  char *unicode;
  Command_Targets targets;
  Command_Help help;
  Cin_Macro *macro;
} cmd_ctx = {0};

static inline void set_preview(bool success, const char *format, ...) {
  array_clear(&preview);
  if (!success) {
    array_extend(&arena_console, &preview, COMMAND_ERROR_MESSAGE, COMMAND_ERROR_MESSAGE_LEN);
  }
  const size_t start = preview.count;
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  const int32_t len_i32 = vsnprintf(NULL, 0, format, args);
  assert(len_i32 >= 0);
  const uint32_t len = (uint32_t)len_i32;
  va_end(args);
  array_grow(&arena_console, &preview, len + 1);
  vsnprintf(preview.items + start, preview.capacity, format, args_dup);
#pragma clang diagnostic pop
  va_end(args_dup);
}

#define CIN_SCREEN_SEPARATOR ", "
#define CIN_SCREEN_SEPARATOR_LEN (sizeof(CIN_SCREEN_SEPARATOR) / sizeof(*CIN_SCREEN_SEPARATOR) - 1)
#define FSTR_CIN_SCREEN "%zu" CIN_SCREEN_SEPARATOR

static inline bool validate_screens(void) {
  const size_t n_count = cmd_ctx.numbers.count;
  const size_t screen_count = cmd_ctx.layout->count;
  if (n_count > screen_count) {
    set_preview(false, "layout only has %zu screens (%zu provided)", screen_count, n_count);
    return false;
  }
  for (size_t i = 0; i < n_count; ++i) {
    const size_t screen_index = cmd_ctx.numbers.items[i] - 1;
    if (screen_index >= screen_count) {
      set_preview(false, "screen %zu not found, layout only has %zu screens",
                  screen_index + 1, screen_count);
      return false;
    }
  }
  array_clear(&cmd_ctx.targets);
  if (!n_count) {
    array_sextend(&arena_console, &cmd_ctx.targets, "(all screens)\0");
    for (size_t i = 0; i < cmd_ctx.layout->count; ++i) {
      array_push(&arena_console, &cmd_ctx.numbers, i + 1);
    }
  } else {
    if (n_count == 1) {
      array_sextend(&arena_console, &cmd_ctx.targets, "(screen ");
    } else {
      array_sextend(&arena_console, &cmd_ctx.targets, "(screens ");
    }
    for (size_t i = 0; i < n_count; ++i) {
      const size_t number = cmd_ctx.numbers.items[i];
      const int32_t len_i32 = snprintf(NULL, 0, FSTR_CIN_SCREEN, number);
      assert(len_i32);
      const uint32_t len = (uint32_t)len_i32 + 1;
      array_reserve(&arena_console, &cmd_ctx.targets, len);
      snprintf(cmd_ctx.targets.items + cmd_ctx.targets.count, len, FSTR_CIN_SCREEN, number);
      cmd_ctx.targets.count += len - 1;
    }
    cmd_ctx.targets.count -= CIN_SCREEN_SEPARATOR_LEN;
    array_push(&arena_console, &cmd_ctx.targets, ')');
    cmd_ctx.targets.items[cmd_ctx.targets.count] = '\0';
  }
  return true;
}

#ifdef _WIN32
static wchar_t exe_path_mpv[CIN_MAX_PATH] = {0};
static wchar_t exe_path_ytdlp[CIN_MAX_PATH] = {0};
static wchar_t exe_path_chatterino[CIN_MAX_PATH] = {0};

static bool find_exe(const wchar_t *dir, const wchar_t *exe, wchar_t *buf) {
  const wchar_t extension[] = L".exe";
  if (SearchPathW(NULL, exe, extension, CIN_MAX_PATH, buf, NULL)) return true;
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
                          L"Please install it in a standard directory or add it to your environment variables.",
               exe);
  wmemset(buf, L'\0', CIN_MAX_PATH);
  return false;
}

static bool init_executables(void) {
  if (!find_exe(L"mpv", L"mpv", exe_path_mpv)) return false;
  if (!find_exe(L"mpv", L"yt-dlp", exe_path_ytdlp)) return false;
  find_exe(L"Chatterino", L"chatterino", exe_path_chatterino);
  return true;
}
#endif

struct Chat {
  RECT rect;
  HWND window;
#ifndef _WIN32
  pid_t pid;
#endif
} chat = {0};

static inline void chat_kill(void) {
#ifdef _WIN32
  PostMessageW(chat.window, WM_CLOSE, 0, 0);
#else
  if (chat.pid) kill(chat.pid, SIGTERM);
#endif
}

static inline size_t chat_spawn(const Cin_Layout *layout) {
#ifdef _WIN32
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
  if (!CreateProcessW(exe_path_chatterino, L"chatterino", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      log_last_error("Failed to find chatterino executable");
    } else {
      log_last_error("Failed to start chatterino executable even though it was found");
    }
  }
  return pi.dwProcessId;
#else
  (void)layout;
  signal(SIGCHLD, SIG_IGN);
  pid_t pid = fork();
  if (pid < 0) {
    log_last_error("Failed to fork process");
    return 0;
  }
  if (pid == 0) {
    FILE *dev_null = fopen("/dev/null", "w");
    dup2(fileno(dev_null), STDOUT_FILENO);
    dup2(fileno(dev_null), STDERR_FILENO);
    fclose(dev_null);
    if (execlp("chatterino", "chatterino", NULL) < 0) {
      log_last_error("Failed to start chatterino");
      exit(1);
    }
    assert(false);
  }
  chat.pid = pid;
  return (size_t)pid;
#endif
}

static inline void chat_reposition(const Cin_Layout *layout) {
  RECT chat_rect = layout->chat_rect;
  const bool should_show = chat_rect.bottom != LONG_MIN;
  const bool is_showing = cin_iswindow(chat.window);
  if (should_show) {
    if (is_showing) {
      cin_movewindow(chat.window, chat_rect);
    } else {
      static const size_t CHAT_REPOSITION_TRIES = 50;
      static const long CHAT_REPOSITION_DELAY = 200;
      const size_t pid = chat_spawn(layout);
      for (size_t i = 0; i < CHAT_REPOSITION_TRIES; ++i) {
#ifdef _WIN32
        chat.window = find_window_by_pid((uint32_t)pid);
#else
        (void)pid;
        Window root = pXDefaultRootWindow(pxdisplay);
        chat.window = find_window_by_name(pxdisplay, root, "Chatterino");
#endif
        if (cin_isvisible(chat.window)) {
          cin_movewindow(chat.window, chat_rect);
          break;
        }
        cin_sleep(CHAT_REPOSITION_DELAY);
      }
    }
  } else if (is_showing) {
    chat_kill();
  }
}

#define CIN_MPVCALL_PIPE_ROOT "cinema_mpv_"
#define CIN_MPVCALL_DIGITS 19
#define CIN_MPVCALL_SERVER_LEN 64
#define CIN_MPVCALL_GEOMETRY_LEN 128

#ifdef _WIN32
#define CIN_MPVCALL_PIPE "\\\\.\\pipe\\" CIN_MPVCALL_PIPE_ROOT
#else
#define CIN_MPVCALL_PIPE "/tmp/" CIN_MPVCALL_PIPE_ROOT
#endif

static void mpv_spawn(Instance *instance, size_t index) {
  char geometry_str[CIN_MPVCALL_GEOMETRY_LEN] = {"--geometry="};
  char server_str[CIN_MPVCALL_SERVER_LEN] = {"--input-ipc-server=" CIN_MPVCALL_PIPE};
  char *mpv_flags[] = {
      "mpv",
      "--idle",
      "--config-dir=./",
      server_str,
      geometry_str,
      NULL};
  static_assert((sizeof(mpv_flags) / CIN_PTR) == 6, "expected 6 elements including sentinel");
  const bool extra = index == SIZE_MAX;
  if (extra) index = cmd_ctx.layout->count;
  char *server_flag = mpv_flags[3];
  assert(strstr(server_flag, "ipc-server") && "check flags");
  const size_t server_buf_len = strlen(server_flag);
  const size_t right = server_buf_len + CIN_MPVCALL_DIGITS;
  size_t left = right;
  size_t j = index;
  do {
    server_flag[left--] = '0' + (j % 10);
    j /= 10;
  } while (j);
  const size_t digits = right - left++;
  const size_t start = server_buf_len;
  for (; j < digits; ++j) server_flag[start + j] = server_flag[left + j];
  Cin_Screen screen = cmd_ctx.layout->items[extra ? 0 : index];
  if (extra) array_push(&arena_console, cmd_ctx.layout, screen);
  // screen.len actually includes null-terminator
  char *screen_utf8 = (char *)screen_strings.items + screen.offset;
  const int32_t len = (int32_t)screen.len;
  if (len > (int32_t)CIN_MPVCALL_GEOMETRY_LEN) {
    char *layout_name = (char *)layout_strings.items + cmd_ctx.layout->name_offset;
    printf("Cinema crashed because the config value of screen %zu in layout '%s' is "
           "too large (%d > %u chars): %.*s (first %u shown)",
           index + 1, layout_name, len, CIN_MPVCALL_GEOMETRY_LEN, CIN_MPVCALL_GEOMETRY_LEN,
           screen_utf8, CIN_MPVCALL_GEOMETRY_LEN);
    exit(1);
  }
  char *geometry_flag = mpv_flags[4];
  assert(strstr(geometry_flag, "geometry") && "check flags");
  const size_t geometry_buf_len = strlen(geometry_flag);
  snprintf(geometry_flag + geometry_buf_len, (size_t)len, "%.*s", len, screen_utf8);
  log_message(LOG_DEBUG, "Spawning instance: %s %s %s %s %s",
              mpv_flags[0], mpv_flags[1], mpv_flags[2], mpv_flags[3], mpv_flags[4]);
  char *socket_name = strchr(server_flag, '=');
  assert(socket_name);
  assert(socket_name + 1);
  ++socket_name;
#ifdef _WIN32
  const int32_t mpv_buf_len = snprintf(NULL, 0, "%s %s %s %s %s",
                                       mpv_flags[0], mpv_flags[1], mpv_flags[2], mpv_flags[3], mpv_flags[4]) +
                              1;
  char mpv_command[mpv_buf_len];
  snprintf(mpv_command, (size_t)mpv_buf_len, "%s %s %s %s %s",
           mpv_flags[0], mpv_flags[1], mpv_flags[2], mpv_flags[3], mpv_flags[4]);
  utf8_to_utf16_raw(mpv_command);
  wchar_t mpv_command_utf16[mpv_buf_len];
  wmemcpy(mpv_command_utf16, utf16_buf_raw.items, (size_t)mpv_buf_len);
  STARTUPINFOW si = {0};
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessW(exe_path_mpv, mpv_command_utf16, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      log_last_error("Failed to find mpv executable");
    } else {
      log_last_error("Failed to start mpv executable even though it was found");
    }
    assert(false);
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
#else
  pid_t pid = fork();
  if (pid < 0) {
    log_last_error("Failed to fork process");
    return;
  }
  if (pid == 0) {
    signal(SIGCHLD, SIG_DFL);
    FILE *dev_null = fopen("/dev/null", "w");
    dup2(fileno(dev_null), STDOUT_FILENO);
    dup2(fileno(dev_null), STDERR_FILENO);
    fclose(dev_null);
    if (execvp(mpv_flags[0], mpv_flags) < 0) {
      log_last_error("Failed to start mpv");
      exit(1);
    }
    assert(0);
  }
  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  assert(strlen(socket_name) <= sizeof(addr.sun_path) - 1);
  strncpy(addr.sun_path, socket_name, sizeof(addr.sun_path) - 1);
  static const size_t MPV_SPAWN_TRIES = 20;
  static const long MPV_SPAWN_DELAY = 100;
  for (size_t i = 0; i < MPV_SPAWN_TRIES; ++i) {
    const int32_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
      log_last_error("Socket creation failed, retrying in %ldms", MPV_SPAWN_DELAY);
    } else if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      log_last_error("Socket connection failed, retrying in %ldms", MPV_SPAWN_DELAY);
      close(fd);
    } else {
      log_message(LOG_DEBUG, "Created socket %d", fd);
      instance->socket = fd;
      instance->buf_head = arena_bump_T1(&arena_io, Read_Buffer);
      instance->buf_tail = instance->buf_head;
      pthread_mutex_lock(&listener_lock);
      array_push(&arena_console, &listener_pfds_to_instances, instance);
      pthread_mutex_unlock(&listener_lock);
      write(listener_pipe[1], "x", 1);
      break;
    }
    cin_sleep(MPV_SPAWN_DELAY);
  }
#endif
  assert(instance->playlist);
  playlist_play(instance);
  overlap_write(instance, MPV_WINDOW_ID, "get_property", "window-id", NULL);
  ++mpv_demand;
}

static inline bool init_mpv(void) {
  arena_chunk_init(&arena_io, CIN_IO_ARENA_CAP);
  arena_chunk_init(&arena_iocp_thread, CIN_IO_ARENA_CAP);
  cache_init_core(&arena_io, &cin_io.writes, 1, true);
  cache_init_core(&arena_io, &cin_io.instances, 1, false);
  cache_init_core(&arena_docs, &media.playlists, 1, true);
  Playlist *default_playlist = &media.default_playlist;
  array_to_pow1(&arena_docs, default_playlist);
  playlist_setup_shuffle(default_playlist);
  Instance *head_instance = cin_io.instances.head;
  playlist_set_default(head_instance);
#ifdef _WIN32
  cin_io.iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (!cin_io.iocp) {
    log_last_error("Failed to create iocp");
    return false;
  }
  if (!CreateThread(NULL, 0, iocp_listener, (LPVOID)cin_io.iocp, 0, NULL)) {
    log_last_error("Failed to create iocp listener");
    return false;
  }
#else
  pipe(interrupt_pipe);
  pipe(listener_pipe);
  if (pthread_create(&listener_thread, NULL, mpv_listener, NULL) != 0) {
    log_last_error("Failed to create listener thread");
    return false;
  }
#endif
  return true;
}

#define mpv_target_foreach(i, instance)                         \
  for (size_t i = 0, _j = 0, _s = cmd_ctx.numbers.items[0] - 1; \
       i < cmd_ctx.numbers.count;                               \
       _j = 0, _s = cmd_ctx.numbers.items[++i] - 1)             \
    for (Instance *instance = cin_io.instances.head;            \
         _j <= _s && instance;                                  \
         instance = instance->next, ++_j)                       \
      if (_j == _s && instance->socket)

static void cmd_help_executor(void) {
  cin_write_safe(cmd_ctx.help.items, (uint32_t)cmd_ctx.help.count);
}

static void cmd_help_validator(void) {
  set_preview(true, "help (show a list of all commands)");
  cmd_ctx.executor = cmd_help_executor;
}

static void cmd_layout_executor(void) {
  Cin_Layout *layout = cmd_ctx.queued_layout;
  cmd_ctx.layout = layout;
  const uint32_t next_count = layout->count;
  uint32_t screen = 0;
  mpv_lock();
  chat_reposition(layout);
  cache_foreach(&cin_io.instances, Instance, i, old) {
    if (screen >= next_count) {
      if (old->socket) overlap_write(old, MPV_QUIT, "quit", NULL, NULL);
    } else if (old->socket) {
      log_message(LOG_INFO, "i=%u, screen=%zu", i);
      assert(cin_iswindow(old->window));
      const char *geometry = (char *)screen_strings.items + layout->items[screen].offset;
      overlap_write(old, MPV_SET_GEOMETRY, "set_property", "geometry", geometry);
      if (old->full_screen) {
        old->full_screen = false;
        overlap_write(old, MPV_WRITE, "set_property", "fullscreen", "no");
      }
    } else {
      mpv_spawn(old, screen);
    }
    ++screen;
  }
  for (Instance *next = NULL; screen < next_count; ++screen) {
    cache_get(&arena_io, &cin_io.instances, next);
    playlist_set_default(next);
    mpv_spawn(next, screen);
  }
  if (!mpv_demand) mpv_unlock();
}

static void cmd_layout_validator(void) {
  radix_v layout = NULL;
  const uint8_t *layout_name = NULL;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    layout = radix_query(layout_tree, (uint8_t *)cmd_ctx.unicode, len, &layout_name);
    if (!layout) {
      set_preview(false, "layout does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
    assert(layout);
    assert(layout_name);
    set_preview(true, "change layout to '%s'", (char *)layout_name);
  } else {
    Cin_Layout *curr = cmd_ctx.layout;
    char *curr_name = (char *)layout_strings.items + curr->name_offset;
    set_preview(true, "reset layout '%s'", curr_name);
    layout = curr;
  }
  cmd_ctx.queued_layout = (Cin_Layout *)layout;
  cmd_ctx.executor = cmd_layout_executor;
}

static void cmd_reroll_executor(void) {
  size_t count = 0;
  mpv_target_foreach(i, instance) {
    playlist_play(instance);
    ++count;
  }
  if (count == 0) {
    cmd_ctx.queued_layout = cmd_ctx.layout;
    cmd_layout_executor();
  }
}

static void cmd_reroll_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "reroll %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_reroll_executor;
}

static cmd_validator parse_command(const char *command) {
  // Grammar rules:
  // 1. First character must be either empty or in 'a'..'z' (letter) or in '1'..'9' (digit)
  // 2. Empty (whitespace*\0) is a command
  // 3. Letter must precede one of: 'letter', 'space', '\0';
  // 3a. 'letter' concatenates a string character
  // 3b. 'space' finishes the string to setup (possible) command 'letter+'
  // 3c. '\0' is (possibly) a command comprised of 'letter+'
  // 4. Digit must precede one of: 'digit', '\0', 'space', 'letter'.
  // 4a. 'digit' concatenates a decimal number
  // 4b. '\0' is a command: consumes the number (array)
  // 4c. 'space' pushes decimal number onto the numbers array
  // 4d. 'letter' finishes the number array for command 'letter+' consumption
  // 5. Command 'letter+' with 'space' (3b) may precede 'unicode*'
  // 5a. 'unicode*' string is finished with '\0'
  cmd_ctx.executor = NULL;
  array_clear(&cmd_ctx.numbers);
  cmd_ctx.unicode = NULL;
  const char *p = command;
  while (isspace(*p)) ++p;
  size_t number = 0;
  for (; *p; ++p) {
    if (cin_isnum_1based(*p)) {
      // 4a. build decimal number
      number *= 10;
      number += (size_t)(*p - '0');
    } else if (*p == ' ') {
      if (number) {
        // 4c. push decimal number onto array
        array_push(&arena_console, &cmd_ctx.numbers, number);
      }
      number = 0;
    } else if (cin_isloweralpha(*p)) {
      // if numbers array empty and number, push
      if (number) {
        array_push(&arena_console, &cmd_ctx.numbers, number);
        number = 0;
      }
      break;
    } else {
      const intptr_t pos = p - command;
      assert(pos >= 0);
      set_preview(false, "unexpected character '%c' at position %zd,"
                         " expected: alphanumeric, space, enter",
                  *p, pos + 1);
      return NULL;
    }
  }
  if (!*p) {
    // 2/4b. command
    if (number) {
      array_push(&arena_console, &cmd_ctx.numbers, number);
    }
    return cmd_reroll_validator;
  }
  const char *start = p;
  ++p;
  while (cin_isloweralpha(*p)) ++p;
  // 3/3a. letter+, command begins at start, ends at p
  if (!*p) {
    // 3c. possible command
    cmd_validator validator = patricia_query(cmd_ctx.trie, start);
    if (!validator) {
      set_preview(false, "'%s' is not a valid command", start);
    }
    return validator;
  }
  if (*p != ' ') {
    const intptr_t pos = p - command;
    assert(pos >= 0);
    set_preview(false, "unexpected character '%c' at position %zd,"
                       " expected: letter, space, enter",
                *p, pos + 1);
    return NULL;
  }
  // temporarily null-terminate
  *(char *)p = '\0';
  cmd_validator validator = patricia_query(cmd_ctx.trie, start);
  if (!validator) {
    set_preview(false, "'%s' is not a valid command", start);
  }
  *(char *)p = ' ';
  ++p;
  // 5a. unicode starts at p ends at \0
  cmd_ctx.unicode = (char *)p;
  return validator;
}

static void update_preview(void) {
  array_reserve(&arena_console, repl.msg, 1);
  repl.msg->items[repl.msg->count] = '\0';
  cmd_validator validator_fn = parse_command(repl.msg->items);
  if (validator_fn) {
    validator_fn();
  }
}

static void cmd_tag_executor(void) {
  if (cmd_ctx.tag->playlist) goto reroll;
  cache_get_zero(&arena_docs, &media.playlists, cmd_ctx.tag->playlist);
  Playlist *playlist = cmd_ctx.tag->playlist;
  playlist->from_tag = true;
  size_t directory_k = 0;
  size_t pattern_k = 0;
  size_t url_k = 0;
  Arena *arena1 = &arena_console;
  Arena *arena2 = &arena_docs;
  Arena *arena3 = &arena_io;
#ifdef CIN_OPENMP
#pragma omp parallel
#pragma omp single
#endif
  {
    if (cmd_ctx.tag->directories) {
#ifdef CIN_OPENMP
#pragma omp task priority(8)
#endif
      {
        Tag_Directories *directories = cmd_ctx.tag->directories;
        directory_k = deduplicate_i32(arena1, directories->items, directories->count);
        Robin_Hood_Table duplicates = {0};
        table_init(arena1, &duplicates, CIN_DIRECTORIES_CAP);
        uint8_t *strings = directory_strings.items;
        for (size_t i = 0; i < directory_k; ++i) {
          size_t node_index = (size_t)directories->items[i];
          assert(node_index < directory_nodes.count);
          Directory_Node *start = &directory_nodes.items[node_index];
          table_key_t *start_str = directory_strings.items + start->str_offset;
          const size_t start_len = strlen((char *)start_str);
          Table_Key key = {.strings = strings, .pos = start->str_offset, .len = (table_key_len)start_len + 1};
          table_value dup = table_insert(arena1, &duplicates, &key, 0);
          if (dup >= 0) continue;
          log_message(LOG_TRACE, "Tag directory: %s (%zu)", start_str, start_len);
          array_extend(arena1, playlist, start->items, start->count);
          for (size_t j = ++node_index; j < directory_nodes.count; ++j) {
            Directory_Node *node = &directory_nodes.items[j];
            if (!node->count) continue;
            table_key_t *str = directory_strings.items + node->str_offset;
            if (strncmp((char *)str, (char *)start_str, start_len) != 0) break;
            const size_t len = strlen((char *)str);
            key.pos = node->str_offset;
            key.len = (table_key_len)len + 1;
            dup = table_insert(arena1, &duplicates, &key, 0);
            if (dup >= 0) continue;
            log_message(LOG_TRACE, "Tag directory: %s", str);
            array_extend(arena1, playlist, node->items, node->count);
          }
        }
        table_free_items(arena1, &duplicates);
      }
    }
    if (cmd_ctx.tag->pattern_items) {
#ifdef CIN_OPENMP
#pragma omp task priority(4)
#endif
      {
        Tag_Pattern_Items *patterns = cmd_ctx.tag->pattern_items;
        pattern_k = deduplicate_i32(arena2, patterns->items, patterns->count);
      }
    }
    if (cmd_ctx.tag->url_items) {
#ifdef CIN_OPENMP
#pragma omp task priority(2)
#endif
      {
        Tag_Url_Items *urls = cmd_ctx.tag->url_items;
        url_k = deduplicate_i32(arena3, urls->items, urls->count);
      }
    }
#ifdef CIN_OPENMP
#pragma omp taskwait
#endif
  }
  if (directory_k) {
    array_free(&arena_console, cmd_ctx.tag->directories);
    cmd_ctx.tag->directories = NULL;
  }
  if (pattern_k) {
    array_extend(&arena_console, playlist, cmd_ctx.tag->pattern_items->items, (uint32_t)pattern_k);
    array_free(&arena_console, cmd_ctx.tag->pattern_items);
    cmd_ctx.tag->pattern_items = NULL;
  }
  if (url_k) {
    array_extend(&arena_console, playlist, cmd_ctx.tag->url_items->items, (uint32_t)url_k);
    array_free(&arena_console, cmd_ctx.tag->url_items);
    cmd_ctx.tag->url_items = NULL;
  }
  if (playlist->count > 0) {
    array_to_pow1(&arena_docs, playlist);
    playlist_setup_shuffle(playlist);
  } else {
    playlist->empty = true;
    log_message(LOG_INFO, "Tag is empty");
  }
reroll:
  if (!cmd_ctx.tag->playlist->empty) {
    mpv_target_foreach(i, instance) {
      playlist_set(instance, cmd_ctx.tag->playlist);
      playlist_play(instance);
    }
  }
}

static void cmd_tag_validator(void) {
  if (!validate_screens()) return;
  radix_v tag = NULL;
  const uint8_t *tag_name = NULL;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    tag = radix_query(tag_tree, (uint8_t *)cmd_ctx.unicode, len, &tag_name);
    if (!tag) {
      set_preview(false, "tag does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
  } else {
    tag = radix_query(tag_tree, (const uint8_t *)"", 0, &tag_name);
    if (!tag) {
      set_preview(false, "configuration does not contain any tags");
      return;
    }
  }
  assert(tag);
  assert(tag_name);
  set_preview(true, "tag '%s' %s", (char *)tag_name, cmd_ctx.targets.items);
  cmd_ctx.tag = (Tag_Items *)tag;
  cmd_ctx.executor = cmd_tag_executor;
}

static void cmd_search_executor(void) {
  Playlist *playlist = &media.default_playlist;
  int32_t len = 0;
  if (cmd_ctx.unicode && (len = (int32_t)strlen(cmd_ctx.unicode))) {
#ifdef _WIN32
    setup_file_path_char(cmd_ctx.unicode, &len);
#endif
    ++len; // null-terminator
    uint8_t *pattern = (uint8_t *)cmd_ctx.unicode;
    const table_key_len len_u32 = (table_key_len)len;
    log_message(LOG_DEBUG, "Search with pattern: '%s', len: %d", pattern, len);
    array_reserve(&arena_docs, &media.search_patterns, len_u32);
    table_key_t *strings = media.search_patterns.items;
    const table_key_pos pos = media.search_patterns.count;
    memcpy(strings + pos, pattern, len_u32);
    Table_Key key = {.strings = strings, .pos = pos, .len = len_u32};
    cache_get_zero(&arena_docs, &media.playlists, playlist);
    table_value value = (table_value)playlist;
    table_value result = table_insert(&arena_docs, &media.search_table, &key, value);
    if (result != -1) {
      assert(result);
      cache_put(&media.playlists, playlist);
      playlist = (Playlist *)result;
      log_message(LOG_DEBUG, "Searched for cached pattern");
      if (playlist->empty) {
        log_message(LOG_DEBUG, "Cached pattern is empty, using default playlist");
        return;
      }
    } else {
      playlist->search_pos = pos;
      playlist->search_len = len_u32;
      playlist->from_tag = false;
      media.search_patterns.count += len_u32;
      document_listing(pattern, len - 1, playlist);
      if (!playlist->count) {
        log_message(LOG_INFO, "No results for search query: %s", pattern);
        playlist->empty = true;
        return;
      }
      playlist_setup_shuffle(playlist);
    }
    log_message(LOG_INFO, "Search playlist count=%d, cap=%d", playlist->count, playlist->capacity);
  }
  mpv_target_foreach(i, instance) {
    playlist_set(instance, playlist);
    playlist_play(instance);
  }
}

static void cmd_search_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "search '%s' %s", cmd_ctx.unicode ? cmd_ctx.unicode : "", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_search_executor;
}

static void cmd_hide_executor(void) {
  if (!cmd_ctx.unicode) return;
  const size_t len = strlen(cmd_ctx.unicode) + 1;
  uint8_t *pattern = (uint8_t *)cmd_ctx.unicode;
  if (len <= 1) return;
  const uint32_t len_u32 = (uint32_t)len;
  array_reserve(&arena_docs, &media.search_patterns, len_u32);
  table_key_t *strings = media.search_patterns.items;
  const table_key_pos pos = media.search_patterns.count;
  memcpy(strings + pos, pattern, len_u32);
  Table_Key key = {.strings = strings, .pos = pos, .len = len_u32};
  table_value value = table_find(&media.search_table, &key);
  Playlist tmp_playlist = {0};
  if (value != -1) {
    assert(value);
    tmp_playlist = *(Playlist *)value;
  } else {
    document_listing(pattern, (int32_t)len - 1, &tmp_playlist);
  }
  assert(&tmp_playlist);
  Hidden_Table *table = &media.hidden_table;
  uint32_t hash_n = 1;
  while (hash_n < (table->count + (&tmp_playlist)->count) * 2) hash_n <<= 1;
  const uint32_t start = table->capacity;
  array_ensure_capacity_core(&arena_docs, table, hash_n, true);
  const uint32_t end = table->capacity;
  const uint64_t mask = table->capacity - 1;
  if (start < end) {
    for (uint32_t i = start; i < end; ++i) table->items[i] = -1;
    for (uint32_t i = 0; i < start; ++i) {
      const int32_t v = table->items[i];
      if (v >= 0) {
        table->items[i] = -1;
        const uint64_t hash = (uint64_t)v * CIN_INTEGER_HASH;
        uint64_t index = hash & mask;
        while (table->items[index] >= 0) index = (index + 1) & mask;
        table->items[index] = v;
      }
    }
  }
  array_foreach(&tmp_playlist, int32_t, i, doc) {
    const uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
    uint64_t index = hash & mask;
    while (table->items[index] >= 0) {
      if (table->items[index] == doc) goto next;
      index = (index + 1) & mask;
    }
    table->items[index] = doc;
    ++table->count;
  next:;
  }
  if (value < 0) array_free_items(&arena_docs, &tmp_playlist);
  Playlist prev_default = media.default_playlist;
  Playlist new_default = {0};
  array_copy_shallow(&arena_docs, &new_default, &prev_default);
  array_foreach(&prev_default, int32_t, i, doc) {
    const uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
    uint64_t index = hash & mask;
    while (table->items[index] >= 0) {
      if (table->items[index] == doc) goto skip;
      index = (index + 1) & mask;
    }
    array_push(&arena_docs, &new_default, doc);
  skip:;
  }
  if (!new_default.count) {
    log_message(LOG_WARNING, "Original playlist restored since every item was hidden");
    const int32_t d_bytes = (int32_t)array_bytes(&docs);
    array_ensure_capacity_core(&arena_docs, &new_default, (uint32_t)docs.doc_count, false);
    for (int32_t i = 0, offset = 0; i < d_bytes; ++i) {
      if (docs.items[i] == '\0') {
        const uint32_t playlist_pos = (&new_default)->count++;
        (&new_default)->items[playlist_pos] = offset;
        offset = i + 1;
      }
    }
    array_clear(&media.search_patterns);
    memset(table->items, -1, table->bytes_capacity);
    array_clear(table);
    memset(media.search_table.items, 0, media.search_table.bytes_capacity);
    array_clear(&media.search_table);
  }
  array_to_pow1(&arena_docs, &new_default);
  media.default_playlist = new_default;
  playlist_setup_shuffle(&media.default_playlist);
  arena_free_pos(&arena_docs, (uint8_t *)prev_default.items, prev_default.bytes_capacity);
  cache_foreach(&cin_io.instances, Instance, i, o) {
    if (o->playlist && !o->playlist->from_tag) {
      playlist_set_default(o);
      if (o->socket) playlist_play(o);
    }
  }
}

static void cmd_hide_validator(void) {
  if (cmd_ctx.unicode && *cmd_ctx.unicode) {
    set_preview(true, "hide '%s'", cmd_ctx.unicode);
  } else {
    set_preview(true, "hide '' (nothing)");
  }
  cmd_ctx.executor = cmd_hide_executor;
}

static void cmd_idle_executor(void) {
  cin_idle = !cin_idle;
}

static void cmd_idle_validator(void) {
  set_preview(true, cin_idle ? "allow commands to play media" : "set screens to idle");
  cmd_ctx.executor = cmd_idle_executor;
}

static void cmd_kill_executor(void) {
  chat_kill();
  mpv_target_foreach(i, instance) {
    log_message(LOG_DEBUG, "Closing Window=%lu", instance->window);
    overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
  }
}

static void cmd_kill_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "kill  %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_kill_executor;
}

static void cmd_maximize_executor(void) {
  const size_t target = cmd_ctx.numbers.count ? cmd_ctx.numbers.items[0] - 1 : 0;
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    if (instance->socket) {
      if (i == target) {
        instance->full_screen = !instance->full_screen;
        overlap_write(instance, MPV_WRITE, "cycle", "fullscreen", NULL);
      } else {
        overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
      }
    }
  }
}

static void cmd_maximize_validator(void) {
  const size_t n = cmd_ctx.numbers.count;
  if (n > 1) {
    set_preview(false, "maximize supports 1 screen, not %zu", n);
    return;
  }
  size_t screen = 1;
  if (n) {
    const size_t target = cmd_ctx.numbers.items[0];
    if (target > cmd_ctx.layout->count) {
      set_preview(false, "cannot maximize screen %zu, layout only has %zu screens",
                  target, cmd_ctx.layout->count);
      return;
    }
    screen = target;
  }
  set_preview(true, "maximize screen %zu", screen);
  cmd_ctx.executor = cmd_maximize_executor;
}

static void cmd_mute_executor(void) {
  mpv_target_foreach(i, instance) {
    overlap_write(instance, MPV_WRITE, "cycle", "mute", NULL);
  }
}

static void cmd_mute_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "mute/unmute %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_mute_executor;
}

static void cmd_autoplay_executor(void) {
  const char *duration = cmd_ctx.unicode;
  char *p = cmd_ctx.unicode;
  int64_t seconds = -1;
  if (p && cin_isnum(*p)) {
    seconds = *p - '0';
    ++p;
    while (cin_isnum(*p)) {
      seconds *= 10;
      seconds += *p - '0';
      ++p;
    }
    if (*p) *p = '\0';
  }
  if (seconds > 0) {
    mpv_target_foreach(i, instance) {
      if (!instance->autoplay_mpv) {
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "no");
        instance->autoplay_mpv = true;
      }
      overlap_write(instance, MPV_WRITE, "set_property", "length", duration);
      overlap_write(instance, MPV_WRITE, "set_property", "image-display-duration", duration);
      playlist_insert(instance);
    }
  } else if (seconds == 0) {
    mpv_target_foreach(i, instance) {
      if (instance->autoplay_mpv) {
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
        overlap_write(instance, MPV_WRITE, "set_property", "length", "none");
      }
      instance->autoplay_mpv = false;
    }
  } else {
    mpv_target_foreach(i, instance) {
      if (!instance->autoplay_mpv) {
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "no");
        instance->autoplay_mpv = true;
      } else {
        overlap_write(instance, MPV_WRITE, "set_property", "length", "none");
      }
      // NOTE: default=5 https://mpv.io/manual/stable/#options-image-display-duration
      overlap_write(instance, MPV_WRITE, "set_property", "image-display-duration", "5");
      playlist_insert(instance);
    }
  }
}

static void cmd_autoplay_validator(void) {
  if (!validate_screens()) return;
  int64_t seconds = -1;
  if (cmd_ctx.unicode) {
    char *p = cmd_ctx.unicode;
    if (cin_isnum(*p)) {
      seconds = *p - '0';
      ++p;
    }
    while (cin_isnum(*p)) {
      seconds *= 10;
      seconds += *p - '0';
      ++p;
    }
    if (*p) {
      const ptrdiff_t pos = p - cmd_ctx.unicode;
      set_preview(false, "unexpected character '%c' at position %lld in argument", *p, pos + 1);
      return;
    }
  }
  if (seconds < 0) set_preview(true, "autoplay when media ends %s", cmd_ctx.targets.items);
  else if (seconds == 0) set_preview(true, "turn off autoplay %s", cmd_ctx.targets.items);
  else set_preview(true, "autoplay with '%lld' second delay %s", seconds, cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_autoplay_executor;
}

static void cmd_lock_executor(void) {
  mpv_target_foreach(i, instance) {
    instance->locked = !instance->locked;
    if (!instance->locked) playlist_play(instance);
    if (instance->autoplay_mpv) overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
    instance->autoplay_mpv = false;
  }
}

static void cmd_lock_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "lock/unlock %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_lock_executor;
}

#define CIN_CONF_FILENAME "cinema.conf"

#define FSTR_RECT "%ldx%ld%+ld%+ld"
#define FSTR_NAME "name = %s" CRLF
#define FSTR_SCREEN "screen = %s" CRLF
#define FSTR_CHAT "chat = " FSTR_RECT CRLF
#define FSTR_RECT_ARGS(rect) \
  ((rect).right - (rect).left), ((rect).bottom - (rect).top), ((rect).left), ((rect).top)
#define FSTR_CHAT_ARGS FSTR_RECT_ARGS(chat.rect)

static void cmd_store_executor(void) {
  Cin_Layout *layout = cmd_ctx.queued_layout;
  char *name = NULL;
  const bool try_overwrite = layout != NULL;
  if (try_overwrite) {
    array_clear(layout);
    name = (char *)layout_strings.items + layout->name_offset;
  } else {
    layout = arena_bump_T1(&arena_console, Cin_Layout);
    assert(cmd_ctx.unicode);
    name = cmd_ctx.unicode;
    setup_layout(name, layout);
  }
  cmd_ctx.layout = layout;
  array_clear(&geometry_buf);
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    if (instance->socket && cin_iswindow(instance->window)) {
      cin_getwindow(instance->window, &instance->rect);
      const int32_t bytes = snprintf(NULL, 0, FSTR_RECT, FSTR_RECT_ARGS(instance->rect)) + 1;
      assert(bytes > 1);
      const uint32_t bytes_u32 = (uint32_t)bytes;
      const uint32_t offset = geometry_buf.count;
      array_grow(&arena_console, &geometry_buf, bytes_u32);
      char *pos = geometry_buf.items + offset;
      snprintf(pos, bytes_u32, FSTR_RECT, FSTR_RECT_ARGS(instance->rect));
      setup_screen(pos, layout);
      assert(geometry_buf.items[geometry_buf.count - 1] == '\0');
      geometry_buf.items[geometry_buf.count - 1] = ',';
    }
  }
  if (geometry_buf.count > 0) geometry_buf.items[--geometry_buf.count] = '\0';
  char *buf = NULL;
  uint32_t buf_bytes = 0;
  const bool has_chat = cin_iswindow(chat.window);
  if (has_chat) {
    cin_getwindow(chat.window, &chat.rect);
    layout->chat_rect = chat.rect;
  }
  if (!try_overwrite) goto append;
  int32_t scope_line = layout->scope_line;
  const uint32_t name_len = layout->name_len - 1;
  FILE *file = fopen(CIN_CONF_FILENAME, "rb");
  if (!file) {
    log_last_error("Failed to open file '%s'", CIN_CONF_FILENAME);
  } else {
    fseek(file, 0, SEEK_END);
    assert(ftell(file) > 0);
    buf_bytes = (uint32_t)ftell(file);
    rewind(file);
    buf = arena_bump_T(&arena_console, char, buf_bytes + 1U);
    fread(buf, sizeof(char), buf_bytes, file);
    fclose(file);
    buf[buf_bytes] = '\0';
    const char *p = buf;
    const char *tail = buf + buf_bytes;
    int32_t bottom_line = 1;
    while (bottom_line < scope_line && (p = memchr(p, '\n', (size_t)(tail - p)))) {
      ++p;
      ++bottom_line;
    }
    if (!p || strncmp(p, "[layout]", cin_strlen("[layout]")) != 0) goto append;
    p += cin_strlen("[layout]");
    const char *overwrite_start = p;
    const char *overwrite_end = overwrite_start;
    const char *last_name = NULL;
    int32_t line_breaks = 0;
    while ((p = memchr(p, '\n', (size_t)(tail - p)))) {
      ++line_breaks;
      overwrite_end = ++p;
      if (*p == '[') break;
      if (strncmp(p, "name", cin_strlen("name")) == 0) last_name = p;
    }
    if (!last_name) goto append;
    last_name += cin_strlen("name");
    while (*last_name == ' ') ++last_name;
    if (*last_name != '=') goto append;
    else ++last_name;
    while (*last_name == ' ') ++last_name;
    if (strncmp(last_name, name, name_len) != 0) goto append;
    size_t available_bytes = (size_t)(overwrite_end - overwrite_start);
    size_t needed_chat_bytes = 0;
    char *overwrite = (char *)overwrite_start;
    const int32_t name_bytes = sprintf(overwrite, CRLF FSTR_NAME, name);
    overwrite += (size_t)name_bytes;
    available_bytes -= (size_t)name_bytes;
    if (has_chat) {
      const int32_t bytes = snprintf(NULL, 0, FSTR_CHAT, FSTR_CHAT_ARGS);
      assert(bytes > 0);
      const size_t bytes_size = (size_t)bytes;
      if (bytes_size > available_bytes) {
        needed_chat_bytes = bytes_size;
      } else {
        snprintf(overwrite, bytes_size + 1U, FSTR_CHAT, FSTR_CHAT_ARGS);
        overwrite += bytes_size;
        available_bytes -= bytes_size;
      }
    }
    const int32_t screen_bytes = snprintf(NULL, 0, FSTR_SCREEN CRLF, geometry_buf.items);
    assert(screen_bytes > 0);
    const size_t screen_bytes_size = (size_t)screen_bytes;
    if (needed_chat_bytes || screen_bytes_size > available_bytes) {
      const size_t needed_bytes = needed_chat_bytes + screen_bytes_size;
      const size_t growth_bytes = needed_bytes - available_bytes;
      const size_t new_buf_bytes = buf_bytes + growth_bytes;
      const size_t overwrite_pos = (size_t)(overwrite - buf);
      const char *prev_buf = buf;
      buf = arena_bump_T(&arena_console, char, (uint32_t)new_buf_bytes + 1U);
      memcpy(buf, prev_buf, overwrite_pos);
      const size_t new_overwrite_end = overwrite_pos + screen_bytes_size;
      const size_t leftover_bytes = (size_t)(tail - overwrite_end);
      memcpy(buf + new_overwrite_end, overwrite_end, leftover_bytes);
      arena_free_pos(&arena_console, (uint8_t *)prev_buf, buf_bytes);
      available_bytes += growth_bytes;
      overwrite = buf + overwrite_pos;
      overwrite_end = buf + new_overwrite_end;
      tail = buf + new_buf_bytes;
      buf_bytes = (uint32_t)new_buf_bytes;
    }
    if (needed_chat_bytes) {
      snprintf(overwrite, needed_chat_bytes + 1U, FSTR_CHAT, FSTR_CHAT_ARGS);
      overwrite += needed_chat_bytes;
      available_bytes -= needed_chat_bytes;
    }
    available_bytes -= screen_bytes_size;
    if (available_bytes) {
      snprintf(overwrite, screen_bytes_size + 1U, FSTR_SCREEN CRLF, geometry_buf.items);
      overwrite += screen_bytes_size;
      const size_t end_bytes = (size_t)(tail - overwrite_end);
      memmove(overwrite, overwrite_end, end_bytes);
      tail -= available_bytes;
    } else {
      snprintf(overwrite, screen_bytes_size + 1U, FSTR_SCREEN CR, geometry_buf.items);
      overwrite += screen_bytes_size - 1U;
      assert(*overwrite == '\0');
      *overwrite++ = '\n';
    }
    const size_t used_bytes = (size_t)(tail - buf);
    file = fopen(CIN_CONF_FILENAME, "wb");
    if (!file) {
      log_last_error("Failed to open file '%s'", CIN_CONF_FILENAME);
    } else {
      fwrite(buf, 1, used_bytes, file);
      fclose(file);
    }
    arena_free_pos(&arena_console, (uint8_t *)buf, buf_bytes);
    const int32_t written_lines = has_chat ? 5 : 4;
    const int32_t line_shift = written_lines - line_breaks;
    if (line_shift) {
      Radix_Leaf *next = radix_leftmost(layout_tree->root);
      while (next) {
        Cin_Layout *next_layout = (Cin_Layout *)next->base.v;
        if (next_layout->scope_line > scope_line) {
          next_layout->scope_line += line_shift;
        }
        next = radix_next(layout_tree, next);
      }
    }
    return;
  }
append:
  if (buf) arena_free_pos(&arena_console, (uint8_t *)buf, buf_bytes + 1U);
  scope_line = 2;
  file = fopen(CIN_CONF_FILENAME, "ab+");
  if (!file) {
    log_last_error("Failed to open file '%s'", CIN_CONF_FILENAME);
  } else {
    rewind(file);
    int32_t c;
    while ((c = fgetc(file)) != EOF)
      if (c == '\n') ++scope_line;
    fseek(file, 0, SEEK_END);
    layout->scope_line = scope_line;
    fprintf(file, CRLF "[layout]" CRLF);
    fprintf(file, FSTR_NAME, name);
    fprintf(file, FSTR_SCREEN, geometry_buf.items);
    if (has_chat) fprintf(file, FSTR_CHAT, FSTR_CHAT_ARGS);
    fclose(file);
  }
  return;
}

static void cmd_store_validator(void) {
  radix_v layout = NULL;
  const uint8_t *layout_name = NULL;
  (void)cmd_ctx.unicode;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    layout = radix_query(layout_tree, (uint8_t *)cmd_ctx.unicode, len, &layout_name);
    if (layout) {
      assert(layout);
      assert(layout_name);
      set_preview(true, "store layout '%s' (overwrite)", (char *)layout_name);
    } else {
      set_preview(true, "store new layout: '%s'", cmd_ctx.unicode);
    }
  } else {
    Cin_Layout *curr = cmd_ctx.layout;
    char *curr_name = (char *)layout_strings.items + curr->name_offset;
    set_preview(true, "store layout '%s' (overwrite current)", curr_name);
    layout = curr;
  }
  cmd_ctx.queued_layout = (Cin_Layout *)layout;
  cmd_ctx.executor = cmd_store_executor;
}

static void cmd_swap_executor(void) {
  const size_t first = cmd_ctx.numbers.items[0] - 1;
  const size_t second = cmd_ctx.numbers.items[1] - 1;
  log_message(LOG_DEBUG, "Swapping screen %zu with %zu", first, second);
  Cin_Screen *first_screen = NULL;
  Cin_Screen *second_screen = NULL;
  Instance *first_instance = NULL;
  Instance *second_instance = NULL;
  mpv_target_foreach(i, instance) {
    if (i == 0) {
      first_instance = instance;
      first_screen = &cmd_ctx.layout->items[first];
    } else {
      assert(i == 1);
      second_instance = instance;
      second_screen = &cmd_ctx.layout->items[second];
    }
  }
  if (first_screen && second_screen) {
    const char *first_geometry = (char *)screen_strings.items + first_screen->offset;
    const char *second_geometry = (char *)screen_strings.items + second_screen->offset;
    overlap_write(first_instance, MPV_SET_GEOMETRY, "set_property", "geometry", second_geometry);
    overlap_write(second_instance, MPV_SET_GEOMETRY, "set_property", "geometry", first_geometry);
    Cin_Screen tmp = *second_screen;
    *second_screen = *first_screen;
    *first_screen = tmp;
  }
}

static void cmd_swap_validator(void) {
  const size_t n = cmd_ctx.numbers.count;
  const size_t screen_count = cmd_ctx.layout->count;
  if (screen_count < 2) {
    set_preview(false, "swap requires a layout with at least 2 screens");
    return;
  }
  switch (n) {
  case 2: {
    const size_t first = cmd_ctx.numbers.items[0];
    const size_t second = cmd_ctx.numbers.items[1];
    if (first == second) {
      set_preview(false, "swap needs 2 unique screens, not both %zu", first);
      return;
    }
    if (first > screen_count || second > screen_count) {
      set_preview(false, "cannot swap screen %zu with %zu, layout only has %zu screens",
                  first, second, screen_count);
      return;
    }
  } break;
  case 1:
    set_preview(false, "swap misses another number: %zu ... swap", cmd_ctx.numbers.items[0]);
    return;
  case 0: {
    if (cmd_ctx.layout->count != 2) {
      set_preview(false, "swap requires 2 numbers or a layout with 2 screens");
      return;
    }
    array_push(&arena_console, &cmd_ctx.numbers, 1);
    array_push(&arena_console, &cmd_ctx.numbers, 2);
  } break;
  default:
    set_preview(false, "swap must have 2 or 0 numbers, not %zu", n);
    return;
  }
  cmd_ctx.executor = cmd_swap_executor;
  set_preview(true, "swap screen %zu with %zu", cmd_ctx.numbers.items[0], cmd_ctx.numbers.items[1]);
}

static void cmd_clear_executor(void) {
  mpv_target_foreach(i, instance) {
    playlist_set_default(instance);
    playlist_play(instance);
  }
}

static void cmd_clear_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "clear %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_clear_executor;
}

static void cmd_macro_executor(void) {
  Cin_Macro *macro = cmd_ctx.macro;
  if (macro) {
    const char *p = macro->items;
    const char *tail = macro->items + macro->count - 1;
    do {
      cmd_ctx.executor = NULL;
      cmd_validator validator_fn = parse_command(p);
      if (validator_fn) {
        validator_fn();
        if (cmd_ctx.executor) {
          cmd_ctx.executor();
        } else {
          log_message(LOG_ERROR, "Failed to validate macro command '%s': %s", p, preview.items);
          return;
        }
      } else {
        log_message(LOG_ERROR, "Failed to parse macro command '%s': %s", p, preview.items);
        return;
      }
    } while ((p = memchr(p, '\0', (size_t)(tail - p))) && *++p);
  }
}

static void cmd_macro_validator(void) {
  radix_v macro = NULL;
  const uint8_t *macro_name = NULL;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    macro = radix_query(macro_tree, (uint8_t *)cmd_ctx.unicode, len, &macro_name);
    if (!macro) {
      set_preview(false, "macro does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
    assert(macro);
    assert(macro_name);
    set_preview(true, "execute macro '%s'", (char *)macro_name);
  } else {
    set_preview(true, "execute macro '' (nothing)");
  }
  cmd_ctx.macro = (Cin_Macro *)macro;
  cmd_ctx.executor = cmd_macro_executor;
}

#define TWITCH_CHANNEL_MAX_CHARS 25
#define TWITCH_PREFIX "https://www.twitch.tv/"
#define TWITCH_BUF_SIZE (cin_strlen(TWITCH_PREFIX) + TWITCH_CHANNEL_MAX_CHARS + 1)

static void cmd_twitch_executor(void) {
  if (!cmd_ctx.unicode || cin_idle) return;
  static char twitch_buf[TWITCH_BUF_SIZE] = {TWITCH_PREFIX};
  const size_t len = strlen(cmd_ctx.unicode) + 1;
  const char *channel = (const char *)cmd_ctx.unicode;
  memcpy(twitch_buf + cin_strlen(TWITCH_PREFIX), channel, len);
  mpv_target_foreach(i, instance) {
    overlap_write(instance, MPV_LOADFILE, "loadfile", twitch_buf, NULL);
  }
}

static void cmd_twitch_validator(void) {
  if (!validate_screens()) return;
  if (cmd_ctx.unicode && strlen(cmd_ctx.unicode) > TWITCH_CHANNEL_MAX_CHARS) {
    set_preview(false, "twitch channel name is too long (max is %d characters)", TWITCH_CHANNEL_MAX_CHARS);
    return;
  }
  set_preview(true, "" TWITCH_PREFIX "%s %s", cmd_ctx.unicode ? cmd_ctx.unicode : "", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_twitch_executor;
}

static void cmd_copy_executor(void) {
  array_clear(&clipboard);
  clipboard.supply = 0;
  clipboard.demand = 0;
  mpv_target_foreach(i, instance) {
    ++clipboard.demand;
    overlap_write(instance, MPV_GET_PATH, "get_property", "path", NULL);
  }
  return;
}

static void cmd_copy_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "copy to clipboard %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_copy_executor;
}

static void cmd_extra_executor(void) {
  bool reuse = false;
  mpv_lock();
  cache_foreach(&cin_io.instances, Instance, i, old) {
    if (!old->socket) {
      // reuse if free instance available
      reuse = true;
      mpv_spawn(old, SIZE_MAX);
    }
  }
  if (!reuse) {
    Instance *extra = NULL;
    cache_get(&arena_io, &cin_io.instances, extra);
    playlist_set_default(extra);
    mpv_spawn(extra, SIZE_MAX);
  }
}

static void cmd_extra_validator(void) {
  set_preview(true, "add extra screen to layout");
  cmd_ctx.executor = cmd_extra_executor;
}

static void cmd_chat_executor(void) {
  Cin_Layout *layout = cmd_ctx.layout;
  const bool layout_chat = layout->chat_rect.bottom != LONG_MIN;
  if (!layout_chat) {
    const int32_t default_width = 400;
    const int32_t default_height = 600;
    const int32_t default_x = 0;
    const int32_t default_y = 0;
    layout->chat_rect.right = default_width;
    layout->chat_rect.bottom = default_height;
    layout->chat_rect.left = default_x;
    layout->chat_rect.top = default_y;
  }
  mpv_lock();
  chat_reposition(layout);
  mpv_unlock();
}

static void cmd_chat_validator(void) {
  const bool is_showing = cin_iswindow(chat.window);
  set_preview(true, "%s chat", is_showing ? "reposition" : "show");
  cmd_ctx.executor = cmd_chat_executor;
}

#define CIN_LIST_TAGS_PREFIX CR "Tags: "
#define CIN_LIST_TAGS_PREFIX_LEN cin_strlen(CIN_LIST_TAGS_PREFIX)

static void cmd_list_executor(void) {
  Radix_Leaf *next = radix_leftmost(tag_tree->root);
  array_struct(char) output = {0};
  array_set(&arena_console, &output, CIN_LIST_TAGS_PREFIX, CIN_LIST_TAGS_PREFIX_LEN);
  const size_t start_count = output.count;
  while (next) {
    assert(next->len);
    const char *key = (char *)next->key;
    const uint32_t len = (uint32_t)next->len - 1U;
    array_extend(&arena_console, &output, key, len);
    array_push(&arena_console, &output, ',');
    array_push(&arena_console, &output, ' ');
    next = radix_next(tag_tree, next);
  }
  if (output.count > start_count) {
    array_pop(&output);
    output.items[output.count - 1] = '\0';
  }
  assert(output.count);
  cin_write_safe(output.items, (uint32_t)output.count);
  array_free_items(&arena_console, &output);
}

static void cmd_list_validator(void) {
  set_preview(true, "list all tags");
  cmd_ctx.executor = cmd_list_executor;
}

static void cmd_quit_executor(void) {
  chat_kill();
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    log_message(LOG_DEBUG, "Closing Window=%lu", instance->window);
    overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
  }
  clear_preview(0);
  cursor_curr();
  show_cursor();
#ifdef _WIN32
  SetConsoleMode(repl.in, repl.in_mode);
  SetConsoleMode(repl.out, repl.out_mode);
#else
  tcsetattr(STDIN_FILENO, TCSANOW, &repl.modes);
  if (pxlib) {
    if (pxdisplay) {
      pXCloseDisplay(pxdisplay);
    }
    dlclose(pxlib);
  }
#endif
  exit(1);
}

static void cmd_quit_validator(void) {
  set_preview(true, "quit (also closes screens)");
  cmd_ctx.executor = cmd_quit_executor;
}

#define FSTR_CMD CRLF "  %-10s %s"

static inline void register_cmd(const char *name, const char *help, cmd_validator validator) {
  patricia_insert(&arena_console, cmd_ctx.trie, name, validator);
  const int32_t len_i32 = snprintf(NULL, 0, FSTR_CMD, name, help);
  assert(len_i32);
  const uint32_t len = (uint32_t)len_i32 + 1;
  array_reserve(&arena_console, &cmd_ctx.help, len);
  snprintf(cmd_ctx.help.items + cmd_ctx.help.count, len, FSTR_CMD, name, help);
  cmd_ctx.help.count += len - 1;
}

static bool init_commands(void) {
  radix_v layout_v = radix_query(layout_tree, (const uint8_t *)"", 0, NULL);
  if (!layout_v) {
    log_message(LOG_ERROR, "No layouts found in config file");
    return false;
  }
  cmd_ctx.layout = (Cin_Layout *)layout_v;
  cmd_ctx.queued_layout = cmd_ctx.layout;
  cmd_ctx.trie = patricia_node(&arena_console, NULL, 0);
  array_init(&arena_console, &cmd_ctx.numbers, COMMAND_NUMBERS_CAP);
  const char *commands_note = CR "Available commands:" CRLF "  "
                                 "Note: optional arguments before/after in brackets []" CRLF;
  const uint32_t commands_note_len = (uint32_t)strlen(commands_note);
  array_extend(&arena_console, &cmd_ctx.help, commands_note, commands_note_len);
  register_cmd("autoplay", "Autoplay media [(1 2 ..) autoplay (seconds)]", cmd_autoplay_validator);
  register_cmd("chat", "Show chat (see store command)", cmd_chat_validator);
  register_cmd("clear", "Clear tag/term [(1 2 ..) clear]", cmd_clear_validator);
  register_cmd("copy", "Copy url(s) to clipboard [(1 2 ..) copy]", cmd_copy_validator);
  register_cmd("extra", "Adds an extra screen (see store command)", cmd_extra_validator);
  register_cmd("help", "Show all commands", cmd_help_validator);
  register_cmd("hide", "Hide media with term [hide term]", cmd_hide_validator);
  register_cmd("idle", "Make commands (not) play media [idle]", cmd_idle_validator);
  register_cmd("kill", "Kill screen(s) and chat [(1 2 ..) kill]", cmd_kill_validator);
  register_cmd("layout", "Change layout to name [layout (name)]", cmd_layout_validator);
  register_cmd("list", "Show all tags", cmd_list_validator);
  register_cmd("lock", "Lock/unlock screen contents [(1 2 ..) lock]", cmd_lock_validator);
  register_cmd("macro", "Execute macro [macro (name)]", cmd_macro_validator);
  register_cmd("maximize", "Maximize and close others [(1) maximize]", cmd_maximize_validator);
  register_cmd("mute", "Mute screen(s) [(1 2 ..) mute]", cmd_mute_validator);
  register_cmd("quit", "Close screens and quit Cinema", cmd_quit_validator);
  register_cmd("reroll", "Shuffle media [(1 2 ..) (reroll)]", cmd_reroll_validator);
  register_cmd("search", "Limit media to term [(1 2 ..) search (term)]", cmd_search_validator);
  register_cmd("store", "Store layout in cinema.conf [store (layout)]", cmd_store_validator);
  register_cmd("swap", "Swap screen contents [(1 2) swap]", cmd_swap_validator);
  register_cmd("tag", "Limit media to tag [(1 2 ..) tag (name)]", cmd_tag_validator);
  register_cmd("twitch", "Show channel [(1 2 ..) twitch (channel)]", cmd_twitch_validator);
  return true;
}

static void execute_startup_macros(void) {
  array_foreach(&startup_macros, Cin_Macro *, i, macro) {
    cmd_ctx.macro = macro;
    cmd_macro_executor();
  }
  array_clear(&cmd_ctx.numbers);
  cmd_reroll_validator();
  set_preview(true, "press enter to shuffle (h for help)");
  set_preview_row(repl.home.Y + 1);
  log_preview();
}

static inline int32_t term_read(uint8_t *buf, const int32_t n, bool peek) {
  int32_t chars_read = 0;
  assert(n > 0);
#ifdef _WIN32
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
#else
  struct pollfd pfds[2] = {{.fd = STDIN_FILENO, .events = POLLIN},
                           {.fd = interrupt_pipe[0], .events = POLLIN}};
  if (!peek) {
    for (;;) {
      if (repl.in_buf.count) {
        chars_read = min((int32_t)repl.in_buf.count, n);
        memcpy(buf, repl.in_buf.items, (size_t)chars_read);
        if ((int32_t)repl.in_buf.count > chars_read) {
          size_t in_buf_remainder = repl.in_buf.count - (uint32_t)chars_read;
          memmove(repl.in_buf.items, repl.in_buf.items + chars_read, in_buf_remainder);
        }
        repl.in_buf.count -= (uint32_t)chars_read;
        break;
      }
      const int32_t poll_result = poll(pfds, 2, -1);
      if (poll_result <= 0) {
        log_last_error("Failed to peek");
        break;
      }
      if (pfds[1].revents & POLLIN) {
        term_get_cursor(&repl.cursor);
        interrupt_finish();
      }
      if (pfds[0].revents & POLLIN) {
        chars_read = (int32_t)read(STDIN_FILENO, buf, (size_t)n);
        if (chars_read < 0) log_last_error("Failed to read %d from terminal", n);
        break;
      }
    }
  } else {
    int32_t i = 0;
    bool interrupt = false;
    while (i < n) {
      const int32_t poll_result = poll(pfds, 2, TERM_READ_WAIT_MS);
      if (poll_result == 0) break;
      if (poll_result < 0) {
        log_last_error("Failed to peek");
        break;
      }
      if (pfds[1].revents & POLLIN) interrupt = true;
      if (pfds[0].revents & POLLIN && read(pfds[0].fd, buf + i, 1) > 0) {
        ++chars_read;
        ++i;
      } else {
        log_last_error("Failed to read peek");
        break;
      }
    }
    if (interrupt) {
      term_get_cursor(&repl.cursor);
      interrupt_finish();
    }
  }
#endif
  return chars_read;
}

static bool term_proc_sequence(const uint8_t *sequence, int32_t len) {
  assert(len >= 0);
  bool new_preview = true;
  log_message(LOG_TRACE, "Terminal sequence (len %d): %.*s", len, len, sequence);
  if (len == 0) {
    // ESC
    clear_full();
    repl.msg_index = 0;
    array_clear(repl.msg);
  } else {
    int32_t i = 0;
    if (sequence[i] == TERM_LBRACKET) {
      if (++i == len) goto fail;
      switch (sequence[i]) {
      case TERM_HOME:
        if (++i != len) goto fail;
        cursor_home();
        repl.msg_index = 0;
        new_preview = false;
        break;
      case TERM_END:
        if (++i != len) goto fail;
        repl.msg_index = repl.msg->count;
        cursor_curr();
        new_preview = false;
        break;
      case TERM_DELETE: {
        if (++i == len) goto fail;
        if (repl.msg_index == repl.msg->count) {
          new_preview = false;
          break;
        }
        bool control = sequence[i] == TERM_SEMICOLON;
        if (control) i += 2;
        if (sequence[i] != TERM_TILDE) goto fail;
        if (++i != len) goto fail;
        uint32_t right = repl.msg_index;
        if (control) {
          while (right < repl.msg->count && repl.msg->items[right] != TERM_SPACE) ++right;
          while (right < repl.msg->count && repl.msg->items[++right] == TERM_SPACE) {
          }
        } else {
          ++right;
        }
        const uint32_t leftover = repl.msg->count - right;
        const uint32_t deleted = right - repl.msg_index;
        repl.msg->count -= deleted;
        if (leftover) {
          memmove(&repl.msg->items[repl.msg_index], &repl.msg->items[right], leftover);
          cin_write(repl.msg->items + repl.msg_index, leftover);
          clear_tail(deleted, false);
        } else {
          clear_tail(deleted, true);
        }
        cursor_curr();
      } break;
      case TERM_UP: {
        if (++i != len) goto fail;
        if (!repl.msg->prev) {
          new_preview = false;
          break;
        }
        const uint32_t prev_count = repl.msg->count;
        array_resize(&arena_console, repl.msg, repl.msg->prev->count);
        memcpy(repl.msg->items, repl.msg->prev->items, repl.msg->prev->count);
        repl.msg_index = repl.msg->count;
        repl.msg->next = repl.msg->prev->next;
        repl.msg->prev = repl.msg->prev->prev;
        cursor_home();
        cin_write(repl.msg->items, repl.msg->count);
        if (repl.msg->count < prev_count) {
          const uint32_t to_clear = prev_count - repl.msg->count;
          clear_tail(to_clear, false);
        }
      } break;
      case TERM_DOWN: {
        if (++i != len) goto fail;
        if (repl.msg->next) {
          const uint32_t prev_count = repl.msg->count;
          Console_Message *next = repl.msg->next;
          array_resize(&arena_console, repl.msg, next->count);
          memcpy(repl.msg->items, next->items, next->count);
          repl.msg->prev = next->prev;
          repl.msg->next = next->next;
          repl.msg_index = repl.msg->count;
          cursor_home();
          cin_write(repl.msg->items, repl.msg->count);
          if (repl.msg->count < prev_count) {
            const uint32_t to_clear = prev_count - repl.msg->count;
            clear_tail(to_clear, false);
          }
        } else {
          clear_full();
          repl.msg->prev = repl.msg_tail;
          array_clear(repl.msg);
          repl.msg_index = 0;
        }
      } break;
      case TERM_PAGEUP: {
        if (++i == len || sequence[i] != TERM_TILDE || ++i != len) goto fail;
        if (!repl.msg->prev) {
          new_preview = false;
          break;
        }
        Console_Message *head = repl.msg->prev;
        while (head->prev) head = head->prev;
        const uint32_t prev_count = repl.msg->count;
        array_resize(&arena_console, repl.msg, head->count);
        memcpy(repl.msg->items, head->items, head->count);
        repl.msg_index = repl.msg->count;
        repl.msg->next = head->next;
        cursor_home();
        cin_write(repl.msg->items, repl.msg->count);
        if (repl.msg->count < prev_count) {
          const uint32_t to_clear = prev_count - repl.msg->count;
          clear_tail(to_clear, false);
        }
      } break;
      case TERM_PAGEDOWN: {
        if (++i == len || sequence[i] != TERM_TILDE || ++i != len) goto fail;
        if (repl.msg_tail) {
          const uint32_t prev_count = repl.msg->count;
          Console_Message *next = repl.msg_tail;
          array_resize(&arena_console, repl.msg, next->count);
          memcpy(repl.msg->items, next->items, next->count);
          repl.msg->prev = next->prev;
          repl.msg->next = next->next;
          repl.msg_index = repl.msg->count;
          cursor_home();
          cin_write(repl.msg->items, repl.msg->count);
          if (repl.msg->count < prev_count) {
            const uint32_t to_clear = prev_count - repl.msg->count;
            clear_tail(to_clear, false);
          }
        } else {
          clear_full();
          array_clear(repl.msg);
          repl.msg_index = 0;
        }
      } break;
      case TERM_LEFT:
        if (++i != len) goto fail;
        if (repl.msg_index) {
          --repl.msg_index;
          cursor_curr();
        }
        new_preview = false;
        break;
      case TERM_RIGHT:
        if (++i != len) goto fail;
        if (repl.msg_index < repl.msg->count) {
          ++repl.msg_index;
          cursor_curr();
        }
        new_preview = false;
        break;
      case TERM_DEFAULT:
        // handle possible control arrow keys
        if (++i == len || sequence[i] != TERM_SEMICOLON ||
            ++i == len || sequence[i] != TERM_PAGEUP ||
            ++i + 1 != len) goto fail;
        if (sequence[i] == TERM_LEFT) {
          if (repl.msg_index) {
            --repl.msg_index;
            while (repl.msg_index && repl.msg->items[repl.msg_index] == TERM_SPACE) --repl.msg_index;
            while (repl.msg_index && repl.msg->items[repl.msg_index - 1] != TERM_SPACE) --repl.msg_index;
            cursor_curr();
          }
          new_preview = false;
        } else if (sequence[i] == TERM_RIGHT) {
          if (repl.msg_index < repl.msg->count) {
            while (repl.msg_index < repl.msg->count && repl.msg->items[repl.msg_index] != TERM_SPACE) ++repl.msg_index;
            while (repl.msg_index < repl.msg->count && repl.msg->items[++repl.msg_index] == TERM_SPACE) {
            }
            cursor_curr();
          }
          new_preview = false;
        } else {
          goto fail;
        }
        break;
      default:
        goto fail;
        break;
      }
    }
  }
  return new_preview;
fail:
  new_preview = false;
  log_message(LOG_DEBUG, "Terminal sequence incomplete or not supported: %.*s",
              len, (char *)sequence);
  return new_preview;
}

static bool term_proc_unicode(const uint8_t *unicode, int32_t len) {
  assert(len > 0);
  log_message(LOG_DEBUG, "Unicode input (len %d): %.*s", len, len, unicode);
  if (len == 1) {
    log_message(LOG_ERROR, "Failed to parse unicode");
    return false;
  }
  if (len == 3 && !memcmp(unicode, TERM_REPLACEMENT, 3)) {
    log_message(LOG_ERROR, "This unicode character is not supported");
    return false;
  }
  const uint32_t len_u32 = (uint32_t)len;
  array_splice(&arena_console, repl.msg, repl.msg_index, unicode, len_u32);
  cin_write(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
  repl.msg_index += len_u32;
  return true;
}

static bool term_proc_char(char byte) {
  assert(byte);
  log_message(LOG_TRACE, "Char input: %02hhx", byte);
  bool new_preview = true;
  switch (byte) {
  case TERM_TAB:
  case TERM_LINEFEED:
  case TERM_RETURN: {
    clear_full();
    assert(repl.msg->items);
    uint32_t i = repl.msg->count;
    while (i && isspace(repl.msg->items[i - 1])) --i;
    const bool empty = !i;
    const bool dup = !empty && repl.msg_tail && repl.msg->count == repl.msg_tail->count &&
                     !strncmp(repl.msg->items, repl.msg_tail->items, repl.msg->count);
    if (empty || dup) {
      if (repl.msg_tail) repl.msg->prev = repl.msg_tail;
      repl.msg->next = NULL;
      repl.msg_index = 0;
      array_clear(repl.msg);
    } else {
      // commit to history
      if (repl.msg_tail) {
        repl.msg_tail->next = repl.msg;
        repl.msg->prev = repl.msg_tail;
      }
      repl.msg->next = NULL;
      repl.msg_tail = repl.msg;
      repl.msg = create_console_message();
      repl.msg->prev = repl.msg_tail;
      repl.msg_index = 0;
      array_clear(repl.msg);
    }
    if (cmd_ctx.executor) {
      cmd_ctx.executor();
    }
  } break;
  case TERM_BACK_CTRL:
  case TERM_BACK: {
    if (!repl.msg_index) {
      new_preview = false;
      break;
    }
    uint32_t left = repl.msg_index - 1;
    if (byte == TERM_BACK_CTRL) {
      while (left && repl.msg->items[left] == TERM_SPACE) --left;
      while (left && repl.msg->items[left - 1] != TERM_SPACE) --left;
    }
    if (repl.msg_index < repl.msg->count) {
      memmove(&repl.msg->items[left], &repl.msg->items[repl.msg_index], repl.msg->count - repl.msg_index);
    }
    const uint32_t deleted = repl.msg_index - left;
    repl.msg->count -= deleted;
    repl.msg_index = left;
    const uint32_t leftover = repl.msg->count - repl.msg_index;
    const COORD curr = curr_cursor();
    term_set_cursor(curr);
    if (leftover) {
      cin_write(repl.msg->items + repl.msg_index, leftover);
      const COORD new_curr = index_to_cursor_repl(repl.msg_index + leftover);
      term_clear(new_curr, deleted, false, false);
      term_set_cursor(curr);
    } else {
      term_clear(curr, deleted, false, false);
    }
  } break;
  default:
    if (!byte) {
      new_preview = false;
      break;
    }
    byte = cin_lower(byte);
    array_insert(&arena_console, repl.msg, repl.msg_index, byte);
    cin_write(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
    ++repl.msg_index;
    if (repl.msg_index != repl.msg->count) cursor_curr();
    break;
  }
  return new_preview;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  if (!init_os()) exit(1);
  if (!init_repl()) exit(1);
#ifdef _WIN32
  if (!InitializeCriticalSectionAndSpinCount(&log_lock, 0)) exit(1);
#endif
  if (!init_config(CIN_CONF_FILENAME)) exit(1);
  if (!init_commands()) exit(1);
#ifdef _WIN32
  if (!init_executables()) exit(1);
// on linux we run the exes without searching
#endif
  if (!init_documents()) exit(1);
  if (!init_mpv()) exit(1);
#ifndef _WIN32
  if (!init_xlib()) pxlib = NULL;
#endif
  execute_startup_macros();
  for (;;) {
    show_cursor();
    uint8_t byte;
    if (!term_read(&byte, 1, false)) {
      break;
    }
    hide_cursor();
    const COORD size_change = term_get_size(&repl.size);
    if (size_change.X) {
      lock_logs();
      term_get_cursor(&repl.cursor);
      const uint32_t curr_index = cursor_to_index(repl.cursor, (uint32_t)repl.size.X);
      const uint32_t i = curr_index > repl.msg_index ? curr_index - repl.msg_index : curr_index;
      const short new_home_y = index_y(i, (uint32_t)repl.size.X);
      repl.home.Y = new_home_y;
      unlock_logs();
    } else if (size_change.Y < 0) {
      repl.home.Y = min(repl.home.Y, repl.size.Y - 1);
    }
    bool new_preview = true;
    if (byte == TERM_ESC) {
      uint8_t term_sequence[TERM_SEQUENCE_MAX];
      const int32_t len = term_read(term_sequence, sizeof(term_sequence), true);
      new_preview = term_proc_sequence(term_sequence, len);
    } else if ((byte & 0x80) != 0) {
      int32_t bytes = 1;
      if ((byte & 0xE0) == 0xC0) bytes = 2;
      else if ((byte & 0xF0) == 0xE0) bytes = 3;
      else if ((byte & 0xF8) == 0xF0) bytes = 4;
      uint8_t unicode[4] = {byte};
      const int32_t len = term_read(unicode + 1, bytes - 1, false);
      new_preview = term_proc_unicode(unicode, len + 1);
    } else {
      new_preview = term_proc_char((char)byte);
    }
    if (!new_preview) continue;
    short tail_row = index_y_repl(repl.msg->count);
    tail_row = min(tail_row, repl.size.Y);
    const short preview_row = min(tail_row + 1, repl.size.Y);
    const short preview_shift = preview_row - preview.pos.Y;
    if (tail_row == repl.size.Y) {
      const short tail_col = index_x_repl(repl.msg->count);
      if (tail_col != 0) {
        // clear preview and make space for new line
        const short leftover = (short)preview.len - tail_col;
        term_set_cursor((COORD){.X = tail_col, .Y = tail_row});
        cin_writef(CSI "%hdX\n", leftover);
        --repl.home.Y;
      }
      cursor_curr();
    } else if (preview_shift < 0) {
      // went up preview_shift rows
      clear_preview(0);
      cursor_curr();
    } else if (preview_shift == 1) {
      // went down 1 row
      const short preview_col = index_x_repl(repl.msg->count);
      if ((short)preview.len > preview_col) {
        clear_preview(preview_col);
      }
    }
    const uint32_t prev_len = preview.len;
    set_preview_row(preview_row);
    update_preview();
    log_preview();
    if (preview_shift == 0 && prev_len > preview.len) {
      const uint32_t leftover = prev_len - preview.len;
      const COORD clear_pos = {.X = (short)preview.len, .Y = preview_row};
      term_clear(clear_pos, leftover, true, false);
      cursor_curr();
    }
  }
  return 0;
}
