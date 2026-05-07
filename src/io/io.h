#ifndef CIN_IO_H
#define CIN_IO_H

#ifdef _WIN32
#include <Windows.h>
#endif

#include "base/cache.h"
#include "base/core.h"
#include "config.h"

extern Arena arena_io;
extern Arena arena_iocp_thread;

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

extern struct Cin_IO {
  Write_Cache writes;
  Instance_Cache instances;
#ifdef _WIN32
  HANDLE iocp;
#endif
} cin_io;

#ifdef _WIN32
bool create_pipe(Instance *instance, const wchar_t *name);
bool overlap_read(Instance *instance);
#endif

#define CIN_WRITE_CMD_LEFT "{async:true,request_id:%" PRId64 ",command:[\"%s\""
#define CIN_WRITE_CMD_MID ",\"%s\""
#define CIN_WRITE_CMD_RIGHT "]}\n"
#define CIN_WRITE_CMD_0ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_RIGHT)
#define CIN_WRITE_CMD_1ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_MID CIN_WRITE_CMD_RIGHT)
#define CIN_WRITE_CMD_2ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_MID CIN_WRITE_CMD_MID CIN_WRITE_CMD_RIGHT)

bool internal_write(Instance *instance, Overlapped_Write *msg, int32_t bytes);
bool overlap_write(Instance *instance, MPV_Packet type, const char *cmd, const char *arg1, const char *arg2);

#endif