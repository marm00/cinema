#ifndef CIN_IO_H
#define CIN_IO_H

#include <inttypes.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "base/cache.h"
#include "base/core.h"
#include "config/config.h"

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

extern bool cin_idle;

void playlist_setup_shuffle(Playlist *playlist);
void playlist_shuffle(Playlist *playlist);
void playlist_set(Instance *instance, Playlist *playlist);
void playlist_set_default(Instance *instance);
void playlist_play_core(Instance *instance, const char *arg);
void playlist_insert(Instance *instance);
void playlist_play(Instance *instance);

#define CIN_MPVKEY_LEFT "\""
#define CIN_MPVKEY_RIGHT "\":"
#define CIN_MPVKEY(str) (CIN_MPVKEY_LEFT str CIN_MPVKEY_RIGHT)
#define CIN_MPVVAL(buf, lit) (strncmp((buf), (lit), cin_strlen((lit))) == 0)

extern size_t mpv_supply;
extern size_t mpv_demand;

void mpv_kill(Instance *instance);
void mpv_lock(void);
void mpv_unlock(void);

// NOTE: voidtools Everything supports pipe '|' as search separator and '"' for spaces
#define CIN_CLIPBOARD_SEPARATOR '|'
#define CIN_CLIPBOARD_ENCLOSER '"'

void copy_clipboard(void);

void iocp_parse(Instance *instance, const char *buf_start, size_t buf_offset);
void iocp_process(Instance *instance, size_t bytes);
bool iocp_start(void);

#define CIN_MPVCALL_PIPE_ROOT "cinema_mpv_"
#define CIN_MPVCALL_DIGITS 19
#define CIN_MPVCALL_GEOMETRY_LEN 128
#define CIN_MPVCALL_SERVER_LEN 64
#define CIN_MPVCALL_YTDLP_BASE_LEN 35
#define CIN_MPVCALL_YTDLP_PATH_LEN CIN_MAX_PATH_BYTES
#define CIN_MPVCALL_YTDLP_LEN (CIN_MPVCALL_YTDLP_BASE_LEN + CIN_MPVCALL_YTDLP_PATH_LEN)

#ifdef _WIN32
#define CIN_MPVCALL_PIPE "\\\\.\\pipe\\" CIN_MPVCALL_PIPE_ROOT
#else
#define CIN_MPVCALL_PIPE "/tmp/" CIN_MPVCALL_PIPE_ROOT
#endif

bool init_mpv(void);
void mpv_spawn_internal(Instance *instance, char *mpv_flags[], char *socket_name);
void mpv_spawn(Instance *instance, size_t index);

extern struct Chat {
  RECT rect;
  HWND window;
#ifndef _WIN32
  pid_t pid;
#endif
} chat;

void chat_kill(void);
size_t chat_spawn(const Cin_Layout *layout);
HWND chat_get_window(size_t pid, char *name);
void chat_reposition(const Cin_Layout *layout);

#define TERM_ESC 0x1b
#define TERM_LBRACKET 0x5b
#define TERM_HOME 0x48
#define TERM_END 0x46
#define TERM_DELETE 0x33
#define TERM_TILDE 0x7e
#define TERM_SEMICOLON 0x3b
#define TERM_UP 0x41
#define TERM_DOWN 0x42
#define TERM_PAGEUP 0x35
#define TERM_PAGEDOWN 0x36
#define TERM_LEFT 0x44
#define TERM_RIGHT 0x43
#define TERM_DEFAULT 0x31
#define TERM_TAB 0x09
#define TERM_RETURN 0x0d
#define TERM_LINEFEED 0x0a
#define TERM_BACK 0x7f
#define TERM_BACK_CTRL 0x08
#define TERM_SPACE 0x20
#define TERM_CURSOR_POS 0x52
#define TERM_REPLACEMENT "\xEF\xBF\xBD"
#define TERM_SEQUENCE_MAX 8
#define TERM_READ_WAIT_MS 5

int32_t term_read(uint8_t *buf, const int32_t n, bool peek);
bool term_proc_sequence(const uint8_t *sequence, int32_t len);
bool term_proc_unicode(const uint8_t *unicode, int32_t len);
bool term_proc_char(char byte);

#endif