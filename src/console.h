#ifndef CIN_CONSOLE_H
#define CIN_CONSOLE_H

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#include <assert.h>
#include <limits.h>
#include <stdint.h>

#include "arena.h"
#include "array.h"

extern Arena arena_console;
array_define(UTF8_Buffer, uint8_t);
array_define(UTF8_Buffer_Char, char);
extern UTF8_Buffer utf8_buf;
extern UTF8_Buffer_Char write_buf;

typedef struct Console_Message {
  array_struct_members(char);
  struct Console_Message *prev;
  struct Console_Message *next;
} Console_Message;

static inline Console_Message *create_console_message(void) {
  Console_Message *msg = arena_bump_T1(&arena_console, Console_Message);
  assert(msg);
  array_init(&arena_console, msg, 64);
  msg->next = NULL;
  msg->prev = NULL;
  return msg;
}

extern struct REPL {
  Console_Message *msg;
  Console_Message *msg_tail;
#ifdef _WIN32
  HANDLE out;
  HANDLE in;
  DWORD in_mode;
  DWORD out_mode;
#else
  struct termios modes;
  array_struct(char) in_buf;
#endif
  uint32_t msg_index;
  COORD home;
  COORD cursor;
  COORD size;
} repl;

extern struct Console_Preview {
  array_struct_members(char);
  uint32_t len;
  COORD pos;
} preview;

#ifdef __GNUC__
#define PRINTF_ATTR(fmt, arg) __attribute__((format(printf, fmt, arg)))
#else
#define PRINTF_ATTR(fmt, arg)
#endif

static inline int32_t utf8_norm(char *str) {
  // does not include null-terminator in return value length
  int32_t len = 0;
  for (; *str; ++len, ++str) *str = (char)tolower(*str);
  return len;
}

void cin_write(const char *str, uint32_t len);
void cin_swrite(const char *str);
void PRINTF_ATTR(1, 2) cin_writef(const char *format, ...);
void PRINTF_ATTR(1, 0) cin_vwritef(const char *format, va_list args);

#ifdef _WIN32
void cin_wvwritef(const wchar_t *format, va_list args);
#endif

#define HOME_X 2
#define CSI "\x1b["
#define ESC "\x1b"
#define CR "\r"
#define CRLF "\r\n"
#define WCRLF L"\r\n"
#define PREFIX_STR CR "> "

static inline short index_x(uint32_t index, uint32_t dwSize_X) {
  assert(index % dwSize_X <= SHRT_MAX);
  return (short)(index % dwSize_X);
}

static inline short index_x_repl(uint32_t index) {
  assert(repl.size.X >= 0);
  return index_x(HOME_X + index, (uint32_t)repl.size.X);
}

static inline short index_y(uint32_t index, uint32_t dwSize_X) {
  assert(index / dwSize_X <= SHRT_MAX);
  return (short)(index / dwSize_X);
}

static inline short index_y_repl(uint32_t index) {
  assert(repl.size.X >= 0);
  return repl.home.Y + index_y(HOME_X + index, (uint32_t)repl.size.X);
}

static inline COORD index_to_cursor(uint32_t index, uint32_t dwSize_X) {
  return (COORD){.X = index_x(index, dwSize_X), .Y = index_y(index, dwSize_X)};
}

static inline COORD index_to_cursor_repl(uint32_t index) {
  return (COORD){.X = index_x_repl(index), .Y = index_y_repl(index)};
}

static inline uint32_t cursor_to_index(COORD cursor, uint32_t dwSize_X) {
  assert(cursor.X >= 0);
  assert(cursor.Y >= 0);
  return (uint32_t)cursor.X + ((uint32_t)cursor.Y * dwSize_X);
}

static inline COORD curr_cursor(void) {
  return index_to_cursor_repl(repl.msg_index);
}

static inline COORD tail_cursor(void) {
  return index_to_cursor_repl(repl.msg->count);
}

static inline COORD home_cursor(void) {
  return repl.home;
}

static inline COORD preview_cursor(void) {
  return preview.pos;
}

static inline void hide_cursor(void) {
  cin_swrite(CSI "?25l");
}

static inline void show_cursor(void) {
  cin_swrite(CSI "?25h");
}

static inline void term_set_cursor(COORD coord) {
  cin_writef(CSI "%hd;%hdH", coord.Y, coord.X + 1);
}

bool term_get_cursor(COORD *corsor);
COORD term_get_size(COORD *size);
void term_clear(COORD pos, uint32_t cells, bool set_before, bool set_after);

static inline void term_get_info(COORD *cursor, COORD *size) {
  term_get_cursor(cursor);
  term_get_size(size);
}

static inline void cursor_home(void) {
  term_set_cursor(repl.home);
}

static inline void cursor_curr(void) {
  term_set_cursor(curr_cursor());
}

static inline void cursor_tail(void) {
  term_set_cursor(tail_cursor());
}

static inline void clear_tail(uint32_t count, bool set_before) {
  term_clear(tail_cursor(), count, set_before, false);
}

static inline void clear_full(void) {
  term_clear(home_cursor(), repl.msg->count, true, false);
}

static inline void clear_preview(short pos) {
  assert(pos >= 0);
  assert(pos < repl.size.X);
  preview.pos.X = pos;
  const uint32_t leftover = preview.len - (uint32_t)pos;
  term_clear(preview_cursor(), leftover, true, false);
}

static inline void set_preview_row(short y) {
  assert(y > 0);
  preview.pos.X = 0;
  preview.pos.Y = y;
}

static inline void write_preview(void) {
  cin_writef(ESC "7" CSI "%hd;1H" CSI "1m%.*s" CSI "22m" ESC "8",
             preview.pos.Y, preview.len, preview.items);
}

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

#endif