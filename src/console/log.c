#include <assert.h>

#include "console.h"
#include "log.h"

const Cin_Log_Level GLOBAL_LOG_LEVEL = LOG_LEVEL;
const char *LOG_LEVELS[LOG_TRACE + 1] = {"ERROR", "WARNING", "INFO", "DEBUG", "TRACE"};

#ifdef _WIN32
#include "log_win32.c"
#else
#include "log_posix.c"
#include <errno.h>
#endif

void log_preview(void) {
  if (!preview.count) return;
  assert(repl.size.X >= 0);
  // preview.count includes the null terminator
  const bool use_ellipses = preview.count - 1 > (uint32_t)repl.size.X;
  if (use_ellipses) {
    preview.len = (uint32_t)repl.size.X;
    assert(preview.len > 3);
    const short tmp1_pos = repl.size.X - 1;
    const short tmp2_pos = repl.size.X - 2;
    const short tmp3_pos = repl.size.X - 3;
    const char tmp1 = preview.items[tmp1_pos];
    const char tmp2 = preview.items[tmp2_pos];
    const char tmp3 = preview.items[tmp3_pos];
    preview.items[tmp1_pos] = '.';
    preview.items[tmp2_pos] = '.';
    preview.items[tmp3_pos] = '.';
    write_preview();
    preview.items[tmp1_pos] = tmp1;
    preview.items[tmp2_pos] = tmp2;
    preview.items[tmp3_pos] = tmp3;
  } else {
    preview.len = preview.count - 1;
    write_preview();
  }
}

void rewrite_post_log(void) {
  const COORD prev = repl.home;
#ifdef _WIN32
  term_get_cursor(&repl.cursor);
#else
  if (pthread_equal(pthread_self(), listener_thread)) {
    unlock_logs();
    interrupt_start();
    lock_logs();
  } else {
    term_get_cursor(&repl.cursor);
  }
#endif
  const COORD next = repl.cursor;
  if (repl.cursor.X < repl.size.X) {
    cin_writef(CSI "0K\n> %.*s", repl.msg->count, repl.msg->items);
  } else {
    cin_writef("\n> %.*s", repl.msg->count, repl.msg->items);
  }
  const short line_shift = next.Y - prev.Y;
  if (line_shift == 0) {
    cin_swrite(CSI "0K");
  }
  repl.home.Y = next.Y + 1;
  const short msg_lines = index_y(HOME_X + repl.msg->count, (uint32_t)repl.size.X) + 1;
  if (repl.home.Y + msg_lines >= repl.size.Y) {
    const short excess_lines = (repl.home.Y + msg_lines) - repl.size.Y;
    repl.home.Y -= excess_lines;
    cin_swrite("\n" CSI "1A");
  }
  set_preview_row(repl.home.Y + msg_lines);
  assert(repl.home.Y < repl.size.Y);
  assert(preview.pos.Y <= repl.size.Y);
  assert(preview.pos.Y > repl.home.Y);
  cursor_curr();
  log_preview();
  show_cursor();
}

void log_message(Cin_Log_Level level, const char *message, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  lock_logs();
  hide_cursor();
  cursor_home();
  cin_writef(CR "[%s] ", LOG_LEVELS[level]);
  va_list args;
  va_start(args, message);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  cin_vwritef(message, args);
#pragma clang diagnostic pop
  rewrite_post_log();
  va_end(args);
  unlock_logs();
}

void cin_write_safe(const char *str, uint32_t len) {
  lock_logs();
  clear_preview(0);
  hide_cursor();
  cursor_home();
  cin_write(str, len);
  rewrite_post_log();
  unlock_logs();
}

void log_last_error(const char *message, ...) {
  lock_logs();
#ifdef _WIN32
  static const uint32_t dw_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                   FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS;
  LPVOID buffer = NULL;
  const uint32_t code = GetLastError();
  if (!FormatMessageW(dw_flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&buffer, 0, NULL)) {
    log_message(LOG_ERROR, "Failed to log GLE=%d - error with GLE=%d", code, GetLastError());
    return;
  }
  // remove trailing \r\n
  wchar_t *str = (wchar_t *)buffer;
  const size_t len = wcslen(str);
  assert(len >= 2);
  assert(str[len - 1] == L'\n');
  assert(str[len - 2] == L'\r');
  str[len - 1] = L'\0';
  str[len - 2] = L'\0';
#else
  const size_t code = (size_t)errno;
  char *buffer = strerror((int32_t)code);
#endif
  hide_cursor();
  cursor_home();
  cin_writef(CR "[%s] ", LOG_LEVELS[LOG_ERROR]);
  va_list args;
  va_start(args, message);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  cin_vwritef(message, args);
#pragma clang diagnostic pop
  va_end(args);
#ifdef _WIN32
  cin_wwritef(L" - Code %lu: %s", code, (wchar_t *)buffer);
#else
  cin_writef(" - Code %lu: %s", code, (char *)buffer);
#endif
  rewrite_post_log();
#ifdef _WIN32
  LocalFree(buffer);
#endif
  unlock_logs();
}