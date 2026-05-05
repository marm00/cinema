#include <windows.h>

#include "console.h"
#include "log.h"

static CRITICAL_SECTION log_lock;

void lock_logs(void) {
  EnterCriticalSection(&log_lock);
}

void unlock_logs(void) {
  LeaveCriticalSection(&log_lock);
}

void log_wmessage(Cin_Log_Level level, const wchar_t *wmessage, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  lock_logs();
  hide_cursor();
  cursor_home();
  cin_writef(CR "[%s] ", LOG_LEVELS[level]);
  va_list args;
  va_start(args, wmessage);
  cin_wvwritef(wmessage, args);
  rewrite_post_log();
  va_end(args);
  unlock_logs();
}
