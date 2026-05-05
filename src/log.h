#ifndef CIN_LOG_H
#define CIN_LOG_H

#include "console.h"
#include <stdint.h>

typedef enum {
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} Cin_Log_Level;

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_WARNING
#endif

extern const Cin_Log_Level GLOBAL_LOG_LEVEL;
extern const char *LOG_LEVELS[LOG_TRACE + 1];

void lock_logs(void);
void unlock_logs(void);
void log_preview(void);
void rewrite_post_log(void);
void log_message(Cin_Log_Level level, const char *message, ...);
void cin_write_safe(const char *str, uint32_t len);
void log_last_error(const char *message, ...);

#ifdef _WIN32
void log_wmessage(Cin_Log_Level level, const wchar_t *wmessage, ...);
#endif

#define CIN_STRERROR_BYTES 95

static inline void log_fopen_error(const char *filename, int32_t err) {
#ifdef _WIN32
  char err_buf[CIN_STRERROR_BYTES];
  strerror_s(err_buf, CIN_STRERROR_BYTES, err);
#else
  char *err_buf = strerror(err);
#endif
  log_message(LOG_ERROR, "Failed to open file '%s': %s", filename, err_buf);
}

#endif