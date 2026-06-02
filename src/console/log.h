#ifndef CIN_LOG_H
#define CIN_LOG_H

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

bool init_logs(void);
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

#endif