#include "io.h"

#ifdef _WIN32
#include "io_win32.c"
#else
#include "io_posix.c"
#endif

Arena arena_io = {0};
Arena arena_iocp_thread = {0};
struct Cin_IO cin_io = {0};

bool overlap_write(Instance *instance, MPV_Packet type, const char *cmd, const char *arg1, const char *arg2) {
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
  bool completed_write = internal_write(instance, msg, bytes);
  if (!completed_write) {
    return false;
  }
  log_message(LOG_TRACE, "Write call completed immediately.");
  return true;
}