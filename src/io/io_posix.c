#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include "io.h"

bool internal_write(Instance *instance, Overlapped_Write *msg, int32_t bytes) {
  const ssize_t write_result = write(instance->socket, msg->buf, msg->bytes);
  if (write_result < 0) {
    log_last_error("Failed to write to file descriptor %d", instance->socket);
  } else if (write_result < (ssize_t)msg->bytes) {
    log_message(LOG_ERROR, "Expected '%zu' bytes but received '%ld': %s", msg->bytes, bytes, msg->buf);
  }
}