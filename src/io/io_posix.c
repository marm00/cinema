#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "base/array.h"
#include "console/log_posix.h"
#include "io.h"
#include "os/window_posix.h"

static int32_t listener_pipe[2];
static pthread_mutex_t listener_lock = PTHREAD_MUTEX_INITIALIZER;
static array_struct(struct pollfd) listener_pfds = {0};
static array_struct(Instance *) listener_pfds_to_instances = {0};

bool internal_write(Instance *instance, Overlapped_Write *msg, int32_t bytes) {
  const ssize_t write_result = write(instance->socket, msg->buf, msg->bytes);
  if (write_result < 0) {
    log_last_error("Failed to write to file descriptor %d", instance->socket);
  } else if (write_result < (ssize_t)msg->bytes) {
    log_message(LOG_ERROR, "Expected '%zu' bytes but received '%ld': %s", msg->bytes, bytes, msg->buf);
  }
  return true;
}

void copy_clipboard(void) { /* */ }

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

bool iocp_start(void) {
  pipe(interrupt_pipe);
  pipe(listener_pipe);
  if (pthread_create(&listener_thread, NULL, mpv_listener, NULL) != 0) {
    log_last_error("Failed to create listener thread");
    return false;
  }
  return true;
}

void mpv_spawn_internal(Instance *instance, char *mpv_flags[], char *socket_name) {
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
    os_sleep(MPV_SPAWN_DELAY);
  }
}

void chat_kill(void) {
  if (chat.pid) kill(chat.pid, SIGTERM);
}

size_t chat_spawn(const Cin_Layout *layout) {
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
}

HWND chat_get_window(size_t pid, char *name) {
  (void)pid;
  Window root = pXDefaultRootWindow(pxdisplay);
  return find_window_by_name(pxdisplay, root, "Chatterino");
}

int32_t term_read(uint8_t *buf, const int32_t n, bool peek) {
  int32_t chars_read = 0;
  assert(n > 0);
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
  return chars_read;
}