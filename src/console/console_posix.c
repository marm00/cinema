#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "console.h"
#include "io/io.h"

void cin_write(const char *str, uint32_t len) {
  write(STDOUT_FILENO, str, len);
}

bool term_get_cursor(COORD *cursor) {
  bool ok = true;
  cin_swrite(CSI "6n");
  char pos[16];
  ssize_t n = read(STDIN_FILENO, pos, sizeof(pos) - 1);
  if (n <= 0) {
    ok = false;
  } else {
    static const int32_t MAX_CURSOR_RETRIES = 5;
    int32_t i = 0;
    do {
      pos[n] = '\0';
      const char *p = pos;
      const char *candidate = strchr(p, TERM_ESC);
      if (candidate && p != candidate) {
        ptrdiff_t diff = candidate - p;
        array_extend(&arena_console, &repl.in_buf, p, (uint32_t)diff);
        p = candidate;
      }
      ok = sscanf(p, CSI "%hd;%hdR", &cursor->Y, &cursor->X) == 2;
      if (!ok) {
        size_t remainder = strlen(p);
        array_extend(&arena_console, &repl.in_buf, p, (uint32_t)remainder);
        n = read(STDIN_FILENO, pos, sizeof(pos) - 1);
      }
    } while (!ok && i++ < MAX_CURSOR_RETRIES);
  }
  assert(ok && "Failed to get new cursor position");
  return ok;
}

COORD term_get_size(COORD *size) {
  COORD size_change = {0};
  const short prev_x = size->X;
  const short prev_y = size->Y;
  struct winsize ws;
  ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
  size->X = (short)ws.ws_col;
  size->Y = (short)ws.ws_row;
  size_change.X = size->X - prev_x;
  size_change.Y = size->Y - prev_y;
  return size_change;
}

bool init_repl_internal(void) {
  tcgetattr(STDIN_FILENO, &repl.modes);
  struct termios tmp = repl.modes;
  tmp.c_lflag &= (tcflag_t)~ICANON;
  tmp.c_lflag &= (tcflag_t)~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &tmp);
  return true;
}