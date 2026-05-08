#ifdef _WIN32
#include "console_win32.c"
#else
#include "console_posix.c"
#endif

Arena arena_console = {0};
UTF8_Buffer utf8_buf = {0};
UTF8_Buffer_Char write_buf = {0};
struct REPL repl = {0};
struct Console_Preview preview = {0};

void cin_swrite(const char *str) {
  assert(strlen(str) <= SIZE_MAX && "Corrupted string");
  const size_t len = strlen(str);
  cin_write(str, (uint32_t)len);
}

void PRINTF_ATTR(1, 2) cin_writef(const char *format, ...) {
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  const int32_t len_i32 = vsnprintf(NULL, 0, format, args);
  assert(len_i32 >= 0);
  const uint32_t len = (uint32_t)len_i32;
  va_end(args);
  array_resize(&arena_console, &write_buf, len + 1);
  vsnprintf(write_buf.items, len + 1, format, args_dup);
#pragma clang diagnostic pop
  va_end(args_dup);
  cin_write(write_buf.items, len);
}

void PRINTF_ATTR(1, 0) cin_vwritef(const char *format, va_list args) {
  va_list args_dup;
  va_copy(args_dup, args);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
  const int32_t len_i32 = vsnprintf(NULL, 0, format, args_dup);
  assert(len_i32 >= 0);
  const uint32_t len = (uint32_t)len_i32;
  va_end(args_dup);
  array_resize(&arena_console, &write_buf, len + 1);
  vsnprintf(write_buf.items, len + 1, format, args);
#pragma clang diagnostic pop
  cin_write(write_buf.items, len);
}

void term_clear(COORD pos, uint32_t cells, bool set_before, bool set_after) {
  assert(cells < SHRT_MAX);
  if (set_before) term_set_cursor(pos);
  short n = (short)cells;
  const short max_removed = repl.size.X - pos.X;
  short removed = min(n, max_removed);
  cin_writef(CSI "%hdX", removed);
  if (n > removed) {
    for (n -= removed; n > 0; n -= removed) {
      cin_writef(CSI "1E" CSI "%hdX", n);
      removed = min(n, repl.size.X);
    }
    term_set_cursor(pos);
  } else if (set_after) {
    term_set_cursor(pos);
  }
}

bool init_repl(void) {
  if (!arena_chunk_init(&arena_console, CIN_ARENA_CAP)) goto memory;
  if (!init_repl_internal()) return false;
  repl.msg = create_console_message();
  repl.msg_index = 0;
  term_get_info(&repl.cursor, &repl.size);
  repl.cursor.X = HOME_X;
  repl.home = repl.cursor;
  array_init(&arena_console, &write_buf, CIN_MAX_PATH);
  array_init(&arena_console, &preview, CIN_MAX_PATH);
  array_init(&arena_console, &utf8_buf, CIN_MAX_PATH_BYTES);
  cin_swrite(PREFIX_STR);
  return true;
memory:
  cin_swrite("Failed to allocate memory for repl/console" CRLF);
  return false;
}
