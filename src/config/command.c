#include "command.h"

struct Command_Context cmd_ctx = {0};

void set_preview(bool success, const char *format, ...) {
  array_clear(&preview);
  if (!success) {
    array_extend(&arena_console, &preview, COMMAND_ERROR_MESSAGE, COMMAND_ERROR_MESSAGE_LEN);
  }
  const size_t start = preview.count;
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
  array_grow(&arena_console, &preview, len + 1);
  vsnprintf(preview.items + start, preview.capacity, format, args_dup);
#pragma clang diagnostic pop
  va_end(args_dup);
}

bool validate_screens(void) {
  const size_t n_count = cmd_ctx.numbers.count;
  const size_t screen_count = cmd_ctx.layout->count;
  if (n_count > screen_count) {
    set_preview(false, "layout only has %zu screens (%zu provided)", screen_count, n_count);
    return false;
  }
  for (size_t i = 0; i < n_count; ++i) {
    const size_t screen_index = cmd_ctx.numbers.items[i] - 1;
    if (screen_index >= screen_count) {
      set_preview(false, "screen %zu not found, layout only has %zu screens",
                  screen_index + 1, screen_count);
      return false;
    }
  }
  array_clear(&cmd_ctx.targets);
  if (!n_count) {
    array_sextend(&arena_console, &cmd_ctx.targets, "(all screens)\0");
    for (size_t i = 0; i < cmd_ctx.layout->count; ++i) {
      array_push(&arena_console, &cmd_ctx.numbers, i + 1);
    }
  } else {
    if (n_count == 1) {
      array_sextend(&arena_console, &cmd_ctx.targets, "(screen ");
    } else {
      array_sextend(&arena_console, &cmd_ctx.targets, "(screens ");
    }
    for (size_t i = 0; i < n_count; ++i) {
      const size_t number = cmd_ctx.numbers.items[i];
      const int32_t len_i32 = snprintf(NULL, 0, FSTR_CIN_SCREEN, number);
      assert(len_i32);
      const uint32_t len = (uint32_t)len_i32 + 1;
      array_reserve(&arena_console, &cmd_ctx.targets, len);
      snprintf(cmd_ctx.targets.items + cmd_ctx.targets.count, len, FSTR_CIN_SCREEN, number);
      cmd_ctx.targets.count += len - 1;
    }
    cmd_ctx.targets.count -= CIN_SCREEN_SEPARATOR_LEN;
    array_push(&arena_console, &cmd_ctx.targets, ')');
    cmd_ctx.targets.items[cmd_ctx.targets.count] = '\0';
  }
  return true;
}

void register_cmd(const char *name, const char *help, cmd_validator validator) {
  patricia_insert(&arena_console, cmd_ctx.trie, name, validator);
  const int32_t len_i32 = snprintf(NULL, 0, FSTR_CMD, name, help);
  assert(len_i32);
  const uint32_t len = (uint32_t)len_i32 + 1;
  array_reserve(&arena_console, &cmd_ctx.help, len);
  snprintf(cmd_ctx.help.items + cmd_ctx.help.count, len, FSTR_CMD, name, help);
  cmd_ctx.help.count += len - 1;
}