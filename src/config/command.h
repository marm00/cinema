#ifndef CIN_COMMAND_H
#define CIN_COMMAND_H

#include "base/array.h"
#include "base/patricia.h"
#include "config.h"

#define COMMAND_ERROR_MESSAGE "ERROR: "
#define COMMAND_ERROR_MESSAGE_LEN cin_strlen(COMMAND_ERROR_MESSAGE)
#define COMMAND_NUMBERS_CAP 8

typedef void (*cmd_validator)(void);
typedef void (*cmd_executor)(void);

array_define(Command_Numbers, size_t);
array_define(Command_Help, char);
array_define(Command_Targets, char);

extern struct Command_Context {
  Patricia_Node *trie;
  Cin_Layout *layout;
  Cin_Layout *queued_layout;
  Tag_Items *tag;
  cmd_executor executor;
  Command_Numbers numbers;
  char *unicode;
  Command_Targets targets;
  Command_Help help;
  Cin_Macro *macro;
} cmd_ctx;

#define CIN_SCREEN_SEPARATOR ", "
#define CIN_SCREEN_SEPARATOR_LEN (sizeof(CIN_SCREEN_SEPARATOR) / sizeof(*CIN_SCREEN_SEPARATOR) - 1)
#define FSTR_CIN_SCREEN "%zu" CIN_SCREEN_SEPARATOR

void set_preview(bool success, const char *format, ...);
bool validate_screens(void);

#define mpv_target_foreach(i, instance)                         \
  for (size_t i = 0, _j = 0, _s = cmd_ctx.numbers.items[0] - 1; \
       i < cmd_ctx.numbers.count;                               \
       _j = 0, _s = cmd_ctx.numbers.items[++i] - 1)             \
    for (Instance *instance = cin_io.instances.head;            \
         _j <= _s && instance;                                  \
         instance = instance->next, ++_j)                       \
      if (_j == _s && instance->socket)

#define FSTR_CMD CRLF "  %-10s %s"

void register_cmd(const char *name, const char *help, cmd_validator validator);

#endif