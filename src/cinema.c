// Copyright (c) 2025-2026 marm00

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifdef _WIN32
#define _CRT_RAND_S
#define _CRT_SECURE_NO_DEPRECATE
#endif

#ifdef CIN_OPENMP
#include <omp.h>
#endif

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <wchar.h>
#include <windows.h>
#pragma comment(lib, "user32")
#pragma comment(lib, "advapi32")
#else
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <glob.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#endif

#include "base/arena.h"
#include "base/array.h"
#include "base/cache.h"
#include "base/core.h"
#include "base/patricia.c"
#include "base/radix.c"
#include "base/table.c"
#include "config/command.c"
#include "config/config.c"
#include "console/console.c"
#include "console/log.c"
#include "io/io.c"
#include "os/os.c"
#include "os/window.c"

#include "third_party/libsais.h"

static void cmd_help_executor(void) {
  cin_write_safe(cmd_ctx.help.items, cmd_ctx.help.count);
}

static void cmd_help_validator(void) {
  set_preview(true, "help (show a list of all commands)");
  cmd_ctx.executor = cmd_help_executor;
}

static void cmd_layout_executor(void) {
  Cin_Layout *layout = cmd_ctx.queued_layout;
  cmd_ctx.layout = layout;
  const uint32_t next_count = layout->count;
  uint32_t screen = 0;
  mpv_lock();
  chat_reposition(layout);
  cache_foreach(&cin_io.instances, Instance, i, old) {
    if (screen >= next_count) {
      if (old->socket) overlap_write(old, MPV_QUIT, "quit", NULL, NULL);
    } else if (old->socket) {
      log_message(LOG_INFO, "i=%u, screen=%zu", i);
      assert(cin_iswindow(old->window));
      const char *geometry = (char *)screen_strings.items + layout->items[screen].offset;
      overlap_write(old, MPV_SET_GEOMETRY, "set_property", "geometry", geometry);
      if (old->full_screen) {
        old->full_screen = false;
        overlap_write(old, MPV_WRITE, "set_property", "fullscreen", "no");
      }
    } else {
      mpv_spawn(old, screen);
    }
    ++screen;
  }
  for (Instance *next = NULL; screen < next_count; ++screen) {
    cache_get(&arena_io, &cin_io.instances, next);
    playlist_set_default(next);
    mpv_spawn(next, screen);
  }
  if (!mpv_demand) mpv_unlock();
}

static void cmd_layout_validator(void) {
  radix_v layout = NULL;
  const uint8_t *layout_name = NULL;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    layout = radix_query(layout_tree, (uint8_t *)cmd_ctx.unicode, len, &layout_name);
    if (!layout) {
      set_preview(false, "layout does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
    assert(layout);
    assert(layout_name);
    set_preview(true, "change layout to '%s'", (char *)layout_name);
  } else {
    Cin_Layout *curr = cmd_ctx.layout;
    char *curr_name = (char *)layout_strings.items + curr->name_offset;
    set_preview(true, "reset layout '%s'", curr_name);
    layout = curr;
  }
  cmd_ctx.queued_layout = (Cin_Layout *)layout;
  cmd_ctx.executor = cmd_layout_executor;
}

static void cmd_shuffle_executor(void) {
  size_t count = 0;
  mpv_target_foreach(i, instance) {
    playlist_play(instance);
    ++count;
  }
  if (count == 0) {
    cmd_ctx.queued_layout = cmd_ctx.layout;
    cmd_layout_executor();
  }
}

static void cmd_shuffle_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "shuffle %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_shuffle_executor;
}

static cmd_validator parse_command(const char *command) {
  // Grammar rules:
  // 1. First character must be either empty or in 'a'..'z' (letter) or in '1'..'9' (digit)
  // 2. Empty (whitespace*\0) is a command
  // 3. Letter must precede one of: 'letter', 'space', '\0';
  // 3a. 'letter' concatenates a string character
  // 3b. 'space' finishes the string to setup (possible) command 'letter+'
  // 3c. '\0' is (possibly) a command comprised of 'letter+'
  // 4. Digit must precede one of: 'digit', '\0', 'space', 'letter'.
  // 4a. 'digit' concatenates a decimal number
  // 4b. '\0' is a command: consumes the number (array)
  // 4c. 'space' pushes decimal number onto the numbers array
  // 4d. 'letter' finishes the number array for command 'letter+' consumption
  // 5. Command 'letter+' with 'space' (3b) may precede 'unicode*'
  // 5a. 'unicode*' string is finished with '\0'
  cmd_ctx.executor = NULL;
  array_clear(&cmd_ctx.numbers);
  cmd_ctx.unicode = NULL;
  const char *p = command;
  while (isspace(*p)) ++p;
  size_t number = 0;
  for (; *p; ++p) {
    if (cin_isnum_1based(*p)) {
      // 4a. build decimal number
      number *= 10;
      number += (size_t)(*p - '0');
    } else if (*p == ' ') {
      if (number) {
        // 4c. push decimal number onto array
        array_push(&arena_console, &cmd_ctx.numbers, number);
      }
      number = 0;
    } else if (cin_isloweralpha(*p)) {
      // if numbers array empty and number, push
      if (number) {
        array_push(&arena_console, &cmd_ctx.numbers, number);
        number = 0;
      }
      break;
    } else {
      const intptr_t pos = p - command;
      assert(pos >= 0);
      set_preview(false, "unexpected character '%c' at position %zd,"
                         " expected: alphanumeric, space, enter",
                  *p, pos + 1);
      return NULL;
    }
  }
  if (!*p) {
    // 2/4b. command
    if (number) {
      array_push(&arena_console, &cmd_ctx.numbers, number);
    }
    return cmd_shuffle_validator;
  }
  const char *start = p;
  ++p;
  while (cin_isloweralpha(*p)) ++p;
  // 3/3a. letter+, command begins at start, ends at p
  if (!*p) {
    // 3c. possible command
    cmd_validator validator = patricia_query(cmd_ctx.trie, start);
    if (!validator) {
      set_preview(false, "'%s' is not a valid command", start);
    }
    return validator;
  }
  if (*p != ' ') {
    const intptr_t pos = p - command;
    assert(pos >= 0);
    set_preview(false, "unexpected character '%c' at position %zd,"
                       " expected: letter, space, enter",
                *p, pos + 1);
    return NULL;
  }
  // temporarily null-terminate
  *(char *)p = '\0';
  cmd_validator validator = patricia_query(cmd_ctx.trie, start);
  if (!validator) {
    set_preview(false, "'%s' is not a valid command", start);
  }
  *(char *)p = ' ';
  ++p;
  // 5a. unicode starts at p ends at \0
  cmd_ctx.unicode = (char *)p;
  return validator;
}

static void update_preview(void) {
  array_reserve(&arena_console, repl.msg, 1);
  repl.msg->items[repl.msg->count] = '\0';
  cmd_validator validator_fn = parse_command(repl.msg->items);
  if (validator_fn) {
    validator_fn();
  }
}

static void cmd_tag_executor(void) {
  if (cmd_ctx.tag->playlist) goto shuffle;
  cache_get_zero(&arena_docs, &media.playlists, cmd_ctx.tag->playlist);
  Playlist *playlist = cmd_ctx.tag->playlist;
  playlist->from_tag = true;
  size_t directory_k = 0;
  size_t pattern_k = 0;
  size_t url_k = 0;
  Arena *arena1 = &arena_console;
  Arena *arena2 = &arena_docs;
  Arena *arena3 = &arena_io;
#ifdef CIN_OPENMP
#pragma omp parallel
#pragma omp single
#endif
  {
    if (cmd_ctx.tag->directories) {
#ifdef CIN_OPENMP
#pragma omp task priority(8)
#endif
      {
        Tag_Directories *directories = cmd_ctx.tag->directories;
        directory_k = deduplicate_i32(arena1, directories->items, directories->count);
        Robin_Hood_Table duplicates = {0};
        table_init(arena1, &duplicates, CIN_DIRECTORIES_CAP);
        uint8_t *strings = directory_strings.items;
        for (size_t i = 0; i < directory_k; ++i) {
          size_t node_index = (size_t)directories->items[i];
          assert(node_index < directory_nodes.count);
          Directory_Node *start = &directory_nodes.items[node_index];
          table_key_t *start_str = directory_strings.items + start->str_offset;
          const size_t start_len = strlen((char *)start_str);
          Table_Key key = {.strings = strings, .pos = start->str_offset, .len = (table_key_len)start_len + 1};
          table_value dup = table_insert(arena1, &duplicates, &key, 0);
          if (dup >= 0) continue;
          log_message(LOG_TRACE, "Tag directory: %s (%zu)", start_str, start_len);
          array_extend(arena1, playlist, start->items, start->count);
          for (size_t j = ++node_index; j < directory_nodes.count; ++j) {
            Directory_Node *node = &directory_nodes.items[j];
            if (!node->count) continue;
            table_key_t *str = directory_strings.items + node->str_offset;
            if (strncmp((char *)str, (char *)start_str, start_len) != 0) break;
            const size_t len = strlen((char *)str);
            key.pos = node->str_offset;
            key.len = (table_key_len)len + 1;
            dup = table_insert(arena1, &duplicates, &key, 0);
            if (dup >= 0) continue;
            log_message(LOG_TRACE, "Tag directory: %s", str);
            array_extend(arena1, playlist, node->items, node->count);
          }
        }
        table_free_items(arena1, &duplicates);
      }
    }
    if (cmd_ctx.tag->pattern_items) {
#ifdef CIN_OPENMP
#pragma omp task priority(4)
#endif
      {
        Tag_Pattern_Items *patterns = cmd_ctx.tag->pattern_items;
        pattern_k = deduplicate_i32(arena2, patterns->items, patterns->count);
      }
    }
    if (cmd_ctx.tag->url_items) {
#ifdef CIN_OPENMP
#pragma omp task priority(2)
#endif
      {
        Tag_Url_Items *urls = cmd_ctx.tag->url_items;
        url_k = deduplicate_i32(arena3, urls->items, urls->count);
      }
    }
#ifdef CIN_OPENMP
#pragma omp taskwait
#endif
  }
  if (directory_k) {
    array_free(&arena_console, cmd_ctx.tag->directories);
    cmd_ctx.tag->directories = NULL;
  }
  if (pattern_k) {
    array_extend(&arena_console, playlist, cmd_ctx.tag->pattern_items->items, (uint32_t)pattern_k);
    array_free(&arena_console, cmd_ctx.tag->pattern_items);
    cmd_ctx.tag->pattern_items = NULL;
  }
  if (url_k) {
    array_extend(&arena_console, playlist, cmd_ctx.tag->url_items->items, (uint32_t)url_k);
    array_free(&arena_console, cmd_ctx.tag->url_items);
    cmd_ctx.tag->url_items = NULL;
  }
  if (playlist->count > 0) {
    array_to_pow1(&arena_docs, playlist);
    playlist_setup_shuffle(playlist);
  } else {
    playlist->empty = true;
    log_message(LOG_INFO, "Tag is empty");
  }
shuffle:
  if (!cmd_ctx.tag->playlist->empty) {
    mpv_target_foreach(i, instance) {
      playlist_set(instance, cmd_ctx.tag->playlist);
      playlist_play(instance);
    }
  }
}

static void cmd_tag_validator(void) {
  if (!validate_screens()) return;
  radix_v tag = NULL;
  const uint8_t *tag_name = NULL;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    tag = radix_query(tag_tree, (uint8_t *)cmd_ctx.unicode, len, &tag_name);
    if (!tag) {
      set_preview(false, "tag does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
  } else {
    tag = radix_query(tag_tree, (const uint8_t *)"", 0, &tag_name);
    if (!tag) {
      set_preview(false, "configuration does not contain any tags");
      return;
    }
  }
  assert(tag);
  assert(tag_name);
  set_preview(true, "tag '%s' %s", (char *)tag_name, cmd_ctx.targets.items);
  cmd_ctx.tag = (Tag_Items *)tag;
  cmd_ctx.executor = cmd_tag_executor;
}

static void cmd_search_executor(void) {
  Playlist *playlist = &media.default_playlist;
  int32_t len = 0;
  if (cmd_ctx.unicode && (len = (int32_t)strlen(cmd_ctx.unicode))) {
#ifdef _WIN32
    setup_file_path_char(cmd_ctx.unicode, &len);
#endif
    ++len; // null-terminator
    uint8_t *pattern = (uint8_t *)cmd_ctx.unicode;
    const table_key_len len_u32 = (table_key_len)len;
    log_message(LOG_DEBUG, "Search with pattern: '%s', len: %d", pattern, len);
    array_reserve(&arena_docs, &media.search_patterns, len_u32);
    table_key_t *strings = media.search_patterns.items;
    const table_key_pos pos = media.search_patterns.count;
    memcpy(strings + pos, pattern, len_u32);
    Table_Key key = {.strings = strings, .pos = pos, .len = len_u32};
    cache_get_zero(&arena_docs, &media.playlists, playlist);
    table_value value = (table_value)playlist;
    table_value result = table_insert(&arena_docs, &media.search_table, &key, value);
    if (result != -1) {
      assert(result);
      cache_put(&media.playlists, playlist);
      playlist = (Playlist *)result;
      log_message(LOG_DEBUG, "Searched for cached pattern");
      if (playlist->empty) {
        log_message(LOG_DEBUG, "Cached pattern is empty, using default playlist");
        return;
      }
    } else {
      playlist->search_pos = pos;
      playlist->search_len = len_u32;
      playlist->from_tag = false;
      media.search_patterns.count += len_u32;
      document_listing(pattern, len - 1, playlist);
      if (!playlist->count) {
        log_message(LOG_INFO, "No results for search query: %s", pattern);
        playlist->empty = true;
        return;
      }
      playlist_setup_shuffle(playlist);
    }
    log_message(LOG_INFO, "Search playlist count=%d, cap=%d", playlist->count, playlist->capacity);
  }
  mpv_target_foreach(i, instance) {
    playlist_set(instance, playlist);
    playlist_play(instance);
  }
}

static void cmd_search_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "search '%s' %s", cmd_ctx.unicode ? cmd_ctx.unicode : "", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_search_executor;
}

static void cmd_hide_executor(void) {
  if (!cmd_ctx.unicode) return;
  const size_t len = strlen(cmd_ctx.unicode) + 1;
  uint8_t *pattern = (uint8_t *)cmd_ctx.unicode;
  if (len <= 1) return;
  const uint32_t len_u32 = (uint32_t)len;
  array_reserve(&arena_docs, &media.search_patterns, len_u32);
  table_key_t *strings = media.search_patterns.items;
  const table_key_pos pos = media.search_patterns.count;
  memcpy(strings + pos, pattern, len_u32);
  Table_Key key = {.strings = strings, .pos = pos, .len = len_u32};
  table_value value = table_find(&media.search_table, &key);
  Playlist tmp_playlist = {0};
  if (value != -1) {
    assert(value);
    tmp_playlist = *(Playlist *)value;
  } else {
    document_listing(pattern, (int32_t)len - 1, &tmp_playlist);
  }
  assert(&tmp_playlist);
  Hidden_Table *table = &media.hidden_table;
  uint32_t hash_n = 1;
  while (hash_n < (table->count + (&tmp_playlist)->count) * 2) hash_n <<= 1;
  const uint32_t start = table->capacity;
  array_ensure_capacity_core(&arena_docs, table, hash_n, true);
  const uint32_t end = table->capacity;
  const uint64_t mask = table->capacity - 1;
  if (start < end) {
    for (uint32_t i = start; i < end; ++i) table->items[i] = -1;
    for (uint32_t i = 0; i < start; ++i) {
      const int32_t v = table->items[i];
      if (v >= 0) {
        table->items[i] = -1;
        const uint64_t hash = (uint64_t)v * CIN_INTEGER_HASH;
        uint64_t index = hash & mask;
        while (table->items[index] >= 0) index = (index + 1) & mask;
        table->items[index] = v;
      }
    }
  }
  array_foreach(&tmp_playlist, int32_t, i, doc) {
    const uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
    uint64_t index = hash & mask;
    while (table->items[index] >= 0) {
      if (table->items[index] == doc) goto next;
      index = (index + 1) & mask;
    }
    table->items[index] = doc;
    ++table->count;
  next:;
  }
  if (value < 0) array_free_items(&arena_docs, &tmp_playlist);
  Playlist prev_default = media.default_playlist;
  Playlist new_default = {0};
  array_copy_shallow(&arena_docs, &new_default, &prev_default);
  array_foreach(&prev_default, int32_t, i, doc) {
    const uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
    uint64_t index = hash & mask;
    while (table->items[index] >= 0) {
      if (table->items[index] == doc) goto skip;
      index = (index + 1) & mask;
    }
    array_push(&arena_docs, &new_default, doc);
  skip:;
  }
  if (!new_default.count) {
    log_message(LOG_WARNING, "Original playlist restored since every item was hidden");
    const int32_t d_bytes = (int32_t)array_bytes(&docs);
    array_ensure_capacity_core(&arena_docs, &new_default, (uint32_t)docs.doc_count, false);
    for (int32_t i = 0, offset = 0; i < d_bytes; ++i) {
      if (docs.items[i] == '\0') {
        const uint32_t playlist_pos = (&new_default)->count++;
        (&new_default)->items[playlist_pos] = offset;
        offset = i + 1;
      }
    }
    array_clear(&media.search_patterns);
    memset(table->items, -1, table->bytes_capacity);
    array_clear(table);
    memset(media.search_table.items, 0, media.search_table.bytes_capacity);
    array_clear(&media.search_table);
  }
  array_to_pow1(&arena_docs, &new_default);
  media.default_playlist = new_default;
  playlist_setup_shuffle(&media.default_playlist);
  arena_free_pos(&arena_docs, (uint8_t *)prev_default.items, prev_default.bytes_capacity);
  cache_foreach(&cin_io.instances, Instance, i, o) {
    if (o->playlist && !o->playlist->from_tag) {
      playlist_set_default(o);
      if (o->socket) playlist_play(o);
    }
  }
}

static void cmd_hide_validator(void) {
  if (cmd_ctx.unicode && *cmd_ctx.unicode) {
    set_preview(true, "hide '%s'", cmd_ctx.unicode);
  } else {
    set_preview(true, "hide '' (nothing)");
  }
  cmd_ctx.executor = cmd_hide_executor;
}

static void cmd_idle_executor(void) {
  cin_idle = !cin_idle;
}

static void cmd_idle_validator(void) {
  set_preview(true, cin_idle ? "allow commands to play media" : "set screens to idle");
  cmd_ctx.executor = cmd_idle_executor;
}

static void cmd_kill_executor(void) {
  chat_kill();
  mpv_target_foreach(i, instance) {
    log_message(LOG_DEBUG, "Closing Window=%lu", instance->window);
    overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
  }
}

static void cmd_kill_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "kill  %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_kill_executor;
}

static void cmd_maximize_executor(void) {
  const size_t target = cmd_ctx.numbers.count ? cmd_ctx.numbers.items[0] - 1 : 0;
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    if (instance->socket) {
      if (i == target) {
        instance->full_screen = !instance->full_screen;
        overlap_write(instance, MPV_WRITE, "cycle", "fullscreen", NULL);
      } else {
        overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
      }
    }
  }
}

static void cmd_maximize_validator(void) {
  const size_t n = cmd_ctx.numbers.count;
  if (n > 1) {
    set_preview(false, "maximize supports 1 screen, not %zu", n);
    return;
  }
  size_t screen = 1;
  if (n) {
    const size_t target = cmd_ctx.numbers.items[0];
    if (target > cmd_ctx.layout->count) {
      set_preview(false, "cannot maximize screen %zu, layout only has %zu screens",
                  target, cmd_ctx.layout->count);
      return;
    }
    screen = target;
  }
  set_preview(true, "maximize screen %zu", screen);
  cmd_ctx.executor = cmd_maximize_executor;
}

static void cmd_mute_executor(void) {
  mpv_target_foreach(i, instance) {
    overlap_write(instance, MPV_WRITE, "cycle", "mute", NULL);
  }
}

static void cmd_mute_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "mute/unmute %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_mute_executor;
}

static void cmd_autoplay_executor(void) {
  const char *duration = cmd_ctx.unicode;
  char *p = cmd_ctx.unicode;
  int64_t seconds = -1;
  if (p && cin_isnum(*p)) {
    seconds = *p - '0';
    ++p;
    while (cin_isnum(*p)) {
      seconds *= 10;
      seconds += *p - '0';
      ++p;
    }
    if (*p) *p = '\0';
  }
  if (seconds > 0) {
    mpv_target_foreach(i, instance) {
      if (!instance->autoplay_mpv) {
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "no");
        instance->autoplay_mpv = true;
      }
      overlap_write(instance, MPV_WRITE, "set_property", "length", duration);
      overlap_write(instance, MPV_WRITE, "set_property", "image-display-duration", duration);
      playlist_insert(instance);
    }
  } else if (seconds == 0) {
    mpv_target_foreach(i, instance) {
      if (instance->autoplay_mpv) {
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
        overlap_write(instance, MPV_WRITE, "set_property", "length", "none");
      }
      instance->autoplay_mpv = false;
    }
  } else {
    mpv_target_foreach(i, instance) {
      if (!instance->autoplay_mpv) {
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "no");
        instance->autoplay_mpv = true;
      } else {
        overlap_write(instance, MPV_WRITE, "set_property", "length", "none");
      }
      // NOTE: default=5 https://mpv.io/manual/stable/#options-image-display-duration
      overlap_write(instance, MPV_WRITE, "set_property", "image-display-duration", "5");
      playlist_insert(instance);
    }
  }
}

static void cmd_autoplay_validator(void) {
  if (!validate_screens()) return;
  int64_t seconds = -1;
  if (cmd_ctx.unicode) {
    char *p = cmd_ctx.unicode;
    if (cin_isnum(*p)) {
      seconds = *p - '0';
      ++p;
    }
    while (cin_isnum(*p)) {
      seconds *= 10;
      seconds += *p - '0';
      ++p;
    }
    if (*p) {
      const ptrdiff_t pos = p - cmd_ctx.unicode;
      set_preview(false, "unexpected character '%c' at position %lld in argument", *p, pos + 1);
      return;
    }
  }
  if (seconds < 0) set_preview(true, "autoplay when media ends %s", cmd_ctx.targets.items);
  else if (seconds == 0) set_preview(true, "turn off autoplay %s", cmd_ctx.targets.items);
  else set_preview(true, "autoplay with '%lld' second delay %s", seconds, cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_autoplay_executor;
}

static void cmd_lock_executor(void) {
  mpv_target_foreach(i, instance) {
    instance->locked = !instance->locked;
    if (!instance->locked) playlist_play(instance);
    if (instance->autoplay_mpv) overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
    instance->autoplay_mpv = false;
  }
}

static void cmd_lock_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "lock/unlock %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_lock_executor;
}

#define CIN_CONF_FILENAME "cinema.conf"

#define FSTR_RECT "%ldx%ld%+ld%+ld"
#define FSTR_NAME "name = %s" CRLF
#define FSTR_SCREEN "screen = %s" CRLF
#define FSTR_CHAT "chat = " FSTR_RECT CRLF
#define FSTR_RECT_ARGS(rect) \
  ((rect).right - (rect).left), ((rect).bottom - (rect).top), ((rect).left), ((rect).top)
#define FSTR_CHAT_ARGS FSTR_RECT_ARGS(chat.rect)

static void cmd_store_executor(void) {
  Cin_Layout *layout = cmd_ctx.queued_layout;
  char *name = NULL;
  const bool try_overwrite = layout != NULL;
  if (try_overwrite) {
    array_clear(layout);
    name = (char *)layout_strings.items + layout->name_offset;
  } else {
    layout = arena_bump_T1(&arena_console, Cin_Layout);
    assert(cmd_ctx.unicode);
    name = cmd_ctx.unicode;
    setup_layout(name, layout);
  }
  cmd_ctx.layout = layout;
  array_clear(&geometry_buf);
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    if (instance->socket && cin_iswindow(instance->window)) {
      cin_getwindow(instance->window, &instance->rect);
      const int32_t bytes = snprintf(NULL, 0, FSTR_RECT, FSTR_RECT_ARGS(instance->rect)) + 1;
      assert(bytes > 1);
      const uint32_t bytes_u32 = (uint32_t)bytes;
      const uint32_t offset = geometry_buf.count;
      array_grow(&arena_console, &geometry_buf, bytes_u32);
      char *pos = geometry_buf.items + offset;
      snprintf(pos, bytes_u32, FSTR_RECT, FSTR_RECT_ARGS(instance->rect));
      setup_screen(pos, layout);
      assert(geometry_buf.items[geometry_buf.count - 1] == '\0');
      geometry_buf.items[geometry_buf.count - 1] = ',';
    }
  }
  if (geometry_buf.count > 0) geometry_buf.items[--geometry_buf.count] = '\0';
  char *buf = NULL;
  uint32_t buf_bytes = 0;
  const bool has_chat = cin_iswindow(chat.window);
  if (has_chat) {
    cin_getwindow(chat.window, &chat.rect);
    layout->chat_rect = chat.rect;
  }
  if (!try_overwrite) goto append;
  int32_t scope_line = layout->scope_line;
  const uint32_t name_len = layout->name_len - 1;
  FILE *file = fopen(CIN_CONF_FILENAME, "rb");
  if (!file) {
    log_last_error("Failed to open file '%s'", CIN_CONF_FILENAME);
  } else {
    fseek(file, 0, SEEK_END);
    assert(ftell(file) > 0);
    buf_bytes = (uint32_t)ftell(file);
    rewind(file);
    buf = arena_bump_T(&arena_console, char, buf_bytes + 1U);
    fread(buf, sizeof(char), buf_bytes, file);
    fclose(file);
    buf[buf_bytes] = '\0';
    const char *p = buf;
    const char *tail = buf + buf_bytes;
    int32_t bottom_line = 1;
    while (bottom_line < scope_line && (p = memchr(p, '\n', (size_t)(tail - p)))) {
      ++p;
      ++bottom_line;
    }
    if (!p || strncmp(p, "[layout]", cin_strlen("[layout]")) != 0) goto append;
    p += cin_strlen("[layout]");
    const char *overwrite_start = p;
    const char *overwrite_end = overwrite_start;
    const char *last_name = NULL;
    int32_t line_breaks = 0;
    while ((p = memchr(p, '\n', (size_t)(tail - p)))) {
      ++line_breaks;
      overwrite_end = ++p;
      if (*p == '[') break;
      if (strncmp(p, "name", cin_strlen("name")) == 0) last_name = p;
    }
    if (!last_name) goto append;
    last_name += cin_strlen("name");
    while (*last_name == ' ') ++last_name;
    if (*last_name != '=') goto append;
    else ++last_name;
    while (*last_name == ' ') ++last_name;
    if (strncmp(last_name, name, name_len) != 0) goto append;
    size_t available_bytes = (size_t)(overwrite_end - overwrite_start);
    size_t needed_chat_bytes = 0;
    char *overwrite = (char *)overwrite_start;
    const int32_t name_bytes = sprintf(overwrite, CRLF FSTR_NAME, name);
    overwrite += (size_t)name_bytes;
    available_bytes -= (size_t)name_bytes;
    if (has_chat) {
      const int32_t bytes = snprintf(NULL, 0, FSTR_CHAT, FSTR_CHAT_ARGS);
      assert(bytes > 0);
      const size_t bytes_size = (size_t)bytes;
      if (bytes_size > available_bytes) {
        needed_chat_bytes = bytes_size;
      } else {
        snprintf(overwrite, bytes_size + 1U, FSTR_CHAT, FSTR_CHAT_ARGS);
        overwrite += bytes_size;
        available_bytes -= bytes_size;
      }
    }
    const int32_t screen_bytes = snprintf(NULL, 0, FSTR_SCREEN CRLF, geometry_buf.items);
    assert(screen_bytes > 0);
    const size_t screen_bytes_size = (size_t)screen_bytes;
    if (needed_chat_bytes || screen_bytes_size > available_bytes) {
      const size_t needed_bytes = needed_chat_bytes + screen_bytes_size;
      const size_t growth_bytes = needed_bytes - available_bytes;
      const size_t new_buf_bytes = buf_bytes + growth_bytes;
      const size_t overwrite_pos = (size_t)(overwrite - buf);
      const char *prev_buf = buf;
      buf = arena_bump_T(&arena_console, char, (uint32_t)new_buf_bytes + 1U);
      memcpy(buf, prev_buf, overwrite_pos);
      const size_t new_overwrite_end = overwrite_pos + screen_bytes_size;
      const size_t leftover_bytes = (size_t)(tail - overwrite_end);
      memcpy(buf + new_overwrite_end, overwrite_end, leftover_bytes);
      arena_free_pos(&arena_console, (uint8_t *)prev_buf, buf_bytes);
      available_bytes += growth_bytes;
      overwrite = buf + overwrite_pos;
      overwrite_end = buf + new_overwrite_end;
      tail = buf + new_buf_bytes;
      buf_bytes = (uint32_t)new_buf_bytes;
    }
    if (needed_chat_bytes) {
      snprintf(overwrite, needed_chat_bytes + 1U, FSTR_CHAT, FSTR_CHAT_ARGS);
      overwrite += needed_chat_bytes;
      available_bytes -= needed_chat_bytes;
    }
    available_bytes -= screen_bytes_size;
    if (available_bytes) {
      snprintf(overwrite, screen_bytes_size + 1U, FSTR_SCREEN CRLF, geometry_buf.items);
      overwrite += screen_bytes_size;
      const size_t end_bytes = (size_t)(tail - overwrite_end);
      memmove(overwrite, overwrite_end, end_bytes);
      tail -= available_bytes;
    } else {
      snprintf(overwrite, screen_bytes_size + 1U, FSTR_SCREEN CR, geometry_buf.items);
      overwrite += screen_bytes_size - 1U;
      assert(*overwrite == '\0');
      *overwrite++ = '\n';
    }
    const size_t used_bytes = (size_t)(tail - buf);
    file = fopen(CIN_CONF_FILENAME, "wb");
    if (!file) {
      log_last_error("Failed to open file '%s'", CIN_CONF_FILENAME);
    } else {
      fwrite(buf, 1, used_bytes, file);
      fclose(file);
    }
    arena_free_pos(&arena_console, (uint8_t *)buf, buf_bytes);
    const int32_t written_lines = has_chat ? 5 : 4;
    const int32_t line_shift = written_lines - line_breaks;
    if (line_shift) {
      Radix_Leaf *next = radix_leftmost(layout_tree->root);
      while (next) {
        Cin_Layout *next_layout = (Cin_Layout *)next->base.v;
        if (next_layout->scope_line > scope_line) {
          next_layout->scope_line += line_shift;
        }
        next = radix_next(layout_tree, next);
      }
    }
    return;
  }
append:
  if (buf) arena_free_pos(&arena_console, (uint8_t *)buf, buf_bytes + 1U);
  scope_line = 2;
  file = fopen(CIN_CONF_FILENAME, "ab+");
  if (!file) {
    log_last_error("Failed to open file '%s'", CIN_CONF_FILENAME);
  } else {
    rewind(file);
    int32_t c;
    while ((c = fgetc(file)) != EOF)
      if (c == '\n') ++scope_line;
    fseek(file, 0, SEEK_END);
    layout->scope_line = scope_line;
    fprintf(file, CRLF "[layout]" CRLF);
    fprintf(file, FSTR_NAME, name);
    fprintf(file, FSTR_SCREEN, geometry_buf.items);
    if (has_chat) fprintf(file, FSTR_CHAT, FSTR_CHAT_ARGS);
    fclose(file);
  }
  return;
}

static void cmd_store_validator(void) {
  radix_v layout = NULL;
  const uint8_t *layout_name = NULL;
  (void)cmd_ctx.unicode;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    layout = radix_query(layout_tree, (uint8_t *)cmd_ctx.unicode, len, &layout_name);
    if (layout) {
      assert(layout);
      assert(layout_name);
      set_preview(true, "store layout '%s' (overwrite)", (char *)layout_name);
    } else {
      set_preview(true, "store new layout: '%s'", cmd_ctx.unicode);
    }
  } else {
    Cin_Layout *curr = cmd_ctx.layout;
    char *curr_name = (char *)layout_strings.items + curr->name_offset;
    set_preview(true, "store layout '%s' (overwrite current)", curr_name);
    layout = curr;
  }
  cmd_ctx.queued_layout = (Cin_Layout *)layout;
  cmd_ctx.executor = cmd_store_executor;
}

static void cmd_swap_executor(void) {
  const size_t first = cmd_ctx.numbers.items[0] - 1;
  const size_t second = cmd_ctx.numbers.items[1] - 1;
  log_message(LOG_DEBUG, "Swapping screen %zu with %zu", first, second);
  Cin_Screen *first_screen = NULL;
  Cin_Screen *second_screen = NULL;
  Instance *first_instance = NULL;
  Instance *second_instance = NULL;
  mpv_target_foreach(i, instance) {
    if (i == 0) {
      first_instance = instance;
      first_screen = &cmd_ctx.layout->items[first];
    } else {
      assert(i == 1);
      second_instance = instance;
      second_screen = &cmd_ctx.layout->items[second];
    }
  }
  if (first_screen && second_screen) {
    const char *first_geometry = (char *)screen_strings.items + first_screen->offset;
    const char *second_geometry = (char *)screen_strings.items + second_screen->offset;
    overlap_write(first_instance, MPV_SET_GEOMETRY, "set_property", "geometry", second_geometry);
    overlap_write(second_instance, MPV_SET_GEOMETRY, "set_property", "geometry", first_geometry);
    Cin_Screen tmp = *second_screen;
    *second_screen = *first_screen;
    *first_screen = tmp;
  }
}

static void cmd_swap_validator(void) {
  const size_t n = cmd_ctx.numbers.count;
  const size_t screen_count = cmd_ctx.layout->count;
  if (screen_count < 2) {
    set_preview(false, "swap requires a layout with at least 2 screens");
    return;
  }
  switch (n) {
  case 2: {
    const size_t first = cmd_ctx.numbers.items[0];
    const size_t second = cmd_ctx.numbers.items[1];
    if (first == second) {
      set_preview(false, "swap needs 2 unique screens, not both %zu", first);
      return;
    }
    if (first > screen_count || second > screen_count) {
      set_preview(false, "cannot swap screen %zu with %zu, layout only has %zu screens",
                  first, second, screen_count);
      return;
    }
  } break;
  case 1:
    set_preview(false, "swap misses another number: %zu ... swap", cmd_ctx.numbers.items[0]);
    return;
  case 0: {
    if (cmd_ctx.layout->count != 2) {
      set_preview(false, "swap requires 2 numbers or a layout with 2 screens");
      return;
    }
    array_push(&arena_console, &cmd_ctx.numbers, 1);
    array_push(&arena_console, &cmd_ctx.numbers, 2);
  } break;
  default:
    set_preview(false, "swap must have 2 or 0 numbers, not %zu", n);
    return;
  }
  cmd_ctx.executor = cmd_swap_executor;
  set_preview(true, "swap screen %zu with %zu", cmd_ctx.numbers.items[0], cmd_ctx.numbers.items[1]);
}

static void cmd_clear_executor(void) {
  mpv_target_foreach(i, instance) {
    playlist_set_default(instance);
    playlist_play(instance);
  }
}

static void cmd_clear_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, "clear %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_clear_executor;
}

static void cmd_macro_executor(void) {
  Cin_Macro *macro = cmd_ctx.macro;
  if (macro) {
    const char *p = macro->items;
    const char *tail = macro->items + macro->count - 1;
    do {
      cmd_ctx.executor = NULL;
      cmd_validator validator_fn = parse_command(p);
      if (validator_fn) {
        validator_fn();
        if (cmd_ctx.executor) {
          cmd_ctx.executor();
        } else {
          log_message(LOG_ERROR, "Failed to validate macro command '%s': %s", p, preview.items);
          return;
        }
      } else {
        log_message(LOG_ERROR, "Failed to parse macro command '%s': %s", p, preview.items);
        return;
      }
    } while ((p = memchr(p, '\0', (size_t)(tail - p))) && *++p);
  }
}

static void cmd_macro_validator(void) {
  radix_v macro = NULL;
  const uint8_t *macro_name = NULL;
  if (cmd_ctx.unicode) {
    const size_t len = strlen(cmd_ctx.unicode);
    macro = radix_query(macro_tree, (uint8_t *)cmd_ctx.unicode, len, &macro_name);
    if (!macro) {
      set_preview(false, "macro does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
    assert(macro);
    assert(macro_name);
    set_preview(true, "execute macro '%s'", (char *)macro_name);
  } else {
    set_preview(true, "execute macro '' (nothing)");
  }
  cmd_ctx.macro = (Cin_Macro *)macro;
  cmd_ctx.executor = cmd_macro_executor;
}

#define TWITCH_CHANNEL_MAX_CHARS 25
#define TWITCH_PREFIX "https://www.twitch.tv/"
#define TWITCH_BUF_SIZE (cin_strlen(TWITCH_PREFIX) + TWITCH_CHANNEL_MAX_CHARS + 1)

static void cmd_twitch_executor(void) {
  if (!cmd_ctx.unicode || cin_idle) return;
  static char twitch_buf[TWITCH_BUF_SIZE] = {TWITCH_PREFIX};
  const size_t len = strlen(cmd_ctx.unicode) + 1;
  const char *channel = (const char *)cmd_ctx.unicode;
  memcpy(twitch_buf + cin_strlen(TWITCH_PREFIX), channel, len);
  mpv_target_foreach(i, instance) {
    overlap_write(instance, MPV_LOADFILE, "loadfile", twitch_buf, NULL);
  }
}

static void cmd_twitch_validator(void) {
  if (!validate_screens()) return;
  if (cmd_ctx.unicode && strlen(cmd_ctx.unicode) > TWITCH_CHANNEL_MAX_CHARS) {
    set_preview(false, "twitch channel name is too long (max is %d characters)", TWITCH_CHANNEL_MAX_CHARS);
    return;
  }
  set_preview(true, "" TWITCH_PREFIX "%s %s", cmd_ctx.unicode ? cmd_ctx.unicode : "", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_twitch_executor;
}

static void cmd_copy_executor(void) {
  array_clear(&clipboard);
  clipboard.supply = 0;
  clipboard.demand = 0;
  mpv_target_foreach(i, instance) {
    ++clipboard.demand;
    overlap_write(instance, MPV_GET_PATH, "get_property", "path", NULL);
  }
  return;
}

static void cmd_copy_validator(void) {
  if (!validate_screens()) return;
#ifdef _WIN32
  set_preview(true, "copy to clipboard %s", cmd_ctx.targets.items);
#else
  set_preview(true, "print to console %s", cmd_ctx.targets.items);
#endif
  cmd_ctx.executor = cmd_copy_executor;
}

static void cmd_extra_executor(void) {
  bool reuse = false;
  mpv_lock();
  cache_foreach(&cin_io.instances, Instance, i, old) {
    if (!old->socket) {
      // reuse if free instance available
      reuse = true;
      mpv_spawn(old, SIZE_MAX);
    }
  }
  if (!reuse) {
    Instance *extra = NULL;
    cache_get(&arena_io, &cin_io.instances, extra);
    playlist_set_default(extra);
    mpv_spawn(extra, SIZE_MAX);
  }
}

static void cmd_extra_validator(void) {
  set_preview(true, "add extra screen to layout");
  cmd_ctx.executor = cmd_extra_executor;
}

static void cmd_chat_executor(void) {
  Cin_Layout *layout = cmd_ctx.layout;
  const bool layout_chat = layout->chat_rect.bottom != LONG_MIN;
  if (!layout_chat) {
    const int32_t default_width = 400;
    const int32_t default_height = 600;
    const int32_t default_x = 0;
    const int32_t default_y = 0;
    layout->chat_rect.right = default_width;
    layout->chat_rect.bottom = default_height;
    layout->chat_rect.left = default_x;
    layout->chat_rect.top = default_y;
  }
  mpv_lock();
  chat_reposition(layout);
  mpv_unlock();
}

static void cmd_chat_validator(void) {
  const bool is_showing = cin_iswindow(chat.window);
  set_preview(true, "%s chat", is_showing ? "reposition" : "show");
  cmd_ctx.executor = cmd_chat_executor;
}

#define CIN_LIST_TAGS_PREFIX CR "Tags: "
#define CIN_LIST_TAGS_PREFIX_LEN cin_strlen(CIN_LIST_TAGS_PREFIX)

static void cmd_list_executor(void) {
  Radix_Leaf *next = radix_leftmost(tag_tree->root);
  array_struct(char) output = {0};
  array_set(&arena_console, &output, CIN_LIST_TAGS_PREFIX, CIN_LIST_TAGS_PREFIX_LEN);
  const size_t start_count = output.count;
  while (next) {
    assert(next->len);
    const char *key = (char *)next->key;
    const uint32_t len = (uint32_t)next->len - 1U;
    array_extend(&arena_console, &output, key, len);
    array_push(&arena_console, &output, ',');
    array_push(&arena_console, &output, ' ');
    next = radix_next(tag_tree, next);
  }
  if (output.count > start_count) {
    array_pop(&output);
    output.items[output.count - 1] = '\0';
  }
  assert(output.count);
  cin_write_safe(output.items, output.count);
  array_free_items(&arena_console, &output);
}

static void cmd_list_validator(void) {
  set_preview(true, "list all tags");
  cmd_ctx.executor = cmd_list_executor;
}

static void cmd_quit_executor(void) {
  chat_kill();
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    log_message(LOG_DEBUG, "Closing Window=%lu", instance->window);
    overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
  }
  clear_preview(0);
  cursor_curr();
  show_cursor();
#ifdef _WIN32
  SetConsoleMode(repl.in, repl.in_mode);
  SetConsoleMode(repl.out, repl.out_mode);
#else
  tcsetattr(STDIN_FILENO, TCSANOW, &repl.modes);
  if (pxlib) {
    if (pxdisplay) {
      pXCloseDisplay(pxdisplay);
    }
    dlclose(pxlib);
  }
#endif
  exit(1);
}

static void cmd_quit_validator(void) {
  set_preview(true, "quit (also closes screens)");
  cmd_ctx.executor = cmd_quit_executor;
}

#define CINEMA_VERSION_MAJOR 2
#define CINEMA_VERSION_MINOR 0
#define CINEMA_VERSION_PATCH 0
#define CINEMA_VERSION_STRING "v2.0.0"

static bool init_commands(void) {
  radix_v layout_v = radix_query(layout_tree, (const uint8_t *)"", 0, NULL);
  if (!layout_v) {
    log_message(LOG_ERROR, "No layouts found in config file");
    return false;
  }
  cmd_ctx.layout = (Cin_Layout *)layout_v;
  cmd_ctx.queued_layout = cmd_ctx.layout;
  cmd_ctx.trie = patricia_node(&arena_console, NULL, 0);
  array_init(&arena_console, &cmd_ctx.numbers, COMMAND_NUMBERS_CAP);
  const char *commands_note = CR "Cinema " CINEMA_VERSION_STRING " - Available commands:" CRLF "  "
                                 "Note: optional arguments before/after in brackets []" CRLF;
  const uint32_t commands_note_len = (uint32_t)strlen(commands_note);
  array_extend(&arena_console, &cmd_ctx.help, commands_note, commands_note_len);
  register_cmd("autoplay", "Autoplay media [(1 2 ..) autoplay (seconds)]", cmd_autoplay_validator);
  register_cmd("chat", "Show chat (see store command)", cmd_chat_validator);
  register_cmd("clear", "Clear tag/term [(1 2 ..) clear]", cmd_clear_validator);
  register_cmd("copy", "Copy url(s) to clipboard [(1 2 ..) copy]", cmd_copy_validator);
  register_cmd("extra", "Adds an extra screen (see store command)", cmd_extra_validator);
  register_cmd("help", "Show all commands", cmd_help_validator);
  register_cmd("hide", "Hide media with term [hide term]", cmd_hide_validator);
  register_cmd("idle", "Make commands (not) play media [idle]", cmd_idle_validator);
  register_cmd("kill", "Kill screen(s) and chat [(1 2 ..) kill]", cmd_kill_validator);
  register_cmd("layout", "Change layout to name [layout (name)]", cmd_layout_validator);
  register_cmd("list", "Show all tags", cmd_list_validator);
  register_cmd("lock", "Lock/unlock screen contents [(1 2 ..) lock]", cmd_lock_validator);
  register_cmd("macro", "Execute macro [macro (name)]", cmd_macro_validator);
  register_cmd("maximize", "Maximize and close others [(1) maximize]", cmd_maximize_validator);
  register_cmd("mute", "Mute screen(s) [(1 2 ..) mute]", cmd_mute_validator);
  register_cmd("quit", "Close screens and quit Cinema", cmd_quit_validator);
  register_cmd("search", "Limit media to term [(1 2 ..) search (term)]", cmd_search_validator);
  register_cmd("shuffle", "Shuffle media [(1 2 ..) (shuffle)]", cmd_shuffle_validator);
  register_cmd("store", "Store layout in cinema.conf [store (layout)]", cmd_store_validator);
  register_cmd("swap", "Swap screen contents [(1 2) swap]", cmd_swap_validator);
  register_cmd("tag", "Limit media to tag [(1 2 ..) tag (name)]", cmd_tag_validator);
  register_cmd("twitch", "Show channel [(1 2 ..) twitch (channel)]", cmd_twitch_validator);
  return true;
}

static void execute_startup_macros(void) {
  array_foreach(&startup_macros, Cin_Macro *, i, macro) {
    cmd_ctx.macro = macro;
    cmd_macro_executor();
  }
  array_clear(&cmd_ctx.numbers);
  cmd_shuffle_validator();
  set_preview(true, "press enter to shuffle (h for help)");
  set_preview_row(repl.home.Y + 1);
  log_preview();
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  if (!init_os()) cin_exit(1);
  if (!init_repl()) cin_exit(1);
#ifdef _WIN32
  if (!InitializeCriticalSectionAndSpinCount(&log_lock, 0)) cin_exit(1);
#endif
  if (!init_config(CIN_CONF_FILENAME)) cin_exit(1);
  if (!init_commands()) cin_exit(1);
#ifdef _WIN32
  if (!init_executables()) cin_exit(1);
#endif
  if (!init_documents()) cin_exit(1);
  if (!init_mpv()) cin_exit(1);
#ifndef _WIN32
  if (!init_xlib()) pxlib = NULL;
#endif
  execute_startup_macros();
  for (;;) {
    show_cursor();
    uint8_t byte;
    if (!term_read(&byte, 1, false)) {
      break;
    }
    hide_cursor();
    const COORD size_change = term_get_size(&repl.size);
    if (size_change.X) {
      lock_logs();
      term_get_cursor(&repl.cursor);
      const uint32_t curr_index = cursor_to_index(repl.cursor, (uint32_t)repl.size.X);
      const uint32_t i = curr_index > repl.msg_index ? curr_index - repl.msg_index : curr_index;
      const short new_home_y = index_y(i, (uint32_t)repl.size.X);
      repl.home.Y = new_home_y;
      unlock_logs();
    } else if (size_change.Y < 0) {
      repl.home.Y = min(repl.home.Y, repl.size.Y - 1);
    }
    bool new_preview = true;
    if (byte == TERM_ESC) {
      uint8_t term_sequence[TERM_SEQUENCE_MAX];
      const int32_t len = term_read(term_sequence, sizeof(term_sequence), true);
      new_preview = term_proc_sequence(term_sequence, len);
    } else if ((byte & 0x80) != 0) {
      int32_t bytes = 1;
      if ((byte & 0xE0) == 0xC0) bytes = 2;
      else if ((byte & 0xF0) == 0xE0) bytes = 3;
      else if ((byte & 0xF8) == 0xF0) bytes = 4;
      uint8_t unicode[4] = {byte};
      const int32_t len = term_read(unicode + 1, bytes - 1, false);
      new_preview = term_proc_unicode(unicode, len + 1);
    } else {
      new_preview = term_proc_char((char)byte);
    }
    if (!new_preview) continue;
    short tail_row = index_y_repl(repl.msg->count);
    tail_row = min(tail_row, repl.size.Y);
    const short preview_row = min(tail_row + 1, repl.size.Y);
    const short preview_shift = preview_row - preview.pos.Y;
    if (tail_row == repl.size.Y) {
      const short tail_col = index_x_repl(repl.msg->count);
      if (tail_col != 0) {
        // clear preview and make space for new line
        const short leftover = (short)preview.len - tail_col;
        term_set_cursor((COORD){.X = tail_col, .Y = tail_row});
        cin_writef(CSI "%hdX\n", leftover);
        --repl.home.Y;
      }
      cursor_curr();
    } else if (preview_shift < 0) {
      // cursor went up preview_shift rows
      clear_preview(0);
      cursor_curr();
    } else if (preview_shift == 1) {
      // cursor went down 1 row
      const short preview_col = index_x_repl(repl.msg->count);
      if ((short)preview.len > preview_col) {
        clear_preview(preview_col);
      }
    }
    const uint32_t prev_len = preview.len;
    set_preview_row(preview_row);
    update_preview();
    log_preview();
    if (preview_shift == 0 && prev_len > preview.len) {
      const uint32_t leftover = prev_len - preview.len;
      const COORD clear_pos = {.X = (short)preview.len, .Y = preview_row};
      term_clear(clear_pos, leftover, true, false);
      cursor_curr();
    }
  }
  return 0;
}
