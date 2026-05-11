#include "io.h"
#include "config/command.h"
#include "os/window.h"

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

bool cin_idle = false;

void playlist_setup_shuffle(Playlist *playlist) {
  const uint32_t n = playlist->count;
  assert(n);
  const uint32_t fy = n - 1;
  array_shuffle_fisher_yates(playlist, int32_t, fy, 1);
  playlist->next_index = 0;
}

void playlist_shuffle(Playlist *playlist) {
  const uint32_t n = playlist->count;
  uint32_t s = 0;
  uint32_t fy = 0;
  if (n > 2) {
    s = n - 1;
    static const uint32_t SATTOLO_FACTOR = 5;
    const uint32_t remainder = s / SATTOLO_FACTOR;
    assert(playlist->targets);
    const uint32_t tail = max(playlist->targets, remainder);
    const uint32_t clamped_tail = min(tail, s);
    const uint32_t diff = s - clamped_tail;
    const uint32_t clamped_diff = max(1, diff);
    fy = s - clamped_diff;
    assert(fy >= 1);
    assert(s > fy);
  }
  array_shuffle_fisher_yates(playlist, int32_t, fy, 1);
  array_shuffle_sattolo(playlist, int32_t, s, fy);
  playlist->next_index = 0;
}

void playlist_set(Instance *instance, Playlist *playlist) {
  Playlist *prev = instance->playlist;
  Playlist *next = playlist;
  ++next->targets;
  instance->playlist = next;
  if (prev) {
    assert(prev->targets > 0);
    --prev->targets;
    const bool prev_empty = prev->targets == 0;
    const bool prev_not_default = prev != &media.default_playlist;
    const bool prev_from_search = !prev->from_tag;
    if (prev_empty && prev_not_default && prev_from_search) {
      assert(prev != next);
      Table_Key key = {.strings = media.search_patterns.items,
                       .pos = prev->search_pos,
                       .len = prev->search_len};
      table_delete(&media.search_table, &key);
      array_free_items(&arena_docs, prev);
      cache_put(&media.playlists, prev);
    }
  }
}

void playlist_set_default(Instance *instance) {
  playlist_set(instance, &media.default_playlist);
}

void playlist_play_core(Instance *instance, const char *arg) {
  if (instance->locked || cin_idle) return;
  assert(instance->playlist);
  Playlist *playlist = instance->playlist;
  const uint32_t index = instance->playlist->next_index;
  char *url = (char *)docs.items + playlist->items[index];
  assert(url);
  assert(*url);
  overlap_write(instance, MPV_LOADFILE, "loadfile", url, arg);
  if (++instance->playlist->next_index == instance->playlist->count) {
    playlist_shuffle(instance->playlist);
  }
}

void playlist_insert(Instance *instance) {
  playlist_play_core(instance, "insert-next");
}

void playlist_play(Instance *instance) {
  if (instance->autoplay_mpv) {
    playlist_insert(instance);
    overlap_write(instance, MPV_WRITE, "playlist-next", NULL, NULL);
  } else {
    playlist_play_core(instance, NULL);
  }
}

#define CIN_MPVKEY_REQUEST CIN_MPVKEY("request_id")
#define CIN_MPVKEY_EVENT CIN_MPVKEY("event")
#define CIN_MPVKEY_DATA CIN_MPVKEY("data")
#define CIN_MPVKEY_REASON CIN_MPVKEY("reason")

size_t mpv_supply = 0;
size_t mpv_demand = 0;

void mpv_kill(Instance *instance) {
  assert(instance->playlist);
  --instance->playlist->targets;
#ifndef _WIN32
  close(instance->socket);
#endif
  Read_Buffer *buf_head = instance->buf_head;
  Read_Buffer *buf_tail = instance->buf_tail;
  Instance *next = instance->next;
  memset(instance, 0, sizeof(Instance));
  playlist_set_default(instance);
  instance->buf_head = buf_head;
  instance->buf_tail = buf_tail;
  instance->next = next;
}

void mpv_lock(void) {
  mpv_supply = 0;
  mpv_demand = 0;
#ifdef _WIN32
  LockSetForegroundWindow(LSFW_LOCK);
#endif
}

void mpv_unlock(void) {
#ifdef _WIN32
  LockSetForegroundWindow(LSFW_UNLOCK);
#endif
}

void iocp_parse(Instance *instance, const char *buf_start, size_t buf_offset) {
  const char *buf = buf_start + buf_offset;
  char *p = NULL;
  if ((p = (char *)strstr(buf, CIN_MPVKEY_EVENT))) {
    p += cin_strlen(CIN_MPVKEY_EVENT);
    assert(*p == '\"');
    ++p;
    if (CIN_MPVVAL(p, "end-file")) {
      if ((p = strstr(p, CIN_MPVKEY_REASON))) {
        p += cin_strlen(CIN_MPVKEY_REASON);
        assert(*p == '\"');
        ++p;
        if (CIN_MPVVAL(p, "quit")) mpv_kill(instance);
        // NOTE: When a file fails to load, especially with offline twitch streams,
        // the instance becomes idle. We choose to resolve this by trying the next
        // entry in the playlist. Maybe make this an option instead.
        else if (CIN_MPVVAL(p, "error")) playlist_play(instance);
      }
    } else if (CIN_MPVVAL(p, "file-loaded")) {
      if (instance->autoplay_mpv) playlist_insert(instance);
    }
  } else if ((p = (char *)strstr(buf, CIN_MPVKEY_REQUEST))) {
    p += cin_strlen(CIN_MPVKEY_REQUEST);
    assert(cin_isnum(*p));
    int64_t req_id = *p - '0';
    while (cin_isnum(*++p)) req_id = (req_id * 10) + (*p - '0');
    Overlapped_Write *msg = (Overlapped_Write *)(uintptr_t)req_id;
    assert(msg);
    assert(msg->bytes);
    log_message(LOG_DEBUG, "Recovered original write: %p (%zu bytes)", msg, msg->bytes);
    switch (msg->ovl_ctx.type) {
    case MPV_WINDOW_ID: {
      if (++mpv_supply == mpv_demand) mpv_unlock();
      char *data = (char *)strstr(buf, CIN_MPVKEY_DATA);
      if (!data) {
        // NOTE: If the request was delivered before mpv managed to create
        // the window, it will return something like "error: property
        // unavailable": retry.
        static const long GET_WINDOW_DELAY = 200;
        os_sleep(GET_WINDOW_DELAY);
        overlap_write(instance, MPV_WINDOW_ID, "get_property", "window-id", NULL);
        break;
      }
      assert(data);
      data += cin_strlen(CIN_MPVKEY_DATA);
      assert(cin_isnum(*data));
      intptr_t window_id = 0;
      for (; cin_isnum(*data); ++data) window_id = (window_id * 10) + *data - '0';
      assert(cin_iswindow((HWND)window_id));
      assert(cin_isvisible((HWND)window_id));
      instance->window = (HWND)window_id;
      cin_getwindow(instance->window, &instance->rect);
    } break;
    case MPV_QUIT:
      mpv_kill(instance);
      break;
    case MPV_GET_PATH: {
      char *data = (char *)strstr(buf, CIN_MPVKEY_DATA);
      assert(data);
      data += cin_strlen(CIN_MPVKEY_DATA);
      assert(*data == '"');
      ++data;
      char *tail = strchr(data, '"');
      assert(tail);
      const int32_t len = (int32_t)(tail - data);
      assert(len >= 0);
      array_push(&arena_iocp_thread, &clipboard, CIN_CLIPBOARD_ENCLOSER);
      char prev = '\0';
      for (uint32_t i = 0; i < (uint32_t)len; ++i) {
        const char curr = data[i];
        if (prev != '\\' || curr != '\\') {
          array_push(&arena_iocp_thread, &clipboard, curr);
        }
        prev = curr;
      }
      array_push(&arena_iocp_thread, &clipboard, CIN_CLIPBOARD_ENCLOSER);
      array_push(&arena_iocp_thread, &clipboard, CIN_CLIPBOARD_SEPARATOR);
      if (++clipboard.supply == clipboard.demand) {
        clipboard.supply = 0;
        clipboard.demand = 0;
        if (clipboard.count) clipboard.items[clipboard.count - 1] = '\0';
        cin_write_safe(clipboard.items, clipboard.count - 1);
        copy_clipboard();
      }
    } break;
    default:
      break;
    }
    cache_put(&cin_io.writes, msg);
  }
}

void iocp_process(Instance *instance, size_t bytes) {
  assert(!memchr(instance->buf_tail->buf, '\0', instance->buf_tail->bytes));
  assert(sizeof(instance->buf_tail->buf) - instance->buf_tail->bytes >= bytes);
  char *lf = memchr(instance->buf_tail->buf + instance->buf_tail->bytes, '\n', bytes);
  instance->buf_tail->bytes += bytes;
  if (lf) {
    bool multi = instance->buf_tail != instance->buf_head;
    assert((lf - instance->buf_tail->buf) >= 0);
    size_t tail_pos = (size_t)(lf - instance->buf_tail->buf);
    char *buf = instance->buf_head->buf;
    size_t len = instance->buf_head->bytes;
    if (multi) {
      for (Read_Buffer *b = instance->buf_head->next; b; b = b->next) {
        assert(!memchr(b->buf, '\0', b->bytes));
        len += b->bytes;
      }
      char *contiguous_buf = arena_bump_T(&arena_iocp_thread, char, (uint32_t)len);
      size_t offset = 0;
      for (Read_Buffer *b = instance->buf_head; b != instance->buf_tail; b = b->next) {
        assert(b);
        memcpy(contiguous_buf + offset, b->buf, b->bytes);
        offset += b->bytes;
        b->bytes = 0;
      }
      memcpy(contiguous_buf + offset, instance->buf_tail, instance->buf_tail->bytes);
      instance->buf_tail->bytes -= tail_pos;
      instance->buf_tail->bytes -= 1;
      tail_pos += offset;
      buf = contiguous_buf;
    }
    size_t buf_offset = 0;
    for (;;) {
      *lf = '\0';
      ++tail_pos;
      log_message(LOG_DEBUG, "Message (%p): %.*s", instance, tail_pos, buf + buf_offset);
      iocp_parse(instance, buf, buf_offset);
      if (tail_pos >= len) break;
      lf = memchr(buf + tail_pos, '\n', len - tail_pos);
      if (!lf) break;
      buf_offset = tail_pos;
      assert((lf - buf) >= 0);
      tail_pos = (size_t)(lf - buf);
    }
    const size_t remainder = tail_pos < len ? len - tail_pos : 0;
    memcpy(instance->buf_head, buf + tail_pos, remainder);
    instance->buf_head->bytes = remainder;
    instance->buf_tail = instance->buf_head;
    if (multi) arena_free_pos(&arena_iocp_thread, (uint8_t *)buf, (uint32_t)len);
  } else {
    if (instance->buf_tail->next) instance->buf_tail->next->bytes = 0;
    else instance->buf_tail->next = arena_bump_T1(&arena_iocp_thread, Read_Buffer);
    instance->buf_tail = instance->buf_tail->next;
  }
}

bool init_mpv(void) {
  arena_chunk_init(&arena_io, CIN_IO_ARENA_CAP);
  arena_chunk_init(&arena_iocp_thread, CIN_IO_ARENA_CAP);
  cache_init_core(&arena_io, &cin_io.writes, 1, true);
  cache_init_core(&arena_io, &cin_io.instances, 1, false);
  cache_init_core(&arena_docs, &media.playlists, 1, true);
  Playlist *default_playlist = &media.default_playlist;
  array_to_pow1(&arena_docs, default_playlist);
  playlist_setup_shuffle(default_playlist);
  Instance *head_instance = cin_io.instances.head;
  playlist_set_default(head_instance);
  iocp_start();
  return true;
}

void mpv_spawn(Instance *instance, size_t index) {
  char geometry_str[CIN_MPVCALL_GEOMETRY_LEN] = {"--geometry="};
  char server_str[CIN_MPVCALL_SERVER_LEN] = {"--input-ipc-server=" CIN_MPVCALL_PIPE};
  char *mpv_flags[] = {
      "mpv",
      "--idle",
      "--config-dir=./",
      server_str,
      geometry_str,
      NULL};
  static_assert((sizeof(mpv_flags) / CIN_PTR) == 6, "expected 6 elements including sentinel");
  const bool extra = index == SIZE_MAX;
  if (extra) index = cmd_ctx.layout->count;
  char *server_flag = mpv_flags[3];
  assert(strstr(server_flag, "ipc-server") && "check flags");
  const size_t server_buf_len = strlen(server_flag);
  const size_t right = server_buf_len + CIN_MPVCALL_DIGITS;
  size_t left = right;
  size_t j = index;
  do {
    server_flag[left--] = '0' + (j % 10);
    j /= 10;
  } while (j);
  const size_t digits = right - left++;
  const size_t start = server_buf_len;
  for (; j < digits; ++j) server_flag[start + j] = server_flag[left + j];
  Cin_Screen screen = cmd_ctx.layout->items[extra ? 0 : index];
  if (extra) array_push(&arena_console, cmd_ctx.layout, screen);
  // screen.len actually includes null-terminator
  char *screen_utf8 = (char *)screen_strings.items + screen.offset;
  const int32_t len = (int32_t)screen.len;
  if (len > (int32_t)CIN_MPVCALL_GEOMETRY_LEN) {
    char *layout_name = (char *)layout_strings.items + cmd_ctx.layout->name_offset;
    printf("Cinema crashed because the config value of screen %zu in layout '%s' is "
           "too large (%d > %u chars): %.*s (first %u shown)",
           index + 1, layout_name, len, CIN_MPVCALL_GEOMETRY_LEN, CIN_MPVCALL_GEOMETRY_LEN,
           screen_utf8, CIN_MPVCALL_GEOMETRY_LEN);
    exit(1);
  }
  char *geometry_flag = mpv_flags[4];
  assert(strstr(geometry_flag, "geometry") && "check flags");
  const size_t geometry_buf_len = strlen(geometry_flag);
  snprintf(geometry_flag + geometry_buf_len, (size_t)len, "%.*s", len, screen_utf8);
  log_message(LOG_DEBUG, "Spawning instance: %s %s %s %s %s",
              mpv_flags[0], mpv_flags[1], mpv_flags[2], mpv_flags[3], mpv_flags[4]);
  char *socket_name = strchr(server_flag, '=');
  assert(socket_name);
  assert(socket_name + 1);
  ++socket_name;
  mpv_spawn_internal(instance, mpv_flags, socket_name);
  assert(instance->playlist);
  playlist_play(instance);
  overlap_write(instance, MPV_WINDOW_ID, "get_property", "window-id", NULL);
  ++mpv_demand;
}

struct Chat chat = {0};

void chat_reposition(const Cin_Layout *layout) {
  RECT chat_rect = layout->chat_rect;
  const bool should_show = chat_rect.bottom != LONG_MIN;
  const bool is_showing = cin_iswindow(chat.window);
  if (should_show) {
    if (is_showing) {
      cin_movewindow(chat.window, chat_rect);
    } else {
      static const size_t CHAT_REPOSITION_TRIES = 50;
      static const long CHAT_REPOSITION_DELAY = 200;
      const size_t pid = chat_spawn(layout);
      for (size_t i = 0; i < CHAT_REPOSITION_TRIES; ++i) {
        chat.window = chat_get_window(pid, "Chatterino");
        if (cin_isvisible(chat.window)) {
          cin_movewindow(chat.window, chat_rect);
          break;
        }
        os_sleep(CHAT_REPOSITION_DELAY);
      }
    }
  } else if (is_showing) {
    chat_kill();
  }
}

bool term_proc_sequence(const uint8_t *sequence, int32_t len) {
  assert(len >= 0);
  bool new_preview = true;
  log_message(LOG_TRACE, "Terminal sequence (len %d): %.*s", len, len, sequence);
  if (len == 0) {
    // ESC
    clear_full();
    repl.msg_index = 0;
    array_clear(repl.msg);
  } else {
    int32_t i = 0;
    if (sequence[i] == TERM_LBRACKET) {
      if (++i == len) goto fail;
      switch (sequence[i]) {
      case TERM_HOME:
        if (++i != len) goto fail;
        cursor_home();
        repl.msg_index = 0;
        new_preview = false;
        break;
      case TERM_END:
        if (++i != len) goto fail;
        repl.msg_index = repl.msg->count;
        cursor_curr();
        new_preview = false;
        break;
      case TERM_DELETE: {
        if (++i == len) goto fail;
        if (repl.msg_index == repl.msg->count) {
          new_preview = false;
          break;
        }
        bool control = sequence[i] == TERM_SEMICOLON;
        if (control) i += 2;
        if (sequence[i] != TERM_TILDE) goto fail;
        if (++i != len) goto fail;
        uint32_t right = repl.msg_index;
        if (control) {
          while (right < repl.msg->count && repl.msg->items[right] != TERM_SPACE) ++right;
          while (right < repl.msg->count && repl.msg->items[++right] == TERM_SPACE) {
          }
        } else {
          ++right;
        }
        const uint32_t leftover = repl.msg->count - right;
        const uint32_t deleted = right - repl.msg_index;
        repl.msg->count -= deleted;
        if (leftover) {
          memmove(&repl.msg->items[repl.msg_index], &repl.msg->items[right], leftover);
          cin_write(repl.msg->items + repl.msg_index, leftover);
          clear_tail(deleted, false);
        } else {
          clear_tail(deleted, true);
        }
        cursor_curr();
      } break;
      case TERM_UP: {
        if (++i != len) goto fail;
        if (!repl.msg->prev) {
          new_preview = false;
          break;
        }
        const uint32_t prev_count = repl.msg->count;
        array_resize(&arena_console, repl.msg, repl.msg->prev->count);
        memcpy(repl.msg->items, repl.msg->prev->items, repl.msg->prev->count);
        repl.msg_index = repl.msg->count;
        repl.msg->next = repl.msg->prev->next;
        repl.msg->prev = repl.msg->prev->prev;
        cursor_home();
        cin_write(repl.msg->items, repl.msg->count);
        if (repl.msg->count < prev_count) {
          const uint32_t to_clear = prev_count - repl.msg->count;
          clear_tail(to_clear, false);
        }
      } break;
      case TERM_DOWN: {
        if (++i != len) goto fail;
        if (repl.msg->next) {
          const uint32_t prev_count = repl.msg->count;
          Console_Message *next = repl.msg->next;
          array_resize(&arena_console, repl.msg, next->count);
          memcpy(repl.msg->items, next->items, next->count);
          repl.msg->prev = next->prev;
          repl.msg->next = next->next;
          repl.msg_index = repl.msg->count;
          cursor_home();
          cin_write(repl.msg->items, repl.msg->count);
          if (repl.msg->count < prev_count) {
            const uint32_t to_clear = prev_count - repl.msg->count;
            clear_tail(to_clear, false);
          }
        } else {
          clear_full();
          repl.msg->prev = repl.msg_tail;
          array_clear(repl.msg);
          repl.msg_index = 0;
        }
      } break;
      case TERM_PAGEUP: {
        if (++i == len || sequence[i] != TERM_TILDE || ++i != len) goto fail;
        if (!repl.msg->prev) {
          new_preview = false;
          break;
        }
        Console_Message *head = repl.msg->prev;
        while (head->prev) head = head->prev;
        const uint32_t prev_count = repl.msg->count;
        array_resize(&arena_console, repl.msg, head->count);
        memcpy(repl.msg->items, head->items, head->count);
        repl.msg_index = repl.msg->count;
        repl.msg->next = head->next;
        cursor_home();
        cin_write(repl.msg->items, repl.msg->count);
        if (repl.msg->count < prev_count) {
          const uint32_t to_clear = prev_count - repl.msg->count;
          clear_tail(to_clear, false);
        }
      } break;
      case TERM_PAGEDOWN: {
        if (++i == len || sequence[i] != TERM_TILDE || ++i != len) goto fail;
        if (repl.msg_tail) {
          const uint32_t prev_count = repl.msg->count;
          Console_Message *next = repl.msg_tail;
          array_resize(&arena_console, repl.msg, next->count);
          memcpy(repl.msg->items, next->items, next->count);
          repl.msg->prev = next->prev;
          repl.msg->next = next->next;
          repl.msg_index = repl.msg->count;
          cursor_home();
          cin_write(repl.msg->items, repl.msg->count);
          if (repl.msg->count < prev_count) {
            const uint32_t to_clear = prev_count - repl.msg->count;
            clear_tail(to_clear, false);
          }
        } else {
          clear_full();
          array_clear(repl.msg);
          repl.msg_index = 0;
        }
      } break;
      case TERM_LEFT:
        if (++i != len) goto fail;
        if (repl.msg_index) {
          --repl.msg_index;
          cursor_curr();
        }
        new_preview = false;
        break;
      case TERM_RIGHT:
        if (++i != len) goto fail;
        if (repl.msg_index < repl.msg->count) {
          ++repl.msg_index;
          cursor_curr();
        }
        new_preview = false;
        break;
      case TERM_DEFAULT:
        // handle possible control arrow keys
        if (++i == len || sequence[i] != TERM_SEMICOLON ||
            ++i == len || sequence[i] != TERM_PAGEUP ||
            ++i + 1 != len) goto fail;
        if (sequence[i] == TERM_LEFT) {
          if (repl.msg_index) {
            --repl.msg_index;
            while (repl.msg_index && repl.msg->items[repl.msg_index] == TERM_SPACE) --repl.msg_index;
            while (repl.msg_index && repl.msg->items[repl.msg_index - 1] != TERM_SPACE) --repl.msg_index;
            cursor_curr();
          }
          new_preview = false;
        } else if (sequence[i] == TERM_RIGHT) {
          if (repl.msg_index < repl.msg->count) {
            while (repl.msg_index < repl.msg->count && repl.msg->items[repl.msg_index] != TERM_SPACE) ++repl.msg_index;
            while (repl.msg_index < repl.msg->count && repl.msg->items[++repl.msg_index] == TERM_SPACE) {
            }
            cursor_curr();
          }
          new_preview = false;
        } else {
          goto fail;
        }
        break;
      default:
        goto fail;
        break;
      }
    }
  }
  return new_preview;
fail:
  new_preview = false;
  log_message(LOG_DEBUG, "Terminal sequence incomplete or not supported: %.*s",
              len, (char *)sequence);
  return new_preview;
}

bool term_proc_unicode(const uint8_t *unicode, int32_t len) {
  assert(len > 0);
  log_message(LOG_DEBUG, "Unicode input (len %d): %.*s", len, len, unicode);
  if (len == 1) {
    log_message(LOG_ERROR, "Failed to parse unicode");
    return false;
  }
  if (len == 3 && !memcmp(unicode, TERM_REPLACEMENT, 3)) {
    log_message(LOG_ERROR, "This unicode character is not supported");
    return false;
  }
  const uint32_t len_u32 = (uint32_t)len;
  array_splice(&arena_console, repl.msg, repl.msg_index, unicode, len_u32);
  cin_write(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
  repl.msg_index += len_u32;
  return true;
}

bool term_proc_char(char byte) {
  assert(byte);
  log_message(LOG_TRACE, "Char input: %02hhx", byte);
  bool new_preview = true;
  switch (byte) {
  case TERM_TAB:
  case TERM_LINEFEED:
  case TERM_RETURN: {
    clear_full();
    assert(repl.msg->items);
    uint32_t i = repl.msg->count;
    while (i && isspace(repl.msg->items[i - 1])) --i;
    const bool empty = !i;
    const bool dup = !empty && repl.msg_tail && repl.msg->count == repl.msg_tail->count &&
                     !strncmp(repl.msg->items, repl.msg_tail->items, repl.msg->count);
    if (empty || dup) {
      if (repl.msg_tail) repl.msg->prev = repl.msg_tail;
      repl.msg->next = NULL;
      repl.msg_index = 0;
      array_clear(repl.msg);
    } else {
      // commit to history
      if (repl.msg_tail) {
        repl.msg_tail->next = repl.msg;
        repl.msg->prev = repl.msg_tail;
      }
      repl.msg->next = NULL;
      repl.msg_tail = repl.msg;
      repl.msg = create_console_message();
      repl.msg->prev = repl.msg_tail;
      repl.msg_index = 0;
      array_clear(repl.msg);
    }
    if (cmd_ctx.executor) {
      cmd_ctx.executor();
    }
  } break;
  case TERM_BACK_CTRL:
  case TERM_BACK: {
    if (!repl.msg_index) {
      new_preview = false;
      break;
    }
    uint32_t left = repl.msg_index - 1;
    if (byte == TERM_BACK_CTRL) {
      while (left && repl.msg->items[left] == TERM_SPACE) --left;
      while (left && repl.msg->items[left - 1] != TERM_SPACE) --left;
    }
    if (repl.msg_index < repl.msg->count) {
      memmove(&repl.msg->items[left], &repl.msg->items[repl.msg_index], repl.msg->count - repl.msg_index);
    }
    const uint32_t deleted = repl.msg_index - left;
    repl.msg->count -= deleted;
    repl.msg_index = left;
    const uint32_t leftover = repl.msg->count - repl.msg_index;
    const COORD curr = curr_cursor();
    term_set_cursor(curr);
    if (leftover) {
      cin_write(repl.msg->items + repl.msg_index, leftover);
      const COORD new_curr = index_to_cursor_repl(repl.msg_index + leftover);
      term_clear(new_curr, deleted, false, false);
      term_set_cursor(curr);
    } else {
      term_clear(curr, deleted, false, false);
    }
  } break;
  default:
    if (!byte) {
      new_preview = false;
      break;
    }
    byte = cin_lower(byte);
    array_insert(&arena_console, repl.msg, repl.msg_index, byte);
    cin_write(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
    ++repl.msg_index;
    if (repl.msg_index != repl.msg->count) cursor_curr();
    break;
  }
  return new_preview;
}