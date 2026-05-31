#include <string.h>

#include "config.h"
#include "console/console.h"
#include "console/log.h"

#ifdef _WIN32
#include "console/console_win32.h"
#else
#include <dirent.h>
#include <errno.h>
#include <glob.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "third_party/libsais.h"

Arena arena_docs = {0};
struct Conf_Parser conf_parser = {0};
struct Document_Collection docs = {0};
struct Media media = {0};
struct Directory_Stack dir_stack = {0};
struct Clipboard clipboard = {0};

struct Directory_Strings directory_strings = {0};
struct Directory_Nodes directory_nodes = {0};
struct Layout_Strings layout_strings = {0};
struct Screen_Strings screen_strings = {0};
struct Geometry_Buffer geometry_buf = {0};
struct Startup_Macros startup_macros = {0};

static Robin_Hood_Table dir_table = {0};
static Robin_Hood_Table pat_table = {0};
static Robin_Hood_Table url_table = {0};

Radix_Tree *tag_tree = NULL;
Radix_Tree *layout_tree = NULL;
Radix_Tree *macro_tree = NULL;

bool conf_keycmp(const char *k, Conf_Scope_Type type, Conf_Key *out, bool unique) {
  if (memcmp(k, conf_parser.buf.items, conf_parser.k_len) != 0) return false;
  assert(&conf_scope()->type);
  const size_t v_pos = (size_t)(conf_parser.v - conf_parser.buf.items);
  const uint32_t v_len = (uint32_t)(conf_parser.len - v_pos);
  if (conf_scope()->type != type) {
    conf_parser.error = true;
    char *scope_msg;
    switch (conf_scope()->type) {
    case CONF_SCOPE_ROOT:
      scope_msg = "above any [table]";
      break;
    case CONF_SCOPE_LAYOUT:
      scope_msg = "under a [layout] table";
      break;
    case CONF_SCOPE_MEDIA:
      scope_msg = "under a [media] table";
      break;
    case CONF_SCOPE_MACRO:
      scope_msg = "under a [macro] table";
      break;
    case CONF_SCOPE_SETTINGS:
      scope_msg = "under a [settings] table";
      break;
    default:
      assert(false && "Unexpected type");
      break;
    }
    conf_parser.buf.items[conf_parser.k_len] = '\0';
    log_message(LOG_ERROR, "Unexpected key on line %d: '%s' is not allowed %s",
                conf_parser.line, conf_parser.buf.items, scope_msg);
  } else if (unique) {
    if (out->count > 0) {
      log_message(LOG_WARNING, "Overwriting existing value on line %d for key '%s': %s => %s",
                  conf_parser.line, k, out->items, conf_parser.v);
    }
    array_set(&arena_console, out, conf_parser.v, v_len);
  } else {
    if (out->count > 0) {
      assert(out->items[out->count - 1] == '\0');
      out->items[out->count - 1] = ',';
      array_push(&arena_console, out, ' ');
    }
    array_extend(&arena_console, out, conf_parser.v, v_len);
  }
  return true;
}

bool conf_keyget(void) {
  switch (conf_parser.k_len) {
  case 11:
    if (conf_keycmp("directories", CONF_SCOPE_MEDIA, &conf_scope()->media.directories, false)) return true;
    break;
  case 10:
    if (conf_keycmp("chatterino", CONF_SCOPE_SETTINGS, &conf_scope()->settings.chatterino_path, true)) return true;
    break;
  case 8:
    if (conf_keycmp("patterns", CONF_SCOPE_MEDIA, &conf_scope()->media.patterns, false)) {
      conf_parser.has_patterns = true;
      return true;
    }
    break;
  case 7:
    if (conf_keycmp("command", CONF_SCOPE_MACRO, &conf_scope()->macro.command, false)) return true;
    if (conf_keycmp("startup", CONF_SCOPE_MACRO, &conf_scope()->macro.startup, true)) return true;
    break;
  case 6:
    if (conf_keycmp("screen", CONF_SCOPE_LAYOUT, &conf_scope()->layout.screen, false)) return true;
    break;
  case 5:
    if (conf_keycmp("ytdlp", CONF_SCOPE_SETTINGS, &conf_scope()->settings.ytdlp_path, true)) return true;
    break;
  case 4:
    if (conf_keycmp("urls", CONF_SCOPE_MEDIA, &conf_scope()->media.urls, false)) return true;
    if (conf_keycmp("tags", CONF_SCOPE_MEDIA, &conf_scope()->media.tags, false)) return true;
    if (conf_keycmp("chat", CONF_SCOPE_LAYOUT, &conf_scope()->layout.chat, true)) return true;
    if (conf_scope()->type == CONF_SCOPE_MACRO) {
      if (conf_keycmp("name", CONF_SCOPE_MACRO, &conf_scope()->macro.name, true)) return true;
    } else {
      if (conf_keycmp("name", CONF_SCOPE_LAYOUT, &conf_scope()->layout.name, true)) return true;
    }
    break;
  case 3:
    if (conf_keycmp("mpv", CONF_SCOPE_SETTINGS, &conf_scope()->settings.mpv_path, true)) return true;
    break;
  default:
    break;
  }
  return false;
}

bool conf_scopeget(void) {
  switch (conf_parser.k_len) {
  case 8:
    if (conf_scopecmp("settings", CONF_SCOPE_SETTINGS)) return true;
    break;
  case 6:
    if (conf_scopecmp("layout", CONF_SCOPE_LAYOUT)) return true;
    break;
  case 5:
    if (conf_scopecmp("media", CONF_SCOPE_MEDIA)) return true;
    if (conf_scopecmp("macro", CONF_SCOPE_MACRO)) return true;
    break;
  default:
    break;
  }
  return false;
}

bool parse_config(const char *filename) {
  bool ok = false;
  FILE *file = fopen(filename, "rt");
  if (!file) {
    log_last_error("Failed to open file '%s'", filename);
    return false;
  }
  array_init(&arena_console, &conf_parser.buf, CONF_LINE_CAP);
  array_init(&arena_console, &conf_parser.scopes, CONF_SCOPES_CAP);
  conf_enter_scope(CONF_SCOPE_ROOT);
  conf_parser.line = 1;
  while (fgets(conf_parser.buf.items, (int32_t)conf_parser.buf.capacity, file)) {
    conf_parser.len = strlen(conf_parser.buf.items);
    assert(conf_parser.buf.capacity > 1);
    if (conf_parser.buf.items[conf_parser.len - 1] == '\n') {
      conf_parser.buf.items[conf_parser.len - 1] = '\0';
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
    } else if (feof(file)) {
      ++conf_parser.len;
      assert(conf_parser.buf.items[conf_parser.len - 1] == '\0');
    } else {
      // buffer too small, collect remainder and grow
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
      array_grow(&arena_console, &conf_parser.buf, (uint32_t)conf_parser.len);
      int32_t c;
      while ((c = fgetc(file)) != '\n' && c != EOF) {
        array_push(&arena_console, &conf_parser.buf, (char)c);
      }
      array_push(&arena_console, &conf_parser.buf, '\0');
      conf_parser.len = conf_parser.buf.count - 1;
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
    }
    assert(conf_parser.buf.items[conf_parser.len - 1] != '\n');
    const char first = cin_lower_isalpha(&conf_parser.buf.items[0]) ? 'a' : conf_parser.buf.items[0];
    switch (first) {
    case 'a': {
      // expect abc=def123 or zyx  = wvu123
      char *p = conf_parser.buf.items + 1;
      while (cin_lower_isalpha(p)) ++p;
      conf_parser.k_len = (size_t)(p - conf_parser.buf.items);
      while (*p == ' ') ++p;
      if (*p != '=') {
        log_message(LOG_ERROR, "Token on line %d at position %zu must be '=', not '%c'",
                    conf_parser.line, (size_t)(p - conf_parser.buf.items) + 1, *p);
        goto end;
      }
      ++p;
      while (*p == ' ') ++p;
      if (!*p) {
        conf_parser.buf.items[conf_parser.k_len] = '\0';
        log_message(LOG_ERROR, "Token on line %d at position %zu must not be empty."
                               " Set the value for key '%s = ...'",
                    conf_parser.line, (size_t)(p - conf_parser.buf.items), conf_parser.buf.items);
        goto end;
      }
      conf_parser.v = p;
      const size_t curr_pos = (size_t)(p - conf_parser.buf.items + 1);
      const size_t remainder = conf_parser.len - curr_pos;
      char *comment = memchr(p, '#', remainder);
      if (comment) {
        const size_t dist = (size_t)(comment - p);
        const size_t comment_len = remainder - dist;
        conf_parser.len -= comment_len;
        if (comment_len) *(p + dist) = '\0';
      }
      if (!conf_keyget()) {
        conf_parser.buf.items[conf_parser.k_len] = '\0';
        log_message(LOG_ERROR, "Unknown key '%s' on line %d, please check for typos",
                    conf_parser.buf.items, conf_parser.line);
        goto end;
      } else if (conf_parser.error) {
        goto end;
      }
    } break;
    case '[': {
      // expect abc]
      char *p = conf_parser.buf.items + 1;
      while (cin_lower_isalpha(p)) ++p;
      conf_parser.k_len = (size_t)(p - conf_parser.buf.items) - 1;
      if (*p != ']') {
        conf_parser.buf.items[conf_parser.k_len + 1] = '\0';
        log_message(LOG_ERROR, "Line %d wrongly creates a new scope '%s',"
                               " close it with ']' at position %zu",
                    conf_parser.line, conf_parser.buf.items, conf_parser.k_len + 2);
        goto end;
      }
      if (!conf_scopeget()) {
        conf_parser.buf.items[conf_parser.k_len + 2] = '\0';
        log_message(LOG_ERROR, "Scope '%s' at line %d is unknown, please check for typos",
                    conf_parser.buf.items, conf_parser.line);
        goto end;
      }
    } break;
    case '#':
      break;
    case '\0':
      break;
    default:
      log_message(LOG_ERROR, "Line %d starts with unexpected token '%d'. Only letters,"
                             " #, [, and empty lines are allowed here.",
                  conf_parser.line, conf_parser.buf.items[0]);
      goto end;
    }
    conf_parser.buf.items[0] = '\0';
    array_clear(&conf_parser.buf);
    ++conf_parser.line;
  }
  ok = true;
end:
  fclose(file);
  return ok;
}

#ifdef _WIN32
#define DEFINE_SETUP_FILE_PATH(T, backward, forward, terminator, memcpy_fn) \
  void setup_file_path_##T(T *path, int32_t *len) {                         \
    assert(len);                                                            \
    for (T *p = path; *p; ++p) {                                            \
      if (*p == backward) {                                                 \
        *p++ = forward;                                                     \
        T *dups = p;                                                        \
        while (*dups == backward) ++dups;                                   \
        if (p != dups) {                                                    \
          const ptrdiff_t removed = dups - p;                               \
          const ptrdiff_t pos = dups - path;                                \
          assert((size_t)*len >= (size_t)pos);                              \
          const size_t remainder = (size_t)*len - (size_t)pos;              \
          memcpy_fn(p, dups, remainder);                                    \
          p = dups;                                                         \
          *len -= (int32_t)removed;                                         \
        }                                                                   \
      }                                                                     \
    }                                                                       \
    *(path + (size_t)*len) = terminator;                                    \
  }
DEFINE_SETUP_FILE_PATH(char, '\\', '/', '\0', memcpy)
DEFINE_SETUP_FILE_PATH(wchar_t, L'\\', L'/', L'\0', wmemcpy)
#else
void setup_file_path(char *dst, const char *src, size_t dst_size) {
  // tilde expansion, username substitution
  const bool expand = *src == '~';
  size_t len = 0;
  if (!expand) {
    len = strlen(src) + 1;
    memcpy(dst, src, len);
  } else {
    const char *src_pos = src + 1;
    const bool only_root = !*(src_pos);
    const bool valid_expand = *(src_pos) == '/';
    const bool expand_anon = only_root || valid_expand;
    char *home = NULL;
    char *home_tail = (char *)strchr(src_pos, '/');
    if (expand_anon) {
      home = getenv("HOME");
      if (!home) {
        log_last_error("Failed to expand '~'for path '%s'", src);
        return;
      }
    } else {
      struct passwd *pw = NULL;
      errno = 0;
      if (home_tail) {
        char tmp = *home_tail;
        *home_tail = '\0';
        pw = getpwnam(src_pos);
        *home_tail = tmp;
      } else {
        pw = getpwnam(src_pos);
      }
      if (!pw) {
        log_last_error("Username not found in '%s'", src);
        return;
      }
      home = pw->pw_dir;
    }
    assert(home);
    assert(*home);
    const size_t home_len = strlen(home);
    const size_t path_len = *home_tail ? strlen(home_tail) : 0;
    const size_t new_path_len = home_len + path_len + 1;
    if (dst_size < new_path_len) {
      log_message(LOG_ERROR, "Buffer too small to expand '~': %zu < %zu", dst_size, new_path_len);
      return;
    }
    len = new_path_len;
    memcpy(dst, home, home_len);
    memcpy(dst + home_len, home_tail, path_len);
  }
  if (len > 1 && *(dst + len - 2) != '/') {
    assert(len < CIN_MAX_PATH);
    *(dst + len - 1) = '/';
    *(dst + len) = '\0';
  }
}
#endif

void setup_directory(const char *path, Tag_Directories *tag_dirs) {
#ifdef _WIN32
  int32_t len_utf16 = utf8_to_utf16_norm(path);
  assert(len_utf16);
  setup_file_path_wchar_t(utf16_buf_norm.items, &len_utf16);
  const size_t len = (size_t)len_utf16;
  Directory_Path root_dir = {.len = len};
  wmemcpy(root_dir.path, utf16_buf_norm.items, len);
#else
  Directory_Path root_dir = {0};
  setup_file_path(root_dir.path, path, CIN_MAX_PATH);
  path = root_dir.path;
  const int32_t len_i32 = utf8_norm(root_dir.path) + 1;
  assert(len_i32 > 0);
  const uint32_t len = (uint32_t)len_i32;
  root_dir.len = len;
  const uint32_t bytes = len;
#endif
  array_push(&arena_console, &dir_stack, root_dir);
  while (dir_stack.count > 0) {
    Directory_Path dir = dir_stack.items[--dir_stack.count];
    assert(dir.path);
    assert(dir.len > 0);
    assert(dir.path[dir.len - 1] == L'\0');
#ifdef _WIN32
    log_wmessage(LOG_DEBUG, L"Path: %s", dir.path);
    const int32_t bytes_i32 = utf16_to_utf8(dir.path);
    assert(bytes_i32 > 0);
    const uint32_t bytes = (uint32_t)bytes_i32;
    char *str_src = (char *)utf8_buf.items;
#else
    log_message(LOG_DEBUG, "Path: %s", dir.path);
    char *str_src = dir.path;
#endif
    array_reserve(&arena_console, &directory_strings, bytes + 1);
    uint8_t *strings = directory_strings.items;
    const uint32_t str_offset = directory_strings.count;
    memcpy(strings + str_offset, str_src, bytes);
    const uint32_t node_tail = directory_nodes.count;
    Table_Key key = {.strings = strings, .pos = str_offset, .len = bytes};
    table_value dup_index = table_find(&dir_table, &key);
    if (dup_index >= 0) {
      if (tag_dirs) {
        array_push(&arena_console, tag_dirs, (int32_t)dup_index);
      }
      continue;
    }
#ifdef _WIN32
    if (--dir.len + 2 >= CIN_MAX_PATH) {
      // We have to append 2 chars \ and * for the correct pattern
      log_wmessage(LOG_ERROR, L"Directory name too long: %ls", dir.path);
      continue;
    }
    dir.path[dir.len++] = L'/';
    dir.path[dir.len++] = L'*';
    dir.path[dir.len] = L'\0';
    WIN32_FIND_DATAW data;
    HANDLE search = FindFirstFileExW(dir.path, FindExInfoBasic, &data,
                                     FindExSearchNameMatch, NULL,
                                     FIND_FIRST_EX_LARGE_FETCH);
    // We can now drop the 2 chars \ and * to restore the root,
    // but choose to only drop * so that \ remains as a separator
    // for the next file or directory, instead of adding later.
    --dir.len;
    dir.path[dir.len] = L'\0';
    if (search == INVALID_HANDLE_VALUE) {
      log_last_error("Failed to match directory '%ls'", dir.path);
      continue;
    }
#else
    DIR *directory = opendir(path);
    if (!directory) {
      log_last_error("Failed to match directory '%s'", dir.path);
      continue;
    }
#endif
    // Commit the new directory
    array_grow(&arena_console, &directory_strings, bytes);
    array_grow(&arena_console, &directory_nodes, 1);
    Directory_Node *node = &directory_nodes.items[node_tail];
    assert(node);
    array_init(&arena_console, node, CIN_DIRECTORY_ITEMS_CAP);
    node->str_offset = str_offset;
    if (tag_dirs) {
      array_push(&arena_console, tag_dirs, (int32_t)node_tail);
    }
    table_value inserted = table_insert(&arena_console, &dir_table, &key, (table_value)node_tail);
    assert(inserted == -1);
#ifdef _WIN32
    do {
      if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        continue; // skip junction
      }
      const size_t file_len = (size_t)utf16_norm(data.cFileName);
      wchar_t *file = utf16_buf_norm.items;
      const bool is_dir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
      if (is_dir && (file[0] == L'.') && (!file[1] || (file[1] == L'.' && !file[2]))) {
        continue; // skip dot entry
      }
      const size_t path_len = dir.len + file_len;
      if (path_len >= CIN_MAX_PATH) {
        continue; // skip absolute path (+ NUL) if silently truncated
      }
      if (is_dir) {
        Directory_Path nested_path = {.len = path_len};
        wmemcpy(nested_path.path, dir.path, dir.len);
        wmemcpy(nested_path.path + dir.len, file, file_len);
        assert(nested_path.path[nested_path.len - 1] == L'\0');
        assert(nested_path.len > 0);
        ++dir_stack.abs_count;
        array_ensure_capacity_core(&arena_console, &dir_stack, dir_stack.abs_count, false);
        array_push(&arena_console, &dir_stack, nested_path);
      } else {
        wmemcpy(dir.path + dir.len, file, file_len);
        const int32_t utf8_len = utf16_to_utf8(dir.path);
        const table_key_pos tail_offset = array_bytes(&docs);
        int32_t tail_doc = (int32_t)tail_offset;
        docs_push(utf8_buf.items, utf8_len);
        if (conf_parser.has_patterns) {
          // NOTE: With patterns, we want to let the OS evaluate them.
          // The safest way to deduplicate patterns seems to be file-by-file
          // comparisons, which can of course degenerate, so we check if the
          // config contains patterns first. We solve the cases where a pattern
          // was evaluated before this step, and after this step.
          Table_Key pat_key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)utf8_len};
          table_value dup_doc = table_insert(&arena_console, &pat_table, &pat_key, tail_doc);
          if (dup_doc >= 0) {
            docs_pop((int32_t)len);
            tail_doc = (int32_t)dup_doc;
          }
        }
        array_push(&arena_console, node, tail_doc);
      }
    } while (FindNextFileW(search, &data) != 0);
    if (GetLastError() != ERROR_NO_MORE_FILES) {
      log_last_error("Failed to find next file");
    }
    FindClose(search);
#else
    struct dirent *entry = NULL;
    errno = 0;
    Directory_Path tmp_dir = dir;
    while ((entry = readdir(directory))) {
      char *file = entry->d_name;
      const size_t file_len = strlen(file) + 1;
      tmp_dir.len = dir.len;
      // tmp_dir.len also includes null terminator
      const size_t path_len = tmp_dir.len + file_len - 1;
      if (path_len >= CIN_MAX_PATH) continue;
      memcpy(tmp_dir.path + tmp_dir.len - 1, file, file_len);
      tmp_dir.len = path_len;
      struct stat statbuf;
      if (lstat(tmp_dir.path, &statbuf) < 0) {
        log_last_error("Failed to get stat for '%s'", tmp_dir.path);
        continue;
      }
      const bool is_dir = S_ISDIR(statbuf.st_mode);
      if (is_dir) {
        if (strcmp(file, ".") != 0 && strcmp(file, "..") != 0) {
          assert(tmp_dir.path[tmp_dir.len - 1] == '\0');
          assert(tmp_dir.len > 0);
          ++dir_stack.abs_count;
          array_ensure_capacity_core(&arena_console, &dir_stack, dir_stack.abs_count, false);
          array_push(&arena_console, &dir_stack, tmp_dir);
        }
      } else {
        const table_key_pos tail_offset = array_bytes(&docs);
        int32_t tail_doc = (int32_t)tail_offset;
        docs_push((uint8_t *)tmp_dir.path, (int32_t)path_len);
        if (conf_parser.has_patterns) {
          Table_Key pat_key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)path_len};
          table_value dup_doc = table_insert(&arena_console, &pat_table, &pat_key, tail_doc);
          if (dup_doc >= 0) {
            docs_pop((int32_t)len);
            tail_doc = (int32_t)dup_doc;
          }
        }
        array_push(&arena_console, node, tail_doc);
      }
      errno = 0;
    }
    if (errno != 0) {
      log_last_error("Failed to find next file");
    }
#endif
  }
  assert(dir_stack.count == 0);
}

void setup_pattern(const char *pattern, Tag_Pattern_Items *tag_pattern_items) {
#ifdef _WIN32
  // Processes all files (not directories) that match the pattern
  // https://support.microsoft.com/en-us/office/examples-of-wildcard-characters-939e153f-bd30-47e4-a763-61897c87b3f4
  int32_t len_utf16 = utf8_to_utf16_norm(pattern);
  assert(len_utf16);
  assert(utf16_buf_norm.items[len_utf16 - 1] == L'\0');
  setup_file_path_wchar_t(utf16_buf_norm.items, &len_utf16);
  wchar_t *separator = wcsrchr(utf16_buf_norm.items, L'/');
  if (separator == NULL || *(separator + 1) == L'\0') {
    log_message(LOG_ERROR, "Not a valid pattern: '%s', end properly with '\\...'", pattern);
    return;
  }
  const size_t dir_len = (size_t)(separator - utf16_buf_norm.items) + 1;
  if (dir_len > CIN_MAX_PATH) {
    log_message(LOG_ERROR, "Pattern '%s' is too long (max=%d)", pattern, CIN_MAX_PATH);
    return;
  }
  const wchar_t prev_tail = utf16_buf_norm.items[dir_len];
  utf16_buf_norm.items[dir_len] = L'\0';
  static wchar_t abs_buf[CIN_MAX_PATH];
  uint32_t abs_len = GetFullPathNameW(utf16_buf_norm.items, CIN_MAX_PATH, abs_buf, NULL);
  setup_file_path_wchar_t(abs_buf, (int32_t *)&abs_len);
  if (abs_len == 0 || abs_len > CIN_MAX_PATH) {
    log_wmessage(LOG_ERROR, L"Pattern '%ls' full path '%ls' is empty or too long (max=%d)",
                 pattern, abs_buf, CIN_MAX_PATH);
    return;
  }
  log_wmessage(LOG_INFO, L"pattern: %ls", abs_buf);
  if (abs_buf[abs_len - 1] != L'/') {
    abs_buf[abs_len++] = L'/';
    abs_buf[abs_len] = L'\0';
  }
  utf16_buf_norm.items[dir_len] = prev_tail;
  WIN32_FIND_DATAW data;
  HANDLE search = FindFirstFileExW(utf16_buf_norm.items, FindExInfoBasic, &data,
                                   FindExSearchNameMatch, NULL,
                                   FIND_FIRST_EX_LARGE_FETCH);
  if (search == INVALID_HANDLE_VALUE) {
    log_last_error("Failed to match pattern '%ls'", utf16_buf_norm.items);
    return;
  }
  static const uint32_t file_mask = FILE_ATTRIBUTE_DIRECTORY |
                                    FILE_ATTRIBUTE_REPARSE_POINT |
                                    FILE_ATTRIBUTE_DEVICE;
  do {
    if (data.dwFileAttributes & file_mask) {
      continue; // skip directories
    }
    const size_t file_len = (size_t)utf16_norm(data.cFileName);
    wchar_t *file = utf16_buf_norm.items;
    const int32_t path_len = (int32_t)(abs_len + file_len);
    if (path_len >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(abs_buf + abs_len, file, file_len);
    const int32_t len = utf16_to_utf8(abs_buf);
    const table_key_pos tail_offset = array_bytes(&docs);
    const int32_t tail_doc = (int32_t)tail_offset;
    docs_push(utf8_buf.items, len);
    Table_Key key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)len};
    table_value dup_doc = table_insert(&arena_console, &pat_table, &key, tail_doc);
    if (dup_doc >= 0) {
      docs_pop(len);
      if (tag_pattern_items) array_push(&arena_console, tag_pattern_items, (int32_t)dup_doc);
    } else {
      if (tag_pattern_items) array_push(&arena_console, tag_pattern_items, tail_doc);
    }
  } while (FindNextFileW(search, &data) != 0);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    log_last_error("Failed to find next file");
  }
  FindClose(search);
#else
  char new_pattern[CIN_MAX_PATH];
  setup_file_path(new_pattern, pattern, CIN_MAX_PATH);
  pattern = new_pattern;
  static const int32_t GLOB_FLAGS = GLOB_NOSORT;
  glob_t matches = {0};
  const int32_t result = glob(new_pattern, GLOB_FLAGS, NULL, &matches);
  if (result != 0) {
    if (result == GLOB_NOMATCH) {
      log_message(LOG_ERROR, "Found no results for pattern '%s'", new_pattern);
    } else {
      log_last_error("Failed to match pattern '%s'", new_pattern);
    }
    globfree(&matches);
    return;
  }
  struct stat statbuf;
  const size_t n = matches.gl_pathc;
  char file_buf[CIN_MAX_PATH];
  for (size_t i = 0; i < n; ++i) {
    const char *file = matches.gl_pathv[i];
    if (lstat(file, &statbuf) >= 0 && S_ISREG(statbuf.st_mode)) {
      const size_t len = strlen(file) + 1;
      memcpy(file_buf, file, len);
      utf8_norm(file_buf);
      const table_key_pos tail_offset = array_bytes(&docs);
      const int32_t tail_doc = (int32_t)tail_offset;
      docs_push((uint8_t *)file_buf, (int32_t)len);
      Table_Key key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)len};
      table_value dup_doc = table_insert(&arena_console, &pat_table, &key, tail_doc);
      if (dup_doc >= 0) {
        docs_pop((int32_t)len);
        if (tag_pattern_items) array_push(&arena_console, tag_pattern_items, (int32_t)dup_doc);
      } else {
        if (tag_pattern_items) array_push(&arena_console, tag_pattern_items, tail_doc);
      }
    }
  }
  globfree(&matches);
#endif
}

void setup_url(char *url, Tag_Url_Items *tag_url_items) {
#ifdef _WIN32
  const int32_t len_utf16 = utf8_to_utf16_raw(url);
  assert(len_utf16 > 0);
  const int32_t len = utf16_to_utf8(utf16_buf_raw.items);
  uint8_t *doc = utf8_buf.items;
#else
  const int32_t len = (int32_t)strlen(url) + 1;
  uint8_t *doc = (uint8_t *)url;
#endif
  assert(len > 0);
  const table_key_pos tail_offset = array_bytes(&docs);
  const int32_t tail_doc = (int32_t)tail_offset;
  docs_push(doc, len);
  Table_Key key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)len};
  table_value dup_doc = table_insert(&arena_console, &url_table, &key, tail_doc);
  if (dup_doc >= 0) {
    docs_pop(len);
    if (tag_url_items) array_push(&arena_console, tag_url_items, (int32_t)dup_doc);
  } else {
    if (tag_url_items) array_push(&arena_console, tag_url_items, tail_doc);
  }
}

void setup_tag(char *tag, Tag_Items *tag_items) {
#ifdef _WIN32
  const int32_t len_utf16 = utf8_to_utf16_norm(tag);
  assert(len_utf16 > 0);
  const int32_t len = utf16_to_utf8(utf16_buf_norm.items);
  uint8_t *name = utf8_buf.items;
#else
  const int32_t len = utf8_norm(tag) + 1;
  uint8_t *name = (uint8_t *)tag;
#endif
  assert(len > 0);
  radix_insert(&arena_console, tag_tree, name, (size_t)len, tag_items);
}

bool setup_chat(const char *geometry, uint32_t len, Cin_Layout *layout) {
  if (len == 0) {
    layout->chat_rect.right = LONG_MIN;
    layout->chat_rect.bottom = LONG_MIN;
    layout->chat_rect.left = LONG_MIN;
    layout->chat_rect.top = LONG_MIN;
    return true;
  }
  const char *p = geometry;
  int64_t width, height, x, y;
  cin_getnum(&p, &width);
  if (*p != 'x') return false;
  ++p;
  cin_getnum(&p, &height);
  bool positive;
  if (*p == '-') positive = false;
  else if (*p == '+') positive = true;
  else return false;
  ++p;
  cin_getnum(&p, &x);
  if (!positive) x = -x;
  if (*p == '-') positive = false;
  else if (*p == '+') positive = true;
  else return false;
  ++p;
  cin_getnum(&p, &y);
  if (*p && !isspace(*p)) return false;
  if (!positive) y = -y;
  layout->chat_rect.right = (int32_t)width;
  layout->chat_rect.bottom = (int32_t)height;
  layout->chat_rect.left = (int32_t)x;
  layout->chat_rect.top = (int32_t)y;
  return true;
}

void setup_screen(const char *geometry, Cin_Layout *layout) {
  const size_t geometry_len = strlen(geometry);
  const uint32_t bytes = (uint32_t)geometry_len + 1U;
  Cin_Screen screen = {.offset = screen_strings.count, .len = bytes};
  array_extend(&arena_console, &screen_strings, geometry, bytes);
  array_push(&arena_console, layout, screen);
}

void setup_layout(char *name, Cin_Layout *layout) {
#ifdef _WIN32
  const int32_t len_utf16 = utf8_to_utf16_norm(name);
  assert(len_utf16 > 1);
  const uint32_t len = (uint32_t)utf16_to_utf8(utf16_buf_norm.items);
  uint8_t *layout_name = utf8_buf.items;
#else
  const uint32_t len = (uint32_t)utf8_norm(name) + 1;
  uint8_t *layout_name = (uint8_t *)name;
#endif
  assert(len > 0);
  layout->name_offset = layout_strings.count;
  layout->name_len = len;
  array_extend(&arena_console, &layout_strings, layout_name, len);
  radix_insert(&arena_console, layout_tree, layout_name, len, layout);
}

void setup_macro(char *name, Cin_Macro *macro, bool startup) {
#ifdef _WIN32
  const int32_t len_utf16 = utf8_to_utf16_norm(name);
  assert(len_utf16 > 1);
  const int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  assert(len_utf8 > 1);
  radix_insert(&arena_console, macro_tree, utf8_buf.items, (uint32_t)len_utf8, macro);
#else
  const int32_t len = utf8_norm(name) + 1;
  assert(len > 0);
  radix_insert(&arena_console, macro_tree, (uint8_t *)name, (uint32_t)len, macro);
#endif
  if (startup) array_push(&arena_console, &startup_macros, macro);
}

void setup_macro_command(char *command, Cin_Macro *macro) {
#ifdef _WIN32
  const int32_t len_utf16 = utf8_to_utf16_norm(command);
  assert(len_utf16 > 1);
  const int32_t len = utf16_to_utf8(utf16_buf_norm.items);
  assert(len > 1);
  const uint32_t len_u32 = (uint32_t)len;
  array_extend(&arena_console, macro, utf8_buf.items, len_u32);
#else
  const int32_t len = utf8_norm(command) + 1;
  assert(len > 1);
  array_extend(&arena_console, macro, command, (uint32_t)len);
#endif
}

void setup_settings(Conf_Key *src, char *dst) {
  if (!src->count) return;
#ifdef _WIN32
  const int32_t len_utf16 = utf8_to_utf16_norm(src->items);
  assert(len_utf16 > 1);
  const int32_t len = utf16_to_utf8(utf16_buf_norm.items);
  assert(len > 1);
  const uint32_t len_u32 = (uint32_t)len;
  assert(len_u32 <= CIN_MAX_PATH_BYTES);
  memcpy(dst, utf8_buf.items, len_u32);
#else
  const int32_t len = utf8_norm(src->items) + 1;
  assert(len > 1);
  assert(len <= CIN_MAX_PATH_BYTES);
  memcpy(dst, src->items, len);
#endif
}

#define FOREACH_PART(str, part)                                                     \
  for (char *part = (str)->items, *_right = part, *_tail = part + (str)->count - 1; \
       part && part < _tail;                                                        \
       part = _right ? ++_right : NULL)                                             \
    if ((part += strspn(part, " \t,")),                                             \
        (_right = memchr(part, ',', (size_t)(_tail - part))),                       \
        (_right = _right ? (*_right = '\0', _right) : NULL),                        \
        *part)

bool init_config(const char *filename) {
  if (!parse_config(filename)) return false;
  table_init(&arena_console, &dir_table, CIN_DIRECTORIES_CAP);
  table_init(&arena_console, &pat_table, CIN_PATTERN_ITEMS_CAP);
  table_init(&arena_console, &url_table, CIN_URLS_CAP);
  arena_chunk_init(&arena_docs, CIN_DOCS_ARENA_CAP);
  array_init_zero(&arena_docs, &docs, CIN_DOCS_CAP);
  array_init(&arena_console, &directory_nodes, CIN_DIRECTORIES_CAP);
  array_init(&arena_console, &directory_strings, CIN_DIRECTORY_STRINGS_CAP);
  array_init(&arena_console, &geometry_buf, CIN_LAYOUT_SCREENS_CAP);
  tag_tree = radix_tree(&arena_console);
  layout_tree = radix_tree(&arena_console);
  macro_tree = radix_tree(&arena_console);
  Conf_Root *root = &conf_parser.scopes.items[0].root;
  (void)root;
  for (size_t i = 1; i < conf_parser.scopes.count; ++i) {
    Conf_Scope *scope = &conf_parser.scopes.items[i];
    log_message(LOG_DEBUG, "[Scope %zu: %zu]", i, scope->type);
    switch (scope->type) {
    case CONF_SCOPE_LAYOUT: {
      if (!scope->layout.name.count) {
        log_message(LOG_ERROR, "Layout at [scope] number %zu does not have a name key,"
                               " please supply it: 'name = value'",
                    i);
        return false;
      }
      if (!scope->layout.screen.count) {
        log_message(LOG_ERROR, "Layout at [scope] number %zu does not have any screen"
                               " keys, please supply with: 'screen = 0:0'",
                    i);
        return false;
      }
      Cin_Layout *layout = arena_bump_T1(&arena_console, Cin_Layout);
      if (!setup_chat(scope->layout.chat.items, scope->layout.chat.count, layout)) {
        log_message(LOG_WARNING, "Layout at [scope] number %zu does not have a valid chat"
                                 " key, please fix as: 'chat = 0x0±0±0'",
                    i);
      }
      layout->scope_line = scope->line;
      array_init(&arena_console, layout, CIN_LAYOUT_SCREENS_CAP);
      log_message(LOG_DEBUG, "Name: %s", scope->layout.name.items);
      FOREACH_PART(&scope->layout.screen, part) {
        log_message(LOG_DEBUG, "Screen: %s", part);
        setup_screen(part, layout);
      }
      setup_layout(scope->layout.name.items, layout);
      array_free_items(&arena_console, &scope->layout.name);
      array_free_items(&arena_console, &scope->layout.screen);
      array_free_items(&arena_console, &scope->layout.chat);
    } break;
    case CONF_SCOPE_MEDIA: {
      Tag_Items *tag_items = NULL;
      Tag_Directories *tag_directories = NULL;
      Tag_Pattern_Items *tag_pattern_items = NULL;
      Tag_Url_Items *tag_url_items = NULL;
      if (scope->media.tags.count) {
        tag_items = arena_bump_T1(&arena_console, Tag_Items);
        if (scope->media.directories.count) {
          tag_items->directories = arena_bump_T1(&arena_console, Tag_Directories);
          array_init(&arena_console, tag_items->directories, CIN_DIRECTORIES_CAP);
          tag_directories = tag_items->directories;
        }
        if (scope->media.patterns.count) {
          tag_items->pattern_items = arena_bump_T1(&arena_console, Tag_Pattern_Items);
          array_init(&arena_console, tag_items->pattern_items, scope->media.patterns.count);
          tag_pattern_items = tag_items->pattern_items;
        }
        if (scope->media.urls.count) {
          tag_items->url_items = arena_bump_T1(&arena_console, Tag_Url_Items);
          array_init(&arena_console, tag_items->url_items, scope->media.urls.count);
          tag_url_items = tag_items->url_items;
        }
      }
      FOREACH_PART(&scope->media.directories, part) {
        log_message(LOG_DEBUG, "Directory: %s", part);
        setup_directory(part, tag_directories);
      }
      FOREACH_PART(&scope->media.patterns, part) {
        log_message(LOG_DEBUG, "Pattern: %s", part);
        setup_pattern(part, tag_pattern_items);
      }
      FOREACH_PART(&scope->media.urls, part) {
        log_message(LOG_DEBUG, "URL: %s", part);
        setup_url(part, tag_url_items);
      }
      FOREACH_PART(&scope->media.tags, part) {
        log_message(LOG_DEBUG, "Tag: %s", part);
        setup_tag(part, tag_items);
      }
      // NOTE: Each tag corresponding to this media scope now points to the same
      // Tag_Items address. In it, 'patterns' and 'urls' contain document ids (possibly
      // with duplicates). Its 'directories' is a Tag_Directories struct, where each
      // item is an index into a global Directory_Node array (possibly with duplicates)
      // - these nodes contain a list of unique document ids. Given example directory
      // A:\b\c\, the node array must be traversed starting there up to an index where
      // the first document in the list does not start with A:\b\c\ (so we simulate
      // a correct recursive directory traversal, lazily, i.e., when tag is requested)
      array_free_items(&arena_console, &scope->media.directories);
      array_free_items(&arena_console, &scope->media.patterns);
      array_free_items(&arena_console, &scope->media.urls);
      array_free_items(&arena_console, &scope->media.tags);
    } break;
    case CONF_SCOPE_MACRO: {
      if (!scope->macro.name.count) {
        log_message(LOG_ERROR, "Macro at [scope] number %zu does not have a name key,"
                               " please supply it: 'name = value'",
                    i);
        return false;
      }
      Cin_Macro *macro = arena_bump_T1(&arena_console, Cin_Macro);
      log_message(LOG_DEBUG, "Name: %s", scope->macro.name.items);
      FOREACH_PART(&scope->macro.command, part) {
        log_message(LOG_DEBUG, "Macro: %s", part);
        setup_macro_command(part, macro);
      }
      const bool startup = scope->macro.startup.items && strncmp("yes", scope->macro.startup.items, 3) == 0;
      setup_macro(scope->macro.name.items, macro, startup);
      array_free_items(&arena_console, &scope->macro.name);
      array_free_items(&arena_console, &scope->macro.command);
      array_free_items(&arena_console, &scope->macro.startup);
    } break;
    case CONF_SCOPE_SETTINGS: {
      setup_settings(&scope->settings.mpv_path, exe_path_mpv);
      setup_settings(&scope->settings.ytdlp_path, exe_path_ytdlp);
      setup_settings(&scope->settings.chatterino_path, exe_path_chatterino);
      array_free_items(&arena_console, &scope->settings.mpv_path);
      array_free_items(&arena_console, &scope->settings.ytdlp_path);
      array_free_items(&arena_console, &scope->settings.chatterino_path);
    } break;
    default:
      assert(false && "Unexpected scope");
      break;
    }
  }
  table_free_items(&arena_console, &dir_table);
  table_free_items(&arena_console, &pat_table);
  table_free_items(&arena_console, &url_table);
  array_free_items(&arena_console, &dir_stack);
  array_free_items(&arena_console, &conf_parser.scopes);
  array_free_items(&arena_console, &conf_parser.buf);
  array_to_pow1(&arena_docs, &docs);
  assert(array_bytes(&docs) <= CIN_ARENA_MAX && "overflew k == 31");
  if (array_bytes(&docs) == CIN_ARENA_MAX) {
    // extremely rare case where we exceed INT_MAX by 1 byte,
    // instead of trying to fix it we force a crash
    cin_writef("Cinema crashed receiving too many file paths (exceeding %d bytes)", INT_MAX);
    cin_exit(1);
  }
  docs.bytes_mul32 = array_bytes(&docs) * (uint32_t)sizeof(int32_t);
  docs.doc_mul32 = (uint32_t)docs.doc_count * sizeof(int32_t);
  log_message(LOG_INFO, "Setup media library with %d items (%u bytes)",
              docs.doc_count, array_bytes(&docs));
  return true;
}
#undef FOREACH_PART

bool reinit_documents(void) {
  const int32_t d_bytes = (int32_t)array_bytes(&docs);
  if (d_bytes == 0) {
    log_message(LOG_ERROR, "media library is empty");
    return false;
  }
  const int32_t remainder = (int32_t)docs.bytes_capacity - d_bytes;
#ifdef LIBSAIS_OPENMP
  const int32_t result = libsais_gsa_omp(docs.items, docs.gsa, d_bytes, remainder, NULL, cin_system.threads);
#else
  const int32_t result = libsais_gsa(docs.items, docs.gsa, d_bytes, remainder, NULL);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build SA with code %d", result);
    return false;
  }
  int32_t *tmp = arena_bump_T(&arena_docs, int32_t, (uint32_t)d_bytes);
  Playlist *default_playlist = &media.default_playlist;
  array_ensure_capacity_core(&arena_docs, default_playlist, (uint32_t)docs.doc_count, false);
  for (int32_t i = 0, offset = 0; i < d_bytes; ++i) {
    tmp[i] = offset;
    if (docs.items[i] == '\0') {
      const uint32_t playlist_pos = default_playlist->count++;
      default_playlist->items[playlist_pos] = offset;
      offset = i + 1;
    }
  }
#ifdef CIN_OPENMP
#pragma omp parallel for if (d_bytes >= (1 << 19))
#endif
  for (int32_t i = 0; i < d_bytes; ++i) {
    const int32_t offset = docs.gsa[i];
    const int32_t doc = tmp[offset];
    docs.suffix_to_doc[i] = doc;
  }
  arena_free_pos(&arena_docs, (uint8_t *)tmp, (uint32_t)d_bytes);
  return true;
}

bool init_documents(void) {
  const int32_t d_bytes = (int32_t)array_bytes(&docs);
  docs.gsa = arena_bump_T(&arena_docs, uint8_t, docs.bytes_mul32);
  docs.dedup_counters = arena_bump_T(&arena_docs, uint16_t, (uint32_t)d_bytes);
  docs.suffix_to_doc = arena_bump_T(&arena_docs, int32_t, (uint32_t)d_bytes);
  table_init(&arena_docs, &media.search_table, CIN_QUERIES_CAP);
  return reinit_documents();
}

void document_listing(const uint8_t *pattern, int32_t pattern_len, Playlist *result) {
  int32_t left = docs.doc_count;
  int32_t right = (int32_t)array_bytes(&docs) - 1;
  int32_t l_lcp = lcps(pattern, docs.items + docs.gsa[left]);
  int32_t r_lcp = lcps(pattern, docs.items + docs.gsa[right]);
  if (l_lcp < pattern_len &&
      (docs.items[docs.gsa[left] + l_lcp] == '\0' ||
       pattern[l_lcp] < docs.items[docs.gsa[left] + l_lcp])) {
    // pattern = abc, left = abd
    // l_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[l_lcp] = c, text[left + l_lcp] = d, c < d
    log_message(LOG_DEBUG, "Pattern is smaller than first suffix");
    return;
  }
  if (r_lcp < pattern_len &&
      docs.items[docs.gsa[right] + r_lcp] != '\0' &&
      pattern[r_lcp] > docs.items[docs.gsa[right] + r_lcp]) {
    // pattern = abd, right = abc
    // r_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[r_lcp] = d, text[right + r_lcp] = c, d > c
    log_message(LOG_DEBUG, "Pattern is larger than last suffix");
    return;
  }
  const int32_t tmp_right = right;
  const int32_t tmp_r_lcp = r_lcp;
  bool found = false;
  while (left < right) {
    const int32_t mid = left + ((right - left) >> 1);
    const int32_t min_lcp = (l_lcp < r_lcp) ? l_lcp : r_lcp;
    const int32_t t_lcp = lcps_from(pattern, docs.items + docs.gsa[mid], min_lcp);
    if (t_lcp == pattern_len) {
      // pattern is a prefix of suffix[mid]
      found = true;
      right = mid;
      r_lcp = t_lcp;
    } else if (docs.items[docs.gsa[mid] + t_lcp] == '\0') {
      // pattern was a prefix but larger than suffix[mid]
      left = mid + 1;
      l_lcp = t_lcp;
    } else if (pattern[t_lcp] < docs.items[docs.gsa[mid] + t_lcp]) {
      // pattern is smaller than suffix[mid]
      right = mid;
      r_lcp = t_lcp;
    } else {
      // pattern is larger than suffix[mid]
      left = mid + 1;
      l_lcp = t_lcp;
    }
  }
  if (!found) {
    const int32_t min_lcp = (l_lcp < r_lcp) ? l_lcp : r_lcp;
    if (lcps_from(pattern, docs.items + docs.gsa[left], min_lcp) < pattern_len) {
      log_message(LOG_DEBUG, "No suffix has pattern as prefix");
      return;
    }
  }
  const int32_t l_bound = left;
  right = tmp_right;
  l_lcp = pattern_len;
  r_lcp = tmp_r_lcp;
  while (left < right) {
    const int32_t mid = left + ((right - left + 1) >> 1);
    const int32_t min_lcp = (l_lcp < r_lcp) ? l_lcp : r_lcp;
    const int32_t t_lcp = lcps_from(pattern, docs.items + docs.gsa[mid], min_lcp);
    if (t_lcp >= pattern_len) {
      // pattern is a prefix of suffix[mid]
      left = mid;
      l_lcp = t_lcp;
    } else if (docs.items[docs.gsa[mid] + t_lcp] == '\0') {
      // pattern is larger than suffix[mid]
      right = mid - 1;
      r_lcp = t_lcp;
    } else {
      // mismatch
      right = mid - 1;
      r_lcp = t_lcp;
    }
  }
  const int32_t r_bound = left;
  log_message(LOG_DEBUG, "Boundaries are [%d, %d] or [%s, %s]", l_bound, r_bound,
              docs.items + docs.gsa[l_bound], docs.items + docs.gsa[r_bound]);
  static uint16_t dedup_counter = 1;
  const int32_t n = min(docs.doc_count, (r_bound - l_bound) + 1);
  array_ensure_capacity_core(&arena_docs, result, (uint32_t)n, false);
  array_clear(result);
  for (int32_t i = l_bound; i <= r_bound; ++i) {
    const int32_t doc = docs.suffix_to_doc[i];
    if (docs.dedup_counters[doc] != dedup_counter) {
      docs.dedup_counters[doc] = dedup_counter;
      assert(result->count < result->capacity);
      assert(result->count <= (uint32_t)n);
      if (media.hidden_table.count) {
        Hidden_Table *table = &media.hidden_table;
        const uint64_t mask = table->capacity - 1;
        const uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
        uint64_t index = hash & mask;
        while (table->items[index] >= 0) {
          if (table->items[index] == doc) goto skip;
          index = (index + 1) & mask;
        }
      }
      array_push(&arena_docs, result, doc);
      log_message(LOG_TRACE, "docs.gsa[%7d] = %-25.25s (%7d)| (%7d) = %-30.30s counter=%d",
                  i, docs.items + docs.gsa[i], docs.gsa[i], doc, docs.items + doc, dedup_counter);
    skip:;
    }
  }
  if (dedup_counter++ == USHRT_MAX) {
    memset(docs.dedup_counters, 0, (size_t)array_bytes(&docs) * sizeof(uint16_t));
    dedup_counter = 1;
  }
}