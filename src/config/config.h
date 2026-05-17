#ifndef CIN_CONFIG_H
#define CIN_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#include "base/arena.h"
#include "base/array.h"
#include "base/cache.h"
#include "base/radix.h"
#include "base/table.h"
#include "console/console.h"
#include "console/log.h"
#include "os/os.h"

extern Arena arena_docs;

#define CONF_LINE_CAP 512
#define CONF_SCOPES_CAP 16

array_define(Conf_Key, char);

typedef struct Conf_Root {
  Conf_Key null;
} Conf_Root;

typedef struct Conf_Media {
  Conf_Key directories;
  Conf_Key patterns;
  Conf_Key urls;
  Conf_Key tags;
} Conf_Media;

typedef struct Conf_Layout {
  Conf_Key name;
  Conf_Key screen;
  Conf_Key chat;
} Conf_Layout;

typedef struct Conf_Macro {
  Conf_Key name;
  Conf_Key command;
  Conf_Key startup;
} Conf_Macro;

typedef struct Conf_Settings {
  Conf_Key mpv_path;
  Conf_Key ytdlp_path;
  Conf_Key chatterino_path;
} Conf_Settings;

typedef enum {
  CONF_SCOPE_ROOT,
  CONF_SCOPE_MEDIA,
  CONF_SCOPE_LAYOUT,
  CONF_SCOPE_MACRO,
  CONF_SCOPE_SETTINGS
} Conf_Scope_Type;

typedef struct Conf_Scope {
  Conf_Scope_Type type;
  union {
    Conf_Root root;
    Conf_Media media;
    Conf_Layout layout;
    Conf_Macro macro;
    Conf_Settings settings;
  };
  int32_t line;
} Conf_Scope;

array_define(Conf_Scopes, Conf_Scope);
array_define(Conf_Buf, char);

extern struct Conf_Parser {
  Conf_Scopes scopes;
  Conf_Buf buf;
  size_t len;
  size_t k_len;
  char *v;
  int32_t line;
  bool error;
  // general flags
  bool has_patterns;
} conf_parser;

static inline Conf_Scope *conf_scope(void) {
  assert(conf_parser.scopes.count > 0);
  return &conf_parser.scopes.items[conf_parser.scopes.count - 1];
}

static inline void conf_enter_scope(Conf_Scope_Type type) {
  Conf_Scope scope = {0};
  scope.type = type;
  scope.line = conf_parser.line;
  array_push(&arena_console, &conf_parser.scopes, scope);
}

static inline bool conf_scopecmp(const char *s, Conf_Scope_Type type) {
  if (memcmp(s, conf_parser.buf.items + 1, conf_parser.k_len) != 0) return false;
  conf_enter_scope(type);
  return true;
}

bool conf_keycmp(const char *k, Conf_Scope_Type type, Conf_Key *out, bool unique);
bool conf_keyget(void);
bool conf_scopeget(void);
bool parse_config(const char *filename);

#define CIN_DOCS_ARENA_CAP megabytes(2)
#define CIN_DOCS_CAP (1 << 13)

extern struct Document_Collection {
  // Each byte represents a UTF-8 unit
  array_struct_members(uint8_t);
  uint32_t bytes_mul32;
  uint32_t doc_mul32;
  // Document boundaries are encapsulated in the GSA
  // because the lexicographical sort puts \0 entries
  // at the top; the first doc_count entries
  // represent the start/end positions of each doc
  int32_t doc_count;
  int32_t *gsa;
  int32_t *suffix_to_doc;
  uint16_t *dedup_counters;
} docs;

static inline void docs_push(const uint8_t *utf8, int32_t len) {
  // len should include null-terminator
  array_extend_zero(&arena_docs, &docs, utf8, (uint32_t)len);
  ++docs.doc_count;
}

static inline void docs_pop(int32_t len) {
  array_shrink(&docs, (uint32_t)len);
  --docs.doc_count;
}

typedef struct Directory_Node {
  array_struct_members(int32_t);
  uint32_t str_offset;
} Directory_Node;

typedef struct Directory_Path {
#ifdef _WIN32
  wchar_t path[CIN_MAX_PATH];
#else
  char path[CIN_MAX_PATH];
#endif
  size_t len;
} Directory_Path;

array_define(Tag_Directories, int32_t);
array_define(Tag_Pattern_Items, int32_t);
array_define(Tag_Url_Items, int32_t);

typedef struct Playlist {
  array_struct_members(int32_t);
  uint32_t next_index;
  uint32_t targets;
  bool from_tag;
  bool empty;
  // search table key not applicable to tag playlist
  table_key_pos search_pos;
  table_key_len search_len;
  cache_node_struct_members(Playlist);
} Playlist;

cache_define(Playlist_Cache, Playlist);
array_define(Search_Patterns, uint8_t);
array_define(Hidden_Table, int32_t);

extern struct Media {
  Playlist default_playlist;
  Playlist_Cache playlists;
  Robin_Hood_Table search_table;
  Search_Patterns search_patterns;
  Hidden_Table hidden_table;
} media;

typedef struct Tag_Items {
  Playlist *playlist;
  Tag_Directories *directories;
  Tag_Pattern_Items *pattern_items;
  Tag_Url_Items *url_items;
} Tag_Items;

typedef struct Cin_Screen {
  uint32_t offset;
  uint32_t len;
} Cin_Screen;

typedef struct Cin_Layout {
  RECT chat_rect;
  int32_t scope_line;
  array_struct_members(Cin_Screen);
  uint32_t name_offset;
  uint32_t name_len;
} Cin_Layout;

typedef struct Cin_Macro {
  array_struct_members(char);
} Cin_Macro;

extern struct Directory_Stack {
  array_struct_members(Directory_Path);
  uint32_t abs_count;
} dir_stack;

extern struct Clipboard {
  array_struct_members(char);
  size_t supply;
  size_t demand;
} clipboard;

extern array_struct_named(Directory_Strings, uint8_t) directory_strings;
extern array_struct_named(Directory_Nodes, Directory_Node) directory_nodes;
extern array_struct_named(Layout_Strings, uint8_t) layout_strings;
extern array_struct_named(Screen_Strings, uint8_t) screen_strings;
extern array_struct_named(Geometry_Buffer, char) geometry_buf;
extern array_struct_named(Startup_Macros, Cin_Macro *) startup_macros;

#define CIN_DIRECTORIES_CAP 64
#define CIN_DIRECTORY_ITEMS_CAP 64
#define CIN_DIRECTORY_STRINGS_CAP (CIN_DIRECTORIES_CAP * CIN_MAX_PATH_BYTES)
#define CIN_PATTERN_ITEMS_CAP 64
#define CIN_URLS_CAP 64
#define CIN_LAYOUT_SCREENS_CAP 8
#define CIN_QUERIES_CAP 8

extern Radix_Tree *tag_tree;
extern Radix_Tree *layout_tree;
extern Radix_Tree *macro_tree;

#ifdef _WIN32
void setup_file_path_char(char *path, int32_t *len);
void setup_file_path_wchar_t(wchar_t *path, int32_t *len);
#else
void setup_file_path(char *dst, const char *src, size_t dst_size);
#endif

void setup_directory(const char *path, Tag_Directories *tag_dirs);
void setup_pattern(const char *pattern, Tag_Pattern_Items *tag_pattern_items);
void setup_url(char *url, Tag_Url_Items *tag_url_items);
void setup_tag(char *tag, Tag_Items *tag_items);
bool setup_chat(const char *geometry, uint32_t len, Cin_Layout *layout);
void setup_screen(const char *geometry, Cin_Layout *layout);
void setup_layout(char *name, Cin_Layout *layout);
void setup_macro(char *name, Cin_Macro *macro, bool startup);
void setup_macro_command(char *command, Cin_Macro *macro);
void setup_settings(Conf_Key *src, char *dst);

bool init_config(const char *filename);
bool reinit_documents(void);
bool init_documents(void);
void document_listing(const uint8_t *pattern, int32_t pattern_len, Playlist *result);

#endif