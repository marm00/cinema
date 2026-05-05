#ifndef CIN_MISC_H
#define CIN_MISC_H

#include <stdint.h>

#include "arena.h"
#include "array.h"

#define CIN_INTEGER_HASH 2654435761U

size_t deduplicate_i32(Arena *arena, int32_t *items, size_t len);

#define COMMAND_ALPHABET 26

typedef void (*patricia_fn)(void);

typedef struct Patricia_Node {
  struct Patricia_Node *edges[COMMAND_ALPHABET];
  const char *suffix;
  size_t len;
  patricia_fn fn;
  int32_t min;
} Patricia_Node;

Patricia_Node *patricia_node(Arena *arena, const char *suffix, size_t len);
size_t patricia_lcp(const char *a, const char *b, size_t max);
patricia_fn patricia_query(Patricia_Node *root, const char *pattern);
void patricia_insert(Arena *arena, Patricia_Node *root, const char *str, patricia_fn fn);

typedef void *radix_v;

typedef enum {
  RADIX_LEAF,
  RADIX_INTERNAL
} Radix_Node_Type;

typedef struct Radix_Node {
  Radix_Node_Type type;
  radix_v v;
} Radix_Node;

typedef struct Radix_Leaf {
  Radix_Node base;
  const uint8_t *key;
  size_t len;
} Radix_Leaf;

typedef struct Radix_Internal {
  Radix_Node base;
  size_t critical;
  uint8_t bitmask;
  Radix_Node *child[2];
} Radix_Internal;

typedef struct Radix_Tree {
  Radix_Node *root;
} Radix_Tree;

int32_t radix_bit(const uint8_t *key, size_t len, size_t critical, uint8_t bitmask);
void radix_critical(const uint8_t *k1, size_t len1,
                    const uint8_t *k2, size_t len2,
                    size_t *critical, uint8_t *bitmask);
Radix_Leaf *radix_leaf(Arena *arena, const uint8_t *key, size_t len, radix_v v);
Radix_Internal *radix_internal(Arena *arena, size_t critical, uint8_t bitmask);
int32_t radix_compare(const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2);
void radix_update(Radix_Internal *internal);
Radix_Tree *radix_tree(Arena *arena);
void radix_insert(Arena *arena, Radix_Tree *tree, const uint8_t *key, size_t len, radix_v v);
radix_v radix_query(Radix_Tree *tree, const uint8_t *pattern, size_t len, const uint8_t **out);
Radix_Leaf *radix_leftmost(Radix_Node *node);
Radix_Leaf *radix_next(Radix_Tree *tree, Radix_Leaf *current);

static inline uint64_t fnv1a_hash(const uint8_t *str, uint32_t len) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (uint32_t i = 0; i < len; ++i) {
    hash ^= str[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

typedef uint8_t table_key_t;
typedef uint32_t table_key_pos;
typedef uint32_t table_key_len;
typedef intptr_t table_value;

typedef struct Table_Key {
  table_key_t *strings;
  table_key_pos pos;
  table_key_len len;
} Table_Key;

typedef struct Table_Bucket {
  // key is (char *)strings + pos
  // value is value
  uint64_t hash;
  table_value value;
  uint32_t dist;
  table_key_pos pos;
  bool filled;
  bool deleted;
  // NOTE: free bytes remaining
} Table_Bucket;

typedef struct Robin_Hood_Table {
  array_struct_members(Table_Bucket);
  uint64_t mask;
} Robin_Hood_Table;

#define TABLE_LOAD_FACTOR 85

void table_init(Arena *arena, Robin_Hood_Table *table, uint32_t capacity);
void table_double(Arena *arena, Robin_Hood_Table *table);
table_value table_find(Robin_Hood_Table *table, const Table_Key *key);
table_value table_insert(Arena *arena, Robin_Hood_Table *table,
                         const Table_Key *key, table_value value);
table_value table_delete(Robin_Hood_Table *table, const Table_Key *key);
void table_free_items(Arena *arena, Robin_Hood_Table *table);

#endif
