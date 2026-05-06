#ifndef CIN_TABLE_H
#define CIN_TABLE_H

#include <stdint.h>

#include "arena.h"
#include "array.h"

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

#define CIN_INTEGER_HASH 2654435761U

size_t deduplicate_i32(Arena *arena, int32_t *items, size_t len);

static inline uint64_t fnv1a_hash(const uint8_t *str, uint32_t len) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (uint32_t i = 0; i < len; ++i) {
    hash ^= str[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

#endif