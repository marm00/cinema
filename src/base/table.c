#include "table.h"

void table_init(Arena *arena, Robin_Hood_Table *table, uint32_t capacity) {
  assert(table->capacity == 0);
  assert(capacity > 0);
  table->items = arena_bump_T(arena, Table_Bucket, capacity);
  array_clear(table);
  table->capacity = capacity;
  table->bytes_capacity = capacity * sizeof(Table_Bucket);
  table->bytes_capacity_k = 0;
  table->mask = table->capacity - 1;
}

void table_double(Arena *arena, Robin_Hood_Table *table) {
  if (unlikely(table->bytes_capacity >= CIN_ARENA_MAX)) {
    printf("Cinema crashed trying to allocate excessive memory (%u bytes)",
           table->bytes_capacity << 1);
    cin_exit(1);
  }
  const uint32_t prev_bytes_cap = table->bytes_capacity;
  const uint32_t prev_cap = table->capacity;
  Table_Bucket *prev_buckets = table->items;
  table->capacity <<= 1;
  table->items = arena_bump_T(arena, Table_Bucket, table->capacity);
  table->bytes_capacity <<= 1;
  array_clear(table);
  table->mask = table->capacity - 1;
  assert(prev_buckets != table->items);
  assert(table->capacity > 0);
  assert(cin_ispow2(table->capacity));
  for (uint32_t i = 0; i < prev_cap; ++i) {
    if (prev_buckets[i].filled && !prev_buckets[i].deleted) {
      uint64_t home = prev_buckets[i].hash & table->mask;
      uint32_t dist = 0;
      Table_Bucket candidate = prev_buckets[i];
      while (table->items[home].filled) {
        if (dist > table->items[home].dist) {
          candidate.dist = dist;
          Table_Bucket tmp = table->items[home];
          table->items[home] = candidate;
          candidate = tmp;
        }
        home = (home + 1) & table->mask;
        ++dist;
      }
      table->items[home] = candidate;
      table->items[home].dist = dist;
      ++table->count;
    }
  }
  arena_free_pos(arena, (uint8_t *)prev_buckets, prev_bytes_cap);
}

table_value table_find(Robin_Hood_Table *table, const Table_Key *key) {
  table_key_t *str = key->strings + key->pos;
  const uint64_t hash = fnv1a_hash(str, key->len);
  uint64_t i = hash & table->mask;
  uint32_t dist = 0;
  while (table->items[i].filled) {
    Table_Bucket bucket = table->items[i];
    if (!bucket.deleted) {
      table_key_t *bucket_str = key->strings + bucket.pos;
      if (hash == bucket.hash && strcmp((char *)str, (char *)bucket_str) == 0) {
        return bucket.value;
      }
    }
    if (dist > bucket.dist) return -1;
    i = (i + 1) & table->mask;
    ++dist;
  }
  return -1;
}

table_value table_insert(Arena *arena, Robin_Hood_Table *table,
                         const Table_Key *key, table_value value) {
  // robin hood hashing (with tombstones) with fnv-1a
  table_key_t *str = key->strings + key->pos;
  if (table->count >= (table->capacity * TABLE_LOAD_FACTOR) / 100) {
    table_double(arena, table);
  }
  const uint64_t hash = fnv1a_hash(str, key->len);
  uint64_t i = hash & table->mask;
  uint32_t dist = 0;
  uint64_t tombstone = SIZE_MAX;
  uint32_t tombstone_dist = 0;
  Table_Bucket candidate = {.hash = hash, .dist = 0, .value = value, .pos = key->pos, .filled = true, .deleted = false};
  while (table->items[i].filled) {
    if (table->items[i].deleted) {
      if (tombstone == SIZE_MAX) {
        tombstone = i;
        tombstone_dist = dist;
      }
    } else {
      table_key_t *i_str = key->strings + table->items[i].pos;
      if (table->items[i].hash == hash && strcmp((char *)i_str, (char *)str) == 0) {
        // Found duplicate key (str) in hashmap
        return table->items[i].value;
      }
      if (tombstone == SIZE_MAX && dist > table->items[i].dist) {
        // evict rich to house poor
        candidate.dist = dist;
        Table_Bucket tmp = table->items[i];
        table->items[i] = candidate;
        candidate = tmp;
        str = i_str;
      }
    }
    i = (i + 1) & table->mask;
    ++dist;
  }
  if (tombstone == SIZE_MAX) {
    table->items[i] = candidate;
    table->items[i].dist = dist;
    ++table->count;
  } else {
    table->items[tombstone] = candidate;
    table->items[tombstone].dist = tombstone_dist;
  }
  assert(value >= 0);
  assert(table_find(table, key) >= 0);
  return -1;
}

table_value table_delete(Robin_Hood_Table *table, const Table_Key *key) {
  table_key_t *str = key->strings + key->pos;
  const uint64_t hash = fnv1a_hash(str, key->len);
  uint64_t i = hash & table->mask;
  while (table->items[i].filled) {
    if (!table->items[i].deleted) {
      table_key_t *i_str = key->strings + table->items[i].pos;
      if (table->items[i].hash == hash && strcmp((char *)i_str, (char *)str) == 0) {
        table->items[i].deleted = true;
        return table->items[i].value;
      }
    }
    i = (i + 1) & table->mask;
  }
  assert(false && "tried to delete a key that does not exist");
  return -1;
}

void table_free_items(Arena *arena, Robin_Hood_Table *table) {
  if (table->items) arena_free_pos(arena, (uint8_t *)table->items, table->bytes_capacity);
}

size_t deduplicate_i32(Arena *arena, int32_t *items, size_t len) {
  if (len <= 128) {
    size_t k = 0;
    for (size_t i = 0; i < len; ++i) {
      size_t j;
      for (j = 0; j < k; ++j) {
        if (items[i] == items[j]) break;
      }
      if (j == k) items[k++] = items[i];
    }
    return k;
  } else {
    size_t hash_n = 1;
    while (hash_n < len * 2) hash_n <<= 1;
    assert(hash_n <= CIN_ARENA_MAX);
    int32_t *seen = arena_bump_T(arena, int32_t, (uint32_t)hash_n);
    int32_t *set = arena_bump_T(arena, int32_t, (uint32_t)hash_n);
    size_t k = 0;
    const size_t mask = hash_n - 1;
    for (size_t i = 0; i < len; ++i) {
      const int32_t v = items[i];
      const size_t hash = (size_t)v * CIN_INTEGER_HASH;
      size_t index = hash & mask;
      while (set[index]) {
        if (seen[index] == v) goto next;
        index = (index + 1) & mask;
      }
      seen[index] = v;
      set[index] = 1;
      items[k++] = v;
    next:;
    }
    arena_free_pos(arena, (uint8_t *)seen, (uint32_t)hash_n);
    arena_free_pos(arena, (uint8_t *)set, (uint32_t)hash_n);
    return k;
  }
}