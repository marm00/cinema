#include "misc.h"

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

Patricia_Node *patricia_node(Arena *arena, const char *suffix, size_t len) {
  Patricia_Node *node = arena_bump_T1(arena, Patricia_Node);
  assert(node);
  node->suffix = suffix;
  node->len = len;
  return node;
}

size_t patricia_lcp(const char *a, const char *b, size_t max) {
  size_t i = 0;
  while (i < max && a[i] && a[i] == b[i]) ++i;
  return i;
}

patricia_fn patricia_query(Patricia_Node *root, const char *pattern) {
  assert(root);
  assert(strlen(pattern) > 0);
  assert((*pattern >= 'a' && *pattern <= 'z'));
  Patricia_Node *node = root;
  const char *p = pattern;
  while (*p) {
    assert((*p >= 'a' && *p <= 'z'));
    const int32_t i = *p - 'a';
    Patricia_Node *edge = node->edges[i];
    if (edge == NULL) {
      return NULL;
    }
    const size_t common = patricia_lcp(p, edge->suffix, edge->len);
    if (p[common] == '\0') {
      return edge->fn;
    }
    if (common < edge->len) {
      return NULL;
    }
    p += common;
    node = edge;
  }
  return node->fn;
}

void patricia_insert(Arena *arena, Patricia_Node *root, const char *str, patricia_fn fn) {
  assert(root);
  assert(strlen(str) > 0);
  assert((*str >= 'a' && *str <= 'z'));
  Patricia_Node *node = root;
  const char *p = str;
  while (*p) {
    assert((*p >= 'a' && *p <= 'z'));
    const int32_t i = *p - 'a';
    Patricia_Node *edge = node->edges[i];
    if (edge == NULL) {
      const size_t edge_len = strlen(p);
      edge = patricia_node(arena, p, edge_len);
      edge->fn = fn;
      node->edges[i] = edge;
      if ((node->min == -1) || i < node->min) {
        // update parent lexicographical minimum
        node->min = i;
        node->fn = fn;
      }
      return;
    }
    const size_t common = patricia_lcp(p, edge->suffix, edge->len);
    if (common == edge->len) {
      p += common;
      if (*p == '\0') {
        edge->min = -1;
        edge->fn = fn;
        return;
      }
      node = edge;
    } else {
      Patricia_Node *split = patricia_node(arena, edge->suffix, common);
      edge->suffix += common;
      edge->len -= common;
      node->edges[i] = split;
      split->edges[edge->suffix[0] - 'a'] = edge;
      p += common;
      if (*p == '\0') {
        split->min = -1;
        split->fn = fn;
      } else {
        const size_t remainder_len = strlen(p);
        Patricia_Node *remainder = patricia_node(arena, p, remainder_len);
        remainder->fn = fn;
        const int32_t edge_i = edge->suffix[0] - 'a';
        const int32_t next_i = *p - 'a';
        split->edges[next_i] = remainder;
        // update internal node lexicographical minimum
        if (next_i < edge_i) {
          split->min = next_i;
          split->fn = fn;
        } else {
          split->min = edge_i;
          split->fn = edge->fn;
        }
      }
      return;
    }
  }
}

int32_t radix_bit(const uint8_t *key, size_t len, size_t critical, uint8_t bitmask) {
  return critical < len && key[critical] & bitmask;
}

void radix_critical(const uint8_t *k1, size_t len1,
                    const uint8_t *k2, size_t len2,
                    size_t *critical, uint8_t *bitmask) {
  const size_t max_len = max(len1, len2);
  for (size_t i = 0; i < max_len; ++i) {
    const uint8_t b1 = (i < len1) ? k1[i] : 0;
    const uint8_t b2 = (i < len2) ? k2[i] : 0;
    if (b1 != b2) {
      const uint8_t diff = b1 ^ b2;
      *critical = i;
      *bitmask = 0x80;
      while ((*bitmask & diff) == 0) {
        *bitmask >>= 1;
      }
      return;
    }
  }
  *critical = max_len;
  *bitmask = 0x80;
}

Radix_Leaf *radix_leaf(Arena *arena, const uint8_t *key, size_t len, radix_v v) {
  Radix_Leaf *leaf = arena_bump_T1(arena, Radix_Leaf);
  assert(leaf);
  leaf->base.type = RADIX_LEAF;
  leaf->base.v = v;
  assert(len <= CIN_ARENA_MAX);
  uint8_t *dup = arena_bump_T(arena, uint8_t, (uint32_t)len + 1);
  assert(dup);
  memcpy(dup, key, len);
  dup[len] = '\0';
  leaf->key = dup;
  leaf->len = len;
  return leaf;
}

Radix_Internal *radix_internal(Arena *arena, size_t critical, uint8_t bitmask) {
  Radix_Internal *node = arena_bump_T1(arena, Radix_Internal);
  assert(node);
  node->base.type = RADIX_INTERNAL;
  node->base.v = NULL;
  node->critical = critical;
  node->bitmask = bitmask;
  node->child[0] = NULL;
  node->child[1] = NULL;
  return node;
}

int32_t radix_compare(const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2) {
  const size_t min_len = min(len1, len2);
  const int32_t cmp = memcmp(k1, k2, min_len);
  if (cmp != 0) return cmp;
  if (len1 < len2) return -1;
  if (len1 > len2) return 1;
  return 0;
}

void radix_update(Radix_Internal *internal) {
  Radix_Node *bit0 = internal->child[0];
  Radix_Node *bit1 = internal->child[1];
  if (bit0 && bit1) {
    Radix_Leaf *leaf0 = (Radix_Leaf *)bit0;
    Radix_Leaf *leaf1 = (Radix_Leaf *)bit1;
    while (leaf0->base.type == RADIX_INTERNAL) {
      Radix_Internal *int0 = (Radix_Internal *)leaf0;
      leaf0 = (Radix_Leaf *)(int0->child[0] ? int0->child[0] : int0->child[1]);
    }
    while (leaf1->base.type == RADIX_INTERNAL) {
      Radix_Internal *int1 = (Radix_Internal *)leaf1;
      leaf1 = (Radix_Leaf *)(int1->child[0] ? int1->child[0] : int1->child[1]);
    }
    if (radix_compare(leaf0->key, leaf0->len, leaf1->key, leaf1->len) < 0) {
      internal->base.v = internal->child[0]->v;
    } else {
      internal->base.v = internal->child[1]->v;
    }
  } else if (bit0) {
    internal->base.v = bit0->v;
  } else if (bit1) {
    internal->base.v = bit1->v;
  }
}

Radix_Tree *radix_tree(Arena *arena) {
  Radix_Tree *tree = arena_bump_T1(arena, Radix_Tree);
  assert(tree);
  tree->root = NULL;
  return tree;
}

void radix_insert(Arena *arena, Radix_Tree *tree, const uint8_t *key, size_t len, radix_v v) {
  assert(tree);
  assert(key);
  if (!tree->root) {
    tree->root = (Radix_Node *)radix_leaf(arena, key, len, v);
    return;
  }
  Radix_Node *node = tree->root;
  while (node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    const int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    Radix_Node *next = internal->child[bit];
    if (!next) {
      internal->child[bit] = (Radix_Node *)radix_leaf(arena, key, len, v);
      radix_update(internal);
      if (tree->root->type == RADIX_INTERNAL) {
        radix_update((Radix_Internal *)tree->root);
      }
      return;
    }
    node = next;
  }
  Radix_Leaf *leaf = (Radix_Leaf *)node;
  if (len == leaf->len && memcmp(key, leaf->key, len) == 0) {
    leaf->base.v = v;
    return;
  }
  size_t critical;
  uint8_t bitmask;
  radix_critical(key, len, leaf->key, leaf->len, &critical, &bitmask);
  Radix_Node **parent = &tree->root;
  node = tree->root;
  while (node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    if (internal->critical > critical ||
        (internal->critical == critical && internal->bitmask < bitmask)) {
      break;
    }
    const int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    parent = &internal->child[bit];
    node = internal->child[bit];
    if (!node) break;
  }
  Radix_Internal *new_internal = radix_internal(arena, critical, bitmask);
  const int32_t new_bit = radix_bit(key, len, critical, bitmask);
  Radix_Leaf *new_leaf = radix_leaf(arena, key, len, v);
  new_internal->child[new_bit] = (Radix_Node *)new_leaf;
  new_internal->child[new_bit ^ 1] = *parent;
  radix_update(new_internal);
  *parent = (Radix_Node *)new_internal;
}

radix_v radix_query(Radix_Tree *tree, const uint8_t *pattern, size_t len, const uint8_t **out) {
  assert(tree);
  assert(pattern);
  Radix_Node *node = tree->root;
  while (node) {
    if (node->type == RADIX_LEAF) {
      Radix_Leaf *leaf = (Radix_Leaf *)node;
      if (leaf->len >= len && memcmp(leaf->key, pattern, len) == 0) {
        if (out) *out = leaf->key;
        return leaf->base.v;
      }
      return NULL;
    }
    Radix_Internal *internal = (Radix_Internal *)node;
    const int32_t bit = radix_bit(pattern, len, internal->critical, internal->bitmask);
    node = internal->child[bit];
  }
  return NULL;
}

Radix_Leaf *radix_leftmost(Radix_Node *node) {
  if (!node) return NULL;
  while (node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    node = internal->child[0] ? internal->child[0] : internal->child[1];
  }
  return (Radix_Leaf *)node;
}

Radix_Leaf *radix_next(Radix_Tree *tree, Radix_Leaf *current) {
  assert(current);
  assert(tree->root);
  const uint8_t *key = current->key;
  const size_t len = current->len;
  Radix_Node *node = tree->root;
  Radix_Node *candidate = NULL;
  while (node && node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    const int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    if (bit == 0 && internal->child[1]) candidate = internal->child[1];
    node = internal->child[bit];
  }
  return radix_leftmost(candidate);
}

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
    exit(1);
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
