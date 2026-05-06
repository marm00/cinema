#include "radix.h"

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
