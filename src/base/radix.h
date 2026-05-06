#ifndef CIN_RADIX_H
#define CIN_RADIX_H

#include <stdint.h>

#include "arena.h"

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

#endif