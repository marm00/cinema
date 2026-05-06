#ifndef CIN_PATRICIA_H
#define CIN_PATRICIA_H

#include "arena.h"
#include <stdint.h>

typedef void (*patricia_fn)(void);

#define PATRICIA_ALPHABET_SIZE 26

typedef struct Patricia_Node {
  struct Patricia_Node *edges[PATRICIA_ALPHABET_SIZE];
  const char *suffix;
  size_t len;
  patricia_fn fn;
  int32_t min;
} Patricia_Node;

Patricia_Node *patricia_node(Arena *arena, const char *suffix, size_t len);
size_t patricia_lcp(const char *a, const char *b, size_t max);
patricia_fn patricia_query(Patricia_Node *root, const char *pattern);
void patricia_insert(Arena *arena, Patricia_Node *root, const char *str, patricia_fn fn);

#endif