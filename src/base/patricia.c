#include "patricia.h"

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