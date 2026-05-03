#ifndef CIN_CACHE_H
#define CIN_CACHE_H

#include "arena.h"
#include "common.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#define cache_node_struct_members(T_struct) \
  struct T_struct *next;                    \
  struct T_struct *next_free

#define cache_node_struct(T_struct)      \
  struct {                               \
    cache_node_struct_members(T_struct); \
  }

#define cache_node_define(T_name)      \
  typedef struct T_name {              \
    cache_node_struct_members(T_name); \
  } T_name

#define cache_struct_members(T_node) \
  T_node *head;                      \
  T_node *tail;                      \
  T_node *free_list;                 \
  uint32_t cache_node_bytes;         \
  uint32_t cache_node_align

#define cache_struct(T_node)      \
  struct {                        \
    cache_struct_members(T_node); \
  }

#define cache_define(name, T_node) \
  typedef struct name {            \
    cache_struct_members(T_node);  \
  } name

#define CIN_CACHE_NODE_SIZE sizeof(cache_node_struct(void))
#define CIN_CACHE_SIZE sizeof(cache_struct(void))

#define cache_init_core(arena, c, n, init_free)                   \
  do {                                                            \
    assert((n) > 0 && "must initialize at least 1 node");         \
    (c)->cache_node_bytes = sizeof(*(c)->head);                   \
    (c)->cache_node_align = align_size(*(c)->head);               \
    (c)->head = arena_bump((arena), (c)->cache_node_bytes * (n),  \
                           (c)->cache_node_align);                \
    if ((init_free)) (c)->free_list = (c)->head;                  \
    (c)->tail = (c)->head;                                        \
    for (uint32_t _i = 1, _offset = (c)->cache_node_bytes;        \
         _i < (n);                                                \
         ++_i, _offset += (c)->cache_node_bytes) {                \
      (c)->tail->next = (void *)((uint8_t *)(c)->head + _offset); \
      if ((init_free)) (c)->tail->next_free = (c)->tail->next;    \
      (c)->tail = (c)->tail->next;                                \
    }                                                             \
  } while (0)

#define cache_create(arena) \
  arena_bump((arena), CIN_CACHE_SIZE, align_size(CIN_CACHE_SIZE))

#define cache_free_items(arena, c)                                                        \
  for ((c)->free_list = (c)->head; (c)->free_list; (c)->free_list = (c)->free_list->next) \
  arena_free_pow1((arena), &(Arena_Slice){.items = (uint8_t *)(c)->free_list,             \
                                          .size = (c)->cache_node_bytes,                  \
                                          .k = 0})

#define cache_free(arena, c)                                          \
  do {                                                                \
    cache_free_items((arena), (c));                                   \
    arena_free_pow1((arena), &(Arena_Slice){.items = (uint8_t *)(c),  \
                                            .k = 0,                   \
                                            .size = CIN_CACHE_SIZE}); \
  } while (0)

#define cache_get_core(arena, c, out_node, zero)                   \
  do {                                                             \
    assert((c)->head && "forgot to cache_init_core");              \
    if ((c)->free_list) {                                          \
      out_node = (c)->free_list;                                   \
      (c)->free_list = (c)->free_list->next_free;                  \
      if ((zero)) {                                                \
        void *_next = (out_node)->next;                            \
        memset((out_node), 0, (c)->cache_node_bytes);              \
        (out_node)->next = _next;                                  \
      }                                                            \
    } else {                                                       \
      assert(!(c)->tail->next);                                    \
      (c)->tail->next = arena_bump((arena), (c)->cache_node_bytes, \
                                   (c)->cache_node_align);         \
      out_node = (c)->tail->next;                                  \
      (c)->tail = (out_node);                                      \
    }                                                              \
  } while (0)

#define cache_get(arena, c, out_node) \
  cache_get_core((arena), (c), (out_node), false)

#define cache_get_zero(arena, c, out_node) \
  cache_get_core((arena), (c), (out_node), true)

#define cache_put(c, in_node)              \
  do {                                     \
    (in_node)->next_free = (c)->free_list; \
    (c)->free_list = (in_node);            \
  } while (0)

#define cache_foreach(c, T, i, o)     \
  for (uint32_t i = 0; i == 0; i = 1) \
    for (T *o = (c)->head; o; o = o->next, ++i)

#endif