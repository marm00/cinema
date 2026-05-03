#ifndef CIN_ARRAY_H
#define CIN_ARRAY_H

#include "arena.h"
#include "common.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define array_struct_members(T) \
  T *items;                     \
  uint32_t count;               \
  uint32_t capacity;            \
  uint32_t bytes_capacity;      \
  uint32_t bytes_capacity_k

#define array_struct(T)      \
  struct {                   \
    array_struct_members(T); \
  }

#define array_struct_named(name, T) \
  struct name {                     \
    array_struct_members(T);        \
  }

#define array_define(name, T) \
  typedef struct name {       \
    array_struct_members(T);  \
  } name

#define array_init_core(arena, a, n, zero)                          \
  do {                                                              \
    Arena_Slice _slice = {0};                                       \
    arena_slice_reinit((arena), &_slice, sizeof(*(a)->items) * (n), \
                       align_size(*(a)->items), (zero));            \
    (a)->items = (void *)_slice.items;                              \
    (a)->count = 0;                                                 \
    (a)->capacity = _slice.size / sizeof(*(a)->items);              \
    (a)->bytes_capacity = _slice.size;                              \
    (a)->bytes_capacity_k = _slice.k;                               \
  } while (0)

#define array_init(arena, a, n) \
  array_init_core((arena), (a), (n), false)

#define array_init_zero(arena, a, n) \
  array_init_core((arena), (a), (n), true)

#define array_create(arena, slice) \
  arena_slice_reinit((arena), &slice, CIN_ARRAY_SIZE, align_size(CIN_ARRAY_SIZE), false)

#define array_free_items(arena, a)                                                        \
  if ((a)->items) arena_free_pow2((arena), &(Arena_Slice){.items = (uint8_t *)(a)->items, \
                                                          .k = (a)->bytes_capacity_k,     \
                                                          .size = 0})

#define array_free(arena, a)                                          \
  do {                                                                \
    array_free_items((arena), (a));                                   \
    arena_free_pow1((arena), &(Arena_Slice){.items = (uint8_t *)(a),  \
                                            .k = 0,                   \
                                            .size = CIN_ARRAY_SIZE}); \
  } while (0)

#define array_ensure_capacity_core(arena, a, total, zero)                         \
  do {                                                                            \
    if ((total) > (a)->capacity) {                                                \
      if (!(a)->capacity) {                                                       \
        array_init_core((arena), (a), (total), (zero));                           \
      } else {                                                                    \
        if (unlikely((a)->bytes_capacity_k >= CIN_ARENA_MAX_K)) {                 \
          printf("Cinema crashed trying to allocate excessive memory (%u bytes)", \
                 (a)->bytes_capacity << 1);                                       \
          exit(1);                                                                \
        }                                                                         \
        Arena_Slice _tmp = {0};                                                   \
        arena_slice_reinit((arena), &_tmp, (total) * sizeof(*(a)->items),         \
                           align_size(*(a)->items), (zero));                      \
        memcpy(_tmp.items, (a)->items, (a)->bytes_capacity);                      \
        array_free_items((arena), (a));                                           \
        (a)->items = (void *)_tmp.items;                                          \
        (a)->capacity = _tmp.size / sizeof(*(a)->items);                          \
        (a)->bytes_capacity = _tmp.size;                                          \
        (a)->bytes_capacity_k = _tmp.k;                                           \
      }                                                                           \
    }                                                                             \
  } while (0)

#define array_reserve_core(arena, a, n, zero) \
  array_ensure_capacity_core((arena), (a), (a)->count + (n), (zero))

#define array_reserve(arena, a, n) \
  array_reserve_core((arena), (a), (n), false)

#define array_reserve_zero(arena, a, n) \
  array_reserve_core((arena), (a), (n), true)

#define array_resize(arena, a, total)                         \
  do {                                                        \
    array_ensure_capacity_core((arena), (a), (total), false); \
    (a)->count = (total);                                     \
  } while (0)

#define array_grow(arena, a, n)       \
  do {                                \
    array_reserve((arena), (a), (n)); \
    (a)->count += (n);                \
  } while (0)

#define array_push_core(arena, a, item, zero)    \
  do {                                           \
    array_reserve_core((arena), (a), 1, (zero)); \
    (a)->items[(a)->count++] = (item);           \
  } while (0)

#define array_push(arena, a, item) \
  array_push_core((arena), (a), (item), false)

#define array_push_zero(arena, a, item) \
  array_push_core((arena), (a), (item), true)

#define array_set(arena, a, new_items, n)                       \
  do {                                                          \
    array_resize((arena), (a), (n));                            \
    memcpy((a)->items, (new_items), (n) * sizeof(*(a)->items)); \
  } while (0)

#define array_copy_shallow(arena, to, from)        \
  do {                                             \
    *(to) = *(from);                               \
    array_init_zero((arena), (to), (from)->count); \
  } while (0)

#define array_copy_deep(arena, to, from)                    \
  do {                                                      \
    *(to) = *(from);                                        \
    array_init((arena), (to), (from)->count);               \
    array_set((arena), (to), (from)->items, (from)->count); \
  } while (0)

#define array_extend_core(arena, a, new_items, n, zero)                      \
  do {                                                                       \
    array_reserve_core((arena), (a), (n), (zero));                           \
    memcpy((a)->items + (a)->count, (new_items), (n) * sizeof(*(a)->items)); \
    (a)->count += (n);                                                       \
  } while (0)

#define array_extend(arena, a, new_items, n) \
  array_extend_core((arena), (a), (new_items), (n), false)

#define array_extend_zero(arena, a, new_items, n) \
  array_extend_core((arena), (a), (new_items), (n), true)

#define array_sextend(arena, a, new_items) \
  array_extend((arena), (a), (new_items),  \
               sizeof((new_items)) / sizeof(*((new_items))) - 1)

#define array_splice(arena, a, i, new_items, n)                       \
  do {                                                                \
    assert((i) <= (a)->count);                                        \
    array_reserve((arena), (a), (n));                                 \
    memmove((a)->items + (i) + (n),                                   \
            (a)->items + (i),                                         \
            ((a)->count - (i)) * sizeof(*(a)->items));                \
    memcpy((a)->items + (i), (new_items), (n) * sizeof(*(a)->items)); \
    (a)->count += (n);                                                \
  } while (0)

#define array_insert(arena, a, i, new_item)              \
  do {                                                   \
    assert((i) <= (a)->count);                           \
    array_reserve((arena), (a), 1);                      \
    if ((i) < (a)->count) {                              \
      memmove((a)->items + (i) + 1,                      \
              (a)->items + (i),                          \
              ((a)->count - (i)) * sizeof(*(a)->items)); \
    }                                                    \
    (a)->items[(i)] = (new_item);                        \
    (a)->count++;                                        \
  } while (0)

#define array_remove(a, i)                               \
  do {                                                   \
    assert((i) <= (a)->count);                           \
    if ((i) < (a)->count) {                              \
      memmove((a)->items + (i) + 1,                      \
              (a)->items + (i),                          \
              ((a)->count - (i)) * sizeof(*(a)->items)); \
    }                                                    \
    --(a)->count;                                        \
  } while (0)

#define array_pop(a)    \
  do {                  \
    assert((a)->count); \
    --(a)->count;       \
  } while (0)

#define array_shrink(a, n)     \
  do {                         \
    assert((a)->count >= (n)); \
    (a)->count -= (n);         \
  } while (0)

#define array_clear(a) (a)->count = 0

#define array_bytes(a) \
  ((a)->count * sizeof(*(a)->items))

#define array_to_pow1(arena, a)                                        \
  do {                                                                 \
    uint32_t _nbytes = align_to_size(array_bytes((a)));                \
    assert(_nbytes <= (a)->bytes_capacity);                            \
    uint32_t _diff = (a)->bytes_capacity - _nbytes;                    \
    if (_diff >= CIN_ARENA_MIN) {                                      \
      arena_free_pos((arena), (uint8_t *)(a)->items + _nbytes, _diff); \
    }                                                                  \
    (a)->capacity = _nbytes / sizeof(*(a)->items);                     \
    assert((a)->capacity >= (a)->count);                               \
    (a)->bytes_capacity = _nbytes;                                     \
    (a)->bytes_capacity_k = 0;                                         \
  } while (0)

#define array_foreach(a, T, i, o)                           \
  for (uint32_t i = 0, _j = 0; i < (a)->count; _j = 0, ++i) \
    for (T o = (a)->items[i]; _j == 0; _j = 1)

#define array_shuffle_fisher_yates(a, T, tail, head) \
  do {                                               \
    for (uint32_t _i = (tail); _i >= (head); --_i) { \
      uint32_t _j = rand_between(0, _i);             \
      T _tmp = (a)->items[_j];                       \
      (a)->items[_j] = (a)->items[_i];               \
      (a)->items[_i] = _tmp;                         \
    }                                                \
  } while (0)

#define array_shuffle_sattolo(a, T, tail, head)     \
  do {                                              \
    for (uint32_t _i = (tail); _i > (head); --_i) { \
      uint32_t _j = rand_between((head), _i - 1);   \
      T _tmp = (a)->items[_j];                      \
      (a)->items[_j] = (a)->items[_i];              \
      (a)->items[_i] = _tmp;                        \
    }                                               \
  } while (0)

#ifdef _WIN32

#include <wchar.h>

#define array_wextend(arena, a, new_items, n)           \
  do {                                                  \
    array_reserve((arena), (a), (n));                   \
    wmemcpy((a)->items + (a)->count, (new_items), (n)); \
    (a)->count += (n);                                  \
  } while (0)

#define array_wsextend(arena, a, new_items) \
  array_wextend((arena), (a), (new_items),  \
                sizeof((new_items)) / sizeof(*((new_items))) - 1)

#define array_wsplice(arena, a, i, new_items, n)                          \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((arena), (a), (n));                                     \
    wmemmove((a)->items + (i) + (n), (a)->items + (i), (a)->count - (i)); \
    wmemcpy((a)->items + (i), (new_items), (n));                          \
    (a)->count += (n);                                                    \
  } while (0)

#define array_winsert(arena, a, i, new_item)                              \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((arena), (a), 1);                                       \
    if ((i) < (a)->count) {                                               \
      wmemmove((a)->items + (i) + 1, (a)->items + (i), (a)->count - (i)); \
    }                                                                     \
    (a)->items[(i)] = (new_item);                                         \
    (a)->count++;                                                         \
  } while (0)
#endif

#endif