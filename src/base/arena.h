#ifndef CIN_ARENA_H
#define CIN_ARENA_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "core.h"
#include "os/os.h"

#define CIN_ARENA_MIN_K 3U
#define CIN_ARENA_MAX_K 31U
#define CIN_ARENA_MIN (1U << CIN_ARENA_MIN_K)
#define CIN_ARENA_MAX (1U << CIN_ARENA_MAX_K)
#define CIN_ARENA_CAP megabytes(2)
#define CIN_ARENA_BYTES align(sizeof(Arena), 64)
#define CIN_NUM_CLASSES (1U + CIN_ARENA_MAX_K - CIN_ARENA_MIN_K)

typedef struct Arena_Block {
  struct Arena_Block *next;
} Arena_Block;

typedef struct Arena_Chunk {
  struct Arena_Chunk *prev;
  uint32_t count;
  uint32_t capacity;
} Arena_Chunk;

typedef struct Arena {
  Arena_Chunk *curr;
  Arena_Block *free_list[CIN_NUM_CLASSES];
} Arena;

typedef struct Arena_Slice {
  uint8_t *items;
  uint32_t size;
  // if set, assumes size == 1 << k
  uint32_t k;
} Arena_Slice;

#define CIN_ARENA_SLICE_SIZE sizeof(Arena_Slice)
#define CIN_ARENA_HEADER align(sizeof(Arena_Chunk), CIN_ARENA_MIN)

static_assert(sizeof(Arena_Block) == CIN_PTR, "should just hold a pointer");
static_assert(CIN_ARENA_MIN == 8U, "min alloc should be 8 bytes");
static_assert(CIN_ARENA_MAX == gigabytes(2U), "max alloc should be 2gb");

static inline Arena_Chunk *arena_chunk_init(Arena *arena, uint32_t bytes) {
  assert(arena);
  assert(cin_system.page_size <= CIN_ARENA_MAX);
  const size_t dwSize = align(bytes, cin_system.page_size);
  Arena_Chunk *chunk = (Arena_Chunk *)os_alloc(dwSize);
  chunk->prev = arena->curr;
  chunk->count = CIN_ARENA_HEADER;
  chunk->capacity = (uint32_t)dwSize;
  arena->curr = chunk;
  return chunk;
}

static inline uint32_t arena_size_class(uint32_t k) {
  assert(k >= CIN_ARENA_MIN_K);
  return k - CIN_ARENA_MIN_K;
}

static inline void arena_free_pow2(Arena *arena, const Arena_Slice *slice) {
  assert(slice->k && "supposed to free pow2");
  Arena_Block *block = (Arena_Block *)slice->items;
  const uint32_t i = arena_size_class(slice->k);
  block->next = arena->free_list[i];
  arena->free_list[i] = block;
}

static inline uint32_t arena_free_pow1(Arena *arena, const Arena_Slice *slice) {
  assert(!slice->k && "if slice is certainly pow2, just free it directly");
  assert(slice->size && "trying to free void memory");
  const uint32_t aligned_size = slice->size & ~7U;
  uint32_t occupied = aligned_size;
  uint32_t offset = 0;
  while (occupied) {
    const uint32_t k = (uint32_t)__builtin_ctz(occupied);
    const uint32_t _size = 0;
    uint8_t *pos = slice->items + offset;
    Arena_Slice src = {.items = pos, .size = _size, .k = k};
    arena_free_pow2(arena, &src);
    offset += pow2(k);
    occupied &= occupied - 1;
  }
  return aligned_size;
}

static inline uint32_t arena_free_pos(Arena *arena, uint8_t *pos, uint32_t n) {
  Arena_Slice slice = {.items = pos, .size = n, .k = 0};
  const uint32_t freed = arena_free_pow1(arena, &slice);
  return freed;
}

static inline void *arena_bump(Arena *arena, uint32_t bytes, uint32_t alignment) {
  assert(arena);
  assert(arena->curr);
  assert(CIN_ARENA_MAX > bytes);
  uint32_t left = align(arena->curr->count, alignment);
  uint32_t right = left + bytes;
  assert(right <= CIN_ARENA_MAX);
  if (right >= arena->curr->capacity) {
    uint8_t *free_pos = (uint8_t *)arena->curr + arena->curr->count;
    const uint32_t free_n = arena->curr->capacity - arena->curr->count;
    const uint32_t freed = arena_free_pos(arena, free_pos, free_n);
    arena->curr->count += freed;
    uint32_t cap = arena->curr->capacity;
    if (bytes + CIN_ARENA_HEADER > cap) {
      cap = align(bytes + CIN_ARENA_HEADER, alignment);
    }
    arena_chunk_init(arena, cap);
    left = align(arena->curr->count, alignment);
    right = left + bytes;
  }
  arena->curr->count = right;
  return (uint8_t *)arena->curr + left;
}

static inline void arena_slice_reinit(Arena *arena, Arena_Slice *slice, uint32_t bytes, uint32_t alignment, bool zero) {
  assert(arena);
  assert(arena->curr);
  assert(slice);
  assert(CIN_ARENA_MAX > bytes);
  bytes = max(bytes, CIN_ARENA_MIN);
  slice->k = log2_ceil(bytes);
  slice->size = pow2(slice->k);
  const uint32_t cls = arena_size_class(slice->k);
  Arena_Block *block = arena->free_list[cls];
  if (block) {
    arena->free_list[cls] = block->next;
    slice->items = (uint8_t *)block;
    if (zero) memset(slice->items, 0, slice->size);
  } else {
    slice->items = (uint8_t *)arena_bump(arena, slice->size, alignment);
  }
  assert(slice->items);
}

static inline Arena_Slice *arena_slice_create(Arena *arena, uint32_t bytes, uint32_t alignment, bool zero) {
  Arena_Slice stack_slice = {0};
  arena_slice_reinit(arena, &stack_slice, CIN_ARENA_SLICE_SIZE, __alignof(Arena_Slice), false);
  assert(stack_slice.items);
  assert(stack_slice.k == log2_ceil(CIN_ARENA_SLICE_SIZE));
  assert(stack_slice.size == CIN_ARENA_SLICE_SIZE);
  // both the slice and its contents are stored in the arena (at arbitrary positions)
  Arena_Slice *heap_slice = (Arena_Slice *)stack_slice.items;
  arena_slice_reinit(arena, heap_slice, bytes, alignment, zero);
  assert(heap_slice->items);
  assert(heap_slice->k);
  assert(heap_slice->size);
  return heap_slice;
}

static inline void arena_slice_free_items(Arena *arena, Arena_Slice *slice) {
#if __SIZEOF_POINTER__ == 8
  static_assert(cin_ispow2(CIN_ARENA_SLICE_SIZE), "expected slice to be pow2");
  Arena_Slice stack_slice = {.items = (uint8_t *)slice,
                             .size = 0,
                             .k = log2_floor(CIN_ARENA_SLICE_SIZE)};
  arena_free_pow2(arena, &stack_slice);
#else
  Arena_Slice stack_slice = {.items = (uint8_t *)slice,
                             .k = 0,
                             .size = CIN_ARENA_SLICE_SIZE};
  arena_free_pow1(arena, &stack_slice);
#endif
}

static inline void arena_slice_free(Arena *arena, Arena_Slice *slice) {
  arena_free_pow2(arena, slice);
  arena_slice_free_items(arena, slice);
}

#define arena_bump_T(arena, T, n) arena_bump((arena), sizeof(T) * (n), align_size(T))
#define arena_bump_T1(arena, T) arena_bump((arena), sizeof(T), align_size(T))

#endif