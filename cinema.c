// Copyright (c) 2025-2026 marm00

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define _CRT_RAND_S

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#if defined(_WIN32)
#include <windows.h>
#pragma comment(lib, "user32")
#pragma comment(lib, "advapi32")
#endif

#include "libsais.h"

#if defined(CIN_OPENMP)
#include <omp.h>
#endif

typedef enum {
  LOG_ERROR,
  LOG_WARNING,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} Cin_Log_Level;

#if !defined(LOG_LEVEL)
#define LOG_LEVEL LOG_WARNING
#endif

static const Cin_Log_Level GLOBAL_LOG_LEVEL = LOG_LEVEL;
static const char *LOG_LEVELS[LOG_TRACE + 1] = {"ERROR", "WARNING", "INFO", "DEBUG", "TRACE"};

#define CIN_CONF_FILENAME "cinema.conf"
#define CIN_ARRAY_CAP 256
#define CIN_TABLE_CAP 64
#define CIN_ARRAY_GROWTH 2

static struct Cin_System {
  // Assuming large pages is the default, design around always committing
  DWORD alloc_type;
  size_t page_size;
  int32_t threads;
} cin_system = {
    .alloc_type = MEM_RESERVE | MEM_COMMIT,
    .page_size = 4096,
    .threads = 1};

static inline bool init_os(void) {
  SYSTEM_INFO system;
  GetSystemInfo(&system);
  cin_system.page_size = (size_t)system.dwPageSize;
  cin_system.threads = (int32_t)system.dwNumberOfProcessors;
#if defined(CIN_OPENMP)
  omp_set_num_threads(cin_system.threads);
#endif
  HANDLE token;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
    LUID luid;
    if (LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &luid)) {
      TOKEN_PRIVILEGES p = {.PrivilegeCount = 1,
                            .Privileges[0] = {.Luid = luid, .Attributes = SE_PRIVILEGE_ENABLED}};
      AdjustTokenPrivileges(token, FALSE, &p, sizeof(p), NULL, NULL);
      if (GetLastError() == ERROR_SUCCESS) {
        cin_system.alloc_type |= MEM_LARGE_PAGES;
        cin_system.page_size = GetLargePageMinimum();
      }
    }
    CloseHandle(token);
  }
  return true;
}

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define cin_ispow2(n) ((n) && ((n) & ((n) - 1)) == 0)
#define align(a, b) (((a) + (b) - 1) & (~((b) - 1)))
#define CIN_PTR ((uint32_t)__SIZEOF_POINTER__)
#define align_size(T) max(CIN_PTR, __alignof(T))
#define align_to_size(n) align((n), CIN_PTR)
#define block_bytes(n) ((n) * (CIN_PTR * 8))
#define align_to_block(n) align((n), block_bytes(1))
#define kilobytes(n) ((n) << 10)
#define megabytes(n) ((n) << 20)
#define gigabytes(n) ((n) << 30)
#define CIN_ARENA_CAP megabytes(2)
#define CIN_ARENA_BYTES align(sizeof(Arena), 64)

static inline uint32_t log2_floor(uint32_t n) {
  assert(n > 0U && "0 is undefined behavior");
  return 31U - (uint32_t)__builtin_clz(n);
}

static inline uint32_t log2_ceil(uint32_t n) {
  assert(n > 1U && "1 is not divisible by 2");
  return 32U - (uint32_t)__builtin_clz(n - 1U);
}

static inline uint32_t pow2(uint32_t exponent) {
  assert(exponent <= 31U);
  return 1U << exponent;
}

// Power of 2 allocation, where the max is 1U << 31,
// chosen to support max of 32-bit libsais.
static const uint32_t CIN_SIZE_CLASSES[] = {
    8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
    262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864,
    134217728, 268435456, 536870912, 1073741824, 2147483648};

#define CIN_ARENA_MIN_K 3U
#define CIN_ARENA_MAX_K 31U
#define CIN_NUM_CLASSES (1U + CIN_ARENA_MAX_K - CIN_ARENA_MIN_K)
#define CIN_ARENA_MIN (1U << CIN_ARENA_MIN_K)
#define CIN_ARENA_MAX (1U << CIN_ARENA_MAX_K)
static_assert(CIN_ARENA_MIN == 8U, "min alloc should be 8 bytes");
static_assert(CIN_ARENA_MAX == gigabytes(2U), "max alloc should be 2gb");

static inline uint32_t size_class(uint32_t k) {
  assert(k >= CIN_ARENA_MIN_K);
  return k - CIN_ARENA_MIN_K;
}

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
  // if set, assumes size = 1 << k
  uint32_t k;
} Arena_Slice;

static_assert(sizeof(Arena_Block) == CIN_PTR, "should just hold a pointer");
#define CIN_ARENA_SLICE_SIZE sizeof(Arena_Slice)
#define CIN_ARENA_HEADER align(sizeof(Arena_Chunk), CIN_ARENA_MIN)

static inline Arena_Chunk *arena_chunk_init(Arena *arena, uint32_t bytes) {
  assert(arena);
  assert(cin_system.page_size <= CIN_ARENA_MAX);
  size_t dwSize = align(bytes, cin_system.page_size);
  Arena_Chunk *chunk = VirtualAlloc(NULL, dwSize, cin_system.alloc_type, PAGE_READWRITE);
  if (!chunk) {
    DWORD code = GetLastError();
    printf("Cinema crashed with code %lu trying to use VirtualAlloc", code);
    // https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes
    assert(false);
    exit(1);
  }
  chunk->prev = arena->curr;
  chunk->count = CIN_ARENA_HEADER;
  chunk->capacity = (uint32_t)dwSize;
  arena->curr = chunk;
  return chunk;
}

static inline void arena_free_pow2(Arena *arena, Arena_Slice *slice) {
  assert(slice->k && "supposed to free pow2");
  Arena_Block *block = (Arena_Block *)slice->items;
  uint32_t i = size_class(slice->k);
  block->next = arena->free_list[i];
  arena->free_list[i] = block;
}

static inline uint32_t arena_free_pow1(Arena *arena, Arena_Slice *slice) {
  assert(!slice->k && "if slice is certainly pow2, just free it directly");
  assert(slice->size && "trying to free void memory");
  uint32_t aligned_size = slice->size & ~7U;
  uint32_t occupied = aligned_size;
  uint32_t offset = 0;
  while (occupied) {
    uint32_t k = (uint32_t)__builtin_ctz(occupied);
    uint8_t *pos = slice->items + offset;
    Arena_Slice src = {.items = pos, .k = k, .size = 0};
    arena_free_pow2(arena, &src);
    offset += pow2(k);
    occupied &= occupied - 1;
  }
  return aligned_size;
}

static inline uint32_t arena_free_pos(Arena *arena, uint8_t *pos, uint32_t n) {
  Arena_Slice slice = {.items = pos, .k = 0, .size = n};
  uint32_t freed = arena_free_pow1(arena, &slice);
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
    uint32_t free_n = arena->curr->capacity - arena->curr->count;
    uint32_t freed = arena_free_pos(arena, free_pos, free_n);
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
  uint32_t class = size_class(slice->k);
  Arena_Block *block = arena->free_list[class];
  if (block) {
    arena->free_list[class] = block->next;
    slice->items = (uint8_t *)block;
    if (zero) ZeroMemory(slice->items, slice->size);
  } else {
    slice->items = arena_bump(arena, slice->size, alignment);
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
                             .k = log2_floor(CIN_ARENA_SLICE_SIZE),
                             .size = 0};
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

#define arena_bump_T(arena, T, n) \
  arena_bump((arena), sizeof(T) * (n), align_size(T))

#define arena_bump_T1(arena, T) \
  arena_bump((arena), sizeof(T), align_size(T))

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
        ZeroMemory((out_node), (c)->cache_node_bytes);             \
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

#define CIN_ARRAY_SIZE sizeof(array_struct(void))
static_assert(CIN_PTR == 8 ? (CIN_ARRAY_SIZE == 24) : true, "bytes updated (possibly pow2)");

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

#define array_wextend(arena, a, new_items, n)           \
  do {                                                  \
    array_reserve((arena), (a), (n));                   \
    wmemcpy((a)->items + (a)->count, (new_items), (n)); \
    (a)->count += (n);                                  \
  } while (0)

#define array_wsextend(arena, a, new_items) \
  array_wextend((arena), (a), (new_items),  \
                sizeof((new_items)) / sizeof(*((new_items))) - 1);

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

#define array_wsplice(arena, a, i, new_items, n)                          \
  do {                                                                    \
    assert((i) <= (a)->count);                                            \
    array_reserve((arena), (a), (n));                                     \
    wmemmove((a)->items + (i) + (n), (a)->items + (i), (a)->count - (i)); \
    wmemcpy((a)->items + (i), (new_items), (n));                          \
    (a)->count += (n);                                                    \
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

static Arena console_arena = {0};
static Arena docs_arena = {0};
static Arena io_arena = {0};
static Arena iocp_thread_arena = {0};

// https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
// A path can have 248 "characters" (260 - 12 = 248)
// with 12 reserved for 8.3 file name.
// This refers to a WCHAR sequence (UTF-16 code units),
// i.e., wchar_t, such that max bytes = (248 * 2) = 496
// of UTF-16 data or (260 * 2) = 520 upper bound
// This is different from the full storage since
// a surrogate pair character can hold 2 wchar_t or
// (260 * 2 * 2) = 1040 bytes, exceeding the bound
// if many/all characters need 2 code units
// The cFileName from winapi uses a wchar_t buffer of
// 260 (MAX_PATH) so surrogate pairs get truncated
#define CIN_MAX_PATH MAX_PATH
#define CIN_MAX_PATH_BYTES (MAX_PATH * 4)
#define CIN_MAX_WRITABLE_PATH (MAX_PATH - 12)
#define CIN_MAX_WRITABLE_PATH_BYTES ((MAX_PATH - 12) * 4)
#define CIN_COMMAND_PROMPT_LIMIT 8191
#define CIN_MAX_LOG_MESSAGE 1024

typedef struct Console_Message {
  array_struct_members(wchar_t);
  struct Console_Message *prev;
  struct Console_Message *next;
} Console_Message;

#define CIN_CM_CAP 64

static Console_Message *create_console_message(void) {
  Console_Message *msg = arena_bump_T1(&console_arena, Console_Message);
  assert(msg);
#if defined(NDEBUG)
  array_init(&console_arena, msg, CIN_CM_CAP);
#else
  array_init_zero(&console_arena, msg, CIN_CM_CAP);
#endif
  msg->next = NULL;
  msg->prev = NULL;
  return msg;
}

static struct REPL {
  Console_Message *msg;
  HANDLE out;
  HANDLE in;
  HANDLE window;
  DWORD msg_index;
  COORD home;
  CONSOLE_CURSOR_INFO cursor_info;
  DWORD dwSize_X;
  DWORD _filled;
  DWORD in_mode;
  BOOL viewport_bound;
} repl = {0};

static struct Console_Preview {
  array_struct_members(wchar_t);
  DWORD prev_len;
  DWORD len;
  COORD pos;
} preview = {0};

static array_struct(wchar_t) wwrite_buf = {0};
static array_struct(char) write_buf = {0};

static inline void wswrite(const wchar_t *str) {
  assert(wcslen(str) <= SIZE_MAX && "Corrupted string");
  WriteConsoleW(repl.out, str, (DWORD)wcslen(str), NULL, NULL);
}

static inline void wwrite(const wchar_t *str, DWORD len) {
  WriteConsoleW(repl.out, str, len, NULL, NULL);
}

static void wwritef(const wchar_t *format, ...) {
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
  int32_t len_i32 = _vscwprintf(format, args);
  assert(len_i32 >= 0);
  uint32_t len = (uint32_t)len_i32;
  va_end(args);
  array_resize(&console_arena, &wwrite_buf, len + 1);
  _vsnwprintf_s(wwrite_buf.items, len + 1, len, format, args_dup);
  va_end(args_dup);
  WriteConsoleW(repl.out, wwrite_buf.items, len, NULL, NULL);
}

static void wvwritef(const wchar_t *format, va_list args) {
  va_list args_dup;
  va_copy(args_dup, args);
  int32_t len_i32 = _vscwprintf(format, args_dup);
  assert(len_i32 >= 0);
  uint32_t len = (uint32_t)len_i32;
  va_end(args_dup);
  array_resize(&console_arena, &wwrite_buf, len + 1);
  _vsnwprintf_s(wwrite_buf.items, len + 1, len, format, args);
  WriteConsoleW(repl.out, wwrite_buf.items, len, NULL, NULL);
}

static inline void swrite(const char *str) {
  assert(strlen(str) <= SIZE_MAX && "Corrupted string");
  WriteConsoleA(repl.out, str, (DWORD)strlen(str), NULL, NULL);
}

static inline void write(const char *str, DWORD len) {
  WriteConsoleA(repl.out, str, len, NULL, NULL);
}

static void writef(const char *format, ...) {
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
  int32_t len_i32 = _vscprintf(format, args);
  assert(len_i32 >= 0);
  uint32_t len = (uint32_t)len_i32;
  va_end(args);
  array_resize(&console_arena, &write_buf, len + 1);
  _vsnprintf_s(write_buf.items, len + 1, len, format, args_dup);
  va_end(args_dup);
  WriteConsoleA(repl.out, write_buf.items, len, NULL, NULL);
}

static void vwritef(const char *format, va_list args) {
  va_list args_dup;
  va_copy(args_dup, args);
  int32_t len_i32 = _vscprintf(format, args_dup);
  assert(len_i32 >= 0);
  uint32_t len = (uint32_t)len_i32;
  va_end(args_dup);
  array_resize(&console_arena, &write_buf, len + 1);
  _vsnprintf_s(write_buf.items, len + 1, len, format, args);
  WriteConsoleA(repl.out, write_buf.items, len, NULL, NULL);
}

#define cin_strlen(str) (sizeof((str)) / sizeof(*(str)) - 1)
#define CIN_SPACE 0x20
#define PREFIX_TOKEN L'>'
#define PREFIX 2
#define PREFIX_STR L"\r> "
#define PREFIX_ABS L">"
#define PREFIX_STRLEN cin_strlen(PREFIX_STR)
#define PREFIX_ABSLEN cin_strlen(PREFIX_ABS)
#define WCRLF L"\r\n"
#define WCRLF_LEN 2
#define WCR L"\r"
#define WCR_LEN 1
#define CR "\r"
#define CR_LEN 1
#define CRLF "\r\n"

static inline void hide_cursor(void) {
  repl.cursor_info.bVisible = false;
  SetConsoleCursorInfo(repl.out, &repl.cursor_info);
}

static inline void show_cursor(void) {
  repl.cursor_info.bVisible = true;
  SetConsoleCursorInfo(repl.out, &repl.cursor_info);
}

static inline SHORT index_x(DWORD index, DWORD dwSize_X) {
  assert(index % dwSize_X <= SHRT_MAX);
  return (SHORT)(index % dwSize_X);
}

static inline SHORT index_x_repl(DWORD index) {
  return index_x(PREFIX + index, repl.dwSize_X);
}

static inline SHORT index_y(DWORD index, DWORD dwSize_X) {
  assert(index / dwSize_X <= SHRT_MAX);
  return (SHORT)(index / dwSize_X);
}

static inline SHORT index_y_repl(DWORD index) {
  return repl.home.Y + index_y(PREFIX + index, repl.dwSize_X);
}

static inline COORD index_to_cursor(DWORD index, DWORD dwSize_X) {
  return (COORD){.X = index_x(index, dwSize_X), .Y = index_y(index, dwSize_X)};
}

static inline COORD index_to_cursor_repl(DWORD index) {
  return (COORD){.X = index_x_repl(index), .Y = index_y_repl(index)};
}

static inline DWORD cursor_to_index(COORD cursor, DWORD dwSize_X) {
  assert(cursor.X >= 0);
  assert(cursor.Y >= 0);
  return (DWORD)cursor.X + ((DWORD)cursor.Y * dwSize_X);
}

static inline COORD curr_cursor(void) {
  return index_to_cursor_repl(repl.msg_index);
}

static inline COORD tail_cursor(void) {
  return index_to_cursor_repl(repl.msg->count);
}

static inline COORD home_cursor(void) {
  return repl.home;
}

static inline void cursor_home(void) {
  SetConsoleCursorPosition(repl.out, repl.home);
}

static inline void cursor_curr(void) {
  SetConsoleCursorPosition(repl.out, curr_cursor());
}

static inline void cursor_tail(void) {
  SetConsoleCursorPosition(repl.out, tail_cursor());
}

static inline void cursor_set(COORD cursor) {
  SetConsoleCursorPosition(repl.out, cursor);
}

static inline void clear_tail(DWORD count) {
  FillConsoleOutputCharacterW(repl.out, CIN_SPACE, count, tail_cursor(), &repl._filled);
}

static inline void clear_full(void) {
  FillConsoleOutputCharacterW(repl.out, CIN_SPACE, repl.msg->count, repl.home, &repl._filled);
}

static inline void clear_preview(SHORT pos) {
  assert(pos >= 0);
  assert((DWORD)pos < repl.dwSize_X);
  preview.pos.X = pos;
  DWORD leftover = preview.len - (DWORD)pos;
  FillConsoleOutputCharacterW(repl.out, CIN_SPACE, leftover, preview.pos, &repl._filled);
}

static inline void set_preview_pos(SHORT y) {
  assert(y > 0);
  preview.pos.X = 0;
  preview.pos.Y = y;
}

static inline bool ctrl_on(PINPUT_RECORD input) {
  return input->Event.KeyEvent.dwControlKeyState & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED);
}

static inline BOOL GetConsoleScreenBufferInfo_safe(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo) {
  if (!GetConsoleScreenBufferInfo(hConsoleOutput, lpConsoleScreenBufferInfo)) return FALSE;
  SHORT cur_y = lpConsoleScreenBufferInfo->dwCursorPosition.Y;
  SHORT max_y = lpConsoleScreenBufferInfo->dwSize.Y - 1;
  DWORD max_x = (DWORD)lpConsoleScreenBufferInfo->dwSize.X;
  if (cur_y < max_y) return TRUE;
  HANDLE fresh_buffer = CreateConsoleScreenBuffer(GENERIC_READ | GENERIC_WRITE,
                                                  FILE_SHARE_READ | FILE_SHARE_WRITE,
                                                  NULL, CONSOLE_TEXTMODE_BUFFER, NULL);
  if (fresh_buffer == INVALID_HANDLE_VALUE) return FALSE;
  if (!SetConsoleScreenBufferSize(fresh_buffer, lpConsoleScreenBufferInfo->dwSize)) return FALSE;
  if (!SetConsoleActiveScreenBuffer(fresh_buffer)) return FALSE;
  DWORD mode;
  GetConsoleMode(fresh_buffer, &mode);
  SetConsoleMode(fresh_buffer, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  DWORD written;
  WriteConsoleA(fresh_buffer, "\x1b[2J\x1b[3J\x1b[H", 12, &written, NULL);
  SetConsoleMode(fresh_buffer, mode);
  repl.out = fresh_buffer;
  repl.dwSize_X = max_x;
  SetConsoleCursorPosition(repl.out, (COORD){.X = 0, .Y = 0});
  repl.home.Y = 0;
  preview.pos.Y = 1;
  SHORT msg_tail = index_y_repl(repl.msg->count) + 1;
  if (msg_tail >= max_y) {
    repl.msg_index = 0;
    repl.msg->count = 0;
    wwritef(L"NOTE: Input message too large (tail at line %hd >= console"
            " screen buffer height limit %hd). Cinema resolved this by fully"
            " clearing your input. Your console terminal supports roughly"
            " %lu characters (cells)." WCRLF,
            msg_tail, max_y, max_x * (DWORD)max_y);
  }
  static bool notify_buffer_refresh = true;
  if (notify_buffer_refresh) {
    wwritef(L"NOTE: Console screen buffer height limit reached (%hd>=%hd)."
            " Cinema resolved this by activating a fresh buffer. The content of"
            " the previous buffer will be available once Cinema is closed."
            " If you want to prevent this situation in the future, increase"
            " the screen buffer size (height) of your console." WCRLF,
            cur_y, max_y);
  } else {
    wwritef(L"Cut off? Increase console size and retry");
  }
  notify_buffer_refresh = false;
  if (!GetConsoleScreenBufferInfo(repl.out, lpConsoleScreenBufferInfo)) return FALSE;
  repl.home.Y = lpConsoleScreenBufferInfo->dwCursorPosition.Y;
  SHORT preview_shift = (SHORT)((repl.msg->count + PREFIX) / max_x) + 1;
  set_preview_pos(repl.home.Y + preview_shift);
  if (!FlushConsoleInputBuffer(repl.in)) return FALSE;
  return TRUE;
}

static inline int32_t lcps(const uint8_t *a, const uint8_t *b) {
  int32_t matching = 0;
  while (*a && *b && *(a++) == *(b++)) ++matching;
  return matching;
}

static inline bool cin_isloweralpha(char *c) {
  return *c <= 'z' && *c >= 'a';
}

static inline bool cin_lower_isalpha(char *out) {
  if (*out <= 'Z' && *out >= 'A') {
    *out += ('a' - 'A');
    return true;
  }
  return cin_isloweralpha(out);
}

static inline bool cin_isnum(char c) {
  return c <= '9' && c >= '0';
}

static inline wchar_t cin_wlower(wchar_t c) {
  if (c <= L'Z' && c >= 'A') return c + (L'a' - L'A');
  if (c < 128) return c;
  wchar_t unicode = c;
  LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, &c, 1, &unicode, 1, NULL, NULL, 0);
  return unicode;
}

static inline bool cin_wisloweralpha(wchar_t c) {
  return c <= L'z' && c >= L'a';
}

static inline bool cin_wisnum(wchar_t c) {
  return c <= L'9' && c >= L'0';
}

static inline bool cin_wisnum_1based(wchar_t c) {
  return c <= L'9' && c >= L'1';
}

static inline void cin_getnum(const char **p, int64_t *out) {
  *out = 0;
  while (cin_isnum(**p)) {
    *out *= 10;
    *out += **p - '0';
    ++*p;
  }
}

static void log_preview(void) {
  if (!preview.count) return;
  DWORD msg_len = preview.count;
  preview.len = min(preview.count, repl.dwSize_X);
  assert(wmemchr(preview.items, PREFIX_TOKEN, preview.len) == NULL);
  // set cursor to scroll down (and prep next write if < repl.dwSize_X)
  SetConsoleCursorPosition(repl.out, preview.pos);
  if (msg_len < repl.dwSize_X) {
    wwrite(preview.items, msg_len);
  } else if (msg_len > repl.dwSize_X) {
    assert(msg_len > 3);
    DWORD tmp1_pos = repl.dwSize_X - 1;
    DWORD tmp2_pos = repl.dwSize_X - 2;
    DWORD tmp3_pos = repl.dwSize_X - 3;
    wchar_t tmp1 = preview.items[tmp1_pos];
    wchar_t tmp2 = preview.items[tmp2_pos];
    wchar_t tmp3 = preview.items[tmp3_pos];
    preview.items[tmp1_pos] = '.';
    preview.items[tmp2_pos] = '.';
    preview.items[tmp3_pos] = '.';
    WriteConsoleOutputCharacterW(repl.out, preview.items, preview.len, preview.pos, &repl._filled);
    preview.items[tmp1_pos] = tmp1;
    preview.items[tmp2_pos] = tmp2;
    preview.items[tmp3_pos] = tmp3;
  } else {
    WriteConsoleOutputCharacterW(repl.out, preview.items, preview.len, preview.pos, &repl._filled);
  }
  FillConsoleOutputAttribute(repl.out, FOREGROUND_INTENSITY, preview.len, preview.pos, &repl._filled);
  cursor_curr();
  preview.prev_len = preview.len;
}

static inline void rewrite_post_log(void) {
  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  GetConsoleScreenBufferInfo_safe(repl.out, &buffer_info);
  repl.dwSize_X = (DWORD)buffer_info.dwSize.X;
  assert(repl.msg->count + PREFIX <= SHRT_MAX && "SHORT overflow");
  assert(buffer_info.dwCursorPosition.Y < SHRT_MAX && "SHORT overflow");
  SHORT tail_x = buffer_info.dwCursorPosition.X;
  if (repl.msg->count + PREFIX > (DWORD)tail_x) {
    DWORD leftover = repl.msg->count + PREFIX - (DWORD)tail_x;
    FillConsoleOutputCharacterW(repl.out, CIN_SPACE, leftover, buffer_info.dwCursorPosition, &repl._filled);
  }
  repl.home.Y += buffer_info.dwCursorPosition.Y - repl.home.Y + 1;
  SHORT y_diff = preview.pos.Y - repl.home.Y;
  if (y_diff == -1 && preview.len > (DWORD)tail_x) {
    clear_preview(tail_x);
  } else if (y_diff == 0) {
    DWORD x = min(repl.msg->count + PREFIX, repl.dwSize_X);
    if (preview.len > x && x < repl.dwSize_X) {
      clear_preview((SHORT)x);
    }
  } else if (y_diff > 0) {
    SHORT x = index_x_repl(repl.msg->count);
    if (preview.len > (DWORD)x) {
      clear_preview(x);
    }
  }
  wwrite(WCRLF, WCRLF_LEN);
  wwrite(PREFIX_STR, PREFIX_STRLEN);
  wwrite(repl.msg->items, repl.msg->count);
  SHORT preview_offset = (SHORT)((repl.msg->count + PREFIX) / repl.dwSize_X) + 1;
  SHORT preview_line = repl.home.Y + preview_offset;
  set_preview_pos(preview_line);
  log_preview();
  show_cursor();
}

static CRITICAL_SECTION log_lock;

static void log_message(Cin_Log_Level level, const char *message, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  EnterCriticalSection(&log_lock);
  hide_cursor();
  cursor_home();
  writef(CR "[%s] ", LOG_LEVELS[level]);
  va_list args;
  va_start(args, message);
  vwritef(message, args);
  rewrite_post_log();
  va_end(args);
  LeaveCriticalSection(&log_lock);
}

array_define(UTF16_Buffer, wchar_t);
array_define(UTF8_Buffer, uint8_t);

static UTF16_Buffer utf16_buf_raw = {0};
static UTF16_Buffer utf16_buf_norm = {0};
static UTF8_Buffer utf8_buf = {0};

static inline int32_t utf16_to_utf8(const wchar_t *wstr) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte
  assert(utf8_buf.items);
  assert(wstr);
  // because cchWideChar is set to -1, the output is null-terminated (and len includes it)
  // n_bytes represents the char count needed
  int32_t n_bytes = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  assert(n_bytes);
  array_resize(&console_arena, &utf8_buf, (uint32_t)n_bytes);
  return WideCharToMultiByte(CP_UTF8, 0, wstr, -1, (char *)utf8_buf.items, n_bytes, NULL, NULL);
}

static inline int32_t utf8_to_utf16_raw(const char *str) {
  // https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar
  assert(utf16_buf_raw.items);
  assert(str);
  // because cbMultiByte is set to -1, the output is null-terminated (and len includes it)
  // n_chars represents the wchar_t count needed
  int32_t n_chars = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
  assert(n_chars);
  array_resize(&console_arena, &utf16_buf_raw, (uint32_t)n_chars);
  return MultiByteToWideChar(CP_UTF8, 0, str, -1, utf16_buf_raw.items, n_chars);
}

static inline int32_t utf8_to_utf16_nraw(const char *str, int32_t len) {
  assert(utf16_buf_raw.items);
  assert(str);
  // process len bytes, with n_chars not including null terminator
  int32_t n_chars = MultiByteToWideChar(CP_UTF8, 0, str, len, NULL, 0);
  assert(n_chars);
  array_resize(&console_arena, &utf16_buf_raw, (uint32_t)n_chars);
  return MultiByteToWideChar(CP_UTF8, 0, str, len, utf16_buf_raw.items, n_chars);
}

static inline int32_t utf16_norm(const wchar_t *str) {
  // n_chars represents the possibly updated wchar_t count needed
  int32_t n_chars = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE,
                                  str, -1, NULL, 0, NULL, NULL, 0);
  assert(n_chars);
  array_resize(&console_arena, &utf16_buf_norm, (uint32_t)n_chars);
  return LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, str,
                       -1, utf16_buf_norm.items, n_chars, NULL, NULL, 0);
}

static inline int32_t utf8_to_utf16_norm(const char *str) {
  int32_t len = utf8_to_utf16_raw(str);
  assert(len);
  return utf16_norm(utf16_buf_raw.items);
}

static void log_wmessage(Cin_Log_Level level, const wchar_t *wmessage, ...) {
  if (level > GLOBAL_LOG_LEVEL) {
    return;
  }
  EnterCriticalSection(&log_lock);
  hide_cursor();
  cursor_home();
  writef(CR "[%s] ", LOG_LEVELS[level]);
  va_list args;
  va_start(args, wmessage);
  wvwritef(wmessage, args);
  rewrite_post_log();
  va_end(args);
  LeaveCriticalSection(&log_lock);
}

static void wwrite_safe(const wchar_t *str, DWORD len) {
  EnterCriticalSection(&log_lock);
  clear_preview(0);
  hide_cursor();
  cursor_home();
  wwrite(str, len);
  rewrite_post_log();
  LeaveCriticalSection(&log_lock);
}

static void log_last_error(const char *message, ...) {
  static const DWORD dw_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                FORMAT_MESSAGE_FROM_SYSTEM |
                                FORMAT_MESSAGE_IGNORE_INSERTS;
  EnterCriticalSection(&log_lock);
  LPVOID buffer;
  DWORD code = GetLastError();
  if (!FormatMessageA(dw_flags, NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&buffer, 0, NULL)) {
    log_message(LOG_ERROR, "Failed to log GLE=%d - error with GLE=%d", code, GetLastError());
    return;
  }
  // remove trailing \r\n
  char *str = (char *)buffer;
  size_t len = strlen(str);
  assert(len >= 2);
  assert(str[len - 1] == '\n');
  assert(str[len - 2] == '\r');
  str[--len] = '\0';
  str[--len] = '\0';
  hide_cursor();
  cursor_home();
  writef(CR "[%s] ", LOG_LEVELS[LOG_ERROR]);
  va_list args;
  va_start(args, message);
  vwritef(message, args);
  va_end(args);
  writef(" - Code %lu: %s", code, (char *)buffer);
  rewrite_post_log();
  LocalFree(buffer);
  LeaveCriticalSection(&log_lock);
}

#define CIN_STRERROR_BYTES 95

static inline void log_fopen_error(const char *filename, int32_t err) {
  char err_buf[CIN_STRERROR_BYTES];
  strerror_s(err_buf, CIN_STRERROR_BYTES, err);
  log_message(LOG_ERROR, "Failed to open file '%s': %s", filename, err_buf);
}

#define CIN_INTEGER_HASH 2654435761U

static inline size_t deduplicate_i32(Arena *arena, int32_t *items, size_t len) {
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
    size_t mask = hash_n - 1;
    for (size_t i = 0; i < len; ++i) {
      int32_t v = items[i];
      size_t hash = (size_t)v * CIN_INTEGER_HASH;
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

#define COMMAND_ALPHABET 26

typedef void (*patricia_fn)(void);

typedef struct Patricia_Node {
  struct Patricia_Node *edges[COMMAND_ALPHABET];
  const wchar_t *suffix;
  size_t len;
  patricia_fn fn;
  int32_t min;
} Patricia_Node;

static inline Patricia_Node *patricia_node(const wchar_t *suffix, size_t len) {
  Patricia_Node *node = arena_bump_T1(&console_arena, Patricia_Node);
  assert(node);
  node->suffix = suffix;
  node->len = len;
  return node;
}

static inline size_t patricia_lcp(const wchar_t *a, const wchar_t *b, size_t max) {
  size_t i = 0;
  while (i < max && a[i] && a[i] == b[i]) ++i;
  return i;
}

static inline patricia_fn patricia_query(Patricia_Node *root, const wchar_t *pattern) {
  assert(root);
  assert(wcslen(pattern) > 0);
  assert((*pattern >= L'a' && *pattern <= L'z'));
  Patricia_Node *node = root;
  const wchar_t *p = pattern;
  while (*p) {
    assert((*p >= L'a' && *p <= L'z'));
    int32_t i = *p - L'a';
    Patricia_Node *edge = node->edges[i];
    if (edge == NULL) {
      return NULL;
    }
    size_t common = patricia_lcp(p, edge->suffix, edge->len);
    if (p[common] == L'\0') {
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

static inline void patricia_insert(Patricia_Node *root, const wchar_t *str, patricia_fn fn) {
  assert(root);
  assert(wcslen(str) > 0);
  assert((*str >= L'a' && *str <= L'z'));
  Patricia_Node *node = root;
  const wchar_t *p = str;
  while (*p) {
    assert((*p >= L'a' && *p <= L'z'));
    int32_t i = *p - L'a';
    Patricia_Node *edge = node->edges[i];
    if (edge == NULL) {
      edge = patricia_node(p, wcslen(p));
      edge->fn = fn;
      node->edges[i] = edge;
      if ((node->min == -1) || i < node->min) {
        // update parent lexicographical minimum
        node->min = i;
        node->fn = fn;
      }
      return;
    }
    size_t common = patricia_lcp(p, edge->suffix, edge->len);
    if (common == edge->len) {
      p += common;
      if (*p == L'\0') {
        edge->min = -1;
        edge->fn = fn;
        return;
      }
      node = edge;
    } else {
      Patricia_Node *split = patricia_node(edge->suffix, common);
      edge->suffix += common;
      edge->len -= common;
      node->edges[i] = split;
      split->edges[edge->suffix[0] - L'a'] = edge;
      p += common;
      if (*p == L'\0') {
        split->min = -1;
        split->fn = fn;
      } else {
        Patricia_Node *remainder = patricia_node(p, wcslen(p));
        remainder->fn = fn;
        int32_t edge_i = edge->suffix[0] - L'a';
        int32_t next_i = *p - L'a';
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

static inline int32_t radix_bit(const uint8_t *key, size_t len, size_t critical, uint8_t bitmask) {
  return critical < len && key[critical] & bitmask;
}

static inline void radix_critical(const uint8_t *k1, size_t len1,
                                  const uint8_t *k2, size_t len2,
                                  size_t *critical, uint8_t *bitmask) {
  size_t max_len = max(len1, len2);
  for (size_t i = 0; i < max_len; ++i) {
    uint8_t b1 = (i < len1) ? k1[i] : 0;
    uint8_t b2 = (i < len2) ? k2[i] : 0;
    if (b1 != b2) {
      uint8_t diff = b1 ^ b2;
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

static inline Radix_Leaf *radix_leaf(const uint8_t *key, size_t len, radix_v v) {
  Radix_Leaf *leaf = arena_bump_T1(&console_arena, Radix_Leaf);
  assert(leaf);
  leaf->base.type = RADIX_LEAF;
  leaf->base.v = v;
  assert(len <= CIN_ARENA_MAX);
  uint8_t *dup = arena_bump_T(&console_arena, uint8_t, (uint32_t)len + 1);
  assert(dup);
  memcpy(dup, key, len);
  dup[len] = '\0';
  leaf->key = dup;
  leaf->len = len;
  return leaf;
}

static inline Radix_Internal *radix_internal(size_t critical, uint8_t bitmask) {
  Radix_Internal *node = arena_bump_T1(&console_arena, Radix_Internal);
  assert(node);
  node->base.type = RADIX_INTERNAL;
  node->base.v = NULL;
  node->critical = critical;
  node->bitmask = bitmask;
  node->child[0] = NULL;
  node->child[1] = NULL;
  return node;
}

static inline int32_t radix_compare(const uint8_t *k1, size_t len1, const uint8_t *k2, size_t len2) {
  size_t min_len = min(len1, len2);
  int32_t cmp = memcmp(k1, k2, min_len);
  if (cmp != 0) return cmp;
  if (len1 < len2) return -1;
  if (len1 > len2) return 1;
  return 0;
}

static inline void radix_update(Radix_Internal *internal) {
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

static inline Radix_Tree *radix_tree(void) {
  Radix_Tree *tree = arena_bump_T1(&console_arena, Radix_Tree);
  assert(tree);
  tree->root = NULL;
  return tree;
}

static inline void radix_insert(Radix_Tree *tree, const uint8_t *key, size_t len, radix_v v) {
  assert(tree);
  assert(key);
  if (!tree->root) {
    tree->root = (Radix_Node *)radix_leaf(key, len, v);
    return;
  }
  Radix_Node *node = tree->root;
  while (node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    Radix_Node *next = internal->child[bit];
    if (!next) {
      internal->child[bit] = (Radix_Node *)radix_leaf(key, len, v);
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
    int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    parent = &internal->child[bit];
    node = internal->child[bit];
    if (!node) break;
  }
  Radix_Internal *new_internal = radix_internal(critical, bitmask);
  int32_t new_bit = radix_bit(key, len, critical, bitmask);
  Radix_Leaf *new_leaf = radix_leaf(key, len, v);
  new_internal->child[new_bit] = (Radix_Node *)new_leaf;
  new_internal->child[new_bit ^ 1] = *parent;
  radix_update(new_internal);
  *parent = (Radix_Node *)new_internal;
}

static inline radix_v radix_query(Radix_Tree *tree, const uint8_t *pattern, size_t len, const uint8_t **out) {
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
    int32_t bit = radix_bit(pattern, len, internal->critical, internal->bitmask);
    node = internal->child[bit];
  }
  return NULL;
}

static inline Radix_Leaf *radix_leftmost(Radix_Node *node) {
  if (!node) return NULL;
  while (node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    node = internal->child[0] ? internal->child[0] : internal->child[1];
  }
  return (Radix_Leaf *)node;
}

static inline Radix_Leaf *radix_next(Radix_Tree *tree, Radix_Leaf *current) {
  assert(current);
  assert(tree->root);
  const uint8_t *key = current->key;
  size_t len = current->len;
  Radix_Node *node = tree->root;
  Radix_Node *candidate = NULL;
  while (node && node->type == RADIX_INTERNAL) {
    Radix_Internal *internal = (Radix_Internal *)node;
    int32_t bit = radix_bit(key, len, internal->critical, internal->bitmask);
    if (bit == 0 && internal->child[1]) candidate = internal->child[1];
    node = internal->child[bit];
  }
  return radix_leftmost(candidate);
}

static inline uint32_t rand_between(uint32_t min, uint32_t max) {
  assert(max >= min);
  uint32_t range = max - min + 1;
  uint32_t upper = UINT_MAX - (UINT_MAX % range);
  uint32_t random;
  do rand_s(&random);
  while (random >= upper);
  return min + (random % range);
}

static inline uint64_t fnv1a_hash(const uint8_t *str, uint32_t len) {
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (uint32_t i = 0; i < len; ++i) {
    hash ^= str[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

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

static inline void table_init(Arena *arena, Robin_Hood_Table *table, uint32_t capacity) {
  assert(table->capacity == 0);
  assert(capacity > 0);
  table->items = arena_bump_T(arena, Table_Bucket, capacity);
  table->count = 0;
  table->capacity = capacity;
  table->bytes_capacity = capacity * sizeof(Table_Bucket);
  table->bytes_capacity_k = 0;
  table->mask = table->capacity - 1;
}

static inline void table_double(Arena *arena, Robin_Hood_Table *table) {
  if (unlikely(table->bytes_capacity >= CIN_ARENA_MAX)) {
    printf("Cinema crashed trying to allocate excessive memory (%u bytes)",
           table->bytes_capacity << 1);
    exit(1);
  }
  uint32_t prev_bytes_cap = table->bytes_capacity;
  uint32_t prev_cap = table->capacity;
  Table_Bucket *prev_buckets = table->items;
  table->capacity <<= 1;
  table->items = arena_bump_T(arena, Table_Bucket, table->capacity);
  table->bytes_capacity <<= 1;
  table->count = 0;
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

static inline table_value table_find(Robin_Hood_Table *table, Table_Key *key) {
  table_key_t *str = key->strings + key->pos;
  uint64_t hash = fnv1a_hash(str, key->len);
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

static inline table_value table_insert(Arena *arena, Robin_Hood_Table *table,
                                       Table_Key *key, table_value value) {
  // robin hood hashing (with tombstones) with fnv-1a
  table_key_t *str = key->strings + key->pos;
  if (table->count >= (table->capacity * TABLE_LOAD_FACTOR) / 100) {
    table_double(arena, table);
  }
  uint64_t hash = fnv1a_hash(str, key->len);
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
        log_message(LOG_TRACE, "Found duplicate key '%s' in hashmap", str);
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

static inline table_value table_delete(Robin_Hood_Table *table, Table_Key *key) {
  table_key_t *str = key->strings + key->pos;
  uint64_t hash = fnv1a_hash(str, key->len);
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

static inline void table_free_items(Arena *arena, Robin_Hood_Table *table) {
  if (table->items) arena_free_pos(arena, (uint8_t *)table->items, table->bytes_capacity);
}

array_define(Conf_Key, char);

typedef struct Conf_Root {
  Conf_Key null;
} Conf_Root;

typedef struct Conf_Media {
  Conf_Key directories;
  Conf_Key patterns;
  Conf_Key urls;
  Conf_Key tags;
} Conf_Media;

typedef struct Conf_Layout {
  Conf_Key name;
  Conf_Key screen;
  Conf_Key chat;
} Conf_Layout;

typedef struct Conf_Macro {
  Conf_Key name;
  Conf_Key command;
  Conf_Key startup;
} Conf_Macro;

typedef enum {
  CONF_SCOPE_ROOT,
  CONF_SCOPE_MEDIA,
  CONF_SCOPE_LAYOUT,
  CONF_SCOPE_MACRO
} Conf_Scope_Type;

typedef struct Conf_Scope {
  Conf_Scope_Type type;
  union {
    Conf_Root root;
    Conf_Media media;
    Conf_Layout layout;
    Conf_Macro macro;
  };
  int32_t line;
} Conf_Scope;

array_define(Conf_Scopes, Conf_Scope);
array_define(Conf_Buf, char);

static struct {
  Conf_Scopes scopes;
  Conf_Buf buf;
  size_t len;
  size_t k_len;
  char *v;
  int32_t line;
  bool error;
  // general flags
  bool has_patterns;
} conf_parser = {0};

#define CONF_LINE_CAP 512
#define CONF_SCOPES_CAP 16

static inline Conf_Scope *conf_scope(void) {
  assert(conf_parser.scopes.count > 0);
  return &conf_parser.scopes.items[conf_parser.scopes.count - 1];
}

static inline void conf_enter_scope(Conf_Scope_Type type) {
  Conf_Scope scope = {0};
  scope.type = type;
  scope.line = conf_parser.line;
  array_push(&console_arena, &conf_parser.scopes, scope);
}

static inline bool conf_keycmp(char *k, Conf_Scope_Type type, Conf_Key *out, bool unique) {
  if (memcmp(k, conf_parser.buf.items, conf_parser.k_len) != 0) return false;
  assert(&conf_scope()->type);
  uint32_t v_len = (uint32_t)(conf_parser.len - (size_t)(conf_parser.v - conf_parser.buf.items));
  if (conf_scope()->type != type) {
    conf_parser.error = true;
    char *scope_msg;
    switch (conf_scope()->type) {
    case CONF_SCOPE_ROOT:
      scope_msg = "above any [table]";
      break;
    case CONF_SCOPE_LAYOUT:
      scope_msg = "under a [layout] table";
      break;
    case CONF_SCOPE_MEDIA:
      scope_msg = "under a [media] table";
      break;
    case CONF_SCOPE_MACRO:
      scope_msg = "under a [macro] table";
      break;
    default:
      assert(false && "Unexpected type");
      break;
    }
    conf_parser.buf.items[conf_parser.k_len] = '\0';
    log_message(LOG_ERROR, "Unexpected key on line %d: '%s' is not allowed %s",
                conf_parser.line, conf_parser.buf.items, scope_msg);
  } else if (unique) {
    if (out->count > 0) {
      log_message(LOG_WARNING, "Overwriting existing value on line %d for key '%s': %s => %s",
                  conf_parser.line, k, out->items, conf_parser.v);
    }
    array_set(&console_arena, out, conf_parser.v, v_len);
  } else {
    if (out->count > 0) {
      assert(out->items[out->count - 1] == '\0');
      out->items[out->count - 1] = ',';
      array_push(&console_arena, out, ' ');
    }
    array_extend(&console_arena, out, conf_parser.v, v_len);
  }
  return true;
}

static inline bool conf_keyget(void) {
  switch (conf_parser.k_len) {
  case 11:
    if (conf_keycmp("directories", CONF_SCOPE_MEDIA, &conf_scope()->media.directories, false)) return true;
    break;
  case 8:
    if (conf_keycmp("patterns", CONF_SCOPE_MEDIA, &conf_scope()->media.patterns, false)) {
      conf_parser.has_patterns = true;
      return true;
    }
    break;
  case 7:
    if (conf_keycmp("command", CONF_SCOPE_MACRO, &conf_scope()->macro.command, false)) return true;
    if (conf_keycmp("startup", CONF_SCOPE_MACRO, &conf_scope()->macro.startup, true)) return true;
    break;
  case 6:
    if (conf_keycmp("screen", CONF_SCOPE_LAYOUT, &conf_scope()->layout.screen, false)) return true;
    break;
  case 4:
    if (conf_keycmp("urls", CONF_SCOPE_MEDIA, &conf_scope()->media.urls, false)) return true;
    if (conf_keycmp("tags", CONF_SCOPE_MEDIA, &conf_scope()->media.tags, false)) return true;
    if (conf_keycmp("chat", CONF_SCOPE_LAYOUT, &conf_scope()->layout.chat, true)) return true;
    if (conf_scope()->type == CONF_SCOPE_MACRO) {
      if (conf_keycmp("name", CONF_SCOPE_MACRO, &conf_scope()->macro.name, true)) return true;
    } else {
      if (conf_keycmp("name", CONF_SCOPE_LAYOUT, &conf_scope()->layout.name, true)) return true;
    }
    break;
  default:
    break;
  }
  return false;
}

static inline bool conf_scopecmp(char *s, Conf_Scope_Type type) {
  if (memcmp(s, conf_parser.buf.items + 1, conf_parser.k_len) != 0) return false;
  conf_enter_scope(type);
  return true;
}

static inline bool conf_scopeget(void) {
  switch (conf_parser.k_len) {
  case 6:
    if (conf_scopecmp("layout", CONF_SCOPE_LAYOUT)) return true;
    break;
  case 5:
    if (conf_scopecmp("media", CONF_SCOPE_MEDIA)) return true;
    if (conf_scopecmp("macro", CONF_SCOPE_MACRO)) return true;
    break;
  default:
    break;
  }
  return false;
}

static bool parse_config(const char *filename) {
  bool ok = false;
  FILE *file;
  int32_t err = fopen_s(&file, filename, "rt");
  if (err) {
    log_fopen_error(filename, err);
    goto end;
  }
  array_init(&console_arena, &conf_parser.buf, CONF_LINE_CAP);
  array_init(&console_arena, &conf_parser.scopes, CONF_SCOPES_CAP);
  conf_enter_scope(CONF_SCOPE_ROOT);
  conf_parser.line = 1;
  while (fgets(conf_parser.buf.items, (int32_t)conf_parser.buf.capacity, file)) {
    conf_parser.len = strlen(conf_parser.buf.items);
    assert(conf_parser.buf.capacity > 1);
    if (conf_parser.buf.items[conf_parser.len - 1] == '\n') {
      conf_parser.buf.items[conf_parser.len - 1] = '\0';
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
    } else if (feof(file)) {
      ++conf_parser.len;
      assert(conf_parser.buf.items[conf_parser.len - 1] == '\0');
    } else {
      // buffer too small, collect remainder and grow
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
      array_grow(&console_arena, &conf_parser.buf, (uint32_t)conf_parser.len);
      int32_t c;
      while ((c = fgetc(file)) != '\n' && c != EOF) {
        array_push(&console_arena, &conf_parser.buf, (char)c);
      }
      array_push(&console_arena, &conf_parser.buf, '\0');
      conf_parser.len = conf_parser.buf.count - 1;
      assert(conf_parser.buf.items[conf_parser.len] == '\0');
    }
    assert(conf_parser.buf.items[conf_parser.len - 1] != '\n');
    char first = cin_lower_isalpha(&conf_parser.buf.items[0]) ? 'a' : conf_parser.buf.items[0];
    switch (first) {
    case 'a': {
      // expect abc=def123 or zyx  = wvu123
      char *p = conf_parser.buf.items + 1;
      while (cin_lower_isalpha(p)) ++p;
      conf_parser.k_len = (size_t)(p - conf_parser.buf.items);
      while (*p == ' ') ++p;
      if (*p != '=') {
        log_message(LOG_ERROR, "Token on line %d at position %zu must be '=', not '%c'",
                    conf_parser.line, (size_t)(p - conf_parser.buf.items) + 1, *p);
        goto end;
      }
      ++p;
      while (*p == ' ') ++p;
      if (!*p) {
        conf_parser.buf.items[conf_parser.k_len] = '\0';
        log_message(LOG_ERROR, "Token on line %d at position %zu must not be empty."
                               " Set the value for key '%s = ...'",
                    conf_parser.line, (size_t)(p - conf_parser.buf.items), conf_parser.buf.items);
        goto end;
      }
      conf_parser.v = p;
      size_t curr_pos = (size_t)(p - conf_parser.buf.items + 1);
      size_t remainder = conf_parser.len - curr_pos;
      char *comment = memchr(p, '#', remainder);
      if (comment) {
        size_t dist = (size_t)(comment - p);
        size_t comment_len = remainder - dist;
        conf_parser.len -= comment_len;
        if (conf_parser.len && *(comment - 1) == ' ') --conf_parser.len;
      }
      if (!conf_keyget()) {
        conf_parser.buf.items[conf_parser.k_len] = '\0';
        log_message(LOG_ERROR, "Unknown key '%s' on line %d, please check for typos",
                    conf_parser.buf.items, conf_parser.line);
        goto end;
      } else if (conf_parser.error) {
        goto end;
      }
    } break;
    case '[': {
      // expect abc]
      char *p = conf_parser.buf.items + 1;
      while (cin_lower_isalpha(p)) ++p;
      conf_parser.k_len = (size_t)(p - conf_parser.buf.items) - 1;
      if (*p != ']') {
        conf_parser.buf.items[conf_parser.k_len + 1] = '\0';
        log_message(LOG_ERROR, "Line %d wrongly creates a new scope '%s',"
                               " close it with ']' at position %zu",
                    conf_parser.line, conf_parser.buf.items, conf_parser.k_len + 2);
        goto end;
      }
      if (!conf_scopeget()) {
        conf_parser.buf.items[conf_parser.k_len + 2] = '\0';
        log_message(LOG_ERROR, "Scope '%s' at line %d is unknown, please check for typos",
                    conf_parser.buf.items, conf_parser.line);
        goto end;
      }
    } break;
    case '#':
      break;
    case '\0':
      break;
    default:
      log_message(LOG_ERROR, "Line %d starts with unexpected token '%d'. Only letters,"
                             " #, [, and empty lines are allowed here.",
                  conf_parser.line, conf_parser.buf.items[0]);
      goto end;
    }
    conf_parser.buf.items[0] = '\0';
    conf_parser.buf.count = 0;
    ++conf_parser.line;
  }
  ok = true;
end:
  fclose(file);
  return ok;
}

#define CIN_DOCS_ARENA_CAP megabytes(2)
#define CIN_DOCS_CAP (1 << 13)

struct Document_Collection {
  // Each byte represents a UTF-8 unit
  array_struct_members(uint8_t);
  uint32_t bytes_mul32;
  uint32_t doc_mul32;
  // Document boundaries are encapsulated in the GSA
  // because the lexicographical sort puts \0 entries
  // at the top; the first doc_count entries
  // represent the start/end positions of each doc
  int32_t doc_count;
  int32_t *gsa;
  int32_t *lcp;
  int32_t *suffix_to_doc;
  uint16_t *dedup_counters;
} docs = {0};

static inline void docs_push(uint8_t *utf8, int32_t len) {
  array_extend_zero(&docs_arena, &docs, utf8, (uint32_t)len);
  ++docs.doc_count;
}

static inline void docs_pop(int32_t len) {
  array_shrink(&docs, (uint32_t)len);
  --docs.doc_count;
}

typedef struct Directory_Node {
  array_struct_members(int32_t);
  uint32_t str_offset;
} Directory_Node;

typedef struct Directory_Path {
  wchar_t path[CIN_MAX_PATH];
  size_t len;
} Directory_Path;

array_define(Tag_Directories, int32_t);
array_define(Tag_Pattern_Items, int32_t);
array_define(Tag_Url_Items, int32_t);

typedef struct Playlist {
  array_struct_members(int32_t);
  uint32_t next_index;
  uint32_t targets;
  bool from_tag;
  // search table key not applicable to tag playlist
  table_key_pos search_pos;
  table_key_len search_len;
  cache_node_struct_members(Playlist);
} Playlist;

cache_define(Playlist_Cache, Playlist);
array_define(Search_Patterns, uint8_t);
array_define(Hidden_Table, int32_t);

struct Media {
  Playlist default_playlist;
  Playlist_Cache playlists;
  Robin_Hood_Table search_table;
  Search_Patterns search_patterns;
  Hidden_Table hidden_table;
} media = {0};

typedef struct Tag_Items {
  Playlist *playlist;
  Tag_Directories *directories;
  Tag_Pattern_Items *pattern_items;
  Tag_Url_Items *url_items;
} Tag_Items;

typedef struct Cin_Screen {
  uint32_t offset;
  uint32_t len;
} Cin_Screen;

typedef struct Cin_Layout {
  RECT chat_rect;
  int32_t scope_line;
  array_struct_members(Cin_Screen);
  uint32_t name_offset;
  uint32_t name_len;
} Cin_Layout;

typedef struct Cin_Macro {
  array_struct_members(wchar_t);
} Cin_Macro;

static struct {
  array_struct_members(Directory_Path);
  uint32_t abs_count;
} dir_stack = {0};

static struct {
  array_struct_members(wchar_t);
  size_t supply;
  size_t demand;
} clipboard = {0};

static array_struct(uint8_t) directory_strings = {0};
static array_struct(Directory_Node) directory_nodes = {0};
static array_struct(uint8_t) layout_strings = {0};
static array_struct(uint8_t) screen_strings = {0};
static array_struct(char) geometry_buf = {0};
static array_struct(Cin_Macro *) startup_macros = {0};

#define CIN_DIRECTORIES_CAP 64
#define CIN_DIRECTORY_ITEMS_CAP 64
#define CIN_DIRECTORY_STRINGS_CAP (CIN_DIRECTORIES_CAP * CIN_MAX_PATH_BYTES)
#define CIN_PATTERN_ITEMS_CAP 64
#define CIN_URLS_CAP 64
#define CIN_LAYOUT_SCREENS_CAP 8
#define CIN_QUERIES_CAP 8

static Robin_Hood_Table dir_table = {0};
static Robin_Hood_Table pat_table = {0};
static Robin_Hood_Table url_table = {0};
static Radix_Tree *tag_tree = NULL;
static Radix_Tree *layout_tree = NULL;
static Radix_Tree *macro_tree = NULL;

static inline void setup_file_path(wchar_t *path, int32_t *len) {
  assert(len);
  for (wchar_t *p = path; *p; ++p) {
    if (*p == L'\\') {
      *p++ = L'/';
      wchar_t *dups = p;
      while (*dups == L'\\') ++dups;
      if (p != dups) {
        ptrdiff_t removed = dups - p;
        ptrdiff_t pos = dups - path;
        assert((size_t)*len >= (size_t)pos);
        size_t remainder = (size_t)*len - (size_t)pos;
        wmemcpy(p, dups, remainder);
        p = dups;
        *len -= (int32_t)removed;
      }
    }
  }
  *(path + (size_t)*len) = L'\0';
}

static void setup_directory(const char *path, Tag_Directories *tag_dirs) {
  int32_t len_utf16 = utf8_to_utf16_norm(path);
  assert(len_utf16);
  setup_file_path(utf16_buf_norm.items, &len_utf16);
  size_t len = (size_t)len_utf16;
  Directory_Path root_dir = {.len = len};
  wmemcpy(root_dir.path, utf16_buf_norm.items, len);
  array_push(&console_arena, &dir_stack, root_dir);
  while (dir_stack.count > 0) {
    Directory_Path dir = dir_stack.items[--dir_stack.count];
    log_wmessage(LOG_DEBUG, L"Path: %ls", dir.path);
    assert(dir.path);
    assert(dir.len > 0);
    assert(dir.path[dir.len - 1] == L'\0');
    int32_t bytes_i32 = utf16_to_utf8(dir.path);
    assert(bytes_i32 > 0);
    uint32_t bytes = (uint32_t)bytes_i32;
    array_reserve(&console_arena, &directory_strings, bytes + 1);
    uint8_t *strings = directory_strings.items;
    uint32_t str_offset = directory_strings.count;
    memcpy(strings + str_offset, utf8_buf.items, bytes);
    uint32_t node_tail = directory_nodes.count;
    Table_Key key = {.strings = strings, .pos = str_offset, .len = bytes};
    table_value dup_index = table_find(&dir_table, &key);
    if (dup_index >= 0) {
      // NOTE: When the key is already in the hash, we have access to an index
      // into the dynamic nodes arena. Lazy evaluation: the terminator but must
      // be calculated (e.g., using the document ids to retrieve file names and
      // recognize depth reduction)
      if (tag_dirs) {
        array_push(&console_arena, tag_dirs, (int32_t)dup_index);
      }
      continue;
    }
    if (--dir.len + 2 >= CIN_MAX_PATH) {
      // We have to append 2 chars \ and * for the correct pattern
      log_wmessage(LOG_ERROR, L"Directory name too long: %ls", dir.path);
      continue;
    }
    dir.path[dir.len++] = L'/';
    dir.path[dir.len++] = L'*';
    dir.path[dir.len] = L'\0';
    WIN32_FIND_DATAW data;
    HANDLE search = FindFirstFileExW(dir.path, FindExInfoBasic, &data,
                                     FindExSearchNameMatch, NULL,
                                     FIND_FIRST_EX_LARGE_FETCH);
    // We can now drop the 2 chars \ and * to restore the root,
    // but choose to only drop * so that \ remains as a separator
    // for the next file or directory, instead of adding later.
    --dir.len;
    dir.path[dir.len] = L'\0';
    if (search == INVALID_HANDLE_VALUE) {
      log_last_error("Failed to match directory '%ls'", dir.path);
      continue;
    }
    // Commit the new directory
    array_grow(&console_arena, &directory_strings, bytes);
    array_grow(&console_arena, &directory_nodes, 1);
    Directory_Node *node = &directory_nodes.items[node_tail];
    assert(node);
    array_init(&console_arena, node, CIN_DIRECTORY_ITEMS_CAP);
    node->str_offset = str_offset;
    if (tag_dirs) {
      array_push(&console_arena, tag_dirs, (int32_t)node_tail);
    }
    table_value inserted = table_insert(&console_arena, &dir_table, &key, (table_value)node_tail);
    assert(inserted == -1);
    do {
      if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        continue; // skip junction
      }
      size_t file_len = (size_t)utf16_norm(data.cFileName);
      wchar_t *file = utf16_buf_norm.items;
      bool is_dir = data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
      if (is_dir && (file[0] == L'.') && (!file[1] || (file[1] == L'.' && !file[2]))) {
        continue; // skip dot entry
      }
      size_t path_len = dir.len + file_len;
      if (path_len >= CIN_MAX_PATH) {
        continue; // skip absolute path (+ NUL) if silently truncated
      }
      if (is_dir) {
        Directory_Path nested_path = {.len = path_len};
        wmemcpy(nested_path.path, dir.path, dir.len);
        wmemcpy(nested_path.path + dir.len, file, file_len);
        assert(nested_path.path[nested_path.len - 1] == L'\0');
        assert(nested_path.len > 0);
        ++dir_stack.abs_count;
        array_ensure_capacity_core(&console_arena, &dir_stack, dir_stack.abs_count, false);
        array_push(&console_arena, &dir_stack, nested_path);
      } else {
        wmemcpy(dir.path + dir.len, file, file_len);
        int32_t utf8_len = utf16_to_utf8(dir.path);
        table_key_pos tail_offset = array_bytes(&docs);
        int32_t tail_doc = (int32_t)tail_offset;
        docs_push(utf8_buf.items, utf8_len);
        if (conf_parser.has_patterns) {
          // NOTE: With patterns, we want to let the OS evaluate them.
          // The safest way to deduplicate patterns seems to be file-by-file
          // comparisons, which can of course degenerate so we check if the
          // config contains patterns first. We solve the cases where a pattern
          // was evaluated before this step, and after this step.
          Table_Key pat_key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)utf8_len};
          table_value dup_doc = table_insert(&console_arena, &pat_table, &pat_key, tail_doc);
          if (dup_doc >= 0) {
            docs_pop((int32_t)len);
            tail_doc = (int32_t)dup_doc;
          }
        }
        array_push(&console_arena, node, tail_doc);
      }
    } while (FindNextFileW(search, &data) != 0);
    if (GetLastError() != ERROR_NO_MORE_FILES) {
      log_last_error("Failed to find next file");
    }
    FindClose(search);
  }
  assert(dir_stack.count == 0);
}

static inline void setup_pattern(const char *pattern, Tag_Pattern_Items *tag_pattern_items) {
  // Processes all files (not directories) that match the pattern
  // https://support.microsoft.com/en-us/office/examples-of-wildcard-characters-939e153f-bd30-47e4-a763-61897c87b3f4
  int32_t len_utf16 = utf8_to_utf16_norm(pattern);
  assert(len_utf16);
  assert(utf16_buf_norm.items[len_utf16 - 1] == L'\0');
  setup_file_path(utf16_buf_norm.items, &len_utf16);
  wchar_t *separator = wcsrchr(utf16_buf_norm.items, L'/');
  if (separator == NULL || *(separator + 1) == L'\0') {
    log_message(LOG_ERROR, "Not a valid pattern: '%s', end properly with '\\...'", pattern);
    return;
  }
  size_t dir_len = (size_t)(separator - utf16_buf_norm.items) + 1;
  if (dir_len > CIN_MAX_PATH) {
    log_message(LOG_ERROR, "Pattern '%s' is too long (max=%d)", pattern, CIN_MAX_PATH);
    return;
  }
  wchar_t prev_tail = utf16_buf_norm.items[dir_len];
  utf16_buf_norm.items[dir_len] = L'\0';
  static wchar_t abs_buf[CIN_MAX_PATH];
  DWORD abs_len = GetFullPathNameW(utf16_buf_norm.items, CIN_MAX_PATH, abs_buf, NULL);
  setup_file_path(abs_buf, (int32_t *)&abs_len);
  if (abs_len == 0 || abs_len > CIN_MAX_PATH) {
    log_wmessage(LOG_ERROR, L"Pattern '%ls' full path '%ls' is empty or too long (max=%d)",
                 pattern, abs_buf, CIN_MAX_PATH);
    return;
  }
  log_wmessage(LOG_INFO, L"pattern: %ls", abs_buf);
  if (abs_buf[abs_len - 1] != L'/') {
    abs_buf[abs_len++] = L'/';
    abs_buf[abs_len] = L'\0';
  }
  utf16_buf_norm.items[dir_len] = prev_tail;
  WIN32_FIND_DATAW data;
  HANDLE search = FindFirstFileExW(utf16_buf_norm.items, FindExInfoBasic, &data,
                                   FindExSearchNameMatch, NULL,
                                   FIND_FIRST_EX_LARGE_FETCH);
  if (search == INVALID_HANDLE_VALUE) {
    log_last_error("Failed to match pattern '%ls'", utf16_buf_norm.items);
    return;
  }
  static const DWORD file_mask = FILE_ATTRIBUTE_DIRECTORY |
                                 FILE_ATTRIBUTE_REPARSE_POINT |
                                 FILE_ATTRIBUTE_DEVICE;
  do {
    if (data.dwFileAttributes & file_mask) {
      continue; // skip directories
    }
    size_t file_len = (size_t)utf16_norm(data.cFileName);
    wchar_t *file = utf16_buf_norm.items;
    int32_t path_len = (int32_t)(abs_len + file_len);
    if (path_len >= CIN_MAX_PATH) {
      continue; // skip absolute path (+ NUL) if silently truncated
    }
    wmemcpy(abs_buf + abs_len, file, file_len);
    int32_t len = utf16_to_utf8(abs_buf);
    table_key_pos tail_offset = array_bytes(&docs);
    int32_t tail_doc = (int32_t)tail_offset;
    docs_push(utf8_buf.items, len);
    Table_Key key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)len};
    table_value dup_doc = table_insert(&console_arena, &pat_table, &key, tail_doc);
    if (dup_doc >= 0) {
      docs_pop(len);
      if (tag_pattern_items) array_push(&console_arena, tag_pattern_items, (int32_t)dup_doc);
    } else {
      if (tag_pattern_items) array_push(&console_arena, tag_pattern_items, tail_doc);
    }
  } while (FindNextFileW(search, &data) != 0);
  if (GetLastError() != ERROR_NO_MORE_FILES) {
    log_last_error("Failed to find next file");
  }
  FindClose(search);
}

static inline void setup_url(const char *url, Tag_Url_Items *tag_url_items) {
  int32_t len_utf16 = utf8_to_utf16_raw(url);
  assert(len_utf16);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_raw.items);
  table_key_pos tail_offset = array_bytes(&docs);
  int32_t tail_doc = (int32_t)tail_offset;
  docs_push(utf8_buf.items, len_utf8);
  Table_Key key = {.strings = docs.items, .pos = tail_offset, .len = (table_key_len)len_utf8};
  table_value dup_doc = table_insert(&console_arena, &url_table, &key, tail_doc);
  if (dup_doc >= 0) {
    docs_pop(len_utf8);
    if (tag_url_items) array_push(&console_arena, tag_url_items, (int32_t)dup_doc);
  } else {
    if (tag_url_items) array_push(&console_arena, tag_url_items, tail_doc);
  }
}

static inline void setup_tag(const char *tag, Tag_Items *tag_items) {
  int32_t len_utf16 = utf8_to_utf16_norm(tag);
  assert(len_utf16);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  assert(len_utf8);
  radix_insert(tag_tree, utf8_buf.items, (size_t)len_utf8, tag_items);
}

static inline bool setup_chat(const char *geometry, uint32_t len, Cin_Layout *layout) {
  if (len == 0) {
    layout->chat_rect.right = LONG_MIN;
    layout->chat_rect.bottom = LONG_MIN;
    layout->chat_rect.left = LONG_MIN;
    layout->chat_rect.top = LONG_MIN;
    return true;
  }
  const char *p = geometry;
  int64_t width, height, x, y;
  cin_getnum(&p, &width);
  if (*p != 'x') return false;
  ++p;
  cin_getnum(&p, &height);
  bool positive;
  if (*p == '-') positive = false;
  else if (*p == '+') positive = true;
  else return false;
  ++p;
  cin_getnum(&p, &x);
  if (!positive) x = -x;
  if (*p == '-') positive = false;
  else if (*p == '+') positive = true;
  else return false;
  ++p;
  cin_getnum(&p, &y);
  if (*p && !isspace(*p)) return false;
  if (!positive) y = -y;
  layout->chat_rect.right = (LONG)width;
  layout->chat_rect.bottom = (LONG)height;
  layout->chat_rect.left = (LONG)x;
  layout->chat_rect.top = (LONG)y;
  return true;
}

static inline void setup_screen(const char *geometry, Cin_Layout *layout) {
  uint32_t bytes = (uint32_t)strlen(geometry) + 1U;
  Cin_Screen screen = {.offset = screen_strings.count, .len = bytes};
  array_extend(&console_arena, &screen_strings, geometry, bytes);
  array_push(&console_arena, layout, screen);
}

static inline void setup_layout(const char *name, Cin_Layout *layout) {
  int32_t len_utf16 = utf8_to_utf16_norm(name);
  assert(len_utf16 > 1);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  assert(len_utf8 > 1);
  uint32_t len_utf8_u32 = (uint32_t)len_utf8;
  layout->name_offset = layout_strings.count;
  layout->name_len = len_utf8_u32;
  array_extend(&console_arena, &layout_strings, utf8_buf.items, len_utf8_u32);
  radix_insert(layout_tree, utf8_buf.items, len_utf8_u32, layout);
}

static inline void setup_macro(const char *name, Cin_Macro *macro, bool startup) {
  int32_t len_utf16 = utf8_to_utf16_norm(name);
  assert(len_utf16 > 1);
  int32_t len_utf8 = utf16_to_utf8(utf16_buf_norm.items);
  assert(len_utf8 > 1);
  uint32_t len_utf8_u32 = (uint32_t)len_utf8;
  radix_insert(macro_tree, utf8_buf.items, len_utf8_u32, macro);
  if (startup) array_push(&console_arena, &startup_macros, macro);
}

static inline void setup_macro_command(const char *command, Cin_Macro *macro) {
  int32_t len = utf8_to_utf16_norm(command);
  assert(len > 1);
  uint32_t len_u32 = (uint32_t)len;
  array_wextend(&console_arena, macro, utf16_buf_norm.items, len_u32);
}

#define FOREACH_PART(str, part)                                                     \
  for (char *part = (str)->items, *_right = part, *_tail = part + (str)->count - 1; \
       part && part < _tail;                                                        \
       part = _right ? ++_right : NULL)                                             \
    if ((part += strspn(part, " \t,")),                                             \
        (_right = memchr(part, ',', (size_t)(_tail - part))),                       \
        (_right = _right ? (*_right = '\0', _right) : NULL),                        \
        *part)

static bool init_config(const char *filename) {
  if (!parse_config(filename)) return false;
  table_init(&console_arena, &dir_table, CIN_DIRECTORIES_CAP);
  table_init(&console_arena, &pat_table, CIN_PATTERN_ITEMS_CAP);
  table_init(&console_arena, &url_table, CIN_URLS_CAP);
  arena_chunk_init(&docs_arena, CIN_DOCS_ARENA_CAP);
  array_init_zero(&docs_arena, &docs, CIN_DOCS_CAP);
  array_init(&console_arena, &directory_nodes, CIN_DIRECTORIES_CAP);
  array_init(&console_arena, &directory_strings, CIN_DIRECTORY_STRINGS_CAP);
  array_init(&console_arena, &geometry_buf, CIN_LAYOUT_SCREENS_CAP);
  tag_tree = radix_tree();
  layout_tree = radix_tree();
  macro_tree = radix_tree();
  Conf_Root *root = &conf_parser.scopes.items[0].root;
  for (size_t i = 1; i < conf_parser.scopes.count; ++i) {
    Conf_Scope *scope = &conf_parser.scopes.items[i];
    log_message(LOG_DEBUG, "[Scope %zu: %zu]", i, scope->type);
    switch (scope->type) {
    case CONF_SCOPE_LAYOUT: {
      if (!scope->layout.name.count) {
        log_message(LOG_ERROR, "Layout at [scope] number %zu does not have a name key,"
                               " please supply it: 'name = value'",
                    i);
        return false;
      }
      if (!scope->layout.screen.count) {
        log_message(LOG_ERROR, "Layout at [scope] number %zu does not have any screen"
                               " keys, please supply with: 'screen = 0:0'",
                    i);
        return false;
      }
      Cin_Layout *layout = arena_bump_T1(&console_arena, Cin_Layout);
      if (!setup_chat(scope->layout.chat.items, scope->layout.chat.count, layout)) {
        log_message(LOG_WARNING, "Layout at [scope] number %zu does not have a valid chat"
                                 " key, please fix as: 'chat = 0x0±0±0'",
                    i);
      }
      layout->scope_line = scope->line;
      array_init(&console_arena, layout, CIN_LAYOUT_SCREENS_CAP);
      log_message(LOG_DEBUG, "Name: %s", scope->layout.name.items);
      FOREACH_PART(&scope->layout.screen, part) {
        log_message(LOG_DEBUG, "Screen: %s", part);
        setup_screen(part, layout);
      }
      setup_layout(scope->layout.name.items, layout);
      array_free_items(&console_arena, &scope->layout.name);
      array_free_items(&console_arena, &scope->layout.screen);
      array_free_items(&console_arena, &scope->layout.chat);
    } break;
    case CONF_SCOPE_MEDIA: {
      Tag_Items *tag_items = NULL;
      Tag_Directories *tag_directories = NULL;
      Tag_Pattern_Items *tag_pattern_items = NULL;
      Tag_Url_Items *tag_url_items = NULL;
      if (scope->media.tags.count) {
        tag_items = arena_bump_T1(&console_arena, Tag_Items);
        if (scope->media.directories.count) {
          tag_items->directories = arena_bump_T1(&console_arena, Tag_Directories);
          array_init(&console_arena, tag_items->directories, CIN_DIRECTORIES_CAP);
          tag_directories = tag_items->directories;
        }
        if (scope->media.patterns.count) {
          tag_items->pattern_items = arena_bump_T1(&console_arena, Tag_Pattern_Items);
          array_init(&console_arena, tag_items->pattern_items, scope->media.patterns.count);
          tag_pattern_items = tag_items->pattern_items;
        }
        if (scope->media.urls.count) {
          tag_items->url_items = arena_bump_T1(&console_arena, Tag_Url_Items);
          array_init(&console_arena, tag_items->url_items, scope->media.urls.count);
          tag_url_items = tag_items->url_items;
        }
      }
      FOREACH_PART(&scope->media.directories, part) {
        log_message(LOG_DEBUG, "Directory: %s", part);
        setup_directory(part, tag_directories);
      }
      FOREACH_PART(&scope->media.patterns, part) {
        log_message(LOG_DEBUG, "Pattern: %s", part);
        setup_pattern(part, tag_pattern_items);
      }
      FOREACH_PART(&scope->media.urls, part) {
        log_message(LOG_DEBUG, "URL: %s", part);
        setup_url(part, tag_url_items);
      }
      FOREACH_PART(&scope->media.tags, part) {
        log_message(LOG_DEBUG, "Tag: %s", part);
        setup_tag(part, tag_items);
      }
      // NOTE: Each tag corresponding to this media scope now points to the same
      // Tag_Items address. In it, 'patterns' and 'urls' contain document ids (possibly
      // with duplicates). Its 'directories' is a Tag_Directories struct, where each
      // item is an index into a global Directory_Node arena (possibly with duplicates)
      // - these nodes contain a list of unique document ids. Given example directory
      // A:\b\c\, the node arena must be traversed starting there up to an index where
      // the first document in the list does not start with A:\b\c\ (so we simulate
      // a correct recursive directory traversal, lazily, i.e., when tag is requested)
      array_free_items(&console_arena, &scope->media.directories);
      array_free_items(&console_arena, &scope->media.patterns);
      array_free_items(&console_arena, &scope->media.urls);
      array_free_items(&console_arena, &scope->media.tags);
    } break;
    case CONF_SCOPE_MACRO: {
      if (!scope->macro.name.count) {
        log_message(LOG_ERROR, "Macro at [scope] number %zu does not have a name key,"
                               " please supply it: 'name = value'",
                    i);
        return false;
      }
      Cin_Macro *macro = arena_bump_T1(&console_arena, Cin_Macro);
      log_message(LOG_DEBUG, "Name: %s", scope->macro.name.items);
      FOREACH_PART(&scope->macro.command, part) {
        log_message(LOG_DEBUG, "Macro: %s", part);
        setup_macro_command(part, macro);
      }
      bool startup = scope->macro.startup.items && strcmp("yes", scope->macro.startup.items) == 0;
      setup_macro(scope->macro.name.items, macro, startup);
      array_free_items(&console_arena, &scope->macro.name);
      array_free_items(&console_arena, &scope->macro.command);
      array_free_items(&console_arena, &scope->macro.startup);
    } break;
    default:
      assert(false && "Unexpected scope");
      break;
    }
  }
  table_free_items(&console_arena, &dir_table);
  table_free_items(&console_arena, &pat_table);
  table_free_items(&console_arena, &url_table);
  array_free_items(&console_arena, &dir_stack);
  array_free_items(&console_arena, &conf_parser.scopes);
  array_free_items(&console_arena, &conf_parser.buf);
  array_to_pow1(&docs_arena, &docs);
  assert(array_bytes(&docs) <= CIN_ARENA_MAX && "overflew k = 31");
  if (array_bytes(&docs) == CIN_ARENA_MAX) {
    // extremely rare case where we exceed INT_MAX by 1 byte,
    // instead of trying to fix it we force a crash
    wwritef(L"Cinema crashed receiving too many file paths (exceeding %d bytes)", INT_MAX);
    exit(1);
  }
  docs.bytes_mul32 = array_bytes(&docs) * (uint32_t)sizeof(int32_t);
  docs.doc_mul32 = (uint32_t)docs.doc_count * sizeof(int32_t);
  log_message(LOG_INFO, "Setup media library with %d items (%u bytes)",
              docs.doc_count, array_bytes(&docs));
  return true;
}

static bool reinit_documents(void) {
  int32_t d_bytes = (int32_t)array_bytes(&docs);
  if (d_bytes == 0) {
    log_wmessage(LOG_ERROR, L"media library is empty");
    return false;
  }
  int32_t remainder = (int32_t)docs.bytes_capacity - d_bytes;
#if defined(LIBSAIS_OPENMP)
  int32_t result = libsais_gsa_omp(docs.items, docs.gsa, d_bytes, remainder, NULL, cin_system.threads);
#else
  int32_t result = libsais_gsa(docs.items, docs.gsa, d_bytes, remainder, NULL);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build SA");
    return false;
  }
  int32_t *tmp = arena_bump_T(&docs_arena, int32_t, (uint32_t)d_bytes);
#if defined(LIBSAIS_OPENMP)
  result = libsais_plcp_gsa_omp(docs.items, docs.gsa, tmp, d_bytes, cin_system.threads);
#else
  result = libsais_plcp_gsa(docs.items, docs.gsa, tmp, d_bytes);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build PLCP array");
    return false;
  }
#if defined(LIBSAIS_OPENMP)
  result = libsais_lcp_omp(tmp, docs.gsa, docs.lcp, d_bytes, cin_system.threads);
#else
  result = libsais_lcp(tmp, docs.gsa, docs.lcp, d_bytes);
#endif
  if (result != 0) {
    log_message(LOG_ERROR, "Failed to build LCP array");
    return false;
  }
  Playlist *default_playlist = &media.default_playlist;
  array_ensure_capacity_core(&docs_arena, default_playlist, (uint32_t)docs.doc_count, false);
  for (int32_t i = 0, offset = 0; i < d_bytes; ++i) {
    tmp[i] = offset;
    if (docs.items[i] == '\0') {
      uint32_t playlist_pos = default_playlist->count++;
      default_playlist->items[playlist_pos] = offset;
      offset = i + 1;
    }
  }
#if defined(CIN_OPENMP)
#pragma omp parallel for if (d_bytes >= (1 << 19))
#endif
  for (int32_t i = 0; i < d_bytes; ++i) {
    int32_t offset = docs.gsa[i];
    int32_t doc = tmp[offset];
    docs.suffix_to_doc[i] = doc;
  }
  arena_free_pos(&docs_arena, (uint8_t *)tmp, (uint32_t)d_bytes);
  return true;
}

static bool init_documents(void) {
  int32_t d_bytes = (int32_t)array_bytes(&docs);
  docs.gsa = arena_bump_T(&docs_arena, uint8_t, docs.bytes_mul32);
  docs.lcp = arena_bump_T(&docs_arena, uint8_t, docs.bytes_mul32);
  docs.dedup_counters = arena_bump_T(&docs_arena, uint16_t, (uint32_t)d_bytes);
  docs.suffix_to_doc = arena_bump_T(&docs_arena, int32_t, (uint32_t)d_bytes);
  table_init(&docs_arena, &media.search_table, CIN_QUERIES_CAP);
  return reinit_documents();
}

static void document_listing(const uint8_t *pattern, int32_t pattern_len, Playlist *result) {
  int32_t left = docs.doc_count;
  int32_t right = (int32_t)array_bytes(&docs) - 1;
  int32_t l_lcp = lcps(pattern, docs.items + docs.gsa[left]);
  int32_t r_lcp = lcps(pattern, docs.items + docs.gsa[right]);
  if (l_lcp < pattern_len &&
      (docs.items[docs.gsa[left] + l_lcp] == '\0' ||
       pattern[l_lcp] < docs.items[docs.gsa[left] + l_lcp])) {
    // pattern = abc, left = abd
    // l_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[l_lcp] = c, text[left + l_lcp] = d, c < d
    log_message(LOG_DEBUG, "Pattern is smaller than first suffix");
    return;
  }
  if (r_lcp < pattern_len &&
      docs.items[docs.gsa[right] + r_lcp] != '\0' &&
      pattern[r_lcp] > docs.items[docs.gsa[right] + r_lcp]) {
    // pattern = abd, right = abc
    // r_lcp = 2, pattern_len = 3, 2 < 3
    // pattern[r_lcp] = d, text[right + r_lcp] = c, d > c
    log_message(LOG_DEBUG, "Pattern is larger than last suffix");
    return;
  }
  int32_t tmp_right = right;
  int32_t tmp_r_lcp = r_lcp;
  bool found = false;
  while (left < right) {
    int32_t mid = left + ((right - left) >> 1);
    int32_t t_lcp = lcps(pattern, docs.items + docs.gsa[mid]);
    if (t_lcp == pattern_len) {
      found = true;
      right = mid;
      r_lcp = t_lcp;
    } else if (docs.items[docs.gsa[mid] + t_lcp] == '\0') {
      left = mid + 1;
      l_lcp = t_lcp;
    } else if (pattern[t_lcp] < docs.items[docs.gsa[mid] + t_lcp]) {
      right = mid;
      r_lcp = t_lcp;
    } else {
      left = mid + 1;
      l_lcp = t_lcp;
    }
  }
  if (!found && lcps(pattern, docs.items + docs.gsa[left]) < pattern_len) {
    log_message(LOG_DEBUG, "No suffix has pattern as prefix");
    return;
  }
  int32_t l_bound = left;
  int32_t r_bound = left;
  right = tmp_right;
  l_lcp = pattern_len;
  r_lcp = tmp_r_lcp;
  while (left < right) {
    int32_t mid = left + ((right - left + 1) >> 1);
    int32_t t_lcp = lcps(pattern, docs.items + docs.gsa[mid]);
    if (t_lcp == pattern_len) {
      left = mid;
      l_lcp = pattern_len;
    } else if (docs.items[docs.gsa[mid] + t_lcp] == '\0') {
      right = mid - 1;
      r_lcp = t_lcp;
    } else {
      right = mid - 1;
      r_lcp = t_lcp;
    }
    r_bound = left;
  }
  log_message(LOG_DEBUG, "Boundaries are [%d, %d] or [%s, %s]", l_bound, r_bound,
              docs.items + docs.gsa[l_bound], docs.items + docs.gsa[r_bound]);
  static uint16_t dedup_counter = 1;
  int32_t n = min(docs.doc_count, (r_bound - l_bound) + 1);
  array_ensure_capacity_core(&docs_arena, result, (uint32_t)n, false);
  result->count = 0;
  for (int32_t i = l_bound; i <= r_bound; ++i) {
    int32_t doc = docs.suffix_to_doc[i];
    if (docs.dedup_counters[doc] != dedup_counter) {
      docs.dedup_counters[doc] = dedup_counter;
      assert(result->count < result->capacity);
      assert(result->count <= (uint32_t)n);
      if (media.hidden_table.count) {
        Hidden_Table *table = &media.hidden_table;
        uint64_t mask = table->capacity - 1;
        uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
        uint64_t index = hash & mask;
        while (table->items[index] >= 0) {
          if (table->items[index] == doc) goto skip;
          index = (index + 1) & mask;
        }
      }
      array_push(&docs_arena, result, doc);
      log_message(LOG_TRACE, "docs.gsa[%7d] = %-25.25s (%7d)| (%7d) = %-30.30s counter=%d",
                  i, docs.items + docs.gsa[i], docs.gsa[i], doc, docs.items + doc, dedup_counter);
    skip:;
    }
  }
  if (++dedup_counter == 0) {
    memset(docs.dedup_counters, 0, (size_t)array_bytes(&docs) * sizeof(uint16_t));
    dedup_counter = 1;
  }
}

#define CIN_IO_ARENA_CAP megabytes(2)
#define CIN_READ_SIZE kilobytes(16)
#define CIN_WRITE_SIZE align_to_block(CIN_MAX_PATH_BYTES) + block_bytes(2)

typedef enum {
  MPV_READ,
  MPV_WRITE,
  MPV_LOADFILE,
  MPV_WINDOW_ID,
  MPV_SET_GEOMETRY,
  MPV_GET_PATH,
  MPV_QUIT
} MPV_Packet;

typedef struct Overlapped_Context {
  OVERLAPPED ovl;
  MPV_Packet type;
} Overlapped_Context;

typedef struct Overlapped_Write {
  Overlapped_Context ovl_ctx;
  char buf[CIN_WRITE_SIZE];
  size_t bytes;
  cache_node_struct_members(Overlapped_Write);
} Overlapped_Write;

typedef struct Read_Buffer {
  char buf[CIN_READ_SIZE];
  size_t bytes;
  struct Read_Buffer *next;
} Read_Buffer;

typedef struct Console_Timer_Ctx {
  PTP_TIMER timer;
  LONGLONG millis;
  bool (*f)(struct Console_Timer_Ctx *ctx);
  cache_node_struct_members(Console_Timer_Ctx);
} Console_Timer_Ctx;

typedef struct Instance {
  Overlapped_Context ovl_ctx;
  HANDLE pipe;
  Read_Buffer *buf_head;
  Read_Buffer *buf_tail;
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  HWND window;
  RECT rect;
  Playlist *playlist;
  Console_Timer_Ctx *timer;
  bool full_screen;
  bool autoplay_mpv;
  bool locked;
  cache_node_struct_members(Instance);
} Instance;

cache_define(Write_Cache, Overlapped_Write);
cache_define(Instance_Cache, Instance);

static struct {
  Write_Cache writes;
  Instance_Cache instances;
  HANDLE iocp;
} cin_io = {0};

static bool create_pipe(Instance *instance, const wchar_t *name) {
  // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
  // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
  static const int FOUND_TIMEOUT = 20000;
  static const int UNFOUND_TIMEOUT = 20000;
  static const int UNFOUND_WAIT = 50;
  int unfound_duration = 0;
  HANDLE hPipe = INVALID_HANDLE_VALUE;
  for (;;) {
    hPipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
      break;
    }
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      // Wait for the IPC server to start with timeout
      unfound_duration += UNFOUND_WAIT;
      if (unfound_duration >= UNFOUND_TIMEOUT) {
        log_message(LOG_ERROR, "Failed to find pipe in time: %dms/%dms", unfound_duration, UNFOUND_TIMEOUT);
        return false;
      }
      log_message(LOG_DEBUG, "Failed to find pipe. Trying again in %dms...", UNFOUND_WAIT);
      Sleep(UNFOUND_WAIT);
    } else {
      // Unlikely error, try to resolve by waiting
      log_last_error("Could not connect to pipe - Waiting for %dms", FOUND_TIMEOUT);
      if (!WaitNamedPipeW(name, FOUND_TIMEOUT)) {
        log_last_error("Failed to connect to pipe");
        return false;
      }
    }
  }
  instance->pipe = hPipe;
  log_message(LOG_TRACE, "Successfully created pipe (HANDLE) %p", (void *)instance->pipe);
  return true;
}

static bool overlap_read(Instance *instance) {
  ZeroMemory(&instance->ovl_ctx.ovl, sizeof(OVERLAPPED));
  char *start = instance->buf_tail->buf + instance->buf_tail->bytes;
  DWORD to_read = (DWORD)(sizeof(instance->buf_tail->buf) - instance->buf_tail->bytes);
  if (instance->pipe && !ReadFile(instance->pipe, start, to_read, NULL, &instance->ovl_ctx.ovl)) {
    if (GetLastError() != ERROR_IO_PENDING) {
      log_last_error("Failed to initialize read");
      return false;
    }
  }
  // Read is queued for iocp
  return true;
}

#define CIN_WRITE_CMD_LEFT "{async:true,request_id:%lld,command:[\"%s\""
#define CIN_WRITE_CMD_MID ",\"%s\""
#define CIN_WRITE_CMD_RIGHT "]}\n"
#define CIN_WRITE_CMD_0ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_RIGHT)
#define CIN_WRITE_CMD_1ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_MID CIN_WRITE_CMD_RIGHT)
#define CIN_WRITE_CMD_2ARG (CIN_WRITE_CMD_LEFT CIN_WRITE_CMD_MID CIN_WRITE_CMD_MID CIN_WRITE_CMD_RIGHT)

static bool overlap_write(Instance *instance, MPV_Packet type, const char *cmd, const char *arg1, const char *arg2) {
  Overlapped_Write *write = NULL;
  cache_get_zero(&io_arena, &cin_io.writes, write);
  write->ovl_ctx.type = type;
  int64_t request_id = (int64_t)(uintptr_t)write;
  int32_t bytes = 0;
  if (arg1 && arg2) bytes = snprintf(write->buf, sizeof(write->buf), CIN_WRITE_CMD_2ARG, request_id, cmd, arg1, arg2);
  else if (arg1) bytes = snprintf(write->buf, sizeof(write->buf), CIN_WRITE_CMD_1ARG, request_id, cmd, arg1);
  else bytes = snprintf(write->buf, sizeof(write->buf), CIN_WRITE_CMD_0ARG, request_id, cmd);
  assert(bytes > 0);
  assert((size_t)bytes < sizeof(write->buf) - 1);
  write->bytes = (size_t)bytes;
  log_message(LOG_DEBUG, "Writing message (PID %lu) (%zu bytes): %.*s",
              instance->pi.dwProcessId, write->bytes, write->bytes - 1, write->buf);
  if (instance->pipe && !WriteFile(instance->pipe, write->buf, (DWORD)write->bytes, NULL, &write->ovl_ctx.ovl)) {
    switch (GetLastError()) {
    case ERROR_IO_PENDING:
      // iocp will free write
      log_message(LOG_TRACE, "Pending write call, handled by iocp.");
      return true;
    case ERROR_INVALID_HANDLE:
      // Code 6: The handle is invalid
      break;
    case ERROR_NO_DATA:
      // trying to initialize a write after quit
      break;
    default:
      break;
    }
    log_last_error("Failed to initialize write");
    assert(false);
    return false;
  }
  log_message(LOG_TRACE, "Write call completed immediately.");
  return true;
}

typedef struct Window_Data {
  union {
    DWORD pid;
    wchar_t *name;
    struct {
      DWORD *pids;
      DWORD count;
    };
  };
  HWND hwnd;
} Window_Data;

static BOOL CALLBACK enum_windows_proc_pid(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  DWORD pid;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid == data->pid && IsWindow(hwnd)) {
    data->hwnd = hwnd;
    return FALSE;
  }
  return TRUE;
}

static HWND find_window_by_pid(DWORD pid) {
  Window_Data data = {.pid = pid, .hwnd = NULL};
  EnumWindows(enum_windows_proc_pid, (LPARAM)&data);
  return data.hwnd;
}

static BOOL CALLBACK enum_windows_proc_name(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  wchar_t *pattern = data->name;
  wchar_t query[MAX_CLASS_NAME];
  GetClassNameW(hwnd, query, sizeof(query));
  if (wcscmp(pattern, query) == 0) {
    data->hwnd = hwnd;
    return FALSE;
  }
  return TRUE;
}

static HWND find_window_by_name(wchar_t *name) {
  Window_Data data = {.name = name, .hwnd = NULL};
  EnumWindows(enum_windows_proc_name, (LPARAM)&data);
  return data.hwnd;
}

static BOOL CALLBACK enum_windows_proc_console(HWND hwnd, LPARAM lParam) {
  Window_Data *data = (Window_Data *)lParam;
  DWORD pid;
  GetWindowThreadProcessId(hwnd, &pid);
  for (DWORD i = 0; i < data->count; i++) {
    if (pid == data->pids[i]) {
      if (IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == NULL) {
        data->hwnd = hwnd;
        return FALSE;
      }
    }
  }
  return TRUE;
}

static HWND find_window_of_console(void) {
  array_struct(DWORD) pids = {0};
  DWORD dwProcessCount = 16;
  array_init(&iocp_thread_arena, &pids, dwProcessCount);
  DWORD actual_count = GetConsoleProcessList(pids.items, dwProcessCount);
  array_resize(&iocp_thread_arena, &pids, actual_count);
  if (actual_count > dwProcessCount) {
    dwProcessCount = actual_count;
    actual_count = GetConsoleProcessList(pids.items, dwProcessCount);
  }
  Window_Data data = {.pids = pids.items, .count = actual_count, .hwnd = NULL};
  EnumWindows(enum_windows_proc_console, (LPARAM)&data);
  array_free_items(&iocp_thread_arena, &pids);
  return data.hwnd;
}

static inline void playlist_setup_shuffle(Playlist *playlist) {
  uint32_t n = playlist->count;
  assert(n);
  uint32_t fy = n - 1;
  array_shuffle_fisher_yates(playlist, int32_t, fy, 1);
  playlist->next_index = 0;
}

static inline void playlist_shuffle(Playlist *playlist) {
  uint32_t n = playlist->count;
  uint32_t s = 0;
  uint32_t fy = 0;
  if (n > 2) {
    s = n - 1;
    static const uint32_t SATTOLO_FACTOR = 5;
    uint32_t remainder = s / SATTOLO_FACTOR;
    assert(playlist->targets);
    uint32_t tail = max(playlist->targets, remainder);
    uint32_t clamped_tail = min(tail, s);
    uint32_t diff = s - clamped_tail;
    uint32_t clamped_diff = max(1, diff);
    fy = s - clamped_diff;
    assert(fy >= 1);
    assert(s > fy);
  }
  array_shuffle_fisher_yates(playlist, int32_t, fy, 1);
  array_shuffle_sattolo(playlist, int32_t, s, fy);
  playlist->next_index = 0;
}

static inline void playlist_set(Instance *instance, Playlist *playlist) {
  Playlist *prev = instance->playlist;
  if (prev && --prev->targets == 0 && !prev->from_tag &&
      prev != playlist && prev != &media.default_playlist) {
    Table_Key key = {.strings = media.search_patterns.items,
                     .pos = prev->search_pos,
                     .len = prev->search_len};
    table_delete(&media.search_table, &key);
    array_free_items(&docs_arena, prev);
    cache_put(&media.playlists, prev);
  }
  ++playlist->targets;
  instance->playlist = playlist;
}

static inline void playlist_set_default(Instance *instance) {
  playlist_set(instance, &media.default_playlist);
}

static inline void playlist_play_core(Instance *instance, const char *arg) {
  if (instance->locked) return;
  assert(instance->playlist);
  Playlist *playlist = instance->playlist;
  uint32_t index = instance->playlist->next_index;
  char *url = (char *)docs.items + playlist->items[index];
  overlap_write(instance, MPV_LOADFILE, "loadfile", url, arg);
  if (++instance->playlist->next_index == instance->playlist->count) {
    playlist_shuffle(instance->playlist);
  }
}

static inline void playlist_play(Instance *instance) {
  playlist_play_core(instance, NULL);
}

static inline void playlist_insert(Instance *instance) {
  playlist_play_core(instance, "insert-next");
}

#define CIN_MPVKEY_LEFT "\""
#define CIN_MPVKEY_RIGHT "\":"
#define CIN_MPVKEY(str) (CIN_MPVKEY_LEFT str CIN_MPVKEY_RIGHT)
#define CIN_MPVVAL(buf, lit) (strncmp((buf), (lit), cin_strlen((lit))) == 0)
#define CIN_MPVKEY_REQUEST CIN_MPVKEY("request_id")
#define CIN_MPVKEY_EVENT CIN_MPVKEY("event")
#define CIN_MPVKEY_DATA CIN_MPVKEY("data")
#define CIN_MPVKEY_REASON CIN_MPVKEY("reason")

static inline void mpv_kill(Instance *instance) {
  assert(instance->playlist);
  --instance->playlist->targets;
  Read_Buffer *buf_head = instance->buf_head;
  Read_Buffer *buf_tail = instance->buf_tail;
  Instance *next = instance->next;
  ZeroMemory(instance, sizeof(Instance));
  playlist_set_default(instance);
  instance->buf_head = buf_head;
  instance->buf_tail = buf_tail;
  instance->next = next;
}

static size_t mpv_supply = 0;
static size_t mpv_demand = 0;

static inline void mpv_lock(void) {
  mpv_supply = 0;
  mpv_demand = 0;
  LockSetForegroundWindow(LSFW_LOCK);
}

static inline void mpv_restore_focus(void) {
  if (!repl.window && (repl.viewport_bound || !(repl.window = GetConsoleWindow()))) {
    // Since repl.window is set by calling GetForegroundWindow on launch,
    // this branch is unlikely to be triggered.
    static const size_t MPV_RESTORE_TRIES = 20;
    static const DWORD MPV_RESTORE_DELAY = 100;
    for (size_t i = 0; i < MPV_RESTORE_TRIES; ++i) {
      repl.window = find_window_of_console();
      if (repl.window) break;
      else Sleep(MPV_RESTORE_DELAY);
    }
    assert(repl.window && "terminal window not found");
  }
  SetWindowPos(repl.window, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
}

static inline void mpv_unlock(void) {
  LockSetForegroundWindow(LSFW_UNLOCK);
}

// NOTE: voidtools Everything supports pipe '|' as search separator and '"' for spaces
#define CIN_CLIPBOARD_SEPARATOR L'|'
#define CIN_CLIPBOARD_ENCLOSER L'"'

static inline void iocp_parse(Instance *instance, const char *buf_start, size_t buf_offset) {
  const char *buf = buf_start + buf_offset;
  char *p = NULL;
  if ((p = strstr(buf, CIN_MPVKEY_EVENT))) {
    p += cin_strlen(CIN_MPVKEY_EVENT);
    assert(*p == '\"');
    ++p;
    if (CIN_MPVVAL(p, "end-file")) {
      if ((p = strstr(p, CIN_MPVKEY_REASON))) {
        p += cin_strlen(CIN_MPVKEY_REASON);
        assert(*p == '\"');
        ++p;
        if (CIN_MPVVAL(p, "quit")) mpv_kill(instance);
      }
    } else if (CIN_MPVVAL(p, "file-loaded")) {
      if (instance->autoplay_mpv) playlist_insert(instance);
    } else if (CIN_MPVVAL(p, "video-reconfig")) {
      mpv_restore_focus();
    }
  } else if ((p = strstr(buf, CIN_MPVKEY_REQUEST))) {
    p += cin_strlen(CIN_MPVKEY_REQUEST);
    assert(cin_isnum(*p));
    int64_t req_id = *p - '0';
    while (cin_isnum(*++p)) req_id = (req_id * 10) + (*p - '0');
    Overlapped_Write *write = (Overlapped_Write *)(uintptr_t)req_id;
    assert(write);
    assert(write->bytes);
    log_message(LOG_DEBUG, "Recovered original write: %p (%zu bytes)", write, write->bytes);
    switch (write->ovl_ctx.type) {
    case MPV_LOADFILE:
      // overlap_write(instance, MPV_WRITE, "playlist-next", NULL, NULL);
      break;
    case MPV_WINDOW_ID: {
      if (++mpv_supply == mpv_demand) mpv_unlock();
      char *data = strstr(buf, CIN_MPVKEY_DATA);
      if (!data) {
        // NOTE: If the request was delivered before mpv managed to create
        // the window, it will return something like "error: property
        // unavailable": retry.
        overlap_write(instance, MPV_WINDOW_ID, "get_property", "window-id", NULL);
        break;
      }
      assert(data);
      data += cin_strlen(CIN_MPVKEY_DATA);
      assert(cin_isnum(*data));
      intptr_t window_id = 0;
      for (; cin_isnum(*data); ++data) window_id = (window_id * 10) + *data - '0';
      assert(IsWindow((HWND)window_id));
      assert(IsWindowVisible((HWND)window_id));
      instance->window = (HWND)window_id;
      GetWindowRect(instance->window, &instance->rect);
    } break;
    case MPV_QUIT:
      mpv_kill(instance);
      break;
    case MPV_SET_GEOMETRY:
      mpv_restore_focus();
      break;
    case MPV_GET_PATH: {
      char *data = strstr(buf, CIN_MPVKEY_DATA);
      assert(data);
      data += cin_strlen(CIN_MPVKEY_DATA);
      assert(*data == '"');
      ++data;
      char *tail = strchr(data, '"');
      assert(tail);
      int32_t len_utf8 = (int32_t)(tail - data);
      int32_t len = utf8_to_utf16_nraw(data, len_utf8);
      assert(len > 0);
      uint32_t len_u32 = (uint32_t)len;
      wchar_t *url_utf16 = utf16_buf_raw.items;
      array_push(&iocp_thread_arena, &clipboard, CIN_CLIPBOARD_ENCLOSER);
      wchar_t prev = L'\0';
      for (uint32_t i = 0; i < len_u32; ++i) {
        wchar_t curr = url_utf16[i];
        if (prev != L'\\' || curr != L'\\') {
          array_push(&iocp_thread_arena, &clipboard, curr);
        }
        prev = curr;
      }
      array_push(&iocp_thread_arena, &clipboard, CIN_CLIPBOARD_ENCLOSER);
      array_push(&iocp_thread_arena, &clipboard, CIN_CLIPBOARD_SEPARATOR);
      if (++clipboard.supply == clipboard.demand) {
        clipboard.supply = 0;
        clipboard.demand = 0;
        if (clipboard.count) clipboard.items[clipboard.count - 1] = L'\0';
        if (!OpenClipboard(NULL)) {
          log_last_error("Failed to open clipboard");
          return;
        }
        EmptyClipboard();
        HGLOBAL hglb = GlobalAlloc(GMEM_MOVEABLE, array_bytes(&clipboard));
        if (!hglb) {
          log_last_error("Failed to allocate global memory for clipboard");
          CloseClipboard();
          return;
        }
        LPWSTR lpwstr = GlobalLock(hglb);
        wmemcpy(lpwstr, clipboard.items, clipboard.count);
        GlobalUnlock(hglb);
        SetClipboardData(CF_UNICODETEXT, hglb);
        CloseClipboard();
      }
    } break;
    default:
      break;
    }
    cache_put(&cin_io.writes, write);
  }
}

static DWORD WINAPI iocp_listener(LPVOID lp_param) {
  HANDLE iocp = (HANDLE)lp_param;
  for (;;) {
    DWORD bytes;
    ULONG_PTR completion_key;
    OVERLAPPED *ovl;
    if (!GetQueuedCompletionStatus(iocp, &bytes, &completion_key, &ovl, INFINITE)) {
      // https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus#remarks
      log_last_error("Failed to dequeue packet");
      exit(1);
    }
    Instance *instance = (Instance *)completion_key;
    Overlapped_Context *ctx = (Overlapped_Context *)ovl;
    if (ctx->type != MPV_READ) {
      Overlapped_Write *write = (Overlapped_Write *)ctx;
      if (write->bytes != bytes) {
        log_message(LOG_ERROR, "Expected '%zu' bytes but received '%ld'", write->bytes, bytes);
        exit(1);
      }
    } else {
      if (bytes) {
        assert(!memchr(instance->buf_tail->buf, '\0', instance->buf_tail->bytes));
        assert(sizeof(instance->buf_tail->buf) - instance->buf_tail->bytes >= bytes);
        char *lf = memchr(instance->buf_tail->buf + instance->buf_tail->bytes, '\n', bytes);
        instance->buf_tail->bytes += bytes;
        if (lf) {
          bool multi = instance->buf_tail != instance->buf_head;
          assert((lf - instance->buf_tail->buf) >= 0);
          size_t tail_pos = (size_t)(lf - instance->buf_tail->buf);
          char *buf = instance->buf_head->buf;
          size_t len = instance->buf_head->bytes;
          if (multi) {
            for (Read_Buffer *b = instance->buf_head->next; b; b = b->next) {
              assert(!memchr(b->buf, '\0', b->bytes));
              len += b->bytes;
            }
            char *contiguous_buf = arena_bump_T(&iocp_thread_arena, char, (uint32_t)len);
            size_t offset = 0;
            for (Read_Buffer *b = instance->buf_head; b != instance->buf_tail; b = b->next) {
              assert(b);
              memcpy(contiguous_buf + offset, b->buf, b->bytes);
              offset += b->bytes;
              b->bytes = 0;
            }
            memcpy(contiguous_buf + offset, instance->buf_tail, instance->buf_tail->bytes);
            instance->buf_tail->bytes -= tail_pos;
            instance->buf_tail->bytes -= 1;
            tail_pos += offset;
            buf = contiguous_buf;
          }
          log_message(LOG_DEBUG, "Message (%p): %.*s", instance, tail_pos, buf);
          size_t buf_offset = 0;
          for (;;) {
            *lf = '\0';
            ++tail_pos;
            iocp_parse(instance, buf, buf_offset);
            if (tail_pos >= len) break;
            lf = memchr(buf + tail_pos, '\n', len - tail_pos);
            if (!lf) break;
            buf_offset = tail_pos;
            assert((lf - buf) >= 0);
            tail_pos = (size_t)(lf - buf);
          }
          size_t remainder = tail_pos < len ? len - tail_pos : 0;
          memcpy(instance->buf_head, buf + tail_pos, remainder);
          instance->buf_head->bytes = remainder;
          instance->buf_tail = instance->buf_head;
          if (multi) arena_free_pos(&iocp_thread_arena, (uint8_t *)buf, (uint32_t)len);
        } else {
          if (instance->buf_tail->next) instance->buf_tail->next->bytes = 0;
          else instance->buf_tail->next = arena_bump_T1(&iocp_thread_arena, Read_Buffer);
          instance->buf_tail = instance->buf_tail->next;
        }
      }
      overlap_read(instance);
    }
  }
  return 0;
}

#define CIN_NUL 0x00
#define CIN_BACK 0x08
#define CIN_ENTER 0x0D
#define CIN_CONTROL_BACK 0x7F
#define CIN_ESCAPE 0x1B
#define CIN_VK_0 0x30
#define CIN_VK_9 0x39
#define CIN_VK_A 0x41
#define CIN_VK_Z 0x5A

// https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
#define ESC "\x1b"
#define CSI "\x1b["

static inline bool bounded_console(HANDLE console) {
  assert(console);
  SHORT prev_bot = 0;
  SHORT next_bot = 0;
  CONSOLE_CURSOR_INFO cursor_info = {0};
  GetConsoleCursorInfo(console, &cursor_info);
  BOOL prev_vis = cursor_info.bVisible;
  cursor_info.bVisible = false;
  SetConsoleCursorInfo(console, &cursor_info);
  CONSOLE_SCREEN_BUFFER_INFO info = {0};
  GetConsoleScreenBufferInfo(console, &info);
  prev_bot = info.srWindow.Bottom;
  COORD prev_pos = info.dwCursorPosition;
  COORD next_pos = {.X = 0, .Y = prev_bot + 1};
  SetConsoleCursorPosition(console, next_pos);
  GetConsoleScreenBufferInfo(console, &info);
  SetConsoleCursorPosition(console, prev_pos);
  cursor_info.bVisible = prev_vis;
  SetConsoleCursorInfo(console, &cursor_info);
  next_bot = info.srWindow.Bottom;
  return prev_bot == next_bot;
}

#define viewport_warning L"Large inputs can cause minor scrollback issues in your console. " \
                         "You can use vanilla cmd.exe (Command Prompt), "                    \
                         "which works correctly." WCRLF

static inline bool init_repl(void) {
  repl.window = GetForegroundWindow();
  if (!SetConsoleCP(CP_UTF8)) goto code_page;
  if (!SetConsoleOutputCP(CP_UTF8)) goto code_page;
  if ((repl.in = GetStdHandle(STD_INPUT_HANDLE)) == INVALID_HANDLE_VALUE) goto handle_in;
  if (!GetConsoleMode(repl.in, &repl.in_mode)) goto handle_in;
  if (!SetConsoleMode(repl.in, repl.in_mode | ENABLE_PROCESSED_INPUT | ENABLE_WINDOW_INPUT)) goto handle_in;
  if ((repl.out = GetStdHandle(STD_OUTPUT_HANDLE)) == INVALID_HANDLE_VALUE) goto handle_out;
  if ((repl.viewport_bound = bounded_console(repl.out))) wswrite(viewport_warning);
  if (!arena_chunk_init(&console_arena, CIN_ARENA_CAP)) goto memory;
  repl.msg = create_console_message();
  repl.msg_index = 0;
  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  if (!GetConsoleScreenBufferInfo_safe(repl.out, &buffer_info)) goto handle_out;
  repl.dwSize_X = (DWORD)buffer_info.dwSize.X;
  repl.home = (COORD){.X = PREFIX, .Y = buffer_info.dwCursorPosition.Y};
  repl._filled = 0;
  if (!GetConsoleCursorInfo(repl.out, &repl.cursor_info)) goto handle_out;
  if (!WriteConsoleW(repl.out, PREFIX_STR, PREFIX_STRLEN, NULL, NULL)) goto handle_out;
  array_init(&console_arena, &wwrite_buf, CIN_ARRAY_CAP);
  array_init(&console_arena, &write_buf, CIN_ARRAY_CAP);
  array_init(&console_arena, &preview, CIN_ARRAY_CAP);
  array_init(&console_arena, &utf16_buf_raw, CIN_MAX_PATH);
  array_init(&console_arena, &utf16_buf_norm, CIN_MAX_PATH);
  array_init(&console_arena, &utf8_buf, CIN_MAX_PATH_BYTES);
  return true;
code_page:
  wswrite(L"Failed to modify console code page" WCRLF);
  return false;
handle_in:
  wswrite(L"Failed to setup console input handle" WCRLF);
  return false;
handle_out:
  wswrite(L"Failed to setup console output handle" WCRLF);
memory:
  wswrite(L"Failed to allocate memory for repl/console" WCRLF);
  return false;
}

static inline bool resize_console(Console_Timer_Ctx *ctx) {
  (void)ctx;
  static array_struct(CHAR_INFO) console_buffer = {0};
  // NOTE: Windows cursor / display is not fully predictable. As such,
  // we search for a unique token that marks the start of the REPL.
  // There are probably scenarios where the token (printed by us) is
  // no longer visible; if this is encountered, probably just fully
  // redraw the console.
  EnterCriticalSection(&log_lock);
  hide_cursor();
  CONSOLE_SCREEN_BUFFER_INFO buffer_info;
  if (!GetConsoleScreenBufferInfo_safe(repl.out, &buffer_info)) {
    log_last_error("Failed to read console output region");
    goto cleanup;
  }
  assert(buffer_info.dwCursorPosition.Y < buffer_info.dwSize.Y - 1);
  DWORD buf_dwSize_X = (DWORD)buffer_info.dwSize.X;
  if (buf_dwSize_X == repl.dwSize_X) goto cleanup;
  bool bottom_up = buf_dwSize_X > repl.dwSize_X;
  COORD upper_cursor = buffer_info.dwCursorPosition;
  DWORD upper_bound = cursor_to_index(buffer_info.dwCursorPosition, buf_dwSize_X);
  COORD lower_cursor = {.X = 0, .Y = repl.home.Y};
  DWORD lower_bound = cursor_to_index(lower_cursor, buf_dwSize_X);
  assert(upper_bound > 0);
  if (bottom_up && lower_bound >= upper_bound) {
    lower_bound = upper_bound / 2;
    lower_cursor = index_to_cursor(lower_bound, buf_dwSize_X);
  }
  SHORT rows = upper_cursor.Y - lower_cursor.Y + 1;
  assert(rows > 0);
  assert(rows <= SHRT_MAX);
  SHORT cols = (SHORT)buf_dwSize_X;
  COORD buffer_size = {.X = cols, .Y = rows};
  DWORD buffer_count = (DWORD)cols * (DWORD)rows;
  array_resize(&console_arena, &console_buffer, buffer_count);
  COORD region_start = {.X = 0, .Y = 0};
  SMALL_RECT region = {
      .Left = 0,
      .Top = lower_cursor.Y,
      .Right = cols - 1,
      .Bottom = upper_cursor.Y};
  if (!ReadConsoleOutputW(repl.out, console_buffer.items, buffer_size, region_start, &region)) {
    log_last_error("Failed to read console output region");
    goto cleanup;
  }
  bool match = false;
  if (bottom_up) {
    for (;;) {
      for (SHORT i = 0; i < rows; ++i) {
        SHORT row = rows - 1 - i;
        assert(row >= 0);
        DWORD head = (DWORD)row * buf_dwSize_X;
        if (console_buffer.items[head].Char.UnicodeChar == PREFIX_TOKEN) {
          repl.home.Y = lower_cursor.Y + row;
          match = true;
          goto outer;
        }
      }
      if (lower_bound == 0) goto outer;
      upper_bound = lower_bound;
      upper_cursor = lower_cursor;
      lower_bound /= 2;
      lower_cursor = index_to_cursor(lower_bound, buf_dwSize_X);
      rows = upper_cursor.Y - lower_cursor.Y + 1;
      buffer_size.Y = rows;
      buffer_count = (DWORD)cols * (DWORD)rows;
      array_resize(&console_arena, &console_buffer, buffer_count);
      region.Left = 0;
      region.Top = lower_cursor.Y;
      region.Right = cols - 1;
      region.Bottom = upper_cursor.Y;
      if (!ReadConsoleOutputW(repl.out, console_buffer.items, buffer_size, region_start, &region)) {
        log_last_error("Failed to read console output region");
        goto cleanup;
      }
    }
  outer:;
  } else {
    for (DWORD i = 0; i < (DWORD)rows; ++i) {
      if (console_buffer.items[i * buf_dwSize_X].Char.UnicodeChar == PREFIX_TOKEN) {
        repl.home.Y = lower_cursor.Y + (SHORT)i;
        match = true;
        break;
      }
    }
  }
  assert(match && "Failed to find prefix token in console output. viewport_bound?");
  SHORT msg_shift = (SHORT)((repl.msg->count + PREFIX) / buf_dwSize_X);
  preview.pos.Y = repl.home.Y + msg_shift + 1;
  assert(preview.pos.X == 0);
  if (preview.len > buf_dwSize_X) {
    preview.pos.X = 0;
    ++preview.pos.Y;
    DWORD leftover = preview.len - buf_dwSize_X;
    FillConsoleOutputCharacterW(repl.out, CIN_SPACE, leftover, preview.pos, &repl._filled);
    --preview.pos.Y;
  }
  repl.dwSize_X = buf_dwSize_X;
  log_preview();
cleanup:
  show_cursor();
  LeaveCriticalSection(&log_lock);
  return false;
}

typedef enum {
  CIN_TIMER_RESIZE,
  _CIN_TIMER_END
} Console_Timer_Type;

static Console_Timer_Ctx *console_timers[_CIN_TIMER_END];
static cache_struct(Console_Timer_Ctx) timer_cache = {0};

static inline void reset_console_timer(Console_Timer_Ctx *ctx) {
  LARGE_INTEGER t;
  FILETIME ft;
  t.QuadPart = ctx->millis * -10000LL;
  ft.dwHighDateTime = (DWORD)t.HighPart;
  ft.dwLowDateTime = (DWORD)t.LowPart;
  SetThreadpoolTimer(ctx->timer, &ft, 0, 0);
}

static VOID CALLBACK console_timer_callback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_TIMER Timer) {
  (void)Instance;
  (void)Timer;
  Console_Timer_Ctx *ctx = (Console_Timer_Ctx *)Context;
  bool restart = ctx->f(ctx);
  if (restart) reset_console_timer(ctx);
}

static inline Console_Timer_Ctx *register_console_timer(bool (*f)(Console_Timer_Ctx *ctx), LONGLONG millis) {
  Console_Timer_Ctx *ctx = NULL;
  cache_get_zero(&console_arena, &timer_cache, ctx);
  assert(ctx);
  ctx->millis = millis;
  ctx->f = f;
  ctx->timer = CreateThreadpoolTimer(console_timer_callback, ctx, NULL);
  if (ctx->timer == NULL) {
    log_last_error("Failed to register console timer");
    return false;
  }
  return ctx;
}

static inline bool init_timers(void) {
  cache_init_core(&console_arena, &timer_cache, 1, true);
  console_timers[CIN_TIMER_RESIZE] = register_console_timer(resize_console, 100LL);
  if (!console_timers[CIN_TIMER_RESIZE]) return false;
  return true;
}

#define COMMAND_NUMBERS_CAP 8
#define COMMAND_ERROR_WMESSAGE L"ERROR: "

typedef void (*cmd_validator)(void);
typedef void (*cmd_executor)(void);

array_define(Command_Numbers, size_t);
array_define(Command_Help, wchar_t);
array_define(Command_Targets, wchar_t);

static struct CommandContext {
  Patricia_Node *trie;
  Cin_Layout *layout;
  Cin_Layout *queued_layout;
  Tag_Items *tag;
  cmd_executor executor;
  Command_Numbers numbers;
  wchar_t *unicode;
  Command_Targets targets;
  Command_Help help;
  Cin_Macro *macro;
} cmd_ctx = {0};

static inline void set_preview(bool success, const wchar_t *format, ...) {
  preview.count = 0;
  if (!success) {
    array_wsextend(&console_arena, &preview, COMMAND_ERROR_WMESSAGE);
  }
  size_t start = preview.count;
  va_list args;
  va_list args_dup;
  va_start(args, format);
  va_copy(args_dup, args);
  int32_t len_i32 = _vscwprintf(format, args);
  assert(len_i32 >= 0);
  uint32_t len = (uint32_t)len_i32;
  va_end(args);
  array_grow(&console_arena, &preview, len + 1);
  _vsnwprintf_s(preview.items + start, preview.capacity, len, format, args_dup);
  va_end(args_dup);
}

#define CIN_SCREEN_SEPARATOR L", "
#define CIN_SCREEN_SEPARATOR_LEN (sizeof(CIN_SCREEN_SEPARATOR) / sizeof(*CIN_SCREEN_SEPARATOR) - 1)

static inline bool validate_screens(void) {
  size_t n_count = cmd_ctx.numbers.count;
  size_t screen_count = cmd_ctx.layout->count;
  if (n_count > screen_count) {
    set_preview(false, L"layout only has %zu screens (%zu provided)", screen_count, n_count);
    return false;
  }
  for (size_t i = 0; i < n_count; ++i) {
    size_t screen_index = cmd_ctx.numbers.items[i] - 1;
    if (screen_index >= screen_count) {
      set_preview(false, L"screen %zu not found, layout only has %zu screens",
                  screen_index + 1, screen_count);
      return false;
    }
  }
  cmd_ctx.targets.count = 0;
  if (!n_count) {
    array_wsextend(&console_arena, &cmd_ctx.targets, L"(all screens)\0");
    for (size_t i = 0; i < cmd_ctx.layout->count; ++i) {
      array_push(&console_arena, &cmd_ctx.numbers, i + 1);
    }
  } else {
    if (n_count == 1) {
      array_wsextend(&console_arena, &cmd_ctx.targets, L"(screen ");
    } else {
      array_wsextend(&console_arena, &cmd_ctx.targets, L"(screens ");
    }
    const wchar_t *v_str = L"%zu" CIN_SCREEN_SEPARATOR;
    for (size_t i = 0; i < n_count; ++i) {
      size_t number = cmd_ctx.numbers.items[i];
      int32_t len_i32 = _scwprintf(v_str, number);
      assert(len_i32);
      uint32_t len = (uint32_t)len_i32 + 1;
      array_reserve(&console_arena, &cmd_ctx.targets, len);
      swprintf(cmd_ctx.targets.items + cmd_ctx.targets.count, len, v_str, number);
      cmd_ctx.targets.count += len - 1;
    }
    cmd_ctx.targets.count -= CIN_SCREEN_SEPARATOR_LEN;
    array_push(&console_arena, &cmd_ctx.targets, L')');
    cmd_ctx.targets.items[cmd_ctx.targets.count] = L'\0';
  }
  return true;
}

static wchar_t exe_path_mpv[CIN_MAX_PATH] = {0};
static wchar_t exe_path_ytdlp[CIN_MAX_PATH] = {0};
static wchar_t exe_path_chatterino[CIN_MAX_PATH] = {0};

static bool find_exe(const wchar_t *dir, const wchar_t *exe, wchar_t *buf) {
  const wchar_t extension[] = L".exe";
  if (SearchPathW(NULL, exe, extension, CIN_MAX_PATH, buf, NULL)) return true;
  const wchar_t *paths[] = {
      L"C:\\Program Files\\",
      L"C:\\Program Files (x86)\\",
      L"%LOCALAPPDATA%\\Programs\\",
      NULL};
  size_t dir_len = wcslen(dir);
  size_t exe_len = wcslen(exe);
  wchar_t exe_expanded[CIN_MAX_PATH] = {0};
  for (size_t i = 0; paths[i]; ++i) {
    size_t buf_offset = 0;
    DWORD path_len = ExpandEnvironmentStringsW(paths[i], exe_expanded, CIN_MAX_PATH);
    assert(path_len > 1);
    if (path_len <= 1) continue;
    --path_len;
    wmemcpy(buf + buf_offset, exe_expanded, path_len);
    buf_offset += path_len;
    wmemcpy(buf + buf_offset, dir, dir_len);
    buf_offset += dir_len;
    buf[buf_offset++] = L'\\';
    wmemcpy(buf + buf_offset, exe, exe_len);
    buf_offset += exe_len;
    wmemcpy(buf + buf_offset, extension, cin_strlen(extension));
    buf_offset += cin_strlen(extension);
    buf[buf_offset] = L'\0';
    DWORD attrs = GetFileAttributesW(buf);
    if (attrs != INVALID_FILE_ATTRIBUTES) return true;
  }
  log_wmessage(LOG_ERROR, L"Failed to find executable '%s'."
                          L"Please install it in a standard directory or add it to your environment variables.",
               exe);
  wmemset(buf, L'\0', CIN_MAX_PATH);
  return false;
}

static bool init_executables(void) {
  if (!find_exe(L"mpv", L"mpv", exe_path_mpv)) {
    printf(CRLF "mpv not found" CRLF);
    return false;
  }
  if (!find_exe(L"mpv", L"yt-dlp", exe_path_ytdlp)) {
    printf(CRLF "yt-dlp not found" CRLF);
    return false;
  }
  if (!find_exe(L"Chatterino", L"chatterino", exe_path_chatterino)) {
    printf(CRLF "chatterino not found" CRLF);
  }
  // NOTE: See for ytdl: https://mpv.io/manual/stable/#options-ytdl-path
  return true;
}

struct Chat {
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  RECT rect;
  HWND window;
} chat = {0};

static inline void chat_reposition(Cin_Layout *layout) {
  RECT chat_rect = layout->chat_rect;
  int32_t x = (int32_t)chat_rect.left;
  int32_t y = (int32_t)chat_rect.top;
  int32_t cx = (int32_t)chat_rect.right;
  int32_t cy = (int32_t)chat_rect.bottom;
  bool should_show = chat_rect.bottom != LONG_MIN;
  bool is_showing = IsWindow(chat.window);
  if (should_show) {
    if (is_showing) {
      SetWindowPos(chat.window, HWND_TOPMOST, x, y, cx, cy, SWP_SHOWWINDOW);
    } else {
      STARTUPINFOW *si = &chat.si;
      PROCESS_INFORMATION *pi = &chat.pi;
      si->dwFlags = STARTF_USEPOSITION | STARTF_USESIZE | STARTF_USESHOWWINDOW;
      si->wShowWindow = SW_NORMAL;
      si->dwX = (DWORD)x;
      si->dwXSize = (DWORD)cx;
      si->dwY = (DWORD)y;
      si->dwYSize = (DWORD)cy;
      si->cb = sizeof(*si);
      if (!CreateProcessW(exe_path_chatterino, L"chatterino", NULL, NULL, FALSE, 0, NULL, NULL, si, pi)) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
          log_last_error("Failed to find chatterino executable");
        } else {
          log_last_error("Failed to start chatterino executable even though it was found");
        }
      }
      // since STARTUPINFOW is ignored, manually reposition
      static const size_t CHAT_REPOSITION_TRIES = 50;
      static const DWORD CHAT_REPOSITION_DELAY = 40;
      for (size_t i = 0; i < CHAT_REPOSITION_TRIES; ++i) {
        chat.window = find_window_by_pid(pi->dwProcessId);
        if (IsWindowVisible(chat.window)) {
          SetWindowPos(chat.window, HWND_TOPMOST, x, y, cx, cy, SWP_SHOWWINDOW);
          break;
        }
        Sleep(CHAT_REPOSITION_DELAY);
      }
    }
  } else if (is_showing) {
    PostMessageW(chat.window, WM_CLOSE, 0, 0);
  }
}

#define CIN_MPVCALL_START L"mpv --idle --config-dir=./ --input-ipc-server="
#define CIN_MPVCALL_START_LEN cin_strlen(CIN_MPVCALL_START)
#define CIN_MPVCALL_PIPE L"\\\\.\\pipe\\cinema_mpv_"
#define CIN_MPVCALL_PIPE_LEN cin_strlen(CIN_MPVCALL_PIPE)
#define CIN_MPVCALL (CIN_MPVCALL_START CIN_MPVCALL_PIPE)
#define CIN_MPVCALL_LEN cin_strlen(CIN_MPVCALL)
#define CIN_MPVCALL_DIGITS 19
#define CIN_MPVCALL_GEOMETRY_LEN block_bytes(2)
#define CIN_MPVCALL_BUF align_to_block(CIN_MPVCALL_LEN + CIN_MPVCALL_DIGITS + CIN_MPVCALL_GEOMETRY_LEN)

static void mpv_spawn(Instance *instance, size_t index) {
  static wchar_t mpv_command[CIN_MPVCALL_BUF] = {CIN_MPVCALL};
  bool extra = index == SIZE_MAX;
  if (extra) index = cmd_ctx.layout->count;
  instance->ovl_ctx.type = MPV_READ;
  size_t right = CIN_MPVCALL_LEN + CIN_MPVCALL_DIGITS;
  size_t left = right;
  size_t j = index;
  do {
    mpv_command[left--] = L'0' + (j % 10);
    j /= 10;
  } while (j);
  size_t digits = right - left++;
  for (; j < digits; ++j) mpv_command[CIN_MPVCALL_LEN + j] = mpv_command[left + j];
  Cin_Screen screen = cmd_ctx.layout->items[extra ? 0 : index];
  if (extra) array_push(&console_arena, cmd_ctx.layout, screen);
  // screen.len actually includes null-terminator
  char *screen_utf8 = (char *)screen_strings.items + screen.offset;
  int32_t len = utf8_to_utf16_nraw(screen_utf8, (int32_t)screen.len);
  if (len > (int32_t)CIN_MPVCALL_GEOMETRY_LEN) {
    char *layout_name = (char *)layout_strings.items + cmd_ctx.layout->name_offset;
    printf("Cinema crashed because the config value of screen %zu in layout '%s' is "
           "too large (%d > %u chars): %.*s (first %u shown)",
           index + 1, layout_name, len, CIN_MPVCALL_GEOMETRY_LEN, CIN_MPVCALL_GEOMETRY_LEN,
           screen_utf8, CIN_MPVCALL_GEOMETRY_LEN);
    exit(1);
  }
  swprintf(mpv_command + CIN_MPVCALL_LEN + digits, CIN_MPVCALL_GEOMETRY_LEN, L" --geometry=%.*s",
           len, utf16_buf_raw.items);
  log_wmessage(LOG_DEBUG, L"Spawning instance: %s", mpv_command);
  STARTUPINFOW si = {0};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi = {0};
  if (!CreateProcessW(exe_path_mpv, mpv_command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
      log_last_error("Failed to find mpv executable");
    } else {
      log_last_error("Failed to start mpv executable even though it was found");
    }
    assert(false);
  }
  instance->si = si;
  instance->pi = pi;
  mpv_command[CIN_MPVCALL_LEN + digits] = L'\0';
  bool ok_pipe = create_pipe(instance, mpv_command + CIN_MPVCALL_START_LEN);
  assert(ok_pipe);
  bool ok_iocp = CreateIoCompletionPort(instance->pipe, cin_io.iocp, (ULONG_PTR)instance, 0) != NULL;
  assert(ok_iocp);
  instance->buf_head = arena_bump_T1(&io_arena, Read_Buffer);
  instance->buf_tail = instance->buf_head;
  bool ok_read = overlap_read(instance);
  assert(ok_read);
  assert(instance->playlist);
  playlist_play(instance);
  overlap_write(instance, MPV_WINDOW_ID, "get_property", "window-id", NULL);
  ++mpv_demand;
}

static inline bool init_mpv(void) {
  arena_chunk_init(&io_arena, CIN_IO_ARENA_CAP);
  arena_chunk_init(&iocp_thread_arena, CIN_IO_ARENA_CAP);
  cache_init_core(&io_arena, &cin_io.writes, 1, true);
  cache_init_core(&io_arena, &cin_io.instances, 1, false);
  cache_init_core(&docs_arena, &media.playlists, 1, true);
  Playlist *default_playlist = &media.default_playlist;
  array_to_pow1(&docs_arena, default_playlist);
  playlist_setup_shuffle(default_playlist);
  Instance *head_instance = cin_io.instances.head;
  playlist_set_default(head_instance);
  cin_io.iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
  if (!cin_io.iocp) {
    log_last_error("Failed to create iocp");
    return false;
  }
  if (!CreateThread(NULL, 0, iocp_listener, (LPVOID)cin_io.iocp, 0, NULL)) {
    log_last_error("Failed to create iocp listener");
    return false;
  }
  return true;
}

static inline bool timer_autoplay(Console_Timer_Ctx *ctx) {
  bool targets = false;
  cache_foreach(&cin_io.instances, Instance, i, o) {
    if (o->pipe && o->timer == ctx) {
      targets = true;
      playlist_play(o);
    }
  }
  if (!targets) cache_put(&timer_cache, ctx);
  return true;
}

#define mpv_target_foreach(i, instance)                         \
  for (size_t i = 0, _j = 0, _s = cmd_ctx.numbers.items[0] - 1; \
       i < cmd_ctx.numbers.count;                               \
       _j = 0, _s = cmd_ctx.numbers.items[++i] - 1)             \
    for (Instance *instance = cin_io.instances.head;            \
         _j <= _s && instance;                                  \
         instance = instance->next, ++_j)                       \
      if (_j == _s && instance->pipe)

static void cmd_help_executor(void) {
  wwrite_safe(cmd_ctx.help.items, (DWORD)cmd_ctx.help.count);
}

static void cmd_help_validator(void) {
  set_preview(true, L"help (show a list of all commands)");
  cmd_ctx.executor = cmd_help_executor;
}

static void cmd_layout_executor(void) {
  Cin_Layout *layout = cmd_ctx.queued_layout;
  cmd_ctx.layout = layout;
  uint32_t next_count = layout->count;
  uint32_t screen = 0;
  mpv_lock();
  chat_reposition(layout);
  cache_foreach(&cin_io.instances, Instance, i, old) {
    if (screen >= next_count) {
      if (old->pipe) overlap_write(old, MPV_QUIT, "quit", NULL, NULL);
    } else if (old->pipe) {
      log_message(LOG_INFO, "i=%u, screen=%zu", i);
      assert(IsWindow(old->window));
      const char *geometry = (char *)screen_strings.items + layout->items[screen].offset;
      overlap_write(old, MPV_SET_GEOMETRY, "set_property", "geometry", geometry);
      if (old->full_screen) {
        old->full_screen = false;
        overlap_write(old, MPV_WRITE, "set_property", "fullscreen", "no");
      }
    } else {
      mpv_spawn(old, screen);
    }
    ++screen;
  }
  for (Instance *next = NULL; screen < next_count; ++screen) {
    cache_get(&io_arena, &cin_io.instances, next);
    playlist_set_default(next);
    mpv_spawn(next, screen);
  }
  if (!mpv_demand) mpv_unlock();
}

static void cmd_layout_validator(void) {
  radix_v layout = NULL;
  const uint8_t *layout_name = NULL;
  if (cmd_ctx.unicode) {
    int32_t len = utf16_to_utf8(cmd_ctx.unicode);
    layout = radix_query(layout_tree, utf8_buf.items, (size_t)len - 1, &layout_name);
    if (!layout) {
      set_preview(false, L"layout does not exist: '%ls'", cmd_ctx.unicode);
      return;
    }
    utf8_to_utf16_raw((char *)layout_name);
    assert(layout);
    assert(layout_name);
    set_preview(true, L"change layout to '%s'", utf16_buf_raw.items);
  } else {
    Cin_Layout *curr = cmd_ctx.layout;
    char *curr_name = (char *)layout_strings.items + curr->name_offset;
    utf8_to_utf16_nraw(curr_name, (int32_t)curr->name_len);
    set_preview(true, L"reset layout '%s'", utf16_buf_raw.items);
    layout = curr;
  }
  cmd_ctx.queued_layout = (Cin_Layout *)layout;
  cmd_ctx.executor = cmd_layout_executor;
}

static void cmd_reroll_executor(void) {
  size_t count = 0;
  mpv_target_foreach(i, instance) {
    playlist_play(instance);
    ++count;
  }
  if (count == 0) {
    cmd_ctx.queued_layout = cmd_ctx.layout;
    cmd_layout_executor();
  }
}

static void cmd_reroll_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, L"reroll %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_reroll_executor;
}

static cmd_validator parse_command(const wchar_t *command) {
  // Grammar rules:
  // 1. First character must be either empty or in L'a'..L'z' (letter) or in L'1'..L'9' (digit)
  // 2. Empty (whitespace*\0) is a command
  // 3. Letter must precede one of: 'letter', 'space', '\0';
  // 3a. 'letter' concatenates a string character
  // 3b. 'space' finishes the string to setup (possible) command 'letter+'
  // 3c. '\0' is (possibly) a command comprised of 'letter+'
  // 4. Digit must precede one of: 'digit', '\0', 'space', 'letter'.
  // 4a. 'digit' concatenates a decimal number
  // 4b. '\0' is a command: consumes the number (array)
  // 4c. 'space' pushes decimal number onto the numbers array
  // 4d. 'letter' finishes the number array for command 'letter+' consumption
  // 5. Command 'letter+' with 'space' (3b) may precede 'unicode*'
  // 5a. 'unicode*' string is finished with '\0'
  cmd_ctx.executor = NULL;
  cmd_ctx.numbers.count = 0;
  cmd_ctx.unicode = NULL;
  const wchar_t *p = command;
  while (iswspace(*p)) ++p;
  size_t number = 0;
  for (; *p; ++p) {
    if (cin_wisnum_1based(*p)) {
      // 4a. build decimal number
      number *= 10;
      number += *p - L'0';
    } else if (*p == ' ') {
      if (number) {
        // 4c. push decimal number onto array
        array_push(&console_arena, &cmd_ctx.numbers, number);
      }
      number = 0;
    } else if (cin_wisloweralpha(*p)) {
      // if numbers array empty and number, push
      if (number) {
        array_push(&console_arena, &cmd_ctx.numbers, number);
        number = 0;
      }
      break;
    } else {
      intptr_t pos = p - command;
      assert(pos >= 0);
      set_preview(false, L"unexpected character '%c' at position %zd,"
                         L" expected: alphanumeric, space, enter",
                  *p, pos + 1);
      return NULL;
    }
  }
  if (!*p) {
    // 2/4b. command
    if (number) {
      array_push(&console_arena, &cmd_ctx.numbers, number);
    }
    return cmd_reroll_validator;
  }
  const wchar_t *start = p;
  ++p;
  while (cin_wisloweralpha(*p)) ++p;
  // 3/3a. letter+, command begins at start, ends at p
  if (!*p) {
    // 3c. possible command
    cmd_validator validator = patricia_query(cmd_ctx.trie, start);
    if (!validator) {
      set_preview(false, L"'%s' is not a valid command", start);
    }
    return validator;
  }
  if (*p != L' ') {
    intptr_t pos = p - command;
    assert(pos >= 0);
    set_preview(false, L"unexpected character '%c' at position %zd,"
                       L" expected: letter, space, enter",
                *p, pos + 1);
    return NULL;
  }
  *(wchar_t *)p = L'\0';
  cmd_validator validator = patricia_query(cmd_ctx.trie, start);
  if (!validator) {
    set_preview(false, L"'%s' is not a valid command", start);
  }
  *(wchar_t *)p = L' ';
  ++p;
  // 5a. unicode starts at p ends at \0
  cmd_ctx.unicode = (wchar_t *)p;
  return validator;
}

static void update_preview(void) {
  array_reserve(&console_arena, repl.msg, 1);
  repl.msg->items[repl.msg->count] = L'\0';
  cmd_validator validator_fn = parse_command(repl.msg->items);
  if (validator_fn) {
    validator_fn();
  }
}

static void cmd_tag_executor(void) {
  if (cmd_ctx.tag->playlist) goto reroll;
  cache_get_zero(&docs_arena, &media.playlists, cmd_ctx.tag->playlist);
  Playlist *playlist = cmd_ctx.tag->playlist;
  playlist->from_tag = true;
  size_t directory_k = 0;
  size_t pattern_k = 0;
  size_t url_k = 0;
  Arena *arena1 = &console_arena;
  Arena *arena2 = &docs_arena;
  Arena *arena3 = &io_arena;
#if defined(CIN_OPENMP)
#pragma omp parallel
#pragma omp single
#endif
  {
    if (cmd_ctx.tag->directories) {
#if defined(CIN_OPENMP)
#pragma omp task priority(8)
#endif
      {
        Tag_Directories *directories = cmd_ctx.tag->directories;
        directory_k = deduplicate_i32(arena1, directories->items, directories->count);
        Robin_Hood_Table duplicates = {0};
        table_init(arena1, &duplicates, CIN_DIRECTORIES_CAP);
        uint8_t *strings = directory_strings.items;
        for (size_t i = 0; i < directory_k; ++i) {
          size_t node_index = (size_t)directories->items[i];
          assert(node_index < directory_nodes.count);
          Directory_Node *start = &directory_nodes.items[node_index];
          table_key_t *start_str = directory_strings.items + start->str_offset;
          size_t start_len = strlen((char *)start_str);
          Table_Key key = {.strings = strings, .pos = start->str_offset, .len = (table_key_len)start_len + 1};
          table_value dup = table_insert(arena1, &duplicates, &key, 0);
          if (dup >= 0) continue;
          log_message(LOG_TRACE, "Tag directory: %s (%zu)", start_str, start_len);
          array_extend(arena1, playlist, start->items, start->count);
          for (size_t j = ++node_index; j < directory_nodes.count; ++j) {
            Directory_Node *node = &directory_nodes.items[j];
            if (!node->count) continue;
            table_key_t *str = directory_strings.items + node->str_offset;
            if (strncmp((char *)str, (char *)start_str, start_len) != 0) break;
            size_t len = strlen((char *)str);
            key.pos = node->str_offset;
            key.len = (table_key_len)len + 1;
            dup = table_insert(arena1, &duplicates, &key, 0);
            if (dup >= 0) continue;
            log_message(LOG_TRACE, "Tag directory: %s", str);
            array_extend(arena1, playlist, node->items, node->count);
          }
        }
        table_free_items(arena1, &duplicates);
      }
    }
    if (cmd_ctx.tag->pattern_items) {
#if defined(CIN_OPENMP)
#pragma omp task priority(4)
#endif
      {
        Tag_Pattern_Items *patterns = cmd_ctx.tag->pattern_items;
        pattern_k = deduplicate_i32(arena2, patterns->items, patterns->count);
      }
    }
    if (cmd_ctx.tag->url_items) {
#if defined(CIN_OPENMP)
#pragma omp task priority(2)
#endif
      {
        Tag_Url_Items *urls = cmd_ctx.tag->url_items;
        url_k = deduplicate_i32(arena3, urls->items, urls->count);
      }
    }
#if defined(CIN_OPENMP)
#pragma omp taskwait
#endif
  }
  if (directory_k) {
    array_free(&console_arena, cmd_ctx.tag->directories);
    cmd_ctx.tag->directories = NULL;
  }
  if (pattern_k) {
    array_extend(&console_arena, playlist, cmd_ctx.tag->pattern_items->items, (uint32_t)pattern_k);
    array_free(&console_arena, cmd_ctx.tag->pattern_items);
    cmd_ctx.tag->pattern_items = NULL;
  }
  if (url_k) {
    array_extend(&console_arena, playlist, cmd_ctx.tag->url_items->items, (uint32_t)url_k);
    array_free(&console_arena, cmd_ctx.tag->url_items);
    cmd_ctx.tag->url_items = NULL;
  }
  array_to_pow1(&docs_arena, playlist);
  playlist_setup_shuffle(playlist);
reroll:
  mpv_target_foreach(i, instance) {
    playlist_set(instance, cmd_ctx.tag->playlist);
    playlist_play(instance);
  }
}

static void cmd_tag_validator(void) {
  if (!validate_screens()) return;
  radix_v tag = NULL;
  const uint8_t *tag_name = NULL;
  if (cmd_ctx.unicode) {
    int32_t len = utf16_to_utf8(cmd_ctx.unicode);
    tag = radix_query(tag_tree, utf8_buf.items, (size_t)len - 1, &tag_name);
    if (!tag) {
      set_preview(false, L"tag does not exist: '%ls'", cmd_ctx.unicode);
      return;
    }
  } else {
    tag = radix_query(tag_tree, (const uint8_t *)"", 0, &tag_name);
    if (!tag) {
      set_preview(false, L"configuration does not contain any tags");
      return;
    }
  }
  assert(tag);
  assert(tag_name);
  utf8_to_utf16_raw((char *)tag_name);
  set_preview(true, L"tag '%s' %s", utf16_buf_raw.items, cmd_ctx.targets.items);
  cmd_ctx.tag = (Tag_Items *)tag;
  cmd_ctx.executor = cmd_tag_executor;
}

static void cmd_search_executor(void) {
  Playlist *playlist = &media.default_playlist;
  int32_t len = 0;
  if (cmd_ctx.unicode && (len = (int32_t)wcslen(cmd_ctx.unicode))) {
    setup_file_path(cmd_ctx.unicode, &len);
    len = utf16_to_utf8(cmd_ctx.unicode);
    uint8_t *pattern = utf8_buf.items;
    table_key_len len_u32 = (table_key_len)len;
    log_message(LOG_DEBUG, "Search with pattern: '%s', len: %d", pattern, len);
    array_reserve(&docs_arena, &media.search_patterns, len_u32);
    table_key_t *strings = media.search_patterns.items;
    table_key_pos pos = media.search_patterns.count;
    memcpy(strings + pos, pattern, len_u32);
    Table_Key key = {.strings = strings, .pos = pos, .len = len_u32};
    cache_get_zero(&docs_arena, &media.playlists, playlist);
    table_value value = (table_value)playlist;
    table_value result = table_insert(&docs_arena, &media.search_table, &key, value);
    if (result >= 0) {
      cache_put(&media.playlists, playlist);
      playlist = (Playlist *)result;
      log_message(LOG_DEBUG, "Searched for cached pattern");
    } else {
      playlist->search_pos = pos;
      playlist->search_len = len_u32;
      playlist->from_tag = false;
      media.search_patterns.count += len_u32;
      document_listing(pattern, len - 1, playlist);
      playlist_setup_shuffle(playlist);
    }
    log_message(LOG_INFO, "Search playlist count=%d, cap=%d", playlist->count, playlist->capacity);
  }
  mpv_target_foreach(i, instance) {
    playlist_set(instance, playlist);
    playlist_play(instance);
  }
}

static void cmd_search_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, L"search '%s' %s", cmd_ctx.unicode ? cmd_ctx.unicode : L"", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_search_executor;
}

static void cmd_hide_executor(void) {
  if (!cmd_ctx.unicode) return;
  int32_t len = utf16_to_utf8(cmd_ctx.unicode);
  uint8_t *pattern = utf8_buf.items;
  if (len <= 1) return;
  uint32_t len_u32 = (uint32_t)len;
  array_reserve(&docs_arena, &media.search_patterns, len_u32);
  table_key_t *strings = media.search_patterns.items;
  table_key_pos pos = media.search_patterns.count;
  memcpy(strings + pos, pattern, len_u32);
  Table_Key key = {.strings = strings, .pos = pos, .len = len_u32};
  table_value value = table_find(&media.search_table, &key);
  Playlist *playlist = NULL;
  if (value >= 0) {
    playlist = (Playlist *)value;
  } else {
    Playlist tmp = {0};
    document_listing(pattern, len - 1, &tmp);
    playlist = &tmp;
  }
  assert(playlist);
  Hidden_Table *table = &media.hidden_table;
  uint32_t hash_n = 1;
  while (hash_n < (table->count + playlist->count) * 2) hash_n <<= 1;
  uint32_t start = table->capacity;
  array_ensure_capacity_core(&docs_arena, table, hash_n, true);
  uint32_t end = table->capacity;
  uint64_t mask = table->capacity - 1;
  if (start < end) {
    for (uint32_t i = start; i < end; ++i) table->items[i] = -1;
    for (uint32_t i = 0; i < start; ++i) {
      int32_t v = table->items[i];
      if (v >= 0) {
        table->items[i] = -1;
        uint64_t hash = (uint64_t)v * CIN_INTEGER_HASH;
        uint64_t index = hash & mask;
        while (table->items[index] >= 0) index = (index + 1) & mask;
        table->items[index] = v;
      }
    }
  }
  array_foreach(playlist, int32_t, i, doc) {
    uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
    uint64_t index = hash & mask;
    while (table->items[index] >= 0) {
      if (table->items[index] == doc) goto next;
      index = (index + 1) & mask;
    }
    table->items[index] = doc;
    ++table->count;
  next:;
  }
  if (value < 0) array_free_items(&docs_arena, playlist);
  Playlist prev_default = media.default_playlist;
  Playlist new_default = {0};
  array_ensure_capacity_core(&docs_arena, &new_default, prev_default.count, true);
  array_foreach(&prev_default, int32_t, i, doc) {
    uint64_t hash = (uint64_t)doc * CIN_INTEGER_HASH;
    uint64_t index = hash & mask;
    while (table->items[index] >= 0) {
      if (table->items[index] == doc) goto skip;
      index = (index + 1) & mask;
    }
    array_push(&docs_arena, &new_default, doc);
  skip:;
  }
  array_to_pow1(&docs_arena, &new_default);
  media.default_playlist = new_default;
  playlist_setup_shuffle(&media.default_playlist);
  arena_free_pos(&docs_arena, (uint8_t *)prev_default.items, prev_default.bytes_capacity);
  cache_foreach(&cin_io.instances, Instance, i, o) {
    if (o->playlist && !o->playlist->from_tag) {
      playlist_set_default(o);
      if (o->pipe) playlist_play(o);
    }
  }
}

static void cmd_hide_validator(void) {
  if (cmd_ctx.unicode && *cmd_ctx.unicode) {
    set_preview(true, L"hide '%s'", cmd_ctx.unicode);
  } else {
    set_preview(true, L"hide '' (nothing)");
  }
  cmd_ctx.executor = cmd_hide_executor;
}

static void cmd_kill_executor(void) {
  PostMessageW(chat.window, WM_CLOSE, 0, 0);
  mpv_target_foreach(i, instance) {
    log_message(LOG_DEBUG, "Closing PID=%lu", instance->pi.dwProcessId);
    overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
  }
}

static void cmd_kill_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, L"kill  %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_kill_executor;
}

static void cmd_maximize_executor(void) {
  size_t target = cmd_ctx.numbers.count ? cmd_ctx.numbers.items[0] - 1 : 0;
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    if (instance->pipe) {
      if (i == target) {
        instance->full_screen = !instance->full_screen;
        overlap_write(instance, MPV_WRITE, "cycle", "fullscreen", NULL);
      } else {
        overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
      }
    }
  }
}

static void cmd_maximize_validator(void) {
  size_t n = cmd_ctx.numbers.count;
  if (n > 1) {
    set_preview(false, L"maximize supports 1 screen, not %zu", n);
    return;
  }
  size_t screen = 1;
  if (n) {
    size_t target = cmd_ctx.numbers.items[0];
    if (target > cmd_ctx.layout->count) {
      set_preview(false, L"cannot maximize screen %zu, layout only has %zu screens",
                  target, cmd_ctx.layout->count);
      return;
    }
    screen = target;
  }
  set_preview(true, L"maximize screen %zu", screen);
  cmd_ctx.executor = cmd_maximize_executor;
}

static void cmd_autoplay_executor(void) {
  wchar_t *p = cmd_ctx.unicode;
  LONGLONG seconds = -1;
  if (p && cin_wisnum(*p)) {
    seconds = *p - L'0';
    ++p;
    while (cin_wisnum(*p)) {
      seconds *= 10;
      seconds += *p - L'0';
      ++p;
    }
  }
  if (seconds > 0) {
    LONGLONG millis = seconds * 1000LL;
    Console_Timer_Ctx *timer = register_console_timer(timer_autoplay, millis);
    assert(timer);
    bool targets = false;
    mpv_target_foreach(i, instance) {
      targets = true;
      instance->timer = timer;
      if (instance->autoplay_mpv) overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
      instance->autoplay_mpv = false;
    }
    if (targets) reset_console_timer(timer);
    else cache_put(&timer_cache, timer);
  } else if (seconds == 0) {
    mpv_target_foreach(i, instance) {
      instance->timer = NULL;
      if (instance->autoplay_mpv) overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
      instance->autoplay_mpv = false;
    }
  } else {
    mpv_target_foreach(i, instance) {
      instance->timer = NULL;
      if (!instance->autoplay_mpv) {
        instance->autoplay_mpv = true;
        overlap_write(instance, MPV_WRITE, "set_property", "loop", "no");
      }
      playlist_insert(instance);
    }
  }
}

static void cmd_autoplay_validator(void) {
  if (!validate_screens()) return;
  LONGLONG seconds = -1;
  if (cmd_ctx.unicode) {
    wchar_t *p = cmd_ctx.unicode;
    if (cin_wisnum(*p)) {
      seconds = *p - L'0';
      ++p;
    }
    while (cin_wisnum(*p)) {
      seconds *= 10;
      seconds += *p - L'0';
      ++p;
    }
    if (*p) {
      ptrdiff_t pos = p - cmd_ctx.unicode;
      set_preview(false, L"unexpected character '%c' at position %lld in argument", *p, pos + 1);
      return;
    }
  }
  if (seconds < 0) set_preview(true, L"autoplay when media ends %s", cmd_ctx.targets.items);
  else if (seconds == 0) set_preview(true, L"turn off autoplay %s", cmd_ctx.targets.items);
  else set_preview(true, L"autoplay with '%lld' second delay %s", seconds, cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_autoplay_executor;
}

static void cmd_lock_executor(void) {
  mpv_target_foreach(i, instance) {
    instance->locked = !instance->locked;
    if (!instance->locked) playlist_play(instance);
    instance->timer = NULL;
    if (instance->autoplay_mpv) overlap_write(instance, MPV_WRITE, "set_property", "loop", "inf");
    instance->autoplay_mpv = false;
  }
}

static void cmd_lock_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, L"lock/unlock %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_lock_executor;
}

#define FSTR_RECT "%ldx%ld%+ld%+ld"
#define FSTR_NAME "name = %s" CRLF
#define FSTR_SCREEN "screen = %s" CRLF
#define FSTR_CHAT "chat = " FSTR_RECT CRLF
#define FSTR_RECT_ARGS(rect) \
  ((rect).right - (rect).left), ((rect).bottom - (rect).top), ((rect).left), ((rect).top)
#define FSTR_CHAT_ARGS FSTR_RECT_ARGS(chat.rect)

static void cmd_store_executor(void) {
  Cin_Layout *layout = cmd_ctx.queued_layout;
  char *name = NULL;
  bool try_overwrite = layout != NULL;
  if (try_overwrite) {
    layout->count = 0;
    name = (char *)layout_strings.items + layout->name_offset;
  } else {
    layout = arena_bump_T1(&console_arena, Cin_Layout);
    assert(cmd_ctx.unicode);
    name = (char *)utf8_buf.items;
    setup_layout(name, layout);
  }
  cmd_ctx.layout = layout;
  geometry_buf.count = 0;
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    if (instance->pipe && IsWindow(instance->window)) {
      GetWindowRect(instance->window, &instance->rect);
      int32_t bytes = snprintf(NULL, 0, FSTR_RECT, FSTR_RECT_ARGS(instance->rect)) + 1;
      assert(bytes > 1);
      uint32_t bytes_u32 = (uint32_t)bytes;
      uint32_t offset = geometry_buf.count;
      array_grow(&console_arena, &geometry_buf, bytes_u32);
      char *pos = geometry_buf.items + offset;
      snprintf(pos, bytes_u32, FSTR_RECT, FSTR_RECT_ARGS(instance->rect));
      setup_screen(pos, layout);
      assert(geometry_buf.items[geometry_buf.count - 1] == '\0');
      geometry_buf.items[geometry_buf.count - 1] = ',';
    }
  }
  if (geometry_buf.count > 0) geometry_buf.items[--geometry_buf.count] = '\0';
  FILE *file = NULL;
  int32_t err = 0;
  char *buf = NULL;
  uint32_t buf_bytes = 0;
  bool has_chat = IsWindow(chat.window);
  if (has_chat) {
    GetWindowRect(chat.window, &chat.rect);
    layout->chat_rect = chat.rect;
  }
  if (!try_overwrite) goto append;
  int32_t scope_line = layout->scope_line;
  uint32_t name_len = layout->name_len - 1;
  err = fopen_s(&file, CIN_CONF_FILENAME, "rb");
  if (err) {
    log_fopen_error(CIN_CONF_FILENAME, err);
  } else {
    fseek(file, 0, SEEK_END);
    assert(ftell(file) > 0);
    buf_bytes = (uint32_t)ftell(file);
    rewind(file);
    buf = arena_bump_T(&console_arena, char, buf_bytes + 1U);
    fread(buf, sizeof(char), buf_bytes, file);
    fclose(file);
    buf[buf_bytes] = '\0';
    const char *p = buf;
    const char *tail = buf + buf_bytes;
    int32_t bottom_line = 1;
    while (bottom_line < scope_line && (p = memchr(p, '\n', (size_t)(tail - p)))) {
      ++p;
      ++bottom_line;
    }
    if (strncmp(p, "[layout]", cin_strlen("[layout]")) != 0) goto append;
    p += cin_strlen("[layout]");
    const char *overwrite_start = p;
    const char *overwrite_end = overwrite_start;
    const char *last_name = NULL;
    int32_t line_breaks = 0;
    while ((p = memchr(p, '\n', (size_t)(tail - p)))) {
      ++line_breaks;
      overwrite_end = ++p;
      if (*p == '[') break;
      if (strncmp(p, "name", cin_strlen("name")) == 0) last_name = p;
    }
    if (!last_name) goto append;
    last_name += cin_strlen("name");
    while (*last_name == ' ') ++last_name;
    if (*last_name != '=') goto append;
    else ++last_name;
    while (*last_name == ' ') ++last_name;
    if (strncmp(last_name, name, name_len) != 0) goto append;
    size_t available_bytes = (size_t)(overwrite_end - overwrite_start);
    size_t needed_chat_bytes = 0;
    char *overwrite = (char *)overwrite_start;
    int32_t name_bytes = sprintf(overwrite, CRLF FSTR_NAME, name);
    overwrite += (size_t)name_bytes;
    available_bytes -= (size_t)name_bytes;
    if (has_chat) {
      int32_t bytes = snprintf(NULL, 0, FSTR_CHAT, FSTR_CHAT_ARGS);
      assert(bytes > 0);
      size_t bytes_size = (size_t)bytes;
      if (bytes_size > available_bytes) {
        needed_chat_bytes = bytes_size;
      } else {
        snprintf(overwrite, bytes_size + 1U, FSTR_CHAT, FSTR_CHAT_ARGS);
        overwrite += bytes_size;
        available_bytes -= bytes_size;
      }
    }
    int32_t screen_bytes = snprintf(NULL, 0, FSTR_SCREEN CRLF, geometry_buf.items);
    assert(screen_bytes > 0);
    size_t screen_bytes_size = (size_t)screen_bytes;
    if (needed_chat_bytes || screen_bytes_size > available_bytes) {
      size_t needed_bytes = needed_chat_bytes + screen_bytes_size;
      size_t growth_bytes = needed_bytes - available_bytes;
      size_t new_buf_bytes = buf_bytes + growth_bytes;
      size_t overwrite_pos = (size_t)(overwrite - buf);
      const char *prev_buf = buf;
      buf = arena_bump_T(&console_arena, char, (uint32_t)new_buf_bytes + 1U);
      memcpy(buf, prev_buf, overwrite_pos);
      size_t new_overwrite_end = overwrite_pos + screen_bytes_size;
      size_t leftover_bytes = (size_t)(tail - overwrite_end);
      memcpy(buf + new_overwrite_end, overwrite_end, leftover_bytes);
      arena_free_pos(&console_arena, (uint8_t *)prev_buf, buf_bytes);
      available_bytes += growth_bytes;
      overwrite = buf + overwrite_pos;
      overwrite_end = buf + new_overwrite_end;
      tail = buf + new_buf_bytes;
      buf_bytes = (uint32_t)new_buf_bytes;
    }
    if (needed_chat_bytes) {
      snprintf(overwrite, needed_chat_bytes + 1U, FSTR_CHAT, FSTR_CHAT_ARGS);
      overwrite += needed_chat_bytes;
      available_bytes -= needed_chat_bytes;
    }
    available_bytes -= screen_bytes_size;
    if (available_bytes) {
      snprintf(overwrite, screen_bytes_size + 1U, FSTR_SCREEN CRLF, geometry_buf.items);
      overwrite += screen_bytes_size;
      size_t end_bytes = (size_t)(tail - overwrite_end);
      memmove(overwrite, overwrite_end, end_bytes);
      tail -= available_bytes;
    } else {
      snprintf(overwrite, screen_bytes_size + 1U, FSTR_SCREEN CR, geometry_buf.items);
      overwrite += screen_bytes_size - 1U;
      assert(*overwrite == '\0');
      *overwrite++ = '\n';
    }
    size_t used_bytes = (size_t)(tail - buf);
    err = fopen_s(&file, CIN_CONF_FILENAME, "wb");
    if (err) {
      log_fopen_error(CIN_CONF_FILENAME, err);
    } else {
      fwrite(buf, 1, used_bytes, file);
      fclose(file);
    }
    arena_free_pos(&console_arena, (uint8_t *)buf, buf_bytes);
    int32_t written_lines = has_chat ? 5 : 4;
    int32_t line_shift = written_lines - line_breaks;
    if (line_shift) {
      Radix_Leaf *next = radix_leftmost(layout_tree->root);
      while (next) {
        Cin_Layout *next_layout = (Cin_Layout *)next->base.v;
        if (next_layout->scope_line > scope_line) {
          next_layout->scope_line += line_shift;
        }
        next = radix_next(layout_tree, next);
      }
    }
    return;
  }
append:
  if (buf) arena_free_pos(&console_arena, (uint8_t *)buf, buf_bytes + 1U);
  scope_line = 2;
  err = fopen_s(&file, CIN_CONF_FILENAME, "ab+");
  if (err) {
    log_fopen_error(CIN_CONF_FILENAME, err);
  } else {
    rewind(file);
    int32_t c;
    while ((c = fgetc(file)) != EOF)
      if (c == '\n') ++scope_line;
    layout->scope_line = scope_line;
    fprintf(file, CRLF "[layout]" CRLF);
    fprintf(file, FSTR_NAME, name);
    fprintf(file, FSTR_SCREEN, geometry_buf.items);
    if (has_chat) fprintf(file, FSTR_CHAT, FSTR_CHAT_ARGS);
    fclose(file);
  }
  return;
}

static void cmd_store_validator(void) {
  radix_v layout = NULL;
  const uint8_t *layout_name = NULL;
  (void)cmd_ctx.unicode;
  if (cmd_ctx.unicode) {
    int32_t len = utf16_to_utf8(cmd_ctx.unicode);
    layout = radix_query(layout_tree, utf8_buf.items, (size_t)len - 1, &layout_name);
    if (layout) {
      utf8_to_utf16_raw((char *)layout_name);
      assert(layout);
      assert(layout_name);
      set_preview(true, L"store layout '%s' (overwrite)", utf16_buf_raw.items);
    } else {
      set_preview(true, L"store new layout: '%s'", cmd_ctx.unicode);
    }
  } else {
    Cin_Layout *curr = cmd_ctx.layout;
    char *curr_name = (char *)layout_strings.items + curr->name_offset;
    utf8_to_utf16_nraw(curr_name, (int32_t)curr->name_len);
    set_preview(true, L"store layout '%s' (overwrite current)", utf16_buf_raw.items);
    layout = curr;
  }
  cmd_ctx.queued_layout = (Cin_Layout *)layout;
  cmd_ctx.executor = cmd_store_executor;
}

static void cmd_swap_executor(void) {
  size_t first = cmd_ctx.numbers.items[0] - 1;
  size_t second = cmd_ctx.numbers.items[1] - 1;
  log_message(LOG_DEBUG, "Swapping screen %zu with %zu", first, second);
  Cin_Screen *first_screen = NULL;
  Cin_Screen *second_screen = NULL;
  Instance *first_instance = NULL;
  Instance *second_instance = NULL;
  mpv_target_foreach(i, instance) {
    if (i == 0) {
      first_instance = instance;
      first_screen = &cmd_ctx.layout->items[first];
    } else {
      assert(i == 1);
      second_instance = instance;
      second_screen = &cmd_ctx.layout->items[second];
    }
  }
  if (first_screen && second_screen) {
    const char *first_geometry = (char *)screen_strings.items + first_screen->offset;
    const char *second_geometry = (char *)screen_strings.items + second_screen->offset;
    overlap_write(first_instance, MPV_SET_GEOMETRY, "set_property", "geometry", second_geometry);
    overlap_write(second_instance, MPV_SET_GEOMETRY, "set_property", "geometry", first_geometry);
    Cin_Screen tmp = *second_screen;
    *second_screen = *first_screen;
    *first_screen = tmp;
  }
}

static void cmd_swap_validator(void) {
  size_t n = cmd_ctx.numbers.count;
  size_t screen_count = cmd_ctx.layout->count;
  if (screen_count < 2) {
    set_preview(false, L"swap requires a layout with at least 2 screens");
    return;
  }
  switch (n) {
  case 2:
    size_t first = cmd_ctx.numbers.items[0];
    size_t second = cmd_ctx.numbers.items[1];
    if (first == second) {
      set_preview(false, L"swap needs 2 unique screens, not both %zu", first);
      return;
    }
    if (first > screen_count || second > screen_count) {
      set_preview(false, L"cannot swap screen %zu with %zu, layout only has %zu screens",
                  first, second, screen_count);
      return;
    }
    break;
  case 1:
    set_preview(false, L"swap misses another number: %zu ... swap", cmd_ctx.numbers.items[0]);
    return;
  case 0:
    if (cmd_ctx.layout->count != 2) {
      set_preview(false, L"swap requires 2 numbers or a layout with 2 screens");
      return;
    }
    array_push(&console_arena, &cmd_ctx.numbers, 1);
    array_push(&console_arena, &cmd_ctx.numbers, 2);
    break;
  default:
    set_preview(false, L"swap must have 2 or 0 numbers, not %zu", n);
    return;
  }
  cmd_ctx.executor = cmd_swap_executor;
  set_preview(true, L"swap screen %zu with %zu", cmd_ctx.numbers.items[0], cmd_ctx.numbers.items[1]);
}

static void cmd_clear_executor(void) {
  mpv_target_foreach(i, instance) {
    playlist_set_default(instance);
    playlist_play(instance);
  }
}

static void cmd_clear_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, L"clear %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_clear_executor;
}

static void cmd_macro_executor(void) {
  Cin_Macro *macro = cmd_ctx.macro;
  if (macro) {
    const wchar_t *p = macro->items;
    const wchar_t *tail = macro->items + macro->count - 1;
    do {
      cmd_ctx.executor = NULL;
      cmd_validator validator_fn = parse_command(p);
      if (validator_fn) {
        validator_fn();
        if (cmd_ctx.executor) {
          cmd_ctx.executor();
        } else {
          log_wmessage(LOG_ERROR, L"Failed to validate macro command '%s': %s", p, preview.items);
          return;
        }
      } else {
        log_wmessage(LOG_ERROR, L"Failed to parse macro command '%s': %s", p, preview.items);
        return;
      }
    } while ((p = wmemchr(p, L'\0', (size_t)(tail - p))) && *++p);
  }
}

static void cmd_macro_validator(void) {
  radix_v macro = NULL;
  const uint8_t *macro_name = NULL;
  if (cmd_ctx.unicode) {
    int32_t len = utf16_to_utf8(cmd_ctx.unicode);
    macro = radix_query(macro_tree, utf8_buf.items, (size_t)len - 1, &macro_name);
    if (!macro) {
      set_preview(false, L"macro does not exist: '%s'", cmd_ctx.unicode);
      return;
    }
    utf8_to_utf16_raw((char *)macro_name);
    assert(macro);
    assert(macro_name);
    set_preview(true, L"execute macro '%s'", utf16_buf_raw.items);
  } else {
    set_preview(true, L"execute macro '' (nothing)");
  }
  cmd_ctx.macro = (Cin_Macro *)macro;
  cmd_ctx.executor = cmd_macro_executor;
}

#define TWITCH_CHANNEL_MAX_CHARS 25
#define TWITCH_PREFIX "https://www.twitch.tv/"
#define TWITCH_BUF_SIZE (cin_strlen(TWITCH_PREFIX) + TWITCH_CHANNEL_MAX_CHARS + 1)

static void cmd_twitch_executor(void) {
  if (!cmd_ctx.unicode) return;
  static char twitch_buf[TWITCH_BUF_SIZE] = {TWITCH_PREFIX};
  int32_t len = utf16_to_utf8(cmd_ctx.unicode);
  assert(len >= 0);
  const char *channel = (const char *)utf8_buf.items;
  memcpy(twitch_buf + cin_strlen(TWITCH_PREFIX), channel, (size_t)len);
  mpv_target_foreach(i, instance) {
    overlap_write(instance, MPV_LOADFILE, "loadfile", twitch_buf, NULL);
  }
}

static void cmd_twitch_validator(void) {
  if (!validate_screens()) return;
  if (cmd_ctx.unicode && wcslen(cmd_ctx.unicode) > TWITCH_CHANNEL_MAX_CHARS) {
    set_preview(false, L"twitch channel name is too long (max is %d characters)", TWITCH_CHANNEL_MAX_CHARS);
    return;
  }
  set_preview(true, L"" TWITCH_PREFIX "%s %s", cmd_ctx.unicode ? cmd_ctx.unicode : L"", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_twitch_executor;
}

static void cmd_copy_executor(void) {
  clipboard.count = 0;
  clipboard.supply = 0;
  clipboard.demand = 0;
  mpv_target_foreach(i, instance) {
    ++clipboard.demand;
    overlap_write(instance, MPV_GET_PATH, "get_property", "path", NULL);
  }
  return;
}

static void cmd_copy_validator(void) {
  if (!validate_screens()) return;
  set_preview(true, L"copy to clipboard %s", cmd_ctx.targets.items);
  cmd_ctx.executor = cmd_copy_executor;
}

static void cmd_extra_executor(void) {
  bool reuse = false;
  mpv_lock();
  cache_foreach(&cin_io.instances, Instance, i, old) {
    if (!old->pipe) {
      // reuse if free instance available
      reuse = true;
      mpv_spawn(old, SIZE_MAX);
    }
  }
  if (!reuse) {
    Instance *extra = NULL;
    cache_get(&io_arena, &cin_io.instances, extra);
    playlist_set_default(extra);
    mpv_spawn(extra, SIZE_MAX);
  }
}

static void cmd_extra_validator(void) {
  set_preview(true, L"add extra screen to layout");
  cmd_ctx.executor = cmd_extra_executor;
}

static void cmd_chat_executor(void) {
  Cin_Layout *layout = cmd_ctx.layout;
  bool layout_chat = layout->chat_rect.bottom != LONG_MIN;
  if (!layout_chat) {
    LONG default_width = 400;
    LONG default_height = 600;
    LONG default_x = 0;
    LONG default_y = 0;
    layout->chat_rect.right = default_width;
    layout->chat_rect.bottom = default_height;
    layout->chat_rect.left = default_x;
    layout->chat_rect.top = default_y;
  }
  mpv_lock();
  chat_reposition(layout);
  mpv_unlock();
}

static void cmd_chat_validator(void) {
  bool is_showing = IsWindow(chat.window);
  set_preview(true, L"%s chat", is_showing ? L"reposition" : L"show");
  cmd_ctx.executor = cmd_chat_executor;
}

#define CIN_LIST_TAGS_PREFIX CR "Tags: "
#define CIN_LIST_TAGS_PREFIX_LEN cin_strlen(CIN_LIST_TAGS_PREFIX)

static void cmd_list_executor(void) {
  Radix_Leaf *next = radix_leftmost(tag_tree->root);
  array_struct(char) output = {0};
  array_set(&console_arena, &output, CIN_LIST_TAGS_PREFIX, CIN_LIST_TAGS_PREFIX_LEN);
  size_t start_count = output.count;
  while (next) {
    assert(next->len);
    const char *key = (char *)next->key;
    uint32_t len = (uint32_t)next->len - 1U;
    array_extend(&console_arena, &output, key, len);
    array_push(&console_arena, &output, ',');
    array_push(&console_arena, &output, ' ');
    next = radix_next(tag_tree, next);
  }
  if (output.count > start_count) {
    array_pop(&output);
    output.items[output.count - 1] = '\0';
  }
  int32_t len = utf8_to_utf16_nraw(output.items, (int32_t)output.count);
  assert(len);
  wwrite_safe(utf16_buf_raw.items, (DWORD)len);
  array_free_items(&console_arena, &output);
}

static void cmd_list_validator(void) {
  set_preview(true, L"list all tags");
  cmd_ctx.executor = cmd_list_executor;
}

static void cmd_quit_executor(void) {
  PostMessageW(chat.window, WM_CLOSE, 0, 0);
  cache_foreach(&cin_io.instances, Instance, i, instance) {
    log_message(LOG_DEBUG, "Closing PID=%lu", instance->pi.dwProcessId);
    overlap_write(instance, MPV_QUIT, "quit", NULL, NULL);
  }
  clear_preview(0);
  show_cursor();
  exit(1);
}

static void cmd_quit_validator(void) {
  set_preview(true, L"quit (also closes screens)");
  cmd_ctx.executor = cmd_quit_executor;
}

static inline void register_cmd(const wchar_t *name, const wchar_t *help, cmd_validator validator) {
  assert(wmemchr(help, PREFIX_TOKEN, wcslen(help)) == NULL);
  patricia_insert(cmd_ctx.trie, name, validator);
  const wchar_t *v_str = WCRLF L"  %-10s %s";
  int32_t len_i32 = _scwprintf(v_str, name, help);
  assert(len_i32);
  uint32_t len = (uint32_t)len_i32 + 1;
  array_reserve(&console_arena, &cmd_ctx.help, len);
  swprintf(cmd_ctx.help.items + cmd_ctx.help.count, len, v_str, name, help);
  cmd_ctx.help.count += len - 1;
}

static bool init_commands(void) {
  radix_v layout_v = radix_query(layout_tree, (const uint8_t *)"", 0, NULL);
  if (!layout_v) {
    log_message(LOG_ERROR, "No layouts found in config file");
    return false;
  }
  cmd_ctx.layout = (Cin_Layout *)layout_v;
  cmd_ctx.queued_layout = cmd_ctx.layout;
  cmd_ctx.trie = patricia_node(NULL, 0);
  array_init(&console_arena, &cmd_ctx.numbers, COMMAND_NUMBERS_CAP);
  array_wsextend(&console_arena, &cmd_ctx.help,
                 WCR L"Available commands:" WCRLF L"  "
                     L"Note: optional arguments before/after in brackets []" WCRLF);
  register_cmd(L"autoplay", L"Autoplay media [(1 2 ..) autoplay (seconds)]", cmd_autoplay_validator);
  register_cmd(L"chat", L"Show chat (see store command)", cmd_chat_validator);
  register_cmd(L"clear", L"Clear tag/term [(1 2 ..) clear]", cmd_clear_validator);
  register_cmd(L"copy", L"Copy url(s) to clipboard [(1 2 ..) copy]", cmd_copy_validator);
  register_cmd(L"extra", L"Adds an extra screen (see store command)", cmd_extra_validator);
  register_cmd(L"help", L"Show all commands", cmd_help_validator);
  register_cmd(L"hide", L"Hide media with term [hide term]", cmd_hide_validator);
  register_cmd(L"kill", L"Kill screen(s) and chat [(1 2 ..) kill]", cmd_kill_validator);
  register_cmd(L"layout", L"Change layout to name [layout (name)]", cmd_layout_validator);
  register_cmd(L"list", L"Show all tags", cmd_list_validator);
  register_cmd(L"lock", L"Lock/unlock screen contents [(1 2 ..) lock]", cmd_lock_validator);
  register_cmd(L"macro", L"Execute macro [macro (name)]", cmd_macro_validator);
  register_cmd(L"maximize", L"Maximize and close others [(1) maximize]", cmd_maximize_validator);
  register_cmd(L"quit", L"Close screens and quit Cinema", cmd_quit_validator);
  register_cmd(L"reroll", L"Shuffle media [(1 2 ..) (reroll)]", cmd_reroll_validator);
  register_cmd(L"search", L"Limit media to term [(1 2 ..) search (term)]", cmd_search_validator);
  register_cmd(L"store", L"Store layout in cinema.conf [store (layout)]", cmd_store_validator);
  register_cmd(L"swap", L"Swap screen contents [(1 2) swap]", cmd_swap_validator);
  register_cmd(L"tag", L"Limit media to tag [(1 2 ..) tag (name)]", cmd_tag_validator);
  register_cmd(L"twitch", L"Show channel [(1 2 ..) twitch (channel)]", cmd_twitch_validator);
  return true;
}

static void execute_startup_macros(void) {
  array_foreach(&startup_macros, Cin_Macro *, i, macro) {
    cmd_ctx.macro = macro;
    cmd_macro_executor();
  }
  cmd_reroll_validator();
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
#if !defined(_WIN32)
  printf("Error: Your operating system is not supported, Windows-only currently.\n");
  return 1;
#endif
  if (!init_os()) exit(1);
  if (!init_repl()) exit(1);
  if (!InitializeCriticalSectionAndSpinCount(&log_lock, 0)) exit(1);
  if (!init_config(CIN_CONF_FILENAME)) exit(1);
  if (!init_commands()) exit(1);
  if (!init_executables()) exit(1);
  if (!init_documents()) exit(1);
  if (!init_timers()) exit(1);
  if (!init_mpv()) exit(1);
  execute_startup_macros();
  // NOTE: It seems impossible to reach outside the bounds of the viewport
  // within Windows Terminal using a custom ReadConsoleInput approach. Virtual
  // terminal sequences and related APIs are bound to the viewport. So,
  // we must use the built-in cooked input mode with ReadConsole, OR modify
  // the cmd.exe approach using screen clear tricks and partial writes,
  // but even then the scroll space will surely become confusing at some
  // point. We accept the scrollback issues and support relative consoles.
  Console_Message *msg_tail = NULL;
  for (;;) {
    show_cursor();
    INPUT_RECORD input;
    DWORD read;
    if (!ReadConsoleInputW(repl.in, &input, 1, &read)) {
      log_last_error("Failed to read console input");
      break;
    }
    wchar_t c = input.Event.KeyEvent.uChar.UnicodeChar;
    wchar_t vk = input.Event.KeyEvent.wVirtualKeyCode;
    if (!input.Event.KeyEvent.bKeyDown && (!c || vk != VK_MENU)) continue;
    switch (input.EventType) {
    case KEY_EVENT:
      hide_cursor();
      break;
    case WINDOW_BUFFER_SIZE_EVENT:
      reset_console_timer(console_timers[CIN_TIMER_RESIZE]);
      continue;
    default:
      continue;
    }
    switch (vk) {
    case VK_TAB:
    case VK_RETURN: {
      clear_full();
      cursor_home();
      assert(repl.msg->items);
      DWORD i = repl.msg->count;
      while (i && iswspace(repl.msg->items[i - 1])) --i;
      bool empty = !i;
      bool dup = !empty && msg_tail && repl.msg->count == msg_tail->count &&
                 !wcsncmp(repl.msg->items, msg_tail->items, repl.msg->count);
      if (empty || dup) {
        if (msg_tail) repl.msg->prev = msg_tail;
        repl.msg->next = NULL;
        repl.msg_index = 0;
        repl.msg->count = 0;
      } else {
        // commit to history
        if (msg_tail) {
          msg_tail->next = repl.msg;
          repl.msg->prev = msg_tail;
        }
        repl.msg->next = NULL;
        msg_tail = repl.msg;
        repl.msg = create_console_message();
        repl.msg->prev = msg_tail;
        repl.msg_index = 0;
        repl.msg->count = 0;
      }
      if (cmd_ctx.executor) {
        cmd_ctx.executor();
      }
    } break;
    case VK_ESCAPE: {
      clear_full();
      cursor_home();
      repl.msg_index = 0;
      repl.msg->count = 0;
    } break;
    case VK_HOME:
      cursor_home();
      repl.msg_index = 0;
      continue;
    case VK_END:
      repl.msg_index = repl.msg->count;
      cursor_curr();
      continue;
    case VK_BACK: {
      if (!repl.msg_index) continue;
      DWORD left = repl.msg_index - 1;
      if (ctrl_on(&input)) {
        while (left && repl.msg->items[left] == CIN_SPACE) --left;
        while (left && repl.msg->items[left - 1] != CIN_SPACE) --left;
      }
      if (repl.msg_index < repl.msg->count) {
        wmemmove(&repl.msg->items[left], &repl.msg->items[repl.msg_index], repl.msg->count - repl.msg_index);
      }
      DWORD deleted = repl.msg_index - left;
      repl.msg->count -= deleted;
      repl.msg_index = left;
      cursor_curr();
      DWORD leftover = repl.msg->count - repl.msg_index;
      clear_tail(deleted);
      if (leftover) {
        wwrite(repl.msg->items + repl.msg_index, leftover);
        cursor_curr();
      }
    } break;
    case VK_DELETE: {
      if (repl.msg_index == repl.msg->count) continue;
      DWORD right = repl.msg_index;
      if (ctrl_on(&input)) {
        while (right < repl.msg->count && repl.msg->items[right] != CIN_SPACE) ++right;
        while (right < repl.msg->count && repl.msg->items[++right] == CIN_SPACE);
      } else {
        ++right;
      }
      DWORD leftover = repl.msg->count - right;
      DWORD deleted = right - repl.msg_index;
      repl.msg->count -= deleted;
      clear_tail(deleted);
      if (leftover) {
        wmemmove(&repl.msg->items[repl.msg_index], &repl.msg->items[right], leftover);
        wwrite(repl.msg->items + repl.msg_index, leftover);
        cursor_curr();
      }
    } break;
    case VK_UP: {
      if (!repl.msg->prev) continue;
      DWORD prev_count = repl.msg->count;
      array_resize(&console_arena, repl.msg, repl.msg->prev->count);
      wmemcpy(repl.msg->items, repl.msg->prev->items, repl.msg->prev->count);
      repl.msg_index = repl.msg->count;
      repl.msg->next = repl.msg->prev->next;
      repl.msg->prev = repl.msg->prev->prev;
      if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
      cursor_home();
      wwrite(repl.msg->items, repl.msg->count);
    } break;
    case VK_DOWN: {
      if (repl.msg->next) {
        DWORD prev_count = repl.msg->count;
        repl.msg->capacity = repl.msg->next->capacity;
        repl.msg->count = repl.msg->next->count;
        wmemcpy(repl.msg->items, repl.msg->next->items, repl.msg->next->count);
        if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
        cursor_home();
        wwrite(repl.msg->items, repl.msg->count);
        repl.msg->prev = repl.msg->next->prev;
        repl.msg->next = repl.msg->next->next;
        repl.msg_index = repl.msg->count;
      } else {
        clear_full();
        cursor_home();
        repl.msg->prev = msg_tail;
        repl.msg->count = 0;
        repl.msg_index = 0;
      }
    } break;
    case VK_PRIOR: {
      if (!repl.msg->prev) continue;
      Console_Message *head = repl.msg->prev;
      while (head->prev) head = head->prev;
      DWORD prev_count = repl.msg->count;
      array_resize(&console_arena, repl.msg, head->count);
      wmemcpy(repl.msg->items, head->items, head->count);
      repl.msg_index = repl.msg->count;
      repl.msg->next = head->next;
      head = head->prev;
      if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
      cursor_home();
      wwrite(repl.msg->items, repl.msg->count);
    } break;
    case VK_NEXT: {
      if (msg_tail) {
        DWORD prev_count = repl.msg->count;
        repl.msg->capacity = msg_tail->capacity;
        repl.msg->count = msg_tail->count;
        wmemcpy(repl.msg->items, msg_tail->items, msg_tail->count);
        if (repl.msg->count < prev_count) clear_tail(prev_count - repl.msg->count);
        cursor_home();
        wwrite(repl.msg->items, repl.msg->count);
        repl.msg->prev = msg_tail->prev;
        repl.msg->next = msg_tail->next;
        repl.msg_index = repl.msg->count;
      } else {
        clear_full();
        cursor_home();
        repl.msg->count = 0;
        repl.msg_index = 0;
      }
    } break;
    case VK_LEFT:
      if (repl.msg_index) {
        --repl.msg_index;
        if (ctrl_on(&input)) {
          while (repl.msg_index && repl.msg->items[repl.msg_index] == CIN_SPACE) --repl.msg_index;
          while (repl.msg_index && repl.msg->items[repl.msg_index - 1] != CIN_SPACE) --repl.msg_index;
        }
        cursor_curr();
      }
      continue;
    case VK_RIGHT:
      if (repl.msg_index < repl.msg->count) {
        if (ctrl_on(&input)) {
          while (repl.msg_index < repl.msg->count && repl.msg->items[repl.msg_index] != CIN_SPACE) ++repl.msg_index;
          while (repl.msg_index < repl.msg->count && repl.msg->items[++repl.msg_index] == CIN_SPACE);
        } else {
          ++repl.msg_index;
        }
        cursor_curr();
      }
      continue;
    default:
      if (!c || c == PREFIX_TOKEN) continue;
      // NOTE: When a surrogate is encountered, build a grapheme cluster.
      // This ensures that, not only do we store the wchar_t properly, we also
      // print it accurately as it arrives - the console normally appends a space
      // after every single surrogate, so a pair will be 4 cells (now 2).
      // Unfortunately, surrogate pairs still corrupt cursor positioning, which
      // you could try to alleviate by tracking cells - simply not worth.
      static wchar_t surrogates[4] = {0};
      static wchar_t surrogate_count = 0;
      assert(surrogate_count < 4);
      if (surrogate_count == 3) {
        // completed grapheme cluster
        // overwrite first written pair
        assert(IS_LOW_SURROGATE(c));
        surrogates[surrogate_count] = c;
        array_wsplice(&console_arena, repl.msg, repl.msg_index, surrogates + 2, 2);
        repl.msg_index -= 2;
        cursor_curr();
        wwrite(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
        repl.msg_index += 4;
        cursor_curr();
        surrogate_count = 0;
      } else if (surrogate_count == 1) {
        // pair might be completed, write just in case
        assert(IS_LOW_SURROGATE(c));
        surrogates[surrogate_count++] = c;
        array_wsplice(&console_arena, repl.msg, repl.msg_index, surrogates, 2);
        wwrite(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
        repl.msg_index += 2;
        cursor_curr();
      } else {
        if (IS_HIGH_SURROGATE(c)) {
          surrogates[surrogate_count++] = c;
          continue;
        } else {
          assert(!IS_LOW_SURROGATE(c));
          c = cin_wlower(c);
          array_winsert(&console_arena, repl.msg, repl.msg_index, c);
          wwrite(repl.msg->items + repl.msg_index, repl.msg->count - repl.msg_index);
          ++repl.msg_index;
          cursor_curr();
          surrogate_count = 0;
        }
      }
      log_wmessage(LOG_TRACE, L"char=%hu (%lc), v=%hu (%lc), pressed=%d, ctrl=%d",
                   c, c, vk, vk ? vk : L' ', input.Event.KeyEvent.bKeyDown, ctrl_on(&input));
      break;
    }
    SHORT preview_offset = (SHORT)((repl.msg->count + PREFIX) / repl.dwSize_X) + 1;
    SHORT preview_line = repl.home.Y + preview_offset;
    SHORT y_diff = preview_line - preview.pos.Y;
    if (y_diff < 0) {
      clear_preview((SHORT)(repl.dwSize_X - preview.len));
    } else if (y_diff == 1) {
      DWORD tail_x = (repl.msg->count + PREFIX) % repl.dwSize_X;
      if (preview.len > tail_x) {
        clear_preview((SHORT)tail_x);
      }
    }
    set_preview_pos(preview_line);
    clear_preview(0);
    update_preview();
    log_preview();
  }
  if (!SetConsoleMode(repl.in, repl.in_mode)) {
    log_last_error("Failed to reset in console mode");
    return 1;
  }
  return 0;
}
