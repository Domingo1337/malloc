#include "malloc.h"
#include <sys/queue.h>

typedef struct mem_block mem_block_t;
typedef struct mem_arena mem_arena_t;
typedef LIST_ENTRY(mem_block) mb_node_t;
typedef LIST_ENTRY(mem_arena) ma_node_t;
typedef LIST_HEAD(, mem_block) mb_list_t;
typedef LIST_HEAD(, mem_arena) ma_list_t;

struct mem_block {
  int64_t mb_size; /* mb_size > 0 => free, mb_size < 0 => allocated */
  union {
    mb_node_t mb_link;   /* link on free block list, valid if block is free */
    uint64_t mb_data[0]; /* user data pointer, valid if block is allocated */
  };
};

struct mem_arena {
  ma_node_t ma_link;     /* link on list of all arenas */
  mb_list_t ma_freeblks; /* list of all free blocks in the arena */
  int64_t size;          /* arena size minus sizeof(mem_arena_t) */
  mem_block_t ma_first;  /* first block in the arena */
};

static ma_list_t *arenas __used = &(ma_list_t){}; /* list of all arenas */

/* This procedure is called before any allocation happens. */
__constructor void __malloc_init(void) {
  __malloc_debug_init();
  LIST_INIT(arenas);
}

void *__my_malloc(size_t size) {
  debug("%s(%ld)", __func__, size);
  return NULL;
}

void *__my_realloc(void *ptr, size_t size) {
  debug("%s(%p, %ld)", __func__, ptr, size);
  return NULL;
}

void __my_free(void *ptr) {
  debug("%s(%p)", __func__, ptr);
}

void *__my_memalign(size_t alignment, size_t size) {
  debug("%s(%ld, %ld)", __func__, alignment, size);
  return NULL;
}

size_t __my_malloc_usable_size(void *ptr) {
  debug("%s(%p)", __func__, ptr);
  return 0;
}

/* DO NOT remove following lines */
__strong_alias(__my_free, cfree);
__strong_alias(__my_free, free);
__strong_alias(__my_malloc, malloc);
__strong_alias(__my_malloc_usable_size, malloc_usable_size);
__strong_alias(__my_memalign, aligned_alloc);
__strong_alias(__my_memalign, memalign);
__strong_alias(__my_realloc, realloc);
