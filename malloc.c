/* Imię i nazwisko: Dominik Gulczyński *\
\* Numer indeksu: 299391               */

#include "malloc.h"
#include <dlfcn.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <pthread.h>

static void *dummy_malloc(size_t size) {
  void *ptr = sbrk(align(size, 16));
  if (ptr == NULL)
    exit(EXIT_FAILURE);
  debug("%s(%ld) = %p", __func__, size, ptr);
  return ptr;
}

static void dummy_free(void *ptr) {
  debug("%s(%p)", __func__, ptr);
}

static malloc_t real_malloc = dummy_malloc;
static realloc_t real_realloc = NULL;
static free_t real_free = dummy_free;
static memalign_t real_memalign = NULL;
static malloc_usable_size_t real_malloc_usable_size = NULL;

#define bind_next_symbol(name)                                                 \
  real_##name = (name##_t)dlsym(RTLD_NEXT, #name);                             \
  if (real_##name == NULL)                                                     \
  exit(EXIT_FAILURE)

typedef struct mem_block mem_block_t;
typedef struct mem_arena mem_arena_t;
typedef LIST_ENTRY(mem_block) mb_node_t;
typedef LIST_ENTRY(mem_arena) ma_node_t;
typedef LIST_HEAD(, mem_block) mb_list_t;
typedef LIST_HEAD(, mem_arena) ma_list_t;

typedef int64_t bdtag_t;
#define MIN_BLOCK_SIZE (sizeof(mem_block_t) + sizeof(bdtag_t))
#define BLOCK_METADATA (sizeof(int64_t) + sizeof(bdtag_t))
#define ARENA_METADATA (sizeof(mem_arena_t) + BLOCK_METADATA)
#define ARENA_TAG ((bdtag_t)0xFFFFFFFFFFFFFFFF)
#define MB_ALIGNMENT (2 * sizeof(void *))
#define MA_MAXSIZE (MB_ALIGNMENT * 32768)
#define MA_THRESHOLD (MA_MAXSIZE / 2)
#define MAX_MEM 0xFFFFFFFF
#define MAX(a, b) ((a) > (b) ? (a) : (b))

/*       STRUCTURES       *\
\*========================*/

struct mem_block {
  int64_t mb_size; /* mb_size > 0 => free, mb_size < 0 => allocated */
  union {
    mb_node_t mb_link;   /* link on free block list, valid if block is free */
    uint64_t mb_data[0]; /* user data pointer, valid if block is allocated */
  };
  /* after data comes boundary tag */
};

struct mem_arena {
  ma_node_t ma_link;     /* link on list of all arenas */
  mb_list_t ma_freeblks; /* list of all free blocks in the arena */
  int64_t size;          /* maximum size of data in this arena */
  bdtag_t tag;           /* tag to indicate end f arena metadata */
  mem_block_t ma_first;  /* first block in the arena */
};

static ma_list_t *arenas __used = &(ma_list_t){}; /* list of all arenas */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* This procedure is called before any allocation happens. */
__constructor void __malloc_init(void) {
  __malloc_debug_init();

  bind_next_symbol(malloc);
  bind_next_symbol(realloc);
  bind_next_symbol(free);
  bind_next_symbol(memalign);
  bind_next_symbol(malloc_usable_size);
  LIST_INIT(arenas);
}

/*  AUXILIARY PROCEDURES  *\
\*========================*/

inline bdtag_t *get_boundary_tag(mem_block_t *block) {
  return ((void *)block->mb_data) + abs(block->mb_size);
}

inline void set_boundary_tag(mem_block_t *block) {
  *get_boundary_tag(block) = block->mb_size;
}

inline mem_block_t *block_of(void *ptr) {
  int64_t *iptr = (int64_t *)ptr;
  do {
    iptr--;
  } while ((*iptr) == 0);
  return (mem_block_t *)iptr;
}

inline mem_block_t *prev_block_of(mem_block_t *block) {
  bdtag_t tag = *((bdtag_t *)block - 1);
  if (tag == ARENA_TAG)
    return NULL;
  void *prev = (void *)block - 2 * sizeof(void *);
  return prev - abs(tag);
}

inline mem_block_t *next_block_of(mem_block_t *block) {
  return (mem_block_t *)(get_boundary_tag(block) + 1);
}

inline mem_arena_t *arena_of(mem_block_t *block) {
  while (*((bdtag_t *)block - 1) != ARENA_TAG) {
    block = prev_block_of(block);
  }
  return ((void *)block - sizeof(mem_arena_t) + sizeof(mem_block_t));
}

void *create_new_arena(size_t size) {
  /* fit desired size and empty block to indicate end of arena */
  size_t arena_size = size + ARENA_METADATA;
  arena_size = align(arena_size, getpagesize());

  mem_arena_t *arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (arena == MAP_FAILED) {
    debug("%s MAP_FAILED\n", __func__);
    return NULL;
  }

  arena->size = arena_size - ARENA_METADATA;
  arena->tag = ARENA_TAG;

  LIST_INSERT_HEAD(arenas, arena, ma_link);

  mem_block_t *block = &arena->ma_first;
  block->mb_size = arena->size;
  set_boundary_tag(block);
  LIST_INIT(&arena->ma_freeblks);
  LIST_INSERT_HEAD(&arena->ma_freeblks, block, mb_link);

  mem_block_t *last = next_block_of(block);
  last->mb_size = 0;
  set_boundary_tag(last);

  return block;
}

void insert_to_freeblks_of(mem_arena_t *arena, mem_block_t *block) {
  assert((size_t)block->mb_size >= sizeof(mb_node_t));
  mem_block_t *current;
  mem_block_t *prev = NULL;
  LIST_FOREACH(current, &arena->ma_freeblks, mb_link) {
    if (current > block) {
      LIST_INSERT_BEFORE(current, block, mb_link);
      return;
    } else {
      prev = current;
    }
  }
  if (prev == NULL) {
    LIST_INSERT_HEAD(&arena->ma_freeblks, block, mb_link);
  } else {
    LIST_INSERT_AFTER(prev, block, mb_link);
  }
}

mem_block_t *find_first_free_block(size_t size, size_t alignment) {
  mem_arena_t *arena;
  mem_block_t *block;
  LIST_FOREACH(arena, arenas, ma_link) {
    LIST_FOREACH(block, &arena->ma_freeblks, mb_link) {
      size_t block_size = (size_t)block->mb_size;
      if (block_size >= size) {
        void *aligned = (void *)align((size_t)block->mb_data, alignment);
        if (block_size >= size + (aligned - (void *)block->mb_data))
          return block;
      }
    }
  }
  return NULL;
}

bool should_delete(mem_arena_t *arena_to_delete) {
  int64_t free_space = 0;
  mem_arena_t *arena;
  mem_block_t *block;
  LIST_FOREACH(arena, arenas, ma_link) {
    if (arena != arena_to_delete) {
      LIST_FOREACH(block, &arena->ma_freeblks, mb_link) {
        free_space += block->mb_size > 0 ? block->mb_size : 0;
      }
    }
    if ((size_t)free_space > MA_THRESHOLD)
      return true;
  }
  return false;
}

/*   PRINT   STRUCTURES   *\
\*========================*/

void print_block(mem_block_t *block) {
  debug("\t\tblock @ %p {size: %ld, bdtag: %ld }", block, block->mb_size,
        *get_boundary_tag(block));
}

void print_arena(mem_arena_t *arena) {
  debug("\tarena @ %p{", arena);
  debug("\t\tsize:\t%ld", arena->size);
  debug("\t\ttag:\t%ld", arena->tag);
  debug("\t\tfreeblks:");
  void *max_addr = (void *)arena + arena->size + ARENA_METADATA;
  mem_block_t *block;
  LIST_FOREACH(block, &arena->ma_freeblks, mb_link) {
    debug("\t|%p|", block);
    if ((void *)block >= max_addr) {
      debug("!!! block out of arena, stop freebloks loop !!!");
      break;
    }
  }
  block = &arena->ma_first;
  do {
    print_block(block);
    block = next_block_of(block);
    if ((void *)block >= max_addr) {
      debug("!!! block out of arena, stop loop !!!");
      break;
    }
  } while (block->mb_size);
}

void print_all() {
  debug("malloc stuctures:");
  mem_arena_t *arena;
  LIST_FOREACH(arena, arenas, ma_link) {
    print_arena(arena);
  }
}

/*   INTEGRITY CHECKING   *\
\*========================*/

bool check_arena(mem_arena_t *arena) {
  mem_block_t *block;
  LIST_FOREACH(block, &arena->ma_freeblks, mb_link) {
    if (block->mb_size <= 0) {
      debug("free block@%p->mb_size: %ld", block, block->mb_size);
      return false;
    }
  }
  void *arena_last_addr = (void *)arena + arena->size + ARENA_METADATA;
  int64_t size_sum = 0;
  block = &arena->ma_first;
  do {
    bdtag_t *tag_addr = get_boundary_tag(block);
    if ((void *)tag_addr > arena_last_addr) {
      debug("Out of arena: block@%p->mb_size: %ld (tag_addr: %p) is out of "
            "arena[%p : %p]",
            block, block->mb_size, tag_addr, arena, arena_last_addr);
      return false;
    }
    if (*tag_addr != block->mb_size) {
      debug("Invalid bd_tag and/or size: block@%p->mb_size: %ld, bdtag: %ld",
            block, block->mb_size, *tag_addr);
      return false;
    }

    size_sum += block->mb_size;
    if (size_sum > arena->size) {
      debug("Invalid size: blocks of arena@%p exceed size", arena);
      return false;
    }

    block = next_block_of(block);
  } while (block->mb_size);
  return true;
}

bool check_integrity() {
  debug("Performing integrity check ...");
  mem_arena_t *arena;
  LIST_FOREACH(arena, arenas, ma_link) {
    if (!check_arena(arena)) {
      debug("%s failed", __func__);
      print_arena(arena);
      exit(EXIT_FAILURE);
    }
  }
  return true;
}

/*   THE  MALLOC  FAMILY  *\
\*========================*/

void *__my_memalign(size_t alignment, size_t size) {
  void *res = NULL;

  if (size == 0) {
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  if (size >= MAX_MEM) {
    errno = ENOMEM;
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  if (!powerof2(alignment) || alignment == 0 || alignment % MB_ALIGNMENT != 0) {
    errno = EINVAL;
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  // block must fit the list node
  size = MAX(size, sizeof(mb_node_t));

  pthread_mutex_lock(&mutex);
  mem_block_t *block;

  // big blocks get their own arena
  if (size > MA_MAXSIZE) {
    create_new_arena(size);
    block = find_first_free_block(size, alignment);

    if (block == NULL) {
      errno = ENOMEM;
      res = NULL;
      debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
      pthread_mutex_unlock(&mutex);
      return res;
    }

    LIST_REMOVE(block, mb_link);

    // align user ptr and fill empty space with zeros for free() convenience
    res = (void *)align((size_t)block->mb_data, alignment);
    memset(block->mb_data, 0, res - (void *)block->mb_data);

  } else {
    block = find_first_free_block(size, alignment);
    if (block == NULL) {
      create_new_arena(size + alignment);
      block = find_first_free_block(size, alignment);
    }
    if (block == NULL) {
      errno = ENOMEM;
      res = NULL;
      pthread_mutex_unlock(&mutex);
      return res;
    }

    void *data = block->mb_data;
    void *aligned_data = (void *)align((size_t)data, alignment);
    size_t aligned_diff = aligned_data - data;

    // try to split the block to the right
    int64_t new_size = size + aligned_diff;
    int64_t free_mem = block->mb_size - new_size;
    if (free_mem > 0 && (size_t)free_mem >= MIN_BLOCK_SIZE) {
      block->mb_size = new_size;

      mem_block_t *next = next_block_of(block);
      next->mb_size = free_mem - BLOCK_METADATA;
      set_boundary_tag(next);

      LIST_INSERT_AFTER(block, next, mb_link);
    }

    LIST_REMOVE(block, mb_link);

    // try to split the block to the left
    int64_t block_size = block->mb_size;
    if (aligned_diff >= MIN_BLOCK_SIZE) {
      block->mb_size = aligned_diff - BLOCK_METADATA;
      set_boundary_tag(block);

      insert_to_freeblks_of(arena_of(block), block);

      block = next_block_of(block);
      block->mb_size = block_size - aligned_diff;
    } else {
      // can't create new block, try to give unused aligned_diff to the prev one
      mem_block_t *prev = prev_block_of(block);
      if (aligned_diff > 0 && prev != NULL) {
        prev->mb_size -= aligned_diff;
        set_boundary_tag(prev);
        block = (mem_block_t *)((void *)block + aligned_diff);
        block->mb_size = block_size - aligned_diff;
      } else {
        // block is first on the list we can't do much, but zero the extra bytes
        res = aligned_data;
        memset(block->mb_data, 0, res - (void *)block->mb_data);
      }
    }
    res = (void *)align((size_t)block->mb_data, alignment);
  }

  assert(block->mb_size > 0);
  block->mb_size *= -1;
  set_boundary_tag(block);

  debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
  pthread_mutex_unlock(&mutex);
  return res;
}

void *__my_malloc(size_t size) {
  void *res = size == 0 ? NULL : __my_memalign(MB_ALIGNMENT, size);
  debug("%s(%ld) = %p", __func__, size, res);
  return res;
}

void __my_free(void *ptr) {
  debug("%s(%p)", __func__, ptr);
  if (ptr == NULL)
    return;

  pthread_mutex_lock(&mutex);

  mem_block_t *block = block_of(ptr);
  mem_block_t *prev = prev_block_of(block);
  mem_block_t *next = next_block_of(block);
  mem_arena_t *arena = arena_of(block);
  bool prev_free = prev != NULL && prev->mb_size > 0;
  bool next_free = next->mb_size > 0;

  assert(block->mb_size < 0);
  block->mb_size *= -1;

  // pretty much self-explanatory
  if (next_free && prev_free) {
    LIST_REMOVE(next, mb_link);
    prev->mb_size += block->mb_size + next->mb_size + 2 * BLOCK_METADATA;
    block = prev;
    prev = prev_block_of(block);
    next = next_block_of(block);
  } else if (next_free) {
    LIST_INSERT_BEFORE(next, block, mb_link);
    LIST_REMOVE(next, mb_link);
    block->mb_size += next->mb_size + BLOCK_METADATA;
    next = next_block_of(block);
  } else if (prev_free) {
    prev->mb_size += block->mb_size + BLOCK_METADATA;
    block = prev;
    prev = prev_block_of(block);
  } else {
    insert_to_freeblks_of(arena, block);
  }

  if (prev == NULL && next->mb_size == 0 && should_delete(arena)) {
    LIST_REMOVE(arena, ma_link);
    assert(munmap(arena, arena->size + ARENA_METADATA) == 0);
  } else {
    set_boundary_tag(block);
  }

  pthread_mutex_unlock(&mutex);
}

void *__my_realloc(void *ptr, size_t size) {
  void *res = NULL;

  if (ptr == NULL && size == 0) {
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  } else if (size == 0) {
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    __my_free(ptr);
    return res;
  } else if (ptr == NULL) {
    res = __my_malloc(size);
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  }

  pthread_mutex_lock(&mutex);

  mem_block_t *block = block_of(ptr);
  int64_t block_size = (void *)get_boundary_tag(block) - ptr;
  if (size <= (size_t)block_size) {
    pthread_mutex_unlock(&mutex);
    res = ptr;
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  }

  mem_block_t *next = next_block_of(block);
  int64_t next_size = next->mb_size;
  int64_t possible_size = block_size + next_size + BLOCK_METADATA;
  if (next_size > 0 && size < (size_t)possible_size) {
    LIST_REMOVE(next, mb_link);

    size_t possible_new_size = (size_t)possible_size - size;
    if (possible_new_size > MIN_BLOCK_SIZE) {
      block->mb_size = -size;
      set_boundary_tag(block);

      mem_block_t *next = next_block_of(block);
      next->mb_size = possible_new_size - BLOCK_METADATA;
      set_boundary_tag(next);

      mem_arena_t *arena = arena_of(block);
      LIST_INSERT_HEAD(&arena->ma_freeblks, next, mb_link);
    } else {
      block->mb_size = -possible_size;
      set_boundary_tag(block);
    }

    pthread_mutex_unlock(&mutex);
    res = ptr;
  } else {
    pthread_mutex_unlock(&mutex);
    res = __my_malloc(size);
    if (res != NULL) {
      memcpy(res, ptr, block_size);
      __my_free(ptr);
    }
  }

  debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
  return res;
}

size_t __my_malloc_usable_size(void *ptr) {
  int res = ptr == NULL ? 0 : block_of(ptr)->mb_size;
  debug("%s(%p) = %d", __func__, ptr, res);
  return res;
}

/* DO NOT remove following lines */
__strong_alias(__my_free, cfree);
__strong_alias(__my_free, free);
__strong_alias(__my_malloc, malloc);
__strong_alias(__my_malloc_usable_size, malloc_usable_size);
__strong_alias(__my_memalign, aligned_alloc);
__strong_alias(__my_memalign, memalign);
__strong_alias(__my_realloc, realloc);
