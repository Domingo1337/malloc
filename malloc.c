/* Imię nazwisko: Dominik Gulczyński
 * Numer indeksu: 299391
 */

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
#define FREE_BLOCK_SIZE (sizeof(int64_t) + sizeof(bdtag_t))
#define FREE_ARENA_SIZE (sizeof(mem_arena_t) + FREE_BLOCK_SIZE)
#define ARENA_TAG ((bdtag_t)0xFFFFFFFFFFFFFFFF)
#define MB_ALIGNMENT (2 * sizeof(void *))
#define MA_MAXSIZE (MB_ALIGNMENT * 32768)
#define MA_THRESHOLD (MA_MAXSIZE / 2)
#define MAX_MEM 0xFFFFFFFF
#define max(a, b) ((a) > (b) ? (a) : (b))

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
  int64_t size;          /* arena size minus sizeof(mem_arena_t) */
  bdtag_t tag;
  mem_block_t ma_first; /* first block in the arena */
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

/* helper functions */

inline size_t round_up_to(size_t number, size_t multiple) {
  return (number + multiple - 1) / multiple * multiple;
}

mem_block_t *find_first_free_block(size_t size) {
  int64_t isize = (int64_t)size;
  mem_arena_t *arena;
  mem_block_t *block;
  LIST_FOREACH(arena, arenas, ma_link) {
    LIST_FOREACH(block, &arena->ma_freeblks, mb_link) {
      if (block->mb_size >= isize)
        return block;
    }
  }
  return NULL;
}

bdtag_t *get_boundary_tag(mem_block_t *block) {
  return ((void *)block->mb_data) + abs(block->mb_size);
}

void set_boundary_tag(mem_block_t *block) {
  bdtag_t *bdtag = get_boundary_tag(block);
  *bdtag = block->mb_size;
}

mem_block_t *get_block(void *ptr) {
  int64_t *iptr = (int64_t *)ptr;
  do {
    iptr--;
  } while ((*iptr) == 0);
  return (mem_block_t *)iptr;
}

mem_block_t *get_prev_block(mem_block_t *current) {
  bdtag_t tag = *((bdtag_t *)current - 1);
  if (tag == ARENA_TAG)
    return NULL;
  void *prev = (void *)current - 2 * sizeof(void *);
  return prev - abs(tag);
}

mem_block_t *get_next_block(mem_block_t *current) {
  return (mem_block_t *)(get_boundary_tag(current) + 1);
}

mem_arena_t *get_arena_from_block(mem_block_t *current) {
  while (*((bdtag_t *)current - 1) != ARENA_TAG) {
    current = get_prev_block(current);
  }
  return ((void *)current - sizeof(mem_arena_t) + sizeof(mem_block_t));
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
    } else if ((size_t)free_space > MA_THRESHOLD)
      return true;
  }
  return false;
}

void *create_new_arena(size_t size) {
  size_t arena_size = size + FREE_ARENA_SIZE;
  /* fit user size and empty block to indicate end of arena */
  arena_size = round_up_to(arena_size, getpagesize());

  mem_arena_t *arena = mmap(NULL, arena_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (arena == MAP_FAILED) {
    debug("%s got MAP_FAILED\n", __func__);
    return NULL;
  }

  arena->size = arena_size - FREE_ARENA_SIZE;
  arena->tag = ARENA_TAG;

  LIST_INSERT_HEAD(arenas, arena, ma_link);

  mem_block_t *block = &arena->ma_first;
  block->mb_size = arena->size;
  set_boundary_tag(block);
  LIST_INIT(&arena->ma_freeblks);
  LIST_INSERT_HEAD(&arena->ma_freeblks, block, mb_link);

  mem_block_t *last = get_next_block(block);
  last->mb_size = 0;
  set_boundary_tag(last);
  debug("arena@%p ends with block@%p", arena, last);

  return block;
}

/* print structures */

void print_block(mem_block_t *block) {
  debug("\t\tblock @ %p {size: %ld, bdtag: %ld }", block, block->mb_size,
        *get_boundary_tag(block));
}

void print_arena(mem_arena_t *arena) {
  debug("\tarena @ %p{", arena);
  debug("\t\tsize:\t%ld", arena->size);
  debug("\t\ttag:\t%ld", arena->tag);
  debug("\t\tfreeblks:");
  void *max_addr = (void *)arena + arena->size + FREE_ARENA_SIZE;
  mem_block_t *current;
  LIST_FOREACH(current, &arena->ma_freeblks, mb_link) {
    debug("\t|%p|", current);
    if ((void *)current >= max_addr) {
      debug("block out of arena, stop freebloks loop");
      break;
    }
  }
  debug("\t\tfst:\t%p} bloks:", &arena->ma_first);
  current = &arena->ma_first;
  print_block(current);
  do {
    current = get_next_block(current);
    print_block(current);
  } while (current->mb_size != 0);
}

void print_all() {
  mem_arena_t *arena;
  LIST_FOREACH(arena, arenas, ma_link) {
    print_arena(arena);
  }
}

/* check integrity */

bool check_arena(mem_arena_t *arena) {
  // check freebloks
  mem_block_t *current;
  LIST_FOREACH(current, &arena->ma_freeblks, mb_link) {
    if (current->mb_size <= 0) {
      debug("free block@%p->mb_size: %ld", current, current->mb_size);
      // set_boundary_tag(current);
      return false;
    }
  }
  void *arena_last_addr = (void *)arena + arena->size + FREE_ARENA_SIZE;
  int64_t size_sum = 0;
  current = &arena->ma_first;
  do {
    bdtag_t *tag_addr = get_boundary_tag(current);
    if ((void *)tag_addr > arena_last_addr) {
      debug("\n========\n%s failed\n\n", __func__);
      debug("block@%p->mb_size: %ld (tag_addr: %p)", current, current->mb_size,
            tag_addr);
      debug("out of arena[%p : %p] of size %ld)", arena, arena_last_addr,
            arena->size);
      print_arena(arena);
      return false;
    }
    if (*tag_addr != current->mb_size) {
      debug("block@%p->mb_size: %ld, bdtag: %ld", current, current->mb_size,
            *tag_addr);
      // set_boundary_tag(current);
      return false;
    }

    size_sum += current->mb_size;
    if (size_sum > arena->size) {
      debug("blocks of arena@%p exceed size", arena);
      return false;
    }

    current = get_next_block(current);
  } while (current->mb_size);
  return true;
}

bool check_integrity() {
  debug("performing integirty check ...");
  mem_arena_t *arena;
  LIST_FOREACH(arena, arenas, ma_link) {
    if (!check_arena(arena)) {
      debug("%s failed", __func__);
      print_all();
      exit(1);
    }
  }
  debug("integrity ok");
  return true;
}

/* functions */

void *__my_memalign(size_t alignment, size_t size) {
  void *res;

  if (size == 0) {
    res = NULL;
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  if (size >= MAX_MEM) {
    errno = ENOMEM;
    res = NULL;
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  if (!powerof2(alignment) || alignment == 0 || alignment % MB_ALIGNMENT != 0) {
    errno = EINVAL;
    res = NULL;
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  // we gotta make sure that the pointer can be aligned so we request a lil more
  size = max(align(size + alignment, alignment), sizeof(mb_node_t));

  pthread_mutex_lock(&mutex);
  mem_block_t *block;

  if (size > MA_MAXSIZE) {
    create_new_arena(size);
    block = find_first_free_block(size);
  } else {
    block = find_first_free_block(size);
    if (block == NULL) {
      create_new_arena(size);
      block = find_first_free_block(size);
    }
  }

  if (block == NULL) {
    errno = ENOMEM;

    pthread_mutex_unlock(&mutex);
    res = NULL;
    debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
    return res;
  }

  int64_t free_mem = block->mb_size - size;
  if ((size_t)free_mem >= MIN_BLOCK_SIZE && size <= MA_MAXSIZE) {
    block->mb_size = size;

    mem_block_t *new_block = get_next_block(block);
    new_block->mb_size = free_mem - FREE_BLOCK_SIZE;
    set_boundary_tag(new_block);

    LIST_INSERT_AFTER(block, new_block, mb_link);
  }

  assert(block->mb_size > 0);
  block->mb_size *= -1;
  LIST_REMOVE(block, mb_link);
  set_boundary_tag(block);

  // align user ptr and fill empty space with zeros for free() convenience
  res = (void *)round_up_to((size_t)block->mb_data, alignment);
  memset(block->mb_data, 0, res - (void *)block->mb_data);

  pthread_mutex_unlock(&mutex);
  debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
  return res;
}

void *__my_malloc(size_t size) {
  void *res;
  if (size == 0) {
    res = NULL;
    debug("%s(%ld) = %p", __func__, size, res);
    return res;
  }

  res = __my_memalign(MB_ALIGNMENT, size);
  debug("%s(%ld) = %p", __func__, size, res);
  return res;
}

void __my_free(void *ptr) {
  debug("%s(%p)", __func__, ptr);
  if (ptr == NULL)
    return;

  pthread_mutex_lock(&mutex);
  mem_block_t *current = get_block(ptr);
  mem_block_t *prev = get_prev_block(current);
  mem_block_t *next = get_next_block(current);

  current->mb_size = abs(current->mb_size);

  bool next_free = next->mb_size > 0;
  bool prev_free = prev != NULL && prev->mb_size > 0;

  if (next_free) {
    current->mb_size =
      current->mb_size + next->mb_size + sizeof(int64_t) + sizeof(bdtag_t);
    if (!prev_free) {
      LIST_INSERT_BEFORE(next, current, mb_link);
      set_boundary_tag(current);
    }
    LIST_REMOVE(next, mb_link);
    next = get_next_block(current);
  }
  if (prev_free) {
    prev->mb_size =
      current->mb_size + prev->mb_size + sizeof(int64_t) + sizeof(bdtag_t);
    current = prev;
    set_boundary_tag(current);
    prev = get_prev_block(current);
  }

  assert(current->mb_size > 0);

  mem_arena_t *arena = get_arena_from_block(current);
  if (prev == NULL && next->mb_size == 0 && should_delete(arena)) {
    LIST_REMOVE(arena, ma_link);
    assert(munmap(arena, arena->size + FREE_ARENA_SIZE) == 0);
  } else if (!prev_free && !next_free) {
    LIST_INSERT_HEAD(&arena->ma_freeblks, current, mb_link);
    set_boundary_tag(current);
  }

  pthread_mutex_unlock(&mutex);
}

void *__my_realloc(void *ptr, size_t size) {
  void *res;

  if (ptr == NULL && size == 0) {
    res = NULL;
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  }

  if (ptr == NULL) {

    res = __my_malloc(size);
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  }

  if (size == 0) {
    res = NULL;
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    __my_free(ptr);
    return res;
  }

  pthread_mutex_lock(&mutex);

  int64_t isize = isize;

  mem_block_t *current_block = get_block(ptr);
  int64_t current_size = (void *)get_boundary_tag(current_block) - ptr;

  if (size < (size_t)current_size) {
    pthread_mutex_unlock(&mutex);
    res = ptr;
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  }

  mem_block_t *next_block = get_next_block(current_block);
  int64_t next_size = next_block->mb_size;
  int64_t possible_size = current_size + next_size + FREE_BLOCK_SIZE;
  if (next_size > 0 && size < (size_t)possible_size) {
    LIST_REMOVE(next_block, mb_link);

    size_t possible_new_size = (size_t)possible_size - size;
    if (possible_new_size > MIN_BLOCK_SIZE) {
      current_block->mb_size = -size;
      set_boundary_tag(current_block);

      mem_block_t *new_block = get_next_block(current_block);
      new_block->mb_size = possible_new_size - FREE_BLOCK_SIZE;
      set_boundary_tag(new_block);

      mem_arena_t *arena = get_arena_from_block(current_block);
      LIST_INSERT_HEAD(&arena->ma_freeblks, new_block, mb_link);
    } else {
      current_block->mb_size = -possible_size;
      set_boundary_tag(current_block);
    }

    pthread_mutex_unlock(&mutex);
    res = ptr;
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    return res;
  }

  pthread_mutex_unlock(&mutex);
  void *new_ptr = __my_malloc(size);
  pthread_mutex_lock(&mutex);
  if (new_ptr == NULL) {
    res = NULL;
    debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
    pthread_mutex_unlock(&mutex);
    return res;
  }

  memcpy(new_ptr, ptr, current_size);

  __my_free(ptr);
  res = new_ptr;
  debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
  pthread_mutex_unlock(&mutex);
  return res;
}

size_t __my_malloc_usable_size(void *ptr) {
  int res = (void *)get_boundary_tag(get_block(ptr)) - ptr;
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
