#include "malloc.h"
#include <dlfcn.h>

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

__constructor void __malloc_init(void) {
  __malloc_debug_init();

  bind_next_symbol(malloc);
  bind_next_symbol(realloc);
  bind_next_symbol(free);
  bind_next_symbol(memalign);
  bind_next_symbol(malloc_usable_size);
}

void *__my_malloc(size_t size) {
  void *res = real_malloc(size);
  debug("%s(%ld) = %p", __func__, size, res);
  return res;
}

void *__my_realloc(void *ptr, size_t size) {
  void *res = real_realloc(ptr, size);
  debug("%s(%p, %ld) = %p", __func__, ptr, size, res);
  return res;
}

void __my_free(void *ptr) {
  real_free(ptr);
  debug("%s(%p)", __func__, ptr);
}

void *__my_memalign(size_t alignment, size_t size) {
  void *res = real_memalign(alignment, size);
  debug("%s(%ld, %ld) = %p", __func__, alignment, size, res);
  return res;
}

size_t __my_malloc_usable_size(void *ptr) {
  int res = real_malloc_usable_size(ptr);
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
