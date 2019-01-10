#include "malloc.h"

#include <malloc.h>

void *calloc(size_t count, size_t size) {
  size_t bytes = count * size;
  void *res = malloc(bytes);
  memset(res, 0, bytes);
  debug("calloc(%ld, %ld) = %p", count, size, res);
  return res;
}

#define MINALIGN sizeof(void *)

int posix_memalign(void **memptr, size_t alignment, size_t bytes) {
  int res = 0;

  if (alignment % MINALIGN || !powerof2(alignment / MINALIGN) || !alignment) {
    res = EINVAL;
    goto fail;
  }

  void *mem = memalign(alignment, bytes);

  if (!mem) {
    res = ENOMEM;
    goto fail;
  }

  *memptr = mem;

fail:
  debug("posix_memalign(%p, %ld, %ld) = %d", memptr, alignment, bytes, res);
  return res;
}

void *valloc(size_t bytes) {
  size_t pagesize = sysconf(_SC_PAGESIZE);
  void *res = memalign(pagesize, bytes);
  debug("valloc(%ld) = %p", bytes, res);
  return res;
}

void *pvalloc(size_t bytes) {
  size_t pagesize = sysconf(_SC_PAGESIZE);
  size_t rounded_up = (bytes + (pagesize - 1)) & -pagesize;
  if (rounded_up < bytes) {
    errno = ENOMEM;
    return NULL;
  }
  void *res = memalign(pagesize, rounded_up);
  debug("pvalloc(%ld) = %p", bytes, res);
  return res;
}

int malloc_trim(__unused size_t pad) {
  debug("%s: not implemented!", __func__);
  return 0;
}

int mallopt(__unused int param, __unused int value) {
  debug("%s: not implemented!", __func__);
  return 0;
}

void malloc_stats(void) {
  debug("%s: not implemented!", __func__);
}

struct mallinfo mallinfo(void) {
  debug("%s: not implemented!", __func__);
  return (struct mallinfo){};
}
