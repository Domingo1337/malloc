#pragma once

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define __strong_alias(name, aliasname)                                        \
  extern typeof(name) aliasname __attribute__((alias(#name)))
#define __used __attribute__((used))
#define __unused __attribute__((unused))
#define __constructor __attribute__((constructor))
#define __format(func, str, fst) __attribute__((format(func, str, fst)))

#define align(x, y) (typeof(x))(((intptr_t)(x) + ((y)-1)) & -(y))
#define powerof2(x) ((((x)-1) & (x)) == 0)

typedef void *(*malloc_t)(size_t size);
typedef void *(*realloc_t)(void *ptr, size_t size);
typedef void (*free_t)(void *ptr);
typedef void *(*memalign_t)(size_t alignment, size_t size);
typedef size_t (*malloc_usable_size_t)(void *ptr);

#define debug(fmt, ...) __malloc_debug(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

void __malloc_debug_init(void);
void __malloc_debug(const char *file, int line, const char *fmt, ...)
  __format(printf, 3, 4);
