#include "malloc.h"
#include <stdarg.h>

#define DMSGLEN 80

static bool verbose = false;

void __malloc_debug_init(void) {
  verbose = (bool)getenv("MALLOC_DEBUG");
}

void __malloc_debug(const char *file, int line, const char *fmt, ...) {
  char dmsg[DMSGLEN];
  int written;
  va_list ap;

  if (!verbose)
    return;

  int saved_errno = errno;

  written = snprintf(dmsg, DMSGLEN, "[%s:%d] ", file, line);
  write(STDERR_FILENO, dmsg, written);

  va_start(ap, fmt);
  written = vsnprintf(dmsg, DMSGLEN, fmt, ap);
  write(STDERR_FILENO, dmsg, written);
  va_end(ap);

  write(STDERR_FILENO, "\n", 1);

  errno = saved_errno;
}
