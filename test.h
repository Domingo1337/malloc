#pragma once

#include <assert.h>

#define __section(x) __attribute__((section(x)))
#define __used __attribute__((used))

typedef struct test {
  const char *name;
  int (*func)(void);
} test_t;

#define TEST(name)                                                             \
  static int test_##name(void);                                                \
  __asm__(".globl __start_set_tests");                                         \
  __asm__(".globl __stop_set_tests");                                          \
  static test_t *__set_tests_##name __section("set_tests") __used =            \
    &(test_t){#name, test_##name};                                             \
  static int test_##name(void)

#define TESTS_DECLARE()                                                        \
  extern test_t *__start_set_tests;                                            \
  extern test_t *__stop_set_tests

#define TESTS_BEGIN() (&__start_set_tests)
#define TESTS_END() (&__stop_set_tests)

#define TESTS_FOREACH(tst_p)                                                   \
  for (test_t **tst_p = TESTS_BEGIN(); tst_p < TESTS_END(); tst_p++)
