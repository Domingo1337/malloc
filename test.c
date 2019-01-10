#include "test.h"
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define RED "\033[91m"
#define GRN "\033[92m"
#define YLW "\033[93m"
#define RST "\033[0m"

static int run_test(test_t *tst) {
  if (fork() == 0)
    exit(tst->func() ? EXIT_FAILURE : EXIT_SUCCESS);
  int wstatus;
  wait(&wstatus);
  fprintf(stderr, "Test '%s'... %s\n" RST, tst->name,
          wstatus ? RED "failed" : GRN "passed");
  if (WIFSIGNALED(wstatus))
    fprintf(stderr, "Killed by '%s' signal!\n", sys_siglist[WTERMSIG(wstatus)]);
  return wstatus;
}

TESTS_DECLARE();

int main(int argc, char *argv[]) {
  int status = EXIT_SUCCESS;

  setlinebuf(stderr);

  if (argc == 1) {
    TESTS_FOREACH (tst_p) { status |= run_test(*tst_p); }
  } else {
    bool found_all = true;

    for (int i = 1; i < argc; i++) {
      bool found = false;

      TESTS_FOREACH (tst_p) {
        test_t *tst = *tst_p;
        if (strcmp(argv[i], tst->name) == 0) {
          found = true;
          status = tst->func() ? EXIT_FAILURE : EXIT_SUCCESS;
          fprintf(stderr, "Test '%s'... %s" RST "\n", tst->name,
                  status ? RED "failed" : GRN "passed");
        }
      }

      if (!found)
        fprintf(stderr, "Test '%s'... " YLW "not found\n" RST, argv[i]);

      found_all &= found;
    }

    if (!found_all) {
      fprintf(stderr, "\nList of all tests:\n");
      TESTS_FOREACH (tst_p) { fprintf(stderr, " * %s\n", (*tst_p)->name); }
    }
  }

  return status;
}
