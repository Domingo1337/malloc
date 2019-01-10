CC = gcc
CFLAGS = -ggdb -Og -Wall -Wextra
CPPFLAGS = -DDEBUG $(shell pkg-config --cflags libbsd-overlay)
LDLIBS = $(shell pkg-config --libs libbsd-overlay) -Wl,-rpath=.

all: malloc.so test thread-test

%.lo: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -c -o $@ $<

%.so: %.lo
	$(CC) -shared $^ -ldl -o $@

debug.lo: debug.c malloc.h
wrappers.lo: wrappers.c malloc.h
malloc.lo: malloc.c malloc.h
malloc.so: debug.lo malloc.lo wrappers.lo

TESTS = $(wildcard tst-*.c)

test: test.o $(TESTS:.c=.o) malloc.so

thread-test: LDLIBS += -lpthread
thread-test: thread-test.o malloc.so
thread-test.o: thread-test.c thread-lran2.h thread-st.h thread-test.h

format:
	clang-format -style=file -i *.c *.h

clean:
	rm -f test thread-test *.so *.lo *.o *~

.PRECIOUS: %.o
.PHONY: all clean format run

# vim: ts=8 sw=8 noet
