SHELL := $(if $(wildcard /bin/sh),/bin/sh,$(if $(wildcard /var/jb/usr/bin/sh),/var/jb/usr/bin/sh,/usr/bin/sh))
CC := $(if $(wildcard /usr/bin/gcc),gcc,$(if $(wildcard /var/jb/usr/bin/gcc),gcc,clang))
CFLAGS = -Wall -O2
LDFLAGS =
PREFIX = /usr/local

ifeq ($(shell uname), Darwin)
	PREFIX = /opt/local
	UNAME_M := $(shell uname -m)
	ifneq ($(findstring iPhone,$(UNAME_M)),)
		CFLAGS += -arch arm64
	else ifneq ($(findstring iPad,$(UNAME_M)),)
		CFLAGS += -arch arm64
	else
		CFLAGS += -arch arm64 -arch x86_64
	endif
	LDFLAGS +=
else
	PREFIX = /usr/local
	CFLAGS += -Wno-format -D_FILE_OFFSET_BITS=64
	LDFLAGS +=
endif

TARGET = machoe
SRCS = main.c machoe.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
		$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
		rm -f $(OBJS)

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

install: $(TARGET)
		install -d $(DESTDIR)$(PREFIX)/bin
		install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin

clean:
		rm -f $(TARGET) $(OBJS)

test:
		@echo "=== Compiling test suite ==="
		$(CC) $(CFLAGS) -I./ machoe.c tests/unit_tests.c -o tests/unit_tests -DTESTS_RUNNING=1
		@echo
		@echo "=== Running tests ==="
		@./tests/unit_tests
		@rm -f tests/unit_tests
		@echo
		@echo "=== Test complete ==="