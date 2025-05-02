CC = gcc
CFLAGS = -Wall -O2
LDFLAGS =
PREFIX = /usr/local

ifeq ($(shell uname), Darwin)
    PREFIX = /opt/local
	CFLAGS += -arch arm64
	LDFLAGS +=
else
    PREFIX = /usr/local
	CFLAGS += -Wno-format -D_FILE_OFFSET_BITS=64
	LDFLAGS +=
endif

TARGET = machoe
SRCS = main.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean install

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
