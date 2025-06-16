CC ?= gcc
CFLAGS ?= -O0 -g -pthread -fno-stack-protector -z execstack
LDFLAGS ?=
TARGET = server

all: $(TARGET)

$(TARGET): server.c
$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
rm -f $(TARGET)

.PHONY: all clean
