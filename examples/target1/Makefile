CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -z execstack
LDFLAGS ?=
TARGET = target1

all: $(TARGET)

$(TARGET): target1.c
$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
rm -f $(TARGET)

.PHONY: all clean
