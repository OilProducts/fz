CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -z execstack -pthread
LDFLAGS ?=
TARGET = target4

all: $(TARGET)

$(TARGET): target4.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
