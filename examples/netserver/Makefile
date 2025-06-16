CC ?= gcc
ARM64_CC ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O0 -g -pthread -fno-stack-protector -z execstack
LDFLAGS ?=
TARGET = server
TARGET_ARM64 = $(TARGET)_arm64

all: $(TARGET) $(TARGET_ARM64)

$(TARGET): server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TARGET_ARM64): server.c
	$(ARM64_CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_ARM64)

.PHONY: all clean
