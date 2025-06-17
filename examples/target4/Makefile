CC ?= gcc
ARM64_CC ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O0 -g -fno-stack-protector -z execstack -pthread
LDFLAGS ?=
TARGET = target4
TARGET_ARM64 = $(TARGET)_arm64

all: $(TARGET) $(TARGET_ARM64)

$(TARGET): target4.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TARGET_ARM64): target4.c
	$(ARM64_CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_ARM64)

.PHONY: all clean
