# Makefile for target2
CC ?= gcc
ARM64_CC ?= aarch64-linux-gnu-gcc
CFLAGS ?= -O0 -g -fno-stack-protector -z execstack
LDFLAGS ?=

TARGET=target2
TARGET_ARM64=$(TARGET)_arm64
SRC=$(TARGET).c

all: $(TARGET) $(TARGET_ARM64)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

$(TARGET_ARM64): $(SRC)
	$(ARM64_CC) $(CFLAGS) -o $(TARGET_ARM64) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_ARM64)

.PHONY: all clean
