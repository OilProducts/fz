# Makefile for target2
CC ?= gcc
CFLAGS ?= -O0 -g -fno-stack-protector -z execstack
LDFLAGS ?=

TARGET=target2
SRC=$(TARGET).c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
