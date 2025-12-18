CC ?= cc
CFLAGS ?= -fPIC -O2 -Wall -Wextra
LDFLAGS ?= -shared -pthread

BUILD_DIR := build
LIB := $(BUILD_DIR)/libnet_stub.so

.PHONY: all clean

all: $(LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIB): net_stub.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
