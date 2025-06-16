CC ?= cc
CFLAGS ?= -fPIC -shared -O2
SRC_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
BUILD_DIR := $(SRC_DIR)/build
SOURCES := $(wildcard $(SRC_DIR)/*.c)
LIBS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/lib%.so,$(SOURCES))

all: $(BUILD_DIR) $(LIBS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/lib%.so: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
