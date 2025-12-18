CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -std=c11

# Try to locate qemu-plugin.h; allow override via QEMU_INC
QEMU_INC ?= /usr/include

all: fz_bbcov.so

fz_bbcov.o: fz_bbcov.c
	$(CC) $(CFLAGS) -I$(QEMU_INC) -c $< -o $@

fz_bbcov.so: fz_bbcov.o
	$(CC) -shared -o $@ $<

clean:
	rm -f fz_bbcov.o fz_bbcov.so

.PHONY: all clean

