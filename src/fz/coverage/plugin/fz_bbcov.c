#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint8_t *g_map = NULL;
static size_t g_map_size = 64 * 1024; // default 64k
static uint64_t *g_prev = NULL; // per-vcpu previous ID
static size_t g_prev_count = 0;

static uint64_t hash64(uint64_t x) {
    // SplitMix64
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    x = x ^ (x >> 31);
    return x;
}

static inline void cov_edge(uint64_t prev, uint64_t curr) {
    if (!g_map || g_map_size == 0) return;
    uint64_t e = (prev << 1) ^ curr;
    size_t idx = (size_t)(e & (g_map_size - 1));
    uint8_t v = g_map[idx];
    if (v != 0xFF) g_map[idx] = v + 1;
}

static void tb_exec_cb(unsigned int vcpu_index, void *userdata) {
    uint64_t curr = (uint64_t)(uintptr_t)userdata;
    if (vcpu_index >= g_prev_count) return;
    uint64_t prev = g_prev[vcpu_index];
    cov_edge(prev, curr);
    g_prev[vcpu_index] = curr;
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    uint64_t h = hash64(pc);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec_cb, QEMU_PLUGIN_CB_NO_REGS, (void*)(uintptr_t)h);
}

static void detach_cleanup(qemu_plugin_id_t id, void *p) {
    (void)id; (void)p;
    // memory is unmapped on process exit; no action required
}

int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {
    const char *shm_path = NULL;
    size_t size = g_map_size;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "shm=", 4) == 0) {
            shm_path = argv[i] + 4;
        } else if (strncmp(argv[i], "size=", 5) == 0) {
            size = strtoull(argv[i] + 5, NULL, 0);
        }
    }
    if (!shm_path) {
        fprintf(stderr, "fz_bbcov: missing shm=PATH plugin argument\n");
        return -1;
    }
    if (size == 0) size = 64 * 1024;
    // map_size must be power of two for fast masking
    size_t mask = size - 1;
    if ((size & mask) != 0) {
        // round up to next power of two
        size_t v = 1;
        while (v < size) v <<= 1;
        size = v;
    }

    int fd = open(shm_path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "fz_bbcov: open %s failed: %s\n", shm_path, strerror(errno));
        return -1;
    }
    g_map = (uint8_t*)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (g_map == MAP_FAILED) {
        fprintf(stderr, "fz_bbcov: mmap failed: %s\n", strerror(errno));
        g_map = NULL;
        return -1;
    }
    g_map_size = size;

    g_prev_count = info->n_vcpus;
    if (g_prev_count == 0) g_prev_count = 1;
    g_prev = calloc(g_prev_count, sizeof(*g_prev));

    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, detach_cleanup, NULL);
    return 0;
}

