#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
 * Minimal preload stub library.
 * If FZ_PRELOAD_DATA_B64 is set, a background thread decodes it and attempts
 * to connect to 127.0.0.1:9999 (or NETSTUB_PORT) to send the bytes. This is
 * a best-effort helper to drive simple local servers during tests.
 */

static void *sender_thread(void *arg) {
    (void)arg;
    const char *b64 = getenv("FZ_PRELOAD_DATA_B64");
    if (!b64 || !*b64) return NULL;
    int port = 9999;
    const char *p = getenv("NETSTUB_PORT");
    if (p && *p) port = atoi(p);

    /* naive base64 decode using openssl-ish table */
    static const unsigned char T[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
        ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
        ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
        ['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,
        ['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,
        ['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,
        ['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
        ['8']=60,['9']=61,['+']=62,['/']=63
    };
    size_t len = strlen(b64);
    unsigned char *buf = malloc(len);
    if (!buf) return NULL;
    size_t i = 0, j = 0;
    while (i + 3 < len) {
        unsigned char a = T[(unsigned char)b64[i++]];
        unsigned char b = T[(unsigned char)b64[i++]];
        unsigned char c = b64[i] == '=' ? 0 : T[(unsigned char)b64[i]]; i++;
        unsigned char d = b64[i] == '=' ? 0 : T[(unsigned char)b64[i]]; i++;
        buf[j++] = (a << 2) | (b >> 4);
        if (b64[i-2] != '=') buf[j++] = (b << 4) | (c >> 2);
        if (b64[i-1] != '=') buf[j++] = (c << 6) | d;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        /* retry a few times to allow server to start */
        for (int t = 0; t < 30; t++) {
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                (void)send(s, buf, (int)j, 0);
                (void)shutdown(s, SHUT_RDWR);
                break;
            }
            usleep(100 * 1000);
        }
        close(s);
    }
    free(buf);
    return NULL;
}

__attribute__((constructor)) static void netstub_init(void) {
    pthread_t th;
    pthread_create(&th, NULL, sender_thread, NULL);
    pthread_detach(th);
}

/* Best-effort "single-iteration" helpers for simple fork-per-connection servers. */

pid_t fork(void) {
    return 0;
}

unsigned int sleep(unsigned int seconds) {
    (void)seconds;
    return 0;
}
