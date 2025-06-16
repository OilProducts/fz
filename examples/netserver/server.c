#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>

#define PORT 9000
#define BACKLOG 8

static void *handle_client(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        close(fd);
        return NULL;
    }
    buf[n] = '\0';

    if (strncmp(buf, "OVERFLOW:", 9) == 0) {
        char small[8];
        /* Intentional overflow when input after prefix exceeds 7 bytes */
        strcpy(small, buf + 9);
    } else if (strncmp(buf, "DOUBLEFREE", 10) == 0) {
        char *p = malloc(8);
        strcpy(p, buf); /* Potential overflow */
        free(p);
        free(p); /* Crash via double free */
    } else if (strncmp(buf, "CRASH", 5) == 0) {
        int *p = NULL;
        *p = 42; /* Null dereference */
    }

    sleep(3); /* Keep the connection open for a few seconds */
    close(fd);
    return NULL;
}

int main(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(srv, BACKLOG) < 0) {
        perror("listen");
        return 1;
    }

    while (1) {
        int *fd = malloc(sizeof(int));
        *fd = accept(srv, NULL, NULL);
        if (*fd >= 0) {
            pthread_t tid;
            pthread_create(&tid, NULL, handle_client, fd);
            pthread_detach(tid);
        } else {
            free(fd);
        }
    }
    return 0;
}
