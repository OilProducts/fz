// target4.c - network service with multiple vulnerabilities
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9999

static void handle_client(int connfd) {
    char buf[256];
    ssize_t n = recv(connfd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(connfd);
        exit(0);
    }
    buf[n] = '\0';

    if (strncmp(buf, "OVERFLOW:", 9) == 0) {
        char small[8];
        /* Intentional overflow when input after the prefix exceeds 7 bytes */
        strcpy(small, buf + 9);
    } else if (strncmp(buf, "MAGIC1234", 9) == 0) {
        /* Difficult path: requires exact MAGIC1234 prefix */
        char *p = NULL;
        *p = 'X'; /* crash via NULL dereference */
    } else if (strncmp(buf, "DIVZERO:", 8) == 0) {
        int val = atoi(buf + 8);
        int res = 100 / val; /* crash when val==0 */
        (void)res;
    } else if (strncmp(buf, "WAIT", 4) == 0) {
        sleep(5); /* keep connection open longer */
    }

    /* Keep connection open a little while regardless */
    sleep(2);
    send(connfd, "ok\n", 3, 0);
    close(connfd);
    exit(0);
}

int main(void) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("socket");
        return 1;
    }
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(PORT);

    if (bind(listenfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(listenfd, 5) < 0) {
        perror("listen");
        return 1;
    }

    printf("Listening on port %d\n", PORT);
    signal(SIGCHLD, SIG_IGN); /* avoid zombies */

    while (1) {
        int connfd = accept(listenfd, NULL, NULL);
        if (connfd < 0) {
            continue;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(listenfd);
            handle_client(connfd);
        } else if (pid > 0) {
            close(connfd);
        }
    }
    return 0;
}
