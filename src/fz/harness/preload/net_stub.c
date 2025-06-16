#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stddef.h>

static int dummy_listen_fd = 10000;
static int dummy_conn_fd = 10001;
static int accepted = 0;

int socket(int domain, int type, int protocol) {
    (void)domain; (void)type; (void)protocol;
    return dummy_listen_fd;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    return 0;
}

int listen(int sockfd, int backlog) {
    (void)sockfd; (void)backlog;
    return 0;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    (void)sockfd; (void)level; (void)optname; (void)optval; (void)optlen;
    return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    (void)sockfd; (void)addr; (void)addrlen;
    if (accepted) {
        errno = EAGAIN;
        return -1;
    }
    accepted = 1;
    return dummy_conn_fd;
}

static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static int (*real_close)(int) = NULL;

static void _init(void) __attribute__((constructor));
static void _init(void) {
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_send = dlsym(RTLD_NEXT, "send");
    real_close = dlsym(RTLD_NEXT, "close");
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    if (fd == dummy_conn_fd) {
        return read(STDIN_FILENO, buf, len);
    }
    return real_recv(fd, buf, len, flags);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    if (fd == dummy_conn_fd) {
        return write(STDOUT_FILENO, buf, len);
    }
    return real_send(fd, buf, len, flags);
}

int close(int fd) {
    if (fd == dummy_conn_fd || fd == dummy_listen_fd) {
        return 0;
    }
    return real_close(fd);
}
