#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include "network.h"

#define MAX_FRAME_SIZE (1024U * 1024U)

/* Never let a peer that closed early kill the process with SIGPIPE. */
#ifdef MSG_NOSIGNAL
#define SEND_FLAGS MSG_NOSIGNAL
#else
#define SEND_FLAGS 0
#endif

static void disable_sigpipe(int sock)
{
#ifdef SO_NOSIGPIPE
    int one = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)sock;
#endif
}

static int send_all(int sock, const void *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(sock, (const char *)buf + sent, len - sent, SEND_FLAGS);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

static int recv_all(int sock, void *buf, size_t len) {
    size_t recvd = 0;

    while (recvd < len) {
        ssize_t n = recv(sock, (char *)buf + recvd, len - recvd, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return -1;
        }
        recvd += (size_t)n;
    }

    return 0;
}

/*
 * Non-blocking connect + poll so an unreachable/black-holed IP fails after
 * timeout_seconds instead of hanging for the OS default (minutes).
 */
int connect_to_bank(const char *ip, int port, int timeout_seconds) {
    struct sockaddr_in server;
    int sock;
    int flags;
    int rc;

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &server.sin_addr) != 1) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    disable_sigpipe(sock);

    flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    rc = connect(sock, (struct sockaddr *)&server, sizeof(server));
    if (rc < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    if (rc < 0) {
        struct pollfd pfd;
        int so_error = 0;
        socklen_t so_len = sizeof(so_error);

        pfd.fd = sock;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        do {
            rc = poll(&pfd, 1, timeout_seconds * 1000);
        } while (rc < 0 && errno == EINTR);

        if (rc <= 0 ||
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &so_len) < 0 ||
            so_error != 0) {
            close(sock);
            return -1;
        }
    }

    if (fcntl(sock, F_SETFL, flags) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int listen_on_port(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    /*
     * SO_REUSEADDR only (so a restarted bank can rebind while old connections
     * sit in TIME_WAIT). SO_REUSEPORT is deliberately NOT set: it would let
     * another local process bind the same port and steal connections.
     * Note: socket option names are not bit flags and must not be OR'ed.
     */
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons((uint16_t)port);

    if (bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return -1;
    }

    if (listen(sock, 64) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

int set_socket_timeout_seconds(int sock, int seconds) {
    struct timeval tv;

    disable_sigpipe(sock);

    tv.tv_sec = seconds;
    tv.tv_usec = 0;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return -1;
    }

    return 0;
}

int send_message(int sock, const void *buffer, size_t size) {
    uint32_t len;

    if (size > MAX_FRAME_SIZE) {
        return -1;
    }

    len = htonl((uint32_t)size);
    if (send_all(sock, &len, sizeof(len)) < 0) {
        return -1;
    }

    if (size == 0) {
        return 0;
    }

    if (send_all(sock, buffer, size) < 0) {
        return -1;
    }

    return 0;
}

int receive_message(int sock, void **buffer) {
    uint32_t len_n = 0;
    uint32_t len = 0;

    *buffer = NULL;

    if (recv_all(sock, &len_n, sizeof(len_n)) < 0) {
        return -1;
    }

    len = ntohl(len_n);
    if (len > MAX_FRAME_SIZE) {
        return -1;
    }

    *buffer = malloc(len + 1);
    if (!*buffer) {
        return -1;
    }

    if (len > 0 && recv_all(sock, *buffer, len) < 0) {
        free(*buffer);
        *buffer = NULL;
        return -1;
    }

    ((char*)*buffer)[len] = '\0';
    return (int)len;
}
