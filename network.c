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

static int send_all(int sock, const void *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(sock, (const char *)buf + sent, len - sent, 0);
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
        if (n <= 0) {
            return -1;
        }
        recvd += (size_t)n;
    }

    return 0;
}

int connect_to_bank(char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int listen_on_port(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        return -1;
    }

    if (listen(sock, 10) < 0) {
        return -1;
    }

    return sock;
}

int set_socket_timeout_seconds(int sock, int seconds) {
    struct timeval tv;

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

int send_message(int sock, void *buffer, int size) {
    uint32_t len;

    if (size < 0) {
        return -1;
    }

    len = htonl((uint32_t)size);
    if (send_all(sock, &len, sizeof(len)) < 0) {
        return -1;
    }

    if (size == 0) {
        return 0;
    }

    if (send_all(sock, buffer, (size_t)size) < 0) {
        return -1;
    }

    return 0;
}

int receive_message(int sock, void **buffer) {
    uint32_t len_n = 0;
    uint32_t len = 0;

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

    ((char*)*buffer)[len] = '\0'; // Just to be safe for strings
    return (int)len;
}
