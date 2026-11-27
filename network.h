#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define NET_TIMEOUT_SECONDS 10

int connect_to_bank(const char *ip, int port, int timeout_seconds);
int listen_on_port(int port);
int set_socket_timeout_seconds(int sock, int seconds);
int send_message(int sock, const void *buffer, size_t size);
int receive_message(int sock, void **buffer);

#endif
