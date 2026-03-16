#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int connect_to_bank(char *ip, int port);
int listen_on_port(int port);
int set_socket_timeout_seconds(int sock, int seconds);
int send_message(int sock, void *buffer, int size);
int receive_message(int sock, void **buffer);

#endif
