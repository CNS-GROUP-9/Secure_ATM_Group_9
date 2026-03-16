#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "network.h"

int main(int argc, char **argv) {
    ATMArgs args;
    if (parse_atm_args(argc, argv, &args) != 0) {
        exit(255);
    }

    int sock = connect_to_bank(args.ip, args.port);
    if (sock < 0) {
        exit(63);
    }
    if (set_socket_timeout_seconds(sock, 10) != 0) {
        close(sock);
        exit(63);
    }

    char msg[256];
    sprintf(msg, "hello from atm (mode=%d)", args.mode);
    if (send_message(sock, msg, (int)strlen(msg)) != 0) {
        close(sock);
        exit(63);
    }

    close(sock);
    return 0;
}
