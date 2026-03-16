#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "crypto.h"
#include "network.h"

int main(int argc, char **argv)
{
    ATMArgs args;
    uint8_t auth_secret[AUTH_SECRET_BYTES];
    CryptoKeys keys;

    if (parse_atm_args(argc, argv, &args) != 0)
    {
        exit(255);
    }

    if (crypto_load_auth_secret(args.auth_file, auth_secret) != 0)
    {
        exit(255);
    }
    if (crypto_derive_keys(auth_secret, &keys) != 0)
    {
        crypto_secure_memzero(auth_secret, sizeof(auth_secret));
        exit(255);
    }
    crypto_secure_memzero(auth_secret, sizeof(auth_secret));

    int sock = connect_to_bank(args.ip, args.port);
    if (sock < 0)
    {
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }
    if (set_socket_timeout_seconds(sock, 10) != 0)
    {
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }

    char msg[256];
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int msg_len = snprintf(msg, sizeof(msg), "hello from atm (mode=%d)", args.mode);
    if (msg_len < 0 || (size_t)msg_len >= sizeof(msg))
    {
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(255);
    }

    if (crypto_encrypt_then_mac(&keys, (const uint8_t *)msg, (size_t)msg_len, &wire, &wire_len) != 0)
    {
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(255);
    }

    if (wire_len > 2147483647ULL || send_message(sock, wire, (int)wire_len) != 0)
    {
        crypto_secure_memzero(wire, wire_len);
        free(wire);
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }

    crypto_secure_memzero(wire, wire_len);
    free(wire);
    close(sock);
    crypto_secure_memzero(&keys, sizeof(keys));
    return 0;
}
