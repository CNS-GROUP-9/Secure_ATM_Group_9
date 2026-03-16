#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "crypto.h"
#include "network.h"
#include "protocol.h"

int main(int argc, char **argv)
{
    ATMArgs args;
    uint8_t auth_secret[AUTH_SECRET_BYTES];
    CryptoKeys keys;
    ProtocolRequest request;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;

    if (parse_atm_args(argc, argv, &args) != 0)
    {
        exit(255);
    }

    memset(&request, 0, sizeof(request));
    if (snprintf(request.account, sizeof(request.account), "%s", args.account) <= 0)
    {
        exit(255);
    }
    if (proto_operation_from_mode(args.mode, &request.operation) != 0)
    {
        exit(255);
    }
    if (request.operation == PROTO_OP_GET)
    {
        request.has_amount = 0;
    }
    else
    {
        request.has_amount = 1;
        if (proto_amount_to_cents(args.amount, &request.amount_cents) != 0)
        {
            exit(255);
        }
    }
    if (proto_generate_nonce(&request.nonce) != 0)
    {
        exit(255);
    }
    if (proto_serialize_request(&request, &plaintext, &plaintext_len) != 0)
    {
        exit(255);
    }

    if (crypto_load_auth_secret(args.auth_file, auth_secret) != 0)
    {
        free(plaintext);
        exit(255);
    }
    if (crypto_derive_keys(auth_secret, &keys) != 0)
    {
        crypto_secure_memzero(auth_secret, sizeof(auth_secret));
        free(plaintext);
        exit(255);
    }
    crypto_secure_memzero(auth_secret, sizeof(auth_secret));

    int sock = connect_to_bank(args.ip, args.port);
    if (sock < 0)
    {
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }
    if (set_socket_timeout_seconds(sock, 10) != 0)
    {
        close(sock);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (crypto_encrypt_then_mac(&keys, plaintext, plaintext_len, &wire, &wire_len) != 0)
    {
        close(sock);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(255);
    }
    crypto_secure_memzero(plaintext, plaintext_len);
    free(plaintext);

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
