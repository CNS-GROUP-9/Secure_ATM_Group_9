#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "crypto.h"
#include "network.h"
#include "protocol.h"
#include <openssl/rand.h>
#include <errno.h>
#include <ctype.h>

static int write_card_file(const char *path, const char *card_hex)
{
    FILE *f;
    size_t written;

    if (path == NULL || card_hex == NULL)
    {
        return -1;
    }

    f = fopen(path, "wb");
    if (!f)
    {
        return -1;
    }

    written = fwrite(card_hex, 1, AUTH_SECRET_BYTES * 2, f);
    if (written != AUTH_SECRET_BYTES * 2)
    {
        fclose(f);
        unlink(path);
        return -1;
    }

    if (fputc('\n', f) == EOF)
    {
        fclose(f);
        unlink(path);
        return -1;
    }

    if (fflush(f) != 0)
    {
        fclose(f);
        unlink(path);
        return -1;
    }

    if (fclose(f) != 0)
    {
        unlink(path);
        return -1;
    }

    return 0;
}

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

    /* card handling: on create (-n) generate new card secret and write to card file; otherwise read card file */
    request.card_hex[0] = '\0';
    if (args.mode == 1) /* create */
    {
        unsigned char card_secret[AUTH_SECRET_BYTES];
        static const char digits[] = "0123456789abcdef";
        size_t i;

        if (access(args.card_file, F_OK) == 0)
        {
            /* already exists */
            exit(255);
        }
        if (RAND_bytes(card_secret, sizeof(card_secret)) != 1)
        {
            exit(255);
        }
        for (i = 0; i < sizeof(card_secret); i++)
        {
            request.card_hex[i * 2] = digits[(card_secret[i] >> 4) & 0xF];
            request.card_hex[i * 2 + 1] = digits[card_secret[i] & 0xF];
        }
        request.card_hex[AUTH_SECRET_BYTES * 2] = '\0';
        crypto_secure_memzero(card_secret, sizeof(card_secret));
    }
    else
    {
        /* read existing card file */
        FILE *f = fopen(args.card_file, "rb");
        if (!f)
        {
            exit(255);
        }
        char line[AUTH_SECRET_BYTES * 2 + 16];
        if (fgets(line, sizeof(line), f) == NULL)
        {
            fclose(f);
            exit(255);
        }
        fclose(f);
        size_t len = strcspn(line, "\r\n");
        if (len != AUTH_SECRET_BYTES * 2)
        {
            exit(255);
        }
        memcpy(request.card_hex, line, AUTH_SECRET_BYTES * 2);
        request.card_hex[AUTH_SECRET_BYTES * 2] = '\0';
        /* validate hex chars */
        for (size_t i = 0; i < AUTH_SECRET_BYTES * 2; ++i)
        {
            if (!isxdigit((unsigned char)request.card_hex[i]))
            {
                exit(255);
            }
        }
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

    /* wait for response */
    int resp_len = receive_message(sock, (void **)&wire);
    if (resp_len < 0)
    {
        crypto_secure_memzero(wire, wire_len);
        free(wire);
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }

    uint8_t *resp_plain = NULL;
    size_t resp_plain_len = 0;
    if (crypto_verify_then_decrypt(&keys, wire, (size_t)resp_len, &resp_plain, &resp_plain_len) != 0)
    {
        free(wire);
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }
    free(wire);

    ProtocolResponse response;
    if (proto_deserialize_response(resp_plain, resp_plain_len, &response) != 0)
    {
        crypto_secure_memzero(resp_plain, resp_plain_len);
        free(resp_plain);
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(63);
    }

    /* business failure (ok==0) -> ATM should exit 255 per spec */
    if (!response.ok)
    {
        crypto_secure_memzero(resp_plain, resp_plain_len);
        free(resp_plain);
        close(sock);
        crypto_secure_memzero(&keys, sizeof(keys));
        exit(255);
    }

    if (args.mode == 1)
    {
        if (write_card_file(args.card_file, request.card_hex) != 0)
        {
            crypto_secure_memzero(resp_plain, resp_plain_len);
            free(resp_plain);
            close(sock);
            crypto_secure_memzero(&keys, sizeof(keys));
            exit(255);
        }
    }

    /* helper: format cents -> minimal decimal string */
    char amt_buf[64];
    uint64_t cents = response.amount_cents;
    if ((cents % 100) == 0)
    {
        snprintf(amt_buf, sizeof(amt_buf), "%llu", (unsigned long long)(cents / 100));
    }
    else if ((cents % 10) == 0)
    {
        /* one decimal */
        snprintf(amt_buf, sizeof(amt_buf), "%llu.%llu", (unsigned long long)(cents / 100), (unsigned long long)((cents % 100) / 10));
    }
    else
    {
        snprintf(amt_buf, sizeof(amt_buf), "%llu.%02llu", (unsigned long long)(cents / 100), (unsigned long long)(cents % 100));
    }

    if (args.mode == 1)
    {
        printf("{\"account\":\"%s\",\"initial_balance\":%s}\n", request.account, amt_buf);
    }
    else if (args.mode == 2)
    {
        printf("{\"account\":\"%s\",\"deposit\":%s}\n", request.account, amt_buf);
    }
    else if (args.mode == 3)
    {
        printf("{\"account\":\"%s\",\"withdraw\":%s}\n", request.account, amt_buf);
    }
    else if (args.mode == 4)
    {
        printf("{\"account\":\"%s\",\"balance\":%s}\n", request.account, amt_buf);
    }
    fflush(stdout);

    crypto_secure_memzero(resp_plain, resp_plain_len);
    free(resp_plain);
    close(sock);
    crypto_secure_memzero(&keys, sizeof(keys));
    return 0;
}
