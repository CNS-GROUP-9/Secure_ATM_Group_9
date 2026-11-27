#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "crypto.h"
#include "network.h"
#include "protocol.h"

/* State that must be cleaned up on every exit path. */
static CryptoKeys g_keys;
static int g_sock = -1;
static const char *g_new_card_path = NULL; /* card file created by this run, removed on failure */

static void finish(int code)
{
    if (g_sock >= 0)
    {
        close(g_sock);
    }
    if (g_new_card_path != NULL)
    {
        unlink(g_new_card_path);
    }
    crypto_secure_memzero(&g_keys, sizeof(g_keys));
    exit(code);
}

/*
 * Creates the card file BEFORE talking to the bank, so an unwritable card
 * location can never leave an orphaned account on the bank (issue #3).
 *   O_EXCL     : fails if the file already exists (no TOCTOU with access()).
 *   O_NOFOLLOW : refuses to write through a symlink (issue #28).
 *   0600       : only the owner can read the card secret (issue #13).
 */
static int create_card_file(const char *path, const char *card_hex)
{
    char buf[CARD_SECRET_BYTES * 2 + 1];
    size_t off = 0;
    int fd;
    int rc = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
    {
        return -1;
    }
    g_new_card_path = path; /* from here on, any failure removes it */

    memcpy(buf, card_hex, CARD_SECRET_BYTES * 2);
    buf[CARD_SECRET_BYTES * 2] = '\n';

    while (off < sizeof(buf))
    {
        ssize_t n = write(fd, buf + off, sizeof(buf) - off);
        if (n < 0 && errno == EINTR)
        {
            continue;
        }
        if (n <= 0)
        {
            rc = -1;
            break;
        }
        off += (size_t)n;
    }
    if (rc == 0 && fsync(fd) < 0)
    {
        rc = -1;
    }
    if (close(fd) < 0)
    {
        rc = -1;
    }
    crypto_secure_memzero(buf, sizeof(buf));
    return rc;
}

/* Receives one secure message; any failure is a protocol error (exit 63). */
static void recv_or_die(uint8_t **plain, size_t *plain_len)
{
    if (proto_recv_secure(g_sock, &g_keys, plain, plain_len) != 0)
    {
        finish(63);
    }
}

static void send_or_die(uint8_t *plain, size_t plain_len)
{
    int rc = proto_send_secure(g_sock, &g_keys, plain, plain_len);
    crypto_secure_memzero(plain, plain_len);
    free(plain);
    if (rc != 0)
    {
        finish(63);
    }
}

int main(int argc, char **argv)
{
    static const char *const out_keys[] = {"", "initial_balance", "deposit", "withdraw", "balance"};
    ATMArgs args;
    uint8_t secret[AUTH_SECRET_BYTES];
    ProtocolRequest request;
    ProtocolResponse response;
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    char amt_buf[64];
    int rc;

    signal(SIGPIPE, SIG_IGN);

    if (parse_atm_args(argc, argv, &args) != 0)
    {
        finish(255);
    }

    memset(&request, 0, sizeof(request));
    snprintf(request.account, sizeof(request.account), "%s", args.account);
    if (proto_operation_from_mode(args.mode, &request.operation) != 0)
    {
        finish(255);
    }
    if (request.operation != PROTO_OP_GET)
    {
        request.has_amount = 1;
        if (proto_amount_to_cents(args.amount, &request.amount_cents) != 0)
        {
            finish(255);
        }
    }

    /* Shared auth secret -> session keys. */
    if (crypto_load_auth_secret(args.auth_file, secret) != 0)
    {
        finish(255);
    }
    rc = crypto_derive_keys(secret, &g_keys);
    crypto_secure_memzero(secret, sizeof(secret));
    if (rc != 0)
    {
        finish(255);
    }

    /* Card secret: new random one for create, otherwise read the existing card (strictly). */
    if (request.operation == PROTO_OP_CREATE)
    {
        if (crypto_random_bytes(secret, CARD_SECRET_BYTES) != 0)
        {
            finish(255);
        }
        crypto_hex_encode(secret, CARD_SECRET_BYTES, request.card_hex);
        crypto_secure_memzero(secret, sizeof(secret));
        if (create_card_file(args.card_file, request.card_hex) != 0)
        {
            finish(255);
        }
    }
    else
    {
        if (crypto_read_secret_file(args.card_file, secret) != 0)
        {
            finish(255);
        }
        crypto_hex_encode(secret, CARD_SECRET_BYTES, request.card_hex);
        crypto_secure_memzero(secret, sizeof(secret));
    }

    g_sock = connect_to_bank(args.ip, args.port, NET_TIMEOUT_SECONDS);
    if (g_sock < 0 || set_socket_timeout_seconds(g_sock, NET_TIMEOUT_SECONDS) != 0)
    {
        finish(63);
    }

    /* 1. CHALLENGE from the bank: fresh server nonce for this session. */
    recv_or_die(&plain, &plain_len);
    rc = proto_deserialize_challenge(plain, plain_len, request.snonce);
    free(plain);
    if (rc != 0)
    {
        finish(63);
    }

    /* 2. REQUEST, bound to the server nonce plus our own fresh client nonce. */
    if (proto_generate_nonce(request.cnonce) != 0 ||
        proto_serialize_request(&request, &plain, &plain_len) != 0)
    {
        finish(255);
    }
    send_or_die(plain, plain_len);

    /* 3. RESPONSE must answer exactly this request (no replayed/foreign responses). */
    recv_or_die(&plain, &plain_len);
    rc = proto_deserialize_response(plain, plain_len, &response);
    crypto_secure_memzero(plain, plain_len);
    free(plain);
    if (rc != 0 ||
        !proto_nonce_equal(response.snonce, request.snonce) ||
        !proto_nonce_equal(response.cnonce, request.cnonce) ||
        strcmp(response.account, request.account) != 0 ||
        response.operation != request.operation)
    {
        finish(63);
    }

    if (!response.ok)
    {
        finish(255); /* business failure: bank refused, nothing was changed */
    }
    if (!response.has_amount ||
        (request.operation != PROTO_OP_GET && response.amount_cents != request.amount_cents))
    {
        finish(63);
    }

    /* 4. COMMIT for state-changing operations; the bank only applies it on receipt. */
    if (request.operation != PROTO_OP_GET)
    {
        if (proto_serialize_commit(request.snonce, request.cnonce, &plain, &plain_len) != 0)
        {
            finish(63);
        }
        send_or_die(plain, plain_len);
    }

    g_new_card_path = NULL; /* transaction done: keep the card */

    proto_format_amount(response.amount_cents, amt_buf, sizeof(amt_buf));
    printf("{\"account\":\"%s\",\"%s\":%s}\n", request.account, out_keys[request.operation], amt_buf);
    fflush(stdout);

    crypto_secure_memzero(&request, sizeof(request));
    finish(0);
    return 0;
}
