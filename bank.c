#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"
#include "crypto.h"
#include "network.h"
#include "protocol.h"

static volatile sig_atomic_t g_running = 1;
static int g_listen_sock = -1;
static CryptoKeys g_keys;

#define NONCE_WINDOW 64

typedef struct Account
{
    char name[PROTOCOL_MAX_ACCOUNT_LEN + 1];
    uint64_t balance_cents;
    char card_hex[AUTH_SECRET_BYTES * 2 + 1];
    uint64_t nonces[NONCE_WINDOW];
    size_t nonce_count;
    size_t nonce_next;
    struct Account *next;
} Account;

static Account *g_accounts = NULL;
static pthread_mutex_t g_accounts_lock = PTHREAD_MUTEX_INITIALIZER;

static int card_hex_valid(const char *card_hex)
{
    size_t i;
    if (card_hex == NULL)
    {
        return 0;
    }
    if (strlen(card_hex) != AUTH_SECRET_BYTES * 2)
    {
        return 0;
    }
    for (i = 0; i < AUTH_SECRET_BYTES * 2; i++)
    {
        unsigned char c = (unsigned char)card_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
        {
            return 0;
        }
    }
    return 1;
}

static int nonce_seen(const Account *account, uint64_t nonce)
{
    size_t i;
    for (i = 0; i < account->nonce_count; i++)
    {
        if (account->nonces[i] == nonce)
        {
            return 1;
        }
    }
    return 0;
}

static void nonce_add(Account *account, uint64_t nonce)
{
    if (account->nonce_count < NONCE_WINDOW)
    {
        account->nonces[account->nonce_count++] = nonce;
        return;
    }
    account->nonces[account->nonce_next] = nonce;
    account->nonce_next = (account->nonce_next + 1) % NONCE_WINDOW;
}

static int write_all(int fd, const void *buf, size_t len)
{
    size_t off = 0;

    while (off < len)
    {
        ssize_t n = write(fd, (const char *)buf + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }

    return 0;
}

static int create_auth_file(const char *path)
{
    int fd;
    int rnd;
    unsigned char secret[32];
    char hex[65];
    static const char digits[] = "0123456789abcdef";
    size_t i;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
    {
        return -1;
    }

    rnd = open("/dev/urandom", O_RDONLY);
    if (rnd < 0)
    {
        close(fd);
        return -1;
    }

    if (read(rnd, secret, sizeof(secret)) != (ssize_t)sizeof(secret))
    {
        close(rnd);
        close(fd);
        return -1;
    }
    close(rnd);

    for (i = 0; i < sizeof(secret); i++)
    {
        hex[i * 2] = digits[(secret[i] >> 4) & 0xF];
        hex[i * 2 + 1] = digits[secret[i] & 0xF];
    }
    hex[64] = '\n';

    if (write_all(fd, hex, sizeof(hex)) < 0)
    {
        close(fd);
        return -1;
    }

    if (fsync(fd) < 0)
    {
        close(fd);
        return -1;
    }

    if (close(fd) < 0)
    {
        return -1;
    }

    return 0;
}

static void on_sigterm(int signum)
{
    (void)signum;
    g_running = 0;
    if (g_listen_sock >= 0)
    {
        close(g_listen_sock);
        g_listen_sock = -1;
    }
}

static void *handle_client(void *arg)
{
    int client = *(int *)arg;
    void *msg = NULL;
    uint8_t *plaintext = NULL;
    size_t plaintext_len = 0;
    ProtocolRequest request;
    int len;

    free(arg);

    (void)set_socket_timeout_seconds(client, 10);

    len = receive_message(client, &msg);
    if (len < 0)
    {
        printf("protocol_error\n");
        fflush(stdout);
        close(client);
        return NULL;
    }

    if (crypto_verify_then_decrypt(&g_keys, (const uint8_t *)msg, (size_t)len, &plaintext, &plaintext_len) != 0)
    {
        free(msg);
        printf("protocol_error\n");
        fflush(stdout);
        close(client);
        return NULL;
    }

    if (proto_deserialize_request(plaintext, plaintext_len, &request) != 0)
    {
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        free(msg);
        printf("protocol_error\n");
        fflush(stdout);
        close(client);
        return NULL;
    }

    ProtocolResponse response;
    memset(&response, 0, sizeof(response));
    snprintf(response.account, sizeof(response.account), "%s", request.account);

    int send_protocol_error = 0;
    int business_fail = 0;
    int commit_required = 0;
    int is_create_commit = 0;
    uint64_t pending_delta = 0;
    uint64_t pending_nonce = request.nonce;
    Account *commit_account = NULL;
    Account *new_account = NULL;

    pthread_mutex_lock(&g_accounts_lock);

    /* find account */
    Account *cur = g_accounts;
    Account *found = NULL;
    while (cur)
    {
        if (strcmp(cur->name, request.account) == 0)
        {
            found = cur;
            break;
        }
        cur = cur->next;
    }

    if (request.operation == PROTO_OP_CREATE)
    {
        if (request.has_amount == 0 || !card_hex_valid(request.card_hex))
        {
            send_protocol_error = 1;
        }
        else if (found != NULL)
        {
            /* account exists */
            business_fail = 1;
        }
        else
        {
            new_account = (Account *)malloc(sizeof(Account));
            if (!new_account)
            {
                send_protocol_error = 1;
            }
            else
            {
                memset(new_account, 0, sizeof(*new_account));
                snprintf(new_account->name, sizeof(new_account->name), "%s", request.account);
                new_account->balance_cents = request.amount_cents;
                snprintf(new_account->card_hex, sizeof(new_account->card_hex), "%s", request.card_hex);
                response.ok = 1;
                response.has_amount = 1;
                response.amount_cents = new_account->balance_cents;
                commit_required = 1;
                is_create_commit = 1;
            }
        }
    }
    else if (request.operation == PROTO_OP_DEPOSIT)
    {
        if (request.has_amount == 0 || !card_hex_valid(request.card_hex))
        {
            send_protocol_error = 1;
        }
        else if (found == NULL)
        {
            business_fail = 1;
        }
        else if (strcmp(found->card_hex, request.card_hex) != 0)
        {
            business_fail = 1;
        }
        else if (nonce_seen(found, request.nonce))
        {
            send_protocol_error = 1;
        }
        else if (UINT64_MAX - found->balance_cents < request.amount_cents)
        {
            business_fail = 1;
        }
        else
        {
            response.ok = 1;
            response.has_amount = 1;
            response.amount_cents = request.amount_cents;
            commit_required = 1;
            pending_delta = request.amount_cents;
            commit_account = found;
        }
    }
    else if (request.operation == PROTO_OP_WITHDRAW)
    {
        if (request.has_amount == 0 || !card_hex_valid(request.card_hex))
        {
            send_protocol_error = 1;
        }
        else if (found == NULL)
        {
            business_fail = 1;
        }
        else if (strcmp(found->card_hex, request.card_hex) != 0)
        {
            business_fail = 1;
        }
        else if (nonce_seen(found, request.nonce))
        {
            send_protocol_error = 1;
        }
        else if (found->balance_cents < request.amount_cents)
        {
            business_fail = 1;
        }
        else
        {
            response.ok = 1;
            response.has_amount = 1;
            response.amount_cents = request.amount_cents;
            commit_required = 1;
            pending_delta = request.amount_cents;
            commit_account = found;
        }
    }
    else if (request.operation == PROTO_OP_GET)
    {
        if (!card_hex_valid(request.card_hex))
        {
            send_protocol_error = 1;
        }
        else if (found == NULL)
        {
            business_fail = 1;
        }
        else if (strcmp(found->card_hex, request.card_hex) != 0)
        {
            business_fail = 1;
        }
        else if (nonce_seen(found, request.nonce))
        {
            send_protocol_error = 1;
        }
        else
        {
            response.ok = 1;
            response.has_amount = 1;
            response.amount_cents = found->balance_cents;
            commit_account = found;
        }
    }
    else
    {
        send_protocol_error = 1;
    }

    if (business_fail)
    {
        response.ok = 0;
        response.has_amount = 0;
        response.amount_cents = 0;
    }

    /* prepare output amount text while still under lock */
    char amt_buf[64];
    if (response.has_amount)
    {
        uint64_t cents = response.amount_cents;
        if ((cents % 100) == 0)
        {
            snprintf(amt_buf, sizeof(amt_buf), "%llu", (unsigned long long)(cents / 100));
        }
        else if ((cents % 10) == 0)
        {
            snprintf(amt_buf, sizeof(amt_buf), "%llu.%llu", (unsigned long long)(cents / 100), (unsigned long long)((cents % 100) / 10));
        }
        else
        {
            snprintf(amt_buf, sizeof(amt_buf), "%llu.%02llu", (unsigned long long)(cents / 100), (unsigned long long)(cents % 100));
        }
    }

    if (send_protocol_error)
    {
        pthread_mutex_unlock(&g_accounts_lock);
        if (new_account != NULL)
        {
            free(new_account);
        }
        printf("protocol_error\n");
        fflush(stdout);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        free(msg);
        close(client);
        return NULL;
    }

    /* build response, serialize, encrypt, and send back */
    uint8_t *resp_plain = NULL;
    size_t resp_plain_len = 0;
    if (proto_serialize_response(&response, &resp_plain, &resp_plain_len) != 0)
    {
        pthread_mutex_unlock(&g_accounts_lock);
        if (new_account != NULL)
        {
            free(new_account);
        }
        printf("protocol_error\n");
        fflush(stdout);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        free(msg);
        close(client);
        return NULL;
    }

    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (crypto_encrypt_then_mac(&g_keys, resp_plain, resp_plain_len, &wire, &wire_len) != 0)
    {
        pthread_mutex_unlock(&g_accounts_lock);
        if (new_account != NULL)
        {
            free(new_account);
        }
        crypto_secure_memzero(resp_plain, resp_plain_len);
        free(resp_plain);
        printf("protocol_error\n");
        fflush(stdout);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        free(msg);
        close(client);
        return NULL;
    }

    crypto_secure_memzero(resp_plain, resp_plain_len);
    free(resp_plain);

    if (wire_len > 2147483647ULL || send_message(client, wire, (int)wire_len) != 0)
    {
        pthread_mutex_unlock(&g_accounts_lock);
        if (new_account != NULL)
        {
            free(new_account);
        }
        crypto_secure_memzero(wire, wire_len);
        free(wire);
        printf("protocol_error\n");
        fflush(stdout);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        free(msg);
        close(client);
        return NULL;
    }

    crypto_secure_memzero(wire, wire_len);
    free(wire);

    /* apply commit only after successful response send */
    if (!business_fail)
    {
        if (is_create_commit && new_account != NULL)
        {
            nonce_add(new_account, pending_nonce);
            new_account->next = g_accounts;
            g_accounts = new_account;
            new_account = NULL;
        }
        else if (commit_required && commit_account != NULL)
        {
            if (request.operation == PROTO_OP_DEPOSIT)
            {
                commit_account->balance_cents += pending_delta;
            }
            else if (request.operation == PROTO_OP_WITHDRAW)
            {
                commit_account->balance_cents -= pending_delta;
            }
            nonce_add(commit_account, pending_nonce);
        }
        else if (request.operation == PROTO_OP_GET && commit_account != NULL)
        {
            nonce_add(commit_account, pending_nonce);
        }
    }

    if (response.ok)
    {
        switch (request.operation)
        {
        case PROTO_OP_CREATE:
            printf("{\"account\":\"%s\",\"initial_balance\":%s}\n", request.account, amt_buf);
            break;
        case PROTO_OP_DEPOSIT:
            printf("{\"account\":\"%s\",\"deposit\":%s}\n", request.account, amt_buf);
            break;
        case PROTO_OP_WITHDRAW:
            printf("{\"account\":\"%s\",\"withdraw\":%s}\n", request.account, amt_buf);
            break;
        case PROTO_OP_GET:
            printf("{\"account\":\"%s\",\"balance\":%s}\n", request.account, amt_buf);
            break;
        default:
            break;
        }
        fflush(stdout);
    }

    pthread_mutex_unlock(&g_accounts_lock);

    if (new_account != NULL)
    {
        free(new_account);
    }

    crypto_secure_memzero(plaintext, plaintext_len);
    free(plaintext);
    free(msg);
    close(client);
    return NULL;
}

int main(int argc, char **argv)
{
    BankArgs args;
    struct sigaction sa;
    uint8_t auth_secret[AUTH_SECRET_BYTES];

    if (parse_bank_args(argc, argv, &args) != 0)
    {
        exit(255);
    }

    if (create_auth_file(args.auth_file) != 0)
    {
        exit(255);
    }

    printf("created\n");
    fflush(stdout);

    if (crypto_load_auth_secret(args.auth_file, auth_secret) != 0)
    {
        exit(255);
    }
    if (crypto_derive_keys(auth_secret, &g_keys) != 0)
    {
        crypto_secure_memzero(auth_secret, sizeof(auth_secret));
        exit(255);
    }
    crypto_secure_memzero(auth_secret, sizeof(auth_secret));

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigterm;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);

    g_listen_sock = listen_on_port(args.port);
    if (g_listen_sock < 0)
    {
        exit(255);
    }

    while (g_running)
    {
        int client = accept(g_listen_sock, NULL, NULL);
        if (client < 0)
        {
            if (!g_running)
            {
                break;
            }
            continue;
        }

        int *client_ptr = malloc(sizeof(int));
        pthread_t thread;

        if (!client_ptr)
        {
            close(client);
            continue;
        }
        *client_ptr = client;

        if (pthread_create(&thread, NULL, handle_client, client_ptr) != 0)
        {
            free(client_ptr);
            close(client);
            continue;
        }
        pthread_detach(thread);
    }

    if (g_listen_sock >= 0)
    {
        close(g_listen_sock);
    }

    crypto_secure_memzero(&g_keys, sizeof(g_keys));

    return 0;
}
