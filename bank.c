#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
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

    /* Process business logic using an in-memory DB protecting with mutex */
    /* Process business logic using an in-memory DB protecting with mutex */
    typedef struct Account {
        char name[PROTOCOL_MAX_ACCOUNT_LEN + 1];
        uint64_t balance_cents;
        char card_hex[AUTH_SECRET_BYTES * 2 + 1];
        struct Account *next;
    } Account;

    static Account *g_accounts = NULL;
    static pthread_mutex_t g_accounts_lock = PTHREAD_MUTEX_INITIALIZER;

    ProtocolResponse response;
    memset(&response, 0, sizeof(response));
    snprintf(response.account, sizeof(response.account), "%s", request.account);

    int send_protocol_error = 0;
    int business_fail = 0;

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
        /* card_hex must be present */
        if (request.card_hex[0] == '\0' || request.has_amount == 0)
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
            /* create new account */
            /* validate card_hex hex chars */
            for (size_t _i = 0; _i < AUTH_SECRET_BYTES * 2; ++_i)
            {
                unsigned char cc = (unsigned char)request.card_hex[_i];
                if (!((cc >= '0' && cc <= '9') || (cc >= 'a' && cc <= 'f') || (cc >= 'A' && cc <= 'F')))
                {
                    send_protocol_error = 1;
                    break;
                }
            }
            if (send_protocol_error)
            {
                /* leave send_protocol_error set */
            }
            else
            {
            Account *a = (Account *)malloc(sizeof(Account));
            if (!a)
            {
                send_protocol_error = 1;
            }
            else
            {
                memset(a, 0, sizeof(*a));
                snprintf(a->name, sizeof(a->name), "%s", request.account);
                a->balance_cents = request.amount_cents;
                snprintf(a->card_hex, sizeof(a->card_hex), "%s", request.card_hex);
                a->next = g_accounts;
                g_accounts = a;

                response.ok = 1;
                response.has_amount = 1;
                response.amount_cents = a->balance_cents;
            }
            }
        }
    }
    else if (request.operation == PROTO_OP_DEPOSIT)
    {
        if (request.has_amount == 0 || request.card_hex[0] == '\0')
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
        else
        {
            found->balance_cents += request.amount_cents;
            response.ok = 1;
            response.has_amount = 1;
            response.amount_cents = request.amount_cents;
        }
    }
    else if (request.operation == PROTO_OP_WITHDRAW)
    {
        if (request.has_amount == 0 || request.card_hex[0] == '\0')
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
        else if (found->balance_cents < request.amount_cents)
        {
            business_fail = 1;
        }
        else
        {
            found->balance_cents -= request.amount_cents;
            response.ok = 1;
            response.has_amount = 1;
            response.amount_cents = request.amount_cents;
        }
    }
    else if (request.operation == PROTO_OP_GET)
    {
        if (request.card_hex[0] == '\0')
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
        else
        {
            response.ok = 1;
            response.has_amount = 1;
            response.amount_cents = found->balance_cents;
        }
    }
    else
    {
        send_protocol_error = 1;
    }

    /* prepare minimal-decimal amount string and print bank-side JSON while holding lock to preserve ordering */
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

    pthread_mutex_unlock(&g_accounts_lock);

    if (send_protocol_error)
    {
        printf("protocol_error\n");
        fflush(stdout);
        crypto_secure_memzero(plaintext, plaintext_len);
        free(plaintext);
        free(msg);
        close(client);
        return NULL;
    }

    if (business_fail)
    {
        /* send ok=0 response (no bank JSON printed) */
        response.ok = 0;
        response.has_amount = 0;
        response.amount_cents = 0;
    }
    else if (response.ok)
    {
        /* print bank-side JSON summary matching ATM output */
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

    /* build response, serialize, encrypt, and send back */
    uint8_t *resp_plain = NULL;
    size_t resp_plain_len = 0;
    if (proto_serialize_response(&response, &resp_plain, &resp_plain_len) != 0)
    {
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
