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

/* ------------------------------------------------------------------------
 * Account store
 *
 * Locking model (fixes the old single global lock held across network I/O):
 *   - g_map_lock protects only the hash-bucket chains (lookup / insert).
 *     It is held for a few microseconds and never while holding an account
 *     lock or doing I/O.
 *   - Each Account has its own mutex protecting its balance/state. It is
 *     never held during network I/O either.
 *   - Account nodes are never freed while the bank runs (a rolled-back create
 *     just goes back to ACCT_ABSENT), so a pointer obtained from the map stays
 *     valid after g_map_lock is released.
 *
 * Two-phase commit: a transaction first PREPAREs (reserves) under the account
 * lock, the lock is dropped, the response is sent and the ATM's COMMIT is
 * awaited; then the reservation is either COMMITted or ROLLed BACK.
 * ------------------------------------------------------------------------ */

#define ACCOUNT_BUCKETS 1024
#define MAX_ACTIVE_CLIENTS 256

typedef enum
{
    ACCT_ABSENT = 0, /* no account (or a create that was rolled back) */
    ACCT_PENDING,    /* create prepared, waiting for the ATM's COMMIT */
    ACCT_ACTIVE
} AccountState;

typedef struct Account
{
    char name[PROTOCOL_MAX_ACCOUNT_LEN + 1];
    pthread_mutex_t lock;
    AccountState state;
    uint64_t balance_cents; /* spendable balance (withdrawal reservations already removed) */
    uint64_t reserved_out;  /* withdrawals prepared but not yet committed */
    uint64_t pending_in;    /* deposits prepared but not yet committed */
    uint8_t card_hash[SHA256_BYTES];
    struct Account *next;
} Account;

static Account *g_buckets[ACCOUNT_BUCKETS];
static pthread_mutex_t g_map_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_active_clients = 0;

typedef struct
{
    Account *account;
    ProtocolOperation operation;
    uint64_t amount_cents;
    int needs_commit;
} PreparedTxn;

static size_t bucket_of(const char *name)
{
    uint64_t h = 1469598103934665603ULL; /* FNV-1a */
    while (*name)
    {
        h ^= (unsigned char)*name++;
        h *= 1099511628211ULL;
    }
    return (size_t)(h % ACCOUNT_BUCKETS);
}

/* Returns the node for `name`; inserts an ACCT_ABSENT node if `create` is set. */
static Account *account_lookup(const char *name, int create)
{
    size_t b = bucket_of(name);
    Account *cur;

    pthread_mutex_lock(&g_map_lock);
    for (cur = g_buckets[b]; cur != NULL; cur = cur->next)
    {
        if (strcmp(cur->name, name) == 0)
        {
            pthread_mutex_unlock(&g_map_lock);
            return cur;
        }
    }

    if (create)
    {
        cur = (Account *)calloc(1, sizeof(*cur));
        if (cur != NULL)
        {
            snprintf(cur->name, sizeof(cur->name), "%s", name);
            if (pthread_mutex_init(&cur->lock, NULL) != 0)
            {
                free(cur);
                cur = NULL;
            }
            else
            {
                cur->state = ACCT_ABSENT;
                cur->next = g_buckets[b];
                g_buckets[b] = cur;
            }
        }
    }
    pthread_mutex_unlock(&g_map_lock);
    return cur;
}

static int card_hash_of(const char *card_hex, uint8_t out[SHA256_BYTES])
{
    uint8_t secret[CARD_SECRET_BYTES];
    int rc;

    if (crypto_hex_decode(card_hex, CARD_SECRET_BYTES * 2, secret) != 0)
    {
        return -1;
    }
    rc = crypto_sha256(secret, sizeof(secret), out);
    crypto_secure_memzero(secret, sizeof(secret));
    return rc;
}

static int amount_in_range(ProtocolOperation op, uint64_t cents)
{
    if (cents > PROTO_MAX_AMOUNT_CENTS)
    {
        return 0;
    }
    if (op == PROTO_OP_CREATE)
    {
        return cents >= PROTO_MIN_CREATE_CENTS;
    }
    return cents > 0;
}

/*
 * PHASE 1 (prepare). Validates the request and reserves its effect.
 * Fills response->ok / amount. Returns -1 only on internal error.
 * Nothing becomes visible to other transactions until txn_commit():
 *   create   -> account goes ABSENT -> PENDING (blocks duplicate creates, invisible to others)
 *   deposit  -> amount parked in pending_in (not spendable yet)
 *   withdraw -> amount moved from balance to reserved_out (cannot be double-spent)
 */
static int txn_prepare(const ProtocolRequest *req, ProtocolResponse *resp, PreparedTxn *txn)
{
    uint8_t card_hash[SHA256_BYTES];
    Account *acct;

    memset(txn, 0, sizeof(*txn));
    resp->ok = 0;
    resp->has_amount = 0;
    resp->amount_cents = 0;

    if (req->operation != PROTO_OP_GET && !amount_in_range(req->operation, req->amount_cents))
    {
        return 0; /* business failure: amount outside allowed limits */
    }

    if (card_hash_of(req->card_hex, card_hash) != 0)
    {
        return -1;
    }

    acct = account_lookup(req->account, req->operation == PROTO_OP_CREATE);
    if (acct == NULL)
    {
        crypto_secure_memzero(card_hash, sizeof(card_hash));
        return req->operation == PROTO_OP_CREATE ? -1 : 0;
    }

    pthread_mutex_lock(&acct->lock);

    if (req->operation == PROTO_OP_CREATE)
    {
        if (acct->state == ACCT_ABSENT)
        {
            acct->state = ACCT_PENDING;
            acct->balance_cents = req->amount_cents;
            acct->reserved_out = 0;
            acct->pending_in = 0;
            memcpy(acct->card_hash, card_hash, sizeof(card_hash));
            resp->ok = 1;
            txn->needs_commit = 1;
        }
    }
    else if (acct->state == ACCT_ACTIVE && crypto_ct_equal(acct->card_hash, card_hash, sizeof(card_hash)))
    {
        if (req->operation == PROTO_OP_DEPOSIT)
        {
            /* Invariant: balance + reserved_out + pending_in <= UINT64_MAX */
            uint64_t committed = acct->balance_cents + acct->reserved_out + acct->pending_in;
            if (UINT64_MAX - committed >= req->amount_cents)
            {
                acct->pending_in += req->amount_cents;
                resp->ok = 1;
                txn->needs_commit = 1;
            }
        }
        else if (req->operation == PROTO_OP_WITHDRAW)
        {
            if (acct->balance_cents >= req->amount_cents)
            {
                acct->balance_cents -= req->amount_cents;
                acct->reserved_out += req->amount_cents;
                resp->ok = 1;
                txn->needs_commit = 1;
            }
        }
        else if (req->operation == PROTO_OP_GET)
        {
            resp->ok = 1;
            resp->has_amount = 1;
            resp->amount_cents = acct->balance_cents;
        }
    }

    pthread_mutex_unlock(&acct->lock);
    crypto_secure_memzero(card_hash, sizeof(card_hash));

    if (resp->ok && req->operation != PROTO_OP_GET)
    {
        resp->has_amount = 1;
        resp->amount_cents = req->amount_cents;
    }

    txn->account = acct;
    txn->operation = req->operation;
    txn->amount_cents = req->amount_cents;
    return 0;
}

/* PHASE 2a: make the prepared change permanent. */
static void txn_commit(const PreparedTxn *txn)
{
    Account *acct = txn->account;

    pthread_mutex_lock(&acct->lock);
    switch (txn->operation)
    {
    case PROTO_OP_CREATE:
        acct->state = ACCT_ACTIVE;
        break;
    case PROTO_OP_DEPOSIT:
        acct->pending_in -= txn->amount_cents;
        acct->balance_cents += txn->amount_cents;
        break;
    case PROTO_OP_WITHDRAW:
        acct->reserved_out -= txn->amount_cents;
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&acct->lock);
}

/* PHASE 2b: undo the prepared change. */
static void txn_rollback(const PreparedTxn *txn)
{
    Account *acct = txn->account;

    pthread_mutex_lock(&acct->lock);
    switch (txn->operation)
    {
    case PROTO_OP_CREATE:
        acct->state = ACCT_ABSENT;
        acct->balance_cents = 0;
        crypto_secure_memzero(acct->card_hash, sizeof(acct->card_hash));
        break;
    case PROTO_OP_DEPOSIT:
        acct->pending_in -= txn->amount_cents;
        break;
    case PROTO_OP_WITHDRAW:
        acct->reserved_out -= txn->amount_cents;
        acct->balance_cents += txn->amount_cents;
        break;
    default:
        break;
    }
    pthread_mutex_unlock(&acct->lock);
}

static void print_line(const char *line)
{
    flockfile(stdout);
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    funlockfile(stdout);
}

static void print_result(const ProtocolRequest *req, const ProtocolResponse *resp)
{
    static const char *const keys[] = {"", "initial_balance", "deposit", "withdraw", "balance"};
    char amt[64];
    char line[256];

    proto_format_amount(resp->amount_cents, amt, sizeof(amt));
    snprintf(line, sizeof(line), "{\"account\":\"%s\",\"%s\":%s}", req->account, keys[req->operation], amt);
    print_line(line);
}

static int create_auth_file(const char *path)
{
    uint8_t secret[AUTH_SECRET_BYTES];
    char hex[AUTH_SECRET_BYTES * 2 + 1];
    size_t off = 0;
    int fd;
    int rc = -1;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
    {
        return -1;
    }

    if (crypto_random_bytes(secret, sizeof(secret)) == 0)
    {
        crypto_hex_encode(secret, sizeof(secret), hex);
        hex[AUTH_SECRET_BYTES * 2] = '\n'; /* replace NUL: file is 64 hex + '\n' */
        rc = 0;
        while (off < sizeof(hex))
        {
            ssize_t n = write(fd, hex + off, sizeof(hex) - off);
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
    }

    crypto_secure_memzero(secret, sizeof(secret));
    crypto_secure_memzero(hex, sizeof(hex));
    if (close(fd) < 0)
    {
        rc = -1;
    }
    if (rc != 0)
    {
        unlink(path);
    }
    return rc;
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

/*
 * One connection = one transaction:
 *   1. send CHALLENGE(snonce)               fresh 128-bit nonce for this connection
 *   2. recv REQUEST, require its snonce     -> a captured request can never be replayed
 *   3. PREPARE (reserve) under account lock
 *   4. send RESPONSE (echoes snonce/cnonce/account/op/amount); no lock held
 *   5. recv COMMIT for mutating ops         -> COMMIT, otherwise ROLLBACK
 */
static void handle_session(int client)
{
    char snonce[PROTO_NONCE_HEX_LEN + 1];
    char c_snonce[PROTO_NONCE_HEX_LEN + 1];
    char c_cnonce[PROTO_NONCE_HEX_LEN + 1];
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    ProtocolRequest request;
    ProtocolResponse response;
    PreparedTxn txn;
    int committed = 0;

    memset(&request, 0, sizeof(request));
    memset(&txn, 0, sizeof(txn));

    /* 1. challenge */
    if (proto_generate_nonce(snonce) != 0 ||
        proto_serialize_challenge(snonce, &plain, &plain_len) != 0)
    {
        print_line("protocol_error");
        return;
    }
    if (proto_send_secure(client, &g_keys, plain, plain_len) != 0)
    {
        free(plain);
        print_line("protocol_error");
        return;
    }
    free(plain);
    plain = NULL;

    /* 2. request, bound to this connection's challenge */
    if (proto_recv_secure(client, &g_keys, &plain, &plain_len) != 0 ||
        proto_deserialize_request(plain, plain_len, &request) != 0 ||
        !proto_nonce_equal(request.snonce, snonce))
    {
        if (plain != NULL)
        {
            crypto_secure_memzero(plain, plain_len);
            free(plain);
        }
        crypto_secure_memzero(&request, sizeof(request));
        print_line("protocol_error");
        return;
    }
    crypto_secure_memzero(plain, plain_len);
    free(plain);
    plain = NULL;

    /* 3. prepare */
    memset(&response, 0, sizeof(response));
    snprintf(response.account, sizeof(response.account), "%s", request.account);
    response.operation = request.operation;
    memcpy(response.snonce, request.snonce, sizeof(response.snonce));
    memcpy(response.cnonce, request.cnonce, sizeof(response.cnonce));

    if (txn_prepare(&request, &response, &txn) != 0)
    {
        crypto_secure_memzero(&request, sizeof(request));
        print_line("protocol_error");
        return;
    }

    /* 4. response (no locks held) */
    if (proto_serialize_response(&response, &plain, &plain_len) != 0 ||
        proto_send_secure(client, &g_keys, plain, plain_len) != 0)
    {
        free(plain);
        if (txn.needs_commit)
        {
            txn_rollback(&txn);
        }
        crypto_secure_memzero(&request, sizeof(request));
        print_line("protocol_error");
        return;
    }
    free(plain);
    plain = NULL;

    /* 5. commit / rollback */
    if (txn.needs_commit)
    {
        if (proto_recv_secure(client, &g_keys, &plain, &plain_len) == 0 &&
            proto_deserialize_commit(plain, plain_len, c_snonce, c_cnonce) == 0 &&
            proto_nonce_equal(c_snonce, request.snonce) &&
            proto_nonce_equal(c_cnonce, request.cnonce))
        {
            txn_commit(&txn);
            committed = 1;
        }
        else
        {
            txn_rollback(&txn);
        }
        free(plain);
        plain = NULL;

        if (!committed)
        {
            crypto_secure_memzero(&request, sizeof(request));
            print_line("protocol_error");
            return;
        }
    }

    if (response.ok)
    {
        print_result(&request, &response);
    }
    crypto_secure_memzero(&request, sizeof(request));
}

static void *handle_client(void *arg)
{
    int client = *(int *)arg;
    free(arg);

    if (set_socket_timeout_seconds(client, NET_TIMEOUT_SECONDS) == 0)
    {
        handle_session(client);
    }
    else
    {
        print_line("protocol_error");
    }
    close(client);

    pthread_mutex_lock(&g_clients_lock);
    g_active_clients--;
    pthread_mutex_unlock(&g_clients_lock);
    return NULL;
}

int main(int argc, char **argv)
{
    BankArgs args;
    struct sigaction sa;
    uint8_t auth_secret[AUTH_SECRET_BYTES];

    signal(SIGPIPE, SIG_IGN);

    if (parse_bank_args(argc, argv, &args) != 0)
    {
        exit(255);
    }

    if (create_auth_file(args.auth_file) != 0)
    {
        exit(255);
    }

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
        unlink(args.auth_file);
        exit(255);
    }

    printf("created\n");
    fflush(stdout);

    while (g_running)
    {
        int client = accept(g_listen_sock, NULL, NULL);
        int *client_ptr;
        pthread_t thread;

        if (client < 0)
        {
            if (!g_running)
            {
                break;
            }
            continue;
        }

        /* Bound the number of concurrent worker threads (connection flooding). */
        pthread_mutex_lock(&g_clients_lock);
        if (g_active_clients >= MAX_ACTIVE_CLIENTS)
        {
            pthread_mutex_unlock(&g_clients_lock);
            close(client);
            continue;
        }
        g_active_clients++;
        pthread_mutex_unlock(&g_clients_lock);

        client_ptr = malloc(sizeof(int));
        if (client_ptr != NULL)
        {
            *client_ptr = client;
            if (pthread_create(&thread, NULL, handle_client, client_ptr) == 0)
            {
                pthread_detach(thread);
                continue;
            }
            free(client_ptr);
        }

        close(client);
        pthread_mutex_lock(&g_clients_lock);
        g_active_clients--;
        pthread_mutex_unlock(&g_clients_lock);
    }

    if (g_listen_sock >= 0)
    {
        close(g_listen_sock);
    }

    crypto_secure_memzero(&g_keys, sizeof(g_keys));

    return 0;
}
