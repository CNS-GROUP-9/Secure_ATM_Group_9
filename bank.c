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
