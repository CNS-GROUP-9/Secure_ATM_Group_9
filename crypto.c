#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    return -1;
}

void crypto_secure_memzero(void *buf, size_t len)
{
    if (buf == NULL || len == 0)
    {
        return;
    }
    OPENSSL_cleanse(buf, len);
}

int crypto_random_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0 || len > INT_MAX)
    {
        return -1;
    }
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

void crypto_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++)
    {
        out[i * 2] = digits[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

int crypto_hex_decode(const char *hex, size_t hex_len, uint8_t *out)
{
    size_t i;

    if (hex == NULL || out == NULL || (hex_len % 2) != 0)
    {
        return -1;
    }
    for (i = 0; i < hex_len / 2; i++)
    {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            crypto_secure_memzero(out, hex_len / 2);
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int crypto_sha256(const uint8_t *in, size_t len, uint8_t out[SHA256_BYTES])
{
    if (in == NULL || out == NULL)
    {
        return -1;
    }
    return SHA256(in, len, out) == NULL ? -1 : 0;
}

int crypto_ct_equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

int crypto_read_secret_file(const char *path, uint8_t secret[AUTH_SECRET_BYTES])
{
    /* Room for 64 hex chars + '\n' + 1 extra byte to detect trailing data. */
    char buf[AUTH_SECRET_BYTES * 2 + 2];
    size_t total = 0;
    int fd;
    int rc = -1;

    if (path == NULL || secret == NULL)
    {
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return -1;
    }

    while (total < sizeof(buf))
    {
        ssize_t n = read(fd, buf + total, sizeof(buf) - total);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            crypto_secure_memzero(buf, sizeof(buf));
            return -1;
        }
        if (n == 0)
        {
            break;
        }
        total += (size_t)n;
    }
    close(fd);

    /* Exactly 64 hex chars, optionally followed by exactly one newline. */
    if (total == AUTH_SECRET_BYTES * 2 ||
        (total == AUTH_SECRET_BYTES * 2 + 1 && buf[AUTH_SECRET_BYTES * 2] == '\n'))
    {
        rc = crypto_hex_decode(buf, AUTH_SECRET_BYTES * 2, secret);
    }

    crypto_secure_memzero(buf, sizeof(buf));
    return rc;
}

int crypto_load_auth_secret(const char *auth_file, uint8_t secret[AUTH_SECRET_BYTES])
{
    return crypto_read_secret_file(auth_file, secret);
}

int crypto_derive_keys(const uint8_t secret[AUTH_SECRET_BYTES], CryptoKeys *keys)
{
    uint8_t inbuf[AUTH_SECRET_BYTES + 4];
    uint8_t digest[SHA256_DIGEST_LENGTH];

    if (secret == NULL || keys == NULL)
    {
        return -1;
    }

    memcpy(inbuf, secret, AUTH_SECRET_BYTES);

    memcpy(inbuf + AUTH_SECRET_BYTES, "ENC", 4);
    if (SHA256(inbuf, sizeof(inbuf), digest) == NULL)
    {
        crypto_secure_memzero(inbuf, sizeof(inbuf));
        return -1;
    }
    memcpy(keys->enc_key, digest, AES_KEY_BYTES);

    memcpy(inbuf + AUTH_SECRET_BYTES, "MAC", 4);
    if (SHA256(inbuf, sizeof(inbuf), digest) == NULL)
    {
        crypto_secure_memzero(inbuf, sizeof(inbuf));
        crypto_secure_memzero(digest, sizeof(digest));
        return -1;
    }
    memcpy(keys->mac_key, digest, HMAC_KEY_BYTES);

    crypto_secure_memzero(inbuf, sizeof(inbuf));
    crypto_secure_memzero(digest, sizeof(digest));
    return 0;
}

int crypto_encrypt_then_mac(
    const CryptoKeys *keys,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **out,
    size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t iv[AES_BLOCK_BYTES];
    uint8_t *ciphertext = NULL;
    uint8_t *message = NULL;
    unsigned int mac_len = 0;
    int ct_len = 0;
    int final_len = 0;
    size_t total_len;

    if (keys == NULL || plaintext == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }

    if (RAND_bytes(iv, sizeof(iv)) != 1)
    {
        return -1;
    }

    ciphertext = (uint8_t *)malloc(plaintext_len + AES_BLOCK_BYTES);
    if (ciphertext == NULL)
    {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        free(ciphertext);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keys->enc_key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &ct_len, plaintext, (int)plaintext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_memzero(ciphertext, plaintext_len + AES_BLOCK_BYTES);
        free(ciphertext);
        return -1;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_memzero(ciphertext, plaintext_len + AES_BLOCK_BYTES);
        free(ciphertext);
        return -1;
    }
    ct_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    total_len = AES_BLOCK_BYTES + (size_t)ct_len + HMAC_BYTES;
    message = (uint8_t *)malloc(total_len);
    if (message == NULL)
    {
        crypto_secure_memzero(ciphertext, plaintext_len + AES_BLOCK_BYTES);
        free(ciphertext);
        return -1;
    }

    memcpy(message, iv, AES_BLOCK_BYTES);
    memcpy(message + AES_BLOCK_BYTES, ciphertext, (size_t)ct_len);

    if (HMAC(
            EVP_sha256(),
            keys->mac_key,
            HMAC_KEY_BYTES,
            message,
            AES_BLOCK_BYTES + (size_t)ct_len,
            message + AES_BLOCK_BYTES + (size_t)ct_len,
            &mac_len) == NULL ||
        mac_len != HMAC_BYTES)
    {
        crypto_secure_memzero(ciphertext, plaintext_len + AES_BLOCK_BYTES);
        free(ciphertext);
        crypto_secure_memzero(message, total_len);
        free(message);
        return -1;
    }

    crypto_secure_memzero(ciphertext, plaintext_len + AES_BLOCK_BYTES);
    free(ciphertext);

    *out = message;
    *out_len = total_len;
    return 0;
}

int crypto_verify_then_decrypt(
    const CryptoKeys *keys,
    const uint8_t *message,
    size_t message_len,
    uint8_t **out,
    size_t *out_len)
{
    const uint8_t *iv;
    const uint8_t *ciphertext;
    const uint8_t *recv_mac;
    uint8_t calc_mac[HMAC_BYTES];
    uint8_t *plaintext = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned int mac_len = 0;
    size_t ct_len;
    int pt_len = 0;
    int final_len = 0;

    if (keys == NULL || message == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }

    if (message_len < AES_BLOCK_BYTES + HMAC_BYTES + AES_BLOCK_BYTES)
    {
        return -1;
    }

    iv = message;
    ct_len = message_len - AES_BLOCK_BYTES - HMAC_BYTES;
    ciphertext = message + AES_BLOCK_BYTES;
    recv_mac = message + AES_BLOCK_BYTES + ct_len;

    if ((ct_len % AES_BLOCK_BYTES) != 0)
    {
        return -1;
    }

    if (HMAC(
            EVP_sha256(),
            keys->mac_key,
            HMAC_KEY_BYTES,
            message,
            AES_BLOCK_BYTES + ct_len,
            calc_mac,
            &mac_len) == NULL ||
        mac_len != HMAC_BYTES)
    {
        return -1;
    }

    if (CRYPTO_memcmp(calc_mac, recv_mac, HMAC_BYTES) != 0)
    {
        crypto_secure_memzero(calc_mac, sizeof(calc_mac));
        return -1;
    }
    crypto_secure_memzero(calc_mac, sizeof(calc_mac));

    plaintext = (uint8_t *)malloc(ct_len + 1);
    if (plaintext == NULL)
    {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        free(plaintext);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, keys->enc_key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &pt_len, ciphertext, (int)ct_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_memzero(plaintext, ct_len + 1);
        free(plaintext);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + pt_len, &final_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        crypto_secure_memzero(plaintext, ct_len + 1);
        free(plaintext);
        return -1;
    }
    pt_len += final_len;
    EVP_CIPHER_CTX_free(ctx);

    plaintext[pt_len] = '\0';

    *out = plaintext;
    *out_len = (size_t)pt_len;
    return 0;
}
