#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AUTH_SECRET_BYTES 32
#define CARD_SECRET_BYTES 32
#define AES_KEY_BYTES 32
#define HMAC_KEY_BYTES 32
#define AES_BLOCK_BYTES 16
#define HMAC_BYTES 32
#define SHA256_BYTES 32

typedef struct
{
    uint8_t enc_key[AES_KEY_BYTES];
    uint8_t mac_key[HMAC_KEY_BYTES];
} CryptoKeys;

/*
 * Strictly reads a 32-byte secret stored as exactly 64 hex characters,
 * optionally followed by a single '\n', and nothing else.
 * Used for both the auth file and card files.
 */
int crypto_read_secret_file(const char *path, uint8_t secret[AUTH_SECRET_BYTES]);
int crypto_load_auth_secret(const char *auth_file, uint8_t secret[AUTH_SECRET_BYTES]);
int crypto_derive_keys(const uint8_t secret[AUTH_SECRET_BYTES], CryptoKeys *keys);

int crypto_random_bytes(uint8_t *buf, size_t len);
void crypto_hex_encode(const uint8_t *in, size_t len, char *out); /* out: 2*len+1 bytes */
int crypto_hex_decode(const char *hex, size_t hex_len, uint8_t *out); /* hex_len must be even */
int crypto_sha256(const uint8_t *in, size_t len, uint8_t out[SHA256_BYTES]);
int crypto_ct_equal(const void *a, const void *b, size_t len); /* 1 if equal, constant time */

int crypto_encrypt_then_mac(
    const CryptoKeys *keys,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t **out,
    size_t *out_len);

int crypto_verify_then_decrypt(
    const CryptoKeys *keys,
    const uint8_t *message,
    size_t message_len,
    uint8_t **out,
    size_t *out_len);

void crypto_secure_memzero(void *buf, size_t len);

#endif
