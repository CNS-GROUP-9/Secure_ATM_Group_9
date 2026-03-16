#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AUTH_SECRET_BYTES 32
#define AES_KEY_BYTES 32
#define HMAC_KEY_BYTES 32
#define AES_BLOCK_BYTES 16
#define HMAC_BYTES 32

typedef struct
{
    uint8_t enc_key[AES_KEY_BYTES];
    uint8_t mac_key[HMAC_KEY_BYTES];
} CryptoKeys;

int crypto_load_auth_secret(const char *auth_file, uint8_t secret[AUTH_SECRET_BYTES]);
int crypto_derive_keys(const uint8_t secret[AUTH_SECRET_BYTES], CryptoKeys *keys);

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
