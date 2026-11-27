#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define PROTOCOL_MAX_ACCOUNT_LEN 122

/* 128-bit random nonces, carried as 32 lowercase hex chars. */
#define PROTO_NONCE_BYTES 16
#define PROTO_NONCE_HEX_LEN (PROTO_NONCE_BYTES * 2)

/* Business limits, enforced by the bank independently of the ATM CLI. */
#define PROTO_MIN_CREATE_CENTS 1000ULL          /* 10.00 */
#define PROTO_MAX_AMOUNT_CENTS 429496729599ULL  /* 4294967295.99 */

/*
 * Session (one TCP connection = one transaction):
 *
 *   bank -> atm : CHALLENGE { snonce }                       fresh per connection
 *   atm  -> bank: REQUEST   { snonce, cnonce, account, op, amount, card }
 *   bank -> atm : RESPONSE  { snonce, cnonce, account, op, ok, amount }
 *   atm  -> bank: COMMIT    { snonce, cnonce }               only for ok create/deposit/withdraw
 *
 * Every message is Encrypt-then-MAC'd and carries a "type" field, so no
 * message can be reflected or substituted for another kind.
 */

typedef enum
{
    PROTO_OP_CREATE = 1,
    PROTO_OP_DEPOSIT = 2,
    PROTO_OP_WITHDRAW = 3,
    PROTO_OP_GET = 4
} ProtocolOperation;

typedef struct
{
    char account[PROTOCOL_MAX_ACCOUNT_LEN + 1];
    ProtocolOperation operation;
    int has_amount;
    uint64_t amount_cents;
    char card_hex[CARD_SECRET_BYTES * 2 + 1];
    char snonce[PROTO_NONCE_HEX_LEN + 1];
    char cnonce[PROTO_NONCE_HEX_LEN + 1];
} ProtocolRequest;

typedef struct
{
    char account[PROTOCOL_MAX_ACCOUNT_LEN + 1];
    ProtocolOperation operation;
    int ok;
    int has_amount;
    uint64_t amount_cents;
    char snonce[PROTO_NONCE_HEX_LEN + 1];
    char cnonce[PROTO_NONCE_HEX_LEN + 1];
} ProtocolResponse;

int proto_operation_from_mode(int mode, ProtocolOperation *operation);
int proto_amount_to_cents(double amount, uint64_t *amount_cents);
void proto_format_amount(uint64_t cents, char *buf, size_t buf_size);

int proto_generate_nonce(char out[PROTO_NONCE_HEX_LEN + 1]);
int proto_nonce_equal(const char *a, const char *b);

int proto_serialize_challenge(const char *snonce, uint8_t **out, size_t *out_len);
int proto_deserialize_challenge(const uint8_t *data, size_t data_len, char snonce[PROTO_NONCE_HEX_LEN + 1]);

int proto_serialize_request(const ProtocolRequest *request, uint8_t **out, size_t *out_len);
int proto_deserialize_request(const uint8_t *data, size_t data_len, ProtocolRequest *request);

int proto_serialize_response(const ProtocolResponse *response, uint8_t **out, size_t *out_len);
int proto_deserialize_response(const uint8_t *data, size_t data_len, ProtocolResponse *response);

int proto_serialize_commit(const char *snonce, const char *cnonce, uint8_t **out, size_t *out_len);
int proto_deserialize_commit(
    const uint8_t *data,
    size_t data_len,
    char snonce[PROTO_NONCE_HEX_LEN + 1],
    char cnonce[PROTO_NONCE_HEX_LEN + 1]);

/* Encrypt-then-MAC + framed send; receive + verify-then-decrypt. */
int proto_send_secure(int sock, const CryptoKeys *keys, const uint8_t *plain, size_t plain_len);
int proto_recv_secure(int sock, const CryptoKeys *keys, uint8_t **plain, size_t *plain_len);

#endif
