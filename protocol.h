#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PROTOCOL_MAX_ACCOUNT_LEN 122

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
    uint64_t nonce;
    int has_amount;
    uint64_t amount_cents;
} ProtocolRequest;

typedef struct
{
    char account[PROTOCOL_MAX_ACCOUNT_LEN + 1];
    int ok;
    int has_amount;
    uint64_t amount_cents;
} ProtocolResponse;

int proto_operation_from_mode(int mode, ProtocolOperation *operation);
int proto_amount_to_cents(double amount, uint64_t *amount_cents);
int proto_generate_nonce(uint64_t *nonce);

int proto_serialize_request(const ProtocolRequest *request, uint8_t **out, size_t *out_len);
int proto_deserialize_request(const uint8_t *data, size_t data_len, ProtocolRequest *request);

int proto_serialize_response(const ProtocolResponse *response, uint8_t **out, size_t *out_len);
int proto_deserialize_response(const uint8_t *data, size_t data_len, ProtocolResponse *response);

#endif
