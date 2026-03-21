#include <ctype.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

static const char *operation_name(ProtocolOperation operation)
{
    switch (operation)
    {
    case PROTO_OP_CREATE:
        return "create";
    case PROTO_OP_DEPOSIT:
        return "deposit";
    case PROTO_OP_WITHDRAW:
        return "withdraw";
    case PROTO_OP_GET:
        return "get";
    default:
        return NULL;
    }
}

static int operation_from_name(const char *name, ProtocolOperation *operation)
{
    if (strcmp(name, "create") == 0)
    {
        *operation = PROTO_OP_CREATE;
        return 0;
    }
    if (strcmp(name, "deposit") == 0)
    {
        *operation = PROTO_OP_DEPOSIT;
        return 0;
    }
    if (strcmp(name, "withdraw") == 0)
    {
        *operation = PROTO_OP_WITHDRAW;
        return 0;
    }
    if (strcmp(name, "get") == 0)
    {
        *operation = PROTO_OP_GET;
        return 0;
    }

    return -1;
}

static int account_chars_valid(const char *account)
{
    size_t i;
    size_t len = strlen(account);

    if (len < 1 || len > PROTOCOL_MAX_ACCOUNT_LEN)
    {
        return 0;
    }

    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)account[i];
        if (!(c == '_' || c == '-' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')))
        {
            return 0;
        }
    }

    return 1;
}

static int find_string_value(const char *json, const char *key, char *out, size_t out_size)
{
    char pattern[64];
    const char *start;
    const char *end;
    size_t len;

    if (snprintf(pattern, sizeof(pattern), "\"%s\":\"", key) <= 0)
    {
        return -1;
    }

    start = strstr(json, pattern);
    if (start == NULL)
    {
        return 0;
    }
    start += strlen(pattern);

    end = strchr(start, '"');
    if (end == NULL)
    {
        return -1;
    }

    len = (size_t)(end - start);
    if (len == 0 || len >= out_size)
    {
        return -1;
    }

    memcpy(out, start, len);
    out[len] = '\0';
    return 1;
}

static int find_uint64_value(const char *json, const char *key, uint64_t *value)
{
    char pattern[64];
    const char *start;
    char *endptr;
    unsigned long long parsed;

    if (snprintf(pattern, sizeof(pattern), "\"%s\":", key) <= 0)
    {
        return -1;
    }

    start = strstr(json, pattern);
    if (start == NULL)
    {
        return 0;
    }
    start += strlen(pattern);

    if (!isdigit((unsigned char)*start))
    {
        return -1;
    }

    parsed = strtoull(start, &endptr, 10);
    if (endptr == start)
    {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 1;
}

int proto_operation_from_mode(int mode, ProtocolOperation *operation)
{
    if (operation == NULL)
    {
        return -1;
    }

    switch (mode)
    {
    case 1:
        *operation = PROTO_OP_CREATE;
        return 0;
    case 2:
        *operation = PROTO_OP_DEPOSIT;
        return 0;
    case 3:
        *operation = PROTO_OP_WITHDRAW;
        return 0;
    case 4:
        *operation = PROTO_OP_GET;
        return 0;
    default:
        return -1;
    }
}

int proto_amount_to_cents(double amount, uint64_t *amount_cents)
{
    double scaled;

    if (amount_cents == NULL || amount < 0.0)
    {
        return -1;
    }

    scaled = (amount * 100.0) + 0.5;
    if (scaled < 0.0)
    {
        return -1;
    }

    *amount_cents = (uint64_t)scaled;
    return 0;
}

int proto_generate_nonce(uint64_t *nonce)
{
    if (nonce == NULL)
    {
        return -1;
    }

    if (RAND_bytes((unsigned char *)nonce, sizeof(*nonce)) != 1)
    {
        return -1;
    }

    return 0;
}

int proto_serialize_request(const ProtocolRequest *request, uint8_t **out, size_t *out_len)
{
    char buffer[512];
    const char *op_name;
    int n;

    if (request == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }

    op_name = operation_name(request->operation);
    if (op_name == NULL || !account_chars_valid(request->account))
    {
        return -1;
    }

    if (request->has_amount)
    {
        n = snprintf(
            buffer,
            sizeof(buffer),
            "{\"account\":\"%s\",\"operation\":\"%s\",\"amount_cents\":%llu,\"nonce\":%llu,\"card_hex\":\"%s\"}",
            request->account,
            op_name,
            (unsigned long long)request->amount_cents,
            (unsigned long long)request->nonce,
            request->card_hex);
    }
    else
    {
        n = snprintf(
            buffer,
            sizeof(buffer),
            "{\"account\":\"%s\",\"operation\":\"%s\",\"nonce\":%llu,\"card_hex\":\"%s\"}",
            request->account,
            op_name,
            (unsigned long long)request->nonce,
            request->card_hex);
    }

    if (n < 0 || (size_t)n >= sizeof(buffer))
    {
        return -1;
    }

    *out = (uint8_t *)malloc((size_t)n);
    if (*out == NULL)
    {
        return -1;
    }

    memcpy(*out, buffer, (size_t)n);
    *out_len = (size_t)n;
    return 0;
}

int proto_deserialize_request(const uint8_t *data, size_t data_len, ProtocolRequest *request)
{
    char *json = NULL;
    char operation_buf[32];
    uint64_t nonce = 0;
    uint64_t amount_cents = 0;
    int has_account;
    int has_operation;
    int has_nonce;
    int has_amount;

    if (data == NULL || request == NULL || data_len == 0)
    {
        return -1;
    }

    json = (char *)malloc(data_len + 1);
    if (json == NULL)
    {
        return -1;
    }
    memcpy(json, data, data_len);
    json[data_len] = '\0';

    request->card_hex[0] = '\0';

    has_account = find_string_value(json, "account", request->account, sizeof(request->account));
    has_operation = find_string_value(json, "operation", operation_buf, sizeof(operation_buf));
    has_nonce = find_uint64_value(json, "nonce", &nonce);
    has_amount = find_uint64_value(json, "amount_cents", &amount_cents);
    /* optional card_hex */
    find_string_value(json, "card_hex", request->card_hex, sizeof(request->card_hex));

    if (has_account != 1 || has_operation != 1 || has_nonce != 1)
    {
        free(json);
        return -1;
    }
    if (!account_chars_valid(request->account) || operation_from_name(operation_buf, &request->operation) != 0)
    {
        free(json);
        return -1;
    }

    request->nonce = nonce;

    if (request->operation == PROTO_OP_GET)
    {
        if (has_amount == 1)
        {
            free(json);
            return -1;
        }
        request->has_amount = 0;
        request->amount_cents = 0;
    }
    else
    {
        if (has_amount != 1)
        {
            free(json);
            return -1;
        }
        request->has_amount = 1;
        request->amount_cents = amount_cents;
    }

    /* card_hex may be empty; ensure NUL termination */
    request->card_hex[sizeof(request->card_hex) - 1] = '\0';
    free(json);
    return 0;
}

int proto_serialize_response(const ProtocolResponse *response, uint8_t **out, size_t *out_len)
{
    char buffer[512];
    int n;

    if (response == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }
    if (!account_chars_valid(response->account))
    {
        return -1;
    }

    if (response->has_amount)
    {
        n = snprintf(
            buffer,
            sizeof(buffer),
            "{\"account\":\"%s\",\"ok\":%d,\"amount_cents\":%llu}",
            response->account,
            response->ok ? 1 : 0,
            (unsigned long long)response->amount_cents);
    }
    else
    {
        n = snprintf(
            buffer,
            sizeof(buffer),
            "{\"account\":\"%s\",\"ok\":%d}",
            response->account,
            response->ok ? 1 : 0);
    }

    if (n < 0 || (size_t)n >= sizeof(buffer))
    {
        return -1;
    }

    *out = (uint8_t *)malloc((size_t)n);
    if (*out == NULL)
    {
        return -1;
    }

    memcpy(*out, buffer, (size_t)n);
    *out_len = (size_t)n;
    return 0;
}

int proto_deserialize_response(const uint8_t *data, size_t data_len, ProtocolResponse *response)
{
    char *json = NULL;
    uint64_t ok_u64 = 0;
    uint64_t amount_cents = 0;
    int has_account;
    int has_ok;
    int has_amount;

    if (data == NULL || response == NULL || data_len == 0)
    {
        return -1;
    }

    json = (char *)malloc(data_len + 1);
    if (json == NULL)
    {
        return -1;
    }
    memcpy(json, data, data_len);
    json[data_len] = '\0';

    has_account = find_string_value(json, "account", response->account, sizeof(response->account));
    has_ok = find_uint64_value(json, "ok", &ok_u64);
    has_amount = find_uint64_value(json, "amount_cents", &amount_cents);

    if (has_account != 1 || has_ok != 1 || !account_chars_valid(response->account) || (ok_u64 != 0 && ok_u64 != 1))
    {
        free(json);
        return -1;
    }

    response->ok = (ok_u64 == 1) ? 1 : 0;
    if (has_amount == 1)
    {
        response->has_amount = 1;
        response->amount_cents = amount_cents;
    }
    else
    {
        response->has_amount = 0;
        response->amount_cents = 0;
    }

    free(json);
    return 0;
}
