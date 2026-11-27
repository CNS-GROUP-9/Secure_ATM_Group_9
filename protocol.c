#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "network.h"
#include "protocol.h"

#define PROTO_BUF_SIZE 640

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

static int lower_hex_valid(const char *s, size_t expected_len)
{
    size_t i;

    if (strlen(s) != expected_len)
    {
        return 0;
    }
    for (i = 0; i < expected_len; i++)
    {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
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

    errno = 0;
    parsed = strtoull(start, &endptr, 10);
    if (endptr == start || errno == ERANGE)
    {
        return -1;
    }

    if (*endptr != ',' && *endptr != '}')
    {
        return -1;
    }

    if (start[0] == '0' && (endptr - start) > 1)
    {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 1;
}

/* Copies data into a NUL-terminated string and checks its "type" field. */
static char *open_message(const uint8_t *data, size_t data_len, const char *expected_type)
{
    char type_buf[16];
    char *json;

    if (data == NULL || data_len == 0 || data_len > PROTO_BUF_SIZE)
    {
        return NULL;
    }

    json = (char *)malloc(data_len + 1);
    if (json == NULL)
    {
        return NULL;
    }
    memcpy(json, data, data_len);
    json[data_len] = '\0';

    /* Embedded NULs would hide fields from the parser. */
    if (strlen(json) != data_len ||
        find_string_value(json, "type", type_buf, sizeof(type_buf)) != 1 ||
        strcmp(type_buf, expected_type) != 0)
    {
        crypto_secure_memzero(json, data_len + 1);
        free(json);
        return NULL;
    }
    return json;
}

static void close_message(char *json)
{
    if (json != NULL)
    {
        crypto_secure_memzero(json, strlen(json));
        free(json);
    }
}

static int read_nonce(const char *json, const char *key, char out[PROTO_NONCE_HEX_LEN + 1])
{
    return find_string_value(json, key, out, PROTO_NONCE_HEX_LEN + 1) == 1 &&
                   lower_hex_valid(out, PROTO_NONCE_HEX_LEN)
               ? 0
               : -1;
}

static int finish_buffer(char *buffer, int n, uint8_t **out, size_t *out_len)
{
    if (n < 0 || (size_t)n >= PROTO_BUF_SIZE)
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
    crypto_secure_memzero(buffer, PROTO_BUF_SIZE);
    return 0;
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

void proto_format_amount(uint64_t cents, char *buf, size_t buf_size)
{
    if ((cents % 100) == 0)
    {
        snprintf(buf, buf_size, "%llu", (unsigned long long)(cents / 100));
    }
    else if ((cents % 10) == 0)
    {
        snprintf(buf, buf_size, "%llu.%llu", (unsigned long long)(cents / 100), (unsigned long long)((cents % 100) / 10));
    }
    else
    {
        snprintf(buf, buf_size, "%llu.%02llu", (unsigned long long)(cents / 100), (unsigned long long)(cents % 100));
    }
}

int proto_generate_nonce(char out[PROTO_NONCE_HEX_LEN + 1])
{
    uint8_t raw[PROTO_NONCE_BYTES];

    if (out == NULL || crypto_random_bytes(raw, sizeof(raw)) != 0)
    {
        return -1;
    }
    crypto_hex_encode(raw, sizeof(raw), out);
    return 0;
}

int proto_nonce_equal(const char *a, const char *b)
{
    if (a == NULL || b == NULL ||
        !lower_hex_valid(a, PROTO_NONCE_HEX_LEN) || !lower_hex_valid(b, PROTO_NONCE_HEX_LEN))
    {
        return 0;
    }
    return crypto_ct_equal(a, b, PROTO_NONCE_HEX_LEN);
}

/* ---------------- CHALLENGE ---------------- */

int proto_serialize_challenge(const char *snonce, uint8_t **out, size_t *out_len)
{
    char buffer[PROTO_BUF_SIZE];

    if (snonce == NULL || out == NULL || out_len == NULL || !lower_hex_valid(snonce, PROTO_NONCE_HEX_LEN))
    {
        return -1;
    }
    return finish_buffer(buffer,
                         snprintf(buffer, sizeof(buffer), "{\"type\":\"challenge\",\"snonce\":\"%s\"}", snonce),
                         out, out_len);
}

int proto_deserialize_challenge(const uint8_t *data, size_t data_len, char snonce[PROTO_NONCE_HEX_LEN + 1])
{
    char *json = open_message(data, data_len, "challenge");
    int rc;

    if (json == NULL)
    {
        return -1;
    }
    rc = read_nonce(json, "snonce", snonce);
    close_message(json);
    return rc;
}

/* ---------------- REQUEST ---------------- */

int proto_serialize_request(const ProtocolRequest *request, uint8_t **out, size_t *out_len)
{
    char buffer[PROTO_BUF_SIZE];
    char amount_part[48] = "";
    const char *op_name;

    if (request == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }

    op_name = operation_name(request->operation);
    if (op_name == NULL || !account_chars_valid(request->account) ||
        !lower_hex_valid(request->card_hex, CARD_SECRET_BYTES * 2) ||
        !lower_hex_valid(request->snonce, PROTO_NONCE_HEX_LEN) ||
        !lower_hex_valid(request->cnonce, PROTO_NONCE_HEX_LEN))
    {
        return -1;
    }

    if (request->has_amount)
    {
        snprintf(amount_part, sizeof(amount_part), ",\"amount_cents\":%llu", (unsigned long long)request->amount_cents);
    }

    return finish_buffer(
        buffer,
        snprintf(buffer, sizeof(buffer),
                 "{\"type\":\"request\",\"account\":\"%s\",\"operation\":\"%s\"%s,"
                 "\"snonce\":\"%s\",\"cnonce\":\"%s\",\"card_hex\":\"%s\"}",
                 request->account, op_name, amount_part,
                 request->snonce, request->cnonce, request->card_hex),
        out, out_len);
}

int proto_deserialize_request(const uint8_t *data, size_t data_len, ProtocolRequest *request)
{
    char operation_buf[32];
    uint64_t amount_cents = 0;
    int has_amount;
    char *json;

    if (request == NULL)
    {
        return -1;
    }
    memset(request, 0, sizeof(*request));

    json = open_message(data, data_len, "request");
    if (json == NULL)
    {
        return -1;
    }

    has_amount = find_uint64_value(json, "amount_cents", &amount_cents);

    if (find_string_value(json, "account", request->account, sizeof(request->account)) != 1 ||
        !account_chars_valid(request->account) ||
        find_string_value(json, "operation", operation_buf, sizeof(operation_buf)) != 1 ||
        operation_from_name(operation_buf, &request->operation) != 0 ||
        find_string_value(json, "card_hex", request->card_hex, sizeof(request->card_hex)) != 1 ||
        !lower_hex_valid(request->card_hex, CARD_SECRET_BYTES * 2) ||
        read_nonce(json, "snonce", request->snonce) != 0 ||
        read_nonce(json, "cnonce", request->cnonce) != 0 ||
        has_amount < 0)
    {
        close_message(json);
        return -1;
    }

    /* GET must not carry an amount; every other operation must. */
    if ((request->operation == PROTO_OP_GET) != (has_amount == 0))
    {
        close_message(json);
        return -1;
    }

    request->has_amount = (has_amount == 1);
    request->amount_cents = request->has_amount ? amount_cents : 0;
    close_message(json);
    return 0;
}

/* ---------------- RESPONSE ---------------- */

int proto_serialize_response(const ProtocolResponse *response, uint8_t **out, size_t *out_len)
{
    char buffer[PROTO_BUF_SIZE];
    char amount_part[48] = "";
    const char *op_name;

    if (response == NULL || out == NULL || out_len == NULL)
    {
        return -1;
    }

    op_name = operation_name(response->operation);
    if (op_name == NULL || !account_chars_valid(response->account) ||
        !lower_hex_valid(response->snonce, PROTO_NONCE_HEX_LEN) ||
        !lower_hex_valid(response->cnonce, PROTO_NONCE_HEX_LEN))
    {
        return -1;
    }

    if (response->has_amount)
    {
        snprintf(amount_part, sizeof(amount_part), ",\"amount_cents\":%llu", (unsigned long long)response->amount_cents);
    }

    return finish_buffer(
        buffer,
        snprintf(buffer, sizeof(buffer),
                 "{\"type\":\"response\",\"account\":\"%s\",\"operation\":\"%s\",\"ok\":%d%s,"
                 "\"snonce\":\"%s\",\"cnonce\":\"%s\"}",
                 response->account, op_name, response->ok ? 1 : 0, amount_part,
                 response->snonce, response->cnonce),
        out, out_len);
}

int proto_deserialize_response(const uint8_t *data, size_t data_len, ProtocolResponse *response)
{
    char operation_buf[32];
    uint64_t ok_u64 = 0;
    uint64_t amount_cents = 0;
    int has_amount;
    char *json;

    if (response == NULL)
    {
        return -1;
    }
    memset(response, 0, sizeof(*response));

    json = open_message(data, data_len, "response");
    if (json == NULL)
    {
        return -1;
    }

    has_amount = find_uint64_value(json, "amount_cents", &amount_cents);

    if (find_string_value(json, "account", response->account, sizeof(response->account)) != 1 ||
        !account_chars_valid(response->account) ||
        find_string_value(json, "operation", operation_buf, sizeof(operation_buf)) != 1 ||
        operation_from_name(operation_buf, &response->operation) != 0 ||
        find_uint64_value(json, "ok", &ok_u64) != 1 || (ok_u64 != 0 && ok_u64 != 1) ||
        read_nonce(json, "snonce", response->snonce) != 0 ||
        read_nonce(json, "cnonce", response->cnonce) != 0 ||
        has_amount < 0)
    {
        close_message(json);
        return -1;
    }

    response->ok = (ok_u64 == 1);
    response->has_amount = (has_amount == 1);
    response->amount_cents = response->has_amount ? amount_cents : 0;
    close_message(json);
    return 0;
}

/* ---------------- COMMIT ---------------- */

int proto_serialize_commit(const char *snonce, const char *cnonce, uint8_t **out, size_t *out_len)
{
    char buffer[PROTO_BUF_SIZE];

    if (snonce == NULL || cnonce == NULL || out == NULL || out_len == NULL ||
        !lower_hex_valid(snonce, PROTO_NONCE_HEX_LEN) || !lower_hex_valid(cnonce, PROTO_NONCE_HEX_LEN))
    {
        return -1;
    }
    return finish_buffer(
        buffer,
        snprintf(buffer, sizeof(buffer), "{\"type\":\"commit\",\"snonce\":\"%s\",\"cnonce\":\"%s\"}", snonce, cnonce),
        out, out_len);
}

int proto_deserialize_commit(
    const uint8_t *data,
    size_t data_len,
    char snonce[PROTO_NONCE_HEX_LEN + 1],
    char cnonce[PROTO_NONCE_HEX_LEN + 1])
{
    char *json = open_message(data, data_len, "commit");
    int rc;

    if (json == NULL)
    {
        return -1;
    }
    rc = (read_nonce(json, "snonce", snonce) == 0 && read_nonce(json, "cnonce", cnonce) == 0) ? 0 : -1;
    close_message(json);
    return rc;
}

/* ---------------- secure transport ---------------- */

int proto_send_secure(int sock, const CryptoKeys *keys, const uint8_t *plain, size_t plain_len)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    int rc;

    if (crypto_encrypt_then_mac(keys, plain, plain_len, &wire, &wire_len) != 0)
    {
        return -1;
    }
    rc = send_message(sock, wire, wire_len);
    crypto_secure_memzero(wire, wire_len);
    free(wire);
    return rc;
}

int proto_recv_secure(int sock, const CryptoKeys *keys, uint8_t **plain, size_t *plain_len)
{
    void *wire = NULL;
    int len;
    int rc;

    len = receive_message(sock, &wire);
    if (len < 0)
    {
        return -1;
    }
    rc = crypto_verify_then_decrypt(keys, (const uint8_t *)wire, (size_t)len, plain, plain_len);
    free(wire);
    return rc;
}
