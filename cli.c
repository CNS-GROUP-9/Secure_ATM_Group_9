#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "cli.h"

#define MAX_ARG_CHARS 4096

static int has_valid_name_chars(const char *s) {
    size_t i;

    for (i = 0; s[i] != '\0'; i++) {
        char c = s[i];
        if (!(c == '_' || c == '-' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z'))) {
            return 0;
        }
    }

    return 1;
}

static int validate_filename(const char *s) {
    size_t len = strlen(s);

    if (len < 1 || len > 127) {
        return 0;
    }
    if ((strcmp(s, ".") == 0) || (strcmp(s, "..") == 0)) {
        return 0;
    }

    return has_valid_name_chars(s);
}

static int validate_account_name(const char *s) {
    size_t len = strlen(s);

    if (len < 1 || len > 122) {
        return 0;
    }

    return has_valid_name_chars(s);
}

static int parse_number_no_leading_zero(const char *s, uint64_t *out, uint64_t max_val) {
    uint64_t value = 0;
    size_t len = strlen(s);
    size_t i;

    if (len == 0) {
        return 0;
    }
    if (len > 1 && s[0] == '0') {
        return 0;
    }
    for (i = 0; i < len; i++) {
        if (!isdigit((unsigned char)s[i])) {
            return 0;
        }
        value = value * 10 + (uint64_t)(s[i] - '0');
        if (value > max_val) {
            return 0;
        }
    }

    *out = value;
    return 1;
}

static int parse_money_amount(const char *s, double *out) {
    const char *dot;
    char whole_buf[32];
    char frac_buf[3];
    uint64_t whole = 0;
    uint64_t frac = 0;
    size_t whole_len;

    dot = strchr(s, '.');
    if (dot == NULL) {
        return 0;
    }
    if (strchr(dot + 1, '.') != NULL) {
        return 0;
    }

    whole_len = (size_t)(dot - s);
    if (whole_len == 0 || whole_len >= sizeof(whole_buf)) {
        return 0;
    }
    if (strlen(dot + 1) != 2) {
        return 0;
    }

    memcpy(whole_buf, s, whole_len);
    whole_buf[whole_len] = '\0';
    frac_buf[0] = dot[1];
    frac_buf[1] = dot[2];
    frac_buf[2] = '\0';

    if (!parse_number_no_leading_zero(whole_buf, &whole, 4294967295ULL)) {
        return 0;
    }
    if (!isdigit((unsigned char)frac_buf[0]) || !isdigit((unsigned char)frac_buf[1])) {
        return 0;
    }
    frac = (uint64_t)((frac_buf[0] - '0') * 10 + (frac_buf[1] - '0'));

    *out = (double)whole + ((double)frac / 100.0);
    return 1;
}

static int validate_ipv4(const char *s) {
    int parts = 0;
    const char *p = s;

    while (*p != '\0') {
        uint64_t octet = 0;
        int digits = 0;

        if (!isdigit((unsigned char)*p)) {
            return 0;
        }
        if (*p == '0' && isdigit((unsigned char)*(p + 1))) {
            return 0;
        }

        while (*p != '\0' && *p != '.') {
            if (!isdigit((unsigned char)*p)) {
                return 0;
            }
            octet = octet * 10 + (uint64_t)(*p - '0');
            if (octet > 255) {
                return 0;
            }
            digits++;
            p++;
        }

        if (digits == 0) {
            return 0;
        }
        parts++;

        if (*p == '.') {
            p++;
            if (*p == '\0') {
                return 0;
            }
        }
    }

    return parts == 4;
}

static int validate_all_argv_lengths(int argc, char **argv) {
    int i;

    for (i = 0; i < argc; i++) {
        if (strlen(argv[i]) > MAX_ARG_CHARS) {
            return 0;
        }
    }

    return 1;
}

int parse_atm_args(int argc, char **argv, ATMArgs *args) {
    int opt;
    int seen_a = 0;
    int seen_mode = 0;
    int seen_s = 0;
    int seen_i = 0;
    int seen_p = 0;
    int seen_c = 0;

    if (!validate_all_argv_lengths(argc, argv)) {
        return -1;
    }

    memset(args, 0, sizeof(ATMArgs));
    snprintf(args->auth_file, sizeof(args->auth_file), "bank.auth");
    snprintf(args->ip, sizeof(args->ip), "127.0.0.1");
    args->port = 3000;

    opterr = 0;
    optind = 1;
    while ((opt = getopt(argc, argv, "a:n:d:w:gs:p:i:c:")) != -1) {
        uint64_t port_val = 0;

        switch (opt) {
            case 'a':
                if (seen_a || !validate_account_name(optarg) || strlen(optarg) >= sizeof(args->account)) {
                    return -1;
                }
                seen_a = 1;
                snprintf(args->account, sizeof(args->account), "%s", optarg);
                break;
            case 'n':
                if (seen_mode || !parse_money_amount(optarg, &args->amount) || args->amount < 10.0) {
                    return -1;
                }
                seen_mode = 1;
                args->mode = 1;
                break;
            case 'd':
                if (seen_mode || !parse_money_amount(optarg, &args->amount) || args->amount <= 0.0) {
                    return -1;
                }
                seen_mode = 1;
                args->mode = 2;
                break;
            case 'w':
                if (seen_mode || !parse_money_amount(optarg, &args->amount) || args->amount <= 0.0) {
                    return -1;
                }
                seen_mode = 1;
                args->mode = 3;
                break;
            case 'g':
                if (seen_mode) {
                    return -1;
                }
                seen_mode = 1;
                args->mode = 4;
                break;
            case 's':
                if (seen_s || !validate_filename(optarg) || strlen(optarg) >= sizeof(args->auth_file)) {
                    return -1;
                }
                seen_s = 1;
                snprintf(args->auth_file, sizeof(args->auth_file), "%s", optarg);
                break;
            case 'i':
                if (seen_i || !validate_ipv4(optarg) || strlen(optarg) >= sizeof(args->ip)) {
                    return -1;
                }
                seen_i = 1;
                snprintf(args->ip, sizeof(args->ip), "%s", optarg);
                break;
            case 'p':
                if (seen_p || !parse_number_no_leading_zero(optarg, &port_val, 65535ULL)) {
                    return -1;
                }
                if (port_val < 1024ULL || port_val > 65535ULL) {
                    return -1;
                }
                seen_p = 1;
                args->port = (int)port_val;
                break;
            case 'c':
                if (seen_c || !validate_filename(optarg) || strlen(optarg) >= sizeof(args->card_file)) {
                    return -1;
                }
                seen_c = 1;
                snprintf(args->card_file, sizeof(args->card_file), "%s", optarg);
                break;
            default:
                return -1;
        }
    }

    if (!seen_a || !seen_mode || optind != argc) {
        return -1;
    }

    if (!seen_c) {
        int n = snprintf(args->card_file, sizeof(args->card_file), "%s.card", args->account);
        if (n <= 0 || (size_t)n >= sizeof(args->card_file) || !validate_filename(args->card_file)) {
            return -1;
        }
    }

    return 0;
}

int parse_bank_args(int argc, char **argv, BankArgs *args) {
    int opt;
    int seen_p = 0;
    int seen_s = 0;

    if (!validate_all_argv_lengths(argc, argv)) {
        return -1;
    }

    memset(args, 0, sizeof(BankArgs));
    snprintf(args->auth_file, sizeof(args->auth_file), "bank.auth");
    args->port = 3000;

    opterr = 0;
    optind = 1;
    while ((opt = getopt(argc, argv, "p:s:")) != -1) {
        uint64_t port_val = 0;

        switch (opt) {
            case 'p':
                if (seen_p || !parse_number_no_leading_zero(optarg, &port_val, 65535ULL)) {
                    return -1;
                }
                if (port_val < 1024ULL || port_val > 65535ULL) {
                    return -1;
                }
                seen_p = 1;
                args->port = (int)port_val;
                break;
            case 's':
                if (seen_s || !validate_filename(optarg) || strlen(optarg) >= sizeof(args->auth_file)) {
                    return -1;
                }
                seen_s = 1;
                snprintf(args->auth_file, sizeof(args->auth_file), "%s", optarg);
                break;
            default:
                return -1;
        }
    }

    if (optind != argc) {
        return -1;
    }

    return 0;
}
