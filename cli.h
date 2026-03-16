#ifndef CLI_H
#define CLI_H

typedef struct {
    char account[128];
    char auth_file[128];
    char card_file[128];
    char ip[64];
    int port;

    int mode; // 1=create 2=deposit 3=withdraw 4=get
    double amount;
} ATMArgs;

typedef struct {
    char auth_file[128];
    int port;
} BankArgs;

int parse_atm_args(int argc, char **argv, ATMArgs *args);
int parse_bank_args(int argc, char **argv, BankArgs *args);

#endif