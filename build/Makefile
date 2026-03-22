CC ?= gcc
CFLAGS ?= -O2

COMMON_SRCS = ../cli.c ../network.c ../crypto.c ../protocol.c
COMMON_HDRS = ../cli.h ../network.h ../crypto.h ../protocol.h

all: atm bank

atm: ../atm.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) ../atm.c $(COMMON_SRCS) -o atm -lcrypto

bank: ../bank.c $(COMMON_SRCS) $(COMMON_HDRS)
	$(CC) $(CFLAGS) ../bank.c $(COMMON_SRCS) -o bank -lpthread -lcrypto

clean:
	rm -f atm bank
	@if [ -d bankdir ]; then find bankdir ! -type d -delete; find bankdir -depth -type d -exec rmdir {} +; fi
	@if [ -d atmdir ]; then find atmdir ! -type d -delete; find atmdir -depth -type d -exec rmdir {} +; fi

.PHONY: all clean
