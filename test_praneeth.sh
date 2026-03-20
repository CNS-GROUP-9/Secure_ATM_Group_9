#!/usr/bin/env bash
set -euo pipefail

ROOT=$(pwd)
AUTH=praneeth_test.auth
BANK_OUT=praneeth_bank.out
PORT=36000
ACCOUNT=alice
CARD=${ACCOUNT}.card

# build
OPENSSL_PREFIX=$(brew --prefix openssl 2>/dev/null || true)
CFLAGS="-I$OPENSSL_PREFIX/include"
LDFLAGS="-L$OPENSSL_PREFIX/lib -lcrypto"

gcc atm.c cli.c network.c crypto.c protocol.c -o atm $CFLAGS $LDFLAGS
gcc bank.c cli.c network.c crypto.c protocol.c -o bank -lpthread $CFLAGS $LDFLAGS

# start bank
./bank -p $PORT -s $AUTH >$BANK_OUT 2>&1 &
BANK_PID=$!

trap 'kill -TERM "$BANK_PID" 2>/dev/null || true; wait "$BANK_PID" 2>/dev/null || true; rm -f "$AUTH" "$BANK_OUT" "$CARD" atm bank' EXIT

# wait for created
for i in {1..50}; do
  if grep -q "^created$" "$BANK_OUT" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

# create account alice
rm -f "$CARD"
./atm -a "$ACCOUNT" -n 1500.00 -p $PORT -s $AUTH
# deposit
./atm -a alice -d 100.00 -p $PORT -s $AUTH
# withdraw
./atm -a alice -w 63.10 -p $PORT -s $AUTH
# get
./atm -a alice -g -p $PORT -s $AUTH

sleep 0.2

# check expected bank outputs
grep -q '^{"account":"alice","initial_balance":1500}$' $BANK_OUT || { echo "BANK MISSING initial_balance"; exit 2; }
grep -q '^{"account":"alice","deposit":100}$' $BANK_OUT || { echo "BANK MISSING deposit"; exit 2; }
grep -q '^{"account":"alice","withdraw":63.1}$' $BANK_OUT || { echo "BANK MISSING withdraw"; exit 2; }
grep -q '^{"account":"alice","balance":1536.9}$' $BANK_OUT || { echo "BANK MISSING balance"; exit 2; }

echo "test_praneeth completed"

# --- extra negative tests ---
pass_count=0
fail_count=0

assert_exit() {
  local expected=$1
  shift
  local name="$1"
  shift
  set +e
  "$@" >/dev/null 2>&1
  local code=$?
  set -e
  if [ "$code" -eq "$expected" ]; then
    echo "[PASS] $name (exit=$code)"
    pass_count=$((pass_count+1))
  else
    echo "[FAIL] $name (expected $expected, got $code)"
    fail_count=$((fail_count+1))
  fi
}

echo "Running negative tests..."

# duplicate create should fail
assert_exit 255 "duplicate create" ./atm -a "$ACCOUNT" -n 2000.00 -p $PORT -s $AUTH

# withdraw too much should fail
assert_exit 255 "insufficient funds withdraw" ./atm -a "$ACCOUNT" -w 2000000.00 -p $PORT -s $AUTH

# create another account bob to get a bob.card
rm -f bob.card
assert_exit 0 "create bob" ./atm -a bob -n 10.00 -p $PORT -s $AUTH

# using bob's card to access alice should fail
assert_exit 255 "wrong card access" ./atm -a "$ACCOUNT" -g -p $PORT -s $AUTH -c bob.card

# corrupted card file should fail
echo "zzzz" > bad.card
assert_exit 255 "corrupted card file" ./atm -a "$ACCOUNT" -g -p $PORT -s $AUTH -c bad.card
rm -f bad.card

echo
echo "Negative tests: $pass_count passed, $fail_count failed"
if [ "$fail_count" -ne 0 ]; then
  exit 2
fi
