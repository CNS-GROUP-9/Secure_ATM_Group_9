#!/usr/bin/env bash
set -euo pipefail

AUTH="praneeth_test.auth"
BANK_OUT="praneeth_bank.out"
PORT=36000
ACCOUNT="alice"
CARD="${ACCOUNT}.card"

pass_count=0
fail_count=0

say_pass() {
  echo "[PASS] $1"
  pass_count=$((pass_count + 1))
}

say_fail() {
  echo "[FAIL] $1"
  fail_count=$((fail_count + 1))
}

assert_exit() {
  local expected="$1"
  shift
  local name="$1"
  shift

  set +e
  "$@" >/dev/null 2>&1
  local code=$?
  set -e

  if [ "$code" -eq "$expected" ]; then
    say_pass "$name (exit=$code)"
  else
    say_fail "$name (expected $expected, got $code)"
  fi
}

wait_for_created() {
  local retries=50

  while [ "$retries" -gt 0 ]; do
    if grep -q "^created$" "$BANK_OUT" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    retries=$((retries - 1))
  done

  return 1
}

cleanup() {
  if [ -n "${BANK_PID:-}" ]; then
    kill -TERM "$BANK_PID" 2>/dev/null || true
    wait "$BANK_PID" 2>/dev/null || true
  fi
  rm -f "$AUTH" "$BANK_OUT" "$CARD" bob.card bad.card atm bank
}

trap cleanup EXIT

# build
gcc atm.c cli.c network.c crypto.c protocol.c -o atm -lcrypto
gcc bank.c cli.c network.c crypto.c protocol.c -o bank -lpthread -lcrypto
say_pass "Build atm/bank"

# start bank
./bank -p "$PORT" -s "$AUTH" >"$BANK_OUT" 2>&1 &
BANK_PID=$!

if wait_for_created; then
  say_pass "Bank prints created"
else
  say_fail "Bank prints created"
  echo
  echo "Total: $pass_count passed, $fail_count failed"
  exit 2
fi

if [ -f "$AUTH" ]; then
  say_pass "Bank creates auth file"
else
  say_fail "Bank creates auth file"
fi

# positive flow
rm -f "$CARD"
assert_exit 0 "create account" ./atm -a "$ACCOUNT" -n 1500.00 -p "$PORT" -s "$AUTH"
assert_exit 0 "deposit" ./atm -a "$ACCOUNT" -d 100.00 -p "$PORT" -s "$AUTH"
assert_exit 0 "withdraw" ./atm -a "$ACCOUNT" -w 63.10 -p "$PORT" -s "$AUTH"
assert_exit 0 "get balance" ./atm -a "$ACCOUNT" -g -p "$PORT" -s "$AUTH"

sleep 0.2

grep -q '^{"account":"alice","initial_balance":1500}$' "$BANK_OUT" || {
  say_fail "BANK missing initial_balance JSON"
}
grep -q '^{"account":"alice","deposit":100}$' "$BANK_OUT" || {
  say_fail "BANK missing deposit JSON"
}
grep -q '^{"account":"alice","withdraw":63.1}$' "$BANK_OUT" || {
  say_fail "BANK missing withdraw JSON"
}
grep -q '^{"account":"alice","balance":1536.9}$' "$BANK_OUT" || {
  say_fail "BANK missing balance JSON"
}

echo "Running negative tests..."

assert_exit 255 "duplicate create" ./atm -a "$ACCOUNT" -n 2000.00 -p "$PORT" -s "$AUTH"
assert_exit 255 "insufficient funds withdraw" ./atm -a "$ACCOUNT" -w 2000000.00 -p "$PORT" -s "$AUTH"

rm -f bob.card
assert_exit 0 "create bob" ./atm -a bob -n 10.00 -p "$PORT" -s "$AUTH"
assert_exit 255 "wrong card access" ./atm -a "$ACCOUNT" -g -p "$PORT" -s "$AUTH" -c bob.card

echo "zzzz" > bad.card
assert_exit 255 "corrupted card file" ./atm -a "$ACCOUNT" -g -p "$PORT" -s "$AUTH" -c bad.card

echo
echo "Total: $pass_count passed, $fail_count failed"
if [ "$fail_count" -ne 0 ]; then
  exit 2
fi
