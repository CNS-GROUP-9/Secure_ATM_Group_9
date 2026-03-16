#!/usr/bin/env bash
set -u

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

  "$@" >/dev/null 2>&1
  local code=$?
  if [ "$code" -eq "$expected" ]; then
    say_pass "$name (exit=$code)"
  else
    say_fail "$name (expected $expected, got $code)"
  fi
}

build_binaries() {
  gcc atm.c cli.c network.c crypto.c -o atm -lcrypto || return 1
  gcc bank.c cli.c network.c crypto.c -o bank -lpthread -lcrypto || return 1
  return 0
}

start_bank_bg() {
  local port="$1"
  local auth="$2"
  local out_file="$3"

  ./bank -p "$port" -s "$auth" >"$out_file" 2>&1 &
  echo $!
}

wait_for_created() {
  local out_file="$1"
  local retries=50

  while [ $retries -gt 0 ]; do
    if grep -q "^created$" "$out_file" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    retries=$((retries - 1))
  done
  return 1
}

run_tests() {
  local tag
  tag="manoj_test_$$"
  local auth_file="${tag}.auth"
  local single_auth="${tag}_single.auth"
  local bank_out="${tag}.bank.out"
  local single_out="${tag}.single.bank.out"
  local test_port=35555

  trap 'if [ -n "${bank_pid:-}" ]; then kill -TERM "$bank_pid" 2>/dev/null; wait "$bank_pid" 2>/dev/null; fi; if [ -n "${single_pid:-}" ]; then kill -TERM "$single_pid" 2>/dev/null; wait "$single_pid" 2>/dev/null; fi; rm -f "${auth_file:-}" "${single_auth:-}" "${bank_out:-}" "${single_out:-}" manoj_test_*.auth manoj_test_*.bank.out manoj_test_*_single.auth atm bank' EXIT

  if ! build_binaries; then
    echo "Build failed"
    exit 1
  fi
  say_pass "Build atm/bank"

  assert_exit 255 "ATM rejects missing account" ./atm -d 100.00
  assert_exit 255 "ATM rejects duplicate modes" ./atm -a bob -g -d 1.00
  assert_exit 255 "ATM rejects bad port range" ./atm -a bob -g -p 80
  assert_exit 255 "ATM rejects bad amount format" ./atm -a bob -d 100
  assert_exit 255 "ATM rejects bad IPv4" ./atm -a bob -g -i 999.1.1.1

  single_pid=$(start_bank_bg 35556 "$single_auth" "$single_out")
  if wait_for_created "$single_out"; then
    say_pass "Bank prints created"
  else
    say_fail "Bank prints created"
  fi

  if [ -f "$single_auth" ]; then
    say_pass "Bank creates auth file"
  else
    say_fail "Bank creates auth file"
  fi
  kill -TERM "$single_pid" 2>/dev/null
  wait "$single_pid" 2>/dev/null
  unset single_pid

  assert_exit 255 "Bank rejects existing auth file" ./bank -p 35557 -s "$single_auth"

  bank_pid=$(start_bank_bg "$test_port" "$auth_file" "$bank_out")
  if wait_for_created "$bank_out"; then
    say_pass "Bank starts in background"
  else
    say_fail "Bank starts in background"
    exit 1
  fi

  assert_exit 0 "ATM connects and sends framed message" ./atm -a alice -g -p "$test_port" -s "$auth_file"
  if grep -q "protocol_error" "$bank_out"; then
    say_fail "No protocol_error on normal ATM request"
  else
    say_pass "No protocol_error on normal ATM request"
  fi

  kill -TERM "$bank_pid" 2>/dev/null
  wait "$bank_pid" 2>/dev/null
  unset bank_pid

  assert_exit 63 "ATM returns 63 when bank unavailable" ./atm -a alice -g -p 36666 -s "$auth_file"

  echo
  echo "Total: $pass_count passed, $fail_count failed"
  if [ "$fail_count" -ne 0 ]; then
    exit 1
  fi
}

run_tests
