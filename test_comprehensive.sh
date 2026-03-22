#!/usr/bin/env bash
set -u

pass_count=0
fail_count=0
SUITE="cns_spec_$$"
TMP_DIR="${SUITE}.tmp"
BANK_PID=""

say_pass() {
  echo "[PASS] $1"
  pass_count=$((pass_count + 1))
}

say_fail() {
  echo "[FAIL] $1"
  fail_count=$((fail_count + 1))
}

cleanup_bank() {
  if [ -n "${BANK_PID}" ]; then
    kill -TERM "${BANK_PID}" >/dev/null 2>&1 || true
    wait "${BANK_PID}" >/dev/null 2>&1 || true
    BANK_PID=""
  fi
}

cleanup() {
  cleanup_bank
  rm -rf "${TMP_DIR}"
  rm -f atm bank
  rm -f "${SUITE}.a.auth" "${SUITE}.b.auth" "${SUITE}.slow.auth"
  rm -f "${SUITE}.alice2.card" "${SUITE}.bad.card"
  rm -f alice.card bob.card posix.card
}

trap cleanup EXIT

run_capture() {
  local out_file="$1"
  shift
  "$@" >"${out_file}" 2>/dev/null
  return $?
}

assert_exit_and_stdout_empty() {
  local expected="$1"
  local name="$2"
  shift 2
  local out_file="${TMP_DIR}/${name}.out"

  run_capture "${out_file}" "$@"
  local code=$?

  if [ "${code}" -ne "${expected}" ]; then
    say_fail "${name} (expected exit ${expected}, got ${code})"
    return
  fi

  if [ -s "${out_file}" ]; then
    say_fail "${name} (stdout not empty)"
    return
  fi

  say_pass "${name}"
}

assert_exit_and_stdout_exact() {
  local expected_exit="$1"
  local expected_stdout="$2"
  local name="$3"
  shift 3
  local out_file="${TMP_DIR}/${name}.out"

  run_capture "${out_file}" "$@"
  local code=$?

  if [ "${code}" -ne "${expected_exit}" ]; then
    say_fail "${name} (expected exit ${expected_exit}, got ${code})"
    return
  fi

  local actual
  actual="$(cat "${out_file}")"
  if [ "${actual}" != "${expected_stdout}" ]; then
    say_fail "${name} (stdout mismatch)"
    echo "  expected: ${expected_stdout}"
    echo "  actual  : ${actual}"
    return
  fi

  say_pass "${name}"
}

wait_for_line() {
  local file="$1"
  local pattern="$2"
  local retries=80

  while [ "${retries}" -gt 0 ]; do
    if grep -Eq "${pattern}" "${file}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    retries=$((retries - 1))
  done
  return 1
}

build_binaries() {
  if [ -f build/Makefile ]; then
    (cd build && make clean >/dev/null 2>&1 && make >/dev/null 2>&1) || return 1
    cp build/atm ./atm || return 1
    cp build/bank ./bank || return 1
    return 0
  fi

  gcc atm.c cli.c network.c crypto.c protocol.c -o atm -lcrypto || return 1
  gcc bank.c cli.c network.c crypto.c protocol.c -o bank -lpthread -lcrypto || return 1
  return 0
}

start_bank() {
  local port="$1"
  local auth="$2"
  local out="$3"

  ./bank -p "${port}" -s "${auth}" >"${out}" 2>&1 &
  BANK_PID=$!

  if wait_for_line "${out}" '^created$'; then
    return 0
  fi

  cleanup_bank
  return 1
}

compile_helpers() {
  cat > "${TMP_DIR}/malformed_client.c" <<'EOF'
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int port;
    int sock;
    struct sockaddr_in addr;
    uint32_t len;
    const char *msg = "HELLO";

    if (argc != 2) return 2;
    port = atoi(argv[1]);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 3;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 4;
    }

    len = htonl(5);
    if (send(sock, &len, sizeof(len), 0) != 4) {
        close(sock);
        return 5;
    }
    if (send(sock, msg, 5, 0) != 5) {
        close(sock);
        return 6;
    }

    close(sock);
    return 0;
}
EOF

  cat > "${TMP_DIR}/partial_client.c" <<'EOF'
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int port;
    int sock;
    struct sockaddr_in addr;
    unsigned char two_bytes[2] = {0x00, 0x40};

    if (argc != 2) return 2;
    port = atoi(argv[1]);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 3;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return 4;
    }

    if (send(sock, two_bytes, 2, 0) != 2) {
        close(sock);
        return 5;
    }

    sleep(12);
    close(sock);
    return 0;
}
EOF

  cat > "${TMP_DIR}/slow_server.c" <<'EOF'
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int port;
    int srv;
    int cli;
    int opt = 1;
    struct sockaddr_in addr;

    if (argc != 2) return 2;
    port = atoi(argv[1]);

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return 3;

    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(srv);
        return 4;
    }

    if (listen(srv, 1) < 0) {
        close(srv);
        return 5;
    }

    cli = accept(srv, NULL, NULL);
    if (cli >= 0) {
      sleep(12);
      close(cli);
    }

    close(srv);
    return 0;
}
EOF

  gcc "${TMP_DIR}/malformed_client.c" -o "${TMP_DIR}/malformed_client" || return 1
  gcc "${TMP_DIR}/partial_client.c" -o "${TMP_DIR}/partial_client" || return 1
  gcc "${TMP_DIR}/slow_server.c" -o "${TMP_DIR}/slow_server" || return 1
  return 0
}

main() {
  mkdir -p "${TMP_DIR}"

  if ! build_binaries; then
    echo "Build failed"
    exit 1
  fi
  say_pass "build atm and bank"

  if ! compile_helpers; then
    echo "Helper build failed"
    exit 1
  fi
  say_pass "build protocol test helpers"

  local AUTH_A="${SUITE}.a.auth"
  local AUTH_B="${SUITE}.b.auth"
  local BANK_A_OUT="${TMP_DIR}/bank_a.out"
  local BANK_B_OUT="${TMP_DIR}/bank_b.out"
  local PORT_A=37001
  local PORT_B=37002
  local PORT_C=37003

  assert_exit_and_stdout_empty 255 "atm_missing_account" ./atm -g
  assert_exit_and_stdout_empty 255 "atm_duplicate_mode" ./atm -a bob -g -d 1.00
  assert_exit_and_stdout_empty 255 "atm_duplicate_option" ./atm -a bob -a alice -g
  assert_exit_and_stdout_empty 255 "atm_invalid_port_low" ./atm -a bob -g -p 1000
  assert_exit_and_stdout_empty 255 "atm_invalid_port_high" ./atm -a bob -g -p 70000
  assert_exit_and_stdout_empty 255 "atm_invalid_amount_format" ./atm -a bob -d 100
  assert_exit_and_stdout_empty 255 "atm_invalid_amount_leading_zero" ./atm -a bob -d 01.00
  assert_exit_and_stdout_empty 255 "atm_invalid_ipv4" ./atm -a bob -g -i 999.0.0.1
  assert_exit_and_stdout_empty 255 "bank_invalid_option" ./bank -x
  assert_exit_and_stdout_empty 255 "bank_duplicate_port" ./bank -p 37000 -p 37001

  if start_bank "${PORT_A}" "${AUTH_A}" "${BANK_A_OUT}"; then
    say_pass "bank startup creates auth and prints created"
  else
    say_fail "bank startup creates auth and prints created"
    echo
    echo "Total: ${pass_count} passed, ${fail_count} failed"
    exit 2
  fi

  if [ -f "${AUTH_A}" ]; then
    say_pass "bank auth file created"
  else
    say_fail "bank auth file created"
  fi

  assert_exit_and_stdout_empty 255 "bank_reject_existing_auth" ./bank -p "${PORT_B}" -s "${AUTH_A}"

  assert_exit_and_stdout_exact 0 '{"account":"alice","initial_balance":1000}' "create_alice" ./atm -a alice -n 1000.00 -p "${PORT_A}" -s "${AUTH_A}"
  assert_exit_and_stdout_exact 0 '{"account":"alice","deposit":100}' "deposit_alice" ./atm -a alice -d 100.00 -p "${PORT_A}" -s "${AUTH_A}"
  assert_exit_and_stdout_exact 0 '{"account":"alice","withdraw":63.1}' "withdraw_alice" ./atm -a alice -w 63.10 -p "${PORT_A}" -s "${AUTH_A}"
  assert_exit_and_stdout_exact 0 '{"account":"alice","balance":1036.9}' "get_alice_balance" ./atm -a alice -g -p "${PORT_A}" -s "${AUTH_A}"

  assert_exit_and_stdout_empty 255 "duplicate_account_create" ./atm -a alice -n 10.00 -p "${PORT_A}" -s "${AUTH_A}" -c "${SUITE}.alice2.card"
  if [ -f "${SUITE}.alice2.card" ]; then
    say_fail "failed create does not write new card"
  else
    say_pass "failed create does not write new card"
  fi

  assert_exit_and_stdout_empty 255 "insufficient_funds" ./atm -a alice -w 99999.99 -p "${PORT_A}" -s "${AUTH_A}"
  assert_exit_and_stdout_exact 0 '{"account":"bob","initial_balance":10}' "create_bob" ./atm -a bob -n 10.00 -p "${PORT_A}" -s "${AUTH_A}"
  assert_exit_and_stdout_empty 255 "wrong_card_access" ./atm -a alice -g -p "${PORT_A}" -s "${AUTH_A}" -c bob.card

  echo zzzz > "${SUITE}.bad.card"
  assert_exit_and_stdout_empty 255 "corrupted_card_file" ./atm -a alice -g -p "${PORT_A}" -s "${AUTH_A}" -c "${SUITE}.bad.card"

  assert_exit_and_stdout_exact 0 '{"account":"posix","initial_balance":10}' "create_posix" ./atm -a posix -n 10.00 -p "${PORT_A}" -s "${AUTH_A}"
  assert_exit_and_stdout_exact 0 '{"account":"posix","balance":10}' "posix_clustered_options" ./atm -ga posix -p "${PORT_A}" -s "${AUTH_A}"

  ./atm -a alice -g -p "${PORT_A}" -s "${AUTH_A}" >"${TMP_DIR}/tmp_success.out" 2>/dev/null
  if [ -s "${TMP_DIR}/tmp_success.out" ] && [ "$(tail -c 1 "${TMP_DIR}/tmp_success.out" | wc -l)" -eq 1 ]; then
    say_pass "successful output ends with newline"
  else
    say_fail "successful output ends with newline"
  fi

  "${TMP_DIR}/malformed_client" "${PORT_A}" >/dev/null 2>&1
  if wait_for_line "${BANK_A_OUT}" 'protocol_error'; then
    say_pass "bank reports protocol_error for malformed client frame"
  else
    say_fail "bank reports protocol_error for malformed client frame"
  fi

  "${TMP_DIR}/partial_client" "${PORT_A}" >/dev/null 2>&1 &
  sleep 11
  if grep -Eq 'protocol_error' "${BANK_A_OUT}"; then
    say_pass "bank timeout path emits protocol_error"
  else
    say_fail "bank timeout path emits protocol_error"
  fi

  assert_exit_and_stdout_empty 63 "atm_unreachable_bank" ./atm -a alice -g -p 37999 -s "${AUTH_A}"

  cleanup_bank

  if start_bank "${PORT_A}" "${AUTH_B}" "${BANK_B_OUT}"; then
    say_pass "bank restart with new auth works"
  else
    say_fail "bank restart with new auth works"
  fi

  assert_exit_and_stdout_empty 63 "atm_old_auth_protocol_error" ./atm -a alice -g -p "${PORT_A}" -s "${AUTH_A}" -c alice.card
  assert_exit_and_stdout_empty 255 "state_not_persisted_after_restart" ./atm -a alice -g -p "${PORT_A}" -s "${AUTH_B}" -c alice.card

  cleanup_bank

  ./bank -p "${PORT_C}" -s "${SUITE}.slow.auth" >"${TMP_DIR}/slow_bank.out" 2>&1 &
  local temp_bank=$!
  sleep 1
  kill -TERM "${temp_bank}" >/dev/null 2>&1 || true
  wait "${temp_bank}" >/dev/null 2>&1 || true

  "${TMP_DIR}/slow_server" "${PORT_C}" >/dev/null 2>&1 &
  local slow_pid=$!
  sleep 0.5
  assert_exit_and_stdout_empty 63 "atm_timeout_waiting_for_response" ./atm -a timeout -g -p "${PORT_C}" -s "${SUITE}.slow.auth" -c alice.card
  kill -TERM "${slow_pid}" >/dev/null 2>&1 || true
  wait "${slow_pid}" >/dev/null 2>&1 || true

  echo
  echo "Total: ${pass_count} passed, ${fail_count} failed"

  if [ "${fail_count}" -ne 0 ]; then
    exit 2
  fi
}

main
