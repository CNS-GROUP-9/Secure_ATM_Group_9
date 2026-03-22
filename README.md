# Secure ATM

Secure ATM is a C-based client-server system with two binaries:

- bank: TCP server that stores account state and processes requests.
- atm: client CLI that validates input, builds requests, and prints output.

Communication is authenticated and encrypted using OpenSSL.

## Security Model

The system assumes a man-in-the-middle attacker can observe, modify, inject, or replay network traffic between ATM and bank.

- The attacker does not have the shared auth file distributed through a trusted channel.
- Account access is additionally gated by per-account card secrets in card files.
- The protocol is designed to provide confidentiality, integrity, endpoint authentication, and replay resistance.

## Project Structure

- atm.c: ATM client flow, card file handling, request/response integration.
- bank.c: Bank server, auth file creation, request handling, in-memory account database.
- cli.c / cli.h: command-line parsing and validation.
- network.c / network.h: framed TCP send/receive with timeouts.
- crypto.c / crypto.h: key loading/derivation, encrypt-then-MAC, verify-then-decrypt.
- protocol.c / protocol.h: request/response serialization and deserialization.
- build/Makefile: build rules for both binaries.
- test_comprehensive.sh: end-to-end and negative-path test suite.

## Build

From repository root:

```bash
cd build
make clean
make
```

This creates:

- build/atm
- build/bank

## Run

Open two terminals in repository root.

### 1) Start bank

```bash
./bank -p 3000 -s bank.auth
```

Expected behavior:

- Prints created on startup.
- Creates bank.auth if it does not already exist.

### 2) Run ATM commands
(These work correctly if run from build directory. You can also run them from other directories, then use absolute path or the path of the binary relative to it)
Create account:

```bash
./atm -a alice -n 1000.00 -p 3000 -s bank.auth
```

Deposit:

```bash
./atm -a alice -d 100.00 -p 3000 -s bank.auth
```

Withdraw:

```bash
./atm -a alice -w 63.10 -p 3000 -s bank.auth
```

Get balance:

```bash
./atm -a alice -g -p 3000 -s bank.auth
```

Optional card file path:

```bash
./atm -a alice -g -p 3000 -s bank.auth -c alice.card
```

## Brief Code Logic

Each ATM operation follows this high-level pipeline:

1. Parse and validate CLI input.
2. Load auth secret and derive crypto keys.
3. Build protocol request (including account, operation, amount/card data).
4. Serialize request payload.
5. Encrypt payload and attach MAC.
6. Send framed message to bank over TCP.
7. Receive framed response from bank.
8. Verify MAC, decrypt response, deserialize fields.
9. Print required JSON output or return failure code.

Each bank worker thread follows this high-level pipeline:

1. Receive framed request.
2. Verify MAC and decrypt payload.
3. Deserialize request and validate protocol fields.
4. Execute business logic on in-memory account data (mutex protected).
5. Build response (success or business failure).
6. Serialize, encrypt, MAC, and send response.

## Protocol and Key Design

- Shared root secret: bank generates an auth file on startup; ATM and bank load it locally.
- Key derivation: two independent keys are derived using SHA-256 labels (`ENC` and `MAC`).
- Message protection: Encrypt-Then-MAC using AES-256-CBC and HMAC-SHA256.
- Framing: length-prefixed TCP messages (`len || payload`) with socket timeouts.
- Freshness: ATM includes a nonce per request; bank tracks recently seen nonces (sliding window) to reject replays.
- Account ownership: ATM includes card secret in protected request data; bank validates it against account state.

## Command-Line Contract

Supported forms:

- `bank [-p <port>] [-s <auth-file>]`
- `atm ... -a <account> -n <balance>`
- `atm ... -a <account> -d <amount>`
- `atm ... -a <account> -w <amount>`
- `atm ... -a <account> -g`

Defaults:

- `bank`: port `3000`, auth file `bank.auth`
- `atm`: IP `127.0.0.1`, port `3000`, auth file `bank.auth`, card file `<account>.card`

Rules enforced by CLI parser:

- Arguments may appear in any order.
- Clustered options such as `-ga` are accepted.
- Missing required parameters, duplicated parameters, unknown options, or invalid values return exit code `255` with no stdout output.

## Input and Output Guarantees

Input validation includes:

- Port range `1024..65535`.
- IPv4 dotted-decimal format checks.
- Account/file character restrictions and length checks.
- Currency format checks with two fractional digits and internal cents conversion.

Output behavior:

- Successful transaction output is single-line JSON followed by `\n`.
- Bank prints `created` after writing auth file completely.
- Bank prints `protocol_error` on protocol violations and continues serving other clients.
- stdout is flushed after each printed line.

## Exit and Error Behavior

- Exit 0: successful ATM operation.
- Exit 255: invalid CLI input or business-rule failure.
- Exit 63: transport/protocol/timeout errors.
- Protocol errors trigger rollback of the current transaction on bank side.
- Bank logs protocol_error for malformed, tampered, replayed, or timed-out protocol requests.

## Test (Optional)

Run the comprehensive test suite from repository root:

```bash
bash test_comprehensive.sh
```

The script builds binaries, runs positive and negative scenarios, and prints a final summary line:

- Total: X passed, Y failed

### What We Tested (35 Tests)

The 35 checks in `test_comprehensive.sh` cover the following:

- Build and helper compilation: verifies `atm` and `bank` build cleanly and protocol helper clients compile.
- CLI validation: rejects missing account, duplicate modes/options, invalid ports, invalid amount formats, invalid IPv4, and invalid bank options.
- Bank startup behavior: confirms startup prints `created`, creates auth file, and rejects reuse of an existing auth file.
- Core transaction flow: verifies successful create, deposit, withdraw, and get-balance responses with expected JSON output.
- Business-rule failures: verifies duplicate account creation, insufficient funds, wrong card access, and corrupted card file handling.
- Option parsing edge cases: verifies clustered ATM options (for example, `-ga`) work correctly.
- Output format checks: confirms successful output includes a trailing newline.
- Protocol robustness: verifies malformed frame handling and timeout behavior produce `protocol_error` on bank side.
- Network failure paths: verifies ATM returns the expected error code when bank is unreachable or response times out.
- Restart/auth semantics: verifies behavior with old auth material after bank restart and confirms in-memory state is not persisted.

## Notes

- Bank state is in-memory and is not persisted across restarts.
- Existing auth file is treated as an error for bank startup with the same path.
- The command "make clean" removes the bankdir and atmdir, so when it is run all current accounts are lost.
