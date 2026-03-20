# Secure_ATM_Group_9

## Manoj Module Status

Command-line Parser + Network Communication Module: complete and tested.

Implemented:

- ATM argument parsing for `-a -n -d -w -g -s -i -p -c`
- strict validation (duplicates, formats, ranges, defaults)
- bank argument parsing for `-p -s`
- TCP client/server communication
- length-prefixed framing (`len || message`)
- socket timeouts
- bank thread-per-connection model
- bank auth-file creation on startup

## Saharsh Module Status

Cryptographic Module + Protocol Serialization Module: complete and tested.

Implemented:

- auth-file secret loading from bank-generated hex key material
- key derivation for separate encryption and MAC keys
- AES-256-CBC encryption for protocol payloads
- HMAC-SHA256 authentication over encrypted payloads
- encrypt-then-MAC and verify-then-decrypt helpers
- secure memory wiping for derived secrets and plaintext buffers
- protocol request struct for ATM-to-bank messages
- protocol response struct for bank-to-ATM messages
- serialization of request/response payloads into JSON-like plaintext
- deserialization and validation of decrypted request/response payloads
- nonce generation for per-request freshness
- amount conversion to integer cents before serialization
- ATM integration: build request, serialize, encrypt, send
- bank integration: receive, decrypt, deserialize, validate

## Build

```bash
gcc atm.c cli.c network.c crypto.c protocol.c -o atm -lcrypto
gcc bank.c cli.c network.c crypto.c protocol.c -o bank -lpthread -lcrypto
```

## Verify (WSL)

```bash
wsl bash -lc "cd '/mnt/c/Users/Manoj/OneDrive/Acads/sem 6/CNS/CNS_Proj'; ./test_manoj.sh"
```

Expected result:

- all tests pass
- summary prints `Total: 13 passed, 0 failed`

Tested:

- build succeeds for `atm` and `bank`
- ATM rejects invalid CLI inputs with exit `255`
- duplicate mode/options are rejected
- invalid port, amount format, and IPv4 are rejected
- bank prints `created` and generates auth file on startup
- bank rejects existing auth file with exit `255`
- bank accepts ATM connection and framed request path works
- ATM returns exit `63` when bank is unreachable
- encrypted message path works between ATM and bank
- malformed decrypted request payloads are rejected as protocol errors
- serialized request format is accepted by bank worker after decryption

## Next Member Handoff



-------------
For Praneeth (DB + Card File): complete and tested.

Implemented:

- Added card-file handling in the ATM: create (`-n`) generates a 32-byte card secret, writes a hex card file, and validates existing card files for other operations.
- Extended the protocol to carry a hex-encoded card secret (`card_hex`) in `ProtocolRequest` and updated `protocol.c` serializers/deserializers accordingly.
- Implemented an in-memory bank database (linked list) storing account name, `balance_cents` (uint64_t), and `card_hex`, protected by a mutex.
- Implemented business handlers in `bank.c`: CREATE (initial balance), DEPOSIT, WITHDRAW (with insufficient-funds check), and GET (balance). All amounts use integer cents internally.
- Bank prints minimal JSON summaries on successful operations (matching ATM output) while holding the DB lock to preserve ordering.
- Bank distinguishes protocol errors (prints `protocol_error`) from business failures (sends back `ok=0`); ATM exits with the required codes (255 for business failure, 63 for protocol/timeout errors).
- ATM now waits for, verifies, decrypts, and deserializes bank responses and prints spec-compliant JSON output.
- Added `test_praneeth.sh` with positive and negative tests (duplicate create, insufficient funds, wrong card, corrupted card) and verified the flow locally.

Files changed (high level):

- `protocol.h` / `protocol.c` — added `card_hex` field and updated serialization/deserialization.
- `atm.c` — card-file create/read, include `card_hex` in requests, response decryption and JSON output.
- `bank.c` — in-memory DB, business handlers, JSON printing, response encryption.
- `test_praneeth.sh` — automated some positive and negative tests.

Remaining / recommended improvements:

- Replace sending raw card secret over the wire with a proof-of-possession scheme (HMAC over a nonce) to avoid exposing the card secret.
- Add persistence (on-disk DB) if accounts must survive bank restarts.
- Add more unit tests and CI (Makefile + workflow) for reproducible builds and automated test runs.
- Harden input validation and logging, and add limits for number of accounts / memory usage.
- Consider protocol versioning and backward-compatibility tests if fields change further.
--------------------------

For Praneeth (DB + Card File):

- Implement account database storage in bank memory.
- Store at minimum: account name, balance in cents, and card secret.
- Use integer cents internally for balances and transaction amounts.
- Add create/deposit/withdraw/get handlers after request deserialization in `bank.c`.
- Reject invalid business logic with exit/response behavior required by spec.
- Create and read card files in ATM using the validated account/card filename inputs from `cli.c`.
- On `-n`, generate a new card secret, write the card file, and include that secret in the account-creation flow.
- On `-d`, `-w`, and `-g`, read the card file and attach/validate account ownership data.
- Extend `ProtocolRequest` and `ProtocolResponse` in `protocol.h` if card-secret or status fields are needed.
- Update `protocol.c` serializer/deserializer consistently on both ATM and bank sides if message fields change.
- After business logic is implemented, ATM should decrypt and deserialize bank responses instead of only sending requests.
- Print final JSON outputs exactly as required by the assignment after successful operations.

Stable integration points already ready:

- argument parsing: `parse_atm_args()`, `parse_bank_args()` in `cli.c`
- transport framing: `send_message()`, `receive_message()` in `network.c`
- crypto helpers: `crypto_load_auth_secret()`, `crypto_derive_keys()`, `crypto_encrypt_then_mac()`, `crypto_verify_then_decrypt()` in `crypto.c`
- protocol helpers: `proto_serialize_request()`, `proto_deserialize_request()`, `proto_serialize_response()`, `proto_deserialize_response()` in `protocol.c`
- server concurrency path: `handle_client()` in `bank.c`

Suggested implementation order for Praneeth:

1. Add account and card-secret fields to protocol messages as needed.
2. Implement card file generation and loading in ATM.
3. Implement in-memory account database in bank.
4. Process each deserialized request in `handle_client()`.
5. Serialize, encrypt, send bank responses back to ATM.
6. Deserialize bank responses in ATM and print spec-compliant JSON.

## Quick Manual Run

```bash
./bank -p 3000 -s bank.auth
./atm -a alice -g -p 3000 -s bank.auth
```
