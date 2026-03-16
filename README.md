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

## Build

```bash
gcc atm.c cli.c network.c -o atm
gcc bank.c cli.c network.c -o bank -lpthread
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

## Next Member Handoff

For Saharsh (Crypto + Serialization):
- Replace ATM placeholder payload in `atm.c` with serialized request bytes.
- Encrypt and authenticate payload before calling `send_message()`.
- In bank worker (`handle_client`), verify and decrypt bytes returned by `receive_message()`.

For Praneeth (DB + Card File):
- After bank decrypts request, apply account/card checks and balance logic.
- Return structured response payload for ATM to decode.
- Keep transaction processing atomic around shared account state.

Stable integration points already ready:
- argument parsing: `parse_atm_args()`, `parse_bank_args()` in `cli.c`
- transport framing: `send_message()`, `receive_message()` in `network.c`
- server concurrency path: `handle_client()` in `bank.c`

## Quick Manual Run

```bash
./bank -p 3000 -s bank.auth
./atm -a alice -g -p 3000 -s bank.auth
```
