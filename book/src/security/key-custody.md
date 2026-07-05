# Key custody

How zecd stores the wallet seed at rest, when it is decrypted into memory, how that memory is
hardened, and how the daemon proves the keys it holds actually match the wallet database it
serves. Read [Threat model](threat-model.md) first for what these mechanisms do and do not
defend against.

## Custody models

A spending wallet's 24-word mnemonic lives age-encrypted in `keys.toml` (created mode 0600).
There are two at-rest models for it, selected once at `zecd init`, plus watch-only as the
no-keys deployment:

| Model | At rest | Startup state | Passphrase RPCs |
|-------|---------|---------------|-----------------|
| Identity file (default) | Mnemonic age-encrypted to the recipient of `identity.txt` | Unlocked (with default `auto_unlock = true`) | `-15` |
| Passphrase (`init --encrypt`) | Mnemonic age-encrypted with a passphrase (scrypt) | Locked; sends `-13` | `walletpassphrase` / `walletlock` |
| Watch-only (`init --ufvk`) | No seed anywhere; seedless `keys.toml` | n/a | `-15`; sends `-4` |

### Identity file (default)

`zecd init` generates an age X25519 identity at `[keys] age_identity` (default
`<datadir>/identity.txt`, created mode 0600; a reused identity whose permissions have been
widened is refused) and encrypts the mnemonic in `keys.toml` to it. With the default
`[keys] auto_unlock = true`, startup decrypts the seed into a zeroizing in-memory secret so
sends run unattended. `walletpassphrase` and `walletlock` return `-15`, matching bitcoind with
an unencrypted wallet.

The co-location caveat: with `identity.txt` inside the datadir, the at-rest encryption only
protects a leak of `keys.toml` alone. Anyone who can read the whole datadir has the seed. For
an unattended mainnet wallet, store the identity outside the datadir (a secrets-manager mount,
a separate volume) and point zecd at it via `ZECD_AGE_IDENTITY`, `--age-identity`, or
`[keys] age_identity`.

Do not set `auto_unlock = false` on an identity wallet: it starts locked, sends fail `-13`,
and `walletpassphrase` cannot unlock it (`-15`, there is no passphrase). zecd warns loudly at
startup about this dead end. If you want a manually unlocked wallet, use the passphrase model.

### Passphrase (`zecd init --encrypt`)

`zecd init --encrypt` wraps the mnemonic with a passphrase instead (age scrypt; minimum 12
characters, confirmed twice on stdin, or supplied via `ZECD_WALLET_PASSPHRASE` for
non-interactive init). No identity file can decrypt it. `keys.toml` carries an
`encryption = "passphrase"` marker; this is the only model with a runtime lock state, and the
only one where `getwalletinfo.unlocked_until` appears.

The wallet starts locked and follows Bitcoin Core's state machine:

- Sends while locked fail with `-13` ("Please enter the wallet passphrase with walletpassphrase
  first.").
- `walletpassphrase "<pass>" <timeout>` decrypts the seed for `timeout` seconds. A wrong
  passphrase is `-14`. The timeout is a required non-negative integer; values above
  100,000,000 seconds are silently clamped, as in Core. Re-running resets the timer; a timeout
  of 0 relocks immediately. The scrypt derivation is deliberately slow (about a second) and
  runs off the async runtime.
- The wallet auto-relocks at the deadline. `getwalletinfo.unlocked_until` reports the relock
  unix time (0 when locked); the field appears only for passphrase-encrypted wallets, like
  Core.
- `walletlock` zeroizes the seed immediately and cancels the pending relock.

Encryption is set once at init. There is no `encryptwallet` or `walletpassphrasechange` RPC
(both `-32601`), so the passphrase never crosses the network. To change it, re-run
`zecd init --restore --encrypt` from the mnemonic in a fresh data directory.

### Watch-only: no keys on the box

The strongest custody posture is to not hold spending keys at all: run the RPC-facing zecd
watch-only (`zecd export-ufvk` on the spending wallet, `zecd init --ufvk` on the serving one)
and keep the spending wallet on isolated infrastructure. Addresses, balances, and history all
work; sends return `-4`. See [Watch-only wallets](../guide/watch-only.md).

## Memory hardening

Once unlocked, the seed is resident in process memory in every spending model. zecd hardens it
against passive capture at startup. Every step is best-effort: a failure logs a warning and
the daemon keeps serving, never refuses to start.

- **`mlock` on the seed buffer.** The pages holding the decrypted seed are pinned into RAM so
  they are never written to swap, and the bytes are zeroized on lock/relock/shutdown. The lock
  is targeted at the seed buffer, not `mlockall` (which would have to fit the whole RSS,
  proving keys included, under `RLIMIT_MEMLOCK` and typically fails in containers). A denied
  `mlock` (for example an unprivileged container with `RLIMIT_MEMLOCK=0`) warns once and
  leaves the seed usable but swappable; raise the memlock limit to fix it. Transient key
  copies made deeper in librustzcash during derivation and proving are not individually
  locked; back swap with an encrypted device to cover that residue.
- **Core dumps disabled** (`RLIMIT_CORE = 0`), so a crash cannot spill the seed into a core
  file. `ZECD_ALLOW_CORE_DUMPS=1` (the exact value `1`; anything else keeps hardening on)
  opts out for crash debugging. The opt-out does not affect the seed `mlock`.
- **Non-dumpable** (`PR_SET_DUMPABLE = 0`, Linux only), which also blocks `ptrace` attach and
  `/proc/<pid>/mem` reads by other non-root processes.

This defends passive disclosure (swap, core dumps, another process reading zecd's memory). It
does not defend an attacker with code execution inside zecd, who can read the seed directly.
For that isolation, split the deployment watch-only as above.

## Account-to-keys binding

The wallet database (`data.sqlite`) is a rebuildable cache of on-chain data, but one datum in
it is security-critical and has no on-chain check: which account the daemon serves.
`getnewaddress` derives receive addresses from the database account's UFVK, so a planted or
swapped database silently diverts every future deposit to whoever holds that account's keys.
zecd pins the account to `keys.toml` (the operator-controlled root of trust) and verifies the
pin in four layers:

1. `zecd init` refuses a wallet database that already contains an account.
2. `zecd init` records the new account's Unified Full Viewing Key in `keys.toml` (the `ufvk`
   field, written in all custody models including watch-only). The UFVK is derivable from the
   seed, so the pin is a cache of seed-derivable data and respects the
   [statelessness invariant](../design/statelessness.md).
3. Every startup compares the database account's UFVK against the pin. A mismatch is the typed
   `BindingMismatch` error and is fatal for the whole daemon: tampering evidence, unlike
   ordinary per-wallet startup failures, which merely skip the wallet. A `keys.toml` from
   before the pin existed is backfilled trust-on-first-use.
4. Every seed exposure re-verifies that the decrypted seed actually derives the account's
   UFVK: the identity auto-unlock at startup (mismatch is fatal, since an unattended wallet
   has no later unlock where it could surface) and every `walletpassphrase` (mismatch returns
   `-4` and the wallet stays locked). This retroactively validates a trust-on-first-use pin
   and catches a `keys.toml` and database pair swapped in together.

Deliberately not covered: tampering with non-key rows (notes, history, scan state). Once the
account keys are verified, planted notes cannot be spent and balances are rebuildable from
seed plus chain. Error messages abbreviate the UFVK to its first 24 characters, since the full
encoding is itself a viewing capability.

## Secrets outside the config file

Every secret can be sourced from the environment or a mounted file instead of the
(ConfigMap-bound) TOML:

| Secret | Sources (highest precedence first) |
|--------|-----------------------------------|
| RPC password | `--rpcpassword` / `ZECD_RPC_PASSWORD`, then `[rpc] password_file` (a mounted file; configured-but-unreadable is fatal), then inline `[rpc] password` |
| `keys.toml` location | `ZECD_KEYS_FILE` / `--keys-file` / `keys_file` (global for the default wallet, or per `[wallets.<name>]`) |
| age identity | `ZECD_AGE_IDENTITY` / `--age-identity` / `[keys] age_identity` |
| Mnemonic (`init --restore`) | `ZECD_MNEMONIC`, then `--mnemonic-file`, then interactive stdin |
| Passphrase (`init --encrypt`) | `ZECD_WALLET_PASSPHRASE`, then interactive stdin (entered twice) |

Prefer the env var or file over `--rpcpassword` on the command line: argv is world-readable
via `ps` and `/proc/<pid>/cmdline`, and zecd warns at startup when it detects the flag there.

With `[keys] bootstrap_from_keys` (default on), a wallet whose `keys.toml` is present but
whose data directory has no account is rebuilt on boot: the account is recreated from the seed
(immediately for identity/auto-unlock wallets, at the first `walletpassphrase` for encrypted
ones) and the wallet rescans from its birthday. The data directory becomes a disposable cache
and the Kubernetes shape is "mount one Secret, start with an empty PVC". See
[Operations](../guide/operations.md) for the minimal runtime file set and the bootstrap
procedure.

## RPC credentials are spend authority

Anyone with RPC access to an unlocked wallet can spend from it. Treat the RPC credential with
the same care as the seed material above:

- Credentials follow bitcoind: `rpcuser`/`rpcpassword`, salted `rpcauth` entries
  (`[rpc] auth = ["<user>:<salt>$<hmac-sha256>"]`, generated with the built-in
  `zecd rpcauth <user> [password]`, no external `rpcauth.py` needed), or the generated cookie
  file (`<datadir>/.cookie`, mode 0600) when no user/password pair is set. Prefer `rpcauth` or
  the cookie over a bare shared password.
- On mainnet, zecd refuses to start while the password is the example placeholder
  (`CHANGE-ME`).
- zecd serves plaintext HTTP. Bind to `127.0.0.1` (the default) or front it with a
  TLS-terminating proxy; zecd warns at startup about a bare password on a non-loopback bind.
- `[rpc] allowed_methods` shrinks the blast radius of a leaked credential to a chosen method
  subset. See [RPC overview](../rpc/index.md) and [Threat model](threat-model.md).
