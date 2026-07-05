# Configuration

zecd is configured by a TOML file plus Bitcoin-Core-style CLI flags and a handful of
environment variables. This page is the complete reference: every TOML section and key with
its type, default, and semantics, plus the CLI flags and environment variables. The
`zecd.example.toml` file in the repository root is a fully commented starting point.

## File location and precedence

The config file is `<datadir>/zecd.toml`, overridable with `--conf <FILE>`. Like bitcoind,
the file is located *before* its own `datadir` key can apply: the lookup uses only the
`--datadir` flag and the `ZECD_DATADIR` environment variable, never a `datadir` set inside
the file. If the file does not exist, built-in defaults apply.

Unknown keys anywhere in the file are a **startup error** (fail-fast), not a silent ignore:
a typo cannot quietly disable a setting.

General precedence, highest first:

1. CLI flag (some flags read an environment variable as a fallback; see
   [Environment variables](#environment-variables))
2. TOML key
3. Built-in default

Per-key exceptions are noted inline below (the RPC password has a three-way precedence;
`rpcauth` entries accumulate rather than override; per-wallet keys override global `[pools]`
keys).

## Top-level keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network` | string | `"test"` | Chain to run on: `"main"`/`"mainnet"`, `"test"`/`"testnet"`, or `"regtest"`. Overridden by `--network`, `--testnet`, `--regtest`. |
| `datadir` | path | `"./zecd-data"` | Parent directory for per-wallet subdirectories, the RPC cookie file, the datadir lock, and (by default) the age identity. Overridden by `--datadir` / `ZECD_DATADIR`. |
| `default_wallet` | string | `"default"` | Wallet served when a request hits `/` rather than `/wallet/<name>` (see [multiwallet routing](rpc/index.md)). |

The default network is **testnet**; mainnet must be selected explicitly. On mainnet,
zecd additionally refuses to start while `[rpc] password` is still the example placeholder
`change-me` (case-insensitive), since the RPC password is spend authority.

## `[wallets.<name>]`

One section per wallet; each wallet is an independent seed, SQLite database, and directory,
served at `/wallet/<name>`. If no wallet section is declared, an implicit entry for
`default_wallet` is created at `<datadir>/<name>`. Every `[pools]` key can be overridden
per wallet here.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dir` | path | `<datadir>/<name>` | Directory holding this wallet's `data.sqlite`, `keys.toml`, and `blocks/`. |
| `keys_file` | path | `<dir>/keys.toml` | Location of this wallet's `keys.toml` (the encrypted seed), independent of `dir` (for example a read-only mounted Kubernetes Secret while `dir` stays a disposable cache). For the default wallet, `[keys] keys_file` / `ZECD_KEYS_FILE` / `--keys-file` set this too, but an explicit per-wallet `keys_file` wins over all of them. |
| `pools` | array of string | global `[pools] enabled` | Override of the enabled shielded pools for this wallet. |
| `default_receivers` | array of string | see below | Override of the default UA receivers. A wallet that overrides `pools` but not `default_receivers` receives into everything it enabled; a wallet that overrides neither inherits the global default. Must be a subset of the wallet's enabled pools. |
| `transparent` | bool | global value | Override of `[pools] transparent`. |
| `transparent_default` | bool | global value | Override of `[pools] transparent_default`. |
| `transparent_gap_limit` | integer | global value | Override of `[pools] transparent_gap_limit`. |
| `transparent_initial_scan` | integer | global value | Override of `[pools] transparent_initial_scan`. |
| `transparent_allow_beyond_recovery_window` | bool | global value | Override of `[pools] transparent_allow_beyond_recovery_window`. |
| `transparent_gap_warn_threshold` | integer | global value | Override of `[pools] transparent_gap_warn_threshold`. |

At most one loaded wallet may hold spending keys; any number of watch-only (UFVK) wallets
may run alongside it; see [Watch-only wallets](guide/watch-only.md).

## `[backend]`

The chain upstream: a single self-hosted Zebra node's JSON-RPC. See
[A Zebra-only backend](design/zebra-backend.md) for the deployment model and the
cleartext-credential gate.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server` | string | `"zebra"` | Upstream endpoint. `"zebra"` means a local zebrad at `127.0.0.1:8234` (mainnet) or `127.0.0.1:18234` (testnet/regtest); set zebrad's `rpc.listen_addr` accordingly. Any explicit `zebra://host:port` (or bare `host:port`) works. Overridden by `--server`. |
| `connect_timeout_secs` | integer | `10` | Per-attempt dial timeout (seconds); clamped to at least 1. |
| `reconnect_base_secs` | integer | `1` | Reconnect backoff base delay (seconds); clamped to at least 1. Backoff is exponential with full jitter. |
| `reconnect_max_secs` | integer | `60` | Reconnect backoff cap (seconds); clamped to at least `reconnect_base_secs`. |
| `rfc1918_is_local` | bool | `true` | Treat private / non-globally-routable addresses (RFC1918, link-local, CGNAT, IPv6 ULA/link-local) as "local" for the cleartext-credential gate (the Docker/LAN norm). Set `false` for a strict loopback-only posture. |
| `allow_remote_cleartext` | bool | `false` | Escape hatch: allow `[zebra]` credentials to travel in plaintext to a globally-routable host. Only set this when the hop is secured out-of-band (SSH/WireGuard tunnel, private overlay). |

## `[zebra]`

Credentials for the zebrad endpoint. Omit the whole section when zebrad runs with
`enable_cookie_auth = false`. A cookie file wins over user/password; nothing set means no
authentication.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rpc_user` | string | unset | RPC username for zebrad. |
| `rpc_password` | string | unset | RPC password for zebrad. |
| `rpc_cookie` | path | unset | Path to zebrad's cookie file; re-read on every reconnect (zebrad regenerates it at startup). Wins over `rpc_user`/`rpc_password`. |

## `[rpc]`

zecd's own JSON-RPC server (the Bitcoin-Core-dialect surface; see
[Conventions & wire format](rpc/index.md)).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind` | string (IP) | `"127.0.0.1"` | Listen address. Overridden by `--rpcbind`. |
| `port` | integer | `8232` main / `18232` test+regtest | Listen port. Overridden by `--rpcport`. |
| `user` | string | unset | HTTP Basic auth username. Overridden by `--rpcuser`. |
| `password` | string | unset | HTTP Basic auth password. Precedence: `--rpcpassword` / `ZECD_RPC_PASSWORD` > `password_file` > this key. If no user/password pair is configured, cookie auth is used instead. |
| `password_file` | path | unset | Read the RPC password from this file (trailing newline/CR trimmed), keeping the spend-equivalent secret out of a ConfigMap-bound TOML. A configured file that cannot be read is a fatal startup error. |
| `auth` | array of string | `[]` | Bitcoin-Core-style `rpcauth` entries (`<user>:<salt>$<hmac-sha256 hex>`), each an additional accepted credential. Generate with `zecd rpcauth <user> [password]`. Entries from `--rpcauth` flags and this key **accumulate** (all are accepted), matching bitcoind. |
| `cookiefile` | path | `<datadir>/.cookie` | Where the bitcoind-style cookie is written when no user/password is set: zecd mints a random secret at startup and writes `__cookie__:<random>` (mode 0600). |
| `work_queue` | integer | `100` | Max concurrent in-flight requests before returning HTTP 503 (Bitcoin Core's `-rpcworkqueue`); clamped to at least 1. |
| `allowed_methods` | array of string | `[]` | RPC method safelist. Empty means every method is served; non-empty serves *only* the listed methods, anything else returning `-32601` ("Method not found") exactly as if it did not exist. Names are validated against the implemented method set at startup, so a typo fails fast. A coarse server-wide gate, not per-user. |

## `[keys]`

Seed custody and unlock behavior. See [Key custody](security/key-custody.md) for the two
at-rest custody models (age identity vs. passphrase).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `age_identity` | path | `<datadir>/identity.txt` | age identity file used to decrypt the wallet seed for unattended sending (the identity-file custody model). Overridden by `--age-identity` / `ZECD_AGE_IDENTITY`. |
| `auto_unlock` | bool | `true` | Decrypt the seed at startup so sends need no `walletpassphrase` (identity-file wallets only; passphrase-encrypted wallets always start locked). |
| `keys_file` | path | unset | Location of the **default** wallet's `keys.toml`, independent of the datadir (mount it as a Secret). Equivalent to `[wallets.<default>] keys_file`; overridden by `--keys-file` / `ZECD_KEYS_FILE`, and by an explicit per-wallet `keys_file`. |
| `bootstrap_from_keys` | bool | `true` | When a wallet's `keys.toml` exists but its `data.sqlite` has no account, recreate the account from the seed on boot and rescan from the wallet's birthday: the setting that lets the data directory be a disposable cache. Set `false` to fail fast on an empty datadir instead. Watch-only wallets have no seed and are not covered. |

## `[pools]`

Global defaults for which value pools each wallet uses; every key here can be overridden
per wallet in `[wallets.<name>]`. See [Addresses & shielded pools](guide/addresses.md) and
[Transparent support](guide/transparent.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | array of string | `["orchard"]` | Shielded pools the wallet receives into and spends from; supported values are `"sapling"` and `"orchard"`. Change goes to the strongest enabled pool (Orchard if enabled). Must be non-empty. |
| `default_receivers` | array of string | = `enabled` | Receivers included in the Unified Addresses `getnewaddress` hands out when no per-call override is given. Must be a subset of `enabled` (a violation is a startup error). |
| `transparent` | bool | `false` | Allow bare transparent (`t1…`/`tm…`) receiving addresses via `getnewaddress "" "transparent"`. Off keeps zecd shielded-only (`address_type = "transparent"` is rejected with `-8`). |
| `transparent_default` | bool | `false` | Make a bare transparent address the no-argument `getnewaddress` default. Requires `transparent = true` (validated at startup). |
| `transparent_gap_limit` | integer | `20` | External transparent gap limit: how far past the last *funded* receiving address a from-seed restore keeps scanning. Unlike shielded funds (always recoverable by trial decryption), transparent funds are only rediscovered within this window. Must be at least 1. |
| `transparent_initial_scan` | integer | `0` | Initial scan depth: pre-expose external transparent indices `0..N` at startup/restore so the receive scan covers all of them, independent of the (small) steady-state gap limit. Set to your issuance high-water mark; `0` disables pre-exposure. |
| `transparent_allow_beyond_recovery_window` | bool | `true` | What `getnewaddress "" "transparent"` does once the recovery window is exhausted: `true` issues the address anyway with a loud warning that funds sent there may be unrecoverable from seed; `false` fails the call with an actionable `-4` error (fail-closed). |
| `transparent_gap_warn_threshold` | integer | `5` | Warn when fewer than this many in-window transparent address slots remain, giving lead time to widen the limits. `0` warns only on actual exhaustion. |

## `[sync]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interval_secs` | integer | `20` | How often to poll Zebra for new blocks (seconds); clamped to at least 1. |
| `rebroadcast_secs` | integer | `60` | How often (at most) to re-broadcast the wallet's own transactions that are unmined and unexpired (seconds); clamped to at least 1. |

## `[spend]`

Send policy: confirmations, privacy, and the proving pipeline. See
[Privacy policy](design/privacy.md) for the four-rung ladder and its enforcement points.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `trusted_confirmations` | integer | `3` | Confirmations before the wallet's *own* outputs (change) are spendable (ZIP 315 default). Clamped to at least 1. |
| `untrusted_confirmations` | integer | `10` | Confirmations before third-party outputs are spendable (ZIP 315 default). Must be at least `trusted_confirmations` (validated at startup). Anchors balances and spend proposals; `getbalance`'s explicit `minconf` overrides per call. |
| `privacy_policy` | string | `"AllowRevealedRecipients"` | What sends may reveal on-chain: `"FullPrivacy"`, `"AllowRevealedAmounts"`, `"AllowRevealedRecipients"`, or `"AllowFullyTransparent"`. `z_sendmany`'s per-call `privacyPolicy` overrides it. |
| `orchard_action_limit` | integer | `50` | Cap on Orchard actions (`max(inputs, outputs)`) a single send may build; bounds memory/proving cost and yields a clean `-8` for oversized sends. `0` disables the cap. |
| `cache_proving_key` | bool | `true` | Build the Orchard proving key once at startup and prove sends through the PCZT path, instead of rebuilding the key (~seconds of keygen) on every transaction. Both paths produce identical transactions. |
| `pipeline_proving` | bool | `false` | Run a send's proving step off the single-writer actor so a long proof no longer freezes background sync and status. Sends still serialize. Only engages on the cached-Orchard PCZT path (`cache_proving_key = true`, Orchard-only spends). |

## `[health]`

Unauthenticated liveness/readiness probes on a separate port; see the
[operations runbook](guide/operations.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Serve `/healthz`, `/readyz`, `/status`. |
| `bind` | string (IP) | `"127.0.0.1"` | Probe listen address (`0.0.0.0` to expose off-host). |
| `port` | integer | `9233` | Probe listen port (all networks). |
| `readiness` | string | `"connected"` | What `/readyz` gates on: `"connected"` (backend connected and its tip past the wallet's birthday; does not wait for scanning) or `"synced"` (additionally scanned to within `max_scan_lag` blocks of the tip). |
| `max_scan_lag` | integer | `4` | Maximum `chain_tip - fully_scanned` gap at which `/readyz` reports ready. Only consulted in `"synced"` mode. |

## `[log]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `"info"` | Default tracing filter; overridden entirely by `RUST_LOG` when set. |
| `format` | string | `"text"` | `"text"` (human-readable) or `"json"` (structured, for log aggregation). Logs go to stderr. |

## CLI flags

Flags use Bitcoin-Core-style names and always win over the corresponding TOML key.

| Flag | Overrides | Description |
|------|-----------|-------------|
| `--conf <FILE>` | file location | Path to the TOML config (default `<datadir>/zecd.toml`). |
| `--datadir <DIR>` | `datadir` | Data directory. Falls back to `ZECD_DATADIR`, then the file, then `./zecd-data`. |
| `--testnet` | `network` | Use testnet. |
| `--regtest` | `network` | Use regtest (a local Zebra regtest chain). Wins over `--testnet` and `--network`. |
| `--network <NET>` | `network` | `"main"`, `"test"`, or `"regtest"`. |
| `--rpcbind <ADDR>` | `[rpc] bind` | RPC bind address. |
| `--rpcport <PORT>` | `[rpc] port` | RPC port. |
| `--rpcuser <USER>` | `[rpc] user` | RPC username. |
| `--rpcpassword <PASS>` | `[rpc] password` / `password_file` | RPC password; also readable from `ZECD_RPC_PASSWORD`. Passing it on the command line triggers a startup warning: argv is world-readable via `ps` / `/proc/<pid>/cmdline`. Prefer the environment variable or `password_file`. |
| `--rpcauth <USER:SALT$HASH>` | accumulates with `[rpc] auth` | Additional rpcauth credential; may be repeated. |
| `--server <SERVER>` | `[backend] server` | Chain upstream: `zebra` or `zebra://host:port`. |
| `--age-identity <FILE>` | `[keys] age_identity` | age identity file; also readable from `ZECD_AGE_IDENTITY`. |
| `--keys-file <FILE>` | `[keys] keys_file` | Default wallet's `keys.toml` path; also readable from `ZECD_KEYS_FILE`. An explicit `[wallets.<name>] keys_file` still wins. |
| `--version` | | Print the version and exit. |

### Subcommands

Running `zecd` with no subcommand (or `zecd run`) starts the daemon. The global flags above
are accepted on every invocation and must precede the subcommand (`zecd --datadir ./data
--testnet init`). `init` and `export-ufvk` honor the datadir/network/keys flags; the RPC
flags are inert for them. `rpcauth` runs before config resolution and ignores all of them.

| Subcommand | Flags | Description |
|------------|-------|-------------|
| `init` | `--wallet <NAME>` (default `default`), `--restore`, `--mnemonic-file <FILE>`, `--encrypt`, `--ufvk <UFVK>`, `--birthday <HEIGHT>` | Create and initialize a wallet, then exit. `--restore` reads the mnemonic from `ZECD_MNEMONIC`, else `--mnemonic-file`, else stdin. `--encrypt` reads the passphrase from `ZECD_WALLET_PASSPHRASE`, else prompts. `--ufvk` creates a watch-only wallet and conflicts with `--restore`/`--encrypt`. `--birthday` defaults to the current chain tip for new wallets; a restore without it scans from Sapling activation. |
| `export-ufvk` | `--wallet <NAME>` (default `default`) | Print a wallet's Unified Full Viewing Key (reads the wallet DB; no identity/passphrase needed, and not blocked by a running daemon's datadir lock). |
| `rpcauth <username> [password]` | | Generate a salted `[rpc] auth` credential line. Omitting the password generates a strong random one, printed once. Needs no datadir or config. |
| `run` | | Run the JSON-RPC daemon (the default when no subcommand is given). |

## Environment variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `ZECD_DATADIR` | daemon + subcommands | Data directory. Precedence: `--datadir` > `ZECD_DATADIR` > file `datadir` > `./zecd-data`. |
| `ZECD_RPC_PASSWORD` | daemon | RPC password; equivalent to `--rpcpassword` and wins over `[rpc] password_file` and inline `password`. Preferred over the flag (not visible in `ps`). |
| `ZECD_KEYS_FILE` | daemon + `init` | Default wallet's `keys.toml` path; equivalent to `--keys-file`. |
| `ZECD_AGE_IDENTITY` | daemon + `init` | age identity file path; equivalent to `--age-identity`. |
| `ZECD_MNEMONIC` | `init --restore` | The seed phrase for a non-interactive restore. Takes precedence over `--mnemonic-file` and stdin. |
| `ZECD_WALLET_PASSPHRASE` | `init --encrypt` | The at-rest passphrase for a non-interactive encrypted init; otherwise prompted twice on stdin. |
| `ZECD_ALLOW_CORE_DUMPS` | daemon + subcommands | Set to exactly `1` to opt out of the core-dump/ptrace hardening (`RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`) for crash debugging. Any other value, including `0` or empty, keeps hardening on. The seed `mlock` is unaffected. |
| `RUST_LOG` | daemon + subcommands | Standard tracing filter; overrides `[log] level` when set. |

## Minimal example

A testnet daemon against a local zebrad with cookie auth on both hops:

```toml
network = "test"
datadir = "./data"

[backend]
server = "zebra"          # zebra://127.0.0.1:18234 on testnet

[zebra]
rpc_cookie = "/var/lib/zebrad/.cookie"

# No [rpc] user/password: zecd writes its own cookie to ./data/.cookie,
# and local clients authenticate with it like bitcoin-cli does.
```
