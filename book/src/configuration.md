# Configuration

zecd is configured by a TOML file plus Bitcoin-Core-style CLI flags and a handful of
environment variables. This page is the complete reference: every TOML section and key with
its type, default, and semantics, plus the CLI flags and environment variables.

For a fully commented starting point, ask the binary for one:

```sh
zecd example-config > ./data/zecd.toml
```

`zecd example-config` prints the annotated `zecd.example.toml` that ships with zecd, so you
do not need a source checkout to get it: it works the same from a release tarball, a `.deb`,
or a container. See [Subcommands](#subcommands) for `--output-file` and `--force`.

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
| `dir` | path | `<datadir>/<name>` | This wallet's directory. `keys.toml` sits at its root; since 0.7.0 the librustzcash artifacts (`data.sqlite`, `blockmeta.sqlite`, `blocks/`) live in a per-coin, per-engine subdirectory below it, `<dir>/zec/lrz/`. Existing wallets migrate themselves on first start with no configuration change. See [wallet data layout](guide/operations.md#wallet-data-layout). |
| `keys_file` | path | `<dir>/keys.toml` | Location of this wallet's `keys.toml` (the encrypted seed), independent of `dir` (for example a read-only mounted Kubernetes Secret while `dir` stays a disposable cache). For the default wallet, `[keys] keys_file` / `ZECD_KEYS_FILE` / `--keys-file` set this too, but an explicit per-wallet `keys_file` wins over all of them. |
| `pools` | array of string | global `[pools] enabled` | Override of the enabled shielded pools for this wallet. |
| `default_receivers` | array of string | see below | Override of the default UA receivers. A wallet that overrides `pools` but not `default_receivers` receives into everything it enabled; a wallet that overrides neither inherits the global default. Must be a subset of the wallet's enabled pools. |
| `transparent` | bool | global value | Override of `[pools] transparent`. |
| `transparent_default` | bool | global value | Override of `[pools] transparent_default`. |
| `transparent_gap_limit` | integer | global value | Override of `[pools] transparent_gap_limit`. |
| `transparent_initial_scan` | integer | global value | Override of `[pools] transparent_initial_scan`. |
| `transparent_allow_beyond_recovery_window` | bool | global value | Override of `[pools] transparent_allow_beyond_recovery_window`. |
| `transparent_gap_warn_threshold` | integer | global value | Override of `[pools] transparent_gap_warn_threshold`. |

**Per-wallet backend overrides (0.7.0).** `[backend]` used to be daemon-global, so every wallet
in a process dialled the same upstream. These keys, written directly in the wallet's own
section, override it:

| Key | Overrides |
|---|---|
| `server` | `[backend] server` |
| `tls` | `[backend] tls` |
| `tls_roots` | `[backend] tls_roots` |
| `tls_ca_file` | `[backend] tls_ca_file` |
| `tls_pinned_sha256` | `[backend] tls_pinned_sha256` |
| `tls_insecure_skip_verify` | `[backend] tls_insecure_skip_verify` |
| `assume_transparent_in_compact_blocks` | `[backend] assume_transparent_in_compact_blocks` |

Only the settings that describe *which upstream this wallet dials*, and the TLS trust that
authenticates it, are overridable. Fallback is **field by field**, so a wallet overriding only
`server` keeps every global TLS setting. Deployment policy stays global and is deliberately not
listed above: timeouts, reconnect backoff, the cleartext-locality rules, and the `[zebra]`
credentials are properties of the deployment rather than of one endpoint.

One daemon can therefore serve a zebra-backed spending wallet beside a lightwalletd-backed
watch-only replica of the same seed. Existing configurations resolve exactly as before, and a
wallet with no overrides emits no backend keys from `config show`.

At most one loaded wallet may hold spending keys; any number of watch-only (UFVK) wallets
may run alongside it; see [Watch-only wallets](guide/watch-only.md).

## `[backend]`

The chain upstream: a single node, either a self-hosted Zebra's JSON-RPC (the default and the
recommendation) or, since 0.6.0, a lightwalletd gRPC server. **The `server` token picks which**,
so read its row below before changing it. See [Chain backends](design/zebra-backend.md) for the
deployment model, the trade-off between the two, and the cleartext-credential gate.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server` | string | `"zebra"` | Upstream endpoint; **the token also selects the mode**. Full node: `"zebra"` (a local zebrad at `127.0.0.1:8234` mainnet, `127.0.0.1:18234` testnet/regtest; set zebrad's `rpc.listen_addr` accordingly) or an explicit `zebra://host:port`. Light mode: `https://host[:port]`, `http://host:port`, the `"zecrocks"` preset, and **a bare `host:port`** - note that last one is lightwalletd, not zebrad. Overridden by `--server`. |
| `connect_timeout_secs` | integer | `10` | Per-attempt dial timeout (seconds); clamped to at least 1. |
| `reconnect_base_secs` | integer | `1` | Reconnect backoff base delay (seconds); clamped to at least 1. Backoff is exponential with full jitter. |
| `reconnect_max_secs` | integer | `60` | Reconnect backoff cap (seconds); clamped to at least `reconnect_base_secs`. |
| `rfc1918_is_local` | bool | `true` | Treat private / non-globally-routable addresses (RFC1918, link-local, CGNAT, IPv6 ULA/link-local) as "local" for the cleartext-credential gate (the Docker/LAN norm). Set `false` for a strict loopback-only posture. |
| `allow_remote_cleartext` | bool | `false` | Escape hatch: allow `[zebra]` credentials to travel in plaintext to a globally-routable host, and a plaintext light-mode connection to one. Only set this when the hop is secured out-of-band (SSH/WireGuard tunnel, private overlay). |

The remaining keys apply only when `server` names a **lightwalletd** endpoint (0.6.x and later);
a `zebra://` upstream ignores them. See [Chain backends](design/zebra-backend.md#light-mode).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls` | string | `"auto"` | `"yes"` forces TLS, `"no"` forbids it, `"auto"` decides by locality (plaintext toward loopback/private, TLS toward public). An explicit `https://`/`http://` scheme in `server` overrides it. |
| `tls_roots` | string | `"native"` | Which root certificates to trust: `"native"` (the OS store, and `SSL_CERT_FILE`) or `"webpki"` (the embedded Mozilla bundle). |
| `tls_ca_file` | path | unset | PEM of a private CA to trust in addition to the roots, so a privately-issued certificate validates normally, hostname and expiry included. |
| `tls_pinned_sha256` | array of string | `[]` | Acceptable leaf-certificate SHA-256 fingerprints. Non-empty pins the connection to those certificates. The right answer for a self-signed server: it authenticates the peer rather than giving up on authenticating it. Combined with `tls_ca_file`, the chain is validated against that CA as well. |
| `tls_insecure_skip_verify` | bool | `false` | Accept **any** certificate: no chain, hostname, or expiry check. The connection stays encrypted but is no longer authenticated, so an on-path attacker can impersonate the server and observe every address and txid this wallet asks about. Prefer `tls_pinned_sha256`. Refused in combination with `tls_ca_file`/`tls_pinned_sha256`. |
| `assume_transparent_in_compact_blocks` | bool | `false` | Assert that the upstream serves transparent (and Ironwood) data inside compact blocks. zecd normally reads this from the server's advertised protocol version and **refuses to run a transparent-enabled wallet** against a server that does not advertise it, since those receives would otherwise silently never appear. No released lightwalletd populates that advertisement yet, so asserting it is currently the practical path for a transparent wallet on a light upstream. Asserting it wrongly reintroduces exactly the silent-loss failure the check prevents. Shielded-only wallets never need it. |

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
| `allow_duplicate_shielded_recipients` | bool | `false` | Permit a repeated **shielded** address across the recipients of one `z_sendmany`, for callers deliberately paying one address from several memo-carrying outputs in a single transaction. zcashd refuses any repeated recipient, which is the default here too. Repeated *transparent* recipients stay refused either way. In-process callers get the same thing unconditionally through `Node::send` (see [embedding](library.md#sending)). |
| `allowed_methods` | array of string | `[]` | RPC method safelist. Empty means every method is served; non-empty serves *only* the listed methods, anything else returning `-32601` ("Method not found") exactly as if it did not exist. Names are validated against the implemented method set at startup, so a typo fails fast. A coarse server-wide gate, not per-user. |

## `[keys]`

Seed custody and unlock behavior. See [Key custody](security/key-custody.md) for the two
at-rest custody models (age identity vs. passphrase).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `age_identity` | path | `<datadir>/identity.txt` | age identity file used to decrypt the wallet seed for unattended sending (the identity-file custody model). Overridden by `--age-identity` / `ZECD_AGE_IDENTITY`. |
| `auto_unlock` | bool | `true` | Decrypt the seed at startup so sends need no `walletpassphrase` (identity-file wallets only; passphrase-encrypted wallets always start locked). |
| `keys_file` | path | unset | Location of the **default** wallet's `keys.toml`, independent of the datadir (mount it as a Secret). Equivalent to `[wallets.<default>] keys_file`; overridden by `--keys-file` / `ZECD_KEYS_FILE`, and by an explicit per-wallet `keys_file`. |
| `allow_multiple_spending_wallets` | bool | `false` | Load more than one wallet holding spending keys. **Refused by the daemon**, which reports it as a `config check` error: an RPC credential is spend authority for whichever wallet a request routes to, so two loaded spenders leave no single answer to which keys a credential can spend. It exists for [embedded](library.md#several-spending-wallets-in-one-process) hosts, which have no RPC credentials and name the wallet on every call. When on, the loaded spenders are logged to the `zecd::audit` target. |
| `bootstrap_from_keys` | bool | `true` | When a wallet's `keys.toml` exists but its `data.sqlite` has no account, recreate the account from the seed on boot and rescan from the wallet's birthday: the setting that lets the data directory be a disposable cache. Set `false` to fail fast on an empty datadir instead. Watch-only wallets have no seed and are not covered. |

## `[pools]`

Global defaults for which value pools each wallet uses; every key here can be overridden
per wallet in `[wallets.<name>]`. See [Addresses & shielded pools](guide/addresses.md) and
[Transparent support](guide/transparent.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | array of string | `["orchard"]` | Shielded pools the wallet receives into and spends from; supported values are `"sapling"` and `"orchard"`. Change goes to the strongest enabled pool (Orchard if enabled). Must be non-empty. **`"ironwood"` is not a value here** and is rejected at startup - not because it is not a pool, but because this key selects *receivers*. Ironwood is very much a value pool: its own bundle in V6 transactions, its own `valueBalance`, and `pool == "ironwood"` in balances and history. What it lacks is a *receiver*: ironwood notes are Orchard V3 notes reusing Orchard's keys, addresses and receiver, so there is nothing to request or enable. It is compiled in unconditionally and switches on by consensus height (already active on mainnet and testnet), so an `"orchard"` wallet is receiving Ironwood notes today. See [Addresses & shielded pools](guide/addresses.md). |
| `default_receivers` | array of string | = `enabled` | Receivers included in the Unified Addresses `getnewaddress` hands out when no per-call override is given. Must be a subset of `enabled` (a violation is a startup error). |
| `transparent` | bool | `false` | Allow bare transparent (`t1…`/`tm…`) receiving addresses via `getnewaddress "" "transparent"`. Off keeps zecd shielded-only (`address_type = "transparent"` is rejected with `-8`). |
| `transparent_default` | bool | `false` | Make a bare transparent address the no-argument `getnewaddress` default. Requires `transparent = true` (validated at startup). |
| `transparent_gap_limit` | integer | `20` | External transparent gap limit: how far past the wallet's issuance frontier (the highest of the last funded index, the highest index `getnewaddress` handed out, and the `transparent_initial_scan` floor) addresses stay exposed. Unlike shielded funds (always recoverable by trial decryption), transparent funds are only rediscovered within this window; a stateless restore recovers up to `transparent_initial_scan + transparent_gap_limit`. Size it to your outstanding *unfunded* handed-out addresses only: every recorded receive re-derives the whole window, so zecd warns above `1000` and logs an error above `10000` (neither blocks startup). Must be at least 1. |
| `transparent_initial_scan` | integer | `0` | Initial scan depth: pre-expose external transparent indices `0..N` **once** at startup/restore so the receive scan covers all of them, independent of the (small) steady-state gap limit. This is the knob for deep coverage; it raises the gap window's floor, so issuance continues past `N` and stays recoverable to `N + transparent_gap_limit`. Set to your issuance high-water mark; `0` disables pre-exposure. |
| `transparent_allow_beyond_recovery_window` | bool | `true` | What `getnewaddress "" "transparent"` does once the recovery window is exhausted: `true` issues the address anyway with a loud warning that funds sent there may be unrecoverable from seed; `false` fails the call with an actionable `-4` error (fail-closed). |
| `transparent_gap_warn_threshold` | integer | `5` | Warn when fewer than this many in-window transparent address slots remain, giving lead time to widen the limits. `0` warns only on actual exhaustion. |

## `[sync]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `interval_secs` | integer | `20` | How often to poll Zebra for new blocks (seconds); clamped to at least 1. |
| `rebroadcast_secs` | integer | `60` | How often (at most) to re-broadcast the wallet's own transactions that are unmined and unexpired (seconds); clamped to at least 1. |

## `[spend]`

Send policy: confirmations, privacy, and the proving pipeline. See
[Privacy policy](design/privacy.md) for the five-rung ladder and its enforcement points.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `trusted_confirmations` | integer | `3` | Confirmations before the wallet's *own* outputs (change) are spendable (ZIP 315 default). Clamped to at least 1. |
| `untrusted_confirmations` | integer | `10` | Confirmations before third-party outputs are spendable (ZIP 315 default). Must be at least `trusted_confirmations` (validated at startup). Anchors balances and spend proposals; `getbalance`'s explicit `minconf` overrides per call. |
| `privacy_policy` | string | `"AllowRevealedRecipients"` | What sends may reveal on-chain: `"FullPrivacy"`, `"AllowRevealedAmounts"`, `"AllowRevealedRecipients"`, `"AllowRevealedSenders"` (permits funding a send from transparent UTXOs, with shielded change), or `"AllowFullyTransparent"`. `z_sendmany`'s per-call `privacyPolicy` overrides it. Note `"AllowRevealedSenders"` was a synonym for `"AllowRevealedRecipients"` before 0.6.1 and is now a rung of its own. |
| `orchard_action_limit` | integer | `50` | Cap on Orchard actions (`max(inputs, outputs)`) a single send may build; bounds memory/proving cost and yields a clean `-8` for oversized sends. `0` disables the cap. |
| `target_note_count` | integer | `4` | How many change notes a send tries to leave behind, so the next send has several notes to spend in turn rather than serializing on one note's confirmation depth. Must be at least 1; `0` was previously a panic waiting for the first send. |
| `min_split_output_value` | integer (zatoshis) | `10000000` (0.1 ZEC) | Floor below which change is *not* split into `target_note_count` notes. The floor applies to the wallet's balance rather than to a network, so a deployment built on small balances was receiving one change note where it wanted several. Both keys default to what was hard-coded before 0.7.0, and both are validated when the configuration loads. |
| `cache_proving_key` | bool | `true` | Build the Orchard proving key once (on a background task at startup, so it does not delay the listeners) and prove sends through the PCZT path, instead of rebuilding the key (~seconds of keygen) on every transaction. Both paths produce identical transactions. |
| `pipeline_proving` | bool | `false` | Run a send's proving step off the single-writer actor so a long proof no longer freezes background sync and status. Sends still serialize. Only engages on the cached-Orchard PCZT path (`cache_proving_key = true`, Orchard-only spends). |

## `[health]`

Unauthenticated liveness/readiness probes on a separate port; see the
[operations runbook](guide/operations.md).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Serve `/healthz`, `/readyz`, `/status`. |
| `bind` | string (IP) | `"127.0.0.1"` | Probe listen address (`0.0.0.0` to expose off-host). |
| `port` | integer | `9233` | Probe listen port (all networks). |
| `readiness` | string | `"synced"` | What `/readyz` gates on. `"synced"` (the default): connected, scanned to within `max_scan_lag` blocks of the tip, **and** the transaction-enhancement backlog drained. `"scanned"` (new in 0.6.4): the same without the backlog term. `"connected"`: backend connected and its tip past the wallet's birthday, without waiting for the scan at all. |
| `max_scan_lag` | integer | `4` | Maximum `chain_tip - fully_scanned` gap at which `/readyz` reports ready. Consulted in `"synced"` and `"scanned"` modes; ignored in `"connected"`. |

## `[log]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `level` | string | `"info"` | Default tracing filter; overridden entirely by `RUST_LOG` when set. |
| `format` | string | `"text"` | `"text"` (human-readable) or `"json"` (structured, for log aggregation). Logs go to stderr. **Validated since 0.7.0**: anything else used to be silently treated as text, so a typo like `jsonl` produced text logs with no complaint. It is now refused at startup, and `zecd config check` reports the same refusal. |

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

Running `zecd` with no subcommand (or `zecd run`) starts the daemon.

Every flag in the table above is **global**: it is accepted on either side of the subcommand,
so `zecd --conf /etc/zecd.toml config check` and `zecd config check --conf /etc/zecd.toml`
are the same command. (Before 0.6.0 the flags had to precede the subcommand, which made
`zecd config check --conf FILE` - the way anyone would naturally write it - a usage error.)

`init`, `export-ufvk`, `rescan`, `derive-address`, `chain-info` and the `config` group honor
the datadir/network/keys flags; the RPC flags are inert for them. `rpcauth`, `example-config`
and `licenses` run before config resolution and ignore all of them, so they work when there is
no config file yet.

| Subcommand | Flags | Description |
|------------|-------|-------------|
| `init` | `--wallet <NAME>` (default `default`), `--restore`, `--mnemonic-file <FILE>`, `--encrypt`, `--ufvk <UFVK>`, `--birthday <HEIGHT>` | Create and initialize a wallet, then exit. `--restore` reads the mnemonic from `ZECD_MNEMONIC`, else `--mnemonic-file`, else stdin. `--encrypt` reads the passphrase from `ZECD_WALLET_PASSPHRASE`, else prompts. `--ufvk` creates a watch-only wallet and conflicts with `--restore`/`--encrypt`. `--birthday` defaults to the current chain tip for new wallets; a restore without it scans from Sapling activation. |
| `export-ufvk` | `--wallet <NAME>` (default `default`) | Print a wallet's Unified Full Viewing Key (reads the wallet DB; no identity/passphrase needed, and not blocked by a running daemon's datadir lock). |
| `rescan` | `--wallet <NAME>` (default `default`), `--yes` | **Destructive.** Delete the wallet database so the next daemon start rebuilds the account from the seed and rescans from the wallet birthday. `keys.toml` and the seed are kept, and all funds and history are re-derived from the chain, so nothing is lost that a restore could not rebuild. Prompts for confirmation unless `--yes`. Takes the datadir lock like `init`, so it refuses to run while a daemon holds it: stop the daemon first. See [Recovering a stuck sync](guide/operations.md#recovering-a-stuck-sync). |
| `derive-address` | `--wallet <NAME>`, `--mnemonic`, `--mnemonic-file <FILE>`, `--ufvk <UFVK>`, `--address-type <TYPE>`, `--index <N>`, `--count <N>`, `--json` | Derive addresses **offline**. Touches no network, no wallet database and no daemon, and takes no datadir lock, so it runs beside a live daemon. See [Offline address derivation](#offline-address-derivation) below. |
| `config check` | `--strict`, `-q, --quiet` | Validate a config against *this* build without starting the daemon; exits non-zero if the daemon would refuse it. Prints the effective settings on stdout and the verdict on stderr. `--strict` also fails on warnings. See [Validating a config](#validating-a-config). |
| `config show` | | Print the effective configuration as round-trippable TOML, then exit. Secrets are emitted as commented-out key names, never values. |
| `chain-info` | `--server <TOKEN>`, `--json` | **New in 0.7.0.** Dial the configured upstream and report its tip, then exit. See [Probing the chain without a wallet](#probing-the-chain-without-a-wallet). |
| `licenses` | | **New in 0.7.0.** Print the license texts of the third-party crates compiled into this binary, then exit. See [Third-party licenses](#third-party-licenses). |
| `rpcauth <username> [password]` | | Generate a salted `[rpc] auth` credential line. Omitting the password generates a strong random one, printed once. Needs no datadir or config. |
| `example-config` | `-o, --output-file <FILE>`, `--force` | Print the annotated example config, then exit. Goes to stdout by default (`-o -` is the same), so it can be redirected or piped. With `-o <FILE>` it writes there instead and refuses to overwrite an existing file unless `--force`; the "wrote example config to ..." confirmation goes to stderr, so stdout carries config text and nothing else in every mode. The output is the shipped `zecd.example.toml`, byte for byte. Needs no datadir or config. |
| `run` | | Run the JSON-RPC daemon (the default when no subcommand is given). |

### Validating a config

`zecd config check --conf FILE` answers "would this build accept this config?" without
starting the daemon.

The question is not hypothetical: zecd rejects unknown config keys, which is what keeps a
typo'd knob from being silently ignored, but it also means a config valid for one build can be
refused by another **in either direction** - an upgrade may not know a key yet, a rollback may
have dropped one. Before 0.6.0 the only way to find out was to start the daemon on the target
host.

Two properties are structural rather than promised:

- **It reaches the daemon's verdict, not a second opinion.** Every check is either the config
  resolver itself or a helper the daemon calls at startup, so the two cannot drift.
- **It changes nothing.** No datadir lock (so it runs against a live deployment), no wallet
  database, and no cookie file - minting one would invalidate the credential a running daemon
  already handed out.

Errors mean "the daemon would refuse, or would start and never sync". Warnings cover the
legal-but-risky shapes: an uninitialized wallet, a `transparent_gap_limit` wide enough to
stall restores, a bare RPC password on a non-loopback bind. `--strict` fails on warnings too;
`-q` reports through the exit code alone.

A missing config file is an **error** here, unlike at startup where a missing file falls back
to defaults: checking a file that is not there is a typo, and silently validating the defaults
would confirm nothing.

```sh
zecd config check --conf /etc/zecd/zecd.toml || exit 1     # CI gate
zecd config check --conf /etc/zecd/zecd.toml --strict       # also fail on warnings
```

**stdout carries settings, stderr carries the verdict** - the `nginx -t` / `nginx -T` split.
That is what makes the diff below a diff of configuration and nothing else:

```sh
diff <(zecd-old config show --conf zecd.toml 2>/dev/null) \
     <(zecd-new config show --conf zecd.toml 2>/dev/null)
```

`config show` is the `sshd -T` to `config check`'s `sshd -t`: it prints the **effective**
configuration - the file, CLI flags and environment resolved together, with every unset key
filled in by this build's default - as TOML. That is what an operator actually needs before an
upgrade, because a config file is only half the configuration and defaults move between
versions. Capturing it pins today's behaviour as an explicit file before taking the upgrade:

```sh
zecd-old config show --conf zecd.toml > effective.toml
```

The output re-parses: a round-trip test feeds it back through the resolver and requires an
identical second render, so a renderer that drifts from the schema fails a test rather than
emitting a config zecd would itself reject. Secrets - the RPC password, rpcauth hashes,
`[zebra]` credentials - are emitted as **commented-out key names, never values**, since this
output is the kind of thing that gets pasted into a bug report. They are commented rather than
redacted-in-place because a placeholder that parses would silently become a real, wrong
credential if the file were deployed, where an absent password falls back to cookie auth and
fails loudly. The cost is that a secret-bearing config does not round-trip byte for byte.

Unlike `check`, a missing config file is fine for `show`: "what would this binary do with no
config" is well defined, and is the quickest way to see the built-in defaults.

### Probing the chain without a wallet

New in 0.7.0. `zecd chain-info` dials the configured upstream and reports its tip.

Before it, the chain tip was unreachable without a wallet: `config check` is deliberately
offline, and the daemon needs a wallet to start, so both "what height is the chain at?" and
"can this deployment reach its backend?" meant creating a wallet first.

```sh
$ zecd chain-info --conf /etc/zecd/zecd.toml
server            zebra://127.0.0.1:8234
network           main
chain             main
tip height        3512847
tip hash          0000000000d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80912
birthday for new  3512747
branch id         c8e71055
round trip        14 ms
OK: reachable, chain matches, consensus rules understood
```

The summary goes to stdout and the verdict to stderr, so the two can be separated in a script.
`--json` emits an object instead, with `network_matches`, `suggested_birthday`, `branch_id` and
an `unsupported_upgrades` array.

**It exits non-zero exactly when a wallet created there would not sync**, which is what makes
it usable as a deployment gate:

| Outcome | Exit | Meaning |
|---|---|---|
| Reachable, chain matches, upgrades understood | 0 | Good to `init`. |
| Upstream serves a different chain than `network` | non-zero | Pointing at the wrong node. |
| Upstream reports an **active** network upgrade this build does not know | non-zero | The build is too old to follow current consensus. Update zecd before syncing a wallet against it. |
| Upstream reports a *future* upgrade this build does not know | 0, with a warning | Update before it activates. |
| Chain name unrecognized | 0, with a warning | Cannot confirm the match either way, which is not a pass. |

`birthday for new` is the birthday `zecd init` would record for a wallet created right now, and
it comes from the same function `init` itself calls, so the two cannot drift apart. Record it
alongside a mnemonic you generated yourself.

`--server <TOKEN>` probes a candidate endpoint instead of `[backend] server`, using the same
token grammar, so a new upstream can be tested before it is committed to a config file. The
override is applied by re-resolving the configuration with the token swapped, which means the
candidate carries the same `[zebra]` credentials, TLS settings and cleartext policy the daemon
would give it. What is probed is what a daemon on that token would dial, including the
no-network refusals: an endpoint this build would never dial fails here for that reason rather
than as a connection timeout.

Read-only, like `config check`: no datadir lock, no wallet database, no cookie file. It is safe
to run against a live deployment.

### Third-party licenses

New in 0.7.0. `zecd licenses` prints the license texts of every third-party crate compiled into
the binary.

zecd links its dependencies statically, so those crates travel inside the shipped binary, and
most of the licenses in the tree require the text and copyright notice to be reproduced when
they do. The same text ships as `THIRD-PARTY-LICENSES.txt` in the release tarball, in the
Debian package, and in both container images under `/usr/share/doc/zecd/`.

```sh
zecd licenses | less
zecd licenses > THIRD-PARTY-LICENSES.txt
```

The container images are built `FROM scratch` and have no shell, so this subcommand is the one
place the notices are readable wherever zecd runs. It needs no datadir and no config file.

The bundle is generated from the lockfile at release time and covers a few hundred crates, so
expect a few hundred kilobytes of output. Piping it into a pager that exits early is fine.

### Offline address derivation

`zecd derive-address` answers "what address will this wallet hand out?" before the wallet has
a chain.

`zecd init` needs a live upstream (it anchors the account on the tree state at `birthday - 1`)
and `getnewaddress` needs a running daemon, so until 0.6.0 there was no way to learn an address
first. That is a chicken-and-egg for pre-provisioning deposit addresses, air-gapped and cold
setup, pointing a miner at a wallet that does not exist yet, and checking that a `keys.toml`
derives the addresses you expect before trusting it.

It touches no network, no wallet database and no daemon, and takes no datadir lock (like
`export-ufvk`), so it runs safely beside a live daemon.

**Key sources**, in the order it tries them:

| Source | Flag | Notes |
|---|---|---|
| An initialized wallet's `keys.toml` | *(default)* | Uses the account **UFVK** pinned there, so no seed is decrypted and a locked, passphrase-encrypted, or watch-only wallet works. |
| A BIP-39 mnemonic | `--mnemonic` | Read from `ZECD_MNEMONIC`, else `--mnemonic-file`, else stdin. |
| A Unified Full Viewing Key | `--ufvk <UFVK>` | As printed by `export-ufvk`. Addresses are the same either way; only *spending* needs a seed. |

`--index` and `--count` derive a batch at consecutive indices (default: one address at index
0). `--address-type` reuses the same syntax and the same parsing code as
[`getnewaddress`](rpc/wallet-addresses.md#getnewaddress)'s `address_type`, so the CLI and the
RPC cannot drift, and it defaults to what that wallet's `getnewaddress` would hand out. For a
bare t-address the index is the BIP 44 external child index - the same index the daemon
exposes and the same one
[`z_getaddressforaccount`](rpc/wallet-addresses.md#transparent-derivation-at-an-explicit-index)
takes.

stdout is exactly the addresses, one per line, so it pipes; `--json` reports the derivation
key and indices alongside them.

```sh
# Ten deposit addresses, before the daemon exists.
zecd derive-address --address-type transparent --index 0 --count 10

# Check a keys.toml derives what you expect, from the mnemonic in your safe.
ZECD_MNEMONIC="$(cat /mnt/secure/phrase)" zecd derive-address --mnemonic --json
```

What it deliberately **cannot** reproduce is `getnewaddress`'s *next shielded* address: those
diversifier indices are clock-derived, so only an explicit index is deterministic - which is
what an offline caller wants anyway.

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
