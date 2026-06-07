# zecd

A **Bitcoin-Core-style JSON-RPC server for Zcash**, backed entirely by
[librustzcash](https://github.com/zcash/librustzcash), operating an **Orchard-shielded-only**
wallet.

`zecd` speaks Bitcoin Core's JSON-RPC dialect - the same method names, response shapes,
HTTP Basic/cookie auth, JSON-RPC 1.0 envelope, and batching - so existing Bitcoin RPC client
libraries (Python `python-bitcoinrpc`, Rust `bitcoincore-rpc`, Go `rpcclient`, Ruby) and
Bitcoin-RPC-style integrations can talk to it with little or no massaging. It is **not** modeled
on `zcashd`'s `z_*` RPC: it reuses Bitcoin names (`getbalance`, `getnewaddress`, `sendtoaddress`,
`listtransactions`, `gettransaction`, …) and maps them onto Orchard shielded operations.

It is a **lightwalletd-backed light client**: it syncs compact blocks in the background and never
speaks a peer-to-peer protocol, streams full blocks, or indexes the chain itself.

## Deployment model

```
zebra (full node)  →  lightwalletd  →  zecd  →  your app / Bitcoin RPC client
```

- **Self-hosted production:** point `zecd` at your own local `lightwalletd` (which talks to
  `zebra`). Set `[lightwalletd] server = "127.0.0.1:9067"`.
- **Testing / out-of-the-box:** `zecd` defaults to the public **zecrocks** infrastructure
  (`zec.rocks:443` on mainnet, `testnet.zec.rocks:443` on testnet), so it runs immediately with
  no node to stand up.

## Quick start

```sh
# 1. Initialize a testnet wallet (generates an age identity + 24-word mnemonic, creates an account).
cargo run --release -- --datadir ./data --testnet init --wallet default --account-name primary

# 2. Run the daemon (syncs in the background, serves JSON-RPC).
cargo run --release -- --datadir ./data --testnet \
    --rpcuser zec --rpcpassword secret --rpcbind 127.0.0.1 --rpcport 18232
```

Then talk to it like bitcoind:

```sh
curl -s --user zec:secret --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' http://127.0.0.1:18232/
```

```python
from bitcoinrpc.authproxy import AuthServiceProxy
rpc = AuthServiceProxy("http://zec:secret@127.0.0.1:18232")
print(rpc.getblockchaininfo())
addr = rpc.getnewaddress("invoice-1")     # a u1... Orchard Unified Address
print(rpc.getbalance())
print(rpc.listtransactions("*", 20))
```

If you do not set `--rpcuser`/`--rpcpassword`, `zecd` writes a bitcoind-style cookie file to
`<datadir>/.cookie` and authenticates against that.

## Configuration

CLI flags override the TOML config (default `<datadir>/zecd.toml`). See `zecd.example.toml`.

```toml
network = "test"                 # "main" | "test"
datadir = "./data"
default_wallet = "default"

[wallets.default]
dir = "./data/default"

[lightwalletd]
server = "zecrocks"              # "ecc" | "ywallet" | "zecrocks" | "host:port" (or "h:p,h:p")
# Or list multiple endpoints for failover, tried in order and always preferring the first; the
# daemon snaps back to the primary when it recovers. `servers` takes precedence over `server`.
# A scheme prefix sets TLS per endpoint (http:// plaintext, https:// TLS), so a plaintext local
# node and TLS public fallbacks can share one list:
#   mainnet:  servers = ["http://127.0.0.1:9067", "https://zec.rocks:443", "https://eu.zec.rocks:443"]
#   testnet:  servers = ["http://127.0.0.1:9067", "https://testnet.zec.rocks:443"]
connection = "direct"
tls_roots = "native"            # "native" (OS store, honors SSL_CERT_FILE) | "webpki"
tls = "auto"                    # "auto" (TLS for remote, plaintext for localhost) | "yes" | "no"
connect_timeout_secs = 10       # per-attempt dial timeout (so a hung endpoint can't stall sync)
reconnect_base_secs = 1         # reconnect backoff: base delay (doubles, full jitter)
reconnect_max_secs = 60         # reconnect backoff: ceiling
primary_recheck_secs = 60       # while on a fallback, how often to re-probe higher-priority servers

[rpc]
bind = "127.0.0.1"
port = 18232                     # mainnet default 8232, testnet 18232
user = "zec"
password = "secret"
# cookiefile = "./data/.cookie"  # used when user/password are unset
work_queue = 100                 # max in-flight requests before HTTP 503 (= bitcoind -rpcworkqueue)

[keys]
age_identity = "./data/identity.txt"
auto_unlock = true               # decrypt the seed at startup so sends need no walletpassphrase

[sync]
interval_secs = 20

[log]
level = "info"                   # tracing filter; RUST_LOG overrides
format = "text"                  # "text" | "json" (structured, for log aggregation)

[health]
enabled = true
bind = "127.0.0.1"               # set 0.0.0.0 for Kubernetes/LB probes
port = 9233
ready_progress = 0.999           # /readyz is 200 once scan progress reaches this
```

## Supported RPC methods

**Wallet:** `getnewaddress` (→ Orchard UA), `getbalance`, `getunconfirmedbalance`,
`getwalletinfo`, `getaddressinfo`, `setlabel`, `getaddressesbylabel`, `listlabels`,
`listtransactions`, `gettransaction`, `listunspent`, `sendtoaddress`, `sendmany`,
`walletpassphrase`, `walletlock`, `listwallets`.

**Blockchain:** `getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`.

**Network:** `getnetworkinfo`, `getconnectioncount`, `getpeerinfo`, `ping`.

**Utility:** `validateaddress`, `estimatesmartfee`, `estimatefee`, `getmempoolinfo`.

**Control:** `stop`, `uptime`, `help`, `getrpcinfo`.

Multiwallet is addressed bitcoind-style via `POST /wallet/<name>`; the default wallet is used at
`POST /`.

## Addresses

`getnewaddress` returns a fresh **Orchard-only Unified Address** (`u1…` / `utest1…`) on every
call. These are **diversified addresses of a single account**, not new derivation paths: the
wallet has one ZIP-32 account (`m/32'/coin_type'/account'`), and each address is a different
*diversifier index* of that account's Orchard key (`UnifiedAddressRequest::ORCHARD` →
`account.uivk().find_address(j, …)`). librustzcash advances to the next unused diversifier
(starting from a timestamp-derived index, incrementing past any collision) and persists it in the
wallet's `addresses` table, so each call yields a new, unused address - and all of them receive
into the same account and are spendable by the same key (ZIP-316 unified addresses + ZIP-32
diversification).

## Logging

zecd logs via `tracing`. The level comes from `[log] level` and is overridden by the standard
`RUST_LOG` env var (e.g. `RUST_LOG=debug` or `RUST_LOG=zecd=debug,zcash_client_backend=info`). Each
RPC call emits a structured event - `debug` on success (`method`, `wallet`, `elapsed_ms`), `info`
on error (adds `code`, `message`) - and sync/connection lifecycle events log at `info`. Set
`[log] format = "json"` for structured JSON lines suitable for Loki/CloudWatch/Elastic.

## Concurrency & busy servers

zecd is a daemon; each wallet is owned by a single-writer actor, so **sends serialize per
wallet** - the same guarantee Bitcoin Core gets from `cs_wallet`. Concurrent
`sendtoaddress`/`sendmany` calls are processed one at a time, so two sends never select the same
note: there is **no double-spend**. When many sends go out at once they queue at the actor and each
client's HTTP call blocks until its send completes. Because a freshly-created change note is
unconfirmed (not yet spendable), rapid back-to-back sends exhaust spendable notes and then return
`RPC_WALLET_INSUFFICIENT_FUNDS (-6)` until confirmations arrive - the same code bitcoind returns
when funds are already spent/locked.

Overload protection matches bitcoind's work queue: at most `[rpc] work_queue` requests
(default 100, like `-rpcworkqueue`) are in flight; beyond that the server returns **HTTP 503
`Work queue depth exceeded`**. During shutdown it returns **503 `Request rejected during server
shutdown`**.

HTTP status and error codes match Bitcoin Core exactly (`rpc/protocol.h`, `httprpc.cpp`):

| Condition | RPC code | HTTP |
|---|---|---|
| success | - | 200 |
| insufficient funds | `-6` | 500 |
| wallet locked (needs `walletpassphrase`) | `-13` | 500 |
| tx rejected by network | `-26` | 500 |
| bad/unknown address or txid | `-5` | 500 |
| invalid parameter | `-8` | 500 |
| invalid request | `-32600` | 400 |
| method not found | `-32601` | 404 |
| parse error | `-32700` | 500 |
| auth failure | - | 401 (+ `WWW-Authenticate`, 250 ms delay) |
| over work-queue / shutting down | - | 503 |

Batches always return HTTP 200 with per-item errors in the array.

**Visibility under load:** `getrpcinfo` returns `active_commands` - one entry per
currently-executing call with `method` and `duration` (µs) - so you can see exactly what is in
flight. Combine with `getwalletinfo` (`txcount`, balances, `scanning`),
`getbalance`/`getunconfirmedbalance`, `listtransactions`/`gettransaction` (per-tx
`confirmations`), and the `/status` health endpoint.

## Health & readiness

With `[health] enabled` (default), zecd serves unauthenticated probes on a separate port
(`[health] port`, default 9233):

- `GET /healthz` - liveness: `200 ok` while the process is running.
- `GET /readyz` - readiness: `200` once every wallet is connected to lightwalletd and synced to
  `[health] ready_progress`; otherwise `503`. Body is JSON with per-wallet detail; when not ready it
  also carries a `reason` (`"upstream_down"` vs `"syncing"`) so alerting can tell an unreachable
  lightwalletd apart from a normal catch-up.
- `GET /status` - JSON snapshot of per-wallet sync state, including the active `server` endpoint and
  `conn_state` (`down` | `syncing` | `ready`). `getpeerinfo` reflects the same active upstream.

Set `[health] bind = "0.0.0.0"` so a Kubernetes kubelet / load balancer can reach the probes. The
health server starts after wallets load, so cover the brief prover-init at boot with a
`startupProbe` / `initialDelaySeconds`.

## Bitcoin Core conformance

zecd matches Bitcoin Core's method names, response field names/types, the JSON-RPC 1.0 envelope
(`{"result","error","id"}`), HTTP 500-with-error-body / 401 semantics, decimal (8-dp) amounts, and
error codes (`protocol.h`: e.g. `-5`, `-6`, `-13`, `-32601`). This is verified two ways:

- **`scripts/conformance.py`** drives a running daemon with the *same client logic
  `python-bitcoinrpc` uses* (`AuthServiceProxy`): Basic auth, the 1.0 envelope, amounts decoded as
  `decimal.Decimal` (asserting no float drift), `JSONRPCException` raised with the right code, and
  batching. (Validated live against testnet: 49/49.) `scripts/rpc_smoke.py` is a stdlib-only variant.
- **`cargo test`** covers the framing/auth/HTTP-status behavior with offline unit + HTTP
  integration tests, and (with `--include-ignored`) live lightwalletd calls.

Intentional divergences are listed under *Compatibility boundary* below.

## Docker / self-hosted stack

`deploy/docker-compose.yml` runs the full **zebra → lightwalletd → zecd** stack (testnet by
default); `Dockerfile` builds the zecd image.

```sh
cd deploy
docker compose up -d zebra lightwalletd     # let these sync first
docker compose run --rm zecd init --wallet default --account-name primary
docker compose up -d
curl localhost:9233/readyz
curl --user zec:CHANGE-ME --data-binary '{"method":"getblockchaininfo","id":1}' localhost:18232/
```

Image tags in the compose are examples - pin zebra/lightwalletd to releases you've verified. Edit
`deploy/*.toml` / `*.conf` for mainnet (network, ports, and the `zecd.toml` RPC password).

## Compatibility boundary

`zecd` targets **generic Bitcoin-RPC compatibility**: any integration that drives a coin purely
through Bitcoin-Core RPC (request an address with `getnewaddress`, then poll
`listtransactions` / `gettransaction` / `getbalance` to detect payment and confirmations) works.

What is **out of scope by design**:

- **BTCPayServer via NBXplorer.** NBXplorer indexes the chain over Bitcoin P2P / full blocks and
  tracks xpub derivation schemes over transparent UTXOs. The `zebra → lightwalletd → zecd` stack
  exposes no P2P surface and the wallet is shielded-only, so this path is not pursued.

Edges to be aware of (all consequences of being a shielded light wallet):

- **No instant 0-conf:** received notes must be scanned and reach the confirmation minimum before
  they are spendable/visible.
- **Fees:** `estimatesmartfee` returns a stable conventional rate; real fees are ZIP-317,
  computed at transaction-build time.
- **Addresses are shielded UAs** (`u1...`/`utest1...`): clients that parse the address string as a
  transparent Bitcoin address will not understand them; clients that treat addresses as opaque
  strings are fine.
- **`listunspent`** lists each unspent Orchard *note* as one entry. Its `txid`/`vout` identify the
  shielded action that created the note (there is no transparent `scriptPubKey`), and `address` is
  empty.

## Testing

```sh
# Unit + offline tests (amount conversion, auth, JSON-RPC framing, HTTP status codes):
cargo test

# Also run the network integration tests that hit the public zecrocks lightwalletd
# (testnet.zec.rocks / zec.rocks) - get_latest_block, get_lightd_info, tree state:
cargo test -- --include-ignored

# End-to-end RPC smoke test against a running, synced daemon (stdlib-only, validates the
# bitcoind wire format, amounts, and error codes over HTTP):
python3 scripts/rpc_smoke.py --url http://127.0.0.1:18232/ --user u --password p

# Spending smoke test (manual; needs two wallets, the default one funded). Validates the
# walletlock/walletpassphrase gate, sendtoaddress, and sendmany by broadcasting real txs:
python3 scripts/rpc_send_smoke.py --send-timeout 180
```

All wallet RPCs have been exercised against the live public testnet (zecrocks): balances,
addresses/labels, history (`listtransactions`/`gettransaction` incl. `hex`), `listunspent`,
the `walletlock`/`walletpassphrase` gate, and real Orchard `sendtoaddress`/`sendmany`
broadcasts (receiving a note and spending it across two wallets).

## Security

- The wallet seed is stored as an `age`-encrypted mnemonic in `<wallet>/keys.toml` and decrypted
  into memory only when needed (held as a zeroizing secret). Keep your age identity file safe.
- Do not expose the RPC port to untrusted networks. Bind to `127.0.0.1` and/or front it with TLS.

## License

Dual-licensed under Apache-2.0 or MIT.
