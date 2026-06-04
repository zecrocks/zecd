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
server = "zecrocks"              # "ecc" | "ywallet" | "zecrocks" | "host:port"
connection = "direct"

[rpc]
bind = "127.0.0.1"
port = 18232                     # mainnet default 8232, testnet 18232
user = "zec"
password = "secret"
# cookiefile = "./data/.cookie"  # used when user/password are unset

[keys]
age_identity = "./data/identity.txt"
auto_unlock = true               # decrypt the seed at startup so sends need no walletpassphrase

[sync]
interval_secs = 20
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
- **Addresses are shielded UAs** (`u1...`): clients that parse the address string as a transparent
  Bitcoin address will not understand them; clients that treat addresses as opaque strings are fine.
- **`listunspent` returns `[]`:** there are no transparent UTXOs, and shielded notes are not
  exposed as bitcoin-style outpoints. Use `getbalance`.
- **`gettransaction.hex`** is empty and `getaddressinfo.ismine` is always `false` in this version.

## Security

- The wallet seed is stored as an `age`-encrypted mnemonic in `<wallet>/keys.toml` and decrypted
  into memory only when needed (held as a zeroizing secret). Keep your age identity file safe.
- Do not expose the RPC port to untrusted networks. Bind to `127.0.0.1` and/or front it with TLS.

## License

Dual-licensed under Apache-2.0 or MIT.
