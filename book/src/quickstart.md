# Quickstart

From zero to a first RPC call: point a local Zebra node's JSON-RPC at zecd, build the binary,
initialize a wallet, run the daemon, and talk to it with any Bitcoin RPC client. The Docker
compose route at the end does the same with one stack file.

## Prerequisites: a local zebrad

zecd is a wallet server: it holds keys and scans compact blocks, but its entire view of
the chain comes from a **self-hosted [Zebra](https://github.com/ZcashFoundation/zebra) full
node's JSON-RPC**. Run one on the same host (or private network) and let it sync before
starting zecd.

Zebra ships with its RPC endpoint disabled. Enable it in `zebrad.toml` on the port zecd's
default backend expects:

```toml
[rpc]
# The port zecd's default `server = "zebra"` dials:
#   mainnet  ->  zebra://127.0.0.1:8234
#   testnet  ->  zebra://127.0.0.1:18234
listen_addr = "127.0.0.1:8234"      # testnet: "127.0.0.1:18234"
```

Any explicit `[backend] server = "zebra://host:port"` works too if you prefer a different port
or a co-located container host; see [Configuration](configuration.md). If zebrad's cookie
authentication is enabled, point zecd at the cookie (or set user/password) in the `[zebra]`
config section; with `enable_cookie_auth = false` on a loopback-only listener, no credentials
are needed. The connection is plaintext HTTP and deliberately local-only: never expose a
Zebra RPC port publicly (see [the Zebra backend](design/zebra-backend.md) for the
cleartext-credential gate).

Two port families are in play: 8234/18234 are **Zebra's** RPC (what zecd dials), while 8232/18232
are **zecd's own** RPC defaults (what your clients dial), mirroring bitcoind's 8332/18332
convention.

## Build from source

zecd is not yet published on crates.io. Build from source, use the
[release tarballs / `.deb` packages](guide/deployment.md), or use the
[Docker stack](#docker-compose-quickstart) below.

```sh
git clone https://github.com/zecrocks/zecd && cd zecd
cargo build --release --bin zecd
```

Always use `--release`: a debug build takes more than 20 seconds to prove a single shielded
send.

## Initialize a wallet

`zecd init` creates the wallet and exits. It needs the zebrad from the previous step reachable
(a new wallet's birthday defaults to just below the current chain tip, which init fetches from
the node).

```sh
# Testnet (drop --testnet for mainnet):
./target/release/zecd --datadir ./data --testnet init --wallet default
```

This generates three things:

- **An age identity** at `<datadir>/identity.txt` (mode 0600), the key that encrypts the
  wallet seed at rest so the daemon can send unattended.
- **A 24-word mnemonic seed phrase**, printed to stdout exactly once. **Back it up now.** It
  is the only way to recover the wallet: shielded funds are unconditionally recoverable from
  it on any librustzcash wallet; the on-disk data directory is a rebuildable cache
  (see [Stateless & recoverable](design/statelessness.md)).
- **The wallet account** in `<datadir>/default/data.sqlite`, plus `keys.toml` holding the
  age-encrypted mnemonic.

Variants (see [Key custody](security/key-custody.md) for the trade-offs):

```sh
zecd --datadir ./data --testnet init --restore                  # restore from an existing mnemonic
zecd --datadir ./data --testnet init --restore --birthday 2500000  # much faster: scan from a known height
zecd --datadir ./data --testnet init --encrypt                  # passphrase-encrypted (Bitcoin Core style,
                                                                #   starts locked; unlock via walletpassphrase)
zecd --datadir ./data --testnet init --ufvk "uview1..."         # watch-only wallet from a viewing key
```

A restore without `--birthday` scans from the earliest enabled pool's activation height,
which is safe but slow; pass any height at or before the wallet's first transaction. For
watch-only setups see [Watch-only wallets](guide/watch-only.md).

## Run the daemon

```sh
./target/release/zecd --datadir ./data --testnet \
    --rpcuser zec --rpcpassword secret --rpcbind 127.0.0.1 --rpcport 18232
```

The daemon syncs compact blocks in the background and serves JSON-RPC immediately; balances
and history fill in as the scan catches up. Default RPC ports are **8232** (mainnet) and
**18232** (testnet). CLI flags override the TOML config (default `<datadir>/zecd.toml`);
`--rpcpassword` can also come from the `ZECD_RPC_PASSWORD` environment variable, and
bitcoind-style salted credentials from `--rpcauth` (generate one with `zecd rpcauth <user>`).
The full flag and config reference is in [Configuration](configuration.md).

On mainnet, zecd refuses to start while `[rpc] password` is still the example placeholder
`CHANGE-ME`.

## Talk to it

Exactly like bitcoind (HTTP Basic auth, JSON-RPC 1.0 envelope):

```sh
curl -s --user zec:secret --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: text/plain;' http://127.0.0.1:18232/
```

Or with `python-bitcoinrpc`, unchanged:

```python
from bitcoinrpc.authproxy import AuthServiceProxy

rpc = AuthServiceProxy("http://zec:secret@127.0.0.1:18232")
print(rpc.getblockchaininfo())
addr = rpc.getnewaddress()          # a u1.../utest1... Orchard Unified Address
print(rpc.getbalance())
print(rpc.listtransactions("*", 20))
```

Two things to know: `getnewaddress` returns a shielded Unified Address, and a
`label` argument is rejected with `-8` because zecd keeps no labels
(see [Addresses & shielded pools](guide/addresses.md) and
[Stateless & recoverable](design/statelessness.md)). Wire-format details (envelope, batching,
error codes, multiwallet routing) are in the [RPC conventions](rpc/index.md).

### Cookie auth

If you set neither `--rpcuser`/`--rpcpassword` nor `[rpc] user`/`password`, zecd writes a
bitcoind-style cookie file to `<datadir>/.cookie` (mode 0600, regenerated with a fresh random
password on each start) and authenticates against it:

```sh
curl -s --user "$(cat ./data/.cookie)" --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' \
  -H 'content-type: text/plain;' http://127.0.0.1:18232/
```

The cookie's user is the fixed `__cookie__`, as in bitcoind.

## Docker compose quickstart

`deploy/docker-compose.yml` runs the full self-hosted stack (Zebra and zecd on one private
compose network), on **testnet by default**:

```sh
cd deploy
docker compose up -d zebra                        # start the node; let it sync first
docker compose run --rm zecd init --wallet default   # back up the printed mnemonic!
docker compose up -d                              # start zecd
curl localhost:9233/readyz                        # health probe (see guide/operations.md)
curl --user zec:CHANGE-ME --data-binary \
  '{"method":"getblockchaininfo","id":1}' localhost:18232/
```

For **mainnet**, add `-f docker-compose.mainnet.yml` to every command; the overlay swaps each
service onto its mainnet config file (`zebrad.mainnet.toml`, `zecd.mainnet.toml`) while keeping
the ports and volumes identical:

```sh
docker compose -f docker-compose.yml -f docker-compose.mainnet.yml up -d zebra
docker compose -f docker-compose.yml -f docker-compose.mainnet.yml run --rm zecd init --wallet default
docker compose -f docker-compose.yml -f docker-compose.mainnet.yml up -d
```

Before a mainnet deployment, set a real `[rpc] password` in `deploy/zecd.mainnet.toml` (zecd
refuses to start on mainnet with the shipped `CHANGE-ME`), and pin the Zebra image tag to a
release you have verified. The compose file publishes zecd's RPC (18232 on both networks, to
keep the mapping identical) and health (9233) ports on loopback only: RPC credentials are
spend authority over plaintext HTTP, so front them with TLS or a network policy before serving
other hosts. The image build, ARM variant, and `.deb`/systemd routes are covered in
[Deployment](guide/deployment.md).

## Where to go next

- [Configuration](configuration.md): every TOML section and key, CLI flags, environment
  variables (pools, privacy policy, confirmations, health probes).
- [Deployment](guide/deployment.md): reproducible images, release binaries, systemd,
  Kubernetes probes.
- [Operations runbook](guide/operations.md): backup/restore, monitoring, `/healthz`
  `/readyz` `/status`, upgrades, failure modes.
- [RPC reference](rpc/index.md): the wire format and the full method reference.
