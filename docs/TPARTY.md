# tparty

Transparent Zcash deposit addresses that auto-shield. `tparty` is built from the zecd
repository (`cargo build --release --bin tparty`) and shares zecd's library: same JSON-RPC
1.0 wire format, Basic/cookie auth, Bitcoin Core error codes, wallet format, and
light-client architecture (`zebra → tparty` by default, optionally through lightwalletd).

## When to run it

Run tparty when an integration must be given **t-addresses** - legacy exchange or payment
flows that parse the address format and don't understand unified addresses. zecd never
hands out transparent addresses; tparty exists so that requirement doesn't weaken zecd.
Every deposit received on a tparty address is shielded into the wallet seed's shielded
pool as soon as it reaches the configured confirmation depth, so funds spend as little
time as possible exposed in the transparent pool.

If your clients can pay a `u1…` address, run zecd alone and skip tparty entirely.

## Quick start

```sh
cargo run --release --bin tparty -- --datadir ./tparty-data --testnet init
cargo run --release --bin tparty -- --datadir ./tparty-data --testnet \
    --rpcuser t --rpcpassword secret --rpcport 18237
```

Config lives in `<datadir>/tparty.toml` (see `tparty.example.toml`). Defaults stay off
zecd's ports - RPC 8237 mainnet / 18237 testnet, health 9237 - so the pair coexists on one
host.

## Pairing with zecd

Sharing a mnemonic with a zecd instance is supported and is the intended deployment:
restore the same seed into both daemons (**separate datadirs** - each owns its wallet
database) and tparty becomes zecd's transparent deposit front. Deposits land on
t-addresses, auto-shield into the account's internal Orchard receiver - the address every
librustzcash wallet scans by default on a seed restore - and appear in zecd's `getbalance`
to spend.

Addresses cannot collide: zecd issues Orchard-only unified addresses (external scope, no
transparent receiver - a documented zecd invariant), tparty issues P2PKH t-addresses, and
the shield destination is the internal (change) scope that no `getnewaddress` ever
exposes. The invariant is enforced by test
(`regtest_tests::tparty_addresses_never_collide_with_zecd`); if zecd ever grew transparent
receivers, that test fails and the deployment model has to be reconsidered - see the
README's seed-sharing caveats.

## Behavior

- `getnewaddress` returns a fresh base58 t-address (`t1…`/`tm…`) per call - a diversified
  transparent receiver of the wallet's one ZIP-32 account. The unused-address window is
  bounded by `[tparty] gap_limit` (default 100, which yields gap_limit−1 fresh addresses);
  exhausting it returns `-12` until earlier addresses receive funds.
- Auto-shield fires once a deposit has `[tparty] min_conf` confirmations (default 1; `0`
  shields from the mempool) and the spendable total clears `[tparty] threshold_zat`
  (default 100000 zatoshis, so the ZIP-317 fee isn't burned on dust). `shieldfunds`
  shields immediately, ignoring the threshold. The destination pool is `[tparty] pool` -
  only `"orchard"` today; the knob exists so Sapling can be added later.
- `getbalance` reports **unshielded** funds only and trends to zero when the pipeline is
  healthy; `getunconfirmedbalance` is deposits still maturing. `getshieldinginfo` is the
  health view: policy, unshielded/shielded balances, `last_shield_txid`, connection state.
  A persistently positive `getbalance` means shielding is stuck - locked wallet, upstream
  down, or dust below the threshold.
- No spend methods: `sendtoaddress`/`sendmany` return `-32601`. tparty is a deposit
  funnel; spend the shielded funds from any wallet holding the same seed.
- Auto-shielding signs unattended, so it needs `[keys] auto_unlock = true` (the default).
  On a passphrase-encrypted wallet, deposits accumulate unshielded until
  `walletpassphrase`.

## RPC methods

| Category | Methods |
|---|---|
| Deposit | `getnewaddress` (returns a t-address), `getreceivedbyaddress`, `listreceivedbyaddress`, `getreceivedbylabel`, `listreceivedbylabel`, `listunspent` (transparent UTXOs) |
| Balances | `getbalance` (unshielded only), `getunconfirmedbalance`, `getbalances` (+`shielded`), `getwalletinfo` (+`shielded_balance`) |
| Shielding | `getshieldinginfo`, `shieldfunds` |
| History | `listtransactions`, `listsinceblock`, `gettransaction` |
| Shared with zecd | labels, `getaddressinfo`, `validateaddress`, raw transactions, blockchain/network/control, `encryptwallet`/`walletpassphrase`/`walletpassphrasechange`/`walletlock` |

## Testing

Offline (`cargo test`, gating CI): the zecd/tparty address-collision guarantee, gap-limit
`-12`, transparent receive/balance/UTXO reporting, `[tparty]` config parsing and pool
validation, dispatch-table separation, and CLI acceptance. Live
(`regtest-harness/tests/regtest_tparty.rs`, its own matrix leg in the Regtest E2E
workflow): real deposits against zebra+lightwalletd - auto-shield on confirmation,
balances draining, threshold skip, and the `shieldfunds` manual flush.

Operations (backup, restore, monitoring) follow zecd's runbook: `docs/OPERATIONS.md`.
