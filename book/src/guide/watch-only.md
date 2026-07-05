# Watch-only wallets

A zecd wallet can run **watch-only**: initialized from a ZIP-316 Unified Full Viewing Key
(UFVK) instead of a mnemonic, it sees everything the paired spending wallet sees (balances,
incoming payments including 0-conf via the mempool stream, full history) and issues receive
addresses **of the same account**, while holding no spending material on disk or in memory.

## Why: split the invoicer from the spender

The typical deployment puts the internet-facing half of a payment system on a machine that
*cannot* lose funds even if fully compromised:

```
  internet-facing host                      hardened / offline-ish host
 ┌───────────────────────────┐             ┌───────────────────────────┐
 │ payment server / invoicer │             │ payout service            │
 │   getnewaddress           │             │   sendtoaddress, sendmany │
 │   listtransactions        │             │                           │
 │   gettransaction          │             │                           │
 │        │                  │             │        │                  │
 │   zecd (watch-only, UFVK) │             │   zecd (spending wallet)  │
 └────────┼──────────────────┘             └────────┼──────────────────┘
          └──────────────► Zebra node(s) ◄──────────┘
```

The watch-only instance issues invoice addresses and detects payments; the spending wallet,
the only holder of key material, lives elsewhere and signs payouts. Because both wallets
carry the same account's viewing key, every invoice the watch-only instance hands out is
detected and spendable by the spending wallet (see the
[pairing guarantee](#the-pairing-guarantee) below). A compromise of the invoicer host leaks
your transaction graph (see the [privacy warning](#a-ufvk-grants-full-view-access)) but never
funds.

Watch-only wallets can also be loaded *in the same daemon* alongside the spending wallet as
additional `[wallets.<name>]` entries, addressed at `/wallet/<name>`; see
[multiwallet routing](../rpc/index.md).

## Exporting the key: `zecd export-ufvk`

```sh
zecd --datadir ./data export-ufvk --wallet default
```

Prints the wallet's UFVK (`uview1...` on mainnet, `uviewtest1...` on testnet) to stdout, with
an explanatory warning on stderr. `--wallet` defaults to `default`. Properties, all deliberate:

- **Offline.** It reads the UFVK from the wallet DB (where it is stored for scanning anyway)
  over a read-only connection. No upstream connection is made and no identity file or
  passphrase is needed. It works for **locked and passphrase-encrypted wallets** alike, and
  never touches spending material.
- **Works while the daemon runs.** `export-ufvk` is deliberately exempt from the exclusive
  datadir lock that `zecd init` and the daemon take, so you can export from a live wallet.
- **Network-checked.** It refuses to run if the configured network contradicts the wallet on
  disk (the UFVK encoding is network-scoped, so a mismatched key would be rejected by the
  watch-only side anyway).

## Creating the watch-only wallet: `zecd init --ufvk`

On the watch-only host, initialize a fresh datadir from the exported key:

```sh
zecd --datadir ./watch init --ufvk "uview1..." --birthday 2500000
```

- `--ufvk` conflicts with `--restore` and `--encrypt` (there is no mnemonic and nothing to
  encrypt). The malformed-key check runs before any directory or network I/O.
- Unlike `export-ufvk`, `init --ufvk` **needs the Zebra upstream reachable**: it fetches the
  chain tip and the tree state at the birthday to anchor the wallet.
- An imported key may have history, so it is treated like a restore: **pass `--birthday`** (a
  height at or before the account's first transaction) to avoid the safe-but-slow default,
  which scans from the earliest enabled pool's activation (Orchard/NU5 for the default
  Orchard-only configuration; Sapling activation if Sapling is enabled) and logs a warning.
- The result is a seedless `keys.toml` with the UFVK pinned into it (the same
  [account-to-keys binding](../security/key-custody.md) check spending wallets get: every
  startup verifies the DB account against the pin, so a swapped database fails closed).

No mnemonic is printed; there is none. Init confirms (one line, on stderr):

```
Watch-only wallet (imported UFVK): balances, history, and addresses are available; spending and wallet-encryption RPCs are disabled.
```

## RPC semantics

zecd follows Bitcoin Core's modern model: a wallet **without private keys**
(`createwallet ... disable_private_keys=true` in Core). Watch-only is a property of the whole
wallet, never of individual addresses.

| Surface | Behavior on a watch-only wallet |
|---|---|
| `getwalletinfo.private_keys_enabled` | `false`. **This is the watch-only signal**, as in Core. (`unlocked_until` is absent: the wallet is not encrypted, there is nothing to lock.) |
| `getnewaddress` | Works: diversified addresses derive from the viewing key. See the pairing guarantee below. |
| Reads (`getbalance`, `listtransactions`, `listunspent`, `gettransaction`, ...) | Fully available, including 0-conf mempool visibility. |
| `sendtoaddress`, `sendmany`, `z_sendmany` | `-4` `Error: Private keys are disabled for this wallet`, byte-identical to Core's refusal, returned before any balance check. (For `z_sendmany` the error surfaces through the operation result.) |
| `walletpassphrase`, `walletlock` | `-15` `Error: running with an unencrypted wallet, but walletpassphrase was called.` (resp. `walletlock`), the same as any unencrypted wallet, byte-identical to Core. |
| `getaddressinfo` | Unchanged: `iswatchonly` stays **`false`** and own addresses stay `ismine: true`, `solvable: true`. This matches Core master, where `iswatchonly` is documented "(DEPRECATED) Always false" (per-address watch-only died with legacy wallets) and `solvable` is defined "ignoring the possible lack of private keys". Do not probe `getaddressinfo` for watch-only status; use `getwalletinfo.private_keys_enabled`. |

### The pairing guarantee

Every address the watch-only instance issues is a diversified address of the **same account**
as the spending wallet (the UFVK can only derive its own account's addresses), so an invoice
issued by the watch-only instance is always detected and spendable by the paired spending
wallet, whose note detection is viewing-key-based and does not depend on which instance issued
the address.

What is *not* guaranteed is that the two instances hand out the same address **sequence**:
librustzcash picks shielded diversifier indexes from the clock, so two same-key wallets return
identical `getnewaddress` results only when called within the same second. To verify a pairing,
compare key material (`export-ufvk` on both sides returns the identical string), not
`getnewaddress` output. See [Addresses & shielded pools](addresses.md) for the diversifier
mechanics.

## One spender, many watchers

A single daemon may load **at most one wallet with spending keys**, plus any number of
watch-only wallets alongside it. This keeps spend authority unambiguous: there is never a
question of which key signs. Two enforcement points:

1. **At `zecd init`**: creating a spending wallet is refused up front (before any directory or
   network I/O) when another configured wallet already holds spending keys. The error suggests
   `--ufvk` instead. Watch-only inits are exempt: any number are allowed.
2. **At daemon startup**, as a backstop for wallets created out-of-band (independent inits
   later merged into one config, restores, external DB edits): after every wallet reports its
   watch-only flag, a second spender is **fatal for the whole daemon**. zecd will not silently
   pick which one is "the" spender; the error names both offending wallets.

To resolve a violation, convert one spending wallet to watch-only (`zecd export-ufvk` +
`zecd init --ufvk` into a fresh datadir, then delete the spending datadir) or remove it from
the configuration.

## A UFVK grants full view access

A Unified Full Viewing Key reveals **everything**: all balances, all addresses (incoming *and*
outgoing sides), and the full transaction history of the account, forever. `export-ufvk` emits
the account's full viewing key; there is no reduced-visibility export. It cannot spend, but
treat it as a privacy secret:

- Share it only with hosts that may see your entire transaction graph.
- A watch-only datadir still deserves protection (filesystem permissions, encryption at
  rest): it contains the decrypted history, even though it holds no spending material.
- There is no way to revoke a leaked UFVK short of moving all funds to a new seed.

For the custody models and what a spending wallet protects beyond this, see
[Key custody](../security/key-custody.md).
