# Fleet: many watch-only wallets

> **Experimental.** New in 0.8.0, off unless `[fleet] enabled = true`. While it carries this
> label, the manifest format, the `[fleet]` keys and the `createwallet`, `loadwallet`,
> `unloadwallet` and `listwalletdir` RPCs may change in a patch release, with no migration.
> A deployment with one wallet, or a handful of `[wallets.<name>]` entries, does not need it
> and is unaffected by it.

A fleet lets one daemon monitor a large number of watch-only wallets: a service that watches
viewing keys on other people's behalf, for example. Spending is untouched. The one spending
wallet stays a conventional wallet with its own database and actor.

## Why it exists

A conventional view wallet costs a full stack of its own: a database, an actor, a scan pass,
note-commitment trees and a memo backlog. At thousands of wallets against one upstream, that
duplication is what stops zecd scaling.

A fleet puts many viewing keys into one **shard**: one database holding one account per
wallet, behind one actor, scanned in one pass. librustzcash's scanner already trial-decrypts
each block once against every account in a database, so a block is fetched once and decrypted
once against every key in the shard. Trial decryption itself is per key and cannot be shared;
everything around it is.

Shards stay bounded because adding an account rewinds its database to that account's
birthday. In one database for everything, onboarding a wallet with an old birthday would make
every other wallet re-scan with it.

## Enabling it

```toml
[fleet]
enabled = true
# manifest_dir = "fleet/zec/wallets.d"   # relative to the datadir
# dir = "fleet/zec/shards"               # relative to the datadir
# shard_size = 128
# cohort_depth = 10000
```

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Run the fleet. Off, the manifest directory is never read, no shard is opened, and `createwallet`/`loadwallet` refuse with `-4`. |
| `manifest_dir` | `<datadir>/fleet/zec/wallets.d` | One manifest per wallet. **Key material, not a cache**: see [backup](#backup). A value is taken relative to the datadir and replaces the default outright, coin directory included. |
| `dir` | `<datadir>/fleet/zec/shards` | The shard databases, one `shard-NNNN/lrz/` each. A cache, rebuildable from the manifests and the chain. Relative to the datadir, as above. |
| `shard_size` | `128` | Accounts per shard. A bigger shard shares more scanning but is rewound by more arrivals. `0` is a startup error. |
| `cohort_depth` | `10000` | How far below a shard's oldest birthday an arriving wallet may be and still join it, in blocks; deeper arrivals start a new shard. |

Both directories sit under `<datadir>/fleet/<coin>/` because a viewing key serves one currency
and placement is decided by a birthday, which is a height on one chain.

**`fleet` is a reserved wallet name.** A `[wallets.fleet]` entry would resolve to
`<datadir>/fleet`. With the fleet enabled, zecd refuses to start on that overlap; with it
disabled, `zecd config check` warns, since enabling it later would make the daemon refuse to
start. `config check` also warns when manifests are present while the fleet is disabled, and
restates the experimental status when it is enabled.

## Manifests

Each fleet wallet is one file, `<manifest_dir>/<name>.toml`:

```toml
# <datadir>/fleet/zec/wallets.d/acct-00417.toml
ufvk = "uview1..."
birthday = 2837400
```

- The file stem is the wallet name, served at `/wallet/<name>`. Names are ASCII letters,
  digits, `-`, `_` and `.`.
- `ufvk` and `birthday` are both required and nothing else is accepted. The birthday is
  required because defaulting it would choose between a full-chain rescan and a scan that
  misses the wallet's funds.
- Files not ending in `.toml` are ignored.
- An unreadable or malformed manifest is skipped with a warning and reported by
  `listwalletdir`, so one bad file does not hide every other wallet. An unreadable directory,
  or two manifests for one name, is fatal at startup.
- Manifests are written atomically (temporary file, fsync, rename) and never overwritten, so an
  interrupted `createwallet` cannot leave a torn viewing key.

Add a wallet by writing a manifest and restarting, or without a restart with
[`createwallet`](../rpc/wallet-addresses.md#createwallet).

## Placement

Which shard holds a wallet is read back from the shard databases, not recorded in a side file,
so there is nothing to disagree with them. A new wallet joins an open shard unless the shard is
full (`shard_size`) or the wallet's birthday is more than `cohort_depth` blocks below the
shard's oldest birthday, in which case it starts a new shard and rescans only against its own
key.

Two limitations are why the fleet is experimental:

- **Placement groups wallets by arrival, not by birthday.** A shard's scan floor is its oldest
  member's birthday, so a wallet born at today's tip that lands beside a 2018 wallet waits for
  that shard to scan from 2018. A wide spread of birthdays places poorly.
- **A wallet cannot be removed once imported.** `unloadwallet` stops serving it but deletes
  nothing: the manifest and the account stay, and the shard keeps scanning its key. Removing
  it means deleting its manifest and rebuilding the shard.

## What a fleet wallet can do

Fleet wallets are **watch-only and shielded-only**. They answer the read RPCs (balances,
history, `listunspent`, `getaddressinfo`) for their own account and nothing else, and they
cannot sign. Every read that reports a wallet's own money, history or addresses is scoped to
that wallet's account, so a wallet never sees its shard-mates' funds.

A watch-only daemon builds no Sapling prover and, when no loaded wallet can spend, does not
warm the Orchard proving keys either.

## Readiness after onboarding

A new wallet is served the moment it is placed, before its account exists: importing needs tree
state below its birthday and waits for the shard's next connected pass. In that window its
balances and history are empty. Two fields say which state it is in:

- `imported` on [`waitforsync`](../rpc/blockchain.md#waitforsync): `false` until the wallet's
  account exists. `synced` is never true before it.
- `import_error` on `waitforsync` and [`getwalletinfo`](../rpc/wallet-addresses.md#getwalletinfo):
  present only when the import failed. It is terminal, so `waitforsync` returns immediately
  rather than waiting out its timeout.

A restart adopts every account already in its shard database rather than importing it again.

## Backup

`manifest_dir` holds viewing keys that exist nowhere else in zecd, and `createwallet` writes to
it at runtime. Back it up continuously, like `keys.toml`. It is the exception to the rule that
the data directory is a disposable cache (see [what to back up](operations.md#what-to-back-up)).

`dir` is a cache: delete it and the shards are rebuilt from the manifests plus a rescan. Put it
on scratch storage if that helps, and keep the manifests somewhere backed up.

## Embedding

An embedder reaches a fleet wallet's database through `Node::wallet_location`, the only
supported route to a shard directory. See [embedding](../library.md#reading-wallet-history).
