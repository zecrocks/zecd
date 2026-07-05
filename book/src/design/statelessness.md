# Stateless & recoverable

zecd persists no off-chain data that a from-seed restore plus a full chain sync could not
rebuild. This page defines that invariant, explains why the wallet database is a cache rather
than authoritative state, and walks through its consequences: no labels, disposable data
directories, functional (not bitwise) recovery, and deterministic history across restores.

## The invariant

Everything zecd writes to disk is either recoverable from the seed and the chain, or a cache of
such data. The invariant is unconditional: there is no config flag, no side-table, and no way to
turn statefulness on. It is about *persistence*, not memory; transient in-memory caches are fine
(see the exceptions below), but nothing lands on disk that `zecd init --restore` followed by a
sync would not reproduce.

The practical payoff: a wallet's seed phrase (or, for a [watch-only wallet](../guide/watch-only.md),
its UFVK) is the complete backup. There is no wallet.dat to snapshot, no label store to export,
no dump/import cycle on migration.

## The wallet database is a cache

The on-disk state is the librustzcash wallet DB (`data.sqlite`). Every row in it is derivable:

- **Balances, notes, and transparent UTXOs** are rebuilt by re-scanning the chain: note
  trial-decryption with the account's viewing key for shielded funds, the block-scan
  transparent-output matcher for transparent ones.
- **Addresses** are re-derived from the seed. The shielded diversifier cursor (which index
  `getnewaddress` hands out next) is clock-derived, and the transparent gap chain is sequential;
  both are caches of on-chain-recoverable data. Any address that ever *received* funds is
  recovered from the note (or UTXO) itself during the scan, so payments to previously issued
  addresses are detected after a restore.
- An issued-but-never-funded address is simply forgotten on restore. For shielded addresses this
  is harmless (a later payment to it is still detected, because detection is by trial-decryption,
  not by address lookup). For transparent addresses it is bounded by the gap window; see below.

The one security-relevant exception in `data.sqlite` is *which account the daemon serves*:
`getnewaddress` derives from the DB account's UFVK, so a swapped or planted database would
silently divert deposits to a foreign key. zecd defends this by pinning the account's UFVK into
`keys.toml` at init and verifying the DB against the pin on every startup
(`wallet/binding.rs::verify_or_pin_account`); every seed exposure additionally verifies that the
seed derives the pinned UFVK. The pin itself is seed-derivable data (a UFVK is a function of the
seed), so it respects the invariant. Details in [key custody](../security/key-custody.md).

## Consequence: no labels

Address labels are the one kind of state with no on-chain source (they are supplied out-of-band)
that is also persistent by nature. zecd therefore keeps none:

- The five label-dedicated methods are removed from the dispatch table entirely. Calling
  `setlabel`, `getaddressesbylabel`, `listlabels`, `getreceivedbylabel`, or
  `listreceivedbylabel` returns method-not-found (`-32601`, HTTP 404), exactly like any unknown
  method.
- `getnewaddress` rejects a non-empty `label` argument with `-8`
  ("labels are not supported (zecd is stateless); call getnewaddress without a label").
- The embedded `label`/`labels` fields on the general history and address RPCs
  (`getaddressinfo`, `listtransactions`, `listsinceblock`, `gettransaction` details,
  `listreceivedbyaddress`) are retained for Bitcoin Core shape conformance but are always `""`
  or `[]`. A `listtransactions` label filter other than `"*"` or `""` therefore matches nothing.

Keep your address-to-customer mapping in your own database, where it belongs in a payment system
anyway.

## Consequence: disposable data directories

Because the datadir holds only caches (plus `keys.toml`, which holds the age-encrypted seed and
the UFVK pin), a zecd deployment can treat it as expendable. A container with no persistent
volume, rebuilt from the seed on each start, loses nothing an operator depends on; it just pays
the rescan cost. In practice you keep the datadir for speed and keep the seed as the backup.
Restore and rescan mechanics (including `--birthday` to bound the scan) are covered in
[operations](../guide/operations.md).

## Consequence: functional, not bitwise, recovery

A restore reproduces the wallet's *funds and history*, not its exact prior state:

- The sequence of addresses `getnewaddress` hands out is not reproduced. Shielded diversifier
  indexes are clock-derived (librustzcash starts at a Unix-time-based index and increments past
  collisions), so a restored instance issues different fresh addresses than the original would
  have. All of them belong to the same account, and any that get funded are recovered.
- **Track the addresses you hand out yourself.** zecd remembers an address only once it has
  received funds; an issued-but-unfunded address disappears from `listreceivedbyaddress`-style
  views after a restore. Keeping your own record of issued addresses avoids accidentally reusing
  one, which is a privacy/linkability leak, never a loss of funds. (`getaddressinfo.ismine`
  still resolves an unrecorded shielded address cryptographically via the viewing key, so you
  can always check whether an address is yours.)

## The transient exceptions (in-memory only)

Three pieces of state live only in memory. None are written to disk, none survive a restart, and
so none break the invariant:

| State | What it is | On restart |
|---|---|---|
| Tx first-seen times | Wall-clock stamp when the mempool stream first stores a pending tx (`wallet::FirstSeen`), surfaced as `time`/`timereceived` until a block time supersedes it | Rebuilt as the mempool stream re-observes still-pending txs; a mined tx uses its block time. A foreign unmined tx not yet re-observed reports `time` 0 until then |
| Async-operation registry | `z_sendmany` operation IDs and results ([async operations](../rpc/async-operations.md)) | Lost, matching zcashd's behavior; broadcast transactions are unaffected |
| Orchard proving key | `ProvingKeyCache`, built once at startup and shared across wallets | Rebuilt at startup (a pure performance cache) |

An unmined transaction has no block time yet; that is expected, not an off-chain gap, which is
why first-seen is the deliberate exception rather than a violation. The rule for future
development is the same: a transient in-memory cache is fine, but persisting anything the seed
cannot rebuild breaks the invariant and needs an explicit design decision.

## Recovery breadth: shielded vs transparent

Shielded funds are **unconditionally** recoverable from the seed. Detection is note
trial-decryption with the viewing key, which needs no prior knowledge of which addresses were
issued; every note the account ever received is found by scanning.

Transparent funds (opt-in, off by default) are recoverable only within the configured window:
a from-seed restore rediscovers a transparent receive only if its address index falls within
`transparent_gap_limit` of the last funded index, or is pre-exposed by
`transparent_initial_scan`. Transparent change consumes the internal gap chain under the same
limit. This is the standard HD-wallet gap limitation, made sharper by statelessness (zecd does
not persist an issued-address high-water mark for you). Sizing guidance and the full mechanism
are in the [transparent guide](../guide/transparent.md).

## Restore-deterministic outgoing history

A Unified Address can carry several receivers (one per pool), but a transaction pays exactly one
of them on-chain. The full multi-receiver UA you typed is sender-side metadata that never
reaches the chain: librustzcash caches it only on the instance that authored the send, and a
restore recovers only the single receiver actually paid.

Rather than show history that silently changes shape after a restore, zecd's history RPCs
(`listtransactions`, `gettransaction` details, `listsinceblock`, `z_listtransactions`) reduce
every **outgoing** output's address to that single paid receiver
(`address::single_receiver_for_pool`): a bare `t`/`zs` address, or a single-receiver UA for
Orchard (which has no standalone encoding). The reduction is idempotent, so a bare or
single-receiver recipient displays as itself, and it applies only to outgoing outputs; received
and self-transfer entries keep your own recorded address. The result is history that is
identical on the authoring instance and after a restore, where zcashd echoes the
stored UA on the authoring instance and degrades to the single receiver after a restore.

The trade-off: to match a payment back to a multi-receiver UA you issued, deconstruct that UA
into its per-pool receivers and compare against the displayed receiver. zecd keeps no
recipient-side mapping itself, consistent with everything above.
