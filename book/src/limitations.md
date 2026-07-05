# Known limitations

Current limitations and their workarounds, plus the future work each one points at.
Intentional design boundaries (what zecd will never do) are on the [compatibility
boundary](compatibility.md) page; this page is about gaps that may close.

## listunspent outpoints are synthesized

Shielded notes are not bitcoin-style outpoints, so `listunspent` reports each unspent note
with a synthesized `(txid, vout)` identifying the shielded action that created it, and no
transparent `scriptPubKey`. The `address` field is the diversified address the note was
received on when recorded, and empty for change/internal notes. Treat the pair as a stable
opaque identifier for dedupe, not as something you can feed to transparent-UTXO tooling. See
[wallet history and unspent](rpc/wallet-history.md).

## Transparent spending is fully-transparent only

With [transparent support](guide/transparent.md) enabled, a transparent UTXO can be spent to
a transparent recipient with the change kept transparent, but only under the explicit
`AllowFullyTransparent` [privacy policy](design/privacy.md). Two directions are not
implemented:

- **No auto-shielding.** Received transparent UTXOs are not automatically shielded into
  Orchard, so a transparent receive cannot feed a shielded send. librustzcash's
  `propose_shielding` exists and wiring it into a caught-up sync pass is the planned path.
- **No mixed inputs.** Transparent UTXOs and shielded notes cannot fund a single send
  together.

Until then, treat transparent as a receive-only on-ramp (funds stay put until you spend them
transparently), or opt in to `AllowFullyTransparent` for t-to-t spends. Under the default
policy, a transparent-only wallet's `sendtoaddress`/`sendmany` returns `-6`.

## No transparent receive reconciliation pass

Transparent receive discovery is a forward-only block-scan matcher, bounded by which
addresses are exposed at scan time. A receive on an address exposed only after its funding
block was scanned (out-of-order funding within the gap, with a small `transparent_gap_limit`)
is missed until a from-seed rescan. The planned follow-up is a periodic reconciliation pass
that batches all exposed addresses into Zebra's always-on transparent address index
(`getaddressbalance`/`getaddressutxos`) to cross-check the scanned balance and backfill
anything missed, kept off the per-block hot path. Workaround today: set `[pools]
transparent_initial_scan` to your issuance high-water mark so the whole issued range is
pre-exposed before scanning, and size `transparent_gap_limit` to your maximum
outstanding-unfunded address count. See [transparent support](guide/transparent.md).

## One account per wallet

Each wallet surfaces exactly one ZIP-32 account (the first in its database);
multi-account-per-seed is not exposed, and Bitcoin Core's legacy string-account API is not
implemented. Workaround: use multiwallet. Each `[wallets.<name>]` entry is an independent
seed, database, and directory, addressed bitcoind-style at `POST /wallet/<name>` (see
[multiwallet routing](rpc/index.md)). Note the constraint that at most one loaded wallet may
hold spending keys; the rest must be [watch-only](guide/watch-only.md).

## Per-wallet send throughput is one actor

Sends to one wallet serialize on its single-writer actor (the `cs_wallet` analog), so
per-wallet throughput is one core's worth of Orchard proving. `[spend] pipeline_proving`
(default off) addresses the liveness half only: it runs a send's prove-and-sign off the
actor, so a long send no longer freezes background sync, reads of status, and mempool
processing for its whole duration. Sends still serialize (at most one uncommitted transaction
at a time), so it does not raise multi-send throughput. It engages only on the cached-Orchard
PCZT proving path (`cache_proving_key = true`, the default). True concurrent sends
(disjoint-note selection across in-flight sends) remain a design proposal in
`docs/CONCURRENT_SENDS.md`. Workaround: shard the hot float across multiple wallets; K actors
already overlap their proofs across cores with no shared state.

## No -rpcthreads worker pool

bitcoind processes RPC on a configurable thread pool (`-rpcthreads`, default 16) in front of
a bounded queue (`-rpcworkqueue`, default 64). zecd does not replicate the pool model;
requests run on the async runtime, and the `[rpc] work_queue` semaphore (default 100)
provides the same user-visible bound: beyond it the server returns HTTP 503 `Work queue depth
exceeded`, as bitcoind does when its queue fills. There is no thread-count knob to tune. See
[conventions and wire format](rpc/index.md).

## help introspection is a stub

`help` returns a static one-line summary and ignores its optional `command` argument, where
bitcoind lists every command and returns per-method usage for `help <method>`. Tooling that
discovers a node's surface by introspecting `help` gets nothing useful from zecd. Workaround:
the [method index](rpc/method-index.md) is the authoritative surface list, and probing a
method directly distinguishes implemented (any non-`-32601` response) from absent (`-32601`,
HTTP 404). One caveat: with an `[rpc] allowed_methods` safelist configured, a method blocked by
the safelist also returns `-32601`, so probing cannot tell a disabled method from an absent one
(the safelist deliberately discloses nothing about the surface it hides).

## PostgreSQL wallet backend is blocked upstream

The wallet store is SQLite only (`zcash_client_sqlite`). The one structural coupling blocking
an alternative backend is in reorg recovery: `perform_rewind` in `src/sync/engine.rs` must
match the concrete `SqliteClientError::RequestedRewindInvalid` error to retry a truncation at
a shallower bound, because `zcash_client_backend`'s `WalletWrite` trait has no portable
"rewind invalid" error contract. Until upstream grows one (the `TODO(upstream)` on
`perform_rewind` tracks it), a PostgreSQL `WalletDb` backend cannot be wired in without
losing correct reorg recovery. No workaround; scale reads via the WAL-mode short-lived read
connections zecd already uses (see [architecture](design/architecture.md)).
