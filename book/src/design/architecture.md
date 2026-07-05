# Architecture

How zecd is put together: a per-wallet single-writer actor that owns the wallet database, a
read path that bypasses it, a sync engine sliced into batches so the actor stays responsive,
and the background loops (enhancement, mempool, rebroadcast) that hang off the sync loop.
The [Zebra backend](zebra-backend.md) and [statelessness](statelessness.md) pages cover the
upstream interface and the persistence invariant separately.

## Component diagram

```
 RPC client (python-bitcoinrpc, curl, ...)
      |
      v  HTTP Basic / cookie auth
+---------------------------+        +------------------+
| axum RPC server           |        | health server    |
| auth gate -> work-queue   |        | /healthz /readyz |
| semaphore -> dispatch     |        | /status          |
+------------+--------------+        +---------^--------+
             |                                 | SyncStatus (watch channel)
     per-wallet WalletHandle                   |
      |                   |                    |
      | reads             | writes             |
      v                   v                    |
+-----------------+   mpsc command channel     |
| short-lived     |   (oneshot reply each)     |
| SQLite conns    |          |                 |
| (WAL snapshots) |          v                 |
+--------+--------+   +------+----------------------+
         |            | WalletActor (single writer) |
         |            |  owns WalletDb (data.sqlite)|
         +----------->|  sync loop / enhance /      |
           same DB    |  mempool / rebroadcast /    |
           file       |  sends (prove + broadcast)  |
                      +------+----------------------+
                             |  ChainSource (AnySource -> ZebraSource)
                             v
                       zebrad JSON-RPC (zebra://host:port)
```

## The single-writer actor

`zcash_client_sqlite::WalletDb` is `Send` but not `Sync`, and wallet writes (note selection,
scan application, stores) must not interleave. zecd therefore gives each configured wallet one
actor task (`src/wallet/actor.rs`) that owns the `WalletDb` and is the only writer. It is the
analog of Bitcoin Core's `cs_wallet` mutex (`src/wallet/wallet.h` in the Core tree): every
state-changing operation serializes through one queue, so two concurrent `sendtoaddress` calls
cannot select the same notes and double-spend. The actor also runs the background sync loop,
so scans and sends contend for the same writer by construction.

RPC handlers talk to the actor through a clonable `WalletHandle` over a bounded tokio `mpsc`
channel (capacity 64); each `WalletCommand` carries a `oneshot` reply sender the handler
awaits. The command set is small: `GetNewAddress`, `GetAddressForAccount`, `Send`, `GetRawTx`,
`Broadcast`, `Unlock`, `Lock`. Everything else is a read.

Read-only RPCs (`getbalance`, `listtransactions`, `listunspent`, `getwalletinfo`, ...) never
enter the queue. The wallet DB runs in WAL mode, so `src/wallet/read.rs` serves them from
short-lived read connections with consistent snapshots. Reads keep working during a long scan
or proof, and a wedged writer cannot block balance queries. Two more things bypass the queue
deliberately: sync state is published on a `watch` channel (`SyncStatus`), read lock-free by
the blockchain RPCs and the health server; and `walletlock` zeroizes the shared seed directly
from the handle, so the seed does not linger behind a queued long send.

Command handling and mempool ingestion are panic-isolated (`catch_unwind`): a poison
transaction or a librustzcash edge case fails that one command instead of killing the actor,
which would silently stop all writes while reads kept answering.

The actor's main loop, in order per pass: drain any finished pipelined sends, drain all queued
commands (writers are never starved by sync), then run one sync batch. When the batch reports
no more work (caught up), it runs the rebroadcast pass, one enhancement batch, and (re)opens
the mempool subscription. Idle, it sits in a `select!` over shutdown, commands, send
completions, the relock deadline, the poll tick (`[sync] interval_secs`, default 20), and the
mempool stream.

## The sync engine

`src/sync/engine.rs` is the compact-block scan loop, ported from zcash-devtool and refactored
into a one-batch-per-call driver: `sync_one_batch` downloads and scans up to 10,000 compact
blocks, then returns to the actor loop so queued commands run between batches. A monolithic
run-until-caught-up loop (librustzcash ships one behind its `sync` feature) would hold the
writer for the whole initial sync; it also leaves the `RequestedRewindInvalid` reorg case
unhandled, which is why zecd keeps its own driver.

Reorg detection is librustzcash's (a continuity error from `scan_cached_blocks`); recovery is
caller-side by upstream design. zecd's `perform_rewind` truncates below the conflict and
retries at a shallower height when the requested rewind is invalid, so young wallets survive
reorgs near their birthday. Compact blocks themselves are derived from full zebrad blocks; see
[the Zebra backend](zebra-backend.md). For transparent-enabled wallets the same pass matches
each scanned block's transparent outputs against the wallet's exposed-address set; see
[transparent support](../guide/transparent.md).

## Transaction enhancement

Compact blocks carry no memos and no full transaction data, so the block scan records a
received note with a NULL memo. `enhance_step` backfills this by servicing librustzcash's
`transaction_data_requests`: for each request it fetches the full transaction from zebrad and
runs `decrypt_and_store_transaction`, recovering received memos and (via the sender's OVK) the
wallet's own outgoing memos. Without it, any transaction the wallet only ever saw as a compact
block (every receive during initial sync or a restore) would never show its memo.

On a from-birthday restore the backlog is one upstream fetch per transaction: potentially tens
of thousands of requests, hours of work after the block scan already reached the tip. So
`enhance_step` is bounded like the scan: at most 16 requests per call (`ENHANCE_BATCH`), with
commands serviced and the shrinking backlog republished between batches. The count rides on
`SyncStatus.pending_enhancements` and is an observable readiness signal: while it is non-zero
the wallet reports `getwalletinfo.scanning: true`, `/readyz` returns 503 with
`reason: "enhancing"` in synced mode, and `/status` shows the number. "Scanned to tip" is not
"ready to serve full history"; see [operations](../guide/operations.md) for monitoring it.

## Mempool poller (0-conf)

Once caught up, the actor subscribes to the upstream mempool stream: a 2-second
`getrawmempool` poller that closes itself when `getbestblockhash` changes, which doubles as
the "new block, sync now" signal. Every mempool transaction is processed twice over: it is
trial-decrypted against the wallet's keys (`decrypt_and_store_transaction` is a no-op for
unrelated transactions), and its transparent outputs are matched against the exposed-address
set. Incoming payments of either kind therefore appear at 0 conf in `getunconfirmedbalance`,
`listtransactions`, and `listunspent minconf=0`, as in bitcoind. The subscription is
best-effort: a stream error just drops it until the next caught-up pass. The actor also stamps
a transient in-memory first-seen time for unmined transactions here (surfaced as
`time`/`timereceived`); it is never persisted, per [the statelessness
invariant](statelessness.md).

## Rebroadcast loop

On caught-up passes, at most once per `[sync] rebroadcast_secs` (default 60), the actor
re-submits wallet transactions that are still unmined and unexpired. Only transactions that
spend this wallet's own notes or UTXOs qualify: nobody else can spend them, so they were
necessarily authored here, and foreign unmined transactions the mempool stream stored are the
sender's to retransmit. A node that already holds the transaction rejects the duplicate, which
is logged at debug and harmless. This is what makes `sendtoaddress` safe to return a txid even
when the initial relay fails: the inputs are locked in the DB until expiry and the loop keeps
retrying.

## The spend path

All sends (`sendtoaddress`, `sendmany`, `z_sendmany`) funnel through the actor's `do_send`.
Three details matter to operators:

**`sync_to_tip_for_send`.** librustzcash sets a transaction's target height (and thus its
expiry) and its spend anchor from the wallet DB's recorded chain tip. If the sync loop has
starved under load, that tip can lag Zebra's real tip past the expiry delta, and the send is
rejected upstream as already expired (`-25`, intermittently). Bumping only the tip pointer is
worse: the anchor then falls in an unscanned range and `get_wallet_summary` zeroes the entire
shielded balance, turning the failure into `-6` ("0 spendable"). So before building, `do_send`
refreshes the tip and drives `sync_step` until the tip captured at entry is scanned. Normally
a no-op; best-effort (an unreachable upstream falls back to the last-scanned height).

**Cached Orchard proving key.** With `[spend] cache_proving_key` (on by default), sends run
through the PCZT roles with an `orchard::circuit::ProvingKey` built once in `daemon::run` and
shared by `Arc` across all actors. The fused librustzcash path (flag off) rebuilds the proving
key inline on every transaction, about 4.5 s of key generation single-threaded (on the order
of 1 s on a fast multicore node). Analysis and benchmarks: `docs/PROVING_KEY_CACHE.md` in the
repo. Proving runs under `tokio::task::block_in_place`, so it does not stall the async
runtime, but it does hold the actor.

**`[spend] pipeline_proving` (default off).** By default the whole send (select, build, prove,
sign, store, broadcast) runs on the actor, so a long proof freezes background sync for its
duration. With pipelining on, the send splits: phase A (note selection + PCZT build, a
milliseconds-scale DB read) stays on the actor, phase B (prove + sign) runs on a blocking
thread, and phase C (extract + store + broadcast) returns to the actor. Sends still serialize:
only one PCZT is ever uncommitted, so there is no double-spend surface; a send arriving
mid-proof queues (up to 64, then `-4` back-pressure) and starts when the in-flight one
commits. It improves liveness, not multi-send throughput. Engages only on the cached-Orchard
PCZT path. Every send logs a phase profile (select+build / prove+sign / store / broadcast
milliseconds plus input and action counts).

## Datadir lock

The single-writer invariant holds within one process; a second zecd on the same datadir would
still corrupt the wallet DB. `src/lock.rs` takes an exclusive advisory lock on
`<datadir>/.lock` (via `fmutex`, as zcashd does). `zecd` (the daemon) and `zecd init`
take it and hold it for their lifetime; a second writer fails to start with "Cannot lock data
directory ... Another zecd is already running". `zecd rpcauth` (no datadir access) and
`zecd export-ufvk` (read-only) deliberately do not take it, so the UFVK stays exportable while
the daemon runs.

## Module map

| Module (`src/`) | What lives there |
|---|---|
| `main.rs`, `daemon.rs` | CLI shim; wiring: datadir lock, proving-key build, actor spawn, RPC + health servers, shutdown |
| `config.rs`, `pools.rs` | TOML + CLI resolution; pool sets and receiver selection (see [configuration](../configuration.md)) |
| `server/` | axum router, Basic/cookie auth, work-queue semaphore, JSON-RPC 1.0 framing |
| `rpc/` | dispatch table and method handlers (see the [RPC reference](../rpc/index.md)) |
| `wallet/mod.rs` | `WalletHandle`, `WalletCommand`, `SyncStatus`, the multiwallet registry |
| `wallet/actor.rs` | the single-writer actor: sync/enhance/mempool/rebroadcast loops, sends, proving |
| `wallet/read.rs` | read-only queries over short-lived WAL connections |
| `wallet/open.rs`, `store.rs`, `keys.rs`, `binding.rs` | DB open/init + WAL, `keys.toml`, seed custody, account-to-keys binding |
| `chain/` | the `ChainSource` trait and `ZebraSource` (see [Zebra backend](zebra-backend.md)) |
| `sync/engine.rs` | one-batch-per-call scan driver, reorg recovery, block-cache cleanup |
| `operations.rs` | the async-operation registry behind [`z_sendmany`](../rpc/async-operations.md) |
| `health.rs` | `/healthz`, `/readyz`, `/status` on a separate port |
| `error.rs`, `amount.rs`, `address.rs` | Bitcoin Core error codes + HTTP mapping; exact fixed-point amounts; address parsing |
| `lock.rs`, `hardening.rs`, `backoff.rs`, `state.rs` | datadir lock; core-dump/mlock hardening; reconnect backoff; `AppState` |
