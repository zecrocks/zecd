# Operations runbook

Running zecd on mainnet: what to back up, how to restore, what to monitor, how sends behave
under failure, and how to upgrade. For getting the stack up in the first place, see
[Deployment](deployment.md); for config keys, see the [configuration reference](../configuration.md).

## What to back up

Funds are recoverable from the mnemonic alone. Everything else is convenience.

| Artifact | Where | What it protects |
|---|---|---|
| 24-word mnemonic | shown once by `zecd init` | The funds. Record offline (paper/HSM). Loss of the server without it is loss of funds. |
| Birthday height | inside `keys.toml`; also record it with the mnemonic | Makes a from-seed restore fast. Any height at or before the wallet's first transaction works. |
| `keys.toml` | `<wallet dir>/keys.toml`, or wherever `keys_file` points | The age-encrypted mnemonic plus network and birthday. Useless without the identity; pair the two for a full server restore. This is the file you ship as a Secret. |
| `identity.txt` (age identity) | `[keys] age_identity`, default `<datadir>/identity.txt` | Decrypts `keys.toml`. This is spend authority. Store its backup separately from `keys.toml` backups. |

Do not back up `data.sqlite` or `blocks/` (since 0.7.0 both live under
`<wallet dir>/zec/lrz/`; see [wallet data layout](#wallet-data-layout)). They are caches
derived from the chain: zecd is
[stateless](../design/statelessness.md), so with the mnemonic (and birthday) the whole data
directory can be recreated. Shielded funds are unconditionally recoverable from seed;
transparent funds only within the gap-limit / initial-scan window (see
[Transparent support](transparent.md)).

## Minimal runtime file set

Per wallet directory `<dir>`:

| Path | Role | Ship it? |
|---|---|---|
| `<dir>/keys.toml` | Secret: encrypted seed + birthday/network | Yes. Mount as a Secret; relocate with `keys_file` / `ZECD_KEYS_FILE`. |
| `identity.txt` | Secret: decrypts the seed (spend authority) | Yes, if auto-unlocking. Mount as a Secret (`ZECD_AGE_IDENTITY`). |
| `<dir>/zec/lrz/data.sqlite` (+ `-wal`/`-shm`) | Cache: account, scan progress, balances, history. Rebuilt from `keys.toml` plus a rescan. | No. |
| `<dir>/zec/lrz/blockmeta.sqlite` (+ sidecars) | Cache: block metadata. | No. |
| `<dir>/zec/lrz/blocks/` | Cache: downloaded compact blocks. Can grow large; fully re-derivable. | No. Exclude from every snapshot. |
| `<datadir>/.cookie` | Ephemeral RPC cookie, minted at startup, removed on clean shutdown | No. |

Keep secrets out of the TOML (which typically lives in a ConfigMap):

- RPC password: `ZECD_RPC_PASSWORD`, `--rpcpassword`, or `[rpc] password_file`
  (flag/env > `password_file` > inline `password`). Prefer the env var or `password_file`:
  a password on the command line is visible to any local user via `ps`, and zecd warns at
  startup when it is passed that way.
- `keys.toml` location: `ZECD_KEYS_FILE` / `--keys-file` / `[keys] keys_file` (per-wallet
  `[wallets.<name>] keys_file`).
- age identity: `ZECD_AGE_IDENTITY` / `--age-identity` / `[keys] age_identity`.

## Wallet data layout

Since 0.7.0 a wallet directory nests its derived state one coin and one engine deep:

```text
<datadir>/<wallet>/keys.toml                                    <- the seed. Stays at the root.
<datadir>/<wallet>/zec/lrz/data.sqlite
<datadir>/<wallet>/zec/lrz/blockmeta.sqlite
<datadir>/<wallet>/zec/lrz/blocks/
```

Before 0.7.0 all of these sat flat in the wallet directory together.

The split follows what can be rebuilt from what. `keys.toml` wraps a BIP-39 seed that serves
every coin and that nothing on any chain can reconstruct, so it stays at the top. Everything
below it is derived state, namespaced first by the coin that owns it and then by the library
that wrote it, so a second coin gets a sibling directory rather than a share of one flat
namespace, and replacing the storage library becomes a sibling directory plus a rescan.

### The migration

**Existing wallets migrate themselves on first start. No configuration changes**, including for
a wallet with an explicit `dir`. What it guarantees:

- It runs under the datadir lock, before anything opens a wallet, and also at `zecd init` and
  `zecd rescan`.
- Artifacts are **renamed** within the wallet directory, never copied, so no free disk space is
  needed and nothing is deleted.
- The SQLite `-wal` and `-shm` sidecars travel with their databases. A `-wal` holds committed
  transactions not yet checkpointed back, so moving a database without it would silently
  discard the most recent writes.
- An interrupted run resumes: the next start moves whatever is left.
- **A failure is fatal by design.** It is not a silent fallback to rebuilding an empty
  database, because that would look like a working daemon with a wallet that has lost its
  history. The one case it cannot resolve on its own is an error leaving copies in both places,
  which it reports for an operator to settle.

Take the usual datadir backup before the upgrade anyway. The worst case is a from-seed restore,
not lost funds, but a restore costs a scan.

`zecd config check` reports a pending move as a warning and the both-places state as an error,
so an upgrade can be dry-run against a live deployment before anything is stopped.

Read-only commands take no datadir lock and therefore cannot migrate. `zecd export-ufvk` reads
an un-migrated wallet database where it lies; `zecd derive-address` needs no fallback at all,
since it reads only `keys.toml`, which the migration never moves.

### If you compute these paths yourself

Backup scripts, log shippers, and volume mounts that hard-code `<wallet>/data.sqlite` need
updating to `<wallet>/zec/lrz/data.sqlite`. The exclusion advice above is unchanged in
substance: exclude the engine directory, keep `keys.toml`.

Embedders must use `config::engine_dir` or `config::WalletEntry::engine_dir` rather than joining
the components by hand, since the layout is versioned by coin and engine. See
[embedding](../library.md#reading-wallet-history).

## Restore procedures

### Server restore (you have `keys.toml` + `identity.txt`)

Put both files back at their configured paths and start the daemon. With
`[keys] bootstrap_from_keys` (default `true`), an empty data directory next to a present
`keys.toml` is rebuilt automatically on boot: zecd recreates the account from the seed and
rescans from the stored birthday. No `init` needed. This is the disposable-datadir pattern:
mount one Secret, start with an empty volume.

When the rebuild runs depends on the custody model:

- Identity / `auto_unlock`: the seed decrypts at startup, so the rebuild runs as soon as
  Zebra is reachable. No human action.
- Encrypted (`init --encrypt`): the wallet starts locked with no account yet; address and
  spend RPCs return "account is not ready", and `/status` reports `locked: true`. The rebuild
  runs at the first `walletpassphrase`, after which the wallet syncs (and stays synced while
  locked). zecd probes datadir writability when it loads the wallet, so a read-only datadir
  fails at startup rather than at unlock time.
- Watch-only (`--ufvk`): no seed, not covered by bootstrap. Recreate with
  `zecd init --ufvk` against an empty datadir (see [Watch-only wallets](watch-only.md)).

Set `bootstrap_from_keys = false` to fail fast on an empty datadir instead.

### From-seed restore (you have only the mnemonic)

```sh
zecd init --datadir /var/lib/zecd --restore --birthday <height>
# paste the mnemonic when prompted
```

Always pass `--birthday` (any height at or before the wallet's first transaction). Without
it, the restore scans from the activation height of the wallet's earliest enabled pool
(Orchard/NU5 for the default Orchard-only config, Sapling activation when Sapling is
enabled): safe (it can never miss notes) but slow on mainnet. History reappears as the scan
progresses; do not trust balances until the scan and enhancement backlog finish (`"synced"`
readiness, which is the default, or `/status` showing `fully_scanned` at the tip and
`pending_enhancements` 0. The looser `"scanned"` and `"connected"` modes report ready before
that point.)

Non-interactive restore: set `ZECD_MNEMONIC`, or pass `--mnemonic-file <path>`
(`ZECD_MNEMONIC` takes precedence; stdin is the fallback). For `init --encrypt`, set
`ZECD_WALLET_PASSPHRASE` instead of answering the prompt.

### Watch-only replica

Export the viewing key on the spending host with `zecd export-ufvk`, then
`zecd init --ufvk "uview1..." --birthday <height>` on the replica. A watch-only wallet is
fully reconstructable from UFVK + birthday; record both. The UFVK cannot spend but reveals
the wallet's entire transaction graph, so treat it as confidential.

## Monitoring and alerting

zecd serves unauthenticated probes on a separate port (default 9233) when `[health] enabled`
(the default):

| Endpoint | Semantics |
|---|---|
| `GET /healthz` | Liveness. `200 ok` while the process runs. |
| `GET /readyz` | Readiness, 200/503, gated by `[health] readiness`. |
| `GET /status` | JSON snapshot: per-wallet sync state, active upstream endpoint, `conn_state` (`down` \| `syncing` \| `ready`), `pending_enhancements`, `locked`. |

Readiness modes, strictest first:

- `"synced"` (default): ready only once every wallet is connected, within `[health]
  max_scan_lag` blocks of the tip (default 4), and with an empty enhancement backlog. A
  from-birthday restore stays not-ready until it has scanned to its own funds and finished
  backfilling memos.
- `"scanned"` (new in 0.6.4): connected and within `max_scan_lag` of the tip, without the
  empty-backlog term. Balances and note spendability come from the block scan and are
  current in this state; only history completeness lags. Choose it for a deployment that
  sends regularly from a wallet holding many transparent UTXOs, where the strict mode's
  backlog term flaps readiness after routine sends (see below).
- `"connected"`: ready once the backend is connected and its tip is past the wallet's
  birthday. Does not wait for the scan at all, so readiness never flaps during a long
  catch-up; reads may lag the tip arbitrarily.

A 503 body carries a `reason`. Route alerts on it:

| `reason` | Meaning | Action |
|---|---|---|
| `upstream_down` | Zebra unreachable | Page someone. |
| `actor_down` | A wallet's writer actor died | Restart the process. |
| `enhancing` | Scanned to tip, still backfilling memos (`"synced"` mode only; `"scanned"` and `"connected"` stay ready) | Wait; watch `pending_enhancements` trend to zero. If it recurs after ordinary sends rather than after a restore, see the note below. |
| `syncing` | Normal block catch-up | Wait. |

**"Scanned to tip" is not "ready".** Compact blocks carry no memos, so after the block scan
catches up, an enhancement pass fetches each transaction's full data from Zebra and decrypts
it to backfill memos. On a from-birthday restore of a busy wallet that is one fetch + decrypt
per transaction, potentially hours of work after `scan_progress` hits `1.0`. While the
backlog drains, `conn_state` stays `syncing`, `getwalletinfo.scanning` and
`getblockchaininfo.initialblockdownload` stay truthy, and `"synced"` readiness holds 503 with
`reason="enhancing"`. Watch `/status` `pending_enhancements`; if it drains slowly, check that
Zebra's `getrawtransaction` is fast.

> **The backlog is not restore-only.** A wallet holding many transparent UTXOs re-emits its
> recurring spend-search requests every time the chain tip advances past an unspent output's
> observed height, so `pending_enhancements` rises transiently after ordinary sends and new
> blocks, in steady state, on a wallet that has been synced for weeks. Under the default
> `"synced"` readiness that is enough to answer 503 with `reason="enhancing"` for as long as
> the drain takes, which on a busy address is long enough for an orchestrator to pull the
> node out of its service while every balance RPC is answering correctly.
>
> If you see readiness flapping after sends rather than after a restore, that is this, and
> `readiness = "scanned"` is the answer: it keeps the height gate and drops the backlog term,
> so a node that is scanned to the tip stays in rotation while memos land behind it. Clamp
> any consumer that needs complete history to `pending_enhancements` reaching zero rather
> than to readiness.
>
> **Fixed in 0.6.4**, separately from the mode: the backlog count previously included
> duplicate requests, several thousand of them on a wallet with a reused transparent address,
> because the upstream query that generates them matched on transaction id alone. A count in
> the tens of thousands on such a wallet was mostly an artifact. `pending_enhancements` now
> reports distinct outstanding requests, so figures from 0.6.3 and earlier are not comparable
> with figures from 0.6.4.

**Bounding history completeness precisely.** Since 0.7.0,
[`getwalletinfo`](../rpc/wallet-addresses.md#getwalletinfo) reports a top-level
`enhanced_through` height, and `pending_enhancements` appears inside its `scanning` object. That
matters for two readers the health server does not serve: a library consumer running with
`default-features = false` has no health port at all, and anyone driving zecd purely over
JSON-RPC previously had to run one just for this number.

`enhanced_through` is the height below which history is complete, so a consumer replaying wallet
history as a log clamps its cursor to it rather than to readiness. It is `null` when not
currently determinable, which must be read as **hold the cursor**, never as "everything is
enhanced".

[`waitforsync`](../rpc/blockchain.md#waitforsync) (also 0.7.0) blocks until both the scan and
the backlog are done and returns all of these in one object, which is usually what a restore
script wants instead of a poll loop.

`locked` (top-level on both `/readyz` and `/status`, plus per-wallet) is `true` when a
passphrase-encrypted wallet needs a `walletpassphrase` before it can spend. It is reported
independently of readiness (a locked wallet can be `ready: true`), so a controller can drive
an unlock without mistaking it for a sync stall.

For load visibility, `getrpcinfo` returns `active_commands`: one entry per executing call
with `method` and `duration` (microseconds).

Logs: set `[log] format = "json"` for aggregation (Loki/CloudWatch/Elastic). Every RPC call
logs `method`, `wallet`, `elapsed_ms` (`debug` on success; errors log at `info` and add
`code`/`message`). Sync and connection lifecycle events log at `info`; connection failures at
`warn`.

Suggested alerts:

- `/readyz` 503 with `reason=upstream_down` for more than 5 minutes.
- `/status` sync lag (chain tip minus scanned height) not shrinking for 30 minutes.
- Sustained HTTP 503 from the RPC port (work queue exhausted).
- Daemon restarts.

The health server starts after wallets load, so cover prover init at boot with a
`startupProbe` / `initialDelaySeconds`. The port is unauthenticated by design and exposes
sync status only; keep it off the public internet anyway.

## Structured logging

Reworked in 0.7.0. Text output looks much as it did; JSON output (`[log] format = "json"`) is
now queryable without matching on message strings.

**Context lives on spans, not in prose.** Everything emitted while an RPC is handled, the
sanitized error detail lines included, is attributed to that call's method and wallet through an
`rpc` span. Every event from a wallet's actor carries the wallet name as a real field on a
`wallet` span, rather than a `[name]` prefix pasted onto the message text.

**Numbers are fields.** Durations, counts, and the rates on the send profile, the scan batches,
and the periodic heartbeats used to be baked into sentences. They are now fields you can
aggregate on.

### The `zecd::audit` target

A stable tracing target carries the security-relevant events, so an operator routes them to a
separate sink with a one-line filter instead of matching on message text:

- the RPC authentication mode chosen at startup, and per-request outcomes;
- the account-to-keys binding pin;
- seed unlock and relock, including the `walletpassphrase` timeout auto-lock;
- transparent issuance past the recovery horizon;
- every process-hardening step that was a no-op or was opted out of;
- the loaded spending wallets, when
  [`allow_multiple_spending_wallets`](../configuration.md#keys) is on.

Route it with a `RUST_LOG` directive, which overrides `[log] level` entirely when set:

```sh
RUST_LOG='warn,zecd::audit=info'     # audit trail only, plus real problems
```

### Two log levels moved

Both changes reduce steady-state volume, and both are worth knowing before you write an alert
on the old behaviour:

- **Per-request authentication success dropped from INFO to DEBUG**, removing one line per
  authenticated request. Failures stay at WARN.
- **Reconnect attempts during an upstream outage no longer stream WARNs.** The first failure
  warns and names the demotion; the paced retries after it log at DEBUG with their attempt
  number and delay. An alert that counted reconnect WARNs will now fire once per outage rather
  than continuously, which is the intent.

New TRACE events exist for one-per-downloaded-block and one-per-serviced-transaction-data
request. They are off unless asked for, and are verbose enough that you want a narrow filter.

### Startup and shutdown

One identifying line is logged at startup with the version, network, datadir, and upstream,
which nothing did before. Shutdown warns when async operations are still unfinished.

## Send semantics under failure

See [Sending](../rpc/sending.md) for the RPC surface; this is the operational contract.

- `sendtoaddress` and `sendmany` are synchronous and compute Orchard proofs, so a call holds
  the HTTP connection for a few seconds plus any queueing behind other sends (sends serialize
  per wallet). Set client-side send timeouts well above that. (`z_sendmany` returns an
  operation id immediately; see [async operations](../rpc/async-operations.md).)
- **A client timeout is not a failure.** The send may still complete on the server. Retrying
  a send that actually succeeded pays twice, exactly as with bitcoind, but the longer proving
  window makes it likelier. On timeout, reconcile with `listtransactions` (or
  `gettransaction`) before retrying.
- A send whose initial broadcast fails in transport still returns the txid. The transaction
  is already committed to the wallet, its inputs are locked, and the rebroadcast loop
  re-submits it (at most once per `[sync] rebroadcast_secs`, default 60) while it is unmined
  and unexpired. Never retry a send that returned a txid.
- Only an explicit upstream rejection (Zebra examined the tx and refused it) errors, with
  `-26`. The tx's notes stay locked until its expiry height, then become spendable again; an
  immediate retry fails with `-6` rather than double-paying.
- An expired unmined tx reports `confirmations: -1` and `abandoned: true`. Treat it as failed
  and safe to re-send.
- Rapid back-to-back sends exhaust spendable notes and return `-6` until change confirms
  (freshly created shielded change is not spendable unmined). The `-6` message appends any
  balance awaiting confirmations, so "retry after the next block" is distinguishable from
  "the wallet needs funding".

## Reorgs

zecd follows reorgs automatically: the scanner detects the fork, rewinds, and rescans the
replacement chain. Transactions in reorged-away blocks revert to unconfirmed
(`confirmations: 0`) until re-mined; confirmation thresholds keep doing their job. One
operator-visible consequence: a `listsinceblock` cursor pointing at a reorged-away block
returns `-5 Block not found` (zecd keeps no stale-header history to walk back through, unlike
bitcoind). Treat `-5` as "cursor invalid": re-baseline with a parameterless `listsinceblock`,
dedupe by txid, and store the fresh `lastblock`. See
[Wallet: history & unspent](../rpc/wallet-history.md).

## Recovering a stuck sync

A sync that fails, retries, and fails again on the same block is reported with the cause
rather than left as a bare error. There are two shapes, and they need different responses.

**An unsupported network upgrade.** At every connect zecd compares the upgrades the node
reports against the consensus rules the build knows. An unknown *pending* upgrade logs a
warning ahead of its activation height, which is your notice to upgrade zecd before then. An
unknown *active* one logs an error naming it, and sync failures under it are attributed to
the outdated build. The fix is to upgrade zecd; if you are already on the latest release,
report it at <https://forum.zcashcommunity.com>.

**A wallet database that cannot apply otherwise-valid blocks.** If the upstream is serving
blocks and the failure is in applying them (a commitment-tree conflict, say), no amount of
retrying or upgrading will clear it, because the damage is local. Rebuild the database:

```sh
# Stop the daemon first: rescan takes the datadir lock and will refuse otherwise.
zecd --datadir ./data rescan --wallet default
```

That deletes the wallet database only. `keys.toml` and the seed are kept, and the next start
recreates the account from the seed and rescans from the wallet birthday, re-deriving every
balance and all history from the chain. Nothing is lost that a seed restore could not rebuild,
which is the same guarantee described in [Stateless & recoverable](../design/statelessness.md);
the cost is the rescan time. Pass `--yes` to skip the confirmation prompt in automated
recovery.

## Slow sends on a busy transparent address

A wallet holding many unspent outputs on a *reused* transparent address could see an ordinary
`sendtoaddress` block for a minute or more before answering, sometimes only to report
insufficient funds. Through 0.6.3 the cause was the spend-search path: the wallet asks the
chain for transactions involving an address once per unspent output it holds, which is how a
spend authored elsewhere gets noticed, but the address index answers each request with every
transaction in the range rather than only the unseen ones, and all of them were fetched and
re-stored. That work runs on the wallet's single writer, so it starved every command queued
behind it. Measured against an address paid in every block, a send waited 109 seconds.

**Fixed in 0.6.4**, which skips transactions already recorded as mined. Nothing about the
configuration changes and no action is needed beyond upgrading. It matters most to deposit
and payout addresses, which are exactly the ones that accumulate outputs on a single address.

If sends are still slow after upgrading, the cause is elsewhere: check that the node's
`getrawtransaction` is fast (the same dependency the enhancement backlog has), and check
`/status` for a wallet still catching up.

## Upgrades

1. **Check the new binary against your existing config, before stopping anything.**
   `zecd config check` resolves the file with the exact build you are about to deploy and
   exits non-zero if that build would refuse it. It takes no datadir lock and writes nothing,
   so it is safe to run against a live deployment:

   ```sh
   ./zecd-new config check --conf /etc/zecd/zecd.toml
   ```

   This matters because zecd rejects unknown config keys. That is what stops a typo'd knob
   from being silently ignored, but it also means a config valid for one build can be refused
   by another **in either direction**: an upgrade may not know a key yet, a rollback may have
   dropped one. Catching that here turns a failed restart into a no-op.

2. **Diff the effective configuration** to see which *defaults* the upgrade moves. Your file
   is only half the configuration; every key it leaves unset takes the binary's default:

   ```sh
   diff <(./zecd-old config show --conf /etc/zecd/zecd.toml 2>/dev/null) \
        <(./zecd-new config show --conf /etc/zecd/zecd.toml 2>/dev/null)
   ```

   To pin today's behaviour explicitly before upgrading, capture
   `zecd-old config show > effective.toml` and deploy that: it is round-trippable TOML that
   zecd itself accepts. (Secrets come out as commented-out key names, so a captured file needs
   its credentials re-added.)

3. Stop with SIGINT or SIGTERM (both are graceful: in-flight requests finish, new ones get
   503). The `stop` RPC is regtest-only, so a stray RPC call cannot take down a production
   daemon.
4. Replace the binary or pull the new image.
5. Start. Wallet DB migrations run automatically at open; the first start after a large
   librustzcash bump can take longer.

**Upgrading onto 0.7.0 specifically**, the first start also moves each wallet's databases into
a per-coin subdirectory. It is automatic and needs no configuration change, but read
[wallet data layout](#wallet-data-layout) first: a failure there is deliberately fatal rather
than a silent rebuild, and any backup script or volume mount that names `<wallet>/data.sqlite`
by hand needs its path updated. Step 1's `config check` reports a pending move as a warning, so
the dry run tells you it is coming.

Downgrades across DB migrations are not supported. If you need a rollback path, stop the
daemon and snapshot the datadir first. The worst case of a lost datadir is a from-seed
restore, not lost funds.

Steps 1 and 2 need zecd 0.6.0 or later on the *new* side; `config show` on the old side only
works if the old binary is also 0.6.0+, so the first upgrade onto 0.6.0 has nothing to diff
against.

## Single-instance datadir lock

zecd takes an exclusive advisory lock on `<datadir>/.lock` while it owns the data directory
(the daemon for its whole lifetime, `zecd init` for the init). A second `zecd run` or
`zecd init` on the same datadir fails fast with `Cannot lock data directory ...`. The lock is
an OS advisory lock the kernel releases when the process exits, including a crash or kill, so
there is never a stale lockfile to delete: if the error appears and no zecd is running, just
retry. Several commands are exempt because they never write the datadir: `zecd export-ufvk`
(read-only DB access, so you can export a UFVK while the daemon runs), `zecd rpcauth`, and,
since 0.6.0, `zecd derive-address`, `zecd config check` and `zecd config show`. Since 0.7.0
`zecd chain-info` and `zecd licenses` join them: `chain-info` opens no wallet database and
writes no cookie file, and `licenses` never reaches a datadir at all. All of them are safe to
run against a live deployment. `config check` deliberately does not mint a cookie
file either, which would otherwise invalidate the credential a running daemon already handed
out.

## Mainnet checklist

- [ ] `zecd config check --conf <file> --strict` passes against the exact binary being
      deployed (`--strict` also fails on warnings, which is the right setting for a CI gate).
- [ ] `network = "main"` and a real `[rpc] password` (the daemon refuses to start with the
      `CHANGE-ME` placeholder).
- [ ] RPC bound to `127.0.0.1` or a private network; TLS or a reverse proxy in front if it
      must cross a network boundary. RPC credentials are spend authority (see the
      [threat model](../security/threat-model.md)).
- [ ] Key custody chosen deliberately: for unattended sending, the age identity stored
      outside the datadir (secrets manager, separate mount, `ZECD_AGE_IDENTITY`); for
      human-operated wallets, `zecd init --encrypt` so spending requires `walletpassphrase`
      with a timeout. See [Key custody](../security/key-custody.md).
- [ ] Mnemonic and birthday recorded offline; restore procedure tested on testnet.
- [ ] Local Zebra full node configured (`server = "zebra"` or `zebra://host:port`); Docker
      images pinned to verified releases.
- [ ] `/readyz` wired into the orchestrator with a `startupProbe` covering initial sync;
      alerts on `upstream_down`.
