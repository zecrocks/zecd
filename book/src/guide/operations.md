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

Do not back up `data.sqlite` or `blocks/`. They are caches derived from the chain: zecd is
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
| `<dir>/data.sqlite` (+ `-wal`/`-shm`) | Cache: account, scan progress, balances, history. Rebuilt from `keys.toml` plus a rescan. | No. |
| `<dir>/blocks/` | Cache: downloaded compact blocks. Can grow large; fully re-derivable. | No. Exclude from every snapshot. |
| `<datadir>/.cookie` | Ephemeral RPC cookie, minted at startup, removed on clean shutdown | No. |

Keep secrets out of the TOML (which typically lives in a ConfigMap):

- RPC password: `ZECD_RPC_PASSWORD`, `--rpcpassword`, or `[rpc] password_file`
  (flag/env > `password_file` > inline `password`). Prefer the env var or `password_file`:
  a password on the command line is visible to any local user via `ps`, and zecd warns at
  startup when it is passed that way.
- `keys.toml` location: `ZECD_KEYS_FILE` / `--keys-file` / `[keys] keys_file` (per-wallet
  `[wallets.<name>] keys_file`).
- age identity: `ZECD_AGE_IDENTITY` / `--age-identity` / `[keys] age_identity`.

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
readiness, or `/status` showing `fully_scanned` at the tip and `pending_enhancements` 0; the
default `"connected"` readiness reports ready long before that).

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

Readiness modes:

- `"connected"` (default): ready once Zebra is connected and its tip is past the wallet's
  birthday. Does not wait for the scan, so readiness never flaps during a long catch-up;
  reads may lag the tip.
- `"synced"`: ready only once every wallet is connected, within `[health] max_scan_lag`
  blocks of the tip (default 4), and with an empty enhancement backlog. A from-birthday
  restore stays not-ready until it has scanned to its own funds and finished backfilling
  memos.

A 503 body carries a `reason`. Route alerts on it:

| `reason` | Meaning | Action |
|---|---|---|
| `upstream_down` | Zebra unreachable | Page someone. |
| `actor_down` | A wallet's writer actor died | Restart the process. |
| `enhancing` | Scanned to tip, still backfilling memos (`"synced"` mode only) | Wait; watch `pending_enhancements` trend to zero. |
| `syncing` | Normal block catch-up | Wait. |

**"Scanned to tip" is not "ready".** Compact blocks carry no memos, so after the block scan
catches up, an enhancement pass fetches each transaction's full data from Zebra and decrypts
it to backfill memos. On a from-birthday restore of a busy wallet that is one fetch + decrypt
per transaction, potentially hours of work after `scan_progress` hits `1.0`. While the
backlog drains, `conn_state` stays `syncing`, `getwalletinfo.scanning` and
`getblockchaininfo.initialblockdownload` stay truthy, and `"synced"` readiness holds 503 with
`reason="enhancing"`. Watch `/status` `pending_enhancements`; if it drains slowly, check that
Zebra's `getrawtransaction` is fast.

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

## Upgrades

1. Stop with SIGINT or SIGTERM (both are graceful: in-flight requests finish, new ones get
   503). The `stop` RPC is regtest-only, so a stray RPC call cannot take down a production
   daemon.
2. Replace the binary or pull the new image.
3. Start. Wallet DB migrations run automatically at open; the first start after a large
   librustzcash bump can take longer.

Downgrades across DB migrations are not supported. If you need a rollback path, stop the
daemon and snapshot the datadir first. The worst case of a lost datadir is a from-seed
restore, not lost funds.

## Single-instance datadir lock

zecd takes an exclusive advisory lock on `<datadir>/.lock` while it owns the data directory
(the daemon for its whole lifetime, `zecd init` for the init). A second `zecd run` or
`zecd init` on the same datadir fails fast with `Cannot lock data directory ...`. The lock is
an OS advisory lock the kernel releases when the process exits, including a crash or kill, so
there is never a stale lockfile to delete: if the error appears and no zecd is running, just
retry. Two commands are exempt because they never write the datadir: `zecd export-ufvk`
(read-only DB access, so you can export a UFVK while the daemon runs) and `zecd rpcauth`.

## Mainnet checklist

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
