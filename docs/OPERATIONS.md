# zecd operations runbook

How to run `zecd` in production (mainnet) without losing funds or sleep. Read the
README first for the architecture (`zebra → zecd`) and configuration reference; this
document covers backup/restore, monitoring, upgrades, and the mainnet checklist.

## Assumed deployment posture (trust boundary)

`zecd` is built for one shape of deployment, and its safe-by-default behavior assumes it.
Know the assumptions so you can see when you are widening the trust boundary.

**The assumed posture:**

- **RPC is reachable only by trusted callers** - bound to loopback (`127.0.0.1`), or behind
  authentication / a reverse proxy if it must cross a machine. The RPC credentials are spend
  authority: anyone who can reach an unlocked wallet's RPC can move funds.
- **zebra is co-located** - the upstream is a local full node reached over plaintext loopback
  HTTP (`server = "zebra"`). No secrets and no chain-affecting authority cross the wire, so
  the hop is unencrypted by design.
- **The operator owns the datadir** - `keys.toml`, `identity.txt`, the wallet DB, and the
  single-instance lock live on storage only the operator controls. zecd binds the DB to the
  key material (`keys.toml` UFVK pin) and refuses to start on a mismatch, but it cannot defend
  a datadir an attacker can rewrite at will.
- **Auto-unlock keeps spend authority resident** - an identity-file (unencrypted) wallet with
  `auto_unlock` decrypts its seed into memory at startup and holds it there, so unattended
  sends work without a passphrase. That convenience *is* resident spend authority; it logs a
  warning at startup to make the trade-off visible.

**What widens the boundary (deliberate opt-ins, each a bigger blast radius):**

- **Binding RPC off loopback** - exposes spend authority to whatever can reach the bind
  address. zecd warns when a non-loopback bind is paired with a bare password; put TLS / a
  reverse proxy / network policy in front.
- **A remote zebra over plaintext** (`[backend] allow_remote_cleartext = true`) - sends the
  `[zebra]` RPC credentials in cleartext to a non-local host. Only do this when the hop is
  secured out of band (VPN / private link); zecd refuses it otherwise (#111 loopback gate).
- **Auto-unlocking an unencrypted wallet** - the resident-seed model above. Prefer
  `zecd init --encrypt` (Bitcoin-Core-style passphrase, unlocked per session with an enforced
  timeout) whenever unattended spend authority is not actually required.

See the README **Security** section for the underlying rationale (RPC credentials as spend
authority, custody models, the cleartext gate).

## What to back up

Funds are recoverable from **the mnemonic alone**. Everything else is convenience.

| Artifact | Where | What it protects |
|---|---|---|
| **24-word mnemonic** | shown once by `zecd init` | The funds. Record it offline (paper/HSM). Without it, loss of the server is loss of funds. |
| `keys.toml` | `<wallet dir>/keys.toml`, or wherever `keys_file` points | The age-*encrypted* mnemonic plus network and birthday height. Useless without the identity, but pair it with the identity for a full server restore - and it's the file you ship as a Secret. |
| `identity.txt` (age identity) | `[keys] age_identity`, default `<datadir>/identity.txt` | Decrypts `keys.toml`. **This is spend authority** - store the backup separately from `keys.toml` backups. |
| Birthday height | inside `keys.toml`; also worth recording with the mnemonic | Makes a from-seed restore fast. Any height at/before the wallet's first transaction works. |

The SQLite databases (`data.sqlite`, `blocks/`) are caches derived from the chain; they do not
need backup. zecd is **stateless** - it keeps no off-chain data the seed can't rebuild (there is
no label store), so the whole data directory is disposable: with the mnemonic (and birthday) you
can recreate everything via `zecd init --restore`.

### Minimal runtime file set (what's a secret, what's a cache)

A running wallet's data directory holds, per wallet `<dir>`:

| Path | Role | Ship it? |
|---|---|---|
| `<dir>/keys.toml` | **Secret** - encrypted seed + birthday/network. | Yes - mount as a Secret (relocate with `keys_file` / `ZECD_KEYS_FILE`). |
| `identity.txt` | **Secret** - decrypts the seed (spend authority). | Yes, if auto-unlocking - mount as a Secret (`ZECD_AGE_IDENTITY`). |
| `<dir>/data.sqlite` (+ `-wal`/`-shm`) | Wallet state: the account plus scan progress, balances, and tx history. A **cache** - rebuilt from `keys.toml` + a rescan when absent (see bootstrap below). | No (disposable). |
| `<dir>/blocks/` | **Cache** - downloaded compact blocks. **Never ship this** - it can grow large and is fully re-derivable. | No. |
| `<datadir>/.cookie` | Ephemeral RPC cookie, minted at startup and removed on clean shutdown. | No. |

For a cloud deployment: put `keys.toml` (and `identity.txt`, if used) in a read-only Secret
and point `ZECD_KEYS_FILE` / `ZECD_AGE_IDENTITY` at the mount. `blocks/` is always disposable -
excluding it from any image/volume snapshot is the single biggest space win.

> **The data directory must be host-local.** zecd's single-instance lock on `<datadir>/.lock` is
> an OS advisory lock enforced by the *local* kernel, so it only prevents a second zecd on the
> *same host*. It does **not** span hosts: a datadir on a network filesystem shared read-write by
> two machines (NFS, SMB, a Kubernetes `ReadWriteMany` volume) can be locked independently by each
> host's kernel, so two zecd on different hosts could both write the wallet DB and corrupt it. Keep
> the datadir on a local disk or a single-writer volume (Kubernetes `ReadWriteOnce`), and never
> share it read-write across hosts - the `keys.toml`/`identity.txt` Secret can be mounted read-only
> by many pods, but each pod needs its **own** writable datadir. The lockfile records the holder's
> `hostname:pid` for diagnostics. No cross-host lease is implemented.

### Bootstrapping a disposable data directory

With `[keys] bootstrap_from_keys` (default on), an empty data directory next to a present
`keys.toml` is **rebuilt automatically on boot**: zecd recreates the wallet account from the
seed and rescans from the birthday. So "mount one Secret (`keys.toml`, plus `identity.txt` if
auto-unlocking) and start with an empty PVC" just works. When the seed becomes available depends
on the custody model:

- **Identity / `auto_unlock`** - the seed is decrypted at startup, so the rebuild runs as soon
  as zebra is reachable; no human action.
- **Encrypted (`init --encrypt`)** - the wallet starts locked with no account yet. The
  `locked` signal on `/status` is `true`; address/spend RPCs return "account is not ready". The
  rebuild runs at the **first `walletpassphrase`**, after which the wallet syncs (and stays
  synced while locked). The `data.sqlite` write happens then, so the data directory must be
  writable - zecd probes this at launch and refuses to start on a read-only datadir, rather than
  failing at unlock time.
- **Watch-only (`--ufvk`)** - has no seed and is **not** covered by bootstrap; recreate it with
  `zecd init --ufvk` against an empty datadir.

To opt out (fail fast on an empty datadir instead of rebuilding), set `bootstrap_from_keys =
false`. Either way `blocks/` is always discardable.

### Secret inputs without baking them into the config

The RPC password is spend-equivalent for clients, and the seed/identity are spend authority,
so none of them should land in a ConfigMap. Each can come from the environment or a mounted
Secret file instead of the TOML:

- **RPC password** - `ZECD_RPC_PASSWORD`, `--rpcpassword`, or `[rpc] password_file`
  (precedence: flag/env > `password_file` > inline `[rpc] password`). Prefer
  `ZECD_RPC_PASSWORD` or `password_file` over `--rpcpassword`: a password on the command line
  is exposed to any local user via `ps` and `/proc/<pid>/cmdline`, so zecd warns at startup when
  the password is passed that way.
- **keys.toml location** - `ZECD_KEYS_FILE` / `--keys-file` / `[keys] keys_file` (default wallet)
  or per-wallet `[wallets.<name>] keys_file`.
- **age identity** - `ZECD_AGE_IDENTITY` / `--age-identity` / `[keys] age_identity`.
- **Non-interactive `init --restore`** - `ZECD_MNEMONIC` or `--mnemonic-file` (else stdin);
  `ZECD_WALLET_PASSPHRASE` for `init --encrypt` (else prompted).

## Restore procedures

**Server restore (have `keys.toml` + `identity.txt`):** place both files back in their
configured paths and start the daemon. With `bootstrap_from_keys` on (the default), the wallet
account is recreated from `keys.toml` and the DB rebuilds by rescanning from the stored birthday
 - no `init` needed. (For an encrypted wallet, the account is created at the first
`walletpassphrase`; see *Bootstrapping a disposable data directory* below.)

**From-seed restore (have only the mnemonic):**

```sh
zecd init --datadir /var/lib/zecd --restore --birthday <height>
# paste the mnemonic when prompted
```

Pass `--birthday` (any height at/before the wallet's first transaction). Without it,
the restore scans from Sapling activation - safe (never misses notes) but slow on
mainnet. The wallet's receive/send history reappears as the scan progresses; balances
are not final until `/readyz` reports ready.

**Watch-only instance (have a spending wallet somewhere else):** export the viewing key
with `zecd export-ufvk` on the spending wallet's host, then on the watch-only host:

```sh
zecd init --datadir /var/lib/zecd-watch --ufvk "uview1..." --birthday <height>
```

A watch-only wallet has no mnemonic and nothing spendable to back up - it is fully
reconstructable from the UFVK + birthday (record both). Treat the UFVK as confidential:
it reveals the wallet's entire transaction graph, though it cannot spend.

## Monitoring

- `GET /healthz` (health port, default 9233) - liveness.
- `GET /readyz` - readiness, gated by `[health] readiness`. In `"synced"` mode
  (**default**) it's 200 only once connected, within `[health] max_scan_lag` blocks of the
  tip, AND with the transaction-enhancement backlog drained (see below) - so a client
  routed by readiness never sees an empty or stale balance/history as authoritative while
  the wallet is still scanning. **Keep this default for any balance-sensitive deployment**
  (an exchange, an accounting integration): a from-birthday restore or fresh sync stays 503
  until it has actually caught up to its own funds. In `"connected"` mode it's 200 as soon as
  zebra is connected and its tip is past the wallet's birthday - it does NOT wait for the scan
  to finish, so it stays ready (no flapping) while the wallet catches up, but reads may lag the
  tip; choose it only when reachability matters more than balance freshness, and watch the
  per-wallet `scan_lag` to see how far behind reads may be. When 503, the body's `reason`
  distinguishes `upstream_down` (zebra unreachable - page someone) from `syncing` (normal block
  catch-up), `enhancing` (scanned to tip, still backfilling memos), and `actor_down` (a dead
  writer - restart the process).
- `GET /status` - per-wallet sync state, active upstream endpoint, `conn_state`
  (`down` | `syncing` | `ready`), `scan_lag` (the `chain_tip - fully_scanned` block gap - how
  far behind reads may be, reported in both readiness modes), and `pending_enhancements` (the
  enhancement backlog). Alert if `conn_state` stays `down`.
- **Enhancement backlog (`pending_enhancements`).** The compact-block scan reaching the
  tip (`scan_progress: 1.0`, `scanning: false` for the block scan) is NOT "ready to serve
  full history". Compact blocks carry no memos, so a per-transaction enhancement pass then
  fetches each tx's full data from zebra and decrypts it to backfill memos. On a
  from-birthday restore of a busy wallet this is one `getrawtransaction` + decrypt per
  transaction - tens of thousands of them, potentially hours of work *after* the scan
  reports done. While it drains, `conn_state` stays `syncing`, `getwalletinfo.scanning` and
  `getblockchaininfo.initialblockdownload` stay truthy, and `synced` readiness stays 503
  (`reason=enhancing`). Watch `pending_enhancements` trend to zero; if zebra's
  `getrawtransaction` is slow, confirm its transaction index is enabled.
- `locked` (top-level on both `/readyz` and `/status`, plus per-wallet `locked`/`encrypted`)
 - `true` when a passphrase-encrypted wallet is synced and serving reads but still needs a
  `walletpassphrase` before it can spend. It is reported independently of readiness (a locked
  wallet can be `ready: true`), so a controller can drive an unlock without mistaking it for a
  sync stall.
- `getrpcinfo.active_commands` - what's executing right now.
- Logs: set `[log] format = "json"` for aggregation. Every RPC call logs method,
  wallet, elapsed_ms (errors add code/message); connection failover logs at warn.

Suggested alerts: `/readyz` 503 with `reason=upstream_down` for >5 min; `/status`
sync lag (`chain_tip` − scanned height) not shrinking for >30 min; sustained
work-queue 503s; daemon restarts.

## Send semantics worth knowing

- A send whose initial broadcast fails in transport still **returns the txid**: the
  transaction is committed and re-broadcast automatically (every ~60s while unmined and
  unexpired). Never retry a send that returned a txid.
- A send rejected by the upstream node errors with `-26`; its notes stay locked until
  the tx's expiry height, then become spendable again.
- An expired unmined tx reports `confirmations: -1` (`abandoned: true`) - treat it as
  failed and safe to re-send.
- Rapid back-to-back sends can exhaust spendable notes (`-6`) until change confirms.

## Reorgs

zecd follows chain reorgs automatically: the scanner detects the fork via a block-hash
continuity error, rewinds the wallet ~10 blocks below it, and rescans the replacement
chain. Transactions in reorged-away blocks revert to unconfirmed (`confirmations: 0`)
until re-mined - confirmation thresholds keep doing their job. Operator-visible
consequences:

- **A `listsinceblock` cursor pointing at a reorged-away block returns `-5 Block not
  found`** (zecd keeps no stale-header history to walk back through, unlike bitcoind).
  Treat `-5` as "cursor invalid": re-baseline with a parameterless `listsinceblock`,
  process the result idempotently (dedupe by txid), and store the fresh `lastblock`.
  Poller logic should assume any tx below your confirmation threshold can be re-reported.
- Balances and `getblockcount` can dip while the rewound range rescans; `/status` shows
  `scanning` during the catch-up.

## Upgrades

1. `zecd stop` (or SIGINT) - graceful: in-flight requests finish, new ones get 503.
2. Replace the binary / pull the new image.
3. Start. Wallet DB migrations run automatically at open; the first start after a big
   librustzcash bump can take longer.

Downgrades across DB migrations are not supported - snapshot the datadir first if you
need a rollback path (stop the daemon before copying).

## Mainnet checklist

- [ ] `network = "main"` and `[rpc] password` set to a real secret (the daemon refuses
      to start with the `CHANGE-ME` placeholder).
- [ ] RPC bound to `127.0.0.1` or a private network; TLS/reverse proxy in front if it
      must cross a network boundary. **RPC credentials are spend authority** (see
      README → Security).
- [ ] Key custody chosen deliberately: for unattended sending, the age identity stored
      outside the datadir (secrets manager / separate mount / `ZECD_AGE_IDENTITY`); for
      human-operated wallets, `zecd init --encrypt` so spending requires a verified
      `walletpassphrase` with an enforced timeout.
- [ ] Mnemonic + birthday recorded offline; restore procedure tested on testnet.
- [ ] Local zebra full node configured (`server = "zebra"` or `zebra://host:port`);
      Docker images pinned to verified releases.
- [ ] `/readyz` wired into your orchestrator with a `startupProbe` covering initial
      sync; alerts on `upstream_down`.
