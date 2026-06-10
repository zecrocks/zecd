# zecd operations runbook

How to run `zecd` in production (mainnet) without losing funds or sleep. Read the
README first for the architecture (`zebra → lightwalletd → zecd`) and configuration
reference; this document covers backup/restore, monitoring, upgrades, and the mainnet
checklist.

## What to back up

Funds are recoverable from **the mnemonic alone**. Everything else is convenience.

| Artifact | Where | What it protects |
|---|---|---|
| **24-word mnemonic** | shown once by `zecd init` | The funds. Record it offline (paper/HSM). Without it, loss of the server is loss of funds. |
| `keys.toml` | `<wallet dir>/keys.toml` | The age-*encrypted* mnemonic plus network and birthday height. Useless without the identity, but pair it with the identity for a full server restore. |
| `identity.txt` (age identity) | `[keys] age_identity`, default `<datadir>/identity.txt` | Decrypts `keys.toml`. **This is spend authority** - store the backup separately from `keys.toml` backups. |
| Birthday height | inside `keys.toml`; also worth recording with the mnemonic | Makes a from-seed restore fast. Any height at/before the wallet's first transaction works. |

The SQLite databases (`data.sqlite`, `blocks/`, `labels.sqlite`) are caches derived
from the chain; they do not need backup (address labels excepted - back up
`labels.sqlite` if labels matter to you).

## Restore procedures

**Server restore (have `keys.toml` + `identity.txt`):** place both files back in their
configured paths and start the daemon. The wallet DB rebuilds by rescanning from the
stored birthday.

**From-seed restore (have only the mnemonic):**

```sh
zecd init --datadir /var/lib/zecd --restore --birthday <height>
# paste the mnemonic when prompted
```

Pass `--birthday` (any height at/before the wallet's first transaction). Without it,
the restore scans from Sapling activation - safe (never misses notes) but slow on
mainnet. The wallet's receive/send history reappears as the scan progresses; balances
are not final until `/readyz` reports ready.

## Monitoring

- `GET /healthz` (health port, default 9233) - liveness.
- `GET /readyz` - readiness: 200 once connected and scanned past `[health]
  ready_progress`. When 503, the body's `reason` distinguishes `upstream_down`
  (lightwalletd unreachable - page someone) from `syncing` (normal catch-up).
- `GET /status` - per-wallet sync state, active lightwalletd endpoint, `conn_state`
  (`down` | `syncing` | `ready`). Alert if `conn_state` stays `down`.
- `getrpcinfo.active_commands` - what's executing right now (visibility under load).
- Logs: set `[log] format = "json"` for aggregation. Every RPC call logs method,
  wallet, elapsed_ms (errors add code/message); connection failover logs at warn.

Suggested alerts: `/readyz` 503 with `reason=upstream_down` for >5 min; `/status`
`fully_scanned` not advancing for >30 min; daemon restarts.

## Send semantics worth knowing

- A send whose initial broadcast fails in transport still **returns the txid**: the
  transaction is committed and re-broadcast automatically (every ~60s while unmined and
  unexpired). Never retry a send that returned a txid.
- A send rejected by the upstream node errors with `-26`; its notes stay locked until
  the tx's expiry height, then become spendable again.
- An expired unmined tx reports `confirmations: -1` (`abandoned: true`) - treat it as
  failed and safe to re-send.
- Rapid back-to-back sends can exhaust spendable notes (`-6`) until change confirms.

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
      human-operated wallets, `zecd init --encrypt` (or `encryptwallet`) so spending
      requires a verified `walletpassphrase` with an enforced timeout.
- [ ] Mnemonic + birthday recorded offline; restore procedure tested on testnet.
- [ ] Own `lightwalletd` as primary, public endpoints as fallback (`[lightwalletd]
      servers`); Docker images pinned to verified releases.
- [ ] `/readyz` wired into your orchestrator with a `startupProbe` covering initial
      sync; alerts on `upstream_down`.
