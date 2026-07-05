# Threat model & trust boundaries

What zecd protects, what it trusts, which adversaries it defends against, and which it
deliberately does not. Read this before deploying with real funds; the custody mechanics live
in [key custody](key-custody.md).

## Assets

Ordered by blast radius:

| Asset | What it grants | Where it lives |
|-------|----------------|----------------|
| Seed / mnemonic | Spend authority over all funds, forever. The root secret. | Age-encrypted in `keys.toml`; decrypted into process memory when unlocked. |
| RPC credentials | **Spend authority on an unlocked wallet.** Anyone who can call `sendtoaddress` can move funds; treat the RPC password, `rpcauth` secrets, and the `.cookie` file exactly like the seed while the daemon runs unlocked. | `[rpc]` config, `ZECD_RPC_PASSWORD`, `<datadir>/.cookie` (mode 0600). |
| UFVK (Unified Full Viewing Key) | Full view access: every incoming and outgoing transaction, amounts, memos, addresses. Cannot spend, but its leak is a permanent transaction-graph privacy compromise. | Wallet DB; pinned in `keys.toml`; printed by `zecd export-ufvk`. |
| Wallet datadir | The wallet DB (`data.sqlite`), `keys.toml`, the cookie, and (in the default custody model) the age identity file. See the datadir-theft row below. | `--datadir`. |
| Zebra RPC credentials | Access to the node whose answers zecd trusts for its entire chain view. | `[zebra]` config (cookie or user/password). |

## Trust boundaries

```
 RPC client                zecd                       zebrad
 (your app) ---HTTP------> [RPC :8232]                (self-hosted)
             Basic/cookie   |                          |
             auth, JSON-RPC |  actor / wallet DB       |
                            |                          |
             no auth -----> [health :9233]             |
             (sync status)  |                          |
                            +---plaintext JSON-RPC---->+
                            |   (local-only by design)
                            v
                          disk: <datadir>/
                          keys.toml, identity.txt,
                          data.sqlite, .cookie, .lock
```

**RPC client to zecd.** Authenticated (HTTP Basic: `rpcuser`/`rpcpassword`, `rpcauth`
entries, or the generated cookie). The transport is plaintext HTTP, same as bitcoind: the hop
is assumed to be a trusted network segment (loopback, or a private segment fronted by
TLS/reverse proxy). Authentication proves identity; it does not encrypt the wire.

**zecd to Zebra.** Plaintext local JSON-RPC. Zebra is **fully trusted for the chain view**:
balances, confirmation counts, incoming payments, and mempool visibility are whatever Zebra
serves. zecd validates response shapes, not consensus. This is why the deployment model is
self-hosted-only: you point zecd at a node you run, not a public endpoint. See
[the Zebra backend](../design/zebra-backend.md). Zebra never sees key material; a compromised
node cannot steal funds, only lie about the chain.

**zecd to disk.** The datadir holds the encrypted seed, the wallet DB, and the RPC cookie.
Filesystem permissions are the boundary; zecd sets 0600 on the cookie and the identity file
but otherwise trusts the OS user model.

**Health port.** `/healthz`, `/readyz`, `/status` on a separate port (default
`127.0.0.1:9233`) are unauthenticated by design and expose sync status only, no balances or
addresses. Still keep it off the public internet: sync state and upstream reachability are
reconnaissance.

## Adversaries and mitigations

| Adversary | Can attempt | Mitigations |
|-----------|-------------|-------------|
| Network attacker on the RPC hop | Sniff or brute-force credentials, issue spends. | Default bind `127.0.0.1`; front remote access with TLS or a reverse proxy. Cookie auth (fresh random secret, file mode 0600) or `rpcauth` salted HMAC-SHA256 (no plaintext password in config). Constant-time credential comparison with no username short-circuit. 250 ms delay on every 401, matching bitcoind's anti-bruteforce delay. On mainnet, zecd refuses to start while the RPC password is the example placeholder `CHANGE-ME`. |
| Holder of a leaked RPC credential | Full RPC surface, including sends on an unlocked wallet. | `[rpc] allowed_methods` safelist: a non-empty list serves only those methods, everything else returns `-32601` (indistinguishable from nonexistent), shrinking the blast radius to what the deployment actually needs. Server-wide, not per-user. For structural containment, run the exposed instance [watch-only](../guide/watch-only.md) so no credential on it is spend authority. Passphrase custody (`init --encrypt`) keeps the wallet locked between sends. |
| Malicious or compromised Zebra | Serve a wrong chain view: fake confirmations, hidden incoming payments, stale tip. Cannot steal keys (it never sees them). | Run your own node; that is the deployment model, not an option. The cleartext-credential gate refuses to send `[zebra]` credentials to a globally-routable host over plaintext (loopback and private ranges allowed by default; `[backend] rfc1918_is_local = false` tightens, `allow_remote_cleartext = true` opts out for an out-of-band-secured hop). |
| Datadir thief (backup leak, stolen disk, snapshot access) | Read `keys.toml`, `data.sqlite`, the cookie. | The seed in `keys.toml` is age-encrypted. Caveat for the default custody model: the identity file defaults to `<datadir>/identity.txt`, so whoever reads the **whole** datadir has the seed. Mitigate by storing the identity outside the datadir (`ZECD_AGE_IDENTITY`, a secrets manager, a separate mount) or by using passphrase custody, where no on-disk file can decrypt the seed. Either way the thief still gets the UFVK and full history (a privacy loss). Details in [key custody](key-custody.md). |
| DB planter (swaps or plants `data.sqlite` to divert deposits to their key) | Make `getnewaddress` derive addresses from a foreign account. | Account-to-keys binding: `init` pins the account's UFVK into `keys.toml`; every startup verifies the DB account against the pin, and every seed exposure (startup auto-unlock, `walletpassphrase`) verifies the seed derives that UFVK. A mismatch is fatal for the whole daemon (treated as tampering evidence); `walletpassphrase` returns `-4` and stays locked. |
| Memory scraper (swap file, core dump, another process reading `/proc/<pid>/mem`) | Capture the decrypted in-memory seed passively. | Best-effort hardening at startup: the seed buffer is `mlock`ed (never swapped), core dumps are disabled (`RLIMIT_CORE=0`), and the process is non-dumpable (`PR_SET_DUMPABLE=0`, which also blocks ptrace by other non-root processes). `ZECD_ALLOW_CORE_DUMPS=1` opts out for debugging. Each step warns and continues if denied. This is **not** a defense against code execution inside zecd, which can read the seed directly; for that, run zecd watch-only and keep spend authority in a separate signer. |
| Authenticated DoS (credentialed flood) | Exhaust the daemon with requests or queued sends. | Work-queue semaphore (`[rpc] work_queue`, default 100): excess concurrent requests get 503, like bitcoind. The async-operation registry is capped at 1024 retained operations (oldest finished results evicted) and 16 unfinished operations per wallet (further `z_sendmany` rejected with `-4` back-pressure). |
| Concurrent writer (second zecd on the same datadir) | Corrupt the wallet DB. | Exclusive advisory lock on `<datadir>/.lock`, taken by both the daemon and `zecd init` and held for their lifetime; a second writer refuses to start. Kernel-released on exit, so no stale lockfile. Read-only `export-ufvk` is exempt. |

## Residual risks and non-goals

Residual risks (real, accepted, mitigate operationally):

- **Zebra is a single point of trust and availability.** No cross-checking against a second
  source. A lying node lies successfully until you notice; a dead node stalls sync and sends
  (reads keep answering from the local DB).
- **`mlock` covers the seed buffer only.** Transient key copies made inside librustzcash
  during derivation and proving are not individually locked. Back swap with an encrypted
  device to cover the residue.
- **No built-in TLS on the RPC port.** Same posture as bitcoind; anything beyond loopback
  needs a proxy in front.
- **No per-user RPC permissions.** Every accepted credential has the same authority;
  `allowed_methods` is one server-wide gate.
- **The health port leaks operational state** (sync progress, upstream reachability) to
  anyone who can reach it. Keep it private.
- **Transparent funds have a bounded recovery window** on a from-seed restore (gap limit /
  initial scan); a lost datadir plus an undersized window loses sight of sparsely-funded high
  addresses. See [transparent addresses](../guide/transparent.md).

Explicit non-goals:

- **Code execution inside the zecd process.** An attacker running code in-process reads the
  unlocked seed. The supported isolation is the watch-only split, not in-process containment.
- **A hostile host.** Root, the hypervisor, and anyone who can ptrace as root are outside
  the model. `PR_SET_DUMPABLE=0` stops other non-root processes, nothing more.
- **Zcash protocol or librustzcash vulnerabilities.** Report those upstream per the
  [Zcash ecosystem security policy](https://z.cash/support/security/), not against zecd.
- **Hiding metadata from your own Zebra node.** zecd fetches full blocks and polls the
  mempool from a node you run; the node necessarily learns the wallet's sync pattern.

Supply-chain integrity of the shipped binaries is addressed separately by the
[reproducible build pipeline](../design/reproducible-builds.md). To report a vulnerability in
zecd itself, use GitHub's private vulnerability reporting on the repository; do not open a
public issue.
