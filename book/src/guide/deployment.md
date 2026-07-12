# Deployment

How to run zecd in production: the Docker Compose stack, the container images and how to
extract bare binaries from them, the prebuilt `.tar.gz`/`.deb` release artifacts, and the
health-probe wiring for Kubernetes and load balancers. Day-2 concerns (backups, monitoring,
upgrades, failure modes) are in the [operations runbook](operations.md).

## The Docker Compose stack

`deploy/docker-compose.yml` runs the two-service stack: a Zebra full node and zecd talking
straight to Zebra's JSON-RPC over the private compose network. Testnet by default. The
config files it mounts (`deploy/zebrad.toml`, `deploy/zecd.toml`) are part of the stack;
the mainnet variants (`*.mainnet.toml`) are swapped in by the
`docker-compose.mainnet.yml` overlay.

First run is init-then-up: Zebra must be synced far enough before zecd can create a wallet
(a new wallet's birthday defaults to just below the current chain tip, 100 blocks back).

```sh
cd deploy
docker compose up -d zebra                        # let it sync
docker compose run --rm zecd init --wallet default
docker compose up -d                              # start zecd

curl localhost:9233/healthz
curl localhost:9233/readyz
curl --user zec:CHANGE-ME --data-binary \
    '{"method":"getblockchaininfo","id":1}' localhost:18232/
```

`zecd init` prints the wallet mnemonic to stdout once. Record it offline; it is the only
way to restore the wallet. See [operations](operations.md) for what else to back up.

For mainnet, add `-f docker-compose.mainnet.yml` to every command. The overlay only swaps
each service's mounted config file; ports and wiring are unchanged (the mainnet configs
deliberately keep zecd on 18232 and Zebra on 18234 so the compose port mapping is identical
across networks):

```sh
docker compose -f docker-compose.yml -f docker-compose.mainnet.yml up -d zebra
docker compose -f docker-compose.yml -f docker-compose.mainnet.yml run --rm zecd init --wallet default
docker compose -f docker-compose.yml -f docker-compose.mainnet.yml up -d
```

Three things to change before trusting the stack with real funds:

- **Pin Zebra.** The compose file pins `zfnd/zebra:6.0.0` for both networks; Zebra 6.0.0 activates
  Ironwood (NU6.3) at the network's activation height (see Zebra's source and release notes). The
  tag is an example. Pin to a release you have verified; Zebra's flags can vary between versions.
  (Zebra tags have no `v` prefix.)
- **Set a real RPC password.** The shipped configs use `password = "CHANGE-ME"`. On
  mainnet zecd refuses to start while the `[rpc]` password is still that placeholder
  (case-insensitive): the RPC credential is spend authority. On testnet it starts, but
  change it anyway before exposing the port.
- **Keep the RPC port private.** The compose file publishes 18232 and 9233 on loopback
  only. RPC credentials travel as plaintext HTTP Basic auth; to serve other hosts, front
  zecd with TLS or a reverse proxy, or accept the exposure knowingly.

The compose configs bind `[rpc]` and `[health]` to `0.0.0.0` inside the container (so the
published ports are reachable) and point `[backend] server` at `zebra://zebra:18234`. That
connection carries no credentials (`enable_cookie_auth = false` on the Zebra side), which
is what the [cleartext-credential gate](../design/zebra-backend.md) expects for a non-local
hostname.

zecd takes an exclusive lock on its data directory: never run two zecd instances (or
replicas) against the same volume. The second one refuses to start rather than corrupt the
wallet DB.

## Container images

Two Dockerfiles produce interchangeable images:

- **`Dockerfile` (amd64):** a reproducible [StageX](https://stagex.tools) build.
  Full-source-bootstrapped base images pinned by digest, a statically linked musl `zecd`,
  deterministic flags (`SOURCE_DATE_EPOCH=1`, `codegen-units=1`, `--build-id=none`), and a
  bare `scratch` runtime. Independent builders can reproduce the binary bit-for-bit.
- **`Dockerfile.arm64` (arm64):** StageX publishes amd64 images only, so ARM uses a
  static-musl Alpine build (`rust:alpine`, base image pinned by digest, toolchain pinned
  to exact apk versions, Rust pinned via `RUSTUP_TOOLCHAIN`). Same output shape and the
  same runtime contract, and still bit-for-bit reproducible, but the toolchain is upstream
  binaries rather than StageX's full-source bootstrap. Released images carry `-arm64`
  suffixed tags.

How the reproducibility works (and what to verify) is covered in
[reproducible builds](../design/reproducible-builds.md).

### Runtime contract

Both images honor the same contract, so they are drop-in interchangeable:

| Property | Value |
|---|---|
| Binary | `/usr/local/bin/zecd` (static musl, no shell or libc in the image) |
| Entrypoint | `zecd`, default args `--datadir /var/lib/zecd` |
| User | `10001:10001` (unprivileged, non-root) |
| Workdir / datadir | `/var/lib/zecd` (writable by the runtime user) |
| Exposed ports | `8232`, `18232` (JSON-RPC mainnet/testnet), `9233` (health) |
| Base | `scratch`: no CA bundle (the Zebra upstream is plaintext-local, no outbound TLS) |

The image also ships a world-writable `/tmp` for SQLite's temporary files. Because the
runtime is `scratch`, there is no shell: debugging happens through the RPC and health
endpoints, or by mounting the datadir elsewhere.

### Extracting bare binaries

Each Dockerfile has an `export` stage that copies the static binary to the image root, so
you can build and extract without running a container:

```sh
docker build --target export -o ./out .                       # amd64: ./out/zecd
docker build -f Dockerfile.arm64 --target export -o ./out .   # arm64
```

This is exactly how the release workflow produces the published binaries, so a local
export should reproduce the binary inside the released `.tar.gz`/`.deb` bit-for-bit for
the same source.

## Prebuilt release artifacts

Pushing a `v*` tag runs the Release workflow. It extracts the binary from each
Dockerfile's `export` stage (so published binaries inherit the reproducible image
pipeline) and attaches, per target (`x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`, both static):

- `zecd-<version>-<target>.tar.gz` + `.sha256`: the binary plus `README.md`,
  `CHANGELOG.md`, both license files, and `zecd.example.toml`. The tar is reproducible
  (sorted entries, fixed mtime, root-owned, `gzip -n`).
- `zecd_<version>_<amd64|arm64>.deb` + `.sha256`: a reproducible Debian package
  (`scripts/build-deb.sh`: fixed mtimes, `--root-owner-group`, `SOURCE_DATE_EPOCH`
  anchored; verified bit-for-bit).

Verify the checksum, then install:

```sh
sha256sum -c zecd_<version>_amd64.deb.sha256
sudo apt install ./zecd_<version>_amd64.deb     # or _arm64.deb on ARM
```

The `.deb` installs:

- `/usr/bin/zecd`
- `/lib/systemd/system/zecd.service`: installed but **not enabled**; it runs
  `zecd --datadir /var/lib/zecd` as the `zecd` user with systemd hardening
  (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, writable only in
  `/var/lib/zecd`)
- `/usr/share/doc/zecd/`: `zecd.example.toml`, `README.md`, copyright, changelog

The postinst script creates the `zecd` system user/group and `/var/lib/zecd` (mode 0750).
No config file is installed under `/etc`; put your config at `/var/lib/zecd/zecd.toml` (the
datadir default) or point the unit at one with `--conf`. Then:

```sh
sudo -u zecd zecd init --datadir /var/lib/zecd    # one-time wallet creation
sudo systemctl enable --now zecd
```

The same workflow's `docker` jobs push the GHCR images: amd64 under bare semver tags
(`<major>.<minor>.<patch>` and `<major>.<minor>`), arm64 under the same tags with an
`-arm64` suffix. A manual `workflow_dispatch` run can dry-run the packaging without a tag;
image pushes are opt-in for those runs.

## Ports

| Port | Service | Protocol | Notes |
|---|---|---|---|
| 8232 | zecd JSON-RPC (mainnet) | HTTP, Basic/cookie auth | Bitcoin-convention port; spend authority, keep private |
| 18232 | zecd JSON-RPC (testnet/regtest) | HTTP, Basic/cookie auth | Also used for mainnet in the compose stack (config choice) |
| 9233 | zecd health | HTTP, unauthenticated | `/healthz`, `/readyz`, `/status` |
| 8234 | Zebra JSON-RPC (mainnet) | HTTP | What `server = "zebra"` expects; set `rpc.listen_addr` here |
| 18234 | Zebra JSON-RPC (testnet/regtest) | HTTP | Testnet counterpart; keep off public interfaces |

Zebra ships with RPC disabled and has no default RPC port; 8234/18234 are the ports zecd's
default `server = "zebra"` preset dials, chosen next to Zebra's P2P ports (8233/18233).
Any explicit `zebra://host:port` works.

## Health and readiness probes

zecd serves unauthenticated probes on a separate port (default 9233), designed for
Kubernetes probes and load-balancer health checks:

- `GET /healthz`: liveness. Always 200 while the process runs.
- `GET /readyz`: readiness. 200/503 plus a JSON body with `ready`, `locked`, a per-wallet
  map, and (when not ready) a `reason` of `actor_down`, `upstream_down`, `enhancing`, or
  `syncing`.
- `GET /status`: a JSON snapshot of per-wallet sync state, for humans and dashboards (see
  [operations](operations.md)).

Defaults are `[health] enabled = true`, `bind = "127.0.0.1"`, `port = 9233`. In a
container or behind a probe, set `bind = "0.0.0.0"` (the deploy configs do).

What `/readyz` means is a deployment choice, `[health] readiness`:

- `"connected"` (default): ready as soon as the backend is connected and its chain tip is
  past the wallet's birthday (a sanity check that zecd is talking to the right, live
  network). Does not wait for the wallet scan, so RPC clients can reach zecd while it
  catches up and readiness never flaps during a long sync. Reads may lag the tip.
- `"synced"`: ready only once every wallet is connected, within `max_scan_lag` blocks of
  the tip (default 4), and its transaction-enhancement backlog has drained. Strict: a
  from-birthday restore stays not-ready for hours (`reason` distinguishes `syncing` from
  `enhancing`). Use it when clients must not see stale balances or incomplete history.

A locked encrypted wallet is still *ready* (reads work); `/readyz` reports it via the
`locked` flag so a controller can drive a `walletpassphrase` without misreading it as a
sync stall. A dead wallet writer actor fails readiness (`reason: "actor_down"`) even
though reads still answer; that needs a process restart.

```toml
[health]
bind = "0.0.0.0"
port = 9233
readiness = "synced"   # or "connected" (default)
max_scan_lag = 4       # only applies in "synced" mode
```

Kubernetes example:

```yaml
startupProbe:
  httpGet: { path: /healthz, port: 9233 }
  periodSeconds: 2
  failureThreshold: 30
livenessProbe:
  httpGet: { path: /healthz, port: 9233 }
readinessProbe:
  httpGet: { path: /readyz, port: 9233 }
  periodSeconds: 10
```

Give the startup probe headroom: with the default `[spend] cache_proving_key = true`,
zecd builds the Orchard proving key at startup, before the health listener binds. The
clean keygen costs about 4.5 s single-threaded (see `docs/PROVING_KEY_CACHE.md`), so
`/healthz` is not answerable for the first seconds of process life. After a restore or an
upgrade with a long offline gap, prefer `readiness = "connected"` or a generous
readiness budget; in `"synced"` mode a catching-up wallet is 503 until it reaches the tip.

## Allocator: why the images use mimalloc-secure

Both images build with `--features mimalloc-secure`. The static-musl binaries would
otherwise use musl's default allocator, which serializes on a lock under Orchard proving's
multi-threaded allocation churn: roughly 80x more futex syscalls per proof than mimalloc,
measured as about a 10% cost per shielded send on bare metal and several times worse in
syscall-expensive sandboxes (gVisor, nested virtualization, some CI). The `-secure`
variant adds heap hardening (guard pages, canary free-lists) for under 4% on the proving
path, recovering mitigations that replacing musl's hardened allocator would otherwise
drop. Mechanism and A/B numbers are in `benchmarks/orchard-libc-bench/FINDINGS.md`. Native
glibc builds (from source, outside the images) do not need the feature; glibc's allocator
already scales.
