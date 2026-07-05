# A Zebra-only backend

zecd talks to exactly one upstream: a self-hosted [Zebra](https://github.com/ZcashFoundation/zebra)
full node, over its stock JSON-RPC. There is no lightwalletd and no zaino in the stack. This page
explains why, what zecd derives from the node itself, and the connection and security model of
that one hop.

## Why one full node and nothing else

zecd holds spend authority. Its entire view of the chain (balances, confirmations, incoming
payments) is whatever its upstream serves it, so the upstream is the trust root, and the design
goal is to make that trust root exactly one thing you run yourself: `zebra -> zecd`, two
processes, one compose file (see [deployment](../guide/deployment.md)).

Light-client infrastructure exists to serve *many remote wallets* from *someone else's* node:
lightwalletd and zaino sit in front of a full node and re-serve compact blocks over gRPC to
phones. zecd is the opposite shape: a single wallet server co-located with its own node. Putting
lightwalletd or zaino between them would add a second daemon to deploy, monitor, and upgrade, a
second failure domain, and a second codebase inside the trust boundary, in exchange for a data
transformation zecd can do itself. So it does: everything a light-client server would provide
(compact blocks, tree state, mempool visibility) is derived in-process from Zebra's existing
RPCs.

The abstraction that keeps this a choice rather than a hard wire is the `ChainSource` trait
(`src/chain/mod.rs`): the sync engine, reorg recovery, rebroadcast loop, and 0-conf mempool flow
are all generic over it. `AnySource` is today a single-variant enum holding `ZebraSource`; a
future backend (an embedded zaino service, say) is one more variant and one more impl, with no
changes above the trait.

## What zecd derives from Zebra's RPC

Each `ChainSource` operation maps onto the same node RPCs lightwalletd itself uses
(`src/chain/zebra.rs`):

| Operation | Zebra JSON-RPC |
|---|---|
| `latest_block`, `server_info` | `getblockchaininfo` (height, best hash, `chain`) |
| `compact_block_range` | `getblock verbosity=0` + `getblock verbosity=1` (see below) |
| `tree_state` | `z_gettreestate` (`finalState` hex, repackaged as the protobuf `TreeState`) |
| `subtree_roots` | `z_getsubtreesbyindex` (per pool, from index 0) |
| `broadcast_tx` | `sendrawtransaction` |
| `fetch_tx` | `getrawtransaction verbose=1` |
| `transparent_txids` | `getaddresstxids` (batched addresses, height range) |
| `get_address_utxos` | `getaddressutxos` (batched addresses) |
| `subscribe_mempool` | `getrawmempool` + `getrawtransaction`, polled |

### Compact blocks from `getblock`

Two RPCs per block. `getblock verbosity=0` fetches the raw block by height; zecd parses it with
`zcash_primitives` and extracts the trial-decryption fields per transaction (Sapling
nullifier/cmu/epk, Orchard nullifier/cmx/epk, each with the 52-byte ciphertext prefix), the same
conversion lightwalletd performs. The parsed block's coinbase-claimed height is checked against
the requested height; a mismatch fails the stream. Then `getblock verbosity=1` supplies the
note-commitment-tree sizes from its `trees` field, fetched **by the parsed block's hash**, not by
height, so a reorg between the two calls cannot pair one chain's raw bytes with another chain's
tree sizes.

Genesis is never requested: `zcash_primitives` cannot parse the genesis block (no coinbase
height), so scan ranges never include height 0 and tree-state requests clamp to height 1 or
above.

When a wallet has [transparent support](../guide/transparent.md) enabled, the block stream also
harvests every transparent output from the full block it already fetched, at no extra request;
the wallet matches those against its own addresses to discover transparent receives. Compact
blocks omit transparent inputs and outputs entirely, which is why this rides on the raw block.

### Tree state and subtree roots

`z_gettreestate` provides the commitment-tree frontier at a height (used for wallet birthdays and
`ChainState`); `z_getsubtreesbyindex` provides all completed note-commitment-subtree roots per
shielded pool. Both are repackaged into the same protobuf shapes lightwalletd serves, so
librustzcash's `TreeState::to_chain_state` and `AccountBirthday::from_treestate` work unchanged.

### Mempool

Zebra has no push stream, so `ZebraSource` synthesizes lightwalletd's `GetMempoolStream`
semantics with a poller: every 2 seconds it re-reads `getrawmempool`, fetches each unseen txid
via `getrawtransaction` (deduplicating across polls), and yields the raw bytes. The stream
records the best block hash at subscription time and **closes itself when `getbestblockhash`
changes**. That close is load-bearing: it is the wallet actor's "sync now" signal, so a new block
triggers an immediate scan and a fresh subscription once caught up. Polling trades roughly the
poll interval of latency for the missing push stream; the 0-conf visibility it feeds
(`getunconfirmedbalance`, `listunspent minconf=0`) is described in
[architecture](architecture.md).

### Transparent address queries

For transparent-enabled wallets, librustzcash emits `TransactionsInvolvingAddress` requests to
find *spends* of UTXOs the wallet already holds (and to check ZIP-320 ephemeral addresses).
zecd services them with Zebra's always-on transparent address index: `getaddresstxids` over the
requested height range, one batched call for many addresses. Receive discovery is separate (the
block-scan matcher above); see [transparent support](../guide/transparent.md).

## Connection model

`[backend] server` resolves to a single endpoint (`src/backend.rs`). The token `zebra` (the
default) means `zebra://127.0.0.1:8234` on mainnet and `:18234` on testnet/regtest; point
zebrad's `rpc.listen_addr` there (Zebra ships with RPC disabled, and 8232/18232 are zecd's own
RPC ports). Any explicit `zebra://host:port` or bare `host:port` works. `[zebra]` holds the
node's RPC credentials: a cookie file (re-read on every connect, since zebrad regenerates it at
startup) wins over `rpc_user`/`rpc_password`; nothing set means no auth.

Each wallet actor dials the endpoint itself. The dial (client construction plus one
`getblockchaininfo` round trip) is bounded by `connect_timeout_secs` (default 10). A dead
upstream is retried with exponential backoff and full jitter (`src/backoff.rs`): the wait is
uniform in `[0, min(base * 2^attempt, max)]`, with `reconnect_base_secs` (default 1) and
`reconnect_max_secs` (default 60), resetting after a successful connection. Every unary request
carries a hard 30-second deadline and a 64 MiB response-size cap, so a node that accepts and then
hangs (or floods) cannot stall the sync engine.

The error contract separates transport from application outcomes. An `Err` from any
`ChainSource` method is transport-class: the actor drops the client and the next operation
reconnects. Outcomes the node itself decided ride in `Ok`: a rejected broadcast comes back as a
non-zero `BroadcastOutcome` (surfaced to RPC callers as `-26`), and an unknown txid on
`fetch_tx` is `Ok(None)` (Zebra's `-5` reply), neither of which kills the connection.

Connection state is observable. The resolved endpoint and a `conn_state` of `down`, `syncing`,
or `ready` ride on the wallet's `SyncStatus` and surface in three places: `getpeerinfo` (the
upstream appears as the single "peer", with `conn_state` as an extension field), the health
server's `/status`, and the `/readyz` failure reason. See
[operations](../guide/operations.md).

## Local-only by design: the cleartext-credential gate

The hop to Zebra is plaintext HTTP. That is fine for the intended topology (same host, same
container network) and removes an entire TLS/CA surface from the reproducible build, but it means
the `[zebra]` Basic-auth header would cross the network in the clear. So `ZebraClient::new`
refuses to send credentials to a host that is not local (`host_is_local` in
`src/chain/zebra.rs`), before any network I/O:

- **Loopback** (`127.0.0.1`, `::1`, `localhost`) is always local.
- **Private, non-globally-routable ranges** (RFC1918, link-local, CGNAT, IPv6 unique-local and
  link-local, including their IPv4-mapped forms) count as local by default: the self-hosted
  Docker and LAN norm. Set `[backend] rfc1918_is_local = false` for a strict loopback-only
  posture.
- **Any other hostname fails closed.** The gate does no DNS lookup, so a name like
  `zebra.example.com` is treated as non-local even if it would resolve to a private address.
- A credentialed connect to anything non-local fails at startup with an error naming the
  override: `[backend] allow_remote_cleartext = true` (default `false`). Set it only when the
  hop is secured out of band (an SSH or WireGuard tunnel, a private overlay network).

Connections **without** credentials are always allowed, to any host: chain data is public, and
there is nothing to disclose. This is why the documented Docker stack (hostname `zebra`, no
`[zebra]` auth configured) works unchanged despite the fail-closed hostname rule.

The gate protects the credentials, not the chain data. Trusting a *remote* node with your
wallet's chain view is a separate decision the [threat model](../security/threat-model.md)
argues against regardless of transport.

```toml
[backend]
server = "zebra"              # zebra://127.0.0.1:8234 (mainnet) / :18234 (test/regtest)
connect_timeout_secs = 10
reconnect_base_secs = 1
reconnect_max_secs = 60
rfc1918_is_local = true       # false = loopback-only gate
allow_remote_cleartext = false

[zebra]
# rpc_cookie = "/var/lib/zebra/.cookie"   # wins over user/password
# rpc_user = "..."
# rpc_password = "..."
```

The full key reference is in [configuration](../configuration.md).
