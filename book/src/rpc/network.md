# Network

zecd has no P2P layer: its only network relationship is the single [Zebra upstream](../design/zebra-backend.md) it derives chain data from. The four network RPCs exist for client compatibility and report that upstream as if it were the node's one peer. Envelope, auth, and error conventions are on the [RPC conventions page](index.md).

## getnetworkinfo

```
getnetworkinfo
```

Returns zecd's version and identity in Bitcoin Core's `getnetworkinfo` shape. The P2P-specific fields are present but inert.

**Result**

```json
{
  "version": 100,
  "subversion": "/zecd:0.1.0/",
  "protocolversion": 170100,
  "localservices": "0000000000000000",
  "localservicesnames": [],
  "localrelay": false,
  "timeoffset": 0,
  "networkactive": true,
  "connections": 1,
  "connections_in": 0,
  "connections_out": 1,
  "networks": [],
  "relayfee": 0.00001000,
  "incrementalfee": 0.00001000,
  "localaddresses": [],
  "warnings": ""
}
```

- `version`: zecd's own version in Core's numeric encoding (`major*10000 + minor*100 + patch`, derived from the crate version; `0.1.0` encodes to `100`).
- `subversion`: `/zecd:<version>/`.
- `protocolversion`: a hardcoded value (`170100`). zecd does not speak the P2P protocol, so this is a static snapshot, not a live number; it does not track zcashd's current `PROTOCOL_VERSION` (`170150`).
- `connections` / `connections_out`: `1` while the Zebra upstream is reachable, else `0`. `connections_in` is always `0`.
- `relayfee` / `incrementalfee`: the ZIP-317 marginal fee (0.00001 ZEC), as decimal ZEC.
- `localservices`, `localservicesnames`, `localrelay`, `timeoffset`, `networks`, `localaddresses`: fixed inert values (no P2P stack behind them). `networkactive` is always `true`.
- `warnings`: always the empty string.

**vs Bitcoin Core**: same field set and types, but every P2P-derived value is synthetic: `connections*` count the single upstream, `networks`/`localaddresses` are empty, and `warnings` uses the legacy string form (Core master returns an array unless started with `-deprecatedrpc=warnings`). Core's `version`/`subversion` describe bitcoind; zecd reports its own.

**vs zcashd**: zcashd's `getnetworkinfo` reports a real P2P node (peer counts, per-network reachability, proxy settings). Same method name, so version-probing clients work unchanged against zecd.

## getconnectioncount

```
getconnectioncount
```

Returns `1` while the Zebra upstream is reachable, `0` otherwise. Always agrees with the length of `getpeerinfo`.

**Result**

```json
1
```

**vs Bitcoin Core**: identical shape; Core counts P2P peers, zecd counts its one chain upstream.

**vs zcashd**: same as Core: a real P2P connection count.

## getpeerinfo

```
getpeerinfo
```

Returns the Zebra upstream as the single "peer", or an empty array while it is unreachable (bitcoind's shape for a node with no peers).

**Result**

```json
[
  {
    "id": 0,
    "addr": "zebra-rpc 127.0.0.1:8234",
    "inbound": false,
    "conn_state": "ready",
    "syncing": false
  }
]
```

- `addr`: the resolved `[backend] server` endpoint, rendered as `zebra-rpc <host>:<port>`.
- `conn_state` (zecd extension): the upstream connection state, `syncing` or `ready`. (The third state, `down`, never appears here: a down upstream yields the empty array instead. All three states also ride on the `/status` health endpoint.)
- `syncing` (zecd extension): `true` while the block scan is behind the tip **or** the post-scan [transaction-enhancement backlog](../design/architecture.md) is still draining, so it agrees with `conn_state` and with `getblockchaininfo.initialblockdownload`.

**vs Bitcoin Core**: Core emits several dozen fields per peer (`pingtime`, `bytessent`, version handshake data, ban score, and so on); zecd emits only the five above. `id`/`addr`/`inbound` keep their Core meaning; `conn_state` and `syncing` are extensions.

**vs zcashd**: zcashd returns its real P2P peer list. No shielded-specific equivalent exists; monitor zecd's sync progress via `getpeerinfo.syncing`, `getwalletinfo`, or the [health endpoints](../guide/operations.md).

## ping

```
ping
```

A liveness no-op. There is no P2P peer to ping; the call succeeds immediately with a `null` result.

**Result**

```json
null
```

**vs Bitcoin Core**: Core queues a protocol ping to every peer and reports the round-trip in `getpeerinfo.pingtime`; the `null` result is identical. zecd measures nothing.

**vs zcashd**: same as Core (real P2P ping). Use zecd's `ping` only as an "is the RPC server up" probe; `/healthz` is the better tool for that.
