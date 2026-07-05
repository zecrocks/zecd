# Utility & control

Address validation, the fee-probe stubs (Zcash fees are [ZIP-317](sending.md), never client-settable), and the daemon control surface. Envelope, auth, and error conventions are on the [RPC conventions page](index.md).

## validateaddress

```
validateaddress "address"
```

Validates any Zcash address kind against the daemon's configured network: transparent P2PKH/P2SH (`t1`/`t3`, `tm`/`t2` on testnet), Sapling (`zs`), and Unified Addresses (`u1`/`utest1`). An address encoded for a different network is reported invalid.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | address | string | required | The address to validate |

**Result** (valid address)

```json
{
  "isvalid": true,
  "address": "utest12r53eljnr7kev8ychw3ahzjgm6fwxm7fd8vfay7hn9uylj05x0pxxhze800h9dcgyr8hkc7kz3s2crnrhjcy2p90yfce2vl8mq667zw0",
  "scriptPubKey": "",
  "isscript": false,
  "iswitness": false,
  "isvalid_orchard": true,
  "receiver_types": ["orchard"]
}
```

**Result** (invalid address)

```json
{
  "isvalid": false,
  "error_locations": [],
  "error": "Invalid or unsupported address format"
}
```

- `scriptPubKey`: the real hex output script for transparent addresses (`76a914...88ac` P2PKH, `a914...87` P2SH). Shielded addresses have no script form, so the field is the empty string.
- `isscript`: `true` for P2SH. `iswitness`: always `false` (Zcash has no segwit).
- `isvalid_orchard` (zecd extension): whether the address can receive into the Orchard pool.
- `receiver_types` (zecd extension): the pools the address can receive into, in canonical order (`transparent`, `sapling`, `orchard`). For a Unified Address this enumerates its receivers, so a client can see what a `u1...` actually carries; a bare t-addr is `["transparent"]`.
- `receivers_consistent` (zecd extension, sometimes present): for a UA with at least two shielded receivers, whether all of them belong to the routed wallet's account at one diversifier index. `true` means a well-formed UA this wallet could have issued; `false` flags a hand-spliced UA (receivers stapled together from different indices, or one of the wallet's mixed with a stranger's). Absent when not computable: a foreign UA (the diversifier index is the owner's secret) or a single-receiver address.
- On invalid input, `error_locations` is always the empty array (no per-character diagnosis).

Ownership is not reported here; use [`getaddressinfo`](wallet-addresses.md) for `ismine`.

**Errors**

| Code | When |
|------|------|
| -1 | address argument missing |
| -3 | address argument present but not a string |

**vs Bitcoin Core**: same base shape, including the `error`/`error_locations` fields on invalid input. Core additionally emits `witness_version`/`witness_program` for segwit addresses (never applicable here) and populates `scriptPubKey` for every valid address (zecd leaves it empty for shielded). `isvalid_orchard`, `receiver_types`, and `receivers_consistent` are zecd extensions.

**vs zcashd**: zcashd splits validation in two: its `validateaddress` accepts only transparent addresses (and mixes in wallet fields like `ismine`/`iswatchonly`), while `z_validateaddress` handles shielded and Unified Addresses with an `address_type` field and per-pool key material. zecd's single `validateaddress` covers every kind, so a valid UA gets `isvalid: true`.

## estimatesmartfee

```
estimatesmartfee conf_target ( estimate_mode )
```

An inert probe-compatibility stub. Zcash fees follow ZIP-317 and are computed at transaction-build time; there is no fee estimator. Returns a stable conventional rate so fee-probing clients succeed.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | conf_target | numeric | 6 | Echoed back as `blocks`; has no effect |
| 2 | estimate_mode | string | ignored | Accepted for arity compatibility, ignored |

**Result**

```json
{
  "feerate": 0.00001000,
  "blocks": 2
}
```

`feerate` is always 0.00001 ZEC (the ZIP-317 marginal fee, as decimal ZEC per the Core convention); `blocks` echoes `conf_target`.

**vs Bitcoin Core**: Core runs a real estimator and may return an `errors` array with no `feerate`; zecd always returns `feerate`. Same success shape.

**vs zcashd**: no equivalent: current zcashd serves neither `estimatesmartfee` nor `estimatefee`.

## estimatefee

```
estimatefee ( nblocks )
```

The legacy single-number fee probe; same inert stub as `estimatesmartfee`. The optional argument is ignored.

**Result**

```json
0.00001000
```

**vs Bitcoin Core**: removed from Core master (only `estimatesmartfee` remains); zecd keeps it because old clients still call it.

**vs zcashd**: no equivalent in current zcashd.

## settxfee

```
settxfee amount
```

Always fails. Fees follow ZIP-317 and are never client-settable; an explicit fee instruction gets a self-diagnosing `-8` (the same treatment as `fee_rate`/`subtractfeefromamount` on the [send RPCs](sending.md)) rather than a silently ignored `true`.

**Errors**

| Code | When |
|------|------|
| -8 | always: "settxfee is not supported: fees follow ZIP-317 (computed at transaction-build time) and are never client-settable" |

**vs Bitcoin Core**: removed from Core master. Historic Core set a wallet-wide fee rate and returned `true`.

**vs zcashd**: zcashd still carries `settxfee`, deprecated but enabled by default (it is not in zcashd's default-deny deprecated set); it sets the legacy pre-ZIP-317 `paytxfee`.

## getmempoolinfo

```
getmempoolinfo
```

Returns a fixed empty-mempool shape. zecd keeps no mempool of its own (it is a wallet server, not a relay node); mempool visibility for the wallet's transactions comes from the [Zebra mempool poller](../design/zebra-backend.md) and surfaces through the wallet RPCs instead. This stub satisfies client preflight checks.

**Result**

```json
{
  "loaded": true,
  "size": 0,
  "bytes": 0,
  "usage": 0,
  "total_fee": 0.00000000,
  "maxmempool": 300000000,
  "mempoolminfee": 0.00001000,
  "minrelaytxfee": 0.00001000
}
```

Every value is constant: an empty but "loaded" pool with the conventional ZIP-317 fee floors and Core's default 300 MB `maxmempool`.

**vs Bitcoin Core**: same first eight fields; Core master adds more (`incrementalrelayfee`, `unbroadcastcount`, and newer policy/cluster fields) and reports live numbers.

**vs zcashd**: zcashd's `getmempoolinfo` reports its real mempool with only `size`/`bytes`/`usage` (plus a regtest-only `fullyNotified`). Query the Zebra node directly for actual Zcash mempool contents.

## stop

```
stop
```

Requests graceful shutdown: in-flight requests finish, new ones get HTTP 503, and the reply reaches the client before exit. **Regtest only.** On mainnet and testnet the method reports method-not-found (`-32601`), so a stray `stop` cannot take down a production daemon over RPC. Stop a live node with a signal instead (SIGINT/SIGTERM; the systemd unit from the `.deb` does this).

**Result**

```json
"zecd stopping"
```

**Errors**

| Code | When |
|------|------|
| -32601 | called on mainnet or testnet (HTTP 404) |

**vs Bitcoin Core**: Core's `stop` works on every network, returns `"Bitcoin Core stopping"`, and accepts a hidden `wait` (milliseconds) test argument; zecd takes no arguments and restricts the method to regtest.

**vs zcashd**: available on every network, returns `"Zcash server stopping"`.

## uptime

```
uptime
```

Seconds since the daemon started.

**Result**

```json
86400
```

**vs Bitcoin Core**: identical.

**vs zcashd**: no equivalent (zcashd does not implement `uptime`).

## help

```
help ( "command" )
```

Returns a static one-line orientation string naming a handful of methods and pointing at the reference documentation. **The `command` argument is accepted but ignored**: there are no per-method help pages, so `help getbalance` returns the same generic blurb as `help`. Tooling that introspects the RPC surface via `help` (as some Bitcoin libraries do) learns nothing useful from zecd; use the [method index](method-index.md) instead.

**Result**

```json
"zecd: a Bitcoin-Core-style JSON-RPC server for Orchard-only Zcash. Supported methods include getblockchaininfo, getnetworkinfo, getwalletinfo, getnewaddress, z_getaddressforaccount, getbalance, sendtoaddress, sendmany, listtransactions, gettransaction, validateaddress. See the README for the full list and limits."
```

**vs Bitcoin Core**: Core's `help` lists every registered command grouped by category, and `help <command>` returns that method's full usage text. This is the one deliberately weak point in zecd's conformance surface.

**vs zcashd**: same behavior as Core (full listing plus per-method help).

## getrpcinfo

```
getrpcinfo
```

Reports the currently-executing RPC commands, Core's load-visibility RPC. Useful for spotting what is holding the [work queue](index.md) during an overload.

**Result**

```json
{
  "active_commands": [
    {
      "method": "sendtoaddress",
      "duration": 2417093
    },
    {
      "method": "getrpcinfo",
      "duration": 12
    }
  ],
  "logpath": ""
}
```

- `active_commands`: one entry per in-flight command; `duration` is the elapsed running time in **microseconds** (Core's unit; easy to misread as milliseconds). The call always lists itself.
- `logpath`: always empty. zecd logs to stderr via `tracing`, not to a `debug.log` file.

**vs Bitcoin Core**: identical shape and semantics; Core's `logpath` is the absolute path to `debug.log`.

**vs zcashd**: no equivalent.
