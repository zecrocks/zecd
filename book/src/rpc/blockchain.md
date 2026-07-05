# Blockchain

Reference for the chain-state methods. All five are read-only and answer from the wallet's
sync status and its scanned-blocks table, not from a validator's block index: zecd is a
wallet server in front of a [Zebra node](../design/zebra-backend.md), so its heights are
wallet-scan heights. For the wire format, auth, and multiwallet `/wallet/<name>` routing, see
[Conventions & wire format](index.md).

Two height conventions run through this page:

- `blocks` / `getblockcount` is the **fully-scanned height**: the height up to which balances
  and history are accurate.
- `headers` is the Zebra chain tip zecd knows about.

A syncing wallet therefore reports `blocks < headers`, exactly as bitcoind does during IBD.
`getbestblockhash` and `getblockhash(getblockcount())` both describe the fully-scanned block,
so the classic poller pattern `getblockhash(getblockcount())` always answers and always agrees
with `getbestblockhash` (asserted by the conformance suite). With multiwallet routing, each
wallet reports its own scan height.

## getblockchaininfo

```
getblockchaininfo
```

Chain and sync overview for the routed wallet.

**Result**

```json
{
  "chain": "main",
  "blocks": 2913000,
  "headers": 2913004,
  "bestblockhash": "0000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819aabbcc",
  "difficulty": 1.0,
  "time": 1751599123,
  "mediantime": 1751598700,
  "verificationprogress": 0.999998,
  "initialblockdownload": false,
  "size_on_disk": 0,
  "pruned": false,
  "warnings": ""
}
```

- `chain`: `main`, `test`, or `regtest`.
- `blocks`: fully-scanned height (0 before anything is scanned).
- `headers`: Zebra's chain tip as last seen; equals `blocks` if no tip is known yet.
- `bestblockhash`: hash of the `blocks` block; empty string in the brief window before
  anything has been scanned.
- `difficulty`: stub, always `1.0`. zecd never validates proof of work.
- `time` / `mediantime`: the best scanned block's time and the median time past over the last
  up-to-11 scanned blocks (`mediantime` falls back to `time` near the wallet birthday; both
  fall back to 0 before anything is scanned).
- `verificationprogress`: scan progress in `[0, 1]`.
- `initialblockdownload`: `true` while the block scan is behind the tip **or** the post-scan
  [transaction-enhancement backlog](../design/architecture.md) is nonzero. A wallet that has
  scanned to the tip but is still backfilling memos and full transaction data reports `true`;
  only a wallet ready to serve full history reports `false`.
- `size_on_disk`: stub, always `0`.
- `pruned`: always `false`.
- `warnings`: always `""`.

**vs Bitcoin Core**: same field names and types for everything emitted. Core master
additionally emits `bits`, `target`, `chainwork`, and prune details, which have no light
wallet equivalent; Core master also returns `warnings` as an array of strings unless
`-deprecatedrpc=warnings` is set, while zecd keeps the classic string form. Semantics differ:
Core's `blocks` is validated chain height, zecd's is the wallet's scanned height, and
`initialblockdownload` covers the enhancement backlog as well as the scan.

**vs zcashd**: zcashd has no `initialblockdownload` field; it emits the inverted
`initial_block_download_complete` plus `estimatedheight`, and Zcash-specific
`commitments`, `valuePools`, `upgrades`, and `consensus` blocks that zecd does not. zecd
keeps Bitcoin Core's shape instead.

## getblockcount

```
getblockcount
```

The fully-scanned height: the height at which balances and history are accurate. Returns 0
before anything has been scanned.

**Result**

```json
2913000
```

**vs Bitcoin Core**: same shape; Core returns the validated chain height, zecd the wallet's
scanned height. `getblockhash(getblockcount())` holds on both.

**vs zcashd**: same as the Core comparison; zcashd's `getblockcount` is the validator height.

## getbestblockhash

```
getbestblockhash
```

The hash of the `getblockcount` block, in display (byte-reversed) hex.

**Result**

```json
"0000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819aabbcc"
```

**Errors**

| Code | When |
|------|------|
| -1 | Nothing has been scanned yet ("best block hash not yet known (still syncing)") |

**vs Bitcoin Core**: identical shape; the block it names is the wallet's fully-scanned block,
not the validator tip.

**vs zcashd**: same as the Core comparison.

## getblockhash

```
getblockhash height
```

The hash of the block at `height`, answered from the wallet's scanned-blocks table. The
not-yet-scanned chain tip is also answerable (from the sync status), so a poller that jumps
to `headers` still gets a hash. Any other height outside the wallet's range is `-8`: heights
below the wallet birthday were never scanned (a light wallet holds no blocks there), and
heights between the scanned height and the tip, or beyond the tip, are not yet known.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | height | number | required | Block height. Must be an integer in the wallet's scanned range (or the known tip). |

**Result**

```json
"0000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819aabbcc"
```

**Errors**

| Code | When |
|------|------|
| -1 | `height` omitted |
| -3 | `height` is not an integer ("Block height must be an integer") |
| -8 | `height` is negative, above the representable range, below the wallet birthday, or beyond the known tip ("Block height out of range") |

**vs Bitcoin Core**: same signature, same error taxonomy (missing arg `-1`, wrong type `-3`,
out of range `-8` with Core's exact message). Core answers any height from 0 to the chain
tip; zecd answers only the wallet's scanned range plus the tip, so pre-birthday heights that
Core would serve are `-8` here.

**vs zcashd**: zcashd matches Core's behavior (full range from genesis); the same scan-range
restriction applies against it.

## getblockheader

```
getblockheader "blockhash" ( verbose )
```

Header information for a scanned block, verbose form only. zecd stores compact blocks, which
carry no serialized 80-byte-style header, so only the fields a compact block provides are
present and `verbose=false` is rejected rather than fabricated. The common poller pattern
(walk `nextblockhash` from a checkpoint, read `height`/`confirmations`/`time`) works.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | blockhash | string | required | Block hash, 64 hex characters (display order). |
| 2 | verbose | boolean | true | Must be `true` (or omitted). `false` is `-8`. |

**Result**

```json
{
  "hash": "0000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819aabbcc",
  "confirmations": 4,
  "height": 2912997,
  "time": 1751598912,
  "mediantime": 1751598500,
  "previousblockhash": "00000000027f6e5d4c3b2a19087f6e5d4c3b2a19087f6e5d4c3b2a1908ddeeff",
  "nextblockhash": "00000000039e8d7c6b5a49382716059e8d7c6b5a49382716059e8d7c6b112233"
}
```

- `confirmations` counts from the fully-scanned height (the tip header reports 1).
- `mediantime` is the median time past over the last up-to-11 scanned blocks.
- `previousblockhash` / `nextblockhash` appear only when the neighbor is in the wallet's
  scan range; `nextblockhash` is absent on the scanned tip (Core likewise omits
  `previousblockhash` on genesis and `nextblockhash` on the tip).

**Errors**

| Code | When |
|------|------|
| -8 | `blockhash` is not 64 characters or not hex (Core's `ParseHashV` messages) |
| -8 | `verbose` is `false` ("verbose=false is not supported: a light wallet does not store serialized block headers") |
| -3 | `verbose` is not a boolean |
| -5 | Unknown hash, or a block outside the wallet's scan range ("Block not found") |

**vs Bitcoin Core**: same signature, same `-8`/`-5` errors, and the emitted fields are a
subset of Core's with matching names and semantics. Missing: `version`, `versionHex`,
`merkleroot`, `nonce`, `bits`, `target`, `difficulty`, `chainwork`, `nTx` (a compact-block
wallet never sees them), and the `verbose=false` serialized-header form is rejected. Core
reports `confirmations: -1` for a block off the active chain; zecd never serves fork blocks
at all (they are `-5`).

**vs zcashd**: zcashd's header additionally carries `finalsaplingroot`, `solution`, and the
Equihash `nonce`; the same subset relationship and the same `verbose=false` difference apply.
