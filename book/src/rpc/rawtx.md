# Raw transactions

Reference for `getrawtransaction` and `sendrawtransaction`. `getrawtransaction` serves any
transaction by txid, from the wallet's own store when it has the raw bytes and otherwise from
the [Zebra upstream](../design/zebra-backend.md); its verbose form is zcashd's `TxToJSON`
shape, not Bitcoin Core's. `sendrawtransaction` broadcasts
caller-built bytes through Zebra. For the wire format, auth, and multiwallet `/wallet/<name>`
routing, see [Conventions & wire format](index.md); for building and sending transactions
from the wallet itself, see [Sending](sending.md).

## getrawtransaction

```
getrawtransaction "txid" ( verbose "blockhash" )
```

Returns the raw transaction with the given txid: a hex string by default, a decoded JSON
object when `verbose` is truthy. Lookup order: the wallet DB's stored raw bytes first
(present for transactions the wallet created or has enhanced), then a fetch from Zebra. So
any transaction Zebra can serve is retrievable, not only wallet transactions. The third
Bitcoin Core parameter, `blockhash`, is rejected: a light client has no block index to scope
the lookup to.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | txid | string | required | Transaction id, 64 hex characters (display order). |
| 2 | verbose | boolean or number | false | Bitcoin Core passes a boolean, zcashd an integer; both are accepted. Any nonzero integer means verbose. |
| 3 | blockhash | string | must be unset | Rejected with `-8` if present and non-null. |

**Result (verbose omitted or false)**

```json
"050000800a27a726b4d0d6c2000000006df32c00..."
```

The conformance suite asserts this equals `gettransaction`'s `hex` field for wallet
transactions (see [Wallet: history](wallet-history.md)).

**Result (verbose)** for a mined v5 transaction with an Orchard bundle (hex strings
truncated here with `...`; real responses carry full values):

```json
{
  "txid": "3d21f0b1a9c8e7d6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2",
  "authdigest": "8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b",
  "size": 4180,
  "overwintered": true,
  "version": 5,
  "versiongroupid": "26a7270a",
  "locktime": 0,
  "expiryheight": 2913040,
  "vin": [],
  "vout": [],
  "valueBalance": 0.00000000,
  "valueBalanceZat": 0,
  "vShieldedSpend": [],
  "vShieldedOutput": [],
  "orchard": {
    "actions": [
      {
        "cv": "2f8e...",
        "nullifier": "c41a...",
        "rk": "77b2...",
        "cmx": "0e5d...",
        "ephemeralKey": "a93c...",
        "encCiphertext": "f012...",
        "outCiphertext": "5be7...",
        "spendAuthSig": "d84f..."
      }
    ],
    "valueBalance": 0.00010000,
    "valueBalanceZat": 10000,
    "flags": {
      "enableSpends": true,
      "enableOutputs": true
    },
    "anchor": "31d6...",
    "proof": "9a02...",
    "bindingSig": "6cc1..."
  },
  "hex": "050000800a27a726b4d0d6c2...",
  "height": 2912990,
  "confirmations": 11,
  "blockhash": "0000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819aabbcc",
  "time": 1751598912,
  "blocktime": 1751598912
}
```

Field notes:

- Core fields `txid`, `size`, `version`, `locktime`, `vin`, `vout`, `hex` are as in
  Bitcoin Core. The segwit-only `hash`/`vsize`/`weight` are absent (no Zcash equivalent).
- `authdigest`, `overwintered` always present; `versiongroupid` and `expiryheight` only on
  Overwinter+ (v3+) transactions.
- `vin` entries: `txid`, `vout`, `scriptSig{asm, hex}`, `sequence`; a coinbase input is
  `{coinbase, sequence}`. Signature pushes in `scriptSig.asm` render with their sighash type
  decoded (`<sig>[ALL]`), as in zcashd.
- `vout` entries: `value` (decimal ZEC, 8 places), `valueZat` and `valueSat` (zcashd's two
  zatoshi aliases), `n`, `scriptPubKey{asm, hex, type}` plus `reqSigs`/`addresses` for
  standard scripts (absent for `nulldata`/`nonstandard`, matching zcashd).
- The Sapling section (`valueBalance`, `valueBalanceZat`, `vShieldedSpend`,
  `vShieldedOutput`, and `bindingSig` when a bundle exists) is present on v4+ transactions,
  empty-with-zero-balance when the transaction carries no Sapling bundle, and omitted below
  v4. Spend/output descriptions carry the zcashd field set (`cv`, `anchor`, `nullifier`,
  `rk`, `proof`, `spendAuthSig`; `cmu`, `ephemeralKey`, `encCiphertext`, `outCiphertext`).
- `orchard` is present on v5 transactions (empty `actions` with zero balance when there is
  no bundle). A positive `valueBalance` is net value leaving the pool; for a fully-shielded
  Orchard-to-Orchard send with no transparent outputs it equals the ZIP-317 fee (a
  transparent recipient adds its amount on top).
- `height` and `confirmations` appear when the mined height is known (from the wallet record
  or from Zebra); `confirmations` counts from the wallet's fully-scanned height.
  `blockhash`/`time`/`blocktime` come from the wallet's scanned-blocks table and are omitted
  when the block is outside the wallet's scan range. An unmined
  mempool transaction carries none of these fields.

**Errors**

| Code | When |
|------|------|
| -1 | `txid` omitted |
| -8 | `txid` is not 64 hex characters (Core's `ParseHashV` messages), or `blockhash` is set |
| -3 | `verbose` is neither boolean nor integer |
| -5 | Neither the wallet nor Zebra knows the txid ("No such mempool or blockchain transaction") |
| -22 | The raw bytes fail to parse as a transaction ("TX decode failed: ...", verbose only) |

**vs Bitcoin Core**: Core master's second parameter is `verbosity` (0/1/2, with 2 adding fee
and prevout data); zecd has only the hex/verbose split and no level 2. Core's `blockhash`
parameter is rejected here. The verbose shape is zcashd's, not Core's: shielded bundle
fields, `valueZat`/`valueSat`, `height`, and `authdigest` are additive; `hash`, `vsize`,
`weight`, and `in_active_chain` are absent. Core without `-txindex` only serves mempool
transactions; zecd serves anything in its wallet store plus anything Zebra returns. zecd's
`-5` message is the bare `No such mempool or blockchain transaction` (zcashd's exact line);
Core master varies the base text by `-txindex` state and always appends `. Use gettransaction
for wallet transactions.`, which zecd does not.

**vs zcashd**: the verbose object is zcashd's `TxToJSON` shape, field for field.
Differences: zcashd supports the `blockhash` argument and zecd rejects it; zcashd's
`verbose` is an integer while zecd also accepts a boolean; zcashd's block fields come from
its full block index, zecd's from the wallet's scan range.

## sendrawtransaction

```
sendrawtransaction "hexstring" ( maxfeerate )
```

Broadcasts caller-built raw transaction bytes to the network through Zebra and returns the
txid. The bytes are parsed first (an undecodable transaction is `-22`, and parsing yields the
txid to return). Resubmission of a transaction already in Zebra's mempool succeeds
idempotently, as in Bitcoin Core. Unlike wallet sends, a caller-supplied transaction that
does not spend the wallet's own notes is not backed by zecd's rebroadcast loop, so every
failure (transport or rejection) surfaces as an error rather than being retried silently.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | hexstring | string | required | The serialized transaction, hex-encoded. |
| 2 | maxfeerate | any | ignored | Accepted for Bitcoin Core arity compatibility, ignored: fees are [ZIP-317](sending.md) and a shielded transaction's fee is not computable from its serialization alone. |

**Result**

```json
"3d21f0b1a9c8e7d6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2"
```

**Errors**

| Code | When |
|------|------|
| -1 | `hexstring` omitted; or the upstream is unreachable / the broadcast fails in transport |
| -22 | The hex does not decode to a transaction ("TX decode failed") |
| -26 | Zebra examined and rejected the transaction ("transaction rejected (code N): reason") |
| -27 | The transaction is already mined ("Transaction outputs already in utxo set", Core's exact message) |

**vs Bitcoin Core**: same signature and result. Core enforces `maxfeerate` (default 0.10
BTC/kvB) and rejects high-fee transactions with `-25`; zecd ignores the parameter entirely.
The `-22`/`-26`/`-27` mapping and the already-in-mempool-is-success behavior match Core's
contract.

**vs zcashd**: zcashd's second parameter is `allowhighfees` (boolean); zecd's second
positional slot accepts it but ignores it either way. Result and error family are the same.

**Example**

```sh
curl -u user:pass -d '{"jsonrpc": "1.0", "id": "z", "method": "sendrawtransaction",
  "params": ["050000800a27a726b4d0d6c2..."]}' http://127.0.0.1:8232/
```
