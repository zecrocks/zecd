# Wallet: history & unspent

Reference for the wallet history and unspent-output methods: `listtransactions`,
`z_listtransactions`, `listsinceblock`, `gettransaction`, and `listunspent`. All five are
read-only: they run on short-lived SQLite connections and never block on the sync loop.

## Shared conventions

These apply to every method on this page.

- **Categories.** Only `send` and `receive` are emitted. A self-transfer (a payment to one of
  the wallet's own external addresses) appears as Bitcoin Core's send + receive pair. True
  change (internal key scope) is hidden from history but still counted in balances and
  `listunspent`. Core's coinbase categories (`generate`/`immature`/`orphan`) never appear.
- **Confirmations** are anchored to the wallet's fully-scanned height, the same height
  `getblockcount` reports, so `getblockcount() - blockheight + 1` agrees with the field. An
  expired unmined transaction reports `-1` (it can never confirm; Core's "conflicted" signal,
  so pollers terminate).
- **`time` / `timereceived`** are the block time once mined. For an unmined transaction they
  are the wall-clock time the wallet first saw it in the mempool, held in a transient
  in-memory map (never persisted; see [statelessness](../design/statelessness.md)), falling
  back to the creation time for wallet-authored sends. After a restart, an unmined foreign
  transaction reports `0` until the mempool stream re-observes it or it mines. The two fields
  are always equal.
- **`memo` / `memoStr`** are extension fields beyond Bitcoin Core's set, using zcashd's
  `z_viewtransaction` names: `memo` is the raw ZIP-302 memo bytes in hex, `memoStr` the
  decoded text when the memo is valid UTF-8 text. Empty or absent memos add neither field.
- **Outgoing `address` is the single receiver actually paid**, not the full Unified Address
  the caller typed. A multi-receiver UA is sender-side metadata that never reaches the chain,
  so history reduces each outgoing output to the paid receiver (a bare `t`/`zs` address, or a
  single-receiver UA for Orchard). This makes history identical on the authoring instance and
  after a restore-from-seed. Received and self-transfer entries keep the wallet's own
  recorded address. See [statelessness](../design/statelessness.md).
- **`label` is always `""`** and `walletconflicts` always `[]`: zecd keeps no address labels
  and tracks no conflict set. `bip125-replaceable` is always `"no"` (Zcash has no RBF).
- Amounts are bare JSON numbers in decimal ZEC, 8 places.

## listtransactions

```
listtransactions ( "label" count skip include_watchonly )
```

The most recent wallet history entries, one entry per non-change output, oldest-to-newest.
Covers shielded notes and (when enabled) transparent outputs in one list.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | label | string | `"*"` | `"*"` or omitted lists everything. Any other value keeps only entries whose label equals it; every zecd entry's label is `""`, so `""` matches everything and any other string matches nothing. |
| 2 | count | numeric | 10 | Number of entries to return. |
| 3 | skip | numeric | 0 | Number of most-recent entries to skip before taking `count`. |
| 4 | include_watchonly | boolean | false | Accepted and ignored (deprecated in Core too). |

**Result**

```json
[
  {
    "address": "u1a7pqnnzcdev3ka5jyv2q0kag0k8qvyw2s0z1erdhfmwzmp8dip5rk5632cxutlyf6jz062cu5qnkcs2857vy0mnhxen8993rvxmqedqu",
    "category": "receive",
    "amount": 1.25000000,
    "label": "",
    "vout": 0,
    "confirmations": 12,
    "txid": "8ab1c74952e723459d5e18b975bff21af07a90ba1eec368bcb2d3d6d7b0e0c17",
    "bip125-replaceable": "no",
    "memo": "696e766f6963652034322070616964",
    "memoStr": "invoice 42 paid",
    "blockhash": "0000000001d4f81c8494ba9cd02c0ea936f1ba52e6a186a538d3c3e2ab5b91f7",
    "blockheight": 2914301,
    "blockindex": 1,
    "blocktime": 1751581200,
    "walletconflicts": [],
    "time": 1751581200,
    "timereceived": 1751581200
  },
  {
    "address": "u1v40svyy8lqhy4gyq5vysyz39yqwf4ypw9zvhqjmwlqk9vqvyfrgc6yz6e2spwwrjxpwyfwjt3u4nrpydp0hnzqge0ptr9y8yavgvpr7ux",
    "category": "send",
    "amount": -0.50000000,
    "label": "",
    "vout": 0,
    "confirmations": 3,
    "txid": "e37b006aa754e982f2c19152fbd80f26e6a3fe9c418b1ce3f5aab3ad4d7e9b52",
    "bip125-replaceable": "no",
    "abandoned": false,
    "fee": -0.00015000,
    "blockhash": "00000000023a1b6d81c62f1c22f0a3e9a83f6de960e60d357ce09b3c73ef14a8",
    "blockheight": 2914310,
    "blockindex": 2,
    "blocktime": 1751583450,
    "walletconflicts": [],
    "time": 1751583450,
    "timereceived": 1751583450
  }
]
```

- Sends are negative (Core's sign convention); `fee` (negative) and `abandoned` appear on
  send entries only. `abandoned` is true for an expired unmined send.
- Mined entries carry `blockhash`/`blockheight`/`blockindex`/`blocktime`; unmined entries
  carry `trusted` instead (true iff the wallet authored the transaction and it can still be
  mined).

**Errors**

| Code | When |
|------|------|
| -8 | Negative `count` or `skip`. |
| -3 | `count`/`skip` not a number. |

**vs Bitcoin Core:** same arguments and paging (`count` most recent after skipping `skip`
from the newest end, returned oldest-first). Entries omit `wtxid` and `parent_descs`;
`abandoned` appears only on send entries (Core master also puts it on receives); categories
are limited to `send`/`receive`; `memo`/`memoStr` are extensions.

**vs zcashd:** zcashd's `listtransactions` covers transparent activity only (shielded
receipts need per-address `z_listreceivedbyaddress`) and adds `amountZat`, `status`, and
`expiryheight` to each entry. zecd lists shielded and transparent activity in one Core-shaped
list; use [`z_listtransactions`](#z_listtransactions) for the zcashd vocabulary.

## z_listtransactions

```
z_listtransactions ( count from includeWatchonly )
```

A zecd extension (no such method exists in zcashd or Bitcoin Core): per-output wallet history
in zcashd's `z_*` vocabulary. Same content as `listtransactions`, different field names, plus
the value pool and zatoshi amounts. Pagination is identical (newest-first cursor,
oldest-first output).

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | count | numeric | 10 | Number of entries to return. |
| 2 | from | numeric | 0 | Number of most-recent entries to skip. |
| 3 | includeWatchonly | boolean | false | Accepted and ignored. |

There is no account or address argument: results span the wallet's single account.

**Result**

```json
[
  {
    "txid": "e37b006aa754e982f2c19152fbd80f26e6a3fe9c418b1ce3f5aab3ad4d7e9b52",
    "status": "mined",
    "confirmations": 3,
    "time": 1751583450,
    "walletconflicts": [],
    "pool": "orchard",
    "category": "send",
    "amount": -0.50000000,
    "amountZat": -50000000,
    "address": "u1v40svyy8lqhy4gyq5vysyz39yqwf4ypw9zvhqjmwlqk9vqvyfrgc6yz6e2spwwrjxpwyfwjt3u4nrpydp0hnzqge0ptr9y8yavgvpr7ux",
    "outindex": 0,
    "change": false,
    "outgoing": true,
    "blockhash": "00000000023a1b6d81c62f1c22f0a3e9a83f6de960e60d357ce09b3c73ef14a8",
    "blockheight": 2914310,
    "blockindex": 2,
    "blocktime": 1751583450,
    "expiryheight": 2914350,
    "fee": -0.00015000,
    "feeZat": -15000
  }
]
```

- `pool` is `transparent`, `sapling`, `orchard`, or `ironwood`. `ironwood` appears once NU6.3
  activates (testnet). Those notes arrive at ordinary Orchard addresses, so `pool` labels the
  note's bundle, not a distinct receiver. See
  [Addresses & shielded pools](../guide/addresses.md).
- `status` is `mined`, `waiting`, or `expired`. zcashd's fourth value `expiringsoon` is never
  emitted.
- `amountZat` is an integer (zatoshis), negative on sends; `outgoing` is true on the send
  side of a self-transfer pair.
- `change` is always `false` (change outputs are filtered before this point; the key is kept
  for shape compatibility with zcashd's `walletInternal`/`change` convention).
- `expiryheight` appears when the transaction has a non-zero expiry; `fee`/`feeZat`
  (negative) on send entries only; `memo`/`memoStr` on shielded outputs as elsewhere.

**Errors**

| Code | When |
|------|------|
| -8 | Negative `count` or `from`. |
| -3 | `count`/`from` not a number; `includeWatchonly` not a boolean. |

**vs Bitcoin Core:** no equivalent; this is the zcashd-vocabulary view of the same history
`listtransactions` serves.

**vs zcashd:** zcashd has no `z_listtransactions`. The entry shape borrows from
`z_listreceivedbyaddress` (`pool`/`amount`/`amountZat`/`memo`/`memoStr`/`outindex`/`change`/
block fields), `z_viewtransaction` (`outgoing`), and zcashd's per-transaction
`status`/`expiryheight`. Unlike `z_listreceivedbyaddress` it is not per-address and includes
sends; unlike `z_viewtransaction` it is a flat paged list, not a per-transaction
spends/outputs breakdown.

## listsinceblock

```
listsinceblock ( "blockhash" target_confirmations include_watchonly include_removed )
```

The restart-safe payment poller: every wallet transaction in blocks after `blockhash` (plus
all unmined transactions), and a `lastblock` cursor to feed into the next call.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | blockhash | string | omitted | List activity since this block (exclusive). Omitted or `""` lists everything. |
| 2 | target_confirmations | numeric | 1 | Which depth's block hash to return as `lastblock` (must be >= 1). Not a filter. |
| 3 | include_watchonly | boolean | false | Accepted and ignored. |
| 4 | include_removed | boolean | true | Accepted and ignored; `removed` is always `[]`. |

**Result**

```json
{
  "transactions": [],
  "removed": [],
  "lastblock": "0000000001d4f81c8494ba9cd02c0ea936f1ba52e6a186a538d3c3e2ab5b91f7"
}
```

`transactions` entries have exactly the `listtransactions` shape (no label filter applies).
`removed` is always empty: reorged-away transactions are rescanned and re-reported by the
sync engine rather than tracked separately. `lastblock` is the hash of the block that
currently has `target_confirmations` confirmations, anchored to the fully-scanned height;
when the requested depth predates the wallet's scan range it falls back to the earliest
scanned block, and a wallet with nothing scanned returns the all-zero hash.

**Cursor semantics after a reorg.** zecd keeps only the current chain's scanned blocks, so it
cannot walk a stale cursor back to the fork point the way Bitcoin Core's
`findCommonAncestor` does. Instead, a **well-formed** 64-hex hash that is not among the
wallet's scanned blocks (a reorged-away cursor, or one below the wallet birthday) is treated
as "since the earliest scanned block": everything is listed. A lower cursor only ever
re-reports, never misses, so the poller self-heals instead of wedging. Only a **malformed**
hash, which can never be a cursor zecd handed out, is a `-5 Block not found`. Consequence for
integrators: process `listsinceblock` output idempotently, keyed by `txid`. A
`target_confirmations` of, say, 6 keeps re-reporting transactions until they reach 6
confirmations, which is the intended Core usage pattern and absorbs the re-baseline case for
free.

**Errors**

| Code | When |
|------|------|
| -5 | `blockhash` is not a 64-character hex string ("Block not found"). |
| -8 | `target_confirmations` is not an integer >= 1. |

**vs Bitcoin Core:** same cursor pattern and `lastblock` semantics. Core walks a stale hash
back to the fork point and can populate `removed`; zecd re-baselines to the earliest scanned
block and keeps `removed` always `[]`. Core master's two extra positional arguments
(`include_change`, `label`) exceed zecd's four-argument arity and are rejected with `-1`.

**vs zcashd:** zcashd's `listsinceblock` is the inherited transparent-only Bitcoin method;
zecd's covers shielded activity too and adds the reorg re-baseline behavior above.

## gettransaction

```
gettransaction "txid" ( include_watchonly verbose )
```

Detailed information on one wallet transaction: net `amount`, per-output `details`, and the
raw `hex`.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | txid | string | required | The transaction id (display hex). |
| 2 | include_watchonly | boolean | false | Accepted and ignored. |
| 3 | verbose | boolean | false | Accepted and ignored; no `decoded` field is ever emitted (use `getrawtransaction <txid> 1`). |

**Result**

```json
{
  "amount": -0.50000000,
  "fee": -0.00015000,
  "confirmations": 3,
  "txid": "e37b006aa754e982f2c19152fbd80f26e6a3fe9c418b1ce3f5aab3ad4d7e9b52",
  "bip125-replaceable": "no",
  "details": [
    {
      "address": "u1v40svyy8lqhy4gyq5vysyz39yqwf4ypw9zvhqjmwlqk9vqvyfrgc6yz6e2spwwrjxpwyfwjt3u4nrpydp0hnzqge0ptr9y8yavgvpr7ux",
      "category": "send",
      "amount": -0.50000000,
      "vout": 0,
      "label": "",
      "abandoned": false,
      "fee": -0.00015000
    }
  ],
  "hex": "050000800a27a726b4d0d6c2...",
  "blockhash": "00000000023a1b6d81c62f1c22f0a3e9a83f6de960e60d357ce09b3c73ef14a8",
  "blockheight": 2914310,
  "blockindex": 2,
  "blocktime": 1751583450,
  "walletconflicts": [],
  "time": 1751583450,
  "timereceived": 1751583450
}
```

- `amount` is fee-exclusive, per Core: for a wallet-funded transaction it is the negated sum
  of payments (the balance delta with the fee added back); for a pure receive it is the
  received amount; a self-transfer nets to `0`.
- `fee` (negative) appears only when the wallet funded the transaction. librustzcash records
  a derived fee even on pure receives, but zecd gates the field on the balance-delta signal
  so a deposit is never reported with a fee the wallet did not pay.
- `details` has one entry per non-change output and category, with the `listtransactions`
  entry shape minus the per-transaction fields (`confirmations`, `txid`, times), which sit at
  the top level. `memo`/`memoStr` appear per detail entry.
- `hex` is the stored raw transaction when the wallet has it (wallet-authored sends, and
  receives stored via the mempool stream or the enhancement pass). For a transaction the
  wallet only ever saw as a compact block, the bytes are fetched on demand from the Zebra
  upstream. The fetch is best-effort: an unreachable upstream yields `""`, not an error.
- Mined/unmined block fields and `trusted` follow the shared conventions above.

**Errors**

| Code | When |
|------|------|
| -5 | Unknown or non-wallet txid ("Invalid or non-wallet transaction id", Core's message). |

**vs Bitcoin Core:** same top-level shape; omits `wtxid`, `parent_descs`, `generated`,
`comment`, and (since `verbose` is ignored) `decoded`. `fee` appears only on wallet-funded
transactions, as in Core. `details` entries add `memo`/`memoStr`.

**vs zcashd:** zcashd's `gettransaction` reports the transparent parts and defers shielded
detail to `z_viewtransaction`. zecd's `details` cover shielded outputs (with memos) directly;
there is no separate `z_viewtransaction`.

## listunspent

```
listunspent ( minconf maxconf ["address",...] include_unsafe query_options )
```

The wallet's unspent funds in Bitcoin Core's UTXO shape: every unspent shielded note (all
enabled pools) plus, for transparent-enabled wallets, every unspent transparent UTXO.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | minconf | numeric | 1 | Minimum confirmations. `0` includes unconfirmed outputs fed by the mempool stream. |
| 2 | maxconf | numeric | 9999999 | Maximum confirmations. |
| 3 | addresses | array | none | Keep only outputs received on these addresses. Each entry must be a valid address (`-5`); duplicates are `-8`. |
| 4 | include_unsafe | boolean | true | Include outputs not safe to spend (see `safe` below). |
| 5 | query_options | object | none | Accepted and **ignored**: Core's `minimumAmount`/`maximumAmount`/etc. have no effect on the result. |

**Result**

```json
[
  {
    "txid": "8ab1c74952e723459d5e18b975bff21af07a90ba1eec368bcb2d3d6d7b0e0c17",
    "vout": 0,
    "address": "u1a7pqnnzcdev3ka5jyv2q0kag0k8qvyw2s0z1erdhfmwzmp8dip5rk5632cxutlyf6jz062cu5qnkcs2857vy0mnhxen8993rvxmqedqu",
    "amount": 1.25000000,
    "confirmations": 12,
    "spendable": true,
    "solvable": true,
    "safe": true
  }
]
```

- **Synthesized outpoints for notes.** Shielded notes are not bitcoin-style outpoints, so
  `(txid, vout)` is synthesized: `vout` is the note's index within its pool's bundle (the
  Sapling output index or the Orchard action index). It identifies the note stably but cannot
  be fed to raw-transaction spending. Transparent UTXOs carry their real `(txid, vout)` and a
  bare t-address.
- `address` is the receiving diversified address when the wallet recorded one. Change and
  internal notes report `""`, which an `addresses` filter never matches, so a filtered call
  naturally excludes change.
- `safe` is `true` for confirmed outputs and for unconfirmed outputs whose creating
  transaction the wallet itself authored (its own change); a foreign output surfaced at
  0-conf by the mempool stream is `safe: false`. `include_unsafe: false` hides those.
- `spendable` and `solvable` are always `true`. They are nominal: whether a send can actually
  select an output is governed by the wallet's confirmations policy (`[spend]`
  `trusted_confirmations`/`untrusted_confirmations`, ZIP-315 defaults 3/10), so an entry with
  1 confirmation can appear here while a send still returns `-6` until it reaches policy
  depth (see [Sending](sending.md)). A transparent UTXO is additionally spendable only under
  the `AllowFullyTransparent` [privacy policy](../design/privacy.md); under the default
  policy it is receive-only (see [Transparent support](../guide/transparent.md)).

**Errors**

| Code | When |
|------|------|
| -5 | Invalid address in the `addresses` filter. |
| -8 | Duplicated address in the filter. |
| -3 | `minconf`/`maxconf` not a number; `addresses` not an array of strings; `include_unsafe` not a boolean. |

**vs Bitcoin Core:** same arguments and filtering; entries omit `label`, `scriptPubKey`,
`redeemScript`, `desc`, and `parent_descs` (shielded notes have no script form).
`query_options` is accepted but has no effect, where Core applies `minimumAmount` and
friends. The synthesized note outpoints are the largest semantic difference; see
[Compatibility boundary](../compatibility.md).

**vs zcashd:** zcashd splits this surface into `listunspent` (transparent) and
`z_listunspent` (shielded, with `pool`/`outindex`/`memo`/`change` per note). zecd merges both
into one Core-shaped list; for pool and memo detail use
[`z_listtransactions`](#z_listtransactions).
