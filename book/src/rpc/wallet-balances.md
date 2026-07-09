# Wallet: balances

Reference for the balance and received-by-address methods. All five are read-only: they run
on short-lived SQLite connections that bypass the wallet actor, so they never block on a sync
or an in-flight send. For the wire format, auth, and multiwallet `/wallet/<name>` routing, see
[Conventions & wire format](index.md).

Balances aggregate every pool the wallet holds funds in: Orchard, Sapling, Ironwood (once NU6.3
activates; those notes arrive at ordinary Orchard addresses, so no extra receiver is involved),
and (when [transparent receiving](../guide/transparent.md) is enabled) transparent UTXOs. Amounts
are bare JSON numbers in decimal ZEC, 8 places, exact (no float drift).

## getbalance

```
getbalance ( "*" minconf include_watchonly avoid_reuse )
```

Returns the wallet's spendable balance. With no `minconf`, spendability follows the wallet's
configured confirmations policy (ZIP-315 defaults: 3 confirmations for trusted notes such as
your own change, 10 for third-party receipts; `[spend] trusted_confirmations` /
`untrusted_confirmations` in the [configuration](../configuration.md)). The no-argument result
therefore always equals what a send can actually spend, and agrees with the `-6` insufficient
funds accounting on the send methods.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | dummy | string | omitted | Legacy account argument. Must be excluded, `null`, or `"*"`; any other string is `-32`. |
| 2 | minconf | number | wallet policy | Overrides both policy bounds symmetrically: count a note spendable at `minconf` confirmations regardless of trust. Values below 1 (including 0) are served as 1: a shielded note is never spendable unmined. |
| 3 | include_watchonly | any | ignored | Accepted for Bitcoin Core arity compatibility, ignored. |
| 4 | avoid_reuse | any | ignored | Accepted for Bitcoin Core arity compatibility, ignored. |

Because the default policy is stricter than any single `minconf`, `getbalance "*" 1` is always
greater than or equal to `getbalance`.

**Result**

```json
1.25000000
```

**Errors**

| Code | When |
|------|------|
| -32 | `dummy` is a string other than `"*"` |
| -3 | `dummy` is a non-string, or `minconf` is not a number |

**vs Bitcoin Core**: same signature and the same `-32` with the identical message for a bad
`dummy`. Core's `minconf` defaults to 0 and its no-argument result is the trusted balance;
zecd's default is the ZIP-315 policy, and `minconf` 0 is served as 1. `include_watchonly` and
`avoid_reuse` are ignored (Core master also ignores `include_watchonly`).

**vs zcashd**: zcashd's `getbalance` is transparent-only; its shielded balances live in
`z_gettotalbalance` / `z_getbalanceforaccount`. zecd's `getbalance` is the account-wide
spendable total across all pools, so it is closer to `z_getbalanceforaccount` than to zcashd's
`getbalance`. zcashd also accepts `""` for the dummy and rejects a bad one with `-8`, and has
extra `inZat` / `asOfHeight` arguments that zecd does not.

## getbalances

```
getbalances
```

Returns the Bitcoin Core 0.19+ balance object. Everything reports under `mine`, including on
a [watch-only](../guide/watch-only.md) (UFVK) wallet: like Core's descriptor wallets, the
addresses are the wallet's own and only signing is impossible, so there is no `watchonly`
object.

**Result**

```json
{
  "mine": {
    "trusted": 1.25000000,
    "untrusted_pending": 0.10000000,
    "immature": 0.05000000
  },
  "lastprocessedblock": {
    "hash": "00000000012f2e9d7a9ba447d1da6a2c31ec26bd8d0a55a259d3ab1741e5cdcc",
    "height": 2412345
  }
}
```

- `trusted`: spendable under the wallet's confirmations policy; equals `getbalance`.
- `untrusted_pending`: received but not yet spendable under the policy; equals
  `getunconfirmedbalance`. Incoming 0-conf payments seen by the mempool stream land here.
- `immature`: change awaiting confirmation (zecd has no mining, so this is not coinbase
  maturity as in Core; unconfirmed change from your own sends reports here).
- `lastprocessedblock` (Core 26+): the fully-scanned block the balances are anchored to, the
  same anchor as `getblockcount`. Omitted while the wallet has not yet scanned a block.

**vs Bitcoin Core**: same shape minus Core master's `mine.nonmempool` and the optional
`mine.used` (zecd has no avoid-reuse flag). Core's legacy `watchonly` object is likewise gone
from Core master; zecd never emits it.

**vs zcashd**: no equivalent. The nearest is `z_gettotalbalance`, which splits
`transparent`/`private`/`total` rather than trusted/pending.

## getunconfirmedbalance

```
getunconfirmedbalance
```

Returns value received but not yet spendable under the wallet's confirmations policy, across
all pools. Identical to `getbalances.mine.untrusted_pending`. An incoming payment appears here
at 0 confirmations via the mempool stream, before its funding block is scanned.

**Result**

```json
0.10000000
```

**vs Bitcoin Core**: removed in Core 30.0 (its release notes point callers at
`getbalances.mine.untrusted_pending`). zecd keeps it for older clients; prefer `getbalances`
in new code.

**vs zcashd**: exists, but returns the unconfirmed transparent balance only; zecd's spans
shielded pools too.

## getreceivedbyaddress

```
getreceivedbyaddress "address" ( minconf include_immature_coinbase )
```

Returns the total received by one of the wallet's own addresses, summed over transactions
with at least `minconf` confirmations. Internal change is not counted; a payment to one of
the wallet's own external addresses is.

Matching is whole-string equality on the address, not receiver-level: round-tripping the
exact value `getnewaddress` returned always works and sums receipts across all of that UA's
receivers (they share one diversifier index). A different UA that merely shares a receiver,
or a re-encoding with a different receiver subset, is a different string and contributes
nothing. A spliced UA (this wallet's receivers combined across diversifier indices, or mixed
with a stranger's) is rejected with `-5` rather than silently treated as foreign.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | address | string | required | An address belonging to this wallet (UA or bare transparent). |
| 2 | minconf | number | 1 | Count only transactions with at least this many confirmations. 0 includes unmined receipts. Expired or conflicted transactions report -1 confirmations and are never counted at `minconf` >= 0. |
| 3 | include_immature_coinbase | any | ignored | Accepted for Bitcoin Core arity compatibility, ignored. |

Unlike `getbalance`, `minconf` 0 is meaningful here: this method totals receipts, not
spendability.

**Result**

```json
0.50000000
```

**Errors**

| Code | When |
|------|------|
| -5 | Address does not parse for this network |
| -5 | Spliced/inconsistent Unified Address |
| -4 | Valid address that does not belong to this wallet (`Address not found in wallet`) |
| -3 | Non-numeric `minconf` |

**vs Bitcoin Core**: same signature, same `-4 Address not found in wallet` for a foreign
address. `include_immature_coinbase` is ignored (zecd wallets hold no coinbase).

**vs zcashd**: zcashd's `getreceivedbyaddress` covers transparent addresses only; shielded
receipts are enumerated per-note by `z_listreceivedbyaddress` (a list, not a total). zcashd's
extra `inZat` / `asOfHeight` arguments do not exist in zecd.

## listreceivedbyaddress

```
listreceivedbyaddress ( minconf include_empty include_watchonly "address_filter" include_immature_coinbase )
```

Per-address received totals with the txids that paid them. With `include_empty` it also
lists every address the wallet has generated, which makes it the address-enumeration idiom:
zecd has no `listaddresses`, so `listreceivedbyaddress 1 true` is how you enumerate the
wallet's known addresses. The set is what this wallet database has recorded; after a
from-seed restore, handed-out addresses that were never funded are forgotten (zecd is
[stateless](../design/statelessness.md)).

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | minconf | number | 1 | Count only transactions with at least this many confirmations (same semantics as `getreceivedbyaddress`). |
| 2 | include_empty | bool | false | Also list generated addresses that have received nothing. |
| 3 | include_watchonly | any | ignored | Accepted, ignored (deprecated and unused in Core master too). |
| 4 | address_filter | string | none | Return only the entry for this exact address string. |
| 5 | include_immature_coinbase | any | ignored | Accepted, ignored. |

**Result**

```json
[
  {
    "address": "u1v0qh8pw9qm4h2v0negtfzrwhtjzfhgh0jcs9tzkjxg7xkpxkfhz5c4tj0nzqyjrmzgcqnyu7q6cx",
    "amount": 0.50000000,
    "confirmations": 4,
    "label": "",
    "txids": [
      "1f5e1f7b9d0f0c2f0a3f4f4b8f9f6d3e2c1b0a998877665544332211ffeeddcc"
    ]
  }
]
```

- `amount`: total received by the address at `minconf`, decimal ZEC.
- `confirmations`: confirmations of the most recently counted payment (the minimum across the
  counted transactions); 0 for an empty entry.
- `label`: always `""`; zecd keeps no labels, the field is retained for Core shape.
- `txids`: the counted transactions, `[]` for an empty entry.

**Errors**

| Code | When |
|------|------|
| -3 | Non-numeric `minconf` |

**vs Bitcoin Core**: same parameter list and entry shape. `address_filter` is a plain string
match, not validated: a filter that matches nothing (including an address the wallet has
never seen) returns `[]`, where Core rejects an invalid filter address with `-4`. `label` is
always empty, and the by-label variants (`listreceivedbylabel`, `getreceivedbylabel`) are not
implemented (`-32601`).

**vs zcashd**: zcashd's `listreceivedbyaddress` is transparent-only and rejects a non-default
`addressFilter`; per-address shielded receipts come from `z_listreceivedbyaddress` (one entry
per note, with memos). zecd folds all pools into the one Core-shaped method; for per-output
history with memos use [`z_listtransactions`](wallet-history.md).

**Example**

```sh
curl -s --user u:p --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"listreceivedbyaddress","params":[1,true]}' \
  http://127.0.0.1:8232/
```
