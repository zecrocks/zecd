# Async operations

Reference for `z_sendmany` and the operation-tracking trio `z_getoperationstatus` /
`z_getoperationresult` / `z_listoperationids`. These four methods adopt
zcashd's asynchronous send model: they match zcashd's syntax, status shapes, and
state strings, so clients written for zcashd's `z_sendmany` work unchanged. For synchronous
sends in Bitcoin Core's dialect, see [Sending](sending.md).

## The operation model

`z_sendmany` validates its arguments, then returns an operation id (`opid-` followed by a
UUID, identical to zcashd) immediately. The transaction is selected, proved, and
broadcast on a background task; its outcome is fetched later through the tracking methods.
The background task still funnels through the wallet's single-writer actor, so an async send
cannot double-spend against a concurrent `sendtoaddress` (see
[Architecture](../design/architecture.md)).

An operation moves through the zcashd state strings `queued`, `executing`, and then
`success` or `failed`. The `cancelled` state exists in the schema (and as a
`z_listoperationids` filter) for zcashd compatibility, but zecd has no cancellation path, so
no operation ever reports it.

Properties of the registry:

- **In-memory and transient.** Operations are lost on restart, exactly as in zcashd. A send
  that was already committed to the wallet DB still broadcasts via the rebroadcast loop even
  if its status object is gone; only the tracking record is lost. This is one of the two
  deliberate transient exceptions to zecd's
  [statelessness invariant](../design/statelessness.md).
- **Wallet-scoped.** Each operation is tagged with the wallet that created it. The tracking
  methods, routed per-wallet via `/wallet/<name>`, only ever see their own wallet's
  operations, even when an opid from another wallet is named explicitly (it is silently
  omitted). zcashd's queue is node-wide; zcashd only has one wallet.
- **Poll vs reap.** `z_getoperationstatus` is non-destructive: call it as often as you like.
  `z_getoperationresult` is destructive and one-shot: it returns each *finished* operation's
  status once and removes it; a second call for the same opid returns nothing. This matches
  zcashd exactly.
- **Bounded.** Two caps protect the daemon from an authenticated flood of `z_sendmany`:
  - At most **1024** operations are retained. Past that, the oldest *finished* results are
    auto-evicted (logged at WARN). A client that never reaps cannot wedge the daemon; the
    only cost is that old unread status objects may be discarded (the transactions
    themselves already broadcast).
  - At most **16** *unfinished* (queued + executing) operations per wallet. An in-flight
    operation owns a real pending send and cannot be evicted, so past this cap new
    `z_sendmany` calls are rejected with `-4` back-pressure until some finish. Finished
    operations never count toward this cap, so forgetting to reap never blocks new sends.

  zcashd has neither cap. Sends serialize on the wallet actor regardless, so 16 in flight is
  far above any useful concurrency.

## z_sendmany

```
z_sendmany "fromaddress" [{"address":..,"amount":..,"memo":..},...] ( minconf ) ( fee ) ( privacyPolicy )
```

Send to one or more recipients asynchronously. Returns an opid immediately; the outcome
(txid or error) surfaces through the tracking methods. zecd spends from its single account,
so `fromaddress` is an ownership check, not a fund selector: any of the wallet's own
addresses works and selects the same funds.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | fromaddress | string | required | One of this wallet's own addresses (unified, Sapling, or bare transparent). A foreign, undecodable, or hand-spliced address is `-5`. zcashd's `ANY_TADDR` sentinel is rejected with `-5`. |
| 2 | amounts | array | required | Non-empty array of `{"address":.., "amount":.., "memo":..}` objects. `amount` is decimal ZEC, 8 places; zero is allowed (the memo-only pattern, shielded recipients only). `memo` is an optional hex-encoded ZIP-302 memo, at most 512 bytes, shielded recipients only. Unknown keys and duplicate recipient addresses are `-8`. |
| 3 | minconf | number | wallet policy | Only spend notes with at least this many confirmations, overriding both bounds of the wallet's confirmations policy symmetrically for this send. Omitted or `null` uses the configured ZIP-315 policy (3 trusted / 10 untrusted). Values below 1 are served as 1; a non-number is `-3`. |
| 4 | fee | null | null | Must be omitted or `null`. Fees are always ZIP-317, computed by the wallet; any explicit value (including 0) is `-8`. |
| 5 | privacyPolicy | string | LegacyCompat | Per-call override of `[spend] privacy_policy`. See the mapping below. |

`privacyPolicy` accepts every zcashd policy name and maps it onto zecd's
[four-rung ladder](../design/privacy.md):

| Value | Effect in zecd |
|-------|----------------|
| `FullPrivacy` | No shielded leak: a transparent recipient is `-8` up front, and a proposal that crosses the Sapling/Orchard turnstile is rejected. |
| `AllowRevealedAmounts` | Turnstile crossing allowed (reveals the amount). A transparent recipient is still `-8`. |
| `AllowRevealedRecipients`, `AllowRevealedSenders`, `AllowLinkingAccountAddresses` | Transparent recipients allowed, paid from shielded funds with shielded change. zcashd's sender-side rungs collapse here because zecd's shielded sends have no transparent sender to reveal. |
| `AllowFullyTransparent`, `NoPrivacy` | Additionally permits a fully transparent spend: funding the send from transparent UTXOs with kept-transparent change (see [Transparent support](../guide/transparent.md)). |
| `LegacyCompat` or omitted | The wallet's configured `[spend] privacy_policy` (default `AllowRevealedRecipients`). |
| anything else | `-8` |

**Result**

```json
"opid-9c2f0d61-1c2b-4f3e-9a3e-2d4b8c7a5e10"
```

Only argument validation fails synchronously. Everything downstream, including `-6`
insufficient funds, a locked wallet, the `-4` "Private keys are disabled" refusal on a
[watch-only wallet](../guide/watch-only.md), proving failures, and broadcast rejection,
surfaces later in the operation's `error` object, never as an error on this call.

**Errors** (synchronous)

| Code | When |
|------|------|
| -1 | `fromaddress` missing or null |
| -3 | `fromaddress`, `minconf`, or a `memo` field is the wrong JSON type |
| -5 | `fromaddress` is `ANY_TADDR`, undecodable, not this wallet's, or a Unified Address with inconsistently spliced receivers |
| -8 | `amounts` missing or not an array; empty `amounts`; unknown key or missing `address`/`amount` in an entry; duplicate recipient; non-hex or over-512-byte memo; memo on a transparent recipient; explicit `fee`; unknown `privacyPolicy`; transparent recipient under `FullPrivacy`/`AllowRevealedAmounts` |
| -4 | the wallet already has 16 unfinished operations (back-pressure); or the payment set is not a valid transaction request |

**vs Bitcoin Core**: no equivalent; Core has no asynchronous RPC model. The synchronous
counterparts are [`sendtoaddress` and `sendmany`](sending.md).

**vs zcashd**: same signature, same opid model, same status shapes; this is the page where
zecd tracks zcashd rather than Bitcoin Core. Differences:

- `fromaddress` must be this wallet's own address and only gates ownership; zcashd selects
  funds *from* that specific address or account, and accepts `ANY_TADDR` to sweep
  non-coinbase transparent UTXOs across the wallet (zecd rejects it with `-5`).
- `fee` may be an explicit amount in zcashd (default `null` means ZIP-317); zecd rejects any
  explicit fee with `-8`.
- `minconf` defaults to 10 in zcashd (`DEFAULT_NOTE_CONFIRMATIONS`); zecd defaults to the
  wallet's configured ZIP-315 policy and clamps explicit values to at least 1.
- zcashd's `LegacyCompat` default resolves to `FullPrivacy` when a Unified Address is
  involved and `AllowFullyTransparent` otherwise; zecd's resolves to the configured
  `[spend] privacy_policy`. The sender-side policies are accepted but collapse onto
  `AllowRevealedRecipients`.
- The zero-valued memo-only output is accepted by both.

**Example**

```python
opid = rpc.z_sendmany(my_ua, [
    {"address": dest_ua, "amount": 0.5,
     "memo": "7a6563642070617965652072656631323334"},
])
while True:
    status = rpc.z_getoperationstatus([opid])[0]
    if status["status"] in ("success", "failed"):
        break
    time.sleep(1)
rpc.z_getoperationresult([opid])   # reap it
```

## z_getoperationstatus

```
z_getoperationstatus ( ["operationid", ...] )
```

Status objects for this wallet's async operations, all of them when no array is given.
Non-destructive: operations stay in memory.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | operationid | array | all operations | Array of opid strings. A malformed opid (or a non-string element, or a non-array argument) is `-8`; a well-formed but unknown opid is silently omitted. |

**Result** (sorted by `creation_time`, ascending)

```json
[
  {
    "id": "opid-9c2f0d61-1c2b-4f3e-9a3e-2d4b8c7a5e10",
    "method": "z_sendmany",
    "params": {
      "fromaddress": "u1v0m9...",
      "amounts": [{"address": "u1x7pq...", "amount": 0.5}],
      "minconf": 1
    },
    "status": "success",
    "creation_time": 1751600000,
    "result": {
      "txid": "5f8de306fcd7e716f9c39ea55c30d97a5a80439b7c8ec24b3decd80d20f0f1a8"
    },
    "execution_secs": 3
  }
]
```

- `method`/`params` echo the originating call (zcashd's context info). The echoed `minconf`
  is the raw argument, shown as `1` when it was omitted; the *effective* default when omitted
  is the wallet's configured policy.
- `status` is one of `queued`, `executing`, `success`, `failed` (`cancelled` never occurs in
  zecd).
- On `failed`, an `error` object `{"code": .., "message": ..}` replaces `result`; a `-6`
  insufficient-funds send lands here with the same enriched message the synchronous sends
  return.
- `result` and `execution_secs` (whole seconds of wall-clock execution) appear only on
  `success`.

**Errors**

| Code | When |
|------|------|
| -8 | argument is not an array; an element is not a string; an opid is malformed |

**vs Bitcoin Core**: no equivalent.

**vs zcashd**: same shape and sort order. zcashd's view is node-wide and includes its other
async operation types (`z_shieldcoinbase`, `z_mergetoaddress`, the Sapling migration); zecd
only ever has `z_sendmany` operations, scoped to the routed wallet. zcashd silently ignores a
malformed opid string; zecd rejects it with `-8`. zcashd reports
`execution_secs` as a fractional number; zecd reports whole seconds.

## z_getoperationresult

```
z_getoperationresult ( ["operationid", ...] )
```

Like `z_getoperationstatus`, but returns only *finished* operations (`success` or `failed`)
and **removes them from memory**. Destructive and one-shot: each result is returned exactly
once, and a repeat call for the same opid returns an empty array. Still-running operations
are neither returned nor removed. Reaping results promptly is good hygiene but never
required; unreaped results are auto-evicted past the 1024-operation cap.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | operationid | array | all finished operations | Array of opid strings; same validation as `z_getoperationstatus`. |

**Result**: the same status-object array as `z_getoperationstatus`, restricted to finished
operations, sorted by `creation_time`.

**Errors**

| Code | When |
|------|------|
| -8 | argument is not an array; an element is not a string; an opid is malformed |

**vs Bitcoin Core**: no equivalent.

**vs zcashd**: identical semantics, including the destructive removal; the scoping and
malformed-opid differences noted under `z_getoperationstatus` apply here too.

## z_listoperationids

```
z_listoperationids ( "status" )
```

The opid strings of this wallet's operations, sorted by creation time.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | status | string | none | Filter by state: `queued`, `executing`, `success`, `failed`, or `cancelled`. An unrecognized filter matches nothing and returns an empty list, matching zcashd. |

**Result**

```json
["opid-9c2f0d61-1c2b-4f3e-9a3e-2d4b8c7a5e10"]
```

**vs Bitcoin Core**: no equivalent.

**vs zcashd**: same signature and filter behavior; zecd's list is wallet-scoped and sorted
by creation time, and `cancelled` never matches anything because zecd never cancels an
operation.
