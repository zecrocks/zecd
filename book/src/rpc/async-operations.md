# Async operations

Reference for `z_sendmany`, `z_shieldcoinbase`, and the operation-tracking trio
`z_getoperationstatus` / `z_getoperationresult` / `z_listoperationids`. These five methods
adopt zcashd's asynchronous send model: they match zcashd's syntax, status shapes, and
state strings, so clients written for zcashd's `z_sendmany` work unchanged. For synchronous
sends in Bitcoin Core's dialect, see [Sending](sending.md).

A sixth method, [`z_waitforoperation`](#z_waitforoperation), is a **zecd extension** with no
zcashd counterpart: it blocks until one operation finishes, so a client does not have to
write a poll-sleep loop.

## The operation model

`z_sendmany` and `z_shieldcoinbase` validate their arguments, then return an operation id
(`opid-` followed by a UUID, identical to zcashd) immediately. The transaction is selected,
proved, and broadcast on a background task; its outcome is fetched later through the tracking
methods.
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
- **Poll, wait, or reap.** `z_getoperationstatus` is non-destructive: call it as often as you
  like. `z_waitforoperation` is also non-destructive, and blocks instead of returning
  immediately, which is usually what you want for a single send.
  `z_getoperationresult` is destructive and one-shot: it returns each *finished* operation's
  status once and removes it; a second call for the same opid returns nothing. This matches
  zcashd exactly. Waiting never reaps, so a wait followed by a `z_getoperationresult` still
  gets the result.
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
| `FullPrivacy` | No shielded leak: a transparent recipient is `-8` up front, and a proposal that crosses a turnstile between two shielded pools is rejected (Sapling, Orchard and Ironwood are three distinct pools). |
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
status = rpc.z_waitforoperation(opid)       # blocks; no poll loop
if not status["finished"]:
    ...                                     # timed out, still running: call again
elif status["status"] == "failed":
    raise RuntimeError(status["error"]["message"])
txid = status["result"]["txid"]
rpc.z_getoperationresult([opid])            # optional: reap it
```

## z_shieldcoinbase

```
z_shieldcoinbase "fromaddress" "toaddress" ( fee ) ( limit ) ( "memo" ) ( privacyPolicy )
```

Sweep the wallet's mature transparent coinbase UTXOs into a single shielded output. Returns
an opid immediately; the txid or error surfaces through the tracking methods, exactly as with
`z_sendmany`.

**Why this method exists at all.** Zcash consensus forbids a transaction that spends a
transparent coinbase output from having *any* transparent output, change included. A coinbase
spend therefore cannot pay a t-address and cannot keep transparent change: the whole selected
value has to land in one shielded output. That is not a shape the ordinary send methods can
produce, so shielding is the only way to spend transparent coinbase, and this is the method
that does it. The regular transparent-to-transparent path never selects coinbase inputs for
the same reason (see [Sending](sending.md)).

**No change, in any pool.** The shielded payment is exactly `input_total - fee`. Emitting
shielded change instead would leak how much coinbase the wallet chose to sweep, so the
selected value is moved whole. Sweep in stages with `limit` if you do not want it all in one
note.

**Maturity.** Transparent coinbase must reach the standard 100-block maturity before it can
be shielded; the bound is enforced during input selection. Immature coinbase is excluded from
[`listunspent`](wallet-history.md#listunspent) and reported in
[`getwalletinfo.immature_balance`](wallet-addresses.md#getwalletinfo) until it matures.

Shielded coinbase (ZIP-213), a block reward mined directly to a shielded address, needs none
of this: it has no maturity rule and no spend restriction, so those notes spend as ordinary
Orchard notes through the normal send methods.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | fromaddress | string | required | A transparent address of this wallet, or `"*"` for all of them. |
| 2 | toaddress | string | required | Where the swept value lands. Must have a shielded receiver; a transparent-only destination is `-8`, since a coinbase spend may not create a transparent output. |
| 3 | fee | null | null | Must be omitted or `null`. Fees are always ZIP-317, computed by the wallet; any explicit value is `-8`. |
| 4 | limit | number | 50 | Maximum UTXOs to shield in this transaction. `0` means no caller limit: shield as many as fit under the block-space cap. |
| 5 | memo | string (hex) | omitted | Hex-encoded ZIP-302 memo carried on the shielded output. |
| 6 | privacyPolicy | string | wallet policy | Same names as [`z_sendmany`](#z_sendmany). Shielding necessarily reveals the transparent senders being swept, so a policy that forbids revealing senders is `-8`. |

**Result**

```json
{
  "remainingUTXOs": 12,
  "remainingValue": 3.75000000,
  "shieldingUTXOs": 50,
  "shieldingValue": 15.62500000,
  "opid": "opid-9c2f0d61-1c2b-4f3e-9a3e-2d4b8c7a5e10"
}
```

- `shieldingUTXOs` / `shieldingValue`: what this operation is sweeping.
- `remainingUTXOs` / `remainingValue`: mature coinbase left over because `limit` or the
  block-space cap cut the selection short. Non-zero means call again once this operation
  finishes.
- `opid`: feed it to `z_getoperationstatus` / `z_getoperationresult`.

As with `z_sendmany`, only argument validation fails synchronously; proving and broadcast
failures surface in the operation's `error` object.

**Errors** (synchronous)

| Code | When |
|------|------|
| -1 | `fromaddress` or `toaddress` missing |
| -3 | An argument is the wrong JSON type |
| -5 | An address is undecodable, or for the wrong network |
| -6 | No mature coinbase to shield |
| -8 | `toaddress` has no shielded receiver; explicit `fee`; a `privacyPolicy` that forbids revealing senders, or an unknown one |

**vs Bitcoin Core**: no equivalent; Core has no shielded pool and no asynchronous RPC model.

**vs zcashd**: same signature, same response shape, same opid model. The one difference is
the fee: zcashd accepts an explicit `fee` amount, zecd rejects any explicit value with `-8`
and always charges the ZIP-317 conventional fee. The wallet-scoping and eviction properties
of the operation registry described above apply here as they do to `z_sendmany`.

**Example**

```sh
curl -u u:p -d '{
  "jsonrpc": "1.0", "id": 1, "method": "z_shieldcoinbase",
  "params": ["*", "u1abc..."]
}' http://127.0.0.1:8232/
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
async operation types (`z_mergetoaddress`, the Sapling migration); zecd only ever has
`z_sendmany` and `z_shieldcoinbase` operations, scoped to the routed wallet. zcashd silently
ignores a malformed opid string; zecd rejects it with `-8`. zcashd reports `execution_secs` as
a fractional number; zecd reports whole seconds.

## z_waitforoperation

```
z_waitforoperation "opid" ( timeout )
```

Block until one operation reaches a terminal state, then return its status object. A **zecd
extension**, in the same vein as `sendtoaddress`'s memo argument and `listunspent`'s `pool`
field: zcashd has no equivalent, so a client that must also work against zcashd should keep
using `z_getoperationstatus`.

This exists because `z_sendmany` and `z_shieldcoinbase` return an opid the caller has to
poll, so every client ends up reimplementing the same poll-sleep-check loop. One call
replaces it.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | opid | string | required | A single opid, as a bare string. Note this is **not** the array the tracking trio takes; an array is `-3`. |
| 2 | timeout | number | 120 | Seconds to wait. Clamped to 3600 rather than rejected, so an over-large value waits an hour instead of erroring. `0` returns the current status immediately, which is the single-operation, non-destructive read `z_getoperationstatus` only offers as an array. Negative or non-integer is `-8`. |

The 3600-second ceiling exists because a blocking call holds one `[rpc] work_queue` permit
for its whole duration. Without a bound, a few clients waiting forever would starve the queue
and every other request would start returning 503. Size `[rpc] work_queue` with that in mind
if many clients wait concurrently; see [Configuration](../configuration.md).

**Result**: the same status object [`z_getoperationstatus`](#z_getoperationstatus) returns per
operation, plus a `finished` boolean.

```json
{
  "id": "opid-9c2f0d61-1c2b-4f3e-9a3e-2d4b8c7a5e10",
  "method": "z_sendmany",
  "params": { "fromaddress": "u1v0m9...", "amounts": [{"address": "u1x7pq...", "amount": 0.5}], "minconf": 1 },
  "status": "success",
  "creation_time": 1751600000,
  "result": { "txid": "5f8de306fcd7e716f9c39ea55c30d97a5a80439b7c8ec24b3decd80d20f0f1a8" },
  "execution_secs": 3,
  "finished": true
}
```

`finished` and `status` together name all four outcomes, so a caller never has to know which
status strings are terminal:

| `finished` | `status` | Meaning |
|---|---|---|
| `true` | `success` | Done. The txid is in `result`. |
| `true` | `failed` | The operation ran and failed. The send's `-6`/`-4`/`-25` is in `error`, **not** an error on this call. |
| `true` | `cancelled` | Terminal in the schema; zecd never cancels, so this does not occur. |
| `false` | `queued` or `executing` | **The wait gave up**, not the operation. Either the timeout elapsed or the daemon began shutting down while the operation was still running. Call again to keep waiting. |

**Timing out is not an error.** The current `queued`/`executing` status object comes back
instead, mirroring Bitcoin Core's [`waitforblock` family](blockchain.md#waitfornewblock-waitforblock-waitforblockheight) and the
last iteration of the loop this replaces. Callers therefore branch on `finished`/`status`
rather than on two different failure shapes. Daemon shutdown ends the wait the same way, so a
long wait cannot hold a work-queue slot through a graceful stop.

**Non-destructive.** The operation stays in the registry;
[`z_getoperationresult`](#z_getoperationresult) remains the only reader that reaps.

**Errors**

| Code | When |
|------|------|
| -1 | no opid given, or too many arguments |
| -3 | `opid` is not a string (it takes one bare id, not the trio's array) |
| -8 | malformed opid; negative or non-integer `timeout`; or a well-formed opid this wallet has no operation for |
| -18 | unknown `/wallet/<name>` |

That last `-8` is deliberately *not* `z_getoperationstatus`'s silent omission: an opid this
wallet never issued, another wallet's, or one already reaped has nothing to wait for, so
silently returning would leave the caller blocked on a fiction.

**vs Bitcoin Core**: no equivalent (Core has no async operation model), though the
timeout-is-not-an-error contract is taken from Core's `waitforblock` family.

**vs zcashd**: no equivalent. zcashd clients poll `z_getoperationstatus`.

**Example**

```sh
curl -u u:p -d '{
  "jsonrpc": "1.0", "id": 1, "method": "z_waitforoperation",
  "params": ["opid-9c2f0d61-1c2b-4f3e-9a3e-2d4b8c7a5e10", 300]
}' http://127.0.0.1:8232/
```

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
