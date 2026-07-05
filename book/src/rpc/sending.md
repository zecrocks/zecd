# Sending

Reference for the synchronous send methods `sendtoaddress` and `sendmany`. For the
asynchronous zcashd-style send (`z_sendmany` and the operation-tracking trio), see
[async operations](async-operations.md).

## Send semantics

Everything in this section applies to both methods.

**Synchronous.** The call builds the transaction, computes the Orchard proof, commits it to
the wallet, and broadcasts it, all inside the HTTP request; the txid returns only after
broadcast is attempted. Unlike bitcoind's millisecond sends, the proof takes on the order of
seconds (far longer in debug builds), plus any queueing behind other sends. Set client-side
send timeouts well above that. A client that times out and blindly retries a send that
actually succeeded pays twice: on timeout, reconcile with
[`listtransactions`](wallet-history.md) before retrying. Once the transaction is committed,
a transport failure during initial relay does not surface as an error; the txid is returned
and a background loop rebroadcasts until the transaction mines or expires. Only an explicit
rejection by the Zebra node returns an error (`-26`), and the spent notes stay locked until
the transaction's expiry height.

**Sends serialize per wallet.** Each wallet is owned by a single-writer actor, the analog of
Bitcoin Core's `cs_wallet`: concurrent sends to one wallet are processed one at a time and
never select the same note, so there is no double-spend and no note-locking API to manage.
Queued sends hold their HTTP connection longer.

**Fees are ZIP-317, never client-settable.** The wallet computes the conventional fee;
there is no estimator and no fee knob. `subtractfeefromamount` (`sendtoaddress`) and
`subtractfeefrom` (`sendmany`) are rejected with `-8` when engaged, because silently
ignoring them would move different amounts than the caller intended. `fee_rate` is rejected
with `-8` for the same reason. These guards fire before any wallet access, so passing the
defaults (`false`, `null`, `[]`) still works. `conf_target` and `estimate_mode` are
estimation hints and are silently ignored; [`settxfee`](util-control.md) always returns
`-8`.

**Insufficient funds is self-diagnosing.** Shielded change is unspendable until it
confirms (3 confirmations for trusted change by default, see
[configuration](../configuration.md)), so rapid back-to-back sends exhaust spendable notes
and return `-6` until a block arrives. The `-6` message appends any balance awaiting
confirmations, so a client can tell "retry after the next block" from "the wallet needs
funding":

```
Insufficient funds: 0 zatoshis spendable, 10001000 required (including fee);
awaiting confirmations: 0 zatoshis incoming, 49990000 zatoshis change
```

**Privacy policy is enforced per recipient.** Under the wallet's configured
`[spend] privacy_policy` (default `AllowRevealedRecipients`), a recipient with no shielded
receiver (a bare `t1`/`t3` address) is rejected up front with `-8` when the policy is
`FullPrivacy` or `AllowRevealedAmounts`. `FullPrivacy` additionally rejects, on the built
proposal, any send that crosses the Sapling to Orchard turnstile. Neither method takes a
per-call policy argument; the config value applies. See the
[privacy policy ladder](../design/privacy.md).

**Action limit.** `[spend] orchard_action_limit` (default 50, 0 disables) caps the Orchard
actions of a single send to bound its memory and proving cost. A proposal that exceeds it
returns `-8` naming whether inputs or outputs overflowed.

**Common errors** (both methods; verified in the handlers and `src/error.rs`):

| Code | When |
|------|------|
| -1 | Missing required argument; more positional arguments than the method accepts |
| -3 | Amount not a number or string; zero or unparseable amount (`Invalid amount`); negative or above 21,000,000 ZEC (`Amount out of range`); non-boolean `verbose` |
| -5 | Unparseable address, or an address for the wrong network |
| -6 | Insufficient spendable funds (see the enrichment above) |
| -8 | `subtractfeefromamount`/`subtractfeefrom` or `fee_rate` engaged; privacy-policy rejection of a transparent-only recipient; `orchard_action_limit` exceeded |
| -4 | Watch-only wallet (`Error: Private keys are disabled for this wallet`); other wallet-level build failures |
| -13 | Passphrase-encrypted wallet is locked (`walletpassphrase` first) |
| -18 | `/wallet/<name>` names no loaded wallet |
| -26 | The Zebra node examined the transaction and rejected it |

## sendtoaddress

```
sendtoaddress "address" amount ( "comment" "comment_to" subtractfeefromamount replaceable conf_target "estimate_mode" avoid_reuse fee_rate verbose "memo" )
```

Pay one recipient from the wallet's shielded notes (or, under
`AllowFullyTransparent` with a transparent recipient, from transparent UTXOs; see
[transparent](../guide/transparent.md)). Returns the txid after proving and broadcast.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | address | string | required | Recipient: unified, Sapling, or transparent address |
| 2 | amount | number or string | required | Decimal ZEC, 8 places; zero is rejected (-3) |
| 3 | comment | string | omitted | Ignored: zecd persists no local metadata (see [statelessness](../design/statelessness.md)) |
| 4 | comment_to | string | omitted | Ignored, as above |
| 5 | subtractfeefromamount | boolean | false | Rejected with -8 if true (fees are ZIP-317, paid by the sender) |
| 6 | replaceable | boolean | omitted | Ignored (no RBF in Zcash) |
| 7 | conf_target | number | omitted | Ignored (no fee estimator; ZIP-317 buys next-block inclusion) |
| 8 | estimate_mode | string | omitted | Ignored |
| 9 | avoid_reuse | boolean | omitted | Ignored (shielded receiving addresses are diversified) |
| 10 | fee_rate | number | omitted | Rejected with -8 if set |
| 11 | verbose | boolean | false | Return an object with `fee_reason` instead of a bare txid |
| 12 | memo | string (hex) | omitted | zecd extension: hex-encoded ZIP-302 memo for the shielded recipient, at most 512 bytes |

**Result**

```json
"85a13a0895c9ef2e26b1a29321581e19b6cb51b0e6b1e4f0d68f4d5cba1b7f4e"
```

With `verbose = true` (`fee_reason` is always the ZIP-317 conventional fee):

```json
{
  "txid": "85a13a0895c9ef2e26b1a29321581e19b6cb51b0e6b1e4f0d68f4d5cba1b7f4e",
  "fee_reason": "ZIP 317"
}
```

**Errors** (beyond the common table)

| Code | When |
|------|------|
| -3 | `memo` present but not a string |
| -8 | `memo` is not valid hex (`Invalid parameter, expected memo data in hexadecimal format.`); memo longer than 512 bytes; memo paired with a transparent recipient (`Memo cannot be used with a transparent recipient`) |

**vs Bitcoin Core**

Parameter positions 1-11 match Core master's `sendtoaddress` exactly (verified against
`src/wallet/rpc/spend.cpp`), including the verbose result shape. Differences: `comment`/
`comment_to` are accepted but never stored; `subtractfeefromamount` and `fee_rate` are hard
`-8` rejections instead of honored; `replaceable`/`conf_target`/`estimate_mode`/
`avoid_reuse` are ignored; position 12 (`memo`) does not exist in Core.

**vs zcashd**

zcashd retains `sendtoaddress` but as a transparent-only legacy method: it selects funds
exclusively from the transparent pool, its help says "THIS API PROVIDES NO PRIVACY", and it
takes only 5 arguments (through `subtractfeefromamount`, which it honors). The recommended
zcashd send is `z_sendmany`. zecd inverts this: `sendtoaddress` is the primary, shielded
send, and its memo parameter follows `z_sendmany`'s conventions (hex, 512-byte cap). Unlike
`z_sendmany`, zecd's `sendtoaddress` keeps Core's rejection of zero amounts (`-3`), so a
memo-only send needs [`z_sendmany`](async-operations.md).

**Example**

```sh
curl -u u:p --max-time 120 -d '{
  "jsonrpc": "1.0", "id": 1, "method": "sendtoaddress",
  "params": ["u1abc...", 0.1, "", "", false, false, null, "", false, null, false,
             "74616b652074686520686f626269747320746f2069736574686172"]
}' http://127.0.0.1:8232/
```

## sendmany

```
sendmany "" {"address":amount,...} ( minconf "comment" ["address",...] replaceable conf_target "estimate_mode" fee_rate verbose )
```

Pay several recipients in one transaction: one ZIP-317 fee, one anchor. Recipients may mix
shielded and transparent addresses (under the default policy a transparent recipient is
paid from shielded notes, with shielded change).

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | dummy | string | "" | Legacy placeholder; zecd ignores it entirely (Core rejects a non-empty value) |
| 2 | amounts | object | required | `{"address": amount, ...}`; amounts are decimal ZEC, 8 places, number or string; zero is rejected (-3) |
| 3 | minconf | number | omitted | Ignored dummy value, as in Core master |
| 4 | comment | string | omitted | Ignored (not stored) |
| 5 | subtractfeefrom | array | omitted | Rejected with -8 if non-empty |
| 6 | replaceable | boolean | omitted | Ignored |
| 7 | conf_target | number | omitted | Ignored |
| 8 | estimate_mode | string | omitted | Ignored |
| 9 | fee_rate | number | omitted | Rejected with -8 if set |
| 10 | verbose | boolean | false | Return an object with `fee_reason` instead of a bare txid |

**Duplicate recipient keys collapse silently.** Recipients arrive as a JSON object, and
JSON parsing keeps only the last occurrence of a duplicated key before zecd sees it, so
listing the same address twice sends only the last amount. Bitcoin Core's
`Invalid parameter, duplicated address` error cannot be reproduced here. Do not list an
address twice; combine the amounts instead. (`z_sendmany`, whose recipients are an array,
does reject duplicates with `-8`.)

**Transparent-to-transparent spends.** `sendmany` has no per-call privacy argument, so its
only route to a fully transparent spend (transparent UTXOs in, transparent change) is the
`[spend] privacy_policy = "AllowFullyTransparent"` config knob, and it engages only when
every recipient is a bare transparent address. Under the default policy a wallet holding
only transparent funds gets `-6`. See [transparent](../guide/transparent.md).

**Result**

Same shape as `sendtoaddress`: a bare txid string, or `{"txid", "fee_reason"}` with
`verbose = true`.

**Errors** (beyond the common table)

| Code | When |
|------|------|
| -3 | `amounts` present but not an object |
| -8 | `amounts` is an empty object (`sendmany requires at least one recipient`) |

**vs Bitcoin Core**

Parameter positions 1-10 match Core master exactly (verified against
`src/wallet/rpc/spend.cpp`); Core also treats `minconf` as an ignored dummy. Differences:
zecd never validates the `dummy` argument (Core returns `-8` for a non-empty one), rejects
`subtractfeefrom`/`fee_rate` with `-8` instead of honoring them, and does not store the
comment.

**vs zcashd**

zcashd's `sendmany` is a discouraged transparent-only legacy method ("Prefer to use
`z_sendmany` instead"); it takes 5 arguments, honors `minconf`, and honors
`subtractfeefromamount`. zecd's nearest zcashd equivalent for a multi-recipient shielded
send is `z_sendmany`, which zecd also implements ([async operations](async-operations.md))
with per-output memos, a per-call `minconf` and `privacyPolicy`, and zero-amount outputs.

**Example**

```sh
curl -u u:p --max-time 120 -d '{
  "jsonrpc": "1.0", "id": 1, "method": "sendmany",
  "params": ["", {"u1abc...": 0.05, "t1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd": 0.02}]
}' http://127.0.0.1:8232/
```
