# Compatibility boundary

zecd targets generic Bitcoin-RPC compatibility, not bug-for-bug bitcoind emulation. This page
defines what that boundary covers and the edges where a shielded-first light wallet necessarily
behaves differently from bitcoind. Intentional per-method divergences are in the
[method index](rpc/method-index.md).

## What compatibility means

Any integration that drives a coin purely through Bitcoin Core RPC works: request a deposit
address with `getnewaddress`, hand it to the payer, poll `listtransactions` /
`gettransaction` / `getbalance` for the payment and its confirmations. Method names, response
field names and types, the JSON-RPC 1.0 envelope, HTTP Basic/cookie auth, decimal 8-place
amounts, and error codes all match Bitcoin Core (see [conventions and wire
format](rpc/index.md)). The conformance suite drives a live daemon with the same client logic
`python-bitcoinrpc` uses, so an unmodified `AuthServiceProxy` client works out of the box (see
[testing and conformance](testing.md)).

## Edges

Behaviors an integrator should design around. Each follows from being a shielded-first light
wallet.

### Spending needs confirmations

An incoming mempool payment is visible immediately: `getunconfirmedbalance`,
`listtransactions`, and `listunspent` with `minconf=0` all show it at 0 confirmations, fed by
zecd's `getrawmempool` poller. But a received note must mine and reach the confirmation
minimum before it is spendable. The default policy is [ZIP
315](https://zips.z.cash/zip-0315)'s: 3 confirmations for the wallet's own change, 10 for
third-party payments (roughly 12.5 minutes at 75-second blocks). `[spend]
trusted_confirmations` / `untrusted_confirmations` tune it wallet-wide (see
[configuration](configuration.md)).

A parameterless `getbalance` reports what is spendable under that policy; funds below the
threshold show in `getunconfirmedbalance` and `getbalances.mine.untrusted_pending` meanwhile.
An explicit `minconf` (`getbalance "*" 1`) overrides the policy symmetrically and counts
everything at that depth, as in Bitcoin Core. `minconf` 0 is served as 1: a shielded note is
never spendable unmined. See [wallet balances](rpc/wallet-balances.md).

### Fees are never client-settable

Fees follow [ZIP 317](https://zips.z.cash/zip-0317): a deterministic formula (5,000 zatoshis
times max(2, logical actions); a typical send pays 0.0001 ZEC) computed at build time. There
is no fee market to outbid, so client fee instructions are meaningless. zecd rejects them
with `-8` rather than silently ignoring them:

- `subtractfeefromamount` (`sendtoaddress`) and `subtractfeefrom` (`sendmany`): would change
  who pays the fee.
- `fee_rate` on `sendtoaddress`/`sendmany`: an explicit fee instruction.
- `settxfee`: always `-8`.

Estimation hints are safely ignored: `conf_target` and `estimate_mode` on sends, and
`maxfeerate` on `sendrawtransaction` (the conventional fee already buys next-block
inclusion). `estimatesmartfee`/`estimatefee` remain as inert probe-compat stubs returning a
stable conventional rate (`feerate` 0.00001). The exact fee actually paid is reported after
the fact in `gettransaction.fee`. See [sending](rpc/sending.md) and [utility and
control](rpc/util-control.md).

### Addresses are Unified Addresses

`getnewaddress` returns a shielded Unified Address (`u1...` on mainnet, `utest1...` on
testnet). Clients that treat addresses as opaque strings are fine; clients that parse the
address as a transparent Bitcoin address (base58 checks, script construction) are not.
`validateaddress` validates every Zcash address kind and reports what a given address can
receive via its `receiver_types` array. See [addresses and shielded
pools](guide/addresses.md).

### Sends that leave a single shielded pool reveal information

A transparent recipient reveals the recipient and the amount on-chain; crossing the
Sapling to Orchard turnstile (spending one pool, paying the other) reveals the crossed amount
via `valueBalance`. Both are permitted under the default policy, `AllowRevealedRecipients`.
The `[spend] privacy_policy` setting (and `z_sendmany`'s per-call `privacyPolicy`) is a
four-rung ladder that lets you forbid either leak, or additionally opt in to fully
transparent spends. See [privacy policy](design/privacy.md) for the rungs and where each is
enforced.

### Memos are extensions

Shielded memos ([ZIP 302](https://zips.z.cash/zip-0302)) sit beyond Bitcoin Core's surface,
so zecd exposes them as extensions that dialect-pure clients never trip over:

- `sendtoaddress` takes a hex-encoded memo as an extra trailing parameter, after `verbose`.
  At most 512 bytes; non-hex or oversized memos are `-8` (zcashd's messages); a memo paired
  with a transparent recipient is `-8`.
- History entries (`listtransactions`, `gettransaction.details`, `z_listtransactions`) carry
  `memo` (hex) and `memoStr` (decoded text) fields when an output has one; entries without a
  memo omit the fields entirely.
- `z_sendmany` permits a zero-valued output, zcashd's memo-only-send pattern (a shielded
  recipient, `amount: 0`, and a `memo`). The Bitcoin-Core-dialect `sendtoaddress`/`sendmany`
  keep rejecting a zero amount with `-3 Invalid amount`, as Core does.

See [sending](rpc/sending.md) and [async operations](rpc/async-operations.md).

### Partial reads during initial sync

During initial sync or a post-restore rescan, read RPCs serve whatever has been scanned so
far: `getbalance` on a half-synced wallet is a partial number, not an error. (Bitcoin Core
rejects every RPC with a warm-up error, `-28`, while it loads at startup.) Gate automation on
`GET /readyz` with `[health]
readiness = "synced"`, or on `getwalletinfo.scanning` / `getblockchaininfo.initialblockdownload`,
before trusting balances.

These signals stay busy until the wallet can serve full history, not just until the block
scan reaches the tip. Compact blocks carry no memos, so after the scan catches up a
per-transaction enhancement pass fetches each transaction's full data from Zebra to backfill
memos; on a from-birthday restore that backlog can take hours after `scan_progress` hits 1.0.
The backlog is surfaced as `pending_enhancements` on `GET /status`, `scanning` and
`initialblockdownload` stay truthy, and `"synced"` readiness holds `/readyz` at 503 with
`reason="enhancing"` until it drains to zero. See the [operations
runbook](guide/operations.md).

### sendmany collapses duplicate recipients

`sendmany` recipients arrive as a JSON object, and JSON parsing collapses duplicate keys
(last one wins) before zecd sees them, so Bitcoin Core's `-8 Invalid parameter, duplicated
address` cannot be reproduced. Do not list the same address twice; combine the amounts into
one entry. `z_sendmany` takes an array of recipient objects instead, so it does detect and
reject duplicates with `-8`.

### listsinceblock cursors do not survive reorgs

zecd keeps only the current chain's scanned block hashes (a light wallet has no stale-header
index), so if a `listsinceblock` cursor block is reorged away, or is below the wallet
birthday, `listsinceblock <hash>` returns `-5 Block not found`. Bitcoin Core instead walks
back to the common ancestor and includes transactions from the fork point onward. Treat `-5`
as "cursor invalid": re-baseline with a parameterless `listsinceblock` and dedupe by txid
(idempotent payment processing is required for reorg safety anyway). See [wallet
history](rpc/wallet-history.md).
