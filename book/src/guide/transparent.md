# Transparent support

Transparent (t-address) receiving and spending is **off by default**: a zecd wallet is
shielded-only until you opt in.

## An additive capability, not a mode

Transparent support is a separate per-wallet flag, **not** a member of the `[pools]`
`enabled`/`default_receivers` lists (those stay shielded-only; see
[Addresses & shielded pools](addresses.md)). Setting `transparent = true` *adds* the ability to
hand out (and, with a further opt-in, spend from) bare transparent addresses alongside whatever
shielded pools the wallet uses. A wallet can be Orchard-only plus transparent, Sapling+Orchard
plus transparent, and so on.

```toml
[pools]
enabled = ["orchard"]           # shielded pools; transparent is NOT listed here
default_receivers = ["orchard"]
transparent = true              # allow bare t-addresses (receive; opt-in spend)
transparent_default = false     # true: no-arg getnewaddress returns a t-address instead of a UA
# transparent_gap_limit = 20                        # restore-recovery window (see below)
# transparent_initial_scan = 0                      # pre-expose external indices 0..N (see below)
# transparent_allow_beyond_recovery_window = true   # issue past the window (warn) vs fail closed
# transparent_gap_warn_threshold = 5                # warn when this few in-window slots remain
```

All of these can also be set per wallet in `[wallets.<name>]`; see the
[configuration reference](../configuration.md). `transparent_default = true` requires
`transparent = true` (a startup error otherwise).

## Getting a transparent address

With `transparent = true`:

```sh
curl -s --user "$RPCUSER:$RPCPASS" --data-binary \
  '{"jsonrpc":"1.0","id":"doc","method":"getnewaddress","params":["","transparent"]}' \
  http://127.0.0.1:8232/
# {"result":"t1...","error":null,"id":"doc"}   (tm... on testnet/regtest)
```

The result is a **bare** transparent address. Each `getnewaddress` call yields exactly one
address kind, a bare t-address *or* a shielded UA; a transparent receiver is never mixed into a
Unified Address zecd hands out. (ZIP-316 forbids a transparent-only UA, so internally zecd
derives a compliant UA carrying a p2pkh receiver and bare-encodes just the transparent
receiver.) The shielded `address_type` forms keep working unchanged, and
`transparent_default = true` merely flips the no-argument default. Requesting `"transparent"` on
a wallet without the flag is rejected `-8`.

Transparent addresses come from the account's sequential BIP-44 external chain, unlike shielded
addresses, whose diversifier indexes are clock-derived. That sequentiality is exactly what makes
the gap limit below meaningful.

## Receive discovery: block scan + mempool matching

Compact blocks omit transparent inputs/outputs, and librustzcash's shielded scan never records
transparent receives, so zecd owns transparent receive discovery and does it the way zcashd
does: by **scanning blocks**, not by per-address node queries. zecd already fetches and
parses every full block to derive compact blocks for the shielded scan (see the
[Zebra backend](../design/zebra-backend.md)), so it matches each block's transparent outputs
against an in-memory set of the wallet's exposed addresses at no extra request. The cost is
O(outputs-per-block) with a constant-time set lookup, **independent of how many addresses the
wallet holds**, so an operator tracking ~100k addresses pays no per-address cost per block.

Incoming transparent payments also show at **0-conf**: the mempool poller matches each mempool
transaction's transparent outputs against the same address set and records matches unmined, so a
payment appears in `getunconfirmedbalance` / `listtransactions` / `listunspent` with `minconf=0`
before its first confirmation, the same as a shielded receive. Once mined it is confirmed by the
block scan. Received transparent funds are reported by `getbalance`, `listunspent`,
`getreceivedbyaddress`, and the history RPCs, and `getaddressinfo` reports the address as
`ismine`.

One caveat: the block scan is forward-only and only matches outputs paying **exposed** addresses.
A payment to an address that becomes exposed only *after* its funding block was scanned
(out-of-order funding deep into the gap, with a small `transparent_gap_limit`) is missed until a
from-seed rescan. `transparent_initial_scan` (below) is the mitigation; automatic reconciliation
against the node's address index is [not yet implemented](../limitations.md).

## Spending: fully-transparent only, strictly opt-in

A received transparent UTXO can be spent to a transparent recipient with the change kept
transparent (a normal bitcoin-style t→t send that never touches a shielded pool), but **only**
under the top rung of the [privacy policy ladder](../design/privacy.md):

- `[spend] privacy_policy = "AllowFullyTransparent"` in config, the only route for
  `sendtoaddress`/`sendmany`, which take no per-call policy argument; or
- a [`z_sendmany`](../rpc/async-operations.md) `privacyPolicy` of `AllowFullyTransparent` (or
  zcashd's `NoPrivacy`, which maps onto the same rung).

This is the most revealing kind of send (recipient, amount, and funding inputs all public), hence
the explicit opt-in. Under the **default** policy (`AllowRevealedRecipients`) a transparent-only
wallet's send still fails with `-6` (insufficient funds): transparent UTXOs are never selected
as inputs. (Paying *to* a transparent recipient **from shielded funds** works under the default
policy, with shielded change; `FullPrivacy` and `AllowRevealedAmounts` reject transparent
recipients with `-8`.)

Because librustzcash's high-level transfer API funds payments from shielded notes only and has no
persistent transparent-change form, zecd builds the fully-transparent transaction itself: greedy
ZIP-317-aware coin selection over the wallet's spendable transparent UTXOs, recipient plus change
outputs, signed with the account's derived transparent keys, then recorded through the normal
sent-transaction path (spent UTXOs are locked against double-spend and the transaction rides the
rebroadcast loop).

**Change** is routed to the wallet's **internal (change) transparent chain**, which matters
twice: it is recovered on a from-seed restore via the internal gap chain, and the history RPCs
recognize the internal key scope as change and hide it, while a deliberate payment to one of
your own *external* t-addresses stays visible as a send+receive pair, matching Bitcoin Core.

## The gap limit: transparent recovery is bounded

zecd is [stateless](../design/statelessness.md): everything on disk must be rebuildable from the
seed plus a chain scan. For shielded funds that recovery is **unconditional** (note
trial-decryption needs no address list). Transparent funds are different: a from-seed restore
rediscovers them only within the **external transparent gap limit**: the standard HD-wallet gap
mechanism, made sharper by statelessness (there is no persisted keypool to fall back on).

Mechanically, recovery is bounded by which addresses are *exposed* (present in the matcher's
address set). On restore, librustzcash pre-exposes external indices `0..gap_limit`; each funded
index found extends the window to `funded_index + gap_limit`; a run of `gap_limit` consecutive
unfunded indices ends the chain. A payment to index N is recovered **iff** N is exposed.

`[pools] transparent_gap_limit` (default **20**, applied only to transparent-enabled wallets;
librustzcash's own default is 10) sets the external window. If you hand out addresses ahead of
funding (one per invoice, most never paid), size it to at least your maximum number of
outstanding-unfunded addresses, or a restore can silently miss a later payment to a high,
sparsely-funded index. Transparent **change** consumes the internal chain and is recovered via
the internal gap (librustzcash's default internal window; zecd only varies the external limit).

## Large pre-generated runs: `transparent_initial_scan`

A big gap limit is the wrong tool when you pre-generate *many* addresses: the gap is a *sliding*
window kept `gap_limit` past every funded address forever, so an exchange that assigns 10 000
addresses and sizes the gap to match scans 10 000 addresses past each receive, indefinitely.

Instead set `[pools] transparent_initial_scan = N` to pre-expose external indices `0..N` **once**
at startup/restore, so the block-scan matcher covers the whole issued range regardless of the
(small) steady-state `gap_limit`. Set `N` to your issuance high-water mark and keep
`transparent_gap_limit` small.

Pre-exposure is **incremental and non-blocking**: it must complete before the block scan (a
restore only finds a high funded index if that index was exposed first), but per-index derivation
is slow at depth (~1180 addresses/s, so a 100k run takes minutes), so zecd exposes it in chunks
of 1000 indices, servicing queued RPC commands between chunks; reads, sends, and the health
endpoints stay live throughout. Progress is observable two ways:

- a throttled heartbeat log (done/total, %, rolling addr/s, ETA), and
- `getwalletinfo`'s `transparent.initial_sync` object, `{"exposed": n, "total": N,
  "complete": bool}`, present whenever an initial-scan depth is configured (absent when the
  depth is 0).

When transparent receiving is enabled, `getwalletinfo` also reports the effective
`transparent` block (`enabled`, `default`, `gap_limit`) and the daemon logs the gap limit and
initial-scan depth at startup, so coverage can be audited against your issuance records.

## At the edge of the recovery window

librustzcash itself fails closed at the gap: once `gap_limit` consecutive unfunded external
addresses (above the `initial_scan` floor) have been handed out, it refuses to allocate another,
precisely because a from-seed restore could not rediscover funds sent there. zecd turns that edge
into an operator choice:

- `transparent_allow_beyond_recovery_window = true` (default): `getnewaddress` issues the address
  anyway and logs a loud warning that funds received there may be **unrecoverable from seed**
  (downgraded to info when the index is still below `transparent_initial_scan`, hence
  recoverable). A payment to such an address is still *detected live* (issuing it refreshes the
  matcher's address set); the risk is confined to a later from-seed restore.
- `transparent_allow_beyond_recovery_window = false`: the call fails `-4` with an actionable
  message naming the knobs (fail-closed; funds can never land on an unrecoverable address).

Independently, `transparent_gap_warn_threshold` (default **5**) makes `getnewaddress` warn as the
last few in-window slots are consumed, and a one-time startup audit re-warns if a wallet is
already near or over the window, giving lead time to widen `transparent_gap_limit` /
`transparent_initial_scan` (or get a lower index funded) before addresses land outside it.

## Not implemented

- **Auto-shielding.** Received transparent UTXOs are not automatically shielded into Orchard, and
  a transparent receive cannot fund a shielded send. Transparent funds can be spent
  transparently (under `AllowFullyTransparent`) or left in place.
- **Mixed inputs.** Transparent UTXOs and shielded notes cannot fund a single send together.
- **Address-index reconciliation.** No periodic cross-check of exposed addresses against Zebra's
  transparent address index to backfill receives the forward-only scan missed.

See [Known limitations](../limitations.md) for the details and planned direction of each.
