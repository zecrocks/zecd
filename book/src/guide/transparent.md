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

### Asking for a specific index, and asking which index you got

*New in 0.6.0.* `getnewaddress` hands out the next address and returns a bare string, which
leaves an operator reconciling an issued range against the chain without either half of the
loop. Both halves now exist, and neither adds persistent state:

| Question | Call |
|---|---|
| "Give me the address at index 7." | [`z_getaddressforaccount 0 ["p2pkh"] 7`](../rpc/wallet-addresses.md#transparent-derivation-at-an-explicit-index) |
| "Which index is this address?" | [`getaddressinfo`](../rpc/wallet-addresses.md#getaddressinfo) - `address_index`, plus Core's `hdkeypath` and `ischange` |
| "What will index 7 be, before the wallet exists?" | [`zecd derive-address`](../configuration.md#offline-address-derivation) - offline, no daemon |

Deriving at an explicit index runs the **same exposure path** as sequential issuance, so the
two agree by construction: the same recovery-horizon classification, the same warnings, the
same refusal when `transparent_allow_beyond_recovery_window = false` would put the index out
of restore range, and the same refresh of the address matcher. Directly addressing an index
therefore moves the issuance frontier exactly as `getnewaddress` would, which is what keeps
the two windows below coherent - and without the matcher refresh a payment to a directly
addressed index would simply be missed.

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

The same pass finds **spends**, including ones this wallet did not author: each block's
transparent inputs are tested against the outputs the wallet still holds unspent, so a spend made
by another wallet on the same seed, or while this one was down, marks the output spent and records
the outgoing entry. That test is bounded by the outputs held rather than the addresses issued, and
costs no request of its own, since the block is already parsed for the shielded scan. Shielded
spends need none of this: they are found through note nullifiers.

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

**Transparent coinbase is not selectable.** Consensus requires a transaction that spends
transparent coinbase to have no transparent output at all, so coin selection skips those UTXOs
even once they mature: a t-to-t send cannot pay a recipient and return change from them. Mature
coinbase still counts as spendable value, so it is reported on its own as
[`getbalances.mine.coinbase`](../rpc/wallet-balances.md#getbalances) and
`getwalletinfo.transparent.coinbase_balance`, and an insufficient-funds `-6` names the amount
rather than leaving the gap between balance and send unexplained.

**Change** is routed to the wallet's **internal (change) transparent chain**, which matters
twice: it is recovered on a from-seed restore via the internal gap chain, and the history RPCs
recognize the internal key scope as change and hide it, while a deliberate payment to one of
your own *external* t-addresses stays visible as a send+receive pair, matching Bitcoin Core.

## Coinbase: shielding is the only way to spend it

Transparent coinbase (a block reward or fee paid to one of the wallet's t-addresses) is a
special case, and the rule comes from consensus, not from zecd's policy: a transaction that
spends a transparent coinbase output may not have **any** transparent output, change included.
There is therefore no valid t-to-t coinbase spend to build, and the whole selected value must
move into a single shielded output.

[`z_shieldcoinbase`](../rpc/async-operations.md#z_shieldcoinbase) is the method that does it:
it sweeps mature transparent coinbase UTXOs into one shielded output at `toaddress`, which
must have a shielded receiver. It is asynchronous in zcashd's style, returning an opid that
`z_getoperationstatus` / `z_getoperationresult` resolve. The shielded payment is exactly
`input_total - fee`, with no change in any pool: emitting shielded change would leak how much
coinbase the wallet chose to sweep. Use the `limit` argument (default 50) to sweep in stages.

```sh
curl -s --user "$RPCUSER:$RPCPASS" --data-binary \
  '{"jsonrpc":"1.0","id":"doc","method":"z_shieldcoinbase","params":["*","u1..."]}' \
  http://127.0.0.1:8232/
# {"result":{"remainingUTXOs":0,"remainingValue":0.00000000,"shieldingUTXOs":3,
#            "shieldingValue":9.37500000,"opid":"opid-..."},"error":null,"id":"doc"}
```

The surrounding behavior follows from the same rule:

- **Maturity is the standard 100 blocks**, enforced during input selection. Immature coinbase
  is excluded from [`listunspent`](../rpc/wallet-history.md#listunspent) entirely (Bitcoin
  Core's `AvailableCoins` behavior), and its value is reported in
  `getwalletinfo.immature_balance` rather than counted as spendable.
- **`listunspent` marks it.** Transparent entries carry zcashd's `generated` boolean, `true`
  when the output came from a coinbase transaction.
- **The regular send paths skip it.** The transparent-to-transparent spend above always
  produces transparent outputs, so it never selects a coinbase input; nothing you do with
  `sendtoaddress`/`sendmany`/`z_sendmany` can build a consensus-invalid coinbase spend by
  accident.
- **Shielded coinbase (ZIP-213) needs none of this.** A block reward mined directly to a
  shielded address has no maturity rule and no spend restriction, so those notes are ordinary
  Orchard notes and spend through the normal send methods.

## The gap limit: transparent recovery is bounded

zecd is [stateless](../design/statelessness.md): everything on disk must be rebuildable from the
seed plus a chain scan. For shielded funds that recovery is **unconditional** (note
trial-decryption needs no address list). Transparent funds are different: a from-seed restore
rediscovers them only within the **external transparent gap limit**: the standard HD-wallet gap
mechanism, made sharper by statelessness (there is no persisted keypool to fall back on).

Mechanically, recovery is bounded by which addresses are *exposed* (present in the matcher's
address set). The window is anchored at the wallet's **issuance frontier**, the highest of:

1. the last funded external index,
2. the highest index `getnewaddress` has handed out, and
3. the `transparent_initial_scan` floor.

Indices from the frontier up to `frontier + transparent_gap_limit` are exposed, and a payment to
index N is discovered **iff** N is exposed. A funded index (or a fresh issuance) advances the
frontier and drags the window up with it, as in any HD wallet. The block-scan and mempool matcher
carries that window as an **in-memory gap lookahead**: `transparent_gap_limit` addresses derived
past the frontier, written to the wallet database only when a payment to one actually arrives. A
wide gap therefore costs derivation, not stored rows.

`[pools] transparent_gap_limit` (default **20**, applied only to transparent-enabled wallets;
librustzcash's own default is 10) sets the external window. Transparent **change** consumes the
internal chain and is recovered via the internal gap (librustzcash's default internal window;
zecd only varies the external limit).

### The gap limit composes with `transparent_initial_scan`

Because the `transparent_initial_scan` floor is one of the frontier's three inputs, the two knobs
add rather than compete. A from-seed restore has forgotten which addresses were handed out (that
is what statelessness means), and before the scan finds a funded index it has no funded index
either, so its frontier starts at the floor. The recovery horizon of a stateless restore is
therefore:

```
transparent_initial_scan + transparent_gap_limit
```

The window used to be measured from the last *funded* index alone, and the floor did not count.
An operator who pre-exposed, say, 70 000 addresses with `transparent_initial_scan` had to inflate
`transparent_gap_limit` to ~71 000 before `getnewaddress` would keep issuing recoverable
addresses: every issuance past the floor otherwise tripped the gap limit, was warned about as
potentially unrecoverable, and genuinely was unrecoverable from seed. That workaround is no
longer needed, and for the reason in the next section it is now actively discouraged.

### Two windows: live lookahead vs restore recovery

The running wallet and a from-seed restore do not cover the same range, because the two windows
are anchored on different events. Both behaviours are correct, and the difference is what decides
whether funds survive a restore.

| | Anchored on | Moves when |
| --- | --- | --- |
| **Live lookahead** (what the running matcher reaches) | address **exposure** | you hand an address out, *or* an index is funded |
| **Recovery horizon** (what a from-seed restore rediscovers within) | **funding** | an index is funded |

Issuance leaves no trace on chain, so a restore cannot know which addresses you handed out; it
starts its frontier at the floor and works forward from funded indices. A running wallet, by
contrast, must credit a receive on any address it handed out, so its lookahead follows issuance.

The consequence is a band that is matched live but **not** recovered from seed. It opens only
when an address is issued at or past the recovery horizon, which is exactly the act
[`transparent_allow_beyond_recovery_window`](#at-the-edge-of-the-recovery-window) governs and
already warns about, so it is an accepted operator choice rather than a surprise. Funding-driven
movement never opens the band: funding extends the restore's own window too, so a restore chains
forward to it.

`getwalletinfo.transparent` reports both windows, so this is observable rather than inferred:

```json
"transparent": {
  "gap_limit": 20,
  "lookahead_from": 1,
  "lookahead_through": 20,
  "recovery_horizon": 20,
  "restorable": true
}
```

- `lookahead_from` / `lookahead_through` are the live window, both **inclusive**. They describe
  the *forward reach* only: every address with a database row is matched too, including indices
  below `lookahead_from`.
- `recovery_horizon` is `transparent_initial_scan + transparent_gap_limit`.
- `restorable` is the one to watch. It is `lookahead_from <= recovery_horizon`, and `false`
  means the wallet is currently crediting addresses that a restore of the same seed would not
  rediscover. Alert on it rather than comparing the integers yourself.

Do not read a `false` as data loss: those funds are held and spendable, and are only at risk if
the wallet is later rebuilt from seed alone. Raising `transparent_initial_scan` (not
`transparent_gap_limit`, for the reason below) is the fix.

### Sizing `transparent_gap_limit`: keep it small

**Size the gap limit to the addresses you have handed out that are still unfunded, and no
further.** Deep restore coverage is what `transparent_initial_scan` is for: a one-time
pre-exposure, not a per-receive cost.

The reason is that the window is re-derived on the receive path. Recording a transparent receive
regenerates the **entire** gap window (a full unified-address derivation per index), and repeats
that regeneration once per already-recorded output of the same transaction. At roughly 1200
derivations per second, a 71 000-wide window costs about a minute per received UTXO, and
quadratically more for a multi-output transaction, all of it on the wallet's single-writer actor
inside the sync batch. In the field (a zecd 0.5.1-rc2 report) this presented as a restore that
appeared to stall: one core pegged, block scan frozen for hours.

zecd audits the configured value at startup: above **1000** (a gap limit already costing ~1s of
derivation per recorded receive) it logs a warning, and above **10000** (worst case past ~10s per
receive) it logs an error. Neither is a hard failure, and the daemon starts either way: the value
stays the operator's choice, and what it costs is performance, not correctness.

## Large pre-generated runs: `transparent_initial_scan`

A big gap limit is the wrong tool when you pre-generate *many* addresses: the gap is a *sliding*
window kept `gap_limit` past the frontier forever, so an exchange that assigns 10 000 addresses
and sizes the gap to match re-derives 10 000 addresses on every recorded receive, indefinitely.

Instead set `[pools] transparent_initial_scan = N` to pre-expose external indices `0..N` **once**
at startup/restore, so the block-scan matcher covers the whole issued range regardless of the
(small) steady-state `gap_limit`. Set `N` to your issuance high-water mark and keep
`transparent_gap_limit` small: the floor raises the frontier, so issuance continues past `N` with
a normal-sized gap and stays recoverable to `N + transparent_gap_limit`.

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
already near or over the window, giving lead time before addresses land outside it. The lead time
is best spent raising `transparent_initial_scan` (or getting a lower index funded), not inflating
`transparent_gap_limit`, for the per-receive derivation reason above.

## Not implemented

- **Auto-shielding.** Ordinary (non-coinbase) transparent UTXOs are not automatically shielded
  into Orchard, and such a receive cannot fund a shielded send. Those funds can be spent
  transparently (under `AllowFullyTransparent`) or left in place. Coinbase is the exception,
  and it is explicit rather than automatic: `z_shieldcoinbase` (above).
- **Mixed inputs.** Transparent UTXOs and shielded notes cannot fund a single send together.
- **Automatic address-index reconciliation.** No *periodic* cross-check of exposed addresses
  against Zebra's transparent address index to backfill receives the forward-only scan missed.
  Since 0.6.0 the primitives to do it yourself exist - derive or look up an address by index,
  and ask which index an address is (above) - but nothing runs that loop for you.

See [Known limitations](../limitations.md) for the details and planned direction of each.
