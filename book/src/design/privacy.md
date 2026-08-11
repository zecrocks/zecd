# Privacy policy

Every zecd send is governed by a privacy policy: a five-rung ladder that decides what a
transaction may reveal on-chain. This page explains the leaks a Zcash send can cause, what each
rung permits and rejects (with error codes), where the policy is configured and overridden, how
zcashd's `privacyPolicy` names map onto it, and how it is enforced.

## What a Zcash send can reveal

zecd holds funds as shielded notes by default (optionally Sapling notes and, opt-in, transparent
UTXOs; see [addresses](../guide/addresses.md) and
[transparent support](../guide/transparent.md)). With NU6.3 active those notes are **Ironwood**
notes, received at ordinary Orchard receivers - the address is unchanged, the value pool is not.
Orchard V2 remains a real pool that a wallet can still hold and spend from, which is why a send
out of it into Ironwood is a genuine pool crossing rather than a relabelling.

A fully shielded send within one pool reveals nothing about amount, sender, or recipient. Four
things break that, and they are independent:

1. **A transparent recipient.** Paying a bare `t`-address forces a transparent output, which is
   a Bitcoin-style output: the recipient and the amount paid are public forever.
2. **Crossing a shielded turnstile.** When value moves between shielded pools in one
   transaction, the net value entering or leaving each pool is published in the transaction's
   `valueBalance` field (consensus requires it). The recipient stays hidden, but the transferred
   amount is public. Sapling, Orchard and Ironwood are three distinct pools here, so this covers
   an Ironwood-funded send paying a Sapling address, and equally a send that drains legacy
   Orchard V2 notes into Ironwood.
3. **Funding a send from transparent UTXOs.** Spending the wallet's own t-address coins puts them
   in the transaction as inputs, which publishes the *sender's* addresses and the amounts held at
   them, and links them to each other. This is true even when the change shields: a shielding
   (t-to-z) send hides where the value went, not where it came from.
4. **Keeping the change transparent.** A send funded from transparent UTXOs that also pays a
   transparent recipient never touches a shielded pool at all: inputs, outputs, amounts, and
   change are all public, exactly as in Bitcoin.

Because the leaks are independent, the policy cannot be a boolean. A caller who opts into
revealing amounts (leak 2) has not thereby opted into revealing recipients (leak 1); neither
opt-in implies a willingness to reveal the sender (leak 3); and revealing the sender in order to
move transparent funds *into* the shielded pool is a very different act from spending them
straight back out in the clear (leak 4).

## The five rungs

`SendPrivacy` (`src/config.rs`) has five variants, strictest first. Each rung permits everything
the rung above it permits, plus one more disclosure.

| Policy | Transparent recipient | Shielded pool crossing | Transparent-funded spend | Kept-transparent change |
|---|---|---|---|---|
| `FullPrivacy` | rejected, `-8` | rejected, `-8` | no | no |
| `AllowRevealedAmounts` | rejected, `-8` | allowed | no | no |
| `AllowRevealedRecipients` (default) | allowed | allowed | no | no |
| `AllowRevealedSenders` | allowed | allowed | yes (change shields) | no |
| `AllowFullyTransparent` | allowed | allowed | yes | yes |

Details per rung:

- **`FullPrivacy`**: only fully shielded sends confined to a single shielded pool. A recipient
  with no shielded receiver is `-8` at the RPC layer; a proposal whose inputs, outputs, or change
  would touch a transparent component or **more than one** shielded pool is `-8` from the actor,
  with a message naming the policy and the config knob to change. Sapling, Orchard and Ironwood
  are three distinct pools here: ironwood notes are received at ordinary Orchard addresses, but
  they are a separate value pool, so an ironwood-to-Orchard send crosses the turnstile exactly as
  an ironwood-to-Sapling one does.
- **`AllowRevealedAmounts`**: permits the turnstile crossing (revealing the amount via
  `valueBalance`) but still rejects a transparent recipient with `-8`. This rung is the reason
  the ladder exists: collapsing it onto `AllowRevealedRecipients` silently pays transparent
  recipients under a policy chosen to forbid exactly that.
- **`AllowRevealedRecipients`** (the default): permits transparent recipients and crossings. This
  matches the Bitcoin-RPC promise of "send to any valid address". A transparent recipient is
  still paid *from shielded notes*, and the change stays shielded, so the sender side leaks
  nothing. A wallet holding only transparent funds still cannot spend under this policy: the
  shielded input selector sees zero spendable and the send fails `-6` ("Insufficient funds").
- **`AllowRevealedSenders`**: additionally permits *funding* a send from the wallet's transparent
  UTXOs, which is what [`z_sendmany`'s `fromaddress`](../rpc/async-operations.md#z_sendmany)
  selects. The change of such a send is shielded, so with a shielded recipient this is the
  **shielding** (t-to-z) send: it is how received transparent funds move into the shielded pool.
  What it discloses is the sender side, and only that. A transparent `fromaddress` under any
  weaker policy, the default included, is refused with `-4` before the send is queued.
- **`AllowFullyTransparent`**: additionally permits keeping the change transparent, which makes
  the whole transaction transparent. This is the only policy under which transparent change is
  possible. It engages when every recipient of a send is a bare transparent address and the
  funding source is transparent; a shielded recipient in the request routes back to the shielding
  build instead. See [transparent support](../guide/transparent.md) for the spend mechanics.

## Where the policy is set

The wallet-wide policy is `[spend] privacy_policy` in the config file
(see [configuration](../configuration.md)):

```toml
[spend]
# "FullPrivacy" | "AllowRevealedAmounts" | "AllowRevealedRecipients"
#   | "AllowRevealedSenders" | "AllowFullyTransparent"
privacy_policy = "AllowRevealedRecipients"
```

The five names are case-sensitive; anything else (including zcashd-only names such as
`NoPrivacy` or `AllowLinkingAccountAddresses`) is a startup error, not an RPC error.

Note that `AllowRevealedSenders` is a rung in its own right as of 0.6.1. Earlier versions
accepted the name and treated it as `AllowRevealedRecipients`, on the reasoning that a wallet
with no transparent funding source had no sender to reveal. A config carrying that name from an
older deployment therefore gains the ability to fund sends from transparent UTXOs; write
`AllowRevealedRecipients` to keep the previous behaviour.

Only one RPC can override it per call: `z_sendmany`'s fifth positional argument,
`privacyPolicy` (see [async operations](../rpc/async-operations.md)). `sendtoaddress` and
`sendmany` have no per-call argument and always use the configured policy
(see [sending](../rpc/sending.md)). An omitted `privacyPolicy`, or the value `LegacyCompat`,
falls back to the configured policy; an unknown string is `-8`
("Unknown privacy policy: ...").

## zcashd policy-name mapping

zcashd's `PrivacyPolicy` (`src/wallet/wallet.h`, seven policies forming the lattice described in
[zcash/zcash#6240](https://github.com/zcash/zcash/issues/6240)) distinguishes sender-side
disclosures that only matter for a wallet spending from user-visible transparent source
addresses. zecd has such a source as of 0.6.1, so `AllowRevealedSenders` now carries its zcashd
meaning rather than collapsing. `AllowLinkingAccountAddresses` still collapses onto it: zecd
spends from a single account, so there are no separate accounts to link.
`z_sendmany`'s `privacyPolicy` accepts every zcashd name
(`wallet_methods::privacy_from_policy`):

| zcashd `privacyPolicy` | zecd rung |
|---|---|
| omitted, `LegacyCompat` | the configured `[spend] privacy_policy` |
| `FullPrivacy` | `FullPrivacy` |
| `AllowRevealedAmounts` | `AllowRevealedAmounts` |
| `AllowRevealedRecipients` | `AllowRevealedRecipients` |
| `AllowRevealedSenders` | `AllowRevealedSenders` |
| `AllowLinkingAccountAddresses` | `AllowRevealedSenders` |
| `AllowFullyTransparent` | `AllowFullyTransparent` |
| `NoPrivacy` | `AllowFullyTransparent` |
| anything else | `-8` |

`AllowFullyTransparent` and `NoPrivacy` are the two zcashd policies that permit keeping the
change transparent, so both map to zecd's top rung.

One difference from zcashd's lattice is worth stating plainly: zecd's ladder is **linear**, so
each rung implies every rung below it. `AllowRevealedSenders` therefore also permits a
transparent recipient (paid from shielded notes, as `AllowRevealedRecipients` does), where
zcashd treats the sender-side and recipient-side disclosures as incomparable points in a
lattice. The strictly-transparent combination, a transparent recipient paid *from* transparent
funds, is the one zcashd also separates out, and it is `AllowFullyTransparent` in both.

## Enforcement: two halves

The leaks are checked at different times because they are knowable at different times. The
recipient-side and sender-side checks need only the request, so they run synchronously at the
RPC layer; whether a send crosses a shielded turnstile depends on which notes fund it, which is
not known until the proposal is built.

**Half 1: the per-recipient pre-check (RPC layer).** `wallet_methods::build_payment` runs for
every recipient of every send RPC, before anything reaches the wallet actor. If the policy does
not allow transparent recipients (`SendPrivacy::allows_transparent_recipient()`), a recipient
address with no shielded receiver (`address::has_shielded_receiver`) is rejected immediately:

```
-8: Privacy policy AllowRevealedAmounts rejects tmXXXX...: it has no shielded receiver,
so paying it would reveal the amount and recipient on-chain. Use privacyPolicy
"AllowRevealedRecipients" (or set [spend] privacy_policy) to permit this.
```

This check is cheap (address parsing only) and needs no wallet state. For `z_sendmany` it runs
synchronously, so a policy-rejected recipient fails with `-8` before an operation id is ever
returned.

The same pass checks the **funding source**. A transparent `fromaddress` (or `ANY_TADDR`) under a
policy that does not permit transparent inputs (`SendPrivacy::allows_transparent_inputs()`) is
`-4`, naming the rung that would allow it:

```
-4: Insufficient privacy policy to allow transparent sender: AllowRevealedRecipients does
not permit funding a send from transparent UTXOs (which reveals the sender's addresses and
amounts). Use privacyPolicy "AllowRevealedSenders" or weaker to allow this transaction to
proceed.
```

and a transparent source paired with an all-transparent recipient set under anything short of
`AllowFullyTransparent` gets the companion refusal for the fully transparent case. Both are
re-checked authoritatively on the actor before the build, so the RPC-layer copy is a fast path
rather than the only guard, and the two cannot drift.

**Half 2: the proposal check (wallet actor).** Whether a send crosses the turnstile depends on
which notes fund it, and that is unknown until librustzcash builds the transfer proposal
(librustzcash has no privacy-policy concept of its own). So the actor's send path
(`actor::build_proposal_and_pczt` / `do_send_fused`) enforces the single-pool rule on the built
proposal, and only for `FullPrivacy`: `enforce_full_privacy` walks every proposal step with
`Step::involves` and rejects with `-8` if any step touches a transparent component or more than
one shielded pool. Inputs, payment outputs, and change all count. The rule is stated over the
pool *count* rather than as a list of forbidden pairs, so a fourth pool is covered without
another edit; an earlier form that named only Sapling and Orchard let ironwood crossings through
(fixed in 0.5.2). `AllowRevealedAmounts` and above skip this check, since crossing
is exactly what that rung opts into. For `z_sendmany` this half runs on the background operation,
so the failure surfaces in `z_getoperationstatus`/`z_getoperationresult` rather than as a
synchronous error.

Source selection is a third decision point in `actor::do_send`, but it is a routing choice rather
than a rejection: the resolved source maps onto librustzcash's spend policy, with the shielded
pool set left empty for a transparent source so a shortfall is `-6` instead of a silent top-up
from the other pool. Keeping the change transparent is the narrow case within that, taken only
under `AllowFullyTransparent` and only when every recipient is a bare transparent address.

## Why the rungs must not collapse

An earlier zecd version reduced the policy to a boolean and mapped `AllowRevealedAmounts` onto
`AllowRevealedRecipients`. The result: a caller who set the policy specifically to keep
recipients private could still pay a transparent address, silently. The ladder fixes that class
of bug structurally, and the unit tests (`full_privacy_rejects_transparent_recipients`,
`privacy_from_policy_maps_every_case` in `src/rpc/wallet_methods.rs`) plus the funded regtest
tier guard it. When extending the ladder, add a rung; never fold two rungs together.

`AllowRevealedSenders` is the worked example of both halves of that rule. It was a collapsed
alias for as long as zecd had no transparent funding source, which was defensible while true;
when coin control made it false, the fix was to give the name its own rung rather than to leave
it pointing at a weaker one. Collapsing it would have meant a wallet configured for
`AllowRevealedRecipients` could suddenly spend its transparent coins in the clear.

## Lineage

The ladder is zcashd's privacy-policy design
([zcash/zcash#6240](https://github.com/zcash/zcash/issues/6240)) reduced to the disclosures zecd
can actually cause. zcashd models seven policies as a lattice with a meet operation
(`PrivacyPolicyMeet`); zecd keeps the four that are distinguishable for a wallet whose shielded
sends are always funded from shielded notes, and enforces `FullPrivacy` on the built proposal.
