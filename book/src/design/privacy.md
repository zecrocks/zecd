# Privacy policy

Every zecd send is governed by a privacy policy: a four-rung ladder that decides what a
transaction may reveal on-chain. This page explains the leaks a Zcash send can cause, what each
rung permits and rejects (with error codes), where the policy is configured and overridden, how
zcashd's `privacyPolicy` names map onto it, and how it is enforced.

## What a Zcash send can reveal

zecd holds funds as shielded Orchard notes by default (optionally Sapling notes and, opt-in,
transparent UTXOs; see [addresses](../guide/addresses.md) and
[transparent support](../guide/transparent.md)). A fully shielded send within one pool reveals
nothing about amount, sender, or recipient. Three things break that, and they are independent:

1. **A transparent recipient.** Paying a bare `t`-address forces a transparent output, which is
   a Bitcoin-style output: the recipient and the amount paid are public forever.
2. **Crossing the Sapling and Orchard turnstile.** When value moves between shielded pools in one
   transaction, the net value entering or leaving each pool is published in the transaction's
   `valueBalance` field (consensus requires it). The recipient stays hidden, but the transferred
   amount is public. Under the default Orchard-only configuration this happens when an
   Orchard-funded send pays a Sapling address.
3. **Funding a send directly from transparent UTXOs.** A t-to-t send with kept-transparent change
   never touches a shielded pool: inputs, outputs, amounts, and change are all public, exactly as
   in Bitcoin.

Because the leaks are independent, the policy cannot be a boolean. A caller who opts into
revealing amounts (leak 2) has not thereby opted into revealing recipients (leak 1), and neither
opt-in implies a willingness to spend transparently (leak 3).

## The four rungs

`SendPrivacy` (`src/config.rs`) has four variants, strictest first. Each rung permits everything
the rung above it permits, plus one more disclosure.

| Policy | Transparent recipient | Sapling/Orchard crossing | Transparent-funded (t-to-t) spend |
|---|---|---|---|
| `FullPrivacy` | rejected, `-8` | rejected, `-8` | no |
| `AllowRevealedAmounts` | rejected, `-8` | allowed | no |
| `AllowRevealedRecipients` (default) | allowed | allowed | no |
| `AllowFullyTransparent` | allowed (see caveat) | allowed | yes |

Details per rung:

- **`FullPrivacy`**: only fully shielded sends confined to a single shielded pool. A recipient
  with no shielded receiver is `-8` at the RPC layer; a proposal whose inputs, outputs, or change
  would touch a transparent component or both shielded pools is `-8` from the actor, with a
  message naming the policy and the config knob to change.
- **`AllowRevealedAmounts`**: permits the turnstile crossing (revealing the amount via
  `valueBalance`) but still rejects a transparent recipient with `-8`. This rung is the reason
  the ladder exists: collapsing it onto `AllowRevealedRecipients` silently pays transparent
  recipients under a policy chosen to forbid exactly that.
- **`AllowRevealedRecipients`** (the default): permits transparent recipients and crossings. This
  matches the Bitcoin-RPC promise of "send to any valid address". A transparent recipient is
  still paid *from shielded notes*, and the change stays shielded, so the sender side leaks
  nothing. A wallet holding only transparent funds still cannot spend under this policy: the
  shielded input selector sees zero spendable and the send fails `-6` ("Insufficient funds").
- **`AllowFullyTransparent`**: additionally permits the fully transparent spend. When (and only
  when) every recipient of a send is a bare transparent address, the actor funds it directly from
  the wallet's transparent UTXOs and keeps the change transparent
  (`actor::transparent_only_recipients` gates the dispatch to `do_send_transparent`). Any
  shielded recipient in the request, or any weaker policy, falls through to the shielded proposal
  path. See [transparent support](../guide/transparent.md) for the spend mechanics. There is no
  transparent-to-shielded auto-shielding; see [limitations](../limitations.md).

  Caveat (current build): the ladder's design is that `AllowFullyTransparent` permits a bare
  transparent recipient (that is the whole point of the t-to-t path). The shipping code does not
  yet honor this at the RPC pre-check: `SendPrivacy::allows_transparent_recipient()`
  (`src/config.rs`) returns true only for `AllowRevealedRecipients`, so `build_payment` rejects a
  transparent-only recipient with `-8` even under `AllowFullyTransparent`, before the actor's
  `do_send_transparent` dispatch is reached. This is a known regression against the design
  documented here; treat the table's `AllowFullyTransparent` transparent-recipient cell as the
  intended behavior, not the current one.

## Where the policy is set

The wallet-wide policy is `[spend] privacy_policy` in the config file
(see [configuration](../configuration.md)):

```toml
[spend]
# "FullPrivacy" | "AllowRevealedAmounts" | "AllowRevealedRecipients" | "AllowFullyTransparent"
privacy_policy = "AllowRevealedRecipients"
```

The four names are case-sensitive; anything else (including zcashd-only names such as
`NoPrivacy` or `AllowRevealedSenders`) is a startup error, not an RPC error.

Only one RPC can override it per call: `z_sendmany`'s fifth positional argument,
`privacyPolicy` (see [async operations](../rpc/async-operations.md)). `sendtoaddress` and
`sendmany` have no per-call argument and always use the configured policy
(see [sending](../rpc/sending.md)). An omitted `privacyPolicy`, or the value `LegacyCompat`,
falls back to the configured policy; an unknown string is `-8`
("Unknown privacy policy: ...").

## zcashd policy-name mapping

zcashd's `PrivacyPolicy` (`src/wallet/wallet.h`, seven policies forming the lattice described in
[zcash/zcash#6240](https://github.com/zcash/zcash/issues/6240)) distinguishes sender-side
disclosures (`AllowRevealedSenders`, `AllowLinkingAccountAddresses`) that only matter for a
wallet spending from user-visible transparent source addresses. zecd's shielded proposal path
spends shielded notes, so those rungs have no sender to reveal and collapse onto
`AllowRevealedRecipients`. `z_sendmany`'s `privacyPolicy` accepts every zcashd name
(`wallet_methods::privacy_from_policy`):

| zcashd `privacyPolicy` | zecd rung |
|---|---|
| omitted, `LegacyCompat` | the configured `[spend] privacy_policy` |
| `FullPrivacy` | `FullPrivacy` |
| `AllowRevealedAmounts` | `AllowRevealedAmounts` |
| `AllowRevealedRecipients` | `AllowRevealedRecipients` |
| `AllowRevealedSenders` | `AllowRevealedRecipients` |
| `AllowLinkingAccountAddresses` | `AllowRevealedRecipients` |
| `AllowFullyTransparent` | `AllowFullyTransparent` |
| `NoPrivacy` | `AllowFullyTransparent` |
| anything else | `-8` |

`AllowFullyTransparent` and `NoPrivacy` are the two zcashd policies that permit funding a send
from transparent UTXOs with kept-transparent change, so both map to zecd's fourth rung.

## Enforcement: two halves

The two shielded leaks are checked at different times because they are knowable at different
times.

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

**Half 2: the proposal check (wallet actor).** Whether a send crosses the turnstile depends on
which notes fund it, and that is unknown until librustzcash builds the transfer proposal
(librustzcash has no privacy-policy concept of its own). So the actor's send path
(`actor::build_proposal_and_pczt` / `do_send_fused`) enforces the single-pool rule on the built
proposal, and only for `FullPrivacy`: `enforce_full_privacy` walks every proposal step with
`Step::involves` and rejects with `-8` if any step touches a transparent component or both
shielded pools (`single_pool_violated`: `transparent || (sapling && orchard)`). Inputs, payment
outputs, and change all count. `AllowRevealedAmounts` and above skip this check, since crossing
is exactly what that rung opts into. For `z_sendmany` this half runs on the background operation,
so the failure surfaces in `z_getoperationstatus`/`z_getoperationresult` rather than as a
synchronous error.

The `AllowFullyTransparent` dispatch is a third decision point in `actor::do_send`, but it is a
routing choice, not a rejection: the transparent-funded build path is taken only under that
policy and only when every recipient is a bare transparent address.

## Why the rungs must not collapse

An earlier zecd version reduced the policy to a boolean and mapped `AllowRevealedAmounts` onto
`AllowRevealedRecipients`. The result: a caller who set the policy specifically to keep
recipients private could still pay a transparent address, silently. The four-rung ladder fixes
that class of bug structurally, and the unit tests
(`full_privacy_rejects_transparent_recipients`, `privacy_from_policy_maps_every_case` in
`src/rpc/wallet_methods.rs`) plus the funded regtest tier guard it. When extending the ladder,
add a rung; never fold two rungs together.

## Lineage

The ladder is zcashd's privacy-policy design
([zcash/zcash#6240](https://github.com/zcash/zcash/issues/6240)) reduced to the disclosures zecd
can actually cause. zcashd models seven policies as a lattice with a meet operation
(`PrivacyPolicyMeet`); zecd keeps the four that are distinguishable for a wallet whose shielded
sends are always funded from shielded notes, and enforces `FullPrivacy` on the built proposal.
