# Addresses & shielded pools

How zecd generates and interprets addresses: one ZIP-32 account per wallet, fresh diversified
Unified Addresses from `getnewaddress`, the `[pools]` configuration that controls which receivers
those addresses carry, and the address behaviors that follow from zecd's
[stateless design](../design/statelessness.md).

## One account, many diversified addresses

Each zecd wallet holds a single ZIP-32 account (`m/32'/coin_type'/account'`). `getnewaddress`
returns a fresh Unified Address (`u1...` on mainnet, `utest1...` on testnet) on every call, but
these are **diversified addresses of the same account**, not new derivation paths: each is a
different diversifier index of the account's keys. librustzcash advances to the next unused
diversifier and persists the cursor, so every call yields a new, unused address, and all of them
receive into the same account and are spendable by the same key (ZIP-316 + ZIP-32 diversification).

Practical consequences:

- Handing out a distinct address per counterparty costs nothing and needs no key management:
  there is no keypool to top up.
- Every address a wallet ever issued is owned by its one account.
  `getaddressinfo.ismine` recognizes even an issued-but-never-recorded address cryptographically,
  by attributing it to the account's incoming viewing key (see
  [getaddressinfo](../rpc/wallet-addresses.md)).
- "Multiple accounts" in zecd means multiple wallets; see the multiwallet routing in the
  [RPC overview](../rpc/index.md).

## Configuring pools: `[pools]`

zecd is shielded-first. Each wallet declares which shielded pools it uses and which receivers its
Unified Addresses include, via the global `[pools]` section and/or a per-wallet
`[wallets.<name>]` override:

```toml
[pools]
enabled = ["sapling", "orchard"]            # pools the wallet receives into and spends from
default_receivers = ["sapling", "orchard"]  # receivers in the UAs getnewaddress hands out
```

- Supported shielded pools are `sapling` and `orchard` (a future *ironwood* pool will slot in as
  a third name).
- The default (`[pools]` omitted entirely) is **Orchard-only**.
- `default_receivers` must be a subset of `enabled`; naming a disabled pool is a startup error.
  `default_receivers` omitted defaults to `enabled`.
- Transparent receiving is **not** a pool in this list. It is a separate opt-in capability flag
  (`transparent = true`) layered on top. See [Transparent support](transparent.md).

Balances, `listunspent`, and the history RPCs always report across every supported pool, not
just the enabled ones (the scan trial-decrypts all pools, so funds in a since-disabled pool
still show).

## `address_type`: the per-call receiver override

`getnewaddress`'s second argument (Bitcoin Core's `address_type` position) selects which
receivers the returned address carries, constrained to the wallet's enabled pools:

| Call | Returns |
|------|---------|
| `getnewaddress ""` | UA with the wallet's configured `default_receivers` (or a bare t-address if `transparent_default = true`) |
| `getnewaddress "" "unified"` | same as above (alias: `"default"`) |
| `getnewaddress "" "orchard"` | UA with an Orchard receiver only |
| `getnewaddress "" "sapling"` | UA with a Sapling receiver only |
| `getnewaddress "" "sapling,orchard"` | UA with both shielded receivers |
| `getnewaddress "" "transparent"` | bare `t1...`/`tm...` address (requires `[pools] transparent = true`) |

Rejections:

| Code | When |
|------|------|
| `-5` | Unknown `address_type` token (e.g. `"bech32"`), or `"transparent"` combined with a shielded pool in a comma list (zecd hands out one receiver kind at a time) |
| `-8` | Requested shielded receiver set is not a subset of the wallet's `enabled` pools |
| `-8` | `"transparent"` requested on a wallet without `[pools] transparent = true` |
| `-8` | Non-empty `label` argument (zecd is stateless and stores no labels) |

The token syntax (`-5` cases) is validated before wallet resolution; enablement (`-8` cases) is
per-wallet. Full parameter/response reference:
[getnewaddress](../rpc/wallet-addresses.md) and, for zcashd-style fixed-index derivation,
[z_getaddressforaccount](../rpc/wallet-addresses.md) (shielded receivers only; `p2pkh` is
rejected `-8` there).

## Change and spending

- **Change** from a shielded send goes to the strongest enabled pool: Orchard if enabled,
  otherwise the first enabled pool (i.e. Sapling for a Sapling-only wallet).
- **Inputs** are spent from any enabled pool.
- **Recipients** can be any address type: a transparent or Sapling recipient is payable from
  Orchard funds under the default privacy policy. What a send is allowed to reveal is governed by
  the [privacy policy ladder](../design/privacy.md), not by `[pools]`.

## Keys always derive all pools

The `[pools]` config is address-generation and spend *policy* only. The wallet's spending key
(USK) and viewing key (UFVK) always derive key material for **all** pools regardless of
configuration. Two consequences:

- Enabling a pool later (e.g. adding `sapling` to an Orchard-only wallet) requires no key
  migration; the wallet starts issuing addresses with the new receiver.
- A watch-only wallet imported from an [exported UFVK](watch-only.md) can derive addresses for
  any pool the spending wallet could.

## Same-seed instances do not hand out identical address sequences

Shielded diversifier indexes are **clock-derived**: for shielded address requests,
`zcash_client_sqlite` starts the index at the current Unix time (plus a fixed offset) and
increments past collisions. So two instances of the same key material (a restored wallet, a
watch-only UFVK pair, two same-seed daemons) hand out the *same* address only if they happen to
call `getnewaddress` within the same second.

This is harmless (every address either instance issues belongs to the same account, and funds
sent to any of them are found by both), but do not build anything that assumes cross-instance
`getnewaddress` equality. If you need a deterministic address, derive it at a **fixed diversifier
index** with `z_getaddressforaccount`, which re-derives the exact same address for the same index
and receiver set on any instance.

(Transparent addresses are the exception: the transparent chain is sequential, not
clock-derived; see [Transparent support](transparent.md).)

## Outgoing history shows the single receiver actually paid

When you pay a multi-receiver UA, exactly one receiver is paid on-chain (the pool the transaction
selected). The full UA you typed is sender-side metadata that never reaches the chain: the
authoring instance could cache it, but a restore-from-seed recovers only the single receiver
actually paid. To keep history **deterministic across a restore**, zecd's history RPCs
(`listtransactions`, `gettransaction.details`, `listsinceblock`, `z_listtransactions`) always
report an outgoing recipient as that single paid receiver:

- a bare `t...` or `zs...` address for a transparent or Sapling payment, or
- a single-receiver UA for an Orchard payment (Orchard has no standalone encoding).

The reduction is idempotent (a bare or single-receiver address reports as itself) and applies
only to outgoing outputs; received and self-transfer entries show your own recorded address.
This is the stateless counterpart of zcashd's persisted recipient mapping, which echoes
the typed UA on the authoring instance but degrades to the single receiver after a restore
anyway. To match a payment back to a multi-receiver UA you issued, deconstruct that UA into its
per-pool receivers client-side and compare against the reported receiver; zecd keeps no
recipient-side bookkeeping. See also the [history RPCs](../rpc/wallet-history.md).
