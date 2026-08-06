# Wallet: addresses & keys

Reference for the address-generation, address-inspection, wallet-metadata, and lock/unlock
methods. For the wire format, auth, and multiwallet `/wallet/<name>` routing, see
[Conventions & wire format](index.md); for background on Unified Addresses, diversified
addresses, and pool configuration, see [Addresses & shielded pools](../guide/addresses.md).

## getnewaddress

```
getnewaddress ( "" address_type )
```

Returns a fresh receiving address for the wallet's account: a new diversified Unified Address
(new diversifier, same account key), or a bare transparent address when requested. Works on
watch-only wallets and on locked encrypted wallets (addresses derive from the viewing key, not
the seed).

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | label | string | `""` | Must be empty or omitted. zecd is [stateless](../design/statelessness.md) and stores no labels; a non-empty label is rejected with `-8`. Kept in Bitcoin Core's position so `address_type` stays at parameter 2. |
| 2 | address_type | string | wallet default | Per-call receiver override: empty, `"unified"`, or `"default"` use the wallet's configured `default_receivers`; a single shielded pool name (`"orchard"`, `"sapling"`) or a comma-separated list (`"sapling,orchard"`) builds a UA with exactly those receivers; `"transparent"` returns a bare t-address. |

With no `address_type`, the wallet's `[pools]` configuration decides: the default
(Orchard-only) config returns an Orchard-only UA; a wallet with `transparent_default = true`
returns a bare transparent address. Every requested shielded receiver must be a pool enabled
on the wallet. `"transparent"` requires `[pools] transparent = true` and cannot be combined
with shielded pool names (zecd hands out one receiver type at a time; ZIP-316 forbids a
transparent-only UA, so the transparent receiver is bare-encoded as `t1...`/`tm...`).

There is no `"ironwood"` receiver. Ironwood notes are received at ordinary Orchard addresses, so
an Orchard receiver is all a payer needs to send you ironwood funds. See
[Addresses & shielded pools](../guide/addresses.md).

Transparent addresses come from the gap-limited external chain. Once the recovery window is
full of unfunded addresses, zecd by default issues past it with a loud log warning (such an
address may be unrecoverable from seed); with
`[pools] transparent_allow_beyond_recovery_window = false` it returns `-4` instead. See
[Transparent support](../guide/transparent.md).

**Result**: the address as a JSON string.

```json
"u1v0qh8pw9qm4h2v0negtfzrwhtjzfhgh0jcs9tzkjxg7xkpxkfhz5c4tj0nzqyjrmzgcqnyu7q6cx"
```

**Errors**

| Code | When |
|------|------|
| -8 | Non-empty `label` argument |
| -5 | Unknown `address_type` token; `"transparent"` combined with shielded pool names; otherwise-invalid pool list |
| -8 | `address_type` names a shielded pool not enabled on this wallet |
| -8 | `address_type` is `"transparent"` but `[pools] transparent` is off |
| -4 | Transparent gap limit reached and `transparent_allow_beyond_recovery_window = false` |

The `address_type` syntax is validated before the wallet is resolved, so an unknown token is
`-5` regardless of which wallet is targeted; pool enablement is checked per wallet.

**vs Bitcoin Core**: same signature (`label`, `address_type`) and the same `-5 Unknown
address type '...'` for a bad type, but zecd rejects a non-empty label with `-8` where Core
records it in the address book. The type values differ: pool names instead of
`legacy`/`p2sh-segwit`/`bech32`/`bech32m`.

**vs zcashd**: zcashd's `getnewaddress` is deprecated and only produces transparent
addresses; its shielded flow is `z_getnewaccount` + `z_getaddressforaccount`. zecd's
`getnewaddress` is the primary shielded path.

## z_getaddressforaccount

```
z_getaddressforaccount account ( ["receiver_type",...] diversifier_index )
```

Derives an address for the wallet's account in zcashd's syntax, optionally at an exact index.
Unlike `getnewaddress`, the returned object includes the index, so a client can re-derive the
same address deterministically later.

It serves two distinct cases depending on `receiver_types`:

- **Shielded (the default).** A Unified Address carrying the requested shielded receivers,
  indexed by ZIP-32 **diversifier index**.
- **Transparent** (`["p2pkh"]`, *new in 0.6.0*). A bare t-address at a **BIP 44 external
  child index**. See [transparent derivation](#transparent-derivation-at-an-explicit-index)
  below - the parameter is the same slot, but it means a different thing.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | account | number | required | Must be `0`. zecd has one account per wallet; select another wallet via `/wallet/<name>` instead. |
| 2 | receiver_types | array of strings | wallet default | Either shielded pools for a UA (`"sapling"` and/or `"orchard"`, each enabled on this wallet; empty/omitted uses the configured `default_receivers`), **or** exactly `["p2pkh"]` (equivalently `["transparent"]`) for a bare t-address. The two cannot be mixed. `"p2sh"` and unknown tokens are `-8`. |
| 3 | diversifier_index | number | next unused | For a shielded request: a non-negative integer within the 11-byte (2^88) diversifier space. For a transparent request: a BIP 44 external child index, so the hardened half (`>= 2^31`) is `-8`. Omitted picks the next unused index; given, it derives exactly that index. |

Re-deriving at the same index with the same receiver set is idempotent (byte-identical
response, zcashd's invariant). Requesting a *different* receiver set at an already-exposed
index is a `-4` reuse error. Auto-selected shielded indices are not sequential (the
next-unused selection is clock-seeded; see
[Addresses & shielded pools](../guide/addresses.md)), so record the returned
`diversifier_index` if you need to re-derive. Transparent indices *are* sequential.

### Transparent derivation at an explicit index

*New in 0.6.0.* On a wallet with `[pools] transparent = true`,
`z_getaddressforaccount 0 ["p2pkh"] N` returns the bare t-address at BIP 44 external child
index `N`.

**Why the receiver set must be exactly `["p2pkh"]`.** ZIP-316 forbids a transparent-only
unified address, and zecd never mixes a transparent receiver into a UA, so there is no address
shape that could carry both. Asking for `["p2pkh", "orchard"]` is therefore `-8` rather than
something zecd could silently reinterpret.

**It shares the exposure path with sequential issuance.** Deriving here and calling
`getnewaddress "" "transparent"` run the same code, so the two agree by construction: the same
recovery-horizon classification, the same warnings, the same `-4` when
`transparent_allow_beyond_recovery_window = false` would put the index out of restore range,
and the same refresh of the address matcher. That last one matters - without it a payment to a
directly addressed index would be silently dropped by the scanner. See
[Transparent support](../guide/transparent.md) for the two windows involved.

Together with [`getaddressinfo`](#getaddressinfo)'s `address_index`, this closes the loop for
an operator reconciling an issued range against the chain: ask for index `N`, and ask which
index an address was.

**Result**

```json
{
  "account": 0,
  "diversifier_index": 1000000,
  "receiver_types": ["orchard"],
  "address": "u1v0qh8pw9qm4h2v0negtfzrwhtjzfhgh0jcs9tzkjxg7xkpxkfhz5c4tj0nzqyjrmzgcqnyu7q6cx"
}
```

**Errors**

| Code | When |
|------|------|
| -1 | `account` missing |
| -8 | `account` outside zcashd's range `0 <= account <= (2^31)-2`, or not an integer |
| -4 | `account` in range but not `0` ("has not been generated"; zecd wallets have a single account) |
| -8 | `receiver_types` not an array; contains `"p2sh"` or an unknown token; names a pool not enabled on this wallet |
| -8 | `"p2pkh"`/`"transparent"` mixed with a shielded receiver, or requested on a wallet without `[pools] transparent = true` |
| -3 | A `receiver_types` element is not a string |
| -8 | `diversifier_index` fractional, negative, non-numeric, or beyond the 2^88 space ("too large"); for a transparent request, also `>= 2^31` (the hardened half) |
| -4 | Index already exposed with different receiver types ("was already generated with different receiver types.") |
| -4 | No address derivable at the requested index for the requested receivers (e.g. an invalid Sapling diversifier): "no address at diversifier index N." |
| -4 | Transparent index at or beyond the recovery horizon while `transparent_allow_beyond_recovery_window = false` |

**Example**

```sh
# The t-address at BIP 44 external child index 7.
curl -u u:p -d '{
  "jsonrpc": "1.0", "id": 1, "method": "z_getaddressforaccount",
  "params": [0, ["p2pkh"], 7]
}' http://127.0.0.1:8232/
```

**vs Bitcoin Core**: no equivalent.

**vs zcashd**: same syntax and result shape, and the reuse/no-address error strings match
zcashd's wording under the same `-4`. Deliberate divergences: zcashd accepts any previously
generated account number, zecd only account `0`; zcashd can return a UA that *includes* a
`p2pkh` receiver alongside shielded ones, while zecd treats `["p2pkh"]` as a request for a
bare t-address and rejects the mixture, because it never puts a transparent receiver in a UA.

## getaddressinfo

```
getaddressinfo "address"
```

Returns ownership and validity details for an address. `ismine` is cryptographic, not just a
lookup: after the recorded-address fast path, zecd attributes the address to the account's
incoming viewing key by decrypting its diversifier, so an address the account can derive but
never recorded (for example one handed out before a from-seed restore and never funded) still
reports `ismine: true`. Bare transparent addresses are recognized via recorded addresses only.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | address | string | required | The address to inspect. |

**Result**

```json
{
  "address": "u1v0qh8pw9qm4h2v0negtfzrwhtjzfhgh0jcs9tzkjxg7xkpxkfhz5c4tj0nzqyjrmzgcqnyu7q6cx",
  "scriptPubKey": "",
  "ismine": true,
  "solvable": true,
  "iswatchonly": false,
  "isscript": false,
  "iswitness": false,
  "isvalid_orchard": true,
  "receiver_types": ["orchard"],
  "labels": []
}
```

- `scriptPubKey`: the real hex script for transparent addresses; empty for shielded
  addresses, which have no script form.
- `solvable`: equals `ismine`, including on watch-only wallets (Core's definition ignores
  the lack of private keys; the wallet-level signal is `getwalletinfo.private_keys_enabled`).
- `iswatchonly`: always `false`, matching Core master where the field is deprecated.
- `isvalid_orchard`, `receiver_types`: zecd extensions mirroring
  [`validateaddress`](util-control.md): whether the address carries an Orchard receiver, and
  the full list of pools it can receive into (`transparent`/`sapling`/`orchard`).
- `labels`: always `[]` (zecd is [stateless](../design/statelessness.md); the field is kept
  for shape conformance).
- `receivers_consistent` (optional, extension): present only for a multi-receiver UA whose
  consistency against this wallet's keys is computable. `false` flags a hand-spliced UA
  (receivers from different diversifier indices, or one of ours mixed with a stranger's)
  that this wallet can never have issued.

**Derivation fields for an own transparent address** (*new in 0.6.0*)

On a bare t-address this wallet owns, three more fields report where it came from:

```json
{
  "address": "tmEjFVCkiVKmTPMHtnFHYJgvvyRJvpUZ4nD",
  "ismine": true,
  "hdkeypath": "m/44'/133'/0'/0/7",
  "ischange": false,
  "address_index": 7,
  "receiver_types": ["transparent"]
}
```

- `hdkeypath` and `ischange` are Bitcoin Core's fields, with Core's meaning: the full BIP 44
  path, and whether the address is on the internal (change) chain rather than the external
  one.
- `address_index` is a zecd extension carrying the BIP 44 child index on its own, so a caller
  does not have to parse it back out of the path string. It is the same index
  [`z_getaddressforaccount`](#z_getaddressforaccount) takes, which is what makes issuance and
  reconciliation a closed loop.

All three are absent for shielded addresses (a diversifier index is not a BIP 44 path) and
for transparent addresses this wallet does not own.

**Errors**

| Code | When |
|------|------|
| -1 | `address` missing |
| -5 | Address does not decode on this network ("Invalid address"; validity reporting belongs to `validateaddress`) |

**vs Bitcoin Core**: same core fields and the same `-5` on an undecodable address, plus
Core's `hdkeypath`/`ischange` on own transparent addresses. zecd still emits a subset
overall: no `desc`/`parent_desc`, no pubkey fields, no `timestamp`.
`isvalid_orchard`/`receiver_types`/`receivers_consistent`/`address_index` are additions.

**vs zcashd**: no equivalent; zcashd has only `validateaddress`/`z_validateaddress`, with
no ownership attribution for Unified Addresses in this shape.

## getwalletinfo

```
getwalletinfo
```

Wallet metadata and balances. `scanning` reports sync progress and stays truthy while the
transaction-enhancement backlog drains (the wallet is at the tip but still backfilling memos
and full transaction data), not just during the block scan.

**Result**

```json
{
  "walletname": "default",
  "walletversion": 169900,
  "format": "sqlite",
  "balance": 1.25000000,
  "unconfirmed_balance": 0.10000000,
  "immature_balance": 0.00000000,
  "txcount": 12,
  "keypoolsize": 1,
  "keypoolsize_hd_internal": 0,
  "paytxfee": 0.00000000,
  "private_keys_enabled": true,
  "avoid_reuse": false,
  "scanning": { "duration": 0, "progress": 0.9731 },
  "descriptors": false,
  "unlocked_until": 1751629200
}
```

- `balance`/`unconfirmed_balance`/`immature_balance`: decimal ZEC, 8 places, under the
  wallet's [confirmations policy](wallet-balances.md). `immature_balance` carries transparent
  coinbase that has not yet reached the 100-block maturity. It is never counted as spendable
  and never appears in [`listunspent`](wallet-history.md#listunspent); once mature the value
  becomes shieldable with [`z_shieldcoinbase`](async-operations.md#z_shieldcoinbase).
- `keypoolsize` is always `1` and `keypoolsize_hd_internal` always `0`: addresses are
  diversified on demand from the account key; there is no key pool.
- `paytxfee` is always `0` (fees are ZIP-317, never client-settable).
- `private_keys_enabled`: `false` for a [watch-only](../guide/watch-only.md) (imported UFVK)
  wallet; the wallet-level cannot-sign signal, as with Core's `disable_private_keys` wallets.
- `scanning`: an object (`duration` always `0`, `progress` the block-scan ratio in [0,1])
  while scanning or while the enhancement backlog is nonzero; `false` when idle.
- `descriptors`: always `false`.
- `unlocked_until`: present only for passphrase-encrypted wallets; the unix time the wallet
  auto-relocks, or `0` while locked. Absent on unencrypted and watch-only wallets.
- `transparent` (extension): present only when `[pools] transparent = true`, so a
  shielded-only wallet's shape is unchanged. `{"enabled": true, "default": <bool>,
  "gap_limit": <n>, "coinbase_balance": <amount>, "recovery_horizon": <n>}`, plus the
  lookahead fields below and, when `transparent_initial_scan` is set, an `initial_sync`
  object `{"exposed": <n>, "total": <n>, "complete": <bool>}` for polling the address
  pre-exposure. See [Transparent support](../guide/transparent.md).
- `transparent.recovery_horizon` / `.lookahead_from` / `.lookahead_through` / `.restorable`
  (extension): the two address windows, which are anchored differently and can disagree.
  `recovery_horizon` (`transparent_initial_scan + transparent_gap_limit`) is what a from-seed
  restore rediscovers within, anchored on **funding**, so handing an address out does not move
  it. `lookahead_from`/`lookahead_through` are the forward lookahead the running wallet
  scans ahead of its recorded addresses, both **inclusive** and anchored on **exposure**, so
  issuance does move them. They describe forward reach only: every address with a database row
  is matched too, including indices below `lookahead_from`. `restorable` is
  `lookahead_from <= recovery_horizon`, and `false` means the wallet is crediting addresses a
  from-seed restore would not rediscover, which is the field to alert on. The lookahead fields
  are absent until the matcher is first built, and `lookahead_through`/`restorable` are omitted
  when `gap_limit` is `0`. See
  [Two windows](../guide/transparent.md#two-windows-live-lookahead-vs-restore-recovery).
- `transparent.coinbase_balance` (extension): the unspent **mature** transparent coinbase
  value, the same number as [`getbalances.mine.coinbase`](wallet-balances.md#getbalances).
  It is already inside `balance`, and is reported separately because no ordinary send can
  select it: consensus forbids a transaction spending transparent coinbase from having any
  transparent output.

**vs Bitcoin Core**: `walletversion` 169900 and `format: "sqlite"` match Core's values.
Core master has dropped the `balance`/`unconfirmed_balance`/`immature_balance`/`paytxfee`
fields from this method (balances live on `getbalances`); zecd still emits them, in the
older Core shape. zecd omits Core's `external_signer`, `blank`, `birthtime`, `flags`, and
`lastprocessedblock` (the latter appears on zecd's `getbalances`). The `transparent` block
is an addition.

**vs zcashd**: zcashd's `getwalletinfo` keeps the old pre-0.19 Core shape plus its own
split (`balance` is transparent-only, with a separate `shielded_balance`), a real key pool
(`keypoololdest`), and a settable `paytxfee`; zecd follows modern Core instead.

## listwallets

```
listwallets
```

Returns the names of all loaded wallets: every `[wallets.<name>]` in the config (plus the
default wallet). Target a specific wallet with the `/wallet/<name>` URL path, as in Bitcoin
Core; see [Conventions & wire format](index.md).

**Result**

```json
["default", "watch1"]
```

**vs Bitcoin Core**: identical shape. zecd has no `createwallet`/`loadwallet`/
`unloadwallet`: the wallet set is fixed by configuration at startup, and at most one loaded
wallet may hold spending keys.

**vs zcashd**: no equivalent (zcashd is single-wallet).

## walletpassphrase

```
walletpassphrase "passphrase" timeout
```

Decrypts the seed of a passphrase-encrypted wallet into (mlocked) memory for `timeout`
seconds, after which it auto-relocks. Re-running it resets the timer; a `timeout` of `0`
relocks almost immediately. Only wallets created with `zecd init --encrypt` are
passphrase-encrypted; there is no passphrase-setting or passphrase-changing RPC, so the
passphrase is chosen at init and never crosses the network in any other call. See
[Key custody](../security/key-custody.md).

Before holding the seed unlocked, zecd verifies it derives the account's pinned UFVK; a
mismatch (a replaced `keys.toml` or wallet database) fails with `-4` and the wallet stays
locked.

**Parameters**

| # | Name | Type | Default | Description |
|---|------|------|---------|-------------|
| 1 | passphrase | string | required | The wallet passphrase. Must be non-empty. |
| 2 | timeout | number | required | Seconds to stay unlocked. Non-negative integer; values above 100,000,000 (~3.17 years) are silently clamped, as in Bitcoin Core. |

**Result**: `null`.

**Errors**

| Code | When |
|------|------|
| -1 | `passphrase` missing |
| -3 | `passphrase` not a string |
| -8 | Empty passphrase; missing or non-integer `timeout`; negative `timeout` ("Timeout cannot be negative.") |
| -14 | Wrong passphrase ("Error: The wallet passphrase entered was incorrect.") |
| -15 | Wallet is not passphrase-encrypted (identity-file or watch-only wallets): "Error: running with an unencrypted wallet, but walletpassphrase was called." |
| -4 | Decrypted seed does not derive this wallet's account (binding mismatch); refuses to unlock |

Argument validation runs before the encryption-state check, so a negative timeout is `-8`
even on an unencrypted wallet.

**Example**

```sh
curl -u user:pass -d '{"jsonrpc":"1.0","id":1,"method":"walletpassphrase","params":["correct horse battery staple",600]}' http://127.0.0.1:8232/
```

**vs Bitcoin Core**: same semantics, the same 100,000,000-second clamp, and the same
`-14`/`-15` messages. zecd unlocks a seed (scrypt-derived key over an age-encrypted
mnemonic) rather than a `wallet.dat` master key.

**vs zcashd**: same method and error codes, but zcashd has no timeout clamp, and its
wallet encryption (`encryptwallet`/`walletpassphrasechange`) is an experimental feature
disabled by default; zecd sets encryption once at `init --encrypt`.

## walletlock

```
walletlock
```

Drops the decrypted seed immediately and cancels the pending relock. Subsequent sends fail
with `-13` ("unlock needed") until the next `walletpassphrase`.

The zeroization takes a fast path: wallet commands normally serialize through the per-wallet
actor, so a lock queued behind a send that is mid-proof would wait out the whole proving
window. `walletlock` instead zeroizes the shared in-memory seed immediately, bypassing the
queue. The in-flight send already derived its spending key before proving, so it completes;
any queued send then fails `-13` at key derivation, which is the correct post-lock behavior.
The actor still processes the lock command afterward as the authoritative writer of the
relock deadline and published status.

**Result**: `null`.

**Errors**

| Code | When |
|------|------|
| -15 | Wallet is not passphrase-encrypted: "Error: running with an unencrypted wallet, but walletlock was called." |

**vs Bitcoin Core**: same semantics and the same `-15` on an unencrypted wallet.

**vs zcashd**: same method; zcashd locks its `wallet.dat` master key, zecd zeroizes the
in-memory seed.
