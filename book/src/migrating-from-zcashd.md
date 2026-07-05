# Migrating from zcashd

This page maps zcashd concepts and RPC methods onto zecd, and walks through the one supported
way to move funds. It is written for teams whose integration code speaks zcashd's RPC today
and who are replacing it with a `zebra → zecd` stack.

## Philosophy: a Bitcoin Core dialect, not a zcashd clone

zecd is **deliberately not zcashd-RPC-compatible**. Instead of re-implementing zcashd's `z_*`
surface, it speaks Bitcoin Core's JSON-RPC dialect (the same method names, response shapes,
JSON-RPC 1.0 envelope, HTTP Basic/cookie auth, and error codes as bitcoind) and maps those
onto shielded (Orchard-first) operations. The bet is that far more tooling, client libraries,
and operational muscle memory exist for Bitcoin Core RPC than for zcashd's wallet API, and
that zcashd's own trajectory pointed the same way: current zcashd already deprecates
`getnewaddress`, `z_getnewaddress`, `z_getbalance`, and `z_listaddresses` (denied by default
under `-allowdeprecated`), so "keep calling zcashd methods forever" was never on offer.

zecd keeps a small, deliberately chosen `z_*` subset where Bitcoin Core has no counterpart
for a shielded concept:

- [`z_sendmany`](rpc/async-operations.md) plus the operation-tracking trio
  `z_getoperationstatus` / `z_getoperationresult` / `z_listoperationids`: zcashd's
  asynchronous send pattern, kept so opid-based client code keeps working.
- [`z_listtransactions`](rpc/wallet-history.md): per-output history with `pool`, `memo` /
  `memoStr`, and zatoshi amounts.
- [`z_getaddressforaccount`](rpc/wallet-addresses.md): deterministic diversified-address
  derivation at a chosen diversifier index.

Everything else is the bitcoind method under the bitcoind name. The full per-method matrix is
in the [method index](rpc/method-index.md); the boundary itself (what zecd promises to match
and where it intentionally diverges) is in [Compatibility boundary](compatibility.md).

## Concept mapping

| zcashd | zecd |
|---|---|
| **Validator + wallet in one process**: zcashd validates the chain, indexes it, speaks P2P, and serves the wallet | **Wallet server over a separate full node**: zecd is wallet-only and talks JSON-RPC to a self-hosted [Zebra](design/zebra-backend.md) node (`zebra://host:port`, local-only plaintext). No P2P, no mining or chain-index RPC |
| **Many address kinds**: transparent `t1…`, Sprout, Sapling `zs…`, plus ZIP-316 unified accounts (`z_getnewaccount` + `z_getaddressforaccount`) | **One account per wallet, diversified Unified Addresses**: every `getnewaddress` returns a fresh diversified UA of the wallet's single account (Orchard receiver by default). All addresses derive from the seed; see [Addresses & shielded pools](guide/addresses.md) |
| **Sprout + Sapling + transparent pools** | **Orchard by default**; Sapling is opt-in via `[pools]`, transparent receive/spend is opt-in via `[pools] transparent` ([Transparent support](guide/transparent.md)). **No Sprout support at all**: move any Sprout funds with zcashd itself before decommissioning it |
| **Fee arguments**: `z_sendmany`/`z_mergetoaddress`/`z_shieldcoinbase` accept an explicit `fee` (default `null` = ZIP-317); `settxfee` works | **ZIP-317 only, never client-settable**: the wallet computes the fee at build time. An explicit numeric `fee` on `z_sendmany` is rejected `-8` (`null` is fine); `settxfee` always returns `-8`; `subtractfeefromamount`/`fee_rate` on sends are `-8` |
| **Zcash's error numbering** (Zcash `rpc/protocol.h`), e.g. `-18` = `RPC_WALLET_BACKUP_REQUIRED` | **Bitcoin Core's numbering** (Core `rpc/protocol.h`), e.g. `-18` = `RPC_WALLET_NOT_FOUND` (unknown `/wallet/<name>`). This is the one numeric collision zecd actually emits, and only from multiwallet routing, which zcashd lacks; tooling that hard-codes Zcash's numbering should know. The money-path codes (`-4`/`-5`/`-6`/`-8`/`-13` through `-17`/`-20`/`-26`) are identical across zcashd, Core, and zecd. See [Conventions & wire format](rpc/index.md) |
| **Per-key import/export**: `z_exportkey`, `z_importkey`, `dumpprivkey`, `importprivkey`, `z_exportwallet`, `backupwallet` | **Seed-only, no key import by design**: every address derives from the wallet mnemonic; the backup *is* the mnemonic (plus config). See [Stateless & recoverable](design/statelessness.md) |
| **Stateful bookkeeping**: labels/"accounts", `sent_notes` UA echo | **Stateless**: no label store (label methods are `-32601`), outgoing history shows the single receiver actually paid, identically before and after a from-seed restore |
| **Default spend confirmations 10** (`z_sendmany` `minconf`) | **ZIP-315 policy: 3 trusted / 10 untrusted**, configurable in `[spend]`; `minconf` still overrides per call |

## RPC mapping

For each commonly used zcashd wallet RPC, the zecd equivalent, or the supported alternative
where there is none. Methods not listed here (and not in the [method index](rpc/method-index.md))
return method-not-found (`-32601`, HTTP 404).

### Addresses and accounts

| zcashd | zecd | Notes |
|---|---|---|
| `z_getnewaccount` | not supported | zecd is one account per wallet, created at `zecd init`. Need more accounts → more wallets (`[wallets.<name>]`, one spending wallet max) |
| `z_getaddressforaccount` | `z_getaddressforaccount` | Same shape; `account` must be `0`. Receiver types are shielded-only (`orchard`/`sapling`); `p2pkh` is `-8`. Optional `diversifier_index` re-derives idempotently |
| `z_getnewaddress` *(deprecated in zcashd)* | `getnewaddress` | Returns a fresh diversified UA (Orchard by default). A `label` argument is rejected `-8`; the second arg is an `address_type` receiver override |
| `getnewaddress` *(deprecated in zcashd; returns a t-addr)* | `getnewaddress "" "transparent"` | Only with `[pools] transparent = true`; returns a bare `t1…` address. See [Transparent support](guide/transparent.md) |
| `z_listaddresses` *(deprecated)*, `listaddresses` | `listreceivedbyaddress 0 true` | `include_empty=true` enumerates every address the wallet has generated, with received totals |
| `z_listunifiedreceivers` | not supported | Decode the UA client-side with any ZIP-316 library; zecd keeps no recipient-side UA bookkeeping |

### Balances

| zcashd | zecd | Notes |
|---|---|---|
| `z_gettotalbalance` *(deprecated)* | `getbalance` / `getbalances` | Wallet-level totals; `getbalances` splits `trusted` / `untrusted_pending` / `immature` |
| `z_getbalanceforaccount` | `getbalances` | One account per wallet, so the wallet totals are the account totals |
| `z_getbalance` *(deprecated; per-address)* | `getreceivedbyaddress` | zecd has no per-address *balance* (all diversified addresses fund one account); per-address *received* totals exist |
| `z_getbalanceforviewingkey` | watch-only wallet | `zecd export-ufvk` on the spender, `zecd init --ufvk` elsewhere, then `getbalance` there. See [Watch-only wallets](guide/watch-only.md) |
| `getbalance` | `getbalance` | Spendable under the ZIP-315 policy; explicit `minconf` overrides per call |
| `getunconfirmedbalance` | `getunconfirmedbalance` | Includes 0-conf mempool receives |

### History and unspent

| zcashd | zecd | Notes |
|---|---|---|
| `listtransactions` | `listtransactions` | Core shape plus `memo`/`memoStr`; `label` fields always `""` |
| `z_viewtransaction` | `gettransaction` / `z_listtransactions` | `gettransaction` is the Core shape extended with memo fields; `z_listtransactions` carries zcashd's per-output vocabulary (`pool`, `amountZat`, `outindex`, …) |
| `z_listreceivedbyaddress` | `listreceivedbyaddress` / `z_listtransactions` | Core totals per address, or per-output entries with memos |
| `z_listunspent` | `listunspent` | One entry per unspent note with synthesized `(txid, vout)`; `address` empty for change |
| `listsinceblock` | `listsinceblock` | Cursor semantics; `removed` always `[]` |
| `z_getnotescount` | not supported | |

### Sending

| zcashd | zecd | Notes |
|---|---|---|
| `z_sendmany` | `z_sendmany` | Same syntax and async opid flow. Differences: `fromaddress` must be one of this wallet's own addresses (`ANY_TADDR` or a foreign address → `-5`); explicit numeric `fee` → `-8` (pass `null` or omit); `privacyPolicy` maps onto zecd's [four-rung ladder](design/privacy.md), and `LegacyCompat` (or omitted) uses the configured `[spend] privacy_policy` default rather than zcashd's UA-dependent rule; at most 16 unfinished operations per wallet, beyond which new calls are `-4` |
| `sendtoaddress`, `sendmany` | `sendtoaddress`, `sendmany` | Synchronous bitcoind-style sends: build, prove, broadcast, return the txid. Extra trailing hex `memo` parameter on `sendtoaddress`. See [Sending](rpc/sending.md) |
| `z_getoperationstatus` / `z_getoperationresult` / `z_listoperationids` | same | Same semantics, including destructive one-shot `z_getoperationresult`. Wallet-scoped and in-memory (lost on restart, as in zcashd) |
| `z_shieldcoinbase` | not supported | No auto-shielding path yet: a transparent receive can only be spent transparently (opt-in) or left in place. See [Known limitations](limitations.md) |
| `z_mergetoaddress` | not supported | |
| `z_setmigration` / `z_getmigrationstatus` | not supported | The Sapling-migration machinery has no zecd counterpart |
| `z_converttex` | not supported | |

### Keys, backup, and wallet management

| zcashd | zecd | Notes |
|---|---|---|
| `backupwallet`, `z_exportwallet`, `z_importwallet` | not supported | The backup is the mnemonic shown once at `zecd init` (plus your config). Restore with `zecd init --restore --birthday <height>`; the wallet DB rebuilds from seed + chain |
| `z_exportkey`, `z_importkey`, `dumpprivkey`, `importprivkey`, `importaddress`, `importpubkey` | not supported | No per-address key import/export by design; all addresses derive from the seed |
| `z_exportviewingkey` | `zecd export-ufvk` (CLI) | Prints the wallet's Unified Full Viewing Key; not an RPC |
| `z_importviewingkey` | `zecd init --ufvk <key>` (CLI) | Creates a watch-only wallet |
| `encryptwallet`, `walletpassphrasechange` | not supported | Encryption is set once at `zecd init --encrypt`; the passphrase never crosses the network |
| `walletpassphrase`, `walletlock` | same | Bitcoin Core semantics (`-13` locked send, `-14` wrong passphrase, `-15` unencrypted) |
| `walletconfirmbackup` | not supported | zcashd's `-18` "backup required" flow does not exist |
| `getrawchangeaddress`, `addmultisigaddress`, `signmessage`, `keypoolrefill`, `lockunspent`, `listlockunspent` | not supported | `-32601` |
| `settxfee` | dispatched, always `-8` | Fees are ZIP-317, computed by the wallet |

## Migrating funds

**The only supported migration path is an on-chain send** from zcashd to an address generated
by zecd. There is no key or wallet import, by design: zecd's statelessness and restore
guarantees hold only for addresses derived from its own seed.

1. Set up the target: a synced Zebra node, then `zecd init` (record the mnemonic offline) and
   start the daemon; see the [Quickstart](quickstart.md).
2. On zecd, generate a receiving address:

   ```sh
   curl -u user:pass --data-binary \
     '{"jsonrpc":"1.0","id":"m","method":"getnewaddress","params":[]}' \
     http://127.0.0.1:8232/
   ```

   The result is a Unified Address (`u1…`).
3. On zcashd, send everything to that UA with `z_sendmany`. Note zcashd's default
   `privacyPolicy` is `LegacyCompat`, which treats any transaction involving a UA as
   `FullPrivacy`, so spending zcashd's **transparent** funds to zecd's UA fails under the
   default; pass `"AllowRevealedSenders"` (this reveals the sending transparent addresses and
   amounts on-chain). Shielded Sapling funds crossing into Orchard need
   `"AllowRevealedAmounts"` (reveals only the amount crossing the pool turnstile).
4. Wait for confirmations, then verify on zecd with `getbalance` / `listtransactions`.
   Remember zecd's spendability policy defaults to 3 confirmations for your own transactions
   and 10 for third-party ones.

Two seed-related cautions:

- **Do not share a seed phrase between apps**: do not restore zcashd's mnemonic into zecd or
  vice versa. zecd's restore guarantees hold only for wallets its own `init` created.
- As a deliberate **escape hatch**, a zecd seed phrase works in any other librustzcash-based
  wallet (for example Zodl): if something goes badly wrong with zecd, funds remain accessible
  elsewhere. Shielded funds are unconditionally recoverable from seed; transparent funds only
  within the configured gap-limit / initial-scan window; see
  [Stateless & recoverable](design/statelessness.md).

## Operational differences

- **You run two processes, not one.** zecd needs a self-hosted Zebra node reachable over
  local/private JSON-RPC (`zebra://…`; plaintext HTTP guarded by a cleartext-credential gate).
  Everything zecd believes about the chain comes from that node. See
  [A Zebra-only backend](design/zebra-backend.md) and [Deployment](guide/deployment.md).
- **Light-client sync.** zecd derives compact blocks from the node and trial-decrypts them; it
  keeps no chain index. After a restore, an *enhancement* backlog (re-fetching full
  transactions to backfill memos and outgoing details) can keep the wallet in
  `initialblockdownload`/`scanning` state after the block scan reaches the tip. Watch
  `getwalletinfo.scanning` and the `/readyz` health endpoint
  ([Operations runbook](guide/operations.md)).
- **Sends take a few seconds.** Every shielded send builds a zero-knowledge proof, so
  `sendtoaddress`/`sendmany` hold the HTTP connection for a few seconds; raise client
  timeouts accordingly. `z_sendmany` keeps zcashd's asynchronous pattern (returns an opid
  immediately) if you prefer not to block.
- **Sends serialize per wallet.** A single-writer actor owns each wallet, so concurrent sends
  to one wallet queue rather than double-spend ([Architecture](design/architecture.md)).
- **Multiwallet is bitcoind-style** (`/wallet/<name>` routing), with at most one spending
  wallet per daemon plus any number of watch-only wallets.
- **No P2P, mining, or chain-index RPC**: those live on the Zebra node.

## Client code changes checklist

For code that drives zcashd today:

1. **Endpoint**: point the client at zecd (default port 8232 mainnet / 18232 testnet), with
   `/wallet/<name>` paths if you configure multiple wallets. Auth is HTTP Basic or cookie,
   bitcoind-style.
2. **Addresses**: replace `z_getnewaccount` + `z_getaddressforaccount` (or `z_getnewaddress`)
   with `getnewaddress`; expect a UA. Drop any `label` arguments: `getnewaddress` rejects
   them with `-8`, and the label methods are gone (`-32601`).
3. **Balances**: replace `z_gettotalbalance` / `z_getbalanceforaccount` with `getbalance` /
   `getbalances`. Keep parsing amounts as exact decimals (e.g. Python `Decimal`): they are
   bare JSON numbers with 8 decimal places, never floats.
4. **Fees**: delete every fee argument. Pass `null` (or omit) for `z_sendmany`'s `fee`; an
   explicit number is `-8`. Remove `settxfee`, `subtractfeefromamount`, and `fee_rate` usage.
5. **Error handling**: re-check any hard-coded error numbers against Bitcoin Core's
   `rpc/protocol.h`. The money-path codes are unchanged; the notable collision is `-18`
   (zcashd "backup required" vs zecd/Core "wallet not found").
6. **Async sends**: opid flows keep working, but budget for the per-wallet cap of 16
   unfinished operations (`-4` beyond it) and remember `z_getoperationresult` consumes each
   result exactly once.
7. **Timeouts**: raise HTTP client timeouts for `sendtoaddress` / `sendmany` (proving takes
   seconds).
8. **Confirmation assumptions**: zecd's default spend policy is ZIP-315 (3 trusted / 10
   untrusted) rather than a flat `minconf=10`; pass `minconf` explicitly where your logic
   depends on it.
9. **Removed surface**: audit for calls to key import/export, wallet export, shielding
   (`z_shieldcoinbase`/`z_mergetoaddress`), migration, and label RPCs; replace with the
   alternatives in the [mapping table](#rpc-mapping) or remove.
