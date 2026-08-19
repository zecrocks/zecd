# Changelog

All notable changes to zecd are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com), and this
project adheres to [Semantic Versioning](https://semver.org).

## [0.6.2] - 2026-08-19

A dependency security fix. No first-party code changes, no configuration or response shape
moves, so upgrading from 0.6.1 is a drop-in.

### Security
- **h2 is upgraded to 0.4.16**, for RUSTSEC-2026-0258. Versions through 0.4.15 accept and queue empty DATA frames without limit, so a stream that is not actively drained can grow memory without bound. zecd reaches h2 only transitively, but by two paths that both carry real traffic: hyper under axum, which serves the JSON-RPC port, and hyper under tonic, which is light mode's upstream connection. Low severity upstream, and the fix is the upgrade.

### Changed
- The funded regtest tier pays from the 0.6.1 release image rather than 0.5.2, and a funder binary that cannot answer `zecd config check` now fails the run instead of quietly skipping that assertion. Test-only; nothing about a running daemon changes.

## [0.6.1] - 2026-08-11

Received transparent funds can now be moved into the shielded pool. Until this release a wallet
holding t-address UTXOs could pay out of its notes but never out of the coins it had actually
received, because `z_sendmany` accepted a `fromaddress` and then honoured it only as an account
selector.

Nothing changes for a wallet that does not pass a transparent `fromaddress`, and spending
transparent inputs is off unless the operator opts in. Read the Changed section before upgrading
if `[spend] privacy_policy` is set to `AllowRevealedSenders` or `AllowFullyTransparent`: both
mean something different now.

### Added
- **Coin control on `z_sendmany`.** `fromaddress` is a real input-side selector, as it is in zcashd. A wallet-owned t-address funds the send from that address's non-coinbase UTXOs, `ANY_TADDR` (previously refused) funds it from any of them, and a shielded or unified address keeps meaning the account's shielded notes. With a shielded recipient a transparent source is the shielding send: the payment and the change both land in the shielded change pool, which is how received transparent funds reach Orchard. Paying a t-address from shielded notes already worked and is unchanged. One source funds one send, so a shortfall is an error rather than a silent top-up from the other pool, and transparent coinbase remains `z_shieldcoinbase`'s alone.
- An `AllowRevealedSenders` rung on `[spend] privacy_policy`, between `AllowRevealedRecipients` and `AllowFullyTransparent`. Spending transparent inputs publishes the sender's addresses and input amounts, which is a disclosure a caller opts into separately from revealing a recipient. A transparent `fromaddress` under anything weaker, the default included, is refused before the send is queued, with the policy name that would allow it named in the error.
- A regtest end-to-end for the whole ladder: the refusal matrix, a per-address shield that leaves an un-named UTXO untouched, an `ANY_TADDR` shield down to zero transparent UTXOs, and a deshielding round trip under the default policy. It runs on both the full-node and light-mode legs.

### Changed
- `AllowRevealedSenders` in `[spend] privacy_policy` was previously accepted as an alias and collapsed onto `AllowRevealedRecipients`, on the reasoning that a wallet with no transparent source had no sender to reveal. That is no longer true, so the name now selects the distinct, strictly more permissive rung described above. A configuration carrying it gains the ability to fund sends from transparent UTXOs; set `AllowRevealedRecipients` to keep the previous meaning.
- Under `AllowFullyTransparent` with all-transparent recipients, an explicitly shielded `fromaddress` now pays from shielded notes, as zcashd does, instead of silently taking the fully transparent branch; a t-address `fromaddress` on that branch narrows selection to that address. Sends made without a source, including `sendtoaddress` and `sendmany`, are unaffected.

### Fixed
- The stress regtest tier built no notes. Each fan-out round paid the same freshly issued address once per output, which `z_sendmany` refuses as a duplicated recipient, so the call never left the RPC layer. Rounds now pay a set of distinct addresses. Test-only; no effect on a running daemon.

## [0.6.0] - 2026-08-08

The 0.6.0 line, released as `0.6.0-rc1` through `0.6.0-rc3`. Everything below is relative to
0.5.2; the release-candidate sections that follow are kept for history. Two changes land here
that were not in any candidate, both listed under Changed and neither behavioural.

A feature release: an optional lightwalletd backend, four additions to the RPC surface, two new
offline subcommands, and a faster start. No existing response shape or default changes, so
upgrading from 0.5.2 is a drop-in for a full-node deployment.

Two things to read before deploying. Release artifacts are **named differently** from 0.5.x,
which matters to anything that downloads them by filename. And the librustzcash wallet crates
this release depends on are still **published as release candidates** upstream: the NU6.3 line
has no finals yet, and the newest stable versions predate ironwood entirely, so there is nothing
to move to. That is a deliberate choice, not an oversight, and it is unchanged from every release
since 0.5.0-rc3.

### Added
- An optional **lightwalletd backend**. `[backend] server` accepts a lightwalletd gRPC endpoint as well as a local zebrad, so zecd can run without a fully synced full node; the full node remains the default and the recommendation. The token selects the mode: `zebra` and `zebra://host:port` are full mode, while `https://host[:port]`, `http://host:port`, a bare `host:port` and the `zecrocks` preset are light mode. Every feature works on both, including transparent addresses.
- TLS controls for a light upstream: `tls`, `tls_roots`, `tls_ca_file`, `tls_pinned_sha256` and `tls_insecure_skip_verify`. Plaintext to a globally routable host is refused unless `allow_remote_cleartext` is set, because what it leaks is which addresses the wallet is asking about. `assume_transparent_in_compact_blocks` lets an operator assert a server serves transparent and Ironwood data in compact blocks, which a transparent-enabled wallet requires.
- `z_waitforoperation "opid" ( timeout )` blocks until an async operation finishes and returns its status object, so a caller writes two calls instead of a poll-sleep loop. Timing out is not an error, and a `finished` flag distinguishes the two outcomes.
- `waitfornewblock`, `waitforblock` and `waitforblockheight`, matching Bitcoin Core. All three block on the wallet's fully-scanned height rather than the chain tip, which is the answer to "has the wallet caught up to N?". Polling a balance instead is wrong: the mempool credits a payment at zero confirmations, so a balance is satisfied before the confirming block is scanned.
- `z_getaddressforaccount` derives a transparent address at an explicit BIP 44 child index, and `getaddressinfo` on an own transparent address reports `hdkeypath`, `ischange` and an `address_index` extension. Together these close the loop for reconciling an issued transparent range against the chain.
- `zecd derive-address` derives addresses with no network, no wallet database, no daemon and no datadir lock, so it runs beside a live one. Key material comes from an initialized wallet's account UFVK, a mnemonic, or a bare UFVK.
- `zecd config check` resolves a config with the exact binary about to be deployed and exits non-zero if that build would refuse it, without starting the daemon or writing anything. `zecd config show` prints the effective configuration as round-trippable TOML, with secrets emitted as commented-out key names.

### Changed
- The Orchard proving key builds in the background instead of before the daemon binds its listeners. Startup previously spent seconds of CPU, much more on a small machine, unreachable and not syncing, to produce a key only sends need. Startup probes sized around the old behaviour can be tightened.
- Release artifacts use one architecture token per target, so a listing reads `zecd-<version>-linux-amd64.tar.gz` next to `zecd_<version>_amd64.deb` rather than mixing Debian names with Rust target triples, and the per-file `.sha256` sidecars are replaced by a single `SHA256SUMS`. **The 0.5.x line deliberately keeps the old names**, so this is the release where filename-based tooling needs updating.
- Every top-level CLI flag is global, so it is accepted on either side of the subcommand.
- The librustzcash line moves to `zcash_client_backend 0.24.0-rc.7`, `zcash_client_sqlite 0.22.0-rc.8`, `pczt 0.9.3` and `orchard 0.15.5`. Opening a wallet created on an older pin migrates it forward on first start.
- *New since rc3:* the example config no longer promises a future `ironwood` pool under `[pools]`. It was never going to arrive, and a unit test already rejects `enabled = ["ironwood"]`. The replacement keeps the two senses of the word apart: ironwood is a value pool, with its own bundle and its own `valueBalance`, but it has no receiver, and that key selects receivers. This file is embedded in the binary and printed by `zecd example-config`, so the wrong version shipped to operators in every 0.6.0 candidate.
- *New since rc3:* the internal `Pool` type is renamed `Receiver`, which is what it models. No config key, RPC field or behaviour changes: `[pools]` is still `[pools]`, and the `pool` field in `listunspent` and `z_listtransactions` still reports `ironwood`.

### Fixed
- `getwalletinfo.transparent.restorable` no longer reports `false` for a from-seed restore that has issued no addresses. The reported recovery horizon assumed a floor of 0, so any seed whose default-address index exceeded the gap limit was described as beyond its own recovery window. Only the reported horizon was wrong: the exposure is re-derived identically by every restore of a seed, so two restores always agreed and no funds were at risk.
- A wallet that meets an unrecoverable reorg halts instead of retrying forever. Where no note-commitment-tree checkpoint below the conflict has a scanned block, every truncation target is refused and no retry can succeed; the wallet kept trying, re-establishing the upstream connection each time, which reads in the log like a flaky node. It now halts, says so once, and keeps serving reads until an operator rebuilds with `zecd rescan`.

## [0.6.0-rc3] - 2026-08-07

Three fixes and a dependency bump on top of `0.6.0-rc2`. The lightwalletd backend itself is
unchanged.

### Fixed
- `getwalletinfo.transparent.restorable` no longer reports `false` for a from-seed restore that has issued no addresses. Creating an account always derives and exposes the account's default Unified Address, whose diversifier index is the seed's first index valid for every receiver; with a Sapling receiver in play that index is 0 for only about half of seeds and 3 or more for roughly one in eight. The reported recovery horizon assumed the floor was always 0, so any seed whose default index exceeded the gap limit was described as beyond its own recovery window. The horizon is now anchored at the restore floor, the larger of `transparent_initial_scan` and the default-address frontier, through a single helper shared by the wallet reads, the beyond-gap issuance classification, and the low-headroom warnings. Only the reported horizon was ever wrong: the exposure itself is re-derived identically by every restore of a seed, so two restores of the same seed always agreed and no funds were at risk.
- A wallet that meets an unrecoverable reorg halts instead of retrying forever. When a reorg conflicts at a height with no note-commitment-tree checkpoint below it that has a scanned block, every truncation target is refused and no retry can ever apply the range; the wallet nonetheless kept trying, dropping and re-establishing the upstream connection each time, which reads in the log like a flaky node rather than a wallet that needs rebuilding. That failure is now a distinct error carrying the conflict height and the rewind bounds, the sync loop treats it as terminal and says so once, and the wallet keeps serving commands and reads while it waits for an operator to rebuild the database with `zecd rescan`. No other failure class is treated as terminal.
- The light-mode regtest suite exercises a light upstream again. Six of its seven binaries were not swapping the backend, so under the light-mode setting they still ran against zebra and repeated the standard suite's coverage rather than testing light mode. Test-only; it did not affect a running daemon.

### Changed
- The librustzcash line moves to `zcash_client_sqlite 0.22.0-rc.8`, `pczt 0.9.3` and `orchard 0.15.5`, plus the pool-migration and proof-system crates those pull in. `zcash_client_backend` stays at `0.24.0-rc.7`, which is what the sqlite crate requires and the newest published. rc.8 is almost entirely pool-migration work over tables zecd never writes; the two changes that touch paths zecd uses are both more forgiving than before, and the orchard change shares setup across a batch of trial decryptions, which is throughput only on the block-scan path. Opening a wallet created on the previous pin migrates it forward on first start.
- The config-validation tests and the container smoke test now run against the configs that ship, rather than a config written for the test. The container additionally runs `config check` on the config the compose stack mounts, so the runtime image is proved to read a production-shaped config rather than only to report its version.

## [0.6.0-rc2] - 2026-08-06

Adds an optional lightwalletd backend. Everything in 0.6.0-rc1 is unchanged, and full mode
against a local zebra remains the default and the recommendation, so an existing deployment
that does not set a new `[backend] server` token is unaffected.

This is a 0.6.x-only addition: the 0.5.x line does not carry it.

### Added
- `[backend] server` accepts a lightwalletd gRPC endpoint as well as a local zebrad, so zecd can run without a fully synced local full node. The token selects the mode: `zebra` and `zebra://host:port` are full mode; `https://host[:port]`, `http://host:port`, a bare `host:port`, and the `zecrocks` preset are light mode. Every feature, including transparent addresses, works in both.
- TLS controls for a light upstream: `tls` forces or disables it (the default decides by locality, so loopback and private networks stay plaintext and public hosts get TLS), `tls_roots` picks the OS store or the embedded bundle, `tls_ca_file` adds a private CA, and `tls_pinned_sha256` pins the leaf certificate. Plaintext to a globally routable host is refused unless `allow_remote_cleartext` is set, because what it leaks is which addresses the wallet is asking about.
- `assume_transparent_in_compact_blocks` lets an operator assert that their lightwalletd serves transparent and Ironwood data inside compact blocks. The connect-time probe reads the advertised protocol version, and a transparent-enabled wallet refuses to run against a server that does not advertise it rather than silently never discovering those receives. No released lightwalletd populates that advertisement yet, so the assertion is currently required in practice.
- `zecd config check` gained the light-mode gates: it warns about a transparent wallet on a light upstream without the capability assertion, about `tls_insecure_skip_verify`, about a capability assertion that will be ignored on a zebra upstream, and about a large transparent address set on a light backend.

### Changed
- Transparent spend detection costs one upstream query per funded address, which is a local index lookup on zebra and a remote round trip on a light backend. A wallet tracking many funded transparent addresses is therefore still better served by its own zebra; both the daemon and `config check` say so once, at startup and on demand.

## [0.6.0-rc1] - 2026-08-05

A feature release: four additions to the RPC surface, two new offline subcommands, and a faster
start. Nothing here changes an existing response shape or default, so upgrading from 0.5.2 is a
drop-in. The one operational change is that release artifacts are named differently, which matters
only to a script that downloads them by filename.

### Added
- `z_waitforoperation "opid" ( timeout )` blocks until an async operation finishes and returns its status object, so a caller writes two calls instead of a poll-sleep loop. Timing out is not an error: the current queued or executing status comes back, and a `finished` flag distinguishes the two outcomes. The timeout defaults to 120 seconds and clamps at 3600, since a blocking call holds an RPC work-queue permit for its whole duration. The wait is non-destructive; `z_getoperationresult` remains the only reader that reaps.
- `waitfornewblock`, `waitforblock` and `waitforblockheight`, matching Bitcoin Core. All three block on the wallet's fully-scanned height rather than the chain tip, which is the answer to "has the wallet caught up to N?" that previously required reading the source. Polling a balance instead is wrong, because the mempool credits an incoming payment at zero confirmations, so a balance is satisfied before the confirming block is scanned and any height-dependent field read next may not be written yet.
- `z_getaddressforaccount` derives a transparent address at an explicit BIP 44 child index, and `getaddressinfo` on an own transparent address now reports `hdkeypath`, `ischange` and an `address_index` extension. Together these close the loop for an operator reconciling an issued transparent range against the chain: previously there was no way to ask for index N, and no way to learn which index `getnewaddress` had just handed out.
- `zecd derive-address` derives addresses with no network, no wallet database, no daemon and no datadir lock, so it runs beside a live one. Key material comes from an initialized wallet's account UFVK, so no seed is decrypted and a locked or watch-only wallet works, or from a mnemonic or a bare UFVK. It answers the chicken-and-egg for pre-provisioning deposit addresses, air-gapped setup, and pointing a miner at a wallet that does not exist yet.
- `zecd config check` resolves a config file with the exact binary about to be deployed and exits non-zero if that build would refuse it, without starting the daemon, taking the datadir lock, or writing anything. Every check is either the resolver itself or a helper the daemon calls at startup, so the check cannot reach a different verdict than the daemon would.
- `zecd config show` prints the effective configuration as round-trippable TOML: the file, flags and environment resolved together, with every unset key filled in by the build's default. Diffing two versions' output shows exactly which defaults an upgrade moves. Secrets are emitted as commented-out key names, never values.

### Changed
- The Orchard proving key builds in the background instead of before the daemon binds its listeners. Startup previously spent seconds of CPU, and considerably more on a small machine, unreachable and not syncing, to produce a key that only sends need. The first send awaits the build, which on any real deployment has long since finished.
- Release artifacts use one architecture token per target, so a listing reads `zecd-<version>-linux-amd64.tar.gz` next to `zecd_<version>_amd64.deb` rather than mixing Debian names with Rust target triples. The per-file `.sha256` sidecars are replaced by a single `SHA256SUMS` in the standard `sha256sum -c` format.
- The librustzcash wallet crates move to `zcash_client_backend 0.24.0-rc.7` and `zcash_client_sqlite 0.22.0-rc.7`. rc.7 records a transaction's Ironwood outputs when extracting a PCZT, so the workaround that re-decrypted a just-stored send to recover its memos is gone. Opening an existing wallet runs an additive schema migration.

## [0.5.2] - 2026-08-03

Three fixes for wallets holding Ironwood notes, which since NU6.3 activated on mainnet at height
3,428,143 means any wallet whose shielded funds were received after that point. All three are live
behaviour rather than latent, so this release is worth taking.

### Fixed
- Transactions that spend Ironwood notes are rebroadcast. The unmined-transaction set qualified a transaction by checking that it spends something the wallet owns, and that test covered sapling, orchard and transparent spends only. An ironwood spend is recorded separately, so after NU6.3 no send qualified at all: a send whose broadcast failed, which is the case rebroadcast exists for, was never retransmitted and sat unmined until it expired. Nothing reported an error, since the send returns a txid and the transaction is stored.
- A FullPrivacy send no longer crosses the Ironwood turnstile. The policy check asked whether a send involved Transparent, Sapling and Orchard and never asked about Ironwood, so a send spending ironwood notes to a Sapling or Orchard recipient passed unexamined, even though moving value between two pools reveals the amount on chain. The rule is now any transparent component, or more than one shielded pool.
- Outgoing history reduces an Ironwood output to the Orchard receiver it actually pays. Ironwood notes are received at ordinary Orchard addresses, but the reduction handled only transparent, Sapling and Orchard, so an ironwood row fell back to the full multi-receiver address the caller typed, which a restore from seed cannot reproduce.

### Added
- `getwalletinfo.transparent` reports the wallet's live lookahead window as `lookahead_from` and `lookahead_through`, both inclusive, alongside the existing `recovery_horizon`, plus a derived `restorable`. The two windows are anchored differently, and the difference decides whether funds survive a restore: the live window follows addresses handed out, while restore recovery follows funding, so a running wallet can credit a receive that a restore of the same seed would not rediscover. `restorable` is false exactly when the wallet is in that state, which happens only when an address is issued at or past the recovery horizon.

## [0.5.1] - 2026-08-01

The 0.5.1 line, released as `0.5.1-rc1` through `0.5.1-rc4` and unchanged since `0.5.1-rc4`.
Everything below is relative to 0.5.0; the release-candidate sections that follow are kept for
history.

Two of these fixes affect wallets running 0.5.0 with `[pools] transparent = true`, which is off
by default. If that is you, this release is worth taking.

### Added
- Coinbase spending. Transparent coinbase is swept with `z_shieldcoinbase` into a single shielded output once it reaches the 100-block maturity, which is the only shape consensus permits, since a transaction spending transparent coinbase may carry no transparent output at all. Shielded coinbase (ZIP-213) needs no special handling. `listunspent` tags transparent entries with zcashd's `generated` flag and excludes immature coinbase, which is reported as `getwalletinfo.immature_balance` until it matures.
- `zecd rescan` rebuilds a wallet whose database has become unusable, keeping `keys.toml` and the seed so the next start recreates the account and rescans from the birthday. It takes the datadir lock, so it refuses to run against a live daemon.
- A stuck sync says why it is stuck, distinguishing a network upgrade this build does not understand from a wallet database that cannot apply otherwise-valid blocks.
- `getbalances.mine.coinbase` and `getwalletinfo.transparent.coinbase_balance` report the unspent mature transparent coinbase value, which counts toward the balance but which no ordinary send can select; the insufficient-funds error now names that amount and points at `z_shieldcoinbase`.

### Changed
- The transparent gap limit is anchored at the issuance frontier, the highest of the last funded index, the last index handed out, and the `transparent_initial_scan` floor, so it composes with `transparent_initial_scan` and a stateless restore recovers up to the sum of the two. Anyone who inflated `transparent_gap_limit` to match a large initial scan should now reduce it: the daemon warns above 1000 and logs an error above 10000, neither blocking startup.
- `getreceivedbyaddress` and `listreceivedbyaddress` honor `include_immature_coinbase`, as Bitcoin Core does.
- Ironwood sends take the cached proving key rather than rebuilding one per send.
- The librustzcash wallet crates move to `zcash_client_backend 0.24.0-rc.6` and `zcash_client_sqlite 0.22.0-rc.6`.

### Fixed
- Transparent spends the wallet did not author itself are discovered. The spent output used to stay in the unspent set, so the wallet reported a balance it no longer held and could select that output for a send that then failed at broadcast. Watch-only wallets were the sharpest case, since every transparent spend they see is external.
- A received coinbase output is recorded as coinbase, so the maturity rule applies to it rather than letting it count as spendable immediately, and transparent-to-transparent sends exclude coinbase inputs, which would have been consensus-invalid.
- A restore no longer crawls or appears to stall. Transparent spend-detection requests are serviced to the chain tip instead of in roughly 40-block windows that each queued a successor, and a large `transparent_gap_limit` no longer re-derives the whole window on every recorded receive.
- `getwalletinfo.scanning.progress` reflects the whole scan instead of reading 1.0 from the start, and `scanning` no longer flips to false partway through a restore.

## [0.5.1-rc4] - 2026-07-31

### Fixed
- Transparent spends the wallet did not author itself are now discovered. The block scan matched only transparent outputs, and the address check that would have found such a spend is never requested for an output the scan itself recorded, which is every transparent receive. The spent output therefore stayed in the unspent set, so the wallet reported a balance it no longer held and could select that output for a send that then failed at broadcast. A restore of a wallet that had received and spent on a transparent address while down reported 0.7999 against an actual 0.2999. Each block's transparent inputs are now matched against the wallet's unspent outputs during the scan it already performs, at no extra request. This affects every release from 0.5.0 onward for wallets with `[pools] transparent = true`, which is off by default; shielded-only wallets find spends through note nullifiers and were never affected. Watch-only wallets are the sharpest case, since every transparent spend they see is external by definition.

## [0.5.1-rc3] - 2026-07-31

### Added
- `getbalances.mine.coinbase` and `getwalletinfo.transparent.coinbase_balance` report the unspent mature transparent coinbase value. Both are additive extensions, so the Bitcoin Core balance triple still totals the wallet. Mature coinbase counts toward the balance yet no ordinary send can select it, since consensus requires a transaction spending transparent coinbase to carry no transparent output at all; the insufficient-funds error now names that amount and points at `z_shieldcoinbase`.

### Changed
- The transparent gap limit is anchored at the issuance frontier, the highest of the last funded index, the last index handed out, and the `transparent_initial_scan` floor, rather than at the last funded index alone. It therefore composes with `transparent_initial_scan`: a stateless restore recovers up to the sum of the two. Anyone who inflated `transparent_gap_limit` to match a large `transparent_initial_scan` no longer needs to, and should reduce it, since the daemon now warns above 1000 and logs an error above 10000. Neither blocks startup.
- Ironwood sends take the cached proving key instead of the fused build path, which rebuilt its key on every send. The gate that forced this existed because the previously pinned dependency rejected Ironwood bundles; the published release candidate builds them.

### Fixed
- A large `transparent_gap_limit` no longer makes a restore appear to stall. Recording a transparent receive re-derives the whole gap window, once per already-recorded output of the same transaction, so a very wide window cost about a minute of address derivation per received output on the single-writer path. Reported against 0.5.1-rc2 as a restore frozen for hours with one core pegged.

## [0.5.1-rc2] - 2026-07-30

### Added
- `zecd rescan` rebuilds a wallet whose database has become unusable: it deletes the database only, keeping `keys.toml` and the seed, so the next start recreates the account from the seed and rescans from the birthday. It takes the datadir lock the way `init` does and so refuses to run against a live daemon.
- A stuck sync now says why it is stuck. zecd compares the network upgrades the node reports against the consensus rules it knows, warning ahead of an unknown pending upgrade and erroring on an active one, and it distinguishes a failure where the upstream served the blocks from one where the wallet database could not apply them.

### Changed
- `getreceivedbyaddress` and `listreceivedbyaddress` honor `include_immature_coinbase`, excluding immature transparent coinbase from their totals unless it is set, as Bitcoin Core does. Shielded coinbase has no maturity rule and always counts.
- The librustzcash wallet crates move to `zcash_client_backend 0.24.0-rc.6` and `zcash_client_sqlite 0.22.0-rc.6`.

### Fixed
- A wallet restoring from its birthday no longer crawls through transparent spend detection. The requests that find those spends arrive in roughly 40-block windows, each queueing its successor, so one reused address could take thousands of sequential queries across a long restore; they are now serviced through to the chain tip in one query. Anyone restoring a transparent wallet on 0.5.0 or 0.5.1-rc1 would have seen this as a `pending_enhancements` count sitting flat for far longer than the block scan itself.
- `getwalletinfo.scanning.progress` reflects the whole scan rather than reading 1.0 from the start, and `scanning` no longer flips to false partway through a restore.
- An enhancement request whose start height is beyond the chain tip is skipped rather than reported as checked, which had aborted the whole enhancement pass on every retry until the funding transaction was mined.

## [0.5.1-rc1] - 2026-07-28

### Added
- Coinbase spending: zecd can spend block rewards mined to its own addresses. Transparent coinbase is swept with `z_shieldcoinbase` into a single shielded output once it reaches the 100-block maturity, which is the only shape consensus permits - a transaction spending transparent coinbase may carry no transparent output at all, not even change. It takes zcashd's signature and returns zcashd's `{remainingUTXOs, remainingValue, shieldingUTXOs, shieldingValue, opid}` shape, and runs as an async operation. Shielded coinbase (ZIP-213) needs no special handling and spends as an ordinary note.
- `listunspent` tags transparent entries with zcashd's `generated` flag and, like Bitcoin Core's `AvailableCoins`, excludes immature coinbase; that value is reported as `getwalletinfo.immature_balance` until it matures.

### Fixed
- A received coinbase output is now recorded as coinbase, so the maturity rule actually applies to it. It had been stored without the marker that identifies a coinbase transaction, letting such a UTXO count as spendable straight away.
- Transparent-to-transparent sends exclude coinbase inputs from selection. That path always creates transparent outputs, so spending coinbase through it would have been rejected by consensus.

## [0.5.0] - 2026-07-28

The 0.5.0 line, released as `0.5.0-rc1` through `0.5.0-rc4` and unchanged since `0.5.0-rc4`.
Everything below is relative to 0.4.3; the release-candidate sections that follow are kept for
history.

### Added
- Ironwood (NU6.3 / V6) support: receive discovery, balance rollup, `pool == "ironwood"` labelling, and the Ironwood send and proof path, with an NU6.3 regtest end-to-end covering receive, send, and memo decryption. Compiled unconditionally and activated by consensus height - on for testnet, off for mainnet, opt-in on regtest - so no build flag is needed.
- `zecd example-config` prints the annotated example configuration, to stdout or to a file with `-o` (which refuses to overwrite an existing one without `--force`), so a starting config no longer has to be found in a source tree.

### Changed
- The librustzcash crates are consumed from crates.io rather than a pinned git revision, so a build pulls no git dependency: the wallet crates as ironwood release candidates (`zcash_client_backend 0.24.0-rc.4`, `zcash_client_sqlite 0.22.0-rc.4`) and the rest as finals, with `pczt` at 0.9.1.
- The pinned zebra release is 6.2.2, for CI, the ironwood regtest tier, and the Docker compose stack.

### Fixed
- Spends of the wallet's own transparent outputs are now discovered. zecd left librustzcash's address-index data requests, the ones that find those spends, out of the enhancement drain, so they went unanswered.

### Security
- The `RUSTSEC-2026-0009` advisory exception is gone. The newer dependency line no longer holds `time` back, so the advisory is fixed rather than excepted. `spin` also moves off the yanked 0.9.8.

## [0.5.0-rc4] - 2026-07-27

### Added
- `zecd example-config` prints the annotated example configuration, to stdout or to a file with `-o` (which refuses to overwrite an existing one without `--force`), so a starting config no longer has to be found in a source tree.

### Changed
- The librustzcash crates move up to the newer ironwood release candidates (`zcash_client_backend 0.24.0-rc.4`, `zcash_client_sqlite 0.22.0-rc.4`) and the leaf-crate finals they require; `pczt` is now a final release at 0.9.1.
- The pinned zebra release is 6.2.2, for CI, the ironwood regtest tier, and the Docker compose stack.

### Fixed
- Spends of the wallet's own transparent outputs are now discovered. zecd left librustzcash's address-index data requests, the ones that find those spends, out of the enhancement drain, so they went unanswered.

### Security
- The `RUSTSEC-2026-0009` advisory exception is gone. The newer dependency line no longer holds `time` back, so the advisory is fixed rather than excepted. `spin` also moves off the yanked 0.9.8.

## [0.5.0-rc3] - 2026-07-13

### Changed
- The librustzcash crates are now consumed from crates.io - the wallet crates as release candidates (`zcash_client_backend 0.24.0-rc.1`, `zcash_client_sqlite 0.22.0-rc.1`, `pczt 0.8.0-rc.1`, `zip321 0.9.0-rc.1`) and the rest as finals - instead of a pinned git revision, so a build no longer pulls any git dependency.

## [0.5.0-rc2] - 2026-07-12

### Changed
- librustzcash is repointed from the interim zecrocks fork to the upstream zcash/librustzcash ironwood line; its fixes have landed upstream, so the fork is no longer needed.
- Rebased onto 0.4.3, so the ironwood line now carries every 0.4.x maintenance fix through 0.4.3 (Sapling-output fused-path routing, the `/readyz` "synced" default with per-wallet `scan_lag`, and the host-local datadir-lock documentation).

## [0.5.0-rc1] - 2026-07-09

### Added
- Ironwood (NU6.3 / V6) support: receive discovery, balance rollup, `pool == "ironwood"` labelling, and the Ironwood send and proof path, with an NU6.3 regtest end-to-end covering receive, send, and memo decryption. Compiled unconditionally and activated by consensus height - on for testnet, off for mainnet, opt-in on regtest - so no build flag is needed. Pins librustzcash to a working zecrocks fork, to be repointed to mainline before release.

## [0.4.3] - 2026-07-12

### Added
- Published on crates.io: install with `cargo install zecd`. Registry builds are not bit-reproducible; the Docker images remain so.

### Changed
- `/readyz` now defaults to "synced" readiness (ready only once the wallet has scanned to near the tip and drained the enhancement backlog) and surfaces a per-wallet `scan_lag`; set `readiness = "connected"` for the old reachability-only behavior.
- The example Docker Compose stack pins `zfnd/zebra:6.0.0`.

### Fixed
- A send that pays a Sapling output is routed to the fused build path, since the cached-proving-key path has no Sapling verifying key.

### Security
- Document that the single-instance datadir lock is host-local (it does not span hosts over a network filesystem) and stamp the lockfile with its holder.

## [0.4.2] - 2026-07-07

### Fixed
- `z_sendmany` with `privacyPolicy=AllowFullyTransparent` no longer rejects a bare transparent recipient; the top privacy rung had been dropped, so the send was wrongly refused as needing `AllowRevealedRecipients`.

### Security
- `getrawtransaction`, `sendrawtransaction`, and the transparent address-index lookups no longer leak the upstream zebra host, port, or cookie-file path to the RPC client; the detail is logged server-side and a generic message is returned.
- The age identity must resolve to a regular file with owner-only permissions; a symlink is followed (so a Kubernetes Secret mount still works) and the resolved target's file type and mode are enforced, with a dangling symlink failing closed.
- Bump `crossbeam-epoch` to 0.9.20 for RUSTSEC-2026-0204.

## [0.4.1] - 2026-07-05

### Added
- `signmessage`/`verifymessage` for transparent addresses.

## [0.4.0] - 2026-07-04

### Added
- Opt-in transparent (t-address) receiving, with restore recovery via a configurable `transparent_gap_limit`.
- Transparent spending: sends can be funded from transparent UTXOs (auto-shielded through the builder) with ZIP-317 coin selection and exact fees.
- `transparent_initial_scan` pre-exposure so a stateless restore rediscovers funds sent to high address indices, derived incrementally so a deep scan never freezes the daemon.
- Transparent mempool and block scanning for transparent receive discovery and 0-conf visibility.
- Regtest end-to-end coverage for fully-transparent and tri-pool `z_sendmany`.

### Changed
- `z_sendmany`'s privacy policy gains a fourth rung, `AllowFullyTransparent`, permitting fully-transparent sends; transparent recipients remain rejected under stricter policies.
- Transparent addresses are always issued as bare t-addresses, never embedded in a unified address.

## [0.3.4] - 2026-07-12

### Added
- Published on crates.io: install with `cargo install zecd`. Registry builds are not bit-reproducible; the Docker images remain so.

### Changed
- `/readyz` now defaults to "synced" readiness (ready only once the wallet has scanned to near the tip and drained the enhancement backlog) and surfaces a per-wallet `scan_lag`; set `readiness = "connected"` for the old reachability-only behavior.
- The example Docker Compose stack pins `zfnd/zebra:6.0.0`.

### Fixed
- A send that pays a Sapling output is routed to the fused build path, since the cached-proving-key path has no Sapling verifying key.

### Security
- Document that the single-instance datadir lock is host-local (it does not span hosts over a network filesystem) and stamp the lockfile with its holder.

## [0.3.3] - 2026-07-06

### Security
- `getrawtransaction` and `sendrawtransaction` errors no longer leak the upstream zebra host, port, or cookie-file path to the RPC client; the detail is logged server-side and a generic message is returned.
- The age identity must resolve to a regular file with owner-only permissions; a symlink is followed (so a Kubernetes Secret mount still works) and the resolved target's file type and mode are enforced, with a dangling symlink failing closed.
- Bump `crossbeam-epoch` to 0.9.20 for RUSTSEC-2026-0204.

## [0.3.2] - 2026-07-03

### Added
- `[spend] pipeline_proving` (default off): prove a send off the single-writer actor so a long send no longer freezes background sync.

### Changed
- Readiness (`synced` mode), `getwalletinfo.scanning`, and `getblockchaininfo.initialblockdownload` now also account for the post-scan transaction-enhancement backlog, surfaced per-wallet as `pending_enhancements`; a wallet is not "ready" until memos have been backfilled.
- `z_sendmany`'s `privacyPolicy` is a three-rung ladder (`FullPrivacy` / `AllowRevealedAmounts` / `AllowRevealedRecipients`); a transparent recipient is now rejected under every policy short of `AllowRevealedRecipients`.
- RPC argument errors follow Bitcoin Core's taxonomy (missing -1, wrong type -3, out of range -8) and enforce arity.

### Fixed
- A wallet no longer reports ready while the post-scan enhancement backlog is still draining (memos temporarily missing with no signal).
- Chain-status RPCs (`getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getblockheader`) honor `/wallet/<name>` routing instead of always reporting the default wallet.
- `z_sendmany` accepts zero-valued (memo-only) outputs; the privacy-policy collapse that let stricter policies pay transparent recipients is fixed.
- Already-expired sends sync to the real chain tip before spending.
- `gettransaction` no longer over-reports the received amount by the fee.
- `listsinceblock` no longer wedges permanently after a reorg.
- Bound block-cache metadata growth and harden reorg recovery so the cache cannot grow without limit.
- Bound the full zebra request and response round-trip with the request timeout, so a stalled upstream cannot wedge sync.
- Pace reconnects with the exponential backoff after a post-connection failure, so a reachable-but-degraded upstream can no longer drive a tight reconnect loop that pegs a core.

### Security
- `walletlock` zeroizes the decrypted seed immediately via a fast path that bypasses the actor's command queue, so it takes effect even while the actor is mid-proof on a long send.
- Cap a wallet's in-flight async operations to bound a `z_sendmany` denial-of-service.
- Panic-isolate the block-scan and enhancement paths so hostile chain data cannot kill the single-writer actor.
- Gate credentialed zebra RPC connections behind a locality check, refusing cleartext auth to a globally-routable host unless `[backend] allow_remote_cleartext` is set.
- Bind the wallet database to the account viewing key recorded in `keys.toml`, so a mismatched database or keys file is detected instead of silently used.
- Only an explicit environment variable opts out of seed-memory hardening; an unset value no longer disables it.
- Warn at startup when the RPC password is passed via `--rpcpassword`, since it is visible to local users; prefer the environment variable or `password_file`.
- Bump `anyhow` to 1.0.103 for RUSTSEC-2026-0190.
- Harden config clamping, error disclosure, and SIGTERM shutdown.
- Reject unified addresses carrying a transparent receiver in `is_mine`.
- Harden cookie-file writes against symlink and stale-permission exposure.
- Reject out-of-range zebra responses (a mismatched tree-state height or an oversized per-block transaction count) as transport errors before they reach the scanner.
- Warn when an unencrypted wallet auto-unlocks its seed at startup, and document the assumed deployment posture (trust boundary) in the operations guide.

## [0.3.1] - 2026-06-23

### Changed
- Outgoing transaction history is deterministic across a restore from seed.
- Run SQLite `synchronous = NORMAL` on the writer connection (WAL-safe, much faster on networked or encrypted storage).
- Reduce raw-SQL coupling to librustzcash's schema in wallet reads.
- Log the client IP on RPC auth attempts.

### Fixed
- Treat code-less zebra RPC errors as broadcast rejections instead of acceptance.

### Security
- Detect and reject hand-spliced unified addresses across own-address RPCs.
- Refuse to load over-permissive age identity files.

## [0.3.0] - 2026-06-20

### Added
- Make zecd stateless: remove address labels and off-chain state.
- `z_getaddressforaccount` RPC for zcashd-compatible unified-address derivation.
- Orchard proving-key cache to speed up sends.
- mimalloc on musl builds to restore Orchard proving performance.
- Single-instance datadir lock preventing two zecd processes on one directory.
- Bootstrap a wallet from `keys.toml` on an empty data directory.
- Configurable `/readyz` readiness (connected vs fully synced).

### Changed
- Cap the Orchard action count per send to bound memory and proving cost.
- Improve logging (wallet names, RPC auth, zebra connect and disconnect).
- Remove dead code (unused functions, fields, error codes, dependencies).

### Fixed
- Self-payments are no longer hidden from history RPCs.
- Restored wallets correctly detect unfunded addresses as `is_mine`.
- Validate fresh addresses in `listreceivedbyaddress`.

## [0.2.0] - 2026-06-18

Initial release: a Bitcoin Core-style JSON-RPC wallet server for Orchard-shielded
Zcash, backed entirely by librustzcash and running as a light client.

### Added
- bitcoind-compatible JSON-RPC server (framing, error codes, Basic and cookie auth, `rpcauth` multi-user credentials).
- Single-writer wallet actor with a background sync loop; reads served from short-lived connections.
- Orchard unified addresses, per-pool balances, shielded sends, and transaction history, with zcashd-style async `z_sendmany` operation tracking.
- Bitcoin-Core-style passphrase wallet encryption; age-encrypted seed at rest.
- Direct-to-zebra chain backend, watch-only wallets via UFVK import, and configurable shielded pools.
- Health and readiness server, structured logging, reproducible Docker and `.deb` builds, and a tag-driven release workflow.
- Extensive regtest end-to-end harness and Bitcoin Core conformance tests.

### Changed
- Slim zecd to zebra-only: remove lightwalletd, cloud-KMS, SOCKS5, and Prometheus.
- `FullPrivacy` now means a single shielded pool.

### Security
- Pre-release audit hardening; refuse to start on mainnet with the placeholder RPC password; enforce a 12-character passphrase minimum.

[0.6.2]: https://github.com/zecrocks/zecd/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/zecrocks/zecd/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/zecrocks/zecd/compare/v0.5.2...v0.6.0
[0.6.0-rc3]: https://github.com/zecrocks/zecd/compare/v0.6.0-rc2...v0.6.0-rc3
[0.6.0-rc2]: https://github.com/zecrocks/zecd/compare/v0.6.0-rc1...v0.6.0-rc2
[0.6.0-rc1]: https://github.com/zecrocks/zecd/compare/v0.5.2...v0.6.0-rc1
[0.5.2]: https://github.com/zecrocks/zecd/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/zecrocks/zecd/compare/v0.5.0...v0.5.1
[0.5.1-rc4]: https://github.com/zecrocks/zecd/compare/v0.5.1-rc3...v0.5.1-rc4
[0.5.1-rc3]: https://github.com/zecrocks/zecd/compare/v0.5.1-rc2...v0.5.1-rc3
[0.5.1-rc2]: https://github.com/zecrocks/zecd/compare/v0.5.1-rc1...v0.5.1-rc2
[0.5.1-rc1]: https://github.com/zecrocks/zecd/compare/v0.5.0...v0.5.1-rc1
[0.5.0]: https://github.com/zecrocks/zecd/compare/v0.4.3...v0.5.0
[0.5.0-rc4]: https://github.com/zecrocks/zecd/compare/v0.5.0-rc3...v0.5.0-rc4
[0.5.0-rc3]: https://github.com/zecrocks/zecd/compare/v0.5.0-rc2...v0.5.0-rc3
[0.5.0-rc2]: https://github.com/zecrocks/zecd/compare/v0.5.0-rc1...v0.5.0-rc2
[0.5.0-rc1]: https://github.com/zecrocks/zecd/compare/v0.4.2...v0.5.0-rc1
[0.4.3]: https://github.com/zecrocks/zecd/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/zecrocks/zecd/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/zecrocks/zecd/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/zecrocks/zecd/compare/v0.3.2...v0.4.0
[0.3.4]: https://github.com/zecrocks/zecd/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/zecrocks/zecd/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/zecrocks/zecd/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/zecrocks/zecd/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/zecrocks/zecd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zecrocks/zecd/releases/tag/v0.2.0
