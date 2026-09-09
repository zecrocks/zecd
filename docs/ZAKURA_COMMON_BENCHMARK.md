# Zakura Common vs librustzcash - is the switch worth keeping?

**Recommendation: yes, switch permanently.** On the same machine, the same regtest chain and the
same funder, a zecd built on the Zakura Common forks proves an Orchard/Ironwood send about
**4x faster per action**, builds its proving keys **11x faster**, verifies **2x faster**, and
trial-decrypts **1.3-1.7x faster** than the same zecd built on upstream librustzcash. End to end,
a one-input `sendtoaddress` went from ~3.5 s to ~0.66 s and a 16-output fan-out from ~15 s to
~3.2 s. Nothing about the wallet, its database, addresses, keys or the RPC surface changed, every
regtest leg passes, and the forks keep librustzcash's API so the switch is a Cargo-level rename.
The only costs are a higher MSRV (1.91) and a dependency on Zakura keeping the forks current with
upstream (the wallet layer is still on `-rc` version numbers).

Measured 2026-09-02. Everything below was produced by tooling that is
in the tree: `regtest-harness/tests/regtest_bench_stack.rs` (the end-to-end comparison) and
upstream orchard's own criterion benches run unmodified against both crates.

## Method

Two `zecd` release binaries from the same source tree, differing only in the Zcash stack:

| label | tree | stack |
| --- | --- | --- |
| `lrz` | before the switch | crates.io librustzcash: `orchard 0.15.5`, `zcash_client_backend 0.24.0`, `zcash_client_sqlite 0.22.0`, `pczt 0.9.3` |
| `zakura` | the switch alone | `zakura-orchard 1.0.0`, `zakura-client-backend 0.1.0-rc4`, `zakura-client-sqlite 0.1.0-rc4`, `zakura-pczt 0.1.0-rc2` |
| `zakura-orbits` | + `orbits` feature and `ProvingKey::prepare_proving()` at startup | same |
| `zakura-shared` | + share the fork's process-wide key cache, pass a cached verifying key to the extractor (what shipped) | same |

The end-to-end benchmark (`ZECD_BENCH_BINS=... cargo test --test regtest_bench_stack`) brings up
one regtest zebrad (6.3.0, extracted from the CI-pinned image) and one funder (the CI-pinned
zecd 0.7.0 release), then runs every binary through the same workload on that one chain,
**alternating binaries across rounds** so drift is shared: fund the wallet with 14 notes of
0.5 ZEC, five `sendtoaddress` calls with growing input counts (1, 1, 2, 3, 4 notes), a
`z_sendmany` fan-out to 16 of the wallet's own addresses (18 Orchard actions), and a from-seed
restore of the wallet timed to fully-scanned. NU6.3 is active on the chain, so every send is an
Ironwood send, as on mainnet today. Proving is inline (`pipeline_proving = false`) so the RPC
latency covers the whole send. Two rounds per binary; medians reported.

Machine: 4 vCPU Intel Xeon 2.10 GHz, 15 GB, Linux. zebrad, the funder and the wallet under test
share those cores, so absolute numbers are pessimistic; the ratios are what matter.

## End-to-end (regtest, run 3: `lrz` vs `zakura-orbits` vs `zakura-shared`)

Per-phase timings from the daemon's own `send complete` log line (ms, medians):

| inputs | actions | stack | build | **prove** | store | broadcast | total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 2 | lrz | 38 | **1777** | 1493 | 172 | 3472 |
| 1 | 2 | zakura-orbits | 20 | **418** | 148 | 172 | 758 |
| 1 | 2 | zakura-shared | 19 | **460** | 12 | 172 | 644 |
| 3 | 3 | lrz | 66 | **2458** | 1487 | 175 | 4187 |
| 3 | 3 | zakura-orbits | 30 | **550** | 148 | 176 | 906 |
| 3 | 3 | zakura-shared | 33 | **568** | 14 | 155 | 770 |
| 4 | 4 | lrz | 90 | **3162** | 1601 | 180 | 5033 |
| 4 | 4 | zakura-orbits | 38 | **704** | 152 | 178 | 1072 |
| 4 | 4 | zakura-shared | 40 | **730** | 16 | 178 | 963 |
| 1 | 18 (fan-out) | lrz | 159 | **13088** | 1572 | 216 | 15035 |
| 1 | 18 (fan-out) | zakura-orbits | 104 | **2750** | 188 | 196 | 3238 |
| 1 | 18 (fan-out) | zakura-shared | 104 | **2862** | 50 | 218 | 3233 |

Pooled over all 12 sends per stack (62 actions each):

| stack | prove ms per action (median) | startup keygen (both circuits) |
| --- | --- | --- |
| lrz | 840 | 3.45 s |
| zakura (plain, run 2) | 219 | 0.38 s |
| zakura-orbits | 191 | 1.60 s (0.38 s keygen + ~1.2 s arming the prepared tables) |
| zakura-shared | 199 | 1.61 s |

What a client sees (RPC wall clock, medians):

| stack | `sendtoaddress` 1 input | 4 inputs | fan-out (16 outputs) | restore scan (~200 blocks) |
| --- | --- | --- | --- | --- |
| lrz | 3494 ms | 5053 ms | 15054 ms | 1.2 s |
| zakura-orbits | 778 ms | 1093 ms | 3254 ms | 1.2 s |
| zakura-shared | 663 ms | 984 ms | 3248 ms | 1.2 s |

Reading the table:

- **Proving is ~4.2x faster** (840 -> 199 ms per action). This is the headline and it holds at
  every shape, from a 2-action send to the 18-action fan-out.
- **The `store` phase collapsed twice.** On librustzcash it was ~1.5 s, almost all of it the PCZT
  extractor regenerating an Orchard verifying key per send (`VerifyingKey::build`, 1.5 s
  upstream). The fork builds keys from embedded parameters, so that fell to ~150 ms; handing the
  extractor the verifying key zecd already holds (`zakura-shared`) removes it entirely (12-16 ms
  is the SQLite write).
- **`orbits` is worth ~13% on proving** (219 -> 191 ms per action in run 2, where plain and armed
  Zakura builds ran side by side) for ~1.2 s of one-time background startup work and some tens of
  MiB of prepared tables per key. It is kept on: the daemon is long-lived and the tables are
  shared by every path that proves.
- **The restore scan cannot separate the stacks at regtest scale** - a few hundred outputs, so
  the 1.2 s is fixed cost (tree bring-up, upstream round trips). Trial decryption is covered by
  the microbenchmark below.
- `zakura-shared` proves a few percent slower than `zakura-orbits` in this run and a few percent
  faster in others; that is round-to-round noise on a shared 4-core box, not a difference in the
  code path (both arm the same tables on the same keys).

## Crypto microbenchmark (upstream orchard's own benches, criterion, both crates)

`benches/circuit.rs` and `benches/note_decryption.rs` from `orchard 0.15.5` are byte-for-byte
the same workload as the fork's (only the `rand` API differs), so they compare implementations,
not benchmark code. Plus one shared `keygen` bench. Release, 4 cores, default features.

| benchmark | librustzcash `orchard 0.15.5` | `zakura-orchard 1.0.0` | speedup |
| --- | --- | --- | --- |
| proving key build (FixedPostNu6_2) | 2.20 s | 190 ms | 11.6x |
| proving key build (PostNu6_3) | 2.20 s | 195 ms | 11.3x |
| verifying key build | 1.52 s | 133 ms | 11.4x |
| prove bundle, 2 actions | 1.672 s | 424 ms | 3.9x |
| prove bundle, 3 actions | 2.354 s | 583 ms | 4.0x |
| prove bundle, 4 actions | 3.020 s | 723 ms | 4.2x |
| verify bundle, 2 actions | 13.5 ms | 6.3 ms | 2.1x |
| verify bundle, 4 actions | 17.6 ms | 7.5 ms | 2.3x |
| note decryption, valid (one output) | 1.237 ms | 0.773 ms | 1.6x |
| batch decryption, 100 valid | 122.7 ms | 72.1 ms | 1.7x |
| batch compact decryption, 100 invalid (the scan's common case) | 10.61 ms | 8.18 ms | 1.30x |
| compact decryption, 10240 invalid IVKs | 1.080 s | 0.939 s | 1.15x |

The key-build numbers repeat a result zecd already had from vendoring orchard: upstream spends
~0.7 s of each keygen regenerating the halo2 commitment parameters, which are a function of the
circuit size alone; the fork ships them as an embedded 131 KB artifact
(`orchard_k11_params.bin`) and both `ProvingKey::build` and `VerifyingKey::build` read it. The
fork does that upstream of zecd, plus a faster `keygen_pk` on top.

## What the proving-key work in zecd looks like after the switch

- **The fused path no longer rebuilds a key per transaction.** The fork's `zcash_primitives`
  caches built keys process-wide (`builder::cached_orchard_proving_key`, one `OnceLock` per
  circuit version) and `Builder::build` reads from there. So the reason zecd's PCZT path exists -
  avoiding a per-send keygen in `create_proposed_transactions` - is gone. The PCZT path is kept
  because `pipeline_proving` (proving off the actor) rides on its prove/store seam, and because
  it is what gives the per-phase timing above.
- **zecd no longer builds a second key set.** `ProvingKeyCache` now holds `&'static` references
  into the fork's cells, so the PCZT path and every fused-path caller (Sapling spends,
  transparent-source sends, `z_shieldcoinbase`, `z_mergetoaddress`, `cache_proving_key = false`)
  prove with one key set, warmed in the background at startup.
- **Prepared commitment tables are armed** (`ProvingKey::prepare_proving`, the fork's opt-in
  `orbits` feature) on those shared keys, so the fused path benefits too.
- **The extract step gets a cached verifying key** cloned from the proving key (no keygen).
- No send path in zecd bypasses the fork: Sapling proving (`LocalTxProver`) and the
  transparent-only builder already go through the forked crates.

## Caveats

- One machine, shared with the node and the funder. Ratios are robust across the three runs
  (proving 3.8x-4.2x in every run); absolute times are not a mainnet prediction.
- Memory was not measured. The prepared tables are documented as "tens of MiB" per key and the
  fork's proving keys are held once (not twice as before), so the net change is modest; worth
  reading `getmemoryinfo` / RSS on a real deployment before and after.
- The wallet layer is `0.1.0-rc4` / `0.1.0-rc2`. Zakura's own node 1.3.0 ships on this stack,
  but a release-candidate wallet layer means watching their tags.
- The regtest scan is too small to show the 1.3x-1.7x trial-decryption speedup end to end; a
  mainnet restore from a deep birthday is where it would show.

## Reproducing

```sh
# node + funder as CI pins them (no Docker daemon needed - pull_bin.py walks the image layers)
export ZEBRAD_BIN=/path/to/zebrad ZECD_FUNDER_BIN=/path/to/zecd-0.7.0
export ZECD_REGTEST_NU63_HEIGHT=8 ZECD_STDERR=1 RUST_LOG=zecd=info
export ZECD_BENCH_BINS="lrz=/path/to/zecd-main,zakura=/path/to/zecd-branch"
cargo test --manifest-path regtest-harness/Cargo.toml --test regtest_bench_stack -- --nocapture
```

The test prints `BENCH ...` lines plus a `BENCH_RESULTS` JSON summary; the daemon log lines
(`send complete ... prove_ms=`) carry the phase profile. It skips unless `ZECD_BENCH_BINS` is
set, so it is inert in CI and can be deleted once the question is settled.
