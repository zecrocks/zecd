# Method index: zecd vs bitcoind vs zcashd

Every RPC method zecd dispatches (43 methods, the `ALL_METHODS` table in `src/rpc/mod.rs`),
compared against Bitcoin Core master and zcashd. Each method name links to its full reference
entry.

Column legend:

- **Bitcoin Core**: ✓ = exists in current master with the semantics zecd mirrors;
  *removed* = no longer exists in current bitcoind (zecd keeps it for older clients);
  n/a = never existed there.
- **zcashd**: ✓ = same method name, compatible semantics; *same name, differs* = the name
  exists but the semantics diverge (usually transparent-only in zcashd, with a `z_*` method
  for shielded); n/a = no such method (nearest equivalent in parentheses). On chain and
  network rows a ✓ means zcashd serves the method with bitcoind's full-node semantics; zecd's
  wallet-scoped view (scanned heights, one Zebra "peer") is in the zecd column.

An `[rpc] allowed_methods` safelist, when set, answers `-32601` for any method off the list,
indistinguishable from a method that does not exist. Multiwallet routing (`/wallet/<name>`)
is covered in [Conventions & wire format](index.md).

| Method | Bitcoin Core | zcashd | zecd |
|---|---|---|---|
| **Control** | | | |
| [stop](util-control.md#stop) | ✓ | same name, differs (stops any network) | Regtest only; mainnet/testnet answer `-32601`. Stop a live node with SIGINT/SIGTERM |
| [uptime](util-control.md#uptime) | ✓ | n/a | Seconds since the daemon started |
| [help](util-control.md#help) | ✓ | ✓ | Static one-line summary; the method argument is ignored (see below) |
| [getrpcinfo](util-control.md#getrpcinfo) | ✓ | n/a | `active_commands` with elapsed microseconds; `logpath` empty (logs go to stderr) |
| **Network** | | | |
| [getnetworkinfo](network.md#getnetworkinfo) | ✓ | ✓ | zecd version/subversion; `connections` is 0 or 1 (the Zebra upstream is the only "peer") |
| [getconnectioncount](network.md#getconnectioncount) | ✓ | ✓ | 0 or 1 |
| [getpeerinfo](network.md#getpeerinfo) | ✓ | ✓ | At most one entry, describing the Zebra upstream, plus `conn_state`/`syncing` extensions |
| [ping](network.md#ping) | ✓ | ✓ | No-op success; there is no P2P ping to measure |
| **Blockchain** | | | |
| [getblockchaininfo](blockchain.md#getblockchaininfo) | ✓ | ✓ | `blocks` = fully scanned height, `headers` = tip; `initialblockdownload` true while scanning or enhancing |
| [getblockcount](blockchain.md#getblockcount) | ✓ | ✓ | Fully scanned height, so `getblockhash(getblockcount())` always answers |
| [getbestblockhash](blockchain.md#getbestblockhash) | ✓ | ✓ | Hash at the fully scanned height |
| [getblockhash](blockchain.md#getblockhash) | ✓ | ✓ | From the wallet's scanned blocks; pre-birthday or beyond-tip heights answer `-8` |
| [getblockheader](blockchain.md#getblockheader) | ✓ | ✓ | Verbose only, compact-block fields; `verbose=false` answers `-8` |
| **Utility** | | | |
| [validateaddress](util-control.md#validateaddress) | ✓ | same name, differs (transparent-only; shielded via `z_validateaddress`) | Validates every Zcash address kind; adds `isvalid_orchard` and `receiver_types` extension fields |
| [settxfee](util-control.md#settxfee) | *removed* | same name, differs (functional in zcashd) | Always `-8`: fees are ZIP-317, never client-settable |
| [estimatesmartfee](util-control.md#estimatesmartfee) | ✓ | n/a | Inert stub: conventional ZIP-317 rate (0.00001) plus a `blocks` echo |
| [estimatefee](util-control.md#estimatefee) | *removed* | n/a (removed in zcashd 5.6.0) | Same stub rate, kept for old clients |
| [getmempoolinfo](util-control.md#getmempoolinfo) | ✓ | ✓ | Fixed shape with empty-mempool numbers (zecd holds no mempool of its own) |
| **Raw transactions** | | | |
| [getrawtransaction](rawtx.md#getrawtransaction) | ✓ (verbose JSON differs) | ✓ | Hex, or verbose JSON in zcashd's shape with shielded bundles; `blockhash` param rejected |
| [sendrawtransaction](rawtx.md#sendrawtransaction) | ✓ | ✓ | Broadcasts caller-built bytes through Zebra; `maxfeerate` ignored |
| **Wallet: reads** | | | |
| [getbalance](wallet-balances.md#getbalance) | ✓ | same name, differs (transparent-only; `z_getbalanceforaccount` for shielded) | Spendable balance under the ZIP-315 confirmations policy; explicit `minconf` overrides it per call |
| [getbalances](wallet-balances.md#getbalances) | ✓ | n/a (`z_getbalanceforaccount`, `z_gettotalbalance`) | `mine.trusted/untrusted_pending/immature` plus `lastprocessedblock`; no `watchonly` object |
| [getunconfirmedbalance](wallet-balances.md#getunconfirmedbalance) | *removed* | same name, differs (transparent-only) | Incoming funds below the confirmations policy, including 0-conf via the mempool stream |
| [getwalletinfo](wallet-addresses.md#getwalletinfo) | ✓ | ✓ | bitcoind shape; `scanning` progress, `unlocked_until` when encrypted, `private_keys_enabled:false` when watch-only |
| [getaddressinfo](wallet-addresses.md#getaddressinfo) | ✓ | n/a (`validateaddress` / `z_validateaddress`) | `ismine` is cryptographic (viewing-key attribution); `labels` always `[]`; `iswatchonly` always false, as in Core master |
| [listtransactions](wallet-history.md#listtransactions) | ✓ | same name, differs (transparent history only) | Core categories and fields; adds `memo`/`memoStr`; outgoing `address` is the single receiver actually paid |
| [z_listtransactions](wallet-history.md#z_listtransactions) | n/a | n/a (no equivalent; `listtransactions` is transparent-only) | zcashd-style per-output history vocabulary (no `account` arg) |
| [listsinceblock](wallet-history.md#listsinceblock) | ✓ | same name, differs (transparent history only) | Cursor pattern; `removed` always `[]`; a malformed cursor answers `-5`, a reorged-away cursor re-lists from the earliest scanned block |
| [gettransaction](wallet-history.md#gettransaction) | ✓ | same name, differs (`z_viewtransaction` for shielded detail) | `amount`/`fee`/`confirmations`/`details`/`hex`; foreign tx hex fetched from Zebra on demand |
| [listunspent](wallet-history.md#listunspent) | ✓ | same name, differs (transparent UTXOs; `z_listunspent` for notes) | One entry per unspent note; synthesized `txid`/`vout`; `address` empty for change |
| [getreceivedbyaddress](wallet-balances.md#getreceivedbyaddress) | ✓ | same name, differs (transparent; `z_listreceivedbyaddress` for shielded) | Totals over diversified receiving addresses; change never counted |
| [listreceivedbyaddress](wallet-balances.md#listreceivedbyaddress) | ✓ | same name, differs (transparent) | `listreceivedbyaddress 0 true` enumerates every generated address; each entry's `label` is `""` |
| [listwallets](wallet-addresses.md#listwallets) | ✓ | n/a (single wallet) | Names from `[wallets.<name>]` config |
| **Wallet: writes** | | | |
| [getnewaddress](wallet-addresses.md#getnewaddress) | ✓ | same name, differs (deprecated, transparent-only; `z_getaddressforaccount` for UAs) | Fresh diversified UA; a `label` arg is rejected `-8`; `address_type` selects receivers within the enabled pools |
| [sendtoaddress](sending.md#sendtoaddress) | ✓ | same name, differs (transparent-only) | Synchronous shielded send returning a txid; ZIP-317 fee; `subtractfeefromamount`/`fee_rate` answer `-8`; extra trailing `memo` param |
| [sendmany](sending.md#sendmany) | ✓ | same name, differs (transparent-only) | Same, multi-recipient; dummy `""` first arg as in Core |
| [walletpassphrase](wallet-addresses.md#walletpassphrase) | ✓ | ✓ | Unlock with a timeout (capped at 100,000,000 seconds, as in Core); wrong passphrase `-14`, unencrypted wallet `-15` |
| [walletlock](wallet-addresses.md#walletlock) | ✓ | ✓ | Zeroizes the seed immediately, even mid-proof; unencrypted wallet `-15` |
| **Async operations** | | | |
| [z_sendmany](async-operations.md#z_sendmany) | n/a | ✓ | Async: returns an opid, proves/broadcasts in the background; `fromaddress` must be the wallet's own (`ANY_TADDR` rejected `-5`); explicit `fee` answers `-8` |
| [z_getoperationstatus](async-operations.md#z_getoperationstatus) | n/a | ✓ | Non-destructive status objects; wallet-scoped |
| [z_getoperationresult](async-operations.md#z_getoperationresult) | n/a | ✓ | Finished operations only; destructive one-shot reap, matching zcashd |
| [z_listoperationids](async-operations.md#z_listoperationids) | n/a | ✓ | The wallet's operation ids; optional status filter |
| **Address derivation** | | | |
| [z_getaddressforaccount](wallet-addresses.md#z_getaddressforaccount) | n/a | ✓ | Derive a UA for the wallet's single account (`account` must be 0); shielded receiver types only; optional exact `diversifier_index` |

## Deliberately absent method families

These answer method-not-found (`-32601`), the same as any unknown method.

- **Label methods** (`setlabel`, `getaddressesbylabel`, `listlabels`, `getreceivedbylabel`,
  `listreceivedbylabel`): zecd keeps no off-chain label store, by the
  [statelessness invariant](../design/statelessness.md). Embedded `label`/`labels` fields on
  other methods remain, always `""`/`[]`.
- **Key import/export** (`dumpprivkey`, `importprivkey`, `importaddress`, `importpubkey`,
  `z_exportkey`, `z_importkey`, `z_exportviewingkey`, `z_importviewingkey`): each wallet is one
  ZIP-32 account from one mnemonic; key material moves only through the CLI (`zecd init`,
  `zecd export-ufvk`), never over the RPC channel. See [key custody](../security/key-custody.md)
  and [watch-only wallets](../guide/watch-only.md).
- **`dumpwallet` / `backupwallet` / `importwallet`**: the backup is the mnemonic; everything
  else is rebuilt from seed plus chain, so there is no wallet file worth dumping.
- **Wallet encryption RPCs** (`encryptwallet`, `walletpassphrasechange`): at-rest encryption is
  set once at `zecd init --encrypt`, so the passphrase never crosses the network.
- **Raw transaction construction** (`createrawtransaction`, `fundrawtransaction`,
  `signrawtransaction`, `decoderawtransaction`, `decodescript`): shielded transactions cannot
  be assembled from public outpoints. `sendrawtransaction` still broadcasts externally built
  bytes.
- **Mining** (`getblocktemplate`, `submitblock`, `generate`, `getmininginfo`): zecd is a wallet
  server, not a validator; mine against the Zebra node.
- **P2P management** (`addnode`, `disconnectnode`, `setban`, `listbanned`, `getnettotals`,
  `getaddednodeinfo`): zecd has no P2P stack; its only peer is one
  [Zebra node over JSON-RPC](../design/zebra-backend.md).

## The `help` introspection gap

`help <method>` ignores its argument and returns a static one-line blurb naming only a few
methods. bitcoind lists every command and returns per-method usage for `help <method>`, so
tooling that introspects via `help` gets nothing useful from zecd today. Use this index and
the per-category reference pages instead.
