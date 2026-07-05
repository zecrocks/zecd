# Conventions & wire format

zecd speaks Bitcoin Core's JSON-RPC dialect: the JSON-RPC 1.0 envelope, HTTP Basic/cookie
authentication, Bitcoin Core's error codes, and its HTTP status mapping. This page defines the
wire format shared by every method; the methods themselves are in the
[method index](method-index.md).

## JSON-RPC envelope

Requests are `POST`ed as a JSON object (or an array of objects, for a [batch](#batching)):

```json
{"jsonrpc": "1.0", "id": "curltest", "method": "getblockcount", "params": []}
```

- `method` is required; a missing or non-string `method` is rejected with `-32600`.
- `params` is a positional array, as with Bitcoin Core. It may be omitted or `null`
  (treated as empty). Handlers read positional arguments only, so pass an array;
  an object-shaped `params` is accepted at the framing level but yields zero positional
  arguments. Any other type is `-32600`.
- `id` is echoed back verbatim, including on errors (`null` when it could not be parsed).
- A call carrying more positional arguments than the method declares is rejected with `-1`,
  matching Bitcoin Core's help-text error for over-arity calls.

Every response carries both `result` and `error`, one of them `null` (the JSON-RPC 1.0
behavior real Bitcoin clients such as `python-bitcoinrpc` parse):

```json
{"result": 2500000, "error": null, "id": "curltest"}
```

```json
{"result": null, "error": {"code": -32601, "message": "Method not found: no_such"}, "id": "curltest"}
```

## HTTP transport

| Endpoint | Purpose |
|---|---|
| `POST /` | RPC against the default wallet |
| `POST /wallet/<name>` | RPC against wallet `<name>` (bitcoind multiwallet routing) |

The RPC port defaults to `8232` on mainnet and `18232` on testnet/regtest, bound to
`[rpc] bind` (see [configuration](../configuration.md)). Responses are
`Content-Type: application/json` (overload/shutdown rejections are `text/plain`). zecd does
not validate the request `Content-Type`; send `application/json` as clients conventionally do.
Request bodies are capped at 2 MiB; oversize requests get HTTP 413 before auth or dispatch.

A `/wallet/<name>` request naming a wallet that is not configured and loaded fails every
wallet-routed method on it with `-18` (`Requested wallet does not exist or is not loaded:
<name>`), Bitcoin Core's `RPC_WALLET_NOT_FOUND`. Methods that never touch a wallet (`uptime`,
`getnetworkinfo`, `ping`, `getrpcinfo`, the fee estimators) ignore the path and still answer,
as in bitcoind. Each `[wallets.<name>]` section is an independent wallet; see
[Wallet: addresses & keys](wallet-addresses.md) for `listwallets`.

## Authentication

Every RPC request requires HTTP Basic authentication. Accepted credentials are the union of:

- **`[rpc] user` + `password`** (or `--rpcuser`/`--rpcpassword`): a single plaintext pair.
  Hashed at startup; verification only ever compares salted hashes.
- **`[rpc] auth` entries** (or repeated `--rpcauth`): bitcoind-style salted credentials in the
  `<user>:<salt>$<hmac-sha256 hex>` format of `share/rpcauth/rpcauth.py`, so no plaintext
  password lives in the config. zecd ships the generator built in:

  ```sh
  zecd rpcauth alice            # mints a random password, prints it once
  zecd rpcauth alice hunter2    # hashes a password you chose
  ```

  Either prints the `auth = ["alice:<salt>$<hash>"]` line to drop into `[rpc]`.
- **Cookie**: when no user/password pair is set, zecd mints a random secret at startup and
  writes `__cookie__:<random>` to `[rpc] cookiefile` (default `<datadir>/.cookie`), mode 0600,
  regenerated on every startup. This happens alongside `auth` entries too, matching bitcoind's
  behavior whenever `rpcpassword` is empty. A local process reads the file and authenticates
  as `__cookie__` (how `bitcoin-cli` talks to a local node by default).

Credential checks are constant-time (the password HMAC is always computed, and every
configured user is checked without short-circuiting). A failed attempt gets HTTP 401 with
`WWW-Authenticate: Basic realm="jsonrpc"` after a 250 ms delay, the same anti-bruteforce
values as Bitcoin Core's `httprpc.cpp`. Failures are logged with the claimed username, peer
address, and `X-Forwarded-For` when a reverse proxy sets it.

RPC credentials are spend authority: any authenticated caller can reach `sendtoaddress`
unless the [safelist](#method-safelist) removes it. See the
[threat model](../security/threat-model.md).

## HTTP status and error codes

The mapping is Bitcoin Core's (`httprpc.cpp` `JSONErrorReply`): `-32600` is 400, `-32601` is
404, and every other RPC error is 500 with the error object in the body. Clients must read
the body of non-200 responses.

| Condition | RPC code | HTTP |
|---|---|---|
| success | n/a | 200 |
| insufficient funds | `-6` | 500 |
| wallet locked (needs `walletpassphrase`) | `-13` | 500 |
| tx rejected by network | `-26` | 500 |
| bad/unknown address or txid | `-5` | 500 |
| invalid parameter | `-8` | 500 |
| unknown `/wallet/<name>` | `-18` | 500 |
| invalid request | `-32600` | 400 |
| method not found (or safelisted out) | `-32601` | 404 |
| parse error | `-32700` | 500 |
| auth failure | n/a | 401 (+ `WWW-Authenticate`, 250 ms delay) |
| batch (any mix of outcomes) | per item | 200 |
| over work-queue / shutting down | n/a | 503 (`text/plain` body) |
| request body over 2 MiB | n/a | 413 |

## Error numbering: Bitcoin Core's, not zcashd's

Error codes are Bitcoin Core's `rpc/protocol.h` values, because zecd's conformance target is
bitcoind, not zcashd. Two conventions carried over from Core:

- `-32602` (`RPC_INVALID_PARAMS`) is never emitted by a method handler. A missing required
  argument is `-1` (Core answers with the method help text there) and a wrong-typed argument
  is `-3` (`RPC_TYPE_ERROR`).
- Wallet, parameter, and verification codes are Core's numbers.

**The `-18` collision.** zcashd numbers some codes differently in its own `protocol.h`. The
one divergence zecd actually emits is `-18`: in Bitcoin Core (and zecd) it means "wallet not
found" (an unknown `/wallet/<name>`), while in zcashd `-18` is `RPC_WALLET_BACKUP_REQUIRED`.
Since zcashd has no multiwallet routing, a zcashd-derived client never triggers zecd's `-18`
in normal use, but tooling that hard-codes zcashd's numbering should be aware. zcashd's `-11`
(`RPC_WALLET_ACCOUNTS_UNSUPPORTED`, vs Core's "invalid label name") is never returned by zecd
at all: zecd is stateless and has no labels. The codes integrations branch on for the money
path (`-4`, `-5`, `-6`, `-8`, `-13` through `-15`, `-20`, `-26`) are identical across Bitcoin
Core, zcashd, and zecd.

## Amounts

Amounts are bare JSON numbers in decimal ZEC with exactly 8 decimal places (1 ZEC =
100,000,000 zatoshis), never strings and never floats internally. Serialization writes the
decimal digits directly (via `serde_json`'s `arbitrary_precision`), and parsing is an exact
port of Bitcoin Core's `ParseFixedPoint`, so values round-trip with zero drift:
`0.1` is exactly `0.10000000`, and `21000000.00000000` survives untouched.

Use a client that decodes JSON numbers as exact decimals, not IEEE 754 doubles. In Python
that is `python-bitcoinrpc`'s behavior, or plain `json.loads(raw, parse_float=decimal.Decimal)`;
the conformance suite (`scripts/conformance.py`) asserts amount fields arrive as
`Decimal`. A client that parses amounts as `float` will see values like
`0.30000000000000004` and misprice payments.

## Batching

An array body is a batch. The response is always HTTP 200 with an array of envelopes in
request order; per-item failures ride in each item's `error`:

```json
[
  {"result": 2500000, "error": null, "id": 0},
  {"result": null, "error": {"code": -32601, "message": "Method not found: no_such"}, "id": 1}
]
```

An empty batch (`[]`) is rejected with `-32600`. Batch items are processed sequentially, and
the whole batch consumes a single work-queue slot.

## Work queue

zecd bounds concurrent in-flight requests like bitcoind's `-rpcworkqueue`: at most
`[rpc] work_queue` requests (default 100) are admitted; beyond that the server answers
HTTP 503 `Work queue depth exceeded` without doing any work (the bound is enforced before
authentication, so unauthenticated floods cannot starve real clients). During shutdown, new
requests get 503 `Request rejected during server shutdown`. Both 503 bodies are plain text,
not JSON.

Sends hold their slot for the whole call (a shielded send computes proofs for a few seconds),
so a burst of concurrent sends can exhaust the queue; see [Sending](sending.md) for the
serialization semantics. `getrpcinfo.active_commands` shows what is executing right now.

## Method safelist

`[rpc] allowed_methods` is an optional server-wide safelist. Empty (the default) serves every
implemented method. Non-empty serves only the listed methods; anything else, implemented or
not, is rejected with `-32601` (HTTP 404), exactly as if it did not exist, so a locked-down
server discloses nothing about the surface it disabled. Names are validated against the
implemented method set at startup, so a typo is a fatal config error rather than a silently
dead entry. The safelist check runs before argument validation, so a disabled method never
leaks arity hints.

This is coarse and server-wide, not per-user. Its value is shrinking the blast radius of a
leaked credential: an invoicing integration can be limited to `getnewaddress` plus read
methods, keeping `sendtoaddress` and `stop` unreachable. The example config ships a
commented-out safelist grouped by use case.

## Method index

Every implemented method, with its Bitcoin Core status and nearest zcashd equivalent,
is in the [method index](method-index.md). Unimplemented bitcoind methods (including the
label methods, removed deliberately) return `-32601`.
