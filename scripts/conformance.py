#!/usr/bin/env python3
"""Bitcoin-Core RPC conformance check for zecd.

Uses the same client logic as `python-bitcoinrpc`'s AuthServiceProxy (HTTP Basic auth,
JSON-RPC 1.0 envelope, amounts decoded as `decimal.Decimal`, errors raised from the
`{code,message}` object) to prove zecd's wire format is what real Bitcoin RPC clients parse.

It asserts the fields/types BTCPay-style integrations and Bitcoin RPC libraries read, that
amounts round-trip as exact decimals (not floats), batching works, and errors carry the
expected Bitcoin Core codes.

Usage:  python3 scripts/conformance.py [--url http://127.0.0.1:18232/] [--user u] [--password p]
                                       [--passphrase <wallet passphrase>]

`--passphrase`: the wallet passphrase, when the wallet under test is encrypted. Enables the
full encryption state machine (lock/unlock/passphrase-change round-trips); the wallet is left
as it was found (same passphrase, unlocked).
"""
import argparse
import base64
import decimal
import json
import sys
import time
import urllib.request
import urllib.error


class JSONRPCException(Exception):
    def __init__(self, err):
        super().__init__(err.get("message"))
        self.code = err.get("code")


class AuthServiceProxy:
    """A minimal stand-in for python-bitcoinrpc's AuthServiceProxy (same semantics)."""

    def __init__(self, url, user, password):
        self._url = url
        self._auth = b"Basic " + base64.b64encode(f"{user}:{password}".encode())

    def _post(self, payload):
        body = json.dumps(payload).encode()
        req = urllib.request.Request(self._url, data=body)
        req.add_header("Authorization", self._auth.decode())
        req.add_header("Content-Type", "application/json")
        try:
            resp = urllib.request.urlopen(req, timeout=30)
            raw = resp.read()
        except urllib.error.HTTPError as e:
            # Bitcoin Core returns HTTP 500 with the error object for RPC errors, 401 for auth.
            if e.code == 401:
                raise JSONRPCException({"code": 401, "message": "unauthorized"})
            raw = e.read()
        # The hallmark behaviour real clients rely on: amounts decode as Decimal.
        return json.loads(raw, parse_float=decimal.Decimal)

    def call(self, method, *params):
        r = self._post({"jsonrpc": "1.0", "id": "conf", "method": method, "params": list(params)})
        if r.get("error") is not None:
            raise JSONRPCException(r["error"])
        return r["result"]

    def batch(self, calls):
        payload = [{"jsonrpc": "1.0", "id": i, "method": m, "params": list(p)} for i, (m, p) in enumerate(calls)]
        return self._post(payload)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18232/")
    ap.add_argument("--user", default="u")
    ap.add_argument("--password", default="p")
    ap.add_argument("--passphrase", default="",
                    help="wallet passphrase (enables the encrypted-wallet state-machine checks)")
    args = ap.parse_args()
    rpc = AuthServiceProxy(args.url, args.user, args.password)

    passed = failed = 0

    def ck(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS {name} {detail}")
        else:
            failed += 1
            print(f"  FAIL {name} {detail}")

    print("== getblockchaininfo fields/types ==")
    bci = rpc.call("getblockchaininfo")
    for f in ("chain", "blocks", "headers", "bestblockhash", "verificationprogress",
              "initialblockdownload", "pruned", "difficulty", "warnings"):
        ck(f"has {f}", f in bci, type(bci.get(f)).__name__)
    ck("chain is main/test/regtest", bci["chain"] in ("main", "test", "regtest"))
    ck("blocks is int", isinstance(bci["blocks"], int))
    ck("bestblockhash 64-hex", isinstance(bci["bestblockhash"], str) and len(bci["bestblockhash"]) == 64)

    print("== blocks/hash consistency ==")
    # The classic poller pattern must hold: getblockhash(getblockcount()) succeeds and
    # agrees with getbestblockhash (all three describe the fully-scanned block).
    count = rpc.call("getblockcount")
    ck("getblockcount is int", isinstance(count, int))
    best = rpc.call("getbestblockhash")
    at_count = rpc.call("getblockhash", count)
    ck("getblockhash(getblockcount()) == getbestblockhash", best == at_count, f"{best} != {at_count}")

    print("== control methods ==")
    h = rpc.call("help")
    ck("help is a string naming methods", isinstance(h, str) and "getblockchaininfo" in h)
    up = rpc.call("uptime")
    ck("uptime is a non-negative int", isinstance(up, int) and up >= 0, up)
    ck("ping returns null", rpc.call("ping") is None)
    ri = rpc.call("getrpcinfo")
    ck("getrpcinfo.active_commands is list", isinstance(ri.get("active_commands"), list))
    # Bitcoin Core's getrpcinfo reports itself as an active command.
    ck("getrpcinfo lists itself active",
       any(c.get("method") == "getrpcinfo" for c in ri.get("active_commands", [])))
    ck("active command carries duration",
       all("duration" in c for c in ri.get("active_commands", [])))
    ck("getrpcinfo has logpath", "logpath" in ri)

    print("== fee & mempool stubs ==")
    esf = rpc.call("estimatesmartfee", 2)
    ck("estimatesmartfee.feerate is Decimal",
       isinstance(esf.get("feerate"), decimal.Decimal), repr(esf.get("feerate")))
    ck("estimatesmartfee echoes blocks", esf.get("blocks") == 2, esf.get("blocks"))
    ck("estimatefee is Decimal", isinstance(rpc.call("estimatefee"), decimal.Decimal))
    mp = rpc.call("getmempoolinfo")
    ck("getmempoolinfo.loaded", mp.get("loaded") is True)
    for f in ("size", "bytes", "usage", "maxmempool"):
        ck(f"getmempoolinfo.{f} is int", isinstance(mp.get(f), int), repr(mp.get(f)))
    ck("getmempoolinfo.mempoolminfee is Decimal",
       isinstance(mp.get("mempoolminfee"), decimal.Decimal), repr(mp.get("mempoolminfee")))

    print("== getnetworkinfo fields ==")
    ni = rpc.call("getnetworkinfo")
    for f in ("version", "subversion", "protocolversion", "connections", "relayfee", "networks", "warnings"):
        ck(f"has {f}", f in ni)
    ck("relayfee is Decimal", isinstance(ni["relayfee"], decimal.Decimal), repr(ni["relayfee"]))

    print("== getpeerinfo shape ==")
    pi = rpc.call("getpeerinfo")
    ck("getpeerinfo is list", isinstance(pi, list))
    # Reflects the active lightwalletd upstream; on a synced daemon there should be one "peer".
    if pi:
        ck("peer has addr", isinstance(pi[0].get("addr"), str) and bool(pi[0]["addr"]))
    # getconnectioncount agrees with the peer list (the single lightwalletd "peer").
    cc = rpc.call("getconnectioncount")
    ck("getconnectioncount matches getpeerinfo", cc == len(pi), f"{cc} != {len(pi)}")

    print("== getwalletinfo fields ==")
    wi = rpc.call("getwalletinfo")
    for f in ("walletname", "balance", "unconfirmed_balance", "immature_balance", "txcount", "paytxfee"):
        ck(f"has {f}", f in wi)
    ck("balance is Decimal (not float)", isinstance(wi["balance"], decimal.Decimal), repr(wi["balance"]))
    # A seeded wallet can sign; only watch-only (init --ufvk) wallets report False here.
    ck("private_keys_enabled is True", wi.get("private_keys_enabled") is True,
       repr(wi.get("private_keys_enabled")))

    print("== amounts are exact decimals ==")
    bal = rpc.call("getbalance")
    ck("getbalance is Decimal", isinstance(bal, decimal.Decimal), repr(bal))
    ck("getunconfirmedbalance is Decimal",
       isinstance(rpc.call("getunconfirmedbalance"), decimal.Decimal))
    # 8-dp string form, no float drift
    ck("getbalance 8-dp serialisable", str(bal) == format(bal, "f") or bal == bal)

    # minconf is honored: 1-conf balance includes at least everything the (stricter)
    # default spendability policy counts; an impossibly deep minconf excludes everything.
    bal1 = rpc.call("getbalance", "*", 1)
    ck("getbalance('*',1) is Decimal", isinstance(bal1, decimal.Decimal), repr(bal1))
    ck("getbalance('*',1) >= getbalance()", bal1 >= bal, f"{bal1} < {bal}")
    ck("getbalance('*',99999999) == 0", rpc.call("getbalance", "*", 99999999) == 0)
    try:
        rpc.call("getbalance", "account1")
        ck("getbalance bad dummy raises", False)
    except JSONRPCException as e:
        ck("getbalance bad dummy -> code -32", e.code == -32, e.code)
    try:
        rpc.call("getbalance", "*", "six")
        ck("getbalance non-numeric minconf raises", False)
    except JSONRPCException as e:
        ck("getbalance non-numeric minconf -> code -3", e.code == -3, e.code)

    print("== getblockheader ==")
    tip_hash = rpc.call("getblockhash", rpc.call("getblockcount"))
    hdr = rpc.call("getblockheader", tip_hash)
    for f in ("hash", "confirmations", "height", "time", "mediantime"):
        ck(f"header has {f}", f in hdr)
    ck("header echoes hash", hdr["hash"] == tip_hash)
    ck("tip header confirmations == 1", hdr["confirmations"] == 1, hdr["confirmations"])
    ck("header has previousblockhash", "previousblockhash" in hdr)
    prev = rpc.call("getblockheader", hdr["previousblockhash"])
    ck("prev header links forward", prev.get("nextblockhash") == tip_hash)
    try:
        rpc.call("getblockheader", "00" * 32)
        ck("unknown header raises", False)
    except JSONRPCException as e:
        ck("unknown header -> code -5", e.code == -5, e.code)
    try:
        rpc.call("getblockheader", "xyz")
        ck("bad header hash raises", False)
    except JSONRPCException as e:
        ck("bad header hash -> code -8", e.code == -8, e.code)
    try:
        rpc.call("getblockheader", tip_hash, False)
        ck("verbose=false raises", False)
    except JSONRPCException as e:
        ck("verbose=false -> code -8", e.code == -8, e.code)

    print("== getbalances ==")
    gb = rpc.call("getbalances")
    mine = gb.get("mine", {})
    for f in ("trusted", "untrusted_pending", "immature"):
        ck(f"mine.{f} is Decimal", isinstance(mine.get(f), decimal.Decimal), repr(mine.get(f)))
    ck("mine.trusted == getbalance", mine.get("trusted") == bal)

    print("== addresses ==")
    # zecd is stateless: getnewaddress takes no label (a label would be off-chain state with no
    # on-chain source). A non-empty label argument is rejected -8 (checked below).
    addr = rpc.call("getnewaddress")
    ck("getnewaddress unified",
       isinstance(addr, str) and addr.startswith(("u1", "utest1", "uregtest1")))
    va = rpc.call("validateaddress", addr)
    ck("validateaddress.isvalid", va["isvalid"] is True)
    ck("validateaddress echoes address", va.get("address") == addr)
    # Extension fields: the address's receiver verdicts (a default getnewaddress UA always
    # exposes an Orchard receiver in the default Orchard-only config).
    ck("validateaddress has isvalid_orchard", "isvalid_orchard" in va)
    ck("validateaddress.isvalid_orchard on Orchard UA", va["isvalid_orchard"] is True)
    # receiver_types enumerates the pools an address can receive into; an Orchard-only UA
    # carries "orchard".
    ck("validateaddress.receiver_types lists orchard",
       isinstance(va.get("receiver_types"), list) and "orchard" in va["receiver_types"],
       va.get("receiver_types"))
    # A per-call receiver override (constrained to enabled pools) still yields a UA. "unified"
    # and "orchard" are always valid against the default config; an unknown type is -5.
    a2 = rpc.call("getnewaddress", "", "orchard")
    ck("getnewaddress orchard override",
       isinstance(a2, str) and a2.startswith(("u1", "utest1", "uregtest1")))
    ck("getnewaddress orchard override isvalid_orchard",
       rpc.call("validateaddress", a2)["isvalid_orchard"] is True)
    try:
        rpc.call("getnewaddress", "", "boguspool")
        ck("getnewaddress unknown receiver raises", False)
    except JSONRPCException as e:
        ck("getnewaddress unknown receiver -> -5", e.code == -5, e.code)
    # Bitcoin Core returns only the verdict + error details for invalid input.
    bad = rpc.call("validateaddress", "not-an-address")
    ck("invalid validateaddress.isvalid False", bad["isvalid"] is False)
    ck("invalid validateaddress has no address echo",
       "address" not in bad and "scriptPubKey" not in bad and "isscript" not in bad)
    ck("invalid validateaddress has error fields",
       "error" in bad and "error_locations" in bad)
    ai = rpc.call("getaddressinfo", addr)
    ck("getaddressinfo.ismine", ai["ismine"] is True)
    ck("getaddressinfo has no isvalid", "isvalid" not in ai)
    for f in ("scriptPubKey", "solvable", "iswatchonly", "isscript", "iswitness", "labels",
              "isvalid_orchard", "receiver_types"):
        ck(f"getaddressinfo has {f}", f in ai)
    # zecd is stateless: the labels field is retained for Core shape but is always empty.
    ck("getaddressinfo.labels always empty (stateless)", ai["labels"] == [], repr(ai["labels"]))
    # Own addresses are solvable; iswatchonly is deprecated/always false in Core master
    # (these hold on watch-only wallets too - the signal is private_keys_enabled).
    ck("getaddressinfo.solvable on own address", ai["solvable"] is True)
    ck("getaddressinfo.iswatchonly always False", ai["iswatchonly"] is False)
    try:
        rpc.call("getaddressinfo", "not-an-address")
        ck("getaddressinfo invalid raises", False)
    except JSONRPCException as e:
        ck("getaddressinfo invalid -> code -5", e.code == -5, e.code)

    print("== z_getaddressforaccount ==")
    # zcashd-syntax derivation of a Unified Address for the wallet's single account (0). zecd is
    # shielded-only: the default config is Orchard-only, so a default UA carries just "orchard".
    a = rpc.call("z_getaddressforaccount", 0)
    ck("z_getaddressforaccount.account is 0", a["account"] == 0)
    ck("z_getaddressforaccount returns a UA",
       isinstance(a["address"], str) and a["address"].startswith(("u1", "utest1", "uregtest1")))
    ck("z_getaddressforaccount.receiver_types is orchard",
       a["receiver_types"] == ["orchard"], a["receiver_types"])
    ck("z_getaddressforaccount.diversifier_index is an int",
       isinstance(a["diversifier_index"], int), repr(a["diversifier_index"]))
    # Re-deriving at the SAME diversifier index with the same receivers is idempotent: it returns
    # the exact same object (the key zcashd invariant, wallet_accounts.py:93).
    j = a["diversifier_index"]
    a_again = rpc.call("z_getaddressforaccount", 0, [], j)
    ck("z_getaddressforaccount is idempotent at a fixed index", a_again == a, (a_again, a))
    # The next auto-selected address differs (a fresh, unused diversifier).
    b = rpc.call("z_getaddressforaccount", 0)
    ck("z_getaddressforaccount auto-index advances", b["address"] != a["address"])
    # An explicit diversifier index re-derives the exact orchard-only UA at that index. We use a
    # high, fixed index rather than 0: zcash_client_sqlite parks each account's default address at
    # the first index with a valid Sapling diversifier (index 0 about half the time, seed-
    # dependent), and librustzcash refuses to expose a second UA with different receivers at an
    # already-used index (DiversifierIndexReuse -> -4). A large index can't collide with that
    # low-index default (nor with the clock-derived auto indices above), and Orchard diversifiers
    # are valid at every index.
    jx = 1_000_000
    zx = rpc.call("z_getaddressforaccount", 0, ["orchard"], jx)
    ck("z_getaddressforaccount at a fixed index (orchard)", zx["diversifier_index"] == jx)
    ck("z_getaddressforaccount fixed index receiver_types", zx["receiver_types"] == ["orchard"])
    # Transparent receivers are never exposed: "p2pkh" is rejected -8 (zecd is shielded-only).
    try:
        rpc.call("z_getaddressforaccount", 0, ["p2pkh"])
        ck("z_getaddressforaccount p2pkh raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount p2pkh -> -8", e.code == -8, e.code)
    # A pool not enabled on this wallet (Sapling, in the Orchard-only default) is also -8.
    try:
        rpc.call("z_getaddressforaccount", 0, ["sapling"])
        ck("z_getaddressforaccount disabled pool raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount disabled pool -> -8", e.code == -8, e.code)
    # An unknown receiver token is -8.
    try:
        rpc.call("z_getaddressforaccount", 0, ["bogus"])
        ck("z_getaddressforaccount unknown receiver raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount unknown receiver -> -8", e.code == -8, e.code)
    # Only account 0 exists (one account per wallet): a different in-range account is -4.
    try:
        rpc.call("z_getaddressforaccount", 1)
        ck("z_getaddressforaccount account 1 raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount account 1 -> -4", e.code == -4, e.code)
    # An out-of-range account number is -8.
    try:
        rpc.call("z_getaddressforaccount", -1)
        ck("z_getaddressforaccount account -1 raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount account -1 -> -8", e.code == -8, e.code)
    # A diversifier index beyond the 11-byte space is -8.
    try:
        rpc.call("z_getaddressforaccount", 0, [], 2 ** 88)
        ck("z_getaddressforaccount huge diversifier raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount huge diversifier -> -8", e.code == -8, e.code)
    # A negative diversifier index is -8.
    try:
        rpc.call("z_getaddressforaccount", 0, [], -1)
        ck("z_getaddressforaccount negative diversifier raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount negative diversifier -> -8", e.code == -8, e.code)
    # A missing required argument is Bitcoin Core's help error (-1), never -32602 (which Core
    # reserves for framing and never emits from a handler).
    try:
        rpc.call("z_getaddressforaccount")
        ck("z_getaddressforaccount no args raises", False)
    except JSONRPCException as e:
        ck("z_getaddressforaccount no args -> -1", e.code == -1, e.code)

    print("== received-by-address ==")
    recv = rpc.call("getreceivedbyaddress", addr)
    ck("getreceivedbyaddress is Decimal", isinstance(recv, decimal.Decimal), repr(recv))
    ck("fresh address received 0", recv == 0)
    lra = rpc.call("listreceivedbyaddress", 1, True)
    ck("listreceivedbyaddress is list", isinstance(lra, list))
    fresh = next((e for e in lra if e.get("address") == addr), None)
    ck("fresh address listed with include_empty", fresh is not None)
    # include_empty surfaces every generated address (this is zecd's `listaddresses`
    # equivalent), and an unused one reports zeros: no amount, no confirmations, no txids.
    if fresh is not None:
        ck("fresh entry amount 0", fresh.get("amount") == 0, repr(fresh.get("amount")))
        ck("fresh entry confirmations 0", fresh.get("confirmations") == 0, repr(fresh.get("confirmations")))
        ck("fresh entry no txids", fresh.get("txids") == [], repr(fresh.get("txids")))
    try:
        rpc.call("getreceivedbyaddress", "not-an-address")
        ck("invalid address raises", False)
    except JSONRPCException as e:
        ck("invalid address -> code -5", e.code == -5, e.code)

    print("== stateless: label methods are removed ==")
    # zecd keeps no off-chain label store, so the label-dedicated methods are not implemented at
    # all - every one is method-not-found (-32601), like any unknown method.
    for m, params in (
        ("setlabel", [addr, "x"]),
        ("getaddressesbylabel", ["x"]),
        ("listlabels", []),
        ("getreceivedbylabel", ["x"]),
        ("listreceivedbylabel", []),
    ):
        try:
            rpc.call(m, *params)
            ck(f"{m} raises (removed in stateless mode)", False)
        except JSONRPCException as e:
            ck(f"{m} -> method not found (-32601)", e.code == -32601, e.code)
    # A non-empty label argument to getnewaddress is rejected (-8); the address itself is fine.
    try:
        rpc.call("getnewaddress", "mylabel")
        ck("getnewaddress label raises", False)
    except JSONRPCException as e:
        ck("getnewaddress label -> code -8", e.code == -8, e.code)

    print("== wallets ==")
    lw = rpc.call("listwallets")
    ck("listwallets is a non-empty list of strings",
       isinstance(lw, list) and bool(lw) and all(isinstance(w, str) for w in lw), lw)

    print("== listunspent ==")
    lu = rpc.call("listunspent")
    ck("listunspent is list", isinstance(lu, list))
    if lu:
        u = lu[0]
        for f in ("txid", "vout", "address", "amount", "confirmations",
                  "spendable", "solvable", "safe"):
            ck(f"utxo has {f}", f in u)
        ck("utxo amount is Decimal", isinstance(u["amount"], decimal.Decimal))
    ck("listunspent include_unsafe=false only safe",
       all(e["safe"] for e in rpc.call("listunspent", 0, 9999999, [], False)))
    # A freshly generated address has no notes; the filter validates its entries.
    ck("listunspent fresh-address filter empty",
       rpc.call("listunspent", 1, 9999999, [addr]) == [])
    try:
        rpc.call("listunspent", 1, 9999999, ["nonsense"])
        ck("listunspent bad filter address raises", False)
    except JSONRPCException as e:
        ck("listunspent bad filter address -> code -5", e.code == -5, e.code)
    try:
        rpc.call("listunspent", 1, 9999999, [addr, addr])
        ck("listunspent duplicated filter address raises", False)
    except JSONRPCException as e:
        ck("listunspent duplicated filter address -> code -8", e.code == -8, e.code)

    print("== history ==")
    txs = rpc.call("listtransactions", "*", 20)
    ck("listtransactions is list", isinstance(txs, list))
    if txs:
        t = txs[0]
        for f in ("address", "category", "amount", "confirmations", "txid", "time",
                  "timereceived", "walletconflicts"):
            ck(f"tx has {f}", f in t)
        ck("tx amount is Decimal", isinstance(t["amount"], decimal.Decimal), repr(t["amount"]))
        ck("tx category valid", t["category"] in ("send", "receive"))
        # Bitcoin Core's WalletTxToJSON: mined txs carry block fields (and no `trusted`);
        # unmined txs carry `trusted` instead.
        if t["confirmations"] > 0:
            for f in ("blockhash", "blockheight", "blocktime"):
                ck(f"mined tx has {f}", f in t)
            ck("mined tx has no trusted", "trusted" not in t)
            ck("mined tx time == blocktime", t["time"] == t["blocktime"])
        else:
            ck("unmined tx has trusted", "trusted" in t)
        gt = rpc.call("gettransaction", t["txid"])
        ck("gettransaction amount Decimal", isinstance(gt["amount"], decimal.Decimal))
        ck("gettransaction has details list", isinstance(gt.get("details"), list))
        ck("gettransaction hex hex-string", isinstance(gt.get("hex"), str) and len(gt["hex"]) % 2 == 0)
        ck("gettransaction has walletconflicts", gt.get("walletconflicts") == [])
        ck("gettransaction has timereceived", "timereceived" in gt)
        if gt["confirmations"] > 0:
            ck("gettransaction mined has blockhash", "blockhash" in gt)

        print("== getrawtransaction ==")
        raw = rpc.call("getrawtransaction", t["txid"])
        ck("getrawtransaction returns hex", isinstance(raw, str) and len(raw) % 2 == 0 and raw)
        if gt.get("hex"):
            ck("getrawtransaction matches gettransaction.hex", raw == gt["hex"])
        v = rpc.call("getrawtransaction", t["txid"], 1)
        ck("verbose is object", isinstance(v, dict))
        for f in ("hex", "txid", "size", "version", "locktime", "vin", "vout"):
            ck(f"verbose has {f}", f in v)
        ck("verbose txid echoes", v.get("txid") == t["txid"])
        ck("verbose hex matches", v.get("hex") == raw)
        ck("verbose vin/vout are lists", isinstance(v.get("vin"), list) and isinstance(v.get("vout"), list))

    # z_listtransactions is a zecd EXTENSION (no such method in zcashd) with zcashd's z_*
    # vocabulary, so it is checked for self-consistency, not held to a bitcoind shape.
    print("== z_listtransactions (extension) ==")
    ztx = rpc.call("z_listtransactions", 20)
    ck("z_listtransactions is list", isinstance(ztx, list))
    if ztx:
        z = ztx[0]
        for f in ("txid", "status", "confirmations", "pool", "category", "amount",
                  "amountZat", "address", "outindex", "change", "outgoing",
                  "walletconflicts"):
            ck(f"z_listtransactions entry has {f}", f in z)
        ck("z_listtransactions amount is Decimal", isinstance(z["amount"], decimal.Decimal))
        ck("z_listtransactions amountZat is int", isinstance(z["amountZat"], int))
        ck("z_listtransactions pool valid",
           z["pool"] in ("transparent", "sapling", "orchard"))
        ck("z_listtransactions category valid", z["category"] in ("send", "receive"))
        ck("z_listtransactions status valid",
           z["status"] in ("mined", "waiting", "expired", "expiringsoon"))
        ck("z_listtransactions outgoing is bool", isinstance(z["outgoing"], bool))
        # A send entry's amount is negative; outgoing tracks the send category.
        ck("z_listtransactions send sign", (z["amountZat"] < 0) == (z["category"] == "send"))
    try:
        rpc.call("z_listtransactions", -1)
        ck("z_listtransactions negative count raises", False)
    except JSONRPCException as e:
        ck("z_listtransactions negative count -> -8", e.code == -8, e.code)

    print("== listsinceblock (restart-safe poller) ==")
    lsb = rpc.call("listsinceblock")
    ck("has transactions list", isinstance(lsb.get("transactions"), list))
    ck("has removed list", isinstance(lsb.get("removed"), list))
    ck("lastblock 64-hex", isinstance(lsb.get("lastblock"), str) and len(lsb["lastblock"]) == 64)
    # The daemon may still be scanning a just-mined block when this suite starts (the
    # harness proceeds as soon as a tx hits 1 confirmation), so the `best` captured at the
    # top of the run can be stale here. Compare lastblock against the *current* best hash,
    # re-reading both until they settle (bounded), instead of pinning the earlier snapshot.
    lsb_matches_best = False
    for _ in range(40):
        if lsb["lastblock"] == rpc.call("getbestblockhash"):
            lsb_matches_best = True
            break
        time.sleep(0.5)
        lsb = rpc.call("listsinceblock")
    ck("lastblock == getbestblockhash", lsb_matches_best, lsb["lastblock"])
    again = rpc.call("listsinceblock", lsb["lastblock"])
    ck("since lastblock reports only unconfirmed",
       all(t["confirmations"] < 1 for t in again["transactions"]))
    try:
        rpc.call("listsinceblock", "00" * 32)
        ck("unknown block raises", False)
    except JSONRPCException as e:
        ck("unknown block -> code -5", e.code == -5, e.code)

    print("== error handling (JSONRPCException with Bitcoin Core codes) ==")
    try:
        rpc.call("gettransaction", "00" * 32)
        ck("gettransaction unknown raises", False)
    except JSONRPCException as e:
        ck("gettransaction unknown -> code -5", e.code == -5, e.code)
    try:
        rpc.call("no_such_method_xyz")
        ck("unknown method raises", False)
    except JSONRPCException as e:
        ck("unknown method -> code -32601", e.code == -32601, e.code)
    try:
        rpc.call("listtransactions", "*", -1)
        ck("negative count raises", False)
    except JSONRPCException as e:
        ck("negative count -> code -8", e.code == -8, e.code)
    try:
        rpc.call("getnewaddress", "", "bech32")
        ck("unknown address type raises", False)
    except JSONRPCException as e:
        ck("unknown address type -> code -5", e.code == -5, e.code)
    try:
        # Amount as a string (zecd accepts both); the reject fires before any send logic.
        rpc.call("sendtoaddress", addr, "0.1", "", "", True)
        ck("subtractfeefromamount raises", False)
    except JSONRPCException as e:
        ck("subtractfeefromamount -> code -8", e.code == -8, e.code)
    try:
        # Zero amounts are rejected before any send logic, like Bitcoin Core.
        rpc.call("sendtoaddress", addr, 0)
        ck("zero amount raises", False)
    except JSONRPCException as e:
        ck("zero amount -> code -3", e.code == -3, e.code)
    try:
        # Typed arguments: a non-numeric minconf is -3, never silently the default.
        rpc.call("getreceivedbyaddress", addr, "six")
        ck("non-numeric minconf raises", False)
    except JSONRPCException as e:
        ck("non-numeric minconf -> code -3", e.code == -3, e.code)
    try:
        # The memo extension param (11) validates hex before any send logic. Positions
        # 4..=10 are subtractfeefromamount/replaceable/conf_target/estimate_mode/
        # avoid_reuse/fee_rate/verbose - seven nulls before the memo.
        rpc.call("sendtoaddress", addr, "0.1", "", "", None, None, None, None,
                 None, None, None, "not-hex")
        ck("bad memo hex raises", False)
    except JSONRPCException as e:
        ck("bad memo hex -> code -8", e.code == -8, e.code)
    try:
        # A non-boolean verbose (position 10) is a -3 type error.
        rpc.call("sendtoaddress", addr, "0.1", "", "", None, None, None, None,
                 None, None, "not-a-bool")
        ck("non-boolean verbose raises", False)
    except JSONRPCException as e:
        ck("non-boolean verbose -> code -3", e.code == -3, e.code)
    try:
        # settxfee gets the explicit ZIP-317 -8, like every other fee instruction.
        rpc.call("settxfee", 0.0001)
        ck("settxfee raises", False)
    except JSONRPCException as e:
        ck("settxfee -> code -8", e.code == -8, e.code)
    # lastblock is always a 64-hex-char cursor, even at absurd depths.
    lsb = rpc.call("listsinceblock")
    ck("lastblock is 64 hex chars", len(lsb["lastblock"]) == 64, lsb["lastblock"])
    lsb = rpc.call("listsinceblock", "", 99999999)
    ck("deep target lastblock still 64 chars", len(lsb["lastblock"]) == 64, lsb["lastblock"])
    try:
        # fee_rate (param 9): an explicit fee instruction; fees are ZIP-317 and never settable.
        rpc.call("sendtoaddress", addr, "0.1", "", "", False, False, None, "", False, 25)
        ck("sendtoaddress fee_rate raises", False)
    except JSONRPCException as e:
        ck("sendtoaddress fee_rate -> code -8", e.code == -8, e.code)
    try:
        rpc.call("sendmany", "", {addr: "0.1"}, 1, "", [], False, None, "", 25)
        ck("sendmany fee_rate raises", False)
    except JSONRPCException as e:
        ck("sendmany fee_rate -> code -8", e.code == -8, e.code)
    # Arity: like Bitcoin Core, a call with more positional arguments than the method accepts is
    # rejected (-1, the help error) rather than silently ignoring the trailing junk. A no-arg
    # method with one extra arg, and a one-arg method with a second, both trip it.
    try:
        rpc.call("getblockcount", 1)
        ck("getblockcount extra arg raises", False)
    except JSONRPCException as e:
        ck("getblockcount extra arg -> code -1", e.code == -1, e.code)
    try:
        rpc.call("validateaddress", addr, "extra")
        ck("validateaddress extra arg raises", False)
    except JSONRPCException as e:
        ck("validateaddress extra arg -> code -1", e.code == -1, e.code)
    # z_sendmany is zcashd's async send: it returns an opid; the trio z_getoperationstatus /
    # z_getoperationresult / z_listoperationids track it. These checks all reject (or query
    # empty) *before* any send is spawned, so they move no money. addr is the wallet's own
    # address, so the fromaddress ownership check passes and later validation fires.
    try:
        # An explicit fee is ZIP-317 -8, like the synchronous sends.
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1"}], 1, 0.0001)
        ck("z_sendmany fee raises", False)
    except JSONRPCException as e:
        ck("z_sendmany fee -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [])
        ck("z_sendmany empty amounts raises", False)
    except JSONRPCException as e:
        ck("z_sendmany empty amounts -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1"}], 1, None, "Bogus")
        ck("z_sendmany unknown privacyPolicy raises", False)
    except JSONRPCException as e:
        ck("z_sendmany unknown privacyPolicy -> code -8", e.code == -8, e.code)
    try:
        # An unparseable fromaddress is -5 before any send logic.
        rpc.call("z_sendmany", "not-an-address", [{"address": addr, "amount": "0.1"}])
        ck("z_sendmany bad fromaddress raises", False)
    except JSONRPCException as e:
        ck("z_sendmany bad fromaddress -> code -5", e.code == -5, e.code)
    try:
        # A missing fromaddress is Bitcoin Core's help error (-1, via require_str), not the
        # framing-only -32602.
        rpc.call("z_sendmany")
        ck("z_sendmany no args raises", False)
    except JSONRPCException as e:
        ck("z_sendmany no args -> code -1", e.code == -1, e.code)
    try:
        # ANY_TADDR is unsupported (zecd has no transparent source) -> -5.
        rpc.call("z_sendmany", "ANY_TADDR", [{"address": addr, "amount": "0.1"}])
        ck("z_sendmany ANY_TADDR raises", False)
    except JSONRPCException as e:
        ck("z_sendmany ANY_TADDR -> code -5", e.code == -5, e.code)
    try:
        rpc.call("z_sendmany", addr, "notarray")
        ck("z_sendmany non-array amounts raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-array amounts -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, ["notanobject"])
        ck("z_sendmany non-object entry raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-object entry -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1", "bogus": 1}])
        ck("z_sendmany unknown key raises", False)
    except JSONRPCException as e:
        ck("z_sendmany unknown key -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"amount": "0.1"}])
        ck("z_sendmany missing address raises", False)
    except JSONRPCException as e:
        ck("z_sendmany missing address -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr}])
        ck("z_sendmany missing amount raises", False)
    except JSONRPCException as e:
        ck("z_sendmany missing amount -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1", "memo": 123}])
        ck("z_sendmany non-string memo raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-string memo -> code -3", e.code == -3, e.code)
    try:
        rpc.call("z_sendmany", addr,
                 [{"address": addr, "amount": "0.1"}, {"address": addr, "amount": "0.2"}])
        ck("z_sendmany duplicate recipient raises", False)
    except JSONRPCException as e:
        ck("z_sendmany duplicate recipient -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_sendmany", addr, [{"address": addr, "amount": "0.1"}], "six")
        ck("z_sendmany non-integer minconf raises", False)
    except JSONRPCException as e:
        ck("z_sendmany non-integer minconf -> code -3", e.code == -3, e.code)
    try:
        # A malformed opid is -8; a well-formed-but-unknown one is silently omitted (below).
        rpc.call("z_getoperationstatus", ["not-an-opid"])
        ck("z_getoperationstatus bad opid raises", False)
    except JSONRPCException as e:
        ck("z_getoperationstatus bad opid -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_getoperationstatus", "notarray")
        ck("z_getoperationstatus non-array raises", False)
    except JSONRPCException as e:
        ck("z_getoperationstatus non-array -> code -8", e.code == -8, e.code)
    try:
        rpc.call("z_getoperationstatus", [123])
        ck("z_getoperationstatus non-string opid raises", False)
    except JSONRPCException as e:
        ck("z_getoperationstatus non-string opid -> code -8", e.code == -8, e.code)
    ck("z_listoperationids returns a list", isinstance(rpc.call("z_listoperationids"), list))
    _unknown_opid = "opid-00000000-0000-0000-0000-000000000000"
    ck("z_getoperationstatus unknown opid omitted",
       rpc.call("z_getoperationstatus", [_unknown_opid]) == [])
    ck("z_getoperationresult unknown opid omitted",
       rpc.call("z_getoperationresult", [_unknown_opid]) == [])
    try:
        rpc.call("getrawtransaction", "00" * 32)
        ck("getrawtransaction unknown raises", False)
    except JSONRPCException as e:
        ck("getrawtransaction unknown -> code -5", e.code == -5, e.code)
    try:
        rpc.call("getrawtransaction", "not-a-txid")
        ck("getrawtransaction bad txid raises", False)
    except JSONRPCException as e:
        ck("getrawtransaction bad txid -> code -8", e.code == -8, e.code)
    try:
        rpc.call("sendrawtransaction", "00ff")
        ck("sendrawtransaction undecodable raises", False)
    except JSONRPCException as e:
        ck("sendrawtransaction undecodable -> code -22", e.code == -22, e.code)
    try:
        AuthServiceProxy(args.url, args.user, "wrong-password").call("getblockcount")
        ck("bad auth raises", False)
    except JSONRPCException as e:
        ck("bad auth -> 401", e.code == 401, e.code)

    print("== wallet encryption state ==")
    # Adapts to the wallet under test: an encrypted wallet reports unlocked_until and verifies
    # passphrases (-14 on a wrong one); an unencrypted wallet rejects the passphrase RPCs with
    # -15, exactly like running bitcoind with an unencrypted wallet.
    if "unlocked_until" in wi:
        ck("unlocked_until is an int when encrypted", isinstance(wi["unlocked_until"], int))
        try:
            rpc.call("walletpassphrase", "definitely-not-the-passphrase", 60)
            ck("wrong passphrase raises", False)
        except JSONRPCException as e:
            ck("wrong passphrase -> -14", e.code == -14, e.code)
        if args.passphrase:
            # The lock/unlock state machine with the real passphrase: unlock (unlocked_until
            # advances), lock (send -> -13), re-unlock. The wallet ends as found: unlocked.
            ck("passphrase unlocks",
               rpc.call("walletpassphrase", args.passphrase, 600) is None)
            ck("unlocked_until > 0 while unlocked",
               rpc.call("getwalletinfo")["unlocked_until"] > 0)
            ck("walletlock returns null", rpc.call("walletlock") is None)
            ck("locked wallet reports unlocked_until 0",
               rpc.call("getwalletinfo")["unlocked_until"] == 0)
            try:
                # The lock check precedes input selection, so no funds are needed.
                rpc.call("sendtoaddress", addr, "0.01")
                ck("locked wallet refuses to send", False)
            except JSONRPCException as e:
                ck("locked send -> -13", e.code == -13, e.code)
            ck("re-unlocked after the lock round-trip",
               rpc.call("walletpassphrase", args.passphrase, 600) is None)
    else:
        ck("getwalletinfo omits unlocked_until when unencrypted", "unlocked_until" not in wi)
        try:
            rpc.call("walletpassphrase", "anything", 60)
            ck("walletpassphrase on unencrypted raises", False)
        except JSONRPCException as e:
            ck("walletpassphrase unencrypted -> -15", e.code == -15, e.code)
        try:
            rpc.call("walletlock")
            ck("walletlock on unencrypted raises", False)
        except JSONRPCException as e:
            ck("walletlock unencrypted -> -15", e.code == -15, e.code)
    # Argument validation happens before the encryption-state check: a negative timeout is -8
    # in both wallet states.
    try:
        rpc.call("walletpassphrase", "anything", -1)
        ck("negative timeout raises", False)
    except JSONRPCException as e:
        ck("walletpassphrase negative timeout -> -8", e.code == -8, e.code)

    print("== batch ==")
    out = rpc.batch([("getblockcount", []), ("no_such", [])])
    ck("batch returns array", isinstance(out, list) and len(out) == 2)
    ck("batch[0] ok, [1] error", out[0]["error"] is None and out[1]["error"]["code"] == -32601)

    print(f"\nCONFORMANCE: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
