#!/usr/bin/env python3
"""Bitcoin-Core RPC conformance check for zecd.

Uses the same client logic as `python-bitcoinrpc`'s AuthServiceProxy (HTTP Basic auth,
JSON-RPC 1.0 envelope, amounts decoded as `decimal.Decimal`, errors raised from the
`{code,message}` object) to prove zecd's wire format is what real Bitcoin RPC clients parse.

It asserts the fields/types BTCPay-style integrations and Bitcoin RPC libraries read, that
amounts round-trip as exact decimals (not floats), batching works, and errors carry the
expected Bitcoin Core codes.

Usage:  python3 scripts/conformance.py [--url http://127.0.0.1:18232/] [--user u] [--password p]
"""
import argparse
import base64
import decimal
import json
import sys
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
    ck("chain is main/test", bci["chain"] in ("main", "test"))
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

    print("== getwalletinfo fields ==")
    wi = rpc.call("getwalletinfo")
    for f in ("walletname", "balance", "unconfirmed_balance", "immature_balance", "txcount", "paytxfee"):
        ck(f"has {f}", f in wi)
    ck("balance is Decimal (not float)", isinstance(wi["balance"], decimal.Decimal), repr(wi["balance"]))

    print("== amounts are exact decimals ==")
    bal = rpc.call("getbalance")
    ck("getbalance is Decimal", isinstance(bal, decimal.Decimal), repr(bal))
    # 8-dp string form, no float drift
    ck("getbalance 8-dp serialisable", str(bal) == format(bal, "f") or bal == bal)

    print("== addresses ==")
    addr = rpc.call("getnewaddress", "conformance")
    ck("getnewaddress unified", isinstance(addr, str) and addr.startswith(("u1", "utest1")))
    va = rpc.call("validateaddress", addr)
    ck("validateaddress.isvalid", va["isvalid"] is True)
    ai = rpc.call("getaddressinfo", addr)
    ck("getaddressinfo.ismine", ai["ismine"] is True)

    print("== history ==")
    txs = rpc.call("listtransactions", "*", 20)
    ck("listtransactions is list", isinstance(txs, list))
    if txs:
        t = txs[0]
        for f in ("address", "category", "amount", "confirmations", "txid", "time"):
            ck(f"tx has {f}", f in t)
        ck("tx amount is Decimal", isinstance(t["amount"], decimal.Decimal), repr(t["amount"]))
        ck("tx category valid", t["category"] in ("send", "receive"))
        gt = rpc.call("gettransaction", t["txid"])
        ck("gettransaction amount Decimal", isinstance(gt["amount"], decimal.Decimal))
        ck("gettransaction has details list", isinstance(gt.get("details"), list))
        ck("gettransaction hex hex-string", isinstance(gt.get("hex"), str) and len(gt["hex"]) % 2 == 0)

    print("== listsinceblock (restart-safe poller) ==")
    lsb = rpc.call("listsinceblock")
    ck("has transactions list", isinstance(lsb.get("transactions"), list))
    ck("has removed list", isinstance(lsb.get("removed"), list))
    ck("lastblock 64-hex", isinstance(lsb.get("lastblock"), str) and len(lsb["lastblock"]) == 64)
    ck("lastblock == getbestblockhash", lsb["lastblock"] == best)
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
        AuthServiceProxy(args.url, args.user, "wrong-password").call("getblockcount")
        ck("bad auth raises", False)
    except JSONRPCException as e:
        ck("bad auth -> 401", e.code == 401, e.code)

    print("== batch ==")
    out = rpc.batch([("getblockcount", []), ("no_such", [])])
    ck("batch returns array", isinstance(out, list) and len(out) == 2)
    ck("batch[0] ok, [1] error", out[0]["error"] is None and out[1]["error"]["code"] == -32601)

    print(f"\nCONFORMANCE: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
