#!/usr/bin/env python3
"""End-to-end RPC smoke test for a running zecd daemon.

Drives the bitcoind-style JSON-RPC surface over HTTP and asserts the response shapes,
amounts, and error codes that Bitcoin RPC clients rely on. It only needs the stdlib (no
third-party deps), exercising the exact wire format.

Usage:
    # Start a synced daemon first, e.g.:
    #   zecd --datadir ./data --testnet --rpcuser u --rpcpassword p --rpcport 18232
    python3 scripts/rpc_smoke.py [--url http://127.0.0.1:18232/] [--user u] [--password p]

Exit code is non-zero if any check fails.
"""
import argparse
import base64
import json
import sys
import urllib.error
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18232/")
    ap.add_argument("--user", default="u")
    ap.add_argument("--password", default="p")
    args = ap.parse_args()
    auth = "Basic " + base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    def call(method, params=None, authz=auth, path=""):
        body = json.dumps({"jsonrpc": "1.0", "id": "t", "method": method, "params": params or []}).encode()
        req = urllib.request.Request(args.url + path, data=body, headers={"Content-Type": "text/plain"})
        if authz:
            req.add_header("Authorization", authz)

        def parse(code, raw):
            try:
                return code, json.loads(raw)
            except Exception:
                return code, {"raw": raw.decode(errors="replace")}

        try:
            r = urllib.request.urlopen(req, timeout=20)
            return parse(r.getcode(), r.read())
        except urllib.error.HTTPError as e:
            return parse(e.code, e.read())

    passed = failed = 0

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS {name} {detail}")
        else:
            failed += 1
            print(f"  FAIL {name} {detail}")

    print("== chain / network ==")
    _, r = call("getblockchaininfo")
    res = r["result"]
    check("getblockchaininfo.chain", res["chain"] in ("main", "test"), res["chain"])
    check("blocks<=headers", res["blocks"] <= res["headers"])
    check("bestblockhash 64-hex", len(res["bestblockhash"]) == 64)
    _, r = call("getblockcount")
    check("getblockcount is int", isinstance(r["result"], int), str(r["result"]))
    _, r = call("getnetworkinfo")
    check("subversion contains zecd", "zecd" in r["result"]["subversion"], r["result"]["subversion"])

    print("== wallet ==")
    _, r = call("getwalletinfo")
    wi = r["result"]
    check("getwalletinfo.balance numeric", isinstance(wi["balance"], (int, float)))
    _, r = call("getnewaddress", ["smoke-label"])
    addr = r["result"]
    check("getnewaddress unified addr", isinstance(addr, str) and addr.startswith(("u1", "utest1")), addr[:16] + "...")
    _, r = call("getaddressinfo", [addr])
    check("getaddressinfo.ismine", r["result"]["ismine"] is True)
    check("getaddressinfo.labels", "smoke-label" in r["result"]["labels"])
    _, r = call("validateaddress", [addr])
    check("validateaddress own addr", r["result"]["isvalid"] and r["result"]["isvalid_orchard"])
    _, r = call("validateaddress", ["not-an-address"])
    check("validateaddress garbage invalid", r["result"]["isvalid"] is False)
    _, r = call("listtransactions", ["*", 10])
    check("listtransactions is array", isinstance(r["result"], list))
    _, r = call("listunspent")
    check("listunspent is array", isinstance(r["result"], list), f"len={len(r['result'])}")

    print("== error semantics ==")
    c, r = call("gettransaction", ["00" * 32])
    check("gettransaction unknown -> 500/-5", c == 500 and r["error"]["code"] == -5, f"http={c}")
    c, r = call("sendtoaddress", ["badaddr", "0.001"])
    check("sendtoaddress bad addr -> -5", c == 500 and r["error"]["code"] == -5, f"code={r['error']['code']}")
    c, r = call("definitely_not_a_method")
    check("unknown method -> 500/-32601", c == 500 and r["error"]["code"] == -32601, f"http={c}")
    c, _ = call("getblockchaininfo", authz=None)
    check("no auth -> 401", c == 401, f"http={c}")
    c, _ = call("getblockchaininfo", authz="Basic " + base64.b64encode(b"u:wrong").decode())
    check("wrong auth -> 401", c == 401, f"http={c}")

    print("== batch ==")
    body = json.dumps([{"method": "uptime", "id": 1}, {"method": "nope", "id": 2}]).encode()
    req = urllib.request.Request(args.url, data=body, headers={"Content-Type": "text/plain", "Authorization": auth})
    rr = urllib.request.urlopen(req, timeout=20)
    arr = json.loads(rr.read())
    check("batch http 200", rr.getcode() == 200)
    check("batch len 2 + per-item error", len(arr) == 2 and arr[0]["error"] is None and arr[1]["error"]["code"] == -32601)

    print("== multiwallet routing ==")
    c, r = call("getwalletinfo", path="wallet/default")
    check("/wallet/default", c == 200 and r["result"]["walletname"] == "default")
    c, r = call("getbalance", path="wallet/does-not-exist")
    check("/wallet/<missing> -> -18", c == 500 and r["error"]["code"] == -18, f"code={r['error']['code']}")

    print(f"\nRESULT: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
