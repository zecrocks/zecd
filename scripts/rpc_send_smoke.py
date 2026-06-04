#!/usr/bin/env python3
"""Spending smoke test for a running zecd daemon (validates the methods that move funds).

Requires a daemon with TWO wallets loaded (default + w2, see zecd.example.toml), where the
`default` wallet holds at least ~0.05 spendable balance. It validates:

  - walletlock      -> a subsequent send returns RPC_WALLET_UNLOCK_NEEDED (-13)
  - walletpassphrase-> re-unlocks for sending
  - sendtoaddress   -> broadcasts a single-output Orchard tx, returns a txid
  - sendmany        -> broadcasts a multi-output Orchard tx, returns a txid

NOTE: debug builds prove slowly; use a generous --send-timeout. Sends spend real (testnet)
funds and wait for note maturity, so this is a manual tool, not part of `cargo test`.

Usage:
  python3 scripts/rpc_send_smoke.py [--url http://127.0.0.1:18232] [--user u --password p]
                                    [--send-timeout 180] [--maturity-timeout 1200]
"""
import argparse, base64, json, sys, time, urllib.error, urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:18232")
    ap.add_argument("--user", default="u")
    ap.add_argument("--password", default="p")
    ap.add_argument("--send-timeout", type=int, default=180)
    ap.add_argument("--maturity-timeout", type=int, default=1200)
    args = ap.parse_args()
    authz = "Basic " + base64.b64encode(f"{args.user}:{args.password}".encode()).decode()

    def call(method, params=None, wallet=None, timeout=30):
        path = f"/wallet/{wallet}" if wallet else "/"
        body = json.dumps({"jsonrpc": "1.0", "id": "s", "method": method, "params": params or []}).encode()
        req = urllib.request.Request(args.url + path, data=body,
                                     headers={"Content-Type": "text/plain", "Authorization": authz})
        try:
            r = urllib.request.urlopen(req, timeout=timeout)
            return r.getcode(), json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, None

    passed = failed = 0

    def ck(name, cond, detail=""):
        nonlocal passed, failed
        passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
        print(("  PASS " if cond else "  FAIL ") + name + " " + str(detail), flush=True)

    print("== walletlock / walletpassphrase gate ==")
    _, r = call("walletlock", wallet="default")
    ck("walletlock returns null", r["result"] is None)
    _, r2 = call("getnewaddress", ["lock-probe"], wallet="w2")
    probe = r2["result"]
    c, r = call("sendtoaddress", [probe, "0.001"], wallet="default", timeout=args.send_timeout)
    ck("locked send -> -13", c == 500 and r and r["error"]["code"] == -13, f"http={c}")
    _, r = call("walletpassphrase", ["", 600], wallet="default")
    ck("walletpassphrase re-unlocks", r["result"] is None)

    print("== wait for spendable balance ==")
    deadline = time.time() + args.maturity_timeout
    spendable = 0.0
    while time.time() < deadline:
        _, r = call("getwalletinfo", wallet="default")
        spendable = float(r["result"]["balance"])
        print(f"  default spendable={spendable}", flush=True)
        if spendable > 0.03:
            break
        time.sleep(15)
    ck("default has spendable funds", spendable > 0.03, spendable)
    if spendable <= 0.03:
        print(f"\nRESULT: {passed} passed, {failed} failed (insufficient funds to test sends)")
        return 1

    print("== sendtoaddress ==")
    _, r = call("getnewaddress", ["s2a"], wallet="w2")
    c, r = call("sendtoaddress", [r["result"], "0.01"], wallet="default", timeout=args.send_timeout)
    ck("sendtoaddress returns txid", c == 200 and r and not r.get("error") and len(r.get("result", "")) == 64,
       f"http={c} {r}")

    print("== sendmany ==")
    _, ra = call("getnewaddress", ["sm-a"], wallet="w2")
    _, rb = call("getnewaddress", ["sm-b"], wallet="w2")
    # second spend needs the previous change to mature
    deadline = time.time() + args.maturity_timeout
    while time.time() < deadline:
        _, r = call("getwalletinfo", wallet="default")
        if float(r["result"]["balance"]) > 0.02:
            break
        print(f"  waiting for change... spendable={r['result']['balance']}", flush=True)
        time.sleep(15)
    c, r = call("sendmany", ["", {ra["result"]: 0.01, rb["result"]: 0.01}], wallet="default", timeout=args.send_timeout)
    ok = c == 200 and r and not r.get("error") and len(r.get("result", "")) == 64
    ck("sendmany returns txid", ok, f"http={c} {r}")
    if ok:
        _, r = call("gettransaction", [r["result"]], wallet="default")
        ck("sendmany tx has 2 outputs", len(r["result"].get("details", [])) == 2)

    print(f"\nRESULT: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
