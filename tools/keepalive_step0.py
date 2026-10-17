"""Step 0 of the keep-alive gate: does a ping keep a session's cache warm?

    PYTHONPATH=src <venv python> tools/keepalive_step0.py --scratch <dir> [--forms full,held]
    PYTHONPATH=src <venv python> tools/keepalive_step0.py --scratch <dir> --self-check

WHY THIS EXISTS AS A SCRIPT. `_KEEPALIVE_FORMS` ships empty: the sender replays
a session's last body (`max_tokens: 0`, `stream: false`) and nothing has shown
that the API accepts it, reads the cache instead of writing it, or leaves the
session's NEXT real request alone (no `thread_not_found` 404, no dropped
thinking). The ping has no trigger from outside the process, so the pin runs
in-process here and `_keepalive_ping(session, force_form=True)` is called
directly. Per body form (`full`: the whole history; `held`: a
`message-threads-` turn the server holds the history of) it drives one Claude
Code client through a throwaway pin, pings, sends one more real turn, and says
PASS when the ping read the prefix (cache_read >= 0.9 P, cache_creation <=
0.1 P) and the next turn did too with no 404.

THE LIVE FLEET IS NOT TOUCHED, and the script checks it:
  - HOME, CLAUDE_CONFIG_DIR and the cert dir are under --scratch BEFORE the
    pin is imported (it reads `.claude.json` for the port to reclaim). Nothing
    is written outside --scratch.
  - The real home's `.claude.json` `env` and `oauthAccount` (the only keys a
    pin writes) are hashed before and after; CHANGED exits non-zero.
  - The ACTIVE login's access token is read in-process and handed to the
    client through its environment only. The refresh token is never bound to
    a variable (the JSON `object_hook` drops it while parsing), the token is
    never printed or written, and the run refuses when it expires in under 20
    min. The active login's 5h/7d meter is shared with every live session, so
    the utilization before/after is context, not a per-ping cost.
  - Affinity is armed by patching `session_affinity_config` and seeding the
    kept slot; the snapshot rebuild and the usage-header recorder (both read
    the store) are switched off, and the slot's bar is 101 so a reply near a
    wall cannot drop the slot the measurement needs.

--self-check starts and stops the throwaway pin with a dummy token and no
client, answers the ping from a canned reply, and makes no network call.
"""
import argparse
import hashlib
import http.client
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading
import time

REAL_HOME = os.path.expanduser("~")  # home-read
CLIENT = os.path.join(REAL_HOME, ".local/share/claude/versions/2.1.302")  # home-read
TOKEN_MIN_MS = 20 * 60 * 1000
TURN_TIMEOUT_S = 240
FORM_TETHER = {"full": "0", "held": "1"}


def real_state():
    """sha256 of the real `.claude.json`'s `env` and `oauthAccount`."""
    for _ in range(3):  # a live session rewrites the file; a torn read retries
        try:
            with open(os.path.join(REAL_HOME, ".claude.json")) as f:  # home-read
                cfg = json.load(f)
            break
        except FileNotFoundError:
            cfg = {}
            break
        except ValueError:
            time.sleep(0.5)
    else:
        sys.exit("the real .claude.json did not parse three times")
    return {k: hashlib.sha256(json.dumps(cfg.get(k), sort_keys=True).encode()
                              ).hexdigest()[:16] for k in ("env", "oauthAccount")}


def read_login():
    """(access token, expiresAt ms) of the active login. The refresh token is
    parsed by the decoder and never reaches a variable of ours."""
    keep = lambda d: ({k: d[k] for k in ("accessToken", "expiresAt") if k in d}
                      if "accessToken" in d else d)
    with open(os.path.join(REAL_HOME, ".claude/.credentials.json")) as f:  # home-read
        oauth = json.load(f, object_hook=keep)["claudeAiOauth"]
    return oauth["accessToken"], oauth["expiresAt"]


def confine(scratch):
    """Everything the pin and its client read from the environment is under
    ``scratch`` before the pin is imported."""
    for k in list(os.environ):
        if k.startswith(("CLAUDE_CODE_", "CSWAP_PIN_", "LISTEN_", "ANTHROPIC_")) \
                or k.lower() in ("https_proxy", "http_proxy", "all_proxy"):
            del os.environ[k]
    home = scratch / "h"
    cfg = home / ".claude"
    cfg.mkdir(parents=True, exist_ok=True)
    os.environ.update(HOME=str(home), CLAUDE_CONFIG_DIR=str(cfg),
                      XDG_DATA_HOME=str(home / ".local/share"))
    certdir = home / ".local/share/claude-swap/pin-proxy"
    certdir.mkdir(parents=True, exist_ok=True)
    return home, certdir


def start_pin(pp, certdir, token, expires_ms):
    """A throwaway pin on an ephemeral port, armed with one kept slot that
    holds ``token``, and a recorder of every /v1/messages reply it relays."""
    pp.session_affinity_config = lambda _certdir: (3600.0, 90.0, "dynamic")
    pp._spawn_usage_header_recorder = lambda fn: None  # no store read or write
    ident = ("1", "step0@example.invalid")
    pp._affinity_idents[token] = ident
    pp._affinity_kept[ident] = (token, expires_ms, 101.0, None)
    seen = []
    note = pp._note_usage_headers

    def record(status_line, lines, path, *a, **k):
        if (path or "").split("?")[0].rstrip("/") == "/v1/messages":
            seen.append({"status": int(status_line.split()[1]),
                         "util": {l.split(b":")[0].decode().lower(): l.split(b":")[1].strip().decode()
                                  for l in lines[1:] if b"utilization" in l.lower()}})
        return note(status_line, lines, path, *a, **k)

    pp._note_usage_headers = record
    pp.ensure_ca(certdir, "api.anthropic.com")
    proxy = pp.PinProxy(certdir, lambda: token, chain_proxy=("127.0.0.1", 8118))
    proxy.start()
    return proxy, seen


def probe_ping(proxy, session):
    """`_keepalive_ping` with the upstream error body captured on a non-2xx."""
    exchanged = []
    orig = proxy._keepalive_exchange
    proxy._keepalive_exchange = lambda *a: exchanged.append(orig(*a)) or exchanged[-1]
    try:
        out = proxy._keepalive_ping(session, force_form=True)
    finally:
        proxy._keepalive_exchange = orig
    if exchanged and not 200 <= exchanged[0][0] < 300:
        out["error_body"] = exchanged[0][2][:1000].decode("utf-8", "replace")
    return out


def health(proxy):
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    try:
        conn.request("GET", "/health")
        return json.loads(conn.getresponse().read())["cache_aware"]
    finally:
        conn.close()


def prefix(usage):
    return sum(usage.get(k) or 0 for k in (
        "cache_read_input_tokens", "cache_creation_input_tokens", "input_tokens"))


def verdict(rec):
    """PASS when the ping read the prefix and the next turn did too."""
    p, ping, nxt = rec["P"], rec["ping"], rec["next"]
    pu, nu = ping["usage"], nxt["usage"]
    a = (rec["captured"] == rec["want"] and p > 0
         and ping["status"] is not None and 200 <= ping["status"] < 300
         and pu.get("cache_read_input_tokens", 0) >= 0.9 * p
         and pu.get("cache_creation_input_tokens", 0) <= 0.1 * p)
    b = (nxt["ok"] and not rec["any_404"]
         and nu.get("cache_read_input_tokens", 0) >= 0.9 * p)
    return "PASS" if a and b else "FAIL"


def table(form, rec):
    ping, nxt = rec["ping"], rec["next"]
    rows = [
        ("form captured", rec["captured"]), ("P (tokens)", rec["P"]),
        ("last real turn", rec["last_turn"]),
        ("ping status / refused", f"{ping['status']} / {ping['refused']}"),
        ("ping error body", ping.get("error_body", "-")),
        ("ping cache_read", ping["usage"].get("cache_read_input_tokens")),
        ("ping cache_creation", ping["usage"].get("cache_creation_input_tokens")),
        ("utilization before (last real turn)", rec["util_before"]),
        ("utilization after (ping)", ping["ratelimit"]),
        ("next turn ok", nxt["ok"]),
        ("next turn cache_read", nxt["usage"].get("cache_read_input_tokens")),
        ("any 404 from upstream", rec["any_404"]),
        ("/health captures", rec["health"]["captures"]),
        ("/health pings", rec["health"]["pings"]),
    ]
    return "\n".join([f"### {form}: {rec['verdict']}", "", "| row | value |", "|---|---|"]
                     + [f"| {k} | {v} |" for k, v in rows])


class Client:
    """One `claude -p` stream-json process: turns on stdin keep its thread."""

    def __init__(self, env, cwd, token):
        self.token, self.err, self.out = token, [], queue.Queue()
        self.proc = subprocess.Popen(
            [CLIENT, "-p", "--input-format", "stream-json",
             "--output-format", "stream-json", "--verbose"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=cwd, text=True)
        threading.Thread(target=lambda: [self.out.put(l) for l in self.proc.stdout],
                         daemon=True).start()
        threading.Thread(target=lambda: [self.err.append(l) for l in self.proc.stderr],
                         daemon=True).start()

    def turn(self, text="reply with the word ok"):
        """The `result` event of one turn: ok, and the usage of its last API
        call (the `result` one may sum a session)."""
        msg = {"type": "user", "message": {"role": "user", "content": text}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        call, end = {}, time.monotonic() + TURN_TIMEOUT_S
        while time.monotonic() < end:
            try:
                ev = json.loads(self.out.get(timeout=1))
            except queue.Empty:
                if self.proc.poll() is not None:
                    break
                continue
            except ValueError:
                continue
            if ev.get("type") == "assistant":
                call = (ev.get("message") or {}).get("usage") or call
            elif ev.get("type") == "result":
                return {"ok": not ev.get("is_error"),
                        "usage": call or ev.get("usage") or {}}
        tail = re.sub(re.escape(self.token), "<token>", "".join(self.err[-10:]))
        return {"ok": False, "usage": {}, "timeout_or_exit": tail[-500:]}

    def close(self):
        self.proc.kill()
        self.proc.wait()


def captured_form(pp):
    """(session, form) of the pin's only kept body, else (None, None)."""
    with pp._affinity_lock:
        for session, e in pp._affinity_last.items():
            return session, pp._keepalive_form(e[0])
    return None, None


def measure(pp, proxy, seen, scratch, home, token, form):
    env = {"HOME": str(home), "CLAUDE_CONFIG_DIR": os.environ["CLAUDE_CONFIG_DIR"],
           "PATH": os.environ["PATH"], "CLAUDE_CODE_OAUTH_TOKEN": token,
           "HTTPS_PROXY": f"http://127.0.0.1:{proxy.port}",
           "NODE_EXTRA_CA_CERTS": str(proxy._certdir / "ca.pem"),
           "CLAUDE_CODE_PROMPT_CACHE_TTL": "1h",
           "CLAUDE_CODE_TETHER_LIVE": FORM_TETHER[form]}
    work = scratch / "w"
    work.mkdir(exist_ok=True)
    pp._affinity_last.clear()
    pp._affinity_captures.update(kept=0, dropped={})
    pp._affinity_pings.update(sent=0, hit=0, refused={})
    mark = len(seen)
    client = Client(env, str(work), token)
    try:
        session, got = None, None
        for _ in range(4):  # held: turn 1 is a full create, turn 2 held
            last = client.turn()
            session, got = captured_form(pp)
            if got == form or not last["ok"]:
                break
        rec = {"captured": got, "want": form, "P": prefix(last["usage"]),
               "last_turn": last}
        if got != form:
            rec["verdict"] = "FAIL"
            return rec | {"ping": {"status": None, "refused": f"form not captured ({got})",
                                   "usage": {}, "ratelimit": {}},
                          "next": {"ok": False, "usage": {}}, "any_404": None,
                          "util_before": None, "health": health(proxy)}
        ok_before = [s for s in seen[mark:] if 200 <= s["status"] < 300]
        rec["util_before"] = ok_before[-1]["util"] if ok_before else None
        rec["ping"] = probe_ping(proxy, session)
        rec["captured"] = rec["ping"]["form"]  # the body the ping really replayed
        rec["health"] = health(proxy)
        rec["next"] = client.turn()
        rec["any_404"] = any(s["status"] == 404 for s in seen[mark:])
        rec["verdict"] = verdict(rec)
        return rec
    finally:
        client.close()


def self_check(pp, proxy, certdir, token):
    """The arming wiring, the ping path on a canned reply, the verdict."""
    headers = [("Authorization", f"Bearer {token}"), ("x-claude-code-session-id", "SC")]
    body = json.dumps({"model": "m", "system": [{"type": "text", "text": "s",
                       "cache_control": {"type": "ephemeral", "ttl": "1h"}}]}).encode()
    assert pp._affinity_pick(certdir, headers) is None, "client token is the kept one"
    assert pp._affinity_capture(certdir, headers, body, "/v1/messages"), "not armed"
    assert captured_form(pp) == ("SC", "full"), captured_form(pp)
    usage = {"cache_read_input_tokens": 9000, "cache_creation_input_tokens": 0,
             "input_tokens": 1000}
    proxy._keepalive_exchange = lambda *a: (
        200, [("anthropic-ratelimit-unified-5h-utilization", "0.1")],
        json.dumps({"usage": usage}).encode())
    ping = probe_ping(proxy, "SC")
    assert ping["status"] == 200 and ping["refused"] is None and ping["hit"], ping
    h = health(proxy)
    assert h["armed"] and h["captures"]["kept"] == 1 and h["pings"]["sent"] == 1, h
    ok = {"ok": True, "usage": usage}
    rec = {"P": 10000, "ping": ping, "next": ok, "any_404": False,
           "captured": "full", "want": "full"}
    assert verdict(rec) == "PASS" and verdict(rec | {"any_404": True}) == "FAIL"
    assert verdict(rec | {"want": "held"}) == "FAIL"
    assert verdict(rec | {"next": {"ok": True, "usage": {}}}) == "FAIL"
    assert verdict(rec | {"ping": ping | {"status": 400}}) == "FAIL"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scratch", required=True, type=pathlib.Path)
    ap.add_argument("--forms", default="full,held")
    ap.add_argument("--self-check", action="store_true")
    args = ap.parse_args()
    if not sys.platform.startswith("linux"):
        sys.exit("linux only: the login is read from the credentials file")
    scratch = args.scratch.resolve()
    if args.self_check:
        token, expires_ms = "dummy-token", int(time.time() * 1000) + 3600_000
    else:
        token, expires_ms = read_login()
        if expires_ms - time.time() * 1000 < TOKEN_MIN_MS:
            sys.exit("the login expires in under 20 min: refresh it first")
    before = real_state()
    print("rule0 before", before)
    home, certdir = confine(scratch)
    from cswap_pin import proxy as pp  # after confine: the pin reads HOME at start
    proxy, seen = start_pin(pp, certdir, token, expires_ms)
    results = {}
    try:
        if args.self_check:
            self_check(pp, proxy, certdir, token)
        else:
            for form in args.forms.split(","):
                results[form] = measure(pp, proxy, seen, scratch, home, token, form)
                print(table(form, results[form]).replace(token, "<token>"), flush=True)
    finally:
        proxy.stop()
        after = real_state()
        same = before == after
        print("rule0 after", after)
        print("rule0", "IDENTICAL" if same else "CHANGED")
    if args.self_check:
        print("self-check ok")
    else:
        (scratch / "step0.json").write_text(json.dumps(
            {"rule0": {"before": before, "after": after, "identical": same},
             "forms": results}, indent=1, default=str).replace(token, "<token>"))
    sys.exit(0 if same else 1)


if __name__ == "__main__":
    main()
