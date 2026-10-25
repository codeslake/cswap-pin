"""Does a held session's REBUILT create ping keep its cache warm, thread gone or not?

    PYTHONPATH=src <venv python> tools/keepalive_rebuilt.py --scratch <dir> --short
        [--claude <client binary>] [--model <id>] [--chain-port 8118]
    PYTHONPATH=src <venv python> tools/keepalive_rebuilt.py --scratch <dir> --idle 3360
    PYTHONPATH=src <venv python> tools/keepalive_rebuilt.py --scratch <dir> --self-check

WHY THIS EXISTS. A held (`message-threads-`) session's ping used to replay its last
`continue`, which the server always refuses (400 while its ~300 s thread lives, 404
after). The pin now rebuilds the conversation from the replies it relayed and pings
that as a `create` (`rebuilt`). This drives one Claude Code client through a
throwaway pin for three held turns (thinking, a tool call, text), forces the ping
with `_keepalive_ping(session, force_form=True)` (the test-only knob: the tick's
55 min idle rule is skipped, nothing in production is changed), and says PASS when
the ping answered 2xx, read at least 99% of the last real request's prefix P and
created at most 1% of it.

MODES. `--short` pings right after the turns and must finish well inside 300 s (the
deploy rehearsal's bound): every turn is cut at 60 s and the whole run at 240 s,
whichever comes first is NOT MEASURED, never a hang. `--idle N` sleeps N seconds
between the last turn and the ping: 3360 is the 56 min the fix was measured at,
with the server thread gone. The thread is gone either way for the ping, which
carries no thread state.

ONE ACCOUNT. The client and the ping both use the one access token read at start,
so the cache they share is one account's. The account behind it is read from
`/api/oauth/profile` before and after and must be the same; cswap alternates the
ACTIVE login between accounts, so a token read later could belong to another.

EXIT STATUS: 1 when Rule 0 reads CHANGED, else 3 when the run could not judge (no
held session captured, no complete rebuild, a turn failed, the account changed, the
budget ran out), else 2 on a FAIL, else 0. The last line is `REBUILT_PING=<verdict>`.

THE LIVE FLEET IS NOT TOUCHED, as in tools/keepalive_step0.py, whose helpers this
reuses: HOME, CLAUDE_CONFIG_DIR, TMPDIR and the cert dir are under --scratch before
the pin is imported, and the real home's `.claude.json` `env` and `oauthAccount`
(the only keys a pin writes) are hashed before and after.
"""
import argparse
import http.client
import json
import os
import pathlib
import ssl
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import keepalive_step0 as s0  # noqa: E402

SHORT_TURN_S, SHORT_BUDGET_S = 60, 240
HIT, MADE = 0.99, 0.01  # of the last request's prefix
TURNS = ["Think it through, then use the Bash tool to run `echo 221` and say "
         "whether 221 is prime, in one word.",
         "Think carefully: is 223 prime? One word.",
         "Reply with the word ok."]


def account_of(token, chain_port):
    """The account uuid behind ``token`` (GET /api/oauth/profile through the
    egress chain), else a short note of why not."""
    conn = http.client.HTTPSConnection("127.0.0.1", chain_port, timeout=30,
                                       context=ssl.create_default_context())
    conn.set_tunnel("api.anthropic.com", 443)
    try:
        conn.request("GET", "/api/oauth/profile", headers={
            "Authorization": f"Bearer {token}", "anthropic-beta": "oauth-2025-04-20",
            "Content-Type": "application/json", "Accept-Encoding": "identity"})
        r = conn.getresponse()
        body = json.loads(r.read() or b"{}")
        if r.status != 200:
            return f"http {r.status}"
        return (body.get("account") or {}).get("uuid") or "no uuid"
    except Exception as exc:  # noqa: BLE001 (a note, not a failure)
        return f"error {type(exc).__name__}"
    finally:
        conn.close()


def verdict(rec):
    """NOT MEASURED when the run could not judge: it names its `reason`. PASS
    when the ping answered 2xx and read >= 99% of the last request's prefix P
    and created <= 1% of it, else FAIL."""
    if rec.get("reason"):
        return "NOT MEASURED"
    ping, p = rec["ping"], rec["P"]
    u = ping["usage"]
    ok = (ping["status"] is not None and 200 <= ping["status"] < 300 and p > 0
          and u.get("cache_read_input_tokens", 0) >= HIT * p
          and u.get("cache_creation_input_tokens", 0) <= MADE * p)
    return "PASS" if ok else "FAIL"


def table(rec):
    head = f"### rebuilt: {rec['verdict']}" + (
        f" ({rec['reason']})" if rec.get("reason") else "")
    ping = rec.get("ping")
    rows = [("mode", rec["mode"]), ("account (before / after)", rec["account"]),
            ("P, the last request's prefix (tokens)", rec.get("P")),
            ("idle before the ping (s)", rec["idle_s"])]
    if ping:
        u = ping["usage"]
        rows += [("ping status / refused", f"{ping['status']} / {ping['refused']}"),
                 ("ping error body", ping.get("error_body", "-")),
                 ("ping cache_read (>= 99% P)", u.get("cache_read_input_tokens")),
                 ("ping cache_creation (<= 1% P)", u.get("cache_creation_input_tokens"))]
    rows += [("thinking blocks in the session (0: nothing to carry)", rec.get("thinking")),
             ("/health rebuilds", rec.get("rebuilds")),
             ("/health pings by form", rec.get("forms")), ("wall (s)", rec["wall_s"])]
    return "\n".join([head, "", "| row | value |", "|---|---|"]
                     + [f"| {k} | {v} |" for k, v in rows])


def measure(pp, proxy, scratch, home, token, claude, model, mode, idle_s, chain_port):
    """One run. The record holds a `reason` when it could not judge."""
    t0 = time.monotonic()
    short = mode == "short"
    if short:
        s0.TURN_TIMEOUT_S = SHORT_TURN_S
    deadline = t0 + (SHORT_BUDGET_S if short else float("inf"))
    rec = {"mode": mode, "idle_s": 0, "P": 0, "ping": None,
           "account": [account_of(token, chain_port)]}

    def done(reason=None):
        rec["account"].append(account_of(token, chain_port))
        a, b = rec["account"]
        rec["wall_s"] = round(time.monotonic() - t0, 1)
        rec["reason"] = reason or (
            "the account behind the token changed" if a != b and not (
                a.startswith(("http", "error")) or b.startswith(("http", "error")))
            else None)
        rec["verdict"] = verdict(rec)
        return rec

    cfg = os.environ["CLAUDE_CONFIG_DIR"]
    env = {"HOME": str(home), "CLAUDE_CONFIG_DIR": cfg, "TMPDIR": os.environ["TMPDIR"],
           "PATH": os.environ["PATH"], "CLAUDE_CODE_OAUTH_TOKEN": token,
           "HTTPS_PROXY": f"http://127.0.0.1:{proxy.port}",
           "NODE_EXTRA_CA_CERTS": str(proxy._certdir / "ca.pem"),
           "CLAUDE_CODE_PROMPT_CACHE_TTL": "1h", "CLAUDE_CODE_TETHER_LIVE": "1"}
    work = scratch / "w"
    work.mkdir(exist_ok=True)
    client = s0.Client(claude, env, str(work), token, extra_args=(
        "--allowedTools", "Bash(echo:*)", "--effort", "high", "--model", model))
    try:
        last = None
        for prompt in TURNS:
            if time.monotonic() > deadline:
                return done("the run's budget ran out before the last turn")
            last = client.turn(prompt)
            if not last["ok"]:
                return done(f"a turn failed: {last.get('timeout_or_exit', '')[-200:]}")
        rec["P"] = s0.prefix(last["usage"])
        session = None
        end = time.monotonic() + 10  # the relay settles a reply just after the client has it
        while time.monotonic() < end:
            with pp._affinity_lock:
                for sid, e in pp._affinity_last.items():
                    if e[9] == "held" and e[10] is not None and e[10].ready():
                        session = sid
            if session:
                break
            time.sleep(0.1)
        if session is None:
            return done("no held session with a complete rebuild was captured")
        if idle_s:
            time.sleep(idle_s)
        rec["idle_s"] = idle_s
        rec["ping"] = s0.probe_ping(proxy, session)
        rec["thinking"] = s0.scan_transcripts(cfg)[1]
        health = s0.health(proxy)
        rec["rebuilds"], rec["forms"] = health["rebuilds"], health["pings"]["forms"]
        return done()
    finally:
        client.close()


def sse(msg_id, text):
    """A whole streamed reply of one text block."""
    ev = lambda name, d: b"event: %s\ndata: %s\n\n" % (
        name.encode(), json.dumps({"type": name, **d}).encode())
    return b"".join([
        ev("message_start", {"message": {"id": msg_id, "content": []}}),
        ev("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}),
        ev("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": text}}),
        ev("content_block_stop", {"index": 0}), ev("message_stop", {})])


def self_check(pp, proxy, certdir, token):
    """The ping the pin builds from a canned held conversation, and the
    verdict, with no client and no network call."""
    headers = [("Authorization", f"Bearer {token}"), ("x-claude-code-session-id", "SC"),
               ("anthropic-beta", "message-threads-2026-08-12")]
    cc = {"type": "ephemeral", "ttl": "1h"}
    system = [{"type": "text", "text": "s", "cache_control": cc}]

    def body(thread, text, **top):
        return json.dumps({"model": "m", "max_tokens": 9, "thread": thread, **top, "messages": [
            {"role": "user", "content": [{"type": "text", "text": text,
                                          "cache_control": cc}]}]}).encode()

    assert pp._affinity_pick(certdir, headers) is None, "client token is the kept one"
    for thread, text, extra, reply in (
            ({"type": "create"}, "one", {"system": system}, sse("msg_1", "two")),
            ({"type": "continue", "previous_message_id": "msg_1"}, "three", {}, sse("msg_2", "four"))):
        b = body(thread, text, **extra)
        assert pp._affinity_capture(certdir, headers, b, "/v1/messages"), "not kept"
        tee = pp._reply_tee(headers, b, "/v1/messages")
        assert tee is not None, "no tee for an armed held request"
        tee.start(200)
        tee.feed(reply)
        tee.end()
    with pp._affinity_lock:
        entry = pp._affinity_last["SC"]
        assert entry[9] == "held" and entry[10].ready(), (entry[9], entry[10])
    usage = {"cache_read_input_tokens": 9950, "cache_creation_input_tokens": 40,
             "input_tokens": 10}
    sent = []
    proxy._keepalive_exchange = lambda *a: sent.append(a[3]) or (
        200, [], json.dumps({"usage": usage}).encode())
    ping = s0.probe_ping(proxy, "SC")
    req = json.loads(sent[0])
    assert ping["form"] == "rebuilt" and ping["status"] == 200 and ping["hit"], ping
    assert req["thread"] == {"type": "create"} and req["max_tokens"] == 0 and req["stream"] is False, req
    assert [m["content"] for m in req["messages"]] == [
        "one", "two", [{"type": "text", "text": "three", "cache_control": cc}]], req["messages"]
    assert req["system"] == system and "previous_message_id" not in req["thread"], req
    health = s0.health(proxy)
    assert health["pings"]["forms"]["rebuilt"]["sent"] == 1 and health["rebuilds"]["kept"] == 2, health

    rec = {"mode": "short", "idle_s": 0, "P": 10000, "ping": ping, "account": ["a", "a"], "wall_s": 1}
    assert verdict(rec) == "PASS"
    for bad in ({"status": 404}, {"status": None},
                {"usage": {**usage, "cache_read_input_tokens": 9800}},
                {"usage": {**usage, "cache_creation_input_tokens": 150}}):
        assert verdict({**rec, "ping": {**ping, **bad}}) == "FAIL", bad
    assert verdict({**rec, "reason": "no held session"}) == "NOT MEASURED"
    assert "| P, the last" in table({**rec, "verdict": "PASS"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scratch", required=True, type=pathlib.Path)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--short", action="store_true", help="ping at once; finishes inside 300 s")
    mode.add_argument("--idle", type=int, metavar="SECONDS", help="idle this long before the ping")
    mode.add_argument("--self-check", action="store_true")
    ap.add_argument("--claude", help="client binary (default: newest under the claude versions dir)")
    ap.add_argument("--model", default="claude-opus-5-5")
    ap.add_argument("--chain-port", type=int, default=8118, help="the egress chain's port")
    args = ap.parse_args()
    if not sys.platform.startswith("linux"):
        sys.exit("linux only: the login is read from the credentials file")
    if not (args.short or args.idle or args.self_check):
        ap.error("one of --short, --idle, --self-check")
    scratch = args.scratch.resolve()
    if args.self_check:
        token, expires_ms = "dummy-token", int(time.time() * 1000) + 3600_000
    else:
        token, expires_ms = s0.read_login()
        if expires_ms - time.time() * 1000 < s0.TOKEN_MIN_MS + 1000 * (args.idle or 0):
            sys.exit("the login does not outlive the run by 20 min: refresh it first")
        claude = args.claude or s0.newest_client()
        print("client", claude)
    before = s0.real_state()
    print("rule0 before", before)
    home, certdir = s0.confine(scratch)
    from cswap_pin import proxy as pp  # after confine: the pin reads HOME at start
    proxy, _ = s0.start_pin(pp, certdir, token, expires_ms, args.chain_port)
    rec = None
    try:
        if args.self_check:
            self_check(pp, proxy, certdir, token)
        else:
            rec = measure(pp, proxy, scratch, home, token, claude, args.model,
                          "short" if args.short else "idle", args.idle or 0, args.chain_port)
            print(table(rec).replace(token, "<token>"), flush=True)
    finally:
        proxy.stop()
        after = s0.real_state()
        same = before == after
        print("rule0 after", after)
        print("rule0", "IDENTICAL" if same else "CHANGED")
    if args.self_check:
        print("self-check ok")
        sys.exit(0 if same else 1)
    (scratch / "rebuilt.json").write_text(json.dumps(
        {"client": claude, "rule0": {"before": before, "after": after, "identical": same},
         "result": rec}, indent=1, default=str).replace(token, "<token>"))
    print("REBUILT_PING=" + rec["verdict"])
    sys.exit(1 if not same else {"PASS": 0, "FAIL": 2}.get(rec["verdict"], 3))


if __name__ == "__main__":
    main()
