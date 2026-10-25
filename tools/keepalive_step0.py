"""Step 0 of the keep-alive gate: does a ping keep a session's cache warm?

    PYTHONPATH=src <venv python> tools/keepalive_step0.py --scratch <dir> [--forms full,rebuilt]
        [--claude <client binary>] [--chain-port 8118] [--prompt <text>] [--thinking-tokens N]
    PYTHONPATH=src <venv python> tools/keepalive_step0.py --scratch <dir> --no-ping
    PYTHONPATH=src <venv python> tools/keepalive_step0.py --scratch <dir> --self-check

WHY THIS EXISTS AS A SCRIPT. `_KEEPALIVE_FORMS` was empty until it ran: the sender
replays a session's last body (`max_tokens: 0`, `stream: false`) and nothing had
shown that the API accepts it, reads the cache instead of writing it, or leaves
the session's NEXT real request alone (no `thread_not_found` 404, no dropped
thinking). The ping has no trigger from outside the process, so the pin runs
in-process here and `_keepalive_ping(session, force_form=True)` is called
directly. Per ping form (`full`: the whole history; `rebuilt`: a
`message-threads-` session the pin rebuilds as a create, see
tools/keepalive_rebuilt.py for its idle run) it drives one Claude
Code client through a throwaway pin, pings, sends one more real turn, and says
PASS when the ping read the prefix (cache_read >= 0.9 P, cache_creation <=
0.1 P) and the next turn did too (cache_read >= 0.9 P), in the SAME form, with
no 404 after the ping and no `thinking_drop` attachment in the session's
transcript after it. FAIL is a measured failure. NOT MEASURED is a form the
run could not judge: it was never captured, or the recorder saw no 2xx
/v1/messages before or after the ping (blind). The table says whether the
session held any thinking block: a `thinking_drop` count of 0 with none proves
nothing about the drop: `--thinking-tokens N` sets MAX_THINKING_TOKENS=N for the
client (absent = unset) and `--prompt` replaces "reply with the word ok", so a run
can make the session carry thinking blocks.

WHY THE CONTROL EXISTS. `--no-ping` sends the same turns and no ping: each form's
verdict reads CONTROL (it counts as measured) and its table still prints the next
turn's cache_read, form and 404 rows. Measured 2026-10-17, the full form's next
turn read 26746 of P 30274 both with and without a ping (Claude Code's full form
re-creates ~3.5k of the tail every turn), so the absolute 0.9 P rule fails full
regardless of the ping: compare a ping run against the control.

EXIT STATUS: 1 when Rule 0 reads CHANGED, else 3 when any form is NOT MEASURED,
else 0 (a FAIL is a result, not an error, and a CONTROL is measured). The last
line is `FORMS_PASS=<comma list or none>`.

THE THROWAWAY PIN RUNS ITS BACKGROUND SWEEPS, so the live login is used beyond
the ping (first pass ~20 s after start, then every 5 min): `sweep_titles_once`
lists the account's bridges with the live access token and restores or
unarchives only bridges the scratch session registry holds (none);
`sweep_policy_once` reads the account's policy with it and writes
`policy-limits.json` under the scratch CLAUDE_CONFIG_DIR; `_freshen_pin_identity`
reads the profile with it only when the scratch certdir holds a remembered pin
identity (none). The request-path sweep (`sweep_superseded_bridges`, which
closes the account's superseded bridges) fires when a client opens or posts to
a bridge; the measuring client has no Remote Control, and `_should_sweep_bridges`
is switched off here as well. Every write lands under --scratch.

THE LIVE FLEET IS NOT TOUCHED, and the script checks it:
  - HOME, CLAUDE_CONFIG_DIR, TMPDIR and the cert dir are under --scratch BEFORE
    the pin is imported (it reads `.claude.json` for the port to reclaim).
    Nothing is written outside --scratch.
  - The real home's `.claude.json` `env` and `oauthAccount` (the only keys a
    pin writes) are hashed before and after; CHANGED exits non-zero.
  - The ACTIVE login's access token is read in-process and handed to the
    client through its environment only. The JSON `object_hook` drops the
    refresh token while parsing, so none is returned; the access token is
    never printed or written, and the run refuses when it expires in under 20
    min. The active login's 5h/7d meter is shared with every live session, so
    the utilization before/after is context, not a per-ping cost.
  - Affinity is armed by patching `session_affinity_config` and seeding the
    kept slot; the snapshot rebuild and the usage-header recorder (both read
    the store) are switched off, and the slot's bar is 101 so a reply near a
    wall cannot drop the slot the measurement needs.

--self-check starts and stops the throwaway pin with a dummy token and no
client, answers the ping from a canned reply, feeds the recorder canned replies
(a 404 after the ping mark is detected, one before it is not), reaps a fake
client's process group, and makes no network call.
"""
import argparse
import hashlib
import http.client
import json
import os
import pathlib
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from unittest import mock

sys.dont_write_bytecode = True  # nothing outside --scratch, the .pyc files too
REAL_HOME = os.path.expanduser("~")  # home-read
TOKEN_MIN_MS = 20 * 60 * 1000
TURN_TIMEOUT_S = 240
PROMPT = "reply with the word ok"
FORM_TETHER = {"full": "0", "rebuilt": "1"}


def newest_client():
    """The newest binary under the claude versions dir, never the PATH one."""
    vdir = pathlib.Path(REAL_HOME, ".local/share/claude/versions")  # home-read
    best = max(vdir.iterdir(), default=None,
               key=lambda f: [int(n) for n in re.findall(r"\d+", f.name)])
    return str(best) if best else sys.exit(f"no claude binary under {vdir}: pass --claude")


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
    """(access token, expiresAt ms) of the active login. The decoder's hook
    drops every key but those two before it returns the dict."""
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
    tmp = scratch / "tmp"
    for d in (cfg, tmp):
        d.mkdir(parents=True, exist_ok=True)
    os.environ.update(HOME=str(home), CLAUDE_CONFIG_DIR=str(cfg), TMPDIR=str(tmp),
                      XDG_DATA_HOME=str(home / ".local/share"))
    certdir = home / ".local/share/claude-swap/pin-proxy"
    certdir.mkdir(parents=True, exist_ok=True)
    return home, certdir


def start_pin(pp, certdir, token, expires_ms, chain_port):
    """A throwaway pin on an ephemeral port, armed with one kept slot that
    holds ``token``, and a recorder of every /v1/messages reply it relays."""
    pp.session_affinity_config = lambda _certdir: (3600.0, 90.0, "dynamic")
    pp._spawn_usage_header_recorder = lambda fn: None  # no store read or write
    pp.PinProxy._should_sweep_bridges = lambda *a, **k: False  # never close a live bridge
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
    proxy = pp.PinProxy(certdir, lambda: token, chain_proxy=("127.0.0.1", chain_port))
    proxy.start()
    return proxy, seen


def probe_ping(proxy, session):
    """`_keepalive_ping` with the upstream error body captured on a non-2xx."""
    exchanged = []
    orig = proxy._keepalive_exchange

    def wrapped(*a):
        exchanged.append(orig(*a))
        return exchanged[-1]

    proxy._keepalive_exchange = wrapped
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


def window(seen, mark, ping_mark):
    """What the recorder saw of the client's real requests: 2xx counts before
    and after the ping, a 404 only AFTER it (the ping is not relayed)."""
    ok = lambda xs: [s for s in xs if 200 <= s["status"] < 300]
    before, after = seen[mark:ping_mark], seen[ping_mark:]
    return {"ok_before": len(ok(before)), "ok_after": len(ok(after)),
            "any_404": any(s["status"] == 404 for s in after),
            "util_before": ok(before)[-1]["util"] if ok(before) else None}


def scan_transcripts(cfg):
    """(`thinking_drop` attachments, thinking blocks) over the scratch
    transcripts (shape: cache-miss-audit-2026-10-16/A3-cache.md)."""
    drops = thinking = 0
    for f in pathlib.Path(cfg).glob("projects/**/*.jsonl"):
        for line in f.open(errors="replace"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            drops += (r.get("attachment") or {}).get("type") == "thinking_drop"
            content = (r.get("message") or {}).get("content")
            thinking += sum(isinstance(b, dict) and b.get("type") in (
                "thinking", "redacted_thinking") for b in content) \
                if isinstance(content, list) else 0
    return drops, thinking


def verdict(rec):
    """CONTROL when no ping was sent (its 404 row is context, not a FAIL). FAIL
    on a 404 after the ping. NOT MEASURED when the recorder saw no 2xx before or
    after it (blind). Else PASS when the ping read the prefix, the next turn did
    too, in the measured form, with no `thinking_drop`."""
    if rec["any_404"] and rec["ping"]:
        return "FAIL"
    if not (rec["ok_before"] and rec["ok_after"]):
        return "NOT MEASURED"
    if rec["ping"] is None:
        return "CONTROL"
    # shortcut: the 0.9 P rule counts the full form's own tail re-creation as a miss; compare with --no-ping, and make the verdict control-relative when step 0 re-runs.
    p, ping, nxt = rec["P"], rec["ping"], rec["next"]
    pu, nu = ping["usage"], nxt["usage"]
    a = (ping["status"] is not None and 200 <= ping["status"] < 300 and p > 0
         and pu.get("cache_read_input_tokens", 0) >= 0.9 * p
         and pu.get("cache_creation_input_tokens", 0) <= 0.1 * p)
    b = (nxt["ok"] and rec["next_form"] == rec["form"] and not rec["drops"]
         and nu.get("cache_read_input_tokens", 0) >= 0.9 * p)
    return "PASS" if a and b else "FAIL"


def table(form, rec):
    head = f"### {form}: {rec['verdict']}"
    if "ping" not in rec:
        return (f"{head} ({rec['reason']})\n\ncaptured {rec['captured']}, "
                f"last turn {rec['last_turn']}")
    ping, nxt = rec["ping"], rec["next"]
    ping_rows = [] if ping is None else [
        ("ping status / refused", f"{ping['status']} / {ping['refused']}"),
        ("ping error body", ping.get("error_body", "-")),
        ("ping cache_read", ping["usage"].get("cache_read_input_tokens")),
        ("ping cache_creation", ping["usage"].get("cache_creation_input_tokens")),
        ("utilization after (ping)", ping["ratelimit"])]
    vacuous = "" if rec["thinking"] else " (VACUOUS: no thinking block appeared, nothing to drop)"
    rows = [
        ("form captured", rec["captured"]), ("P (tokens)", rec["P"]),
        ("last real turn", rec["last_turn"]),
        ("utilization before (last real turn)", rec["util_before"]), *ping_rows,
        ("next turn ok", nxt["ok"]),
        ("next turn cache_read", nxt["usage"].get("cache_read_input_tokens")),
        ("next request form (must be the captured one)", rec["next_form"]),
        ("404 after the ping", rec["any_404"]),
        ("2xx /v1/messages before / after the ping (0 = recorder blind)",
         f"{rec['ok_before']} / {rec['ok_after']}"),
        ("thinking_drop attachments after the ping", f"{rec['drops']}{vacuous}"),
        ("thinking blocks in the session", rec["thinking"]),
        ("/health captures", rec["health"]["captures"]),
        ("/health pings", rec["health"]["pings"]),
    ]
    return "\n".join([head, "", "| row | value |", "|---|---|"]
                     + [f"| {k} | {v} |" for k, v in rows])


class Client:
    """One `claude -p` stream-json process, in a process group of its own so
    ``close`` takes its children with it: turns on stdin keep its thread."""

    def __init__(self, claude, env, cwd, token, extra_args=()):
        self.token, self.err, self.out = token, [], queue.Queue()
        self.proc = subprocess.Popen(
            [claude, "-p", "--input-format", "stream-json",
             "--output-format", "stream-json", "--verbose", *extra_args],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, cwd=cwd, text=True, start_new_session=True)
        threading.Thread(target=lambda: [self.out.put(l) for l in self.proc.stdout],
                         daemon=True).start()
        threading.Thread(target=lambda: [self.err.append(l) for l in self.proc.stderr],
                         daemon=True).start()

    def turn(self, text=PROMPT):
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
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait()


def captured_form(pp):
    """(session, ping form) of the pin's only kept body, else (None, None)."""
    with pp._affinity_lock:
        for session, e in pp._affinity_last.items():
            return session, pp._ping_form(e)
    return None, None


def await_settle(pp, session, wait_s=10):
    """Wait for ``session``'s rebuild to be ready: the relay settles a reply
    just after the client has it, and a rebuild still awaiting one is not
    pinged."""
    end = time.monotonic() + wait_s
    while time.monotonic() < end:
        with pp._affinity_lock:
            e = pp._affinity_last.get(session)
            if e is not None and e[10] is not None and e[10].ready():
                return True
        time.sleep(0.1)
    return False


def measure(pp, proxy, seen, scratch, home, token, form, claude,
            no_ping=False, prompt=PROMPT, thinking_tokens=None):
    cfg = os.environ["CLAUDE_CONFIG_DIR"]
    env = {"HOME": str(home), "CLAUDE_CONFIG_DIR": cfg, "TMPDIR": os.environ["TMPDIR"],
           "PATH": os.environ["PATH"], "CLAUDE_CODE_OAUTH_TOKEN": token,
           "HTTPS_PROXY": f"http://127.0.0.1:{proxy.port}",
           "NODE_EXTRA_CA_CERTS": str(proxy._certdir / "ca.pem"),
           "CLAUDE_CODE_PROMPT_CACHE_TTL": "1h",
           "CLAUDE_CODE_TETHER_LIVE": FORM_TETHER[form]}
    if thinking_tokens is not None:
        env["MAX_THINKING_TOKENS"] = str(thinking_tokens)
    work = scratch / "w"
    work.mkdir(exist_ok=True)
    pp._affinity_last.clear()
    pp._affinity_captures.update(kept=0, dropped={})
    pp._affinity_pings.update(sent=0, hit=0, refused={})
    mark, scan0 = len(seen), scan_transcripts(cfg)
    client = Client(claude, env, str(work), token)
    try:
        session, got = None, None
        for _ in range(4):  # rebuilt: turn 1 is a create, turn 2 a continue
            last = client.turn(prompt)
            session, got = captured_form(pp)
            if got == form or not last["ok"]:
                break
        rec = {"form": form, "captured": got, "P": prefix(last["usage"]),
               "last_turn": last}
        if got != form:
            return rec | {"verdict": "NOT MEASURED",
                          "reason": f"form never captured (got {got})"}
        if form == "rebuilt" and not await_settle(pp, session):
            return rec | {"verdict": "NOT MEASURED",
                          "reason": "the rebuild never settled its last reply"}
        scan1 = scan_transcripts(cfg)
        rec["ping"] = None if no_ping else probe_ping(proxy, session)
        ping_mark = len(seen)  # a 404 before this mark is not the ping's
        rec["health"] = health(proxy)
        rec["next"] = client.turn(prompt)
        rec["next_form"] = captured_form(pp)[1]
        scan2 = scan_transcripts(cfg)
        rec |= window(seen, mark, ping_mark)
        rec |= {"drops": scan2[0] - scan1[0], "thinking": scan2[1] - scan0[1]}
        rec["verdict"] = verdict(rec)
        return rec
    finally:
        client.close()


def self_check(pp, proxy, certdir, token, seen, scratch):
    """The arming wiring, the ping path on a canned reply, the recorder on
    canned replies, the transcript scan, a client's process group, the verdict."""
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
    assert not proxy._should_sweep_bridges("POST", "/v1/code/sessions"), "bridge sweep armed"

    def reply(status):  # through the pin's own hook, as the relay calls it
        line = f"HTTP/1.1 {status} X".encode()
        pp._note_usage_headers(
            line, [line, b"anthropic-ratelimit-unified-5h-utilization: 0.1"],
            "/v1/messages?beta=true", f"Bearer {token}")

    reply(404)  # the held form's own, before the ping: not the ping's
    reply(200)
    ping_mark = len(seen)
    util = {"anthropic-ratelimit-unified-5h-utilization": "0.1"}
    assert window(seen, 0, ping_mark) == {"ok_before": 1, "ok_after": 0, "any_404": False,
                                          "util_before": util}, seen
    reply(404)  # positive control: a 404 after the ping is seen
    assert window(seen, 0, ping_mark)["any_404"], seen
    assert window([], 0, 0) == {"ok_before": 0, "ok_after": 0, "any_404": False,
                                "util_before": None}

    cfg = pathlib.Path(os.environ["CLAUDE_CONFIG_DIR"])
    (cfg / "projects/p").mkdir(parents=True)
    (cfg / "projects/p/s.jsonl").write_text("\n".join(json.dumps(r) for r in (
        {"type": "attachment", "attachment": {"type": "thinking_drop"}},
        {"type": "assistant", "message": {"content": [{"type": "thinking"}, {"type": "text"}]}},
        {"type": "assistant", "message": {"content": "ok"}})) + "\nnot json\n")
    assert scan_transcripts(cfg) == (1, 1)

    fake = scratch / "fake-claude"  # a client with a child: close takes the group
    fake.write_text('#!/bin/sh\nsleep 300 &\necho $! > "$KID"\nread l\n'
                    'echo \'{"type":"result","is_error":false}\'\nwait\n')
    fake.chmod(0o755)
    kid = scratch / "kid"
    client = Client(str(fake), {"KID": str(kid), "PATH": os.environ["PATH"]},
                    str(scratch), token)
    assert client.turn()["ok"], "fake client"
    pid = int(kid.read_text())
    client.close()
    time.sleep(0.5)
    stat = pathlib.Path(f"/proc/{pid}/stat")
    assert not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] == "Z", \
        "the client's child outlived close()"

    ok = {"ok": True, "usage": usage}
    rec = {"P": 10000, "form": "full", "next_form": "full", "ping": ping, "next": ok,
           "any_404": False, "ok_before": 1, "ok_after": 1, "drops": 0}
    assert verdict(rec) == "PASS"
    for bad in ({"any_404": True}, {"any_404": True, "ok_after": 0},
                {"next": {"ok": True, "usage": {}}}, {"ping": ping | {"status": 400}},
                {"next_form": "held"}, {"next_form": None}, {"drops": 1}):
        assert verdict(rec | bad) == "FAIL", bad
    for blind in ({"ok_before": 0}, {"ok_after": 0}):
        assert verdict(rec | blind) == "NOT MEASURED", blind

    class Stub:  # a client that only answers: every turn is a 2xx the recorder sees
        envs, prompts = [], []

        def __init__(self, claude, env, cwd, token):
            Stub.envs.append(env)

        def turn(self, text):
            Stub.prompts.append(text)
            reply(200)
            return {"ok": True, "usage": usage}

        def close(self):
            pass

    def run(**kw):
        Stub.envs, Stub.prompts, pinged = [], [], []
        fake_ping = lambda *a: pinged.append(a) or ping
        with mock.patch.multiple(sys.modules[__name__], Client=Stub, probe_ping=fake_ping,
                                 captured_form=lambda pp: ("SC", "full")):
            rec = measure(pp, proxy, seen, scratch, scratch, token, "full", "claude", **kw)
        return rec, pinged

    rec, pinged = run(no_ping=True, prompt="say hi", thinking_tokens=5)
    assert not pinged and rec["ping"] is None and rec["verdict"] == "CONTROL", (pinged, rec)
    assert Stub.prompts == ["say hi"] * 2 and Stub.envs[0]["MAX_THINKING_TOKENS"] == "5"
    assert "ping status" not in table("full", rec) and "next turn cache_read" in table("full", rec)
    rec, pinged = run()
    assert len(pinged) == 1 and rec["verdict"] == "PASS", (pinged, rec)
    assert Stub.prompts == [PROMPT] * 2 and "MAX_THINKING_TOKENS" not in Stub.envs[0]
    assert verdict(rec | {"ping": None, "any_404": True}) == "CONTROL"
    assert verdict(rec | {"ping": None, "ok_after": 0}) == "NOT MEASURED"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scratch", required=True, type=pathlib.Path)
    ap.add_argument("--forms", default="full,rebuilt")
    ap.add_argument("--claude", help="client binary (default: newest under the claude versions dir)")
    ap.add_argument("--chain-port", type=int, default=8118, help="the egress chain's port")
    ap.add_argument("--no-ping", action="store_true", help="the control arm: send no ping")
    ap.add_argument("--prompt", default=PROMPT, help="the text of every turn")
    ap.add_argument("--thinking-tokens", type=int, help="MAX_THINKING_TOKENS for the client")
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
        claude = args.claude or newest_client()
        print("client", claude)
    before = real_state()
    print("rule0 before", before)
    home, certdir = confine(scratch)
    from cswap_pin import proxy as pp  # after confine: the pin reads HOME at start
    proxy, seen = start_pin(pp, certdir, token, expires_ms, args.chain_port)
    results = {}
    try:
        if args.self_check:
            self_check(pp, proxy, certdir, token, seen, scratch)
        else:
            for form in args.forms.split(","):
                results[form] = measure(pp, proxy, seen, scratch, home, token, form, claude,
                                        args.no_ping, args.prompt, args.thinking_tokens)
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
            {"client": claude, "rule0": {"before": before, "after": after, "identical": same},
             "forms": results}, indent=1, default=str).replace(token, "<token>"))
        passed = [f for f, r in results.items() if r["verdict"] == "PASS"]
        print("FORMS_PASS=" + (",".join(passed) or "none"))
        if same and any(r["verdict"] == "NOT MEASURED" for r in results.values()):
            sys.exit(3)
    sys.exit(0 if same else 1)


if __name__ == "__main__":
    main()
