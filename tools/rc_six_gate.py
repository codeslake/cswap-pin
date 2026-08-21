#!/usr/bin/env python3
"""The six Remote Control requirements, probed without a human in the loop.

Every one of these was chased for hours with the OWNER as the instrument —
"is it visible on claude.ai now?" — which is slow, wakes him up, and cannot
be repeated after a change. This runs the same questions against the live
fleet from the terminal.

THE AUTH AXIS IS THE PIN ITSELF. Requests go out through the pin daemon,
which swaps the bearer to the pinned account on the RC routes. So nothing
here reads a credential, mints a token, or needs one passed in — the same
trick `test-rc-inbound.sh` uses.

RUN IT FROM THE REPO. This directory is not deployed anywhere — the coupled
pre-commit hook runs these from the checkout, and nothing installs them into
`~/.claude`. So:

    lmd42   python3 ~/dotfiles/dotfiles/claude/tests/cc-wrapper-ccf-cswap/rc_six_gate.py
    macs    python3 ~/Documents/dotfiles/dotfiles/claude/tests/cc-wrapper-ccf-cswap/rc_six_gate.py

I wrote `~/.claude/tests/...` in the commit that added this and it does not
exist on any machine.

THREE VERDICTS, NEVER TWO. PASS / FAIL / UNPROVEN. A probe that could not
run is UNPROVEN and never PASS: today's whole failure mode was instruments
that reported health over a question they had not asked. Where a check has a
control, it runs the control too and downgrades itself if the control is
silent.
"""
from __future__ import annotations

import calendar
import glob
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import typing

HOME = pathlib.Path.home()
# Why `_live_bearer` came back empty, when it did. A probe that cannot
# authenticate has NOT measured the fleet, and the 401 it would collect reads
# exactly like one.
BEARER_WHY = "no credential found in the file or the keychain"
ROWS: list[tuple[str, str, str]] = []


def row(req: str, verdict: str, detail: str) -> None:
    ROWS.append((req, verdict, detail))


def store() -> pathlib.Path:
    for c in (HOME / ".local/share/claude-swap", HOME / ".claude-swap-backup"):
        if (c / "sequence.json").exists():
            return c
    raise SystemExit("no cswap store found")


def pin_port() -> int | None:
    """The port the running pin daemon serves, or None."""
    try:
        rec = json.loads((store() / "pin-proxy/proxy.json").read_text())
        return int(rec.get("port"))
    except (OSError, ValueError, TypeError):
        return None


def _ca() -> str | None:
    """The bundle a session trusts, read from the wiring Claude Code uses.

    The pin MITMs api.anthropic.com with its own CA, so a probe that does not
    trust it fails at TLS and reports http 000 — which reads exactly like the
    network being down. The first run of this gate did precisely that and I
    nearly filed it as a fleet outage; curl's exit 60 is what told the truth.
    """
    try:
        cfg = json.loads((HOME / ".claude.json").read_text())
    except (OSError, ValueError):
        return None
    return ((cfg.get("env") or {}).get("NODE_EXTRA_CA_CERTS")) or None


def _live_bearer() -> str | None:
    """The active account's access token, as every local probe uses it.

    Not the pin's. The pin swaps this for the pinned account's on its own
    routes, so passing the live one is what exercises the swap rather than
    bypassing it.
    """
    try:
        c = json.loads((HOME / ".claude/.credentials.json").read_text())
        tok = (c.get("claudeAiOauth") or {}).get("accessToken")
        if tok:
            return tok
    except (OSError, ValueError, AttributeError):
        pass
    # THE FILE IS NOT THE ONLY STORE. On a mac the credential can live in the
    # KEYCHAIN and nowhere else — measured on one where that file does not
    # exist at all. Reading only the file there sent every probe out with no
    # bearer, and this gate reported "claude.ai cannot be reached from here at
    # all" about a machine whose credential was simply somewhere else. That is
    # the instrument failing, dressed as a fleet fault.
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(
            ["security", "find-generic-password",
             "-s", "Claude Code-credentials", "-w"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        global BEARER_WHY
        # rc=36 IS NOT "no such item" — 44 is. 36 is the ACL refusing an
        # interactive read, which is what an ssh session always gets: the item
        # is right there (a metadata query finds it and names the keychain)
        # and only the SECRET is withheld. Measured on one mac over ssh.
        BEARER_WHY = (
            "the keychain refused the credential to this session "
            f"(security rc={out.returncode}; 36 = ACL, run the gate ON the "
            "machine rather than over ssh)"
            if out.returncode == 36 else
            f"no credential in the file or the keychain (security "
            f"rc={out.returncode})")
        return None
    try:
        c = json.loads(out.stdout.strip())
    except ValueError:
        return None
    return (c.get("claudeAiOauth") or {}).get("accessToken") or None


def api(path: str, port: int, timeout: int = 45):
    """GET through the pin. `(status, body)`, or `(None, reason)` when the
    probe itself could not run — never a status invented for a failure."""
    url = f"https://api.anthropic.com{path}"
    cmd = ["curl", "-s", "-o", "-", "-w", "\n%{http_code} %{exitcode}",
           "--max-time", str(timeout), "--proxy", f"http://127.0.0.1:{port}"]
    ca = _ca()
    if ca:
        cmd += ["--cacert", ca]
    # THE PIN SWAPS A BEARER, IT DOES NOT MINT ONE. Sending no Authorization
    # gets a 401 that looks like an auth failure in the fleet; it is only this
    # probe arriving empty-handed. Hand it the LIVE credential and let the pin
    # replace it with the pinned account's on the routes it owns — which is
    # also what makes this a real test of the swap.
    tok = _live_bearer()
    if not tok:
        # REFUSE, DO NOT GUESS. Sending this without a bearer collects a 401,
        # and a 401 is indistinguishable from a broken fleet — measured: this
        # gate reported "claude.ai cannot be reached from here at all" about a
        # machine whose credential was simply somewhere this probe could not
        # read. An unrunnable probe is UNPROVEN and must say why.
        return None, BEARER_WHY
    cmd += ["-H", f"Authorization: Bearer {tok}"]
    # THE API SAYS WHAT IT NEEDS, so send it rather than reading a 400 as a
    # fleet fault. Without this the gate reported "claude.ai cannot be reached
    # from here at all" about a request the server had received and answered
    # — its body said `anthropic-version: header is required` and carried a
    # request_id, which is proof the whole chain carried.
    cmd += ["-H", "anthropic-version: 2023-06-01"]
    try:
        p = subprocess.run(cmd + [url], capture_output=True, text=True,
                           timeout=timeout + 10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{type(exc).__name__}"
    out = p.stdout.rsplit("\n", 1)
    if len(out) != 2:
        return None, "no status line from curl"
    bits = out[1].split()
    code = int(bits[0]) if bits and bits[0].isdigit() else 0
    cexit = bits[1] if len(bits) > 1 else "?"
    if code == 0:
        # SAY WHY. A bare 0 is indistinguishable from a dead network; curl's
        # own exit code separates TLS (60) from connect (7) from timeout (28).
        return None, (f"curl exit {cexit}"
                      + (" — TLS: the probe does not trust the pin's CA"
                         if cexit == "60" else "")
                      + ("" if ca else "; no NODE_EXTRA_CA_CERTS in the "
                                       "config to trust"))
    return code, out[0]


def live_sessions() -> dict[str, str]:
    """`{sessionId: name}` for sessions whose pid is alive."""
    out = {}
    for f in glob.glob(str(HOME / ".claude/sessions/*.json")):
        try:
            d = json.load(open(f))
            os.kill(int(d["pid"]), 0)
        except Exception:
            continue
        out[str(d.get("sessionId") or "")] = d.get("name") or "?"
    return out


def bridge_pointers() -> list[tuple[str, str]]:
    """`(name, owner)` for every live BACKGROUND session, from its job record.

    Background only, and the key name is why the scope is worth stating rather
    than assuming. Two stores hold this under DIFFERENT spellings —
    `bridgeOwnerAccountUuid` in `~/.claude/jobs/<id>/state.json`,
    `ownerAccountUuid` in the transcript's `bridge-session` record. Reading a
    transcript with the job spelling returns None every time, and an earlier
    note in this file recorded exactly that as a fact about the fleet
    ("every transcript carries bridgeOwnerAccountUuid=None"). It was the
    instrument, not the fleet.

    So an interactive session, whose pointer lives only in the transcript, is
    NOT covered here. That is a real gap and it is deliberate for now: this
    check compares against `~/.claude.json`, and the population it can speak
    for is the one whose owner it can read without guessing a spelling.
    """
    got = []
    for st in glob.glob(str(HOME / ".claude/jobs/*/state.json")):
        try:
            d = json.load(open(st))
        except Exception:
            continue
        if d.get("bridgeOwnerAccountUuid"):
            got.append((d.get("name", "?"), d["bridgeOwnerAccountUuid"]))
    return got


# ---------------------------------------------------------------- 1 RC유지
# The pin's own interpreter. This file runs under the system `python3`, which
# has no cswap_pin — importing it here answered `ModuleNotFoundError` and the
# check went UNPROVEN about a question the pin can answer perfectly well.
_PIN_PY = HOME / ".local/share/uv/tools/claude-swap/bin/python"

_ARREARS_SRC = """
import json
import cswap_pin.proxy as pin
home = pin.require("paths").get_claude_config_home()
out = []
for sid, job in pin._carry_candidates():
    owner = None
    found = pin._last_pointer(sid)
    if found:
        # ownerAccountUuid, NOT bridgeOwnerAccountUuid. The TRANSCRIPT's
        # bridge-session record and the JOB state.json spell this differently,
        # and asking the transcript for the job's spelling returns None every
        # time -- which excluded transcript-only sessions from `owed` entirely,
        # silently exempting them from the one branch of requirement 1 that can
        # FAIL. The job spelling is still used below, for the job record.
        rec = found[1] or {}
        owner = rec.get("ownerAccountUuid") or rec.get("bridgeOwnerAccountUuid")
    if owner is None and job:
        st = pin._read_json(home / "jobs" / str(job) / "state.json")
        owner = (st or {}).get("bridgeOwnerAccountUuid")
    out.append([sid[:8], owner])
print(json.dumps(out))
"""


_STORES_SRC = """
import json
import cswap_pin.proxy as pin
home = pin.require("paths").get_claude_config_home()
out = []
for st in sorted((home / "jobs").glob("*/state.json")):
    try:
        rec = json.loads(st.read_text())
    except (OSError, ValueError):
        continue
    if not rec.get("bridgeOwnerAccountUuid"):
        continue
    sid = rec.get("sessionId") or ""
    found = pin._last_pointer(sid) if sid else None
    t = (found[1] if found else None) or {}
    out.append([rec.get("name", "?"), rec["bridgeOwnerAccountUuid"],
                bool(rec.get("bridgeSessionId")),
                t.get("ownerAccountUuid"), bool(t.get("bridgeSessionId"))])
print(json.dumps(out))
"""


def pointer_stores():
    """Both stores per live background session, because one of them lies.

    `(rows, None)` or `(None, reason)`, each row
    `[name, job_owner, job_has_id, transcript_owner, transcript_has_id]`.

    WHY BOTH. Requirement 1 read the JOB record's owner alone and reported
    every disagreement as risk. Measured on this host, all 13 live records:
    the 9 that name another account carry NO `bridgeSessionId` — and an owner
    with no bridge id beside it cannot be compared against anything, because
    CC's veto (`bt = Boolean(Qe.ownerAccountUuid)`) runs on a pointer it
    hydrated and there is nothing there to hydrate. The correlation is exact
    and it is not recency or version: all 13 are on one cliVersion and the
    creation dates interleave, while id-present matches live-login-owner 13
    of 13.

    Those same 9 sessions have a TRANSCRIPT `bridge-session` record naming the
    live login with a real `cse_` id. That is the half the carry can write:
    `_carry_pointer` refuses any record without `bridgeSessionId`, so the job
    half has never been restamped and the transcript half has.

    Asked through the pin's own `_last_pointer`, not a second reader here —
    the two spellings of the owner field have already cost this file one false
    verdict.
    """
    if not _PIN_PY.exists():
        return None, "the pin's interpreter is not where this expects it"
    try:
        p = subprocess.run([str(_PIN_PY), "-c", _STORES_SRC],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, type(exc).__name__
    if p.returncode != 0:
        return None, (p.stderr.strip().splitlines() or ["no stderr"])[-1][:90]
    try:
        return json.loads(p.stdout), None
    except ValueError:
        return None, "the pin answered something that is not JSON"


def carry_arrears(login_uuid: str):
    """Ended sessions the carry should have restamped and has not.

    `(list_of_ids, None)` or `(None, reason)`. Asks the pin's OWN candidate
    finder, through the pin's OWN interpreter, rather than re-deriving the
    rule here. `_carry_candidates` enumerates job dirs because Claude Code
    garbage-collects the sessions registry, and a census built on the registry
    reported "0 ended sessions" — a population of zero, which discriminates
    nothing. Re-deriving that rule in this file is how the two drift apart.
    """
    if not _PIN_PY.exists():
        return None, "the pin's interpreter is not where this expects it", None
    try:
        p = subprocess.run([str(_PIN_PY), "-c", _ARREARS_SRC],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, type(exc).__name__, None
    if p.returncode != 0:
        return None, (p.stderr.strip().splitlines() or ["no stderr"])[-1][:90], None
    try:
        rows = json.loads(p.stdout)
    except ValueError:
        return None, "the pin answered something that is not JSON", None
    # THE DENOMINATOR TRAVELS WITH THE ANSWER. An empty `owed` used to
    # cover both 'candidates existed and none was owed' and 'there were
    # no candidates', and requirement 1 printed the same sentence for
    # both. `rows` IS the candidate list; it was simply discarded.
    return ([sid for sid, owner in rows
             if owner is not None and owner != login_uuid],
            None, len(rows))


def check_rc_survives() -> None:
    """The config must name the PIN with an accountUuid, and every live
    bridge pointer must match it — that is the comparison Claude Code makes."""
    try:
        cfg = json.loads((HOME / ".claude.json").read_text()).get(
            "oauthAccount") or {}
    except (OSError, ValueError):
        row("1 RC유지", "UNPROVEN", "~/.claude.json unreadable")
        return
    uuid = cfg.get("accountUuid")
    if not uuid:
        row("1 RC유지", "FAIL",
            f"config names {cfg.get('emailAddress')} with NO accountUuid — "
            "CC compares on account uuid AND org uuid, so no bridge can match")
        return
    try:
        st = json.loads((store() / "settings.json").read_text())
        pin = ((st.get("remoteControl") or {}).get("pinnedEmail") or "")
    except (OSError, ValueError):
        pin = ""
    if pin and cfg.get("emailAddress") != pin:
        row("1 RC유지", "FAIL",
            f"config names {cfg.get('emailAddress')}, pin is {pin} — bridges "
            "minted now are owned by the wrong account")
        return
    ptrs = bridge_pointers()
    if not ptrs:
        row("1 RC유지", "UNPROVEN",
            f"config names the pin with an accountUuid, but no live session "
            "carries a bridge pointer — nothing to compare against")
        return
    bad = [n for n, u in ptrs if u != uuid]
    # A STALE POINTER ON A *LIVE* SESSION IS THE STEADY STATE, NOT THE FAULT,
    # and reading it as one made this check fail for hours against a mechanism
    # that was working. Measured, all thirteen live sessions on the linux host:
    #
    #   the owner is in ~/.claude/jobs/<id>/state.json, and 9 of 13 of those
    #   name another account.
    #
    # CORRECTED. This used to add "seven of those nine appear in the pin's own
    # `carry: restamped ...` line, so the carry DID fix them and they went
    # stale again". The carry cannot fix that store at all: `_carry_pointer`
    # returns None on any record without `bridgeSessionId`, and NO job record
    # whose owner is stale has one (measured 9 of 9; the key is ABSENT, not the
    # empty string `clearBridgeSession` writes). The restamps that were logged
    # were the TRANSCRIPT half, which the same function does write. The cited
    # log lines can no longer be re-read either -- the daemon log rotates on
    # size and all three files now hold zero `carry:` lines against 946 lines
    # total, which is the corpus being intact and the record being gone.
    #
    # The carry still writes the login at LAUNCH so CC reattaches instead of
    # vetoing, and CC records the bridge's true server-side owner while it
    # runs, so stale-while-running is the expected shape. The repair lands at
    # the next launch, when the session is ENDED and `_carry_candidates`
    # (bridge + no process) sees it.
    #
    # So the question that can actually fail is about ENDED sessions: those
    # are what the carry claims, and a stale one means it did not run or could
    # not write. `carry_arrears()` asks exactly that.
    owed, why, seen = carry_arrears(uuid)
    if owed is None:
        row("1 RC유지", "UNPROVEN",
            f"config names the pin, but the carry's own candidate list could "
            f"not be read — {why}")
        return
    if owed:
        row("1 RC유지", "FAIL",
            f"{len(owed)} ENDED session(s) still name another account "
            f"({', '.join(owed[:4])}) — the carry is what fixes those before "
            "Claude Code reads them, and it has not")
        return
    # SAY WHICH ZERO IT IS. "no ended session is owed one" covered both a
    # real check and an empty set, and it is the second here: every session on
    # this host is alive, so `_carry_candidates()` yields nothing and the
    # carry's claim has not been tested at all. Reporting that as an
    # examination is the same shape as requirement 3's old PASS-on-a-string.
    carry = (f"and the carry owes nothing to the {seen} ENDED session(s) it "
             f"can see" if seen else
             "and the carry's claim is UNTESTED right now — no session has "
             "ended, so it had no candidate to restamp")
    if not bad:
        row("1 RC유지", "PASS",
            f"config names the pin with accountUuid, all {len(ptrs)} live "
            f"bridge pointers match it, {carry}")
        return
    # AN OWNER WITH NO BRIDGE ID IS NOT A COMPARABLE OWNER, and counting it as
    # one is what made this row report 9 sessions at risk that are not. See
    # `pointer_stores` for the measurement. Split before reporting: the two
    # groups have different meanings and only one of them can fail.
    rows, why2 = pointer_stores()
    if rows is None:
        row("1 RC유지", "WARN",
            f"{len(bad)} of {len(ptrs)} LIVE job records name another account "
            f"({', '.join(sorted(set(bad))[:4])}) — and whether any of them "
            f"carries a bridge id to compare could not be read: {why2}")
        return
    stale = [r for r in rows if r[1] != uuid]
    risky = [r for r in stale if r[2]]
    idless = [r for r in stale if not r[2]]
    covered = [r for r in idless if r[3] == uuid and r[4]]
    if risky:
        row("1 RC유지", "WARN",
            f"{len(risky)} of {len(rows)} live job record(s) name another "
            f"account WITH a bridge id beside it "
            f"({', '.join(sorted(r[0] for r in risky)[:4])}) — that owner is "
            f"comparable, so CC can veto the reattach. {carry}")
        return
    if len(covered) != len(idless):
        loose = [r for r in idless if r not in covered]
        row("1 RC유지", "WARN",
            f"{len(loose)} of {len(rows)} live session(s) have a stale job "
            f"owner with no bridge id AND no transcript pointer naming this "
            f"login ({', '.join(sorted(r[0] for r in loose)[:4])}) — nothing "
            f"on disk would reattach them. {carry}")
        return
    row("1 RC유지", "PASS",
        f"every one of the {len(rows)} live bridge pointer(s) that CC can "
        f"compare names this account: {len(rows) - len(stale)} job record(s) "
        f"match outright, and the other {len(idless)} carry a stale owner "
        f"with NO bridge id beside it — not comparable — while their "
        f"transcript pointer names this login with a real bridge id, "
        f"{carry}. This says the OWNER cannot trigger a veto. If a job record "
        f"with no bridge id ever costs one of those sessions its reattach, "
        f"the fresh bridge wears a server-invented title — which is what "
        f"requirement 2 measures, and it reports none")


def live_bridge_ids() -> dict[str, str]:
    """`{session name: its OWN bridge id}`, from the SESSION REGISTRY.

    THREE stores hold this and only one is current:

        ~/.claude/sessions/<pid>.json     bridgeSessionId   <- this one
        ~/.claude/jobs/<job>/state.json   bridgeSessionId
        transcript `bridge-session` entry bridgeSessionId

    Measured on `ai-inter-session-peer1`: the registry said
    `session_01DLpX38…` and the transcript's NEWEST entry said
    `cse_013sfbS8…`. The server listing contained the first and not the
    second. The registry is what the pin's own `_live_bridge_records()` reads,
    and it is the one that matches the server.

    A first cut read the transcript and made requirement 2 FAIL on a session
    that was fine — a wrong join reported as a fleet fault. The control that
    caught nothing was "is the listing filtering a class?" (13 of 14 listed,
    so no); the alternative it did not exclude was "is MY id the right one".

    NORMALISE THE PREFIX. The registry writes `session_<rest>`, the listing
    and the transcript write `cse_<rest>`. Joining the raw strings would miss
    every session at once — the shape that reads as a fleet outage.

    A session whose id cannot be resolved is simply absent here. The caller
    must skip it, not fail it: unresolvable is not wrong.
    """
    out: dict[str, str] = {}
    names = set(live_sessions().values())
    for path in glob.glob(str(HOME / ".claude/sessions/*.json")):
        try:
            d = json.load(open(path))
        except Exception:
            continue
        bid, name = d.get("bridgeSessionId"), d.get("name")
        if not bid or not name or name not in names:
            continue
        rest = str(bid).split("_", 1)[-1]
        out[name] = f"cse_{rest}"
    return out


# ------------------------------------------------------------ 2 이름복원
def check_names_restored(port: int) -> None:
    """Every LIVE session's bridge must wear that session's own name."""
    st, body = api("/v1/code/sessions?limit=100", port)
    if st != 200:
        row("2 이름복원", "UNPROVEN",
            f"listing failed ({st or body}) — not a verdict about names")
        return
    try:
        items = json.loads(body).get("data") or json.loads(body).get(
            "sessions") or []
    except ValueError:
        row("2 이름복원", "UNPROVEN", "listing was not JSON")
        return
    live = live_sessions()
    if not live:
        row("2 이름복원", "UNPROVEN", "no live session to check a title for")
        return
    titles = {}
    for it in items:
        if isinstance(it, dict):
            titles[str(it.get("id") or it.get("session_id") or "")] = str(
                it.get("title") or it.get("name") or "")
    # ONLY SESSIONS THAT HAVE A BRIDGE CAN HAVE ITS NAME RESTORED.
    # A live session that never enabled Remote Control has no bridge at all,
    # and reporting it as "no bridge under its own name" is the same error
    # this file keeps making elsewhere: a check that cannot tell a failure
    # from an event that never happened. Measured: 16 live sessions, 13 with a
    # pointer, and the two this reported as FAIL were among the three without.
    # The third escaped only because a bridge from an earlier run still
    # carried its title on the server — so the check was not even wrong
    # consistently.
    owners = {n for n, _ in bridge_pointers()}
    # THE SESSION'S OWN BRIDGE, not any bridge wearing the name. This loop
    # used to scan every title in the account and pass on the first equal one.
    # The account carries 72 bridges of which 37 are stale (rc-inbound says so
    # on every run), so a leftover from an earlier run under the same name
    # satisfied the check while the session's CURRENT bridge wore an invented
    # title — exactly the failure this requirement exists to catch. The
    # comment below already recorded it happening once; only the FAIL side had
    # been scoped, and the MATCH side was left matching anything.
    mine = live_bridge_ids()
    wrong = []
    seen = 0
    skipped = []
    for sid, name in live.items():
        if name not in owners or name not in mine:
            skipped.append(name)
            continue
        listed = mine[name] in titles
        title = titles.get(mine[name], "")
        if title and name and title == name:
            seen += 1
        elif name and name != "?":
            # TWO DIFFERENT FACTS, and this file has spent a night on exactly
            # this kind of conflation. "its bridge wears another title" is a
            # naming failure; "its bridge is not in the listing at all" may be
            # a bridge the server reaped, which is not about names.
            wrong.append(name if listed else f"{name} (bridge not listed)")
    # NOTHING TO COMPARE is UNPROVEN; every comparison FAILING is a result.
    # This guard was written for the old any-title join, where zero matches
    # meant the join itself was suspect. Joined on the session's OWN bridge,
    # `seen == 0` with `wrong` non-empty is the precise, checkable statement
    # that every session's bridge wears the wrong title — and swallowing that
    # as UNPROVEN would hide the whole failure this requirement is about.
    if seen == 0 and not wrong:
        row("2 이름복원", "UNPROVEN",
            f"no live session could be joined to its own bridge title "
            f"({len(live)} live, {len(titles)} title(s) listed, "
            f"{len(skipped)} skipped) — nothing was compared")
        return
    if wrong:
        row("2 이름복원", "FAIL",
            f"{seen} matched, but {len(wrong)} live session(s) have no bridge "
            f"under their own name: {', '.join(wrong[:4])}")
        return
    # SAY WHAT WAS EXCLUDED. Narrowing a population silently is how a check
    # starts reporting PASS about fewer and fewer things.
    note = (f" ({len(skipped)} live session(s) have no bridge to name)"
            if skipped else "")
    row("2 이름복원", "PASS",
        f"all {seen} live session name(s) appear as their bridge's "
        f"title{note}")


# -------------------------------------------------------------- 3 재연결
def _rc_watch_dir() -> pathlib.Path:
    """Where rc_watch keeps its per-host cursors. One resolver, so a test can
    point it somewhere and both counts move together."""
    return HOME / "workspace/cswap/experiments/monitors/.rc_watch"


def _rc_watch_count(suffix: str) -> int:
    """How many events of one kind rc_watch has recorded, across all hosts.

    Absent files count 0, which is right here: rc_watch writes them on its
    first cycle, so a missing one means it has not run rather than that
    something is wrong. The caller must not read 0 as "the fleet is healthy" —
    that is exactly the conflation this file keeps having to undo.
    """
    n = 0
    for f in glob.glob(str(_rc_watch_dir() / f"*.{suffix}")):
        try:
            n += len([x for x in open(f).read().splitlines() if x.strip()])
        except OSError:
            pass
    return n


def check_reconnect_possible(binary: pathlib.Path | None) -> None:
    """The transport must have a path back from its terminal state.

    `connect()` returns immediately unless state is idle/reconnecting, and
    exhausting the retry budget sets closed+exhaustedBudget. A public
    `reconnect()` that clears both is what makes /remote-control able to
    recover at all. Static, and it says so.
    """
    if binary is None:
        row("3 재연결", "UNPROVEN", "no Claude Code binary found to read")
        return
    try:
        data = binary.read_bytes()
    except OSError:
        row("3 재연결", "UNPROVEN", "binary unreadable")
        return
    have_reset = b"[SessionsV2Client] Force reconnect" in data
    have_budget = b"exhaustedBudget" in data
    if not (have_reset and have_budget):
        row("3 재연결", "FAIL",
            "the transport's reset path is gone from this build "
            f"(force-reconnect={have_reset}, exhaustedBudget={have_budget}) — "
            "a dropped session cannot come back without a new process")
        return
    # THE LIVE HALF DECIDES. The strings above are in the binary whether or
    # not reconnect WORKS, so a PASS resting on them alone is a verdict this
    # check can never fail to produce. It used to do exactly that, and the
    # state it hid is the one requirement 3 is about: sessions torn off Remote
    # Control with none of them coming back still printed PASS.
    backs = _rc_watch_count("back")
    discos = _rc_watch_count("disco")
    if backs:
        row("3 재연결", "PASS",
            f"the reset path is present in {binary.name} and rc_watch has "
            f"recorded {backs} reconnect(s) — a session that was torn off got "
            f"a bridge again in the same process ({discos} disconnect(s) seen)")
    elif discos:
        row("3 재연결", "WARN",
            f"{discos} session(s) were torn off Remote Control and rc_watch "
            f"has recorded 0 coming back. The reset path is present in "
            f"{binary.name}, so this is not a missing mechanism — either the "
            "recovery is not happening or those sessions exited before it "
            "could. WARN, not FAIL: rc_watch only counts a reconnect in the "
            "SAME process, so a session that ended cannot show one")
    else:
        # The cron rule grants "no event to observe" a pass. It applies HERE
        # and only here — nothing was torn off, so nothing could come back.
        row("3 재연결", "UNPROVEN",
            f"the reset path is present in {binary.name} and nothing has been "
            "torn off Remote Control to recover from (0 disconnects, 0 "
            "reconnects) — the mechanism is there and the event is unobserved")


# ---------------------------------------------------------- 4 이미지첨부
def _daemon_log_text(log: pathlib.Path) -> "str | None":
    """The daemon log AND its rotated siblings, oldest first. None if unreadable.

    THE ROTATION IS THE POINT. The pin rotates this file through `.1` and `.2`
    ON SIZE, so a busy hour is what moves the evidence out of the live file --
    and a reader scoped to the live file alone goes quiet exactly when there is
    most to report. Measured: the live log held 0 slow-request lines while
    `daemon.log.1` held 168, 18 of them inside the window, and requirement 6
    read PASS with nothing about the network having changed.

    Siblings are enumerated from the DIRECTORY and filtered on a numeric
    suffix, never matched from a list of names: the depth belongs to the
    producer and a hardcoded pair goes stale silently. `iterdir` rather than
    `glob` because glob swallows scan errors.

    One implementation, because every reader of this log needs it -- the
    slow-request census and the deaf-bridge history both do.
    """
    def _rank(p):
        tail = p.name.rsplit(".", 1)[-1]
        return int(tail) if tail.isdigit() else 0
    try:
        rotated = sorted(
            (p for p in log.parent.iterdir()
             if p.name.startswith(log.name + ".")
             and p.name[len(log.name) + 1:].isdigit()),
            key=_rank, reverse=True)
    except OSError:
        rotated = []
    texts = []
    for p in [*rotated, log]:
        try:
            texts.append(p.read_text(errors="replace"))
        except OSError:
            continue
    return "\n".join(texts) if texts else None


_BRIDGE_TAG = "[claude.ai -> cli]"


def bridged_attachments() -> list[tuple[str, str]]:
    """`(timestamp, media_type)` for claude.ai attachments seen in transcripts.

    WHERE THEY ACTUALLY LAND, which is not where this row used to look. A
    claude.ai attachment is NOT an image block in `message.content` — it
    arrives as its own record::

        {"type": "attachment",
         "attachment": {"type": "queued_command",
                        "prompt": [{"type": "image", "source": {...}},
                                   {"type": "text", "text": "..."}],
                        "origin": {"kind": "human"}}}

    So the census that reported "no attachment has ever arrived" was scoped to
    a record type that cannot hold one.

    AND THERE IS NO STRUCTURAL FIELD TO KEY ON. Compared field by field
    against a locally supplied image in the same session: `entrypoint`,
    `attachment.type`, `attachment.origin.kind`, `sessionKind`, `userType`
    and `version` are IDENTICAL, and everything else that differs (uuids,
    timestamps, cwd) differs between any two messages. `entrypoint` in
    particular is session-level -- 'cli' on all 201,208 records of a session
    that HAS received one -- so the detector this row previously proposed
    could never have worked.

    What is left is the tag the SENDER writes into the message. It appears in
    neither this fleet's code nor the CC binary (2.1.237 and 2.1.238 both
    grep zero), so it is typed by hand and this row can only ever confirm a
    LABELLED arrival. That is a real positive -- it cannot pass without one
    in the corpus -- but it is not automatic detection, and the row says so
    rather than implying the absence of a tag means the absence of an
    attachment.
    """
    out = []
    for t in sorted(glob.glob(str(HOME / ".claude/projects/*/*.jsonl"))):
        try:
            text = _transcript_tail(t)
        except OSError:
            continue
        if _BRIDGE_TAG not in text:
            continue
        for line in text.splitlines():
            # THE TAG IS THE FILTER, and the record is then PARSED. An earlier
            # draft also pre-matched the raw substring `"type":"image"`, which
            # happens to be how Claude Code writes it today and is not how
            # `json.dumps` does — so the function worked on live data and
            # returned nothing for any JSON with spaces after its separators.
            if _BRIDGE_TAG not in line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            a = rec.get("attachment") or {}
            for b in a.get("prompt") or []:
                if isinstance(b, dict) and b.get("type") == "image":
                    out.append((rec.get("timestamp", "?"),
                                (b.get("source") or {}).get("media_type", "?")))
    return out


def _transcript_tail(path: str, limit: int = 6_000_000) -> str:
    """The last `limit` bytes of a transcript, cut at a line boundary.

    NEVER `open(path).read()` HERE. Measured on the linux host: 4 of the 12
    newest transcripts are over 50MB and the largest is 394MB, so a whole-file
    read allocated most of a gigabyte on every run of a ten-minute cron.

    The tail is also the right window rather than a concession: a reference
    that appears only in the first megabyte of a 394MB transcript is months
    old, and none of the questions this gate asks are about months ago.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > limit:
                fh.seek(size - limit)
                fh.readline()  # drop the partial line the seek landed in
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def check_attachment(port: int) -> None:
    """Fetch a real attachment through the pin.

    THE ROUTE IS PINNED because the file belongs to the pinned account. A
    non-200 is what Claude Code renders as "could not be downloaded".
    """
    fid = None
    for t in sorted(glob.glob(str(HOME / ".claude/projects/*/*.jsonl")),
                    key=os.path.getmtime, reverse=True)[:12]:
        blob = _transcript_tail(t)
        if not blob:
            continue
        # A REAL UUID, 8-4-4-4-12. A loose `[0-9a-f-]{8,}` scraped
        # `8f14e45f-ea` — a FIXTURE out of my own attachment test, which had
        # been written into a transcript. The server said so exactly
        # ("expected 5 groups, found 2") and the gate reported it as an
        # unexplained 400 against the fleet.
        m = re.search(r"/api/oauth/files/([0-9a-f]{8}-[0-9a-f]{4}-"
                      r"[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", blob)
        if m:
            fid = m.group(1)
            break
    if not fid:
        # THIS SILENCE IS NOT "NO ATTACHMENT ARRIVED", and the old wording
        # said so, which let a cron rule grant the "nothing to observe"
        # exemption on a premise nobody had checked.
        #
        # Measured across all 4095 transcripts on the linux host, one pass,
        # excluding this session's own (which holds whatever the
        # investigation printed):
        #
        #     /api/oauth/files/<uuid>     0 files   <- what this greps
        #     "type":"image"             67 files
        #     "media_type":"image/       67 files
        #
        # Images DO reach transcripts — inline, as base64 content blocks —
        # and the fetch URL is never written down. So this detector keys on a
        # shape that cannot appear and can never PASS.
        #
        # Keying on `"type":"image"` instead would be WRONG: a local `Read` of
        # a PNG produces the same block, so it would report a claude.ai
        # attachment on evidence of a local file. A correct detector has to
        # establish BRIDGE ORIGIN, which needs one real claude.ai attachment
        # to look at first.
        # AND NO ATTACHMENT HAS EVER ARRIVED, which is a different fact from
        # the one above and the better one. Measured across every transcript
        # on the linux host, this session's own excluded:
        #
        #     image blocks in a human message   84
        #     entrypoint on those records       "cli", and NOTHING else
        #     with imagePasteIds (a paste)      31
        #     without                           53, all on builds predating
        #                                       the key (2.1.126 … 2.1.220)
        #
        # One distinct entrypoint. Every image on this box was typed or pasted
        # at a terminal; not one came through a bridge. So the cron rule's
        # exemption — "no event to observe is not a defect" — genuinely
        # applies here, rather than being granted on an unchecked premise.
        #
        # CORRECTED, BY AN ATTACHMENT THAT ARRIVED. This block used to name
        # `entrypoint` as the field a correct detector keys on. It cannot be:
        # it is SESSION-level, and it read 'cli' on all 201,208 records of a
        # session that had just received one. The census above was also
        # looking in the wrong record type — see `bridged_attachments`, which
        # is where they actually land, and which found no structural field
        # separating a bridged image from a local one.
        seen = bridged_attachments()
        if seen:
            when, media = seen[-1]
            row("4 이미지첨부", "PASS",
                f"{len(seen)} claude.ai attachment(s) reached a transcript "
                f"here and were read; newest {media} at {when}. The record "
                f"is type=attachment / queued_command with the bytes inline "
                f"as base64 — NOT an image block in message.content, which "
                f"is why the earlier census reported none. Keyed on the "
                f"sender's own '{_BRIDGE_TAG}' tag, because no structural "
                f"field distinguishes it: entrypoint, attachment.type, "
                f"origin.kind, sessionKind, userType and version are all "
                f"identical to a locally supplied image")
            return
        row("4 이미지첨부", "UNPROVEN",
            f"no attachment tagged '{_BRIDGE_TAG}' is in any transcript here. "
            "That is the ONLY handle there is — compared field by field, a "
            "bridged image and a local one are identical (entrypoint is "
            "session-level and reads cli for both), so an untagged arrival "
            "would be invisible. Absence of the tag is therefore not "
            "evidence of absence, and this row stays UNPROVEN rather than "
            "claiming a clean fleet. (The fetch probe above greps "
            "/api/oauth/files/<uuid>; the bytes arrive inline, so that URL "
            "is never written down)")
        return
    st, _ = api(f"/api/oauth/files/{fid}/content", port)
    if st == 200:
        row("4 이미지첨부", "PASS",
            f"fetched attachment {fid[:8]} through the pin (200)")
    elif st in (403, 404):
        row("4 이미지첨부", "FAIL",
            f"attachment {fid[:8]} returned {st} — {'the swap was refused' if st == 403 else 'not this account s file'}; "
            "the user sees 'could not be downloaded'")
    else:
        row("4 이미지첨부", "UNPROVEN",
            f"attachment fetch answered {st} — neither success nor a known "
            "failure")


# ------------------------------------------------------- 5 양방향통신
def _as_of(age_min: float | None) -> str:
    """The age of the observation, always printed. A verdict without one
    cannot be judged by its reader — which is how a 99-minute-old line was
    read as the current state of the fleet."""
    return "" if age_min is None else f" (as of {age_min:.0f} min ago)"


def _line_age_min(line: str) -> float | None:
    """Minutes since a daemon-log line was written, or None if unstamped.

    timegm, like `_pin_slow_records` — the stamp is UTC and the mktime pair
    this file used once read it as local, which put every window an hour out.
    One arithmetic, one place.
    """
    m = re.match(r"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)Z\]", line)
    if not m:
        return None
    try:
        when = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None
    return (time.time() - when) / 60.0


def check_bidirectional(port: int) -> None:
    """Outbound is proven by the listing succeeding through the pin; inbound
    by the daemon's own held-stream report, which is the only thing that can
    see a stream it holds."""
    st, why = api("/v1/code/sessions?limit=1", port)
    out_ok = st == 200
    log = store() / "pin-proxy/daemon.log"
    verdict, n, age_min, wrote_pid = None, 0, None, None
    try:
        for ln in reversed(log.read_text(errors="replace").splitlines()):
            if "every posting bridge holds an inbound stream" in ln:
                verdict = True
                m = re.search(r"\((\d+) posting\)", ln)
                n = int(m.group(1)) if m else 0
            elif "post but hold no inbound stream" in ln:
                verdict = False
                m = re.search(r"(\d+) of (\d+) bridge", ln)
                n = int(m.group(1)) if m else 0
            elif "cannot say whether any bridge is deaf" in ln:
                verdict = "mute"
            else:
                continue
            age_min = _line_age_min(ln)
            m = re.search(r"pid=(\d+)", ln)
            wrote_pid = m.group(1) if m else None
            break
    except OSError:
        pass
    # THE DAEMON THAT IS SERVING NOW, from the record the pin itself keeps.
    try:
        rec = json.loads((store() / "pin-proxy/proxy.json").read_text())
        live_pid = str(rec.get("pid") or "") or None
    except (OSError, ValueError):
        live_pid = None
    # AGE IS THE WRONG TEST, and a two-hour bound here was wrong for an hour
    # tonight before this replaced it. `_report_deaf_bridges` says so in its
    # own docstring — "Transitions only … the event is the set changing" — and
    # returns early when the set is unchanged. SILENCE MEANS UNCHANGED. A
    # 129-minute-old verdict from a daemon that is still running means nothing
    # went deaf in 129 minutes, and the bound reported that healthy fleet as
    # UNPROVEN every ten minutes.
    #
    # The "cadence" that justified the bound was not one either: 15 verdicts
    # over ~7h, median gap 34 min, max 74 — those are intervals between
    # CHANGES, and a long gap is stability.
    #
    # WHAT DOES MAKE IT STALE is the daemon that wrote it being gone: a
    # successor keeps its own `_last_deaf`, has not spoken yet, and its
    # silence says nothing about anything.
    #
    # AND SILENCE ALSO COVERS "NEVER RE-ASKED", which is why the line below
    # says so rather than leaving the age to speak. The sweep has ONE call
    # site, gated on session-lifecycle events — a bridge create, or an
    # attached session posting. It is not a timer: a live trace of 2132
    # requests across 13 attached sessions caught zero of either, so the
    # verdict can be arbitrarily old without anything having re-checked it.
    # Outbound IS measured now; the two halves of this row do not have the
    # same freshness and must not read as if they do.
    if verdict is not None and wrote_pid and live_pid \
            and wrote_pid != live_pid:
        row("5 양방향통신", "UNPROVEN",
            f"outbound {'200' if out_ok else st} through the pin, but the "
            f"inbound verdict was written by pid {wrote_pid}, replaced since "
            f"by pid {live_pid}. The report is transition-only, so a "
            "successor's silence is not a verdict — it has not spoken yet"
            f"{_as_of(age_min)}")
        return
    if st is None:
        # THE PROBE DID NOT RUN. `api` returns None for a status only when it
        # could not ask; that is not a verdict about the fleet.
        row("5 양방향통신", "UNPROVEN", f"outbound not probed — {why}")
        return
    if not out_ok:
        row("5 양방향통신", "FAIL",
            f"outbound through the pin answered {st} — claude.ai cannot be "
            "reached from here at all")
        return
    if verdict is True:
        row("5 양방향통신", "PASS",
            f"outbound 200 through the pin, measured now; inbound is the "
            f"daemon's last verdict — all {n} posting bridge(s) held a "
            f"stream{_as_of(age_min)}, re-asked only when a session starts "
            "or posts, never on a timer")
    elif verdict is False:
        row("5 양방향통신", "FAIL",
            f"outbound 200, but {n} bridge(s) post and hold no inbound "
            f"stream — messages reach the server and never come back"
            f"{_as_of(age_min)}")
    elif verdict == "mute":
        row("5 양방향통신", "UNPROVEN",
            "outbound 200, but the daemon says it cannot see what its "
            "draining predecessors hold")
    else:
        row("5 양방향통신", "UNPROVEN",
            "outbound 200; no inbound verdict in the daemon log yet")


# --------------------------------------------------------- 6 팝업제거
def _pin_slow_records(since_s: float = 3600.0) -> list[tuple[str, str]]:
    """(utc_stamp, text) for what the PIN ITSELF recorded about slow requests, from its own log.

    A probe only sees the moment it runs, and the stall is intermittent: 600
    samples on a mac gave p50 311ms and exactly three over 2.4s, all inside
    one two-minute window. A five-probe check of that population is a coin
    flip in both directions. cswap-pin >= 0.1.149 writes a line when a round
    trip crosses 1.5s, so the log is the record that survives between runs.

    An absent or unreadable log yields nothing, which is not the same as a
    log that recorded nothing — the caller must not read [] as "quiet".
    """
    # THROUGH `store()`, NEVER A LITERAL. The certdir is
    # ~/.local/share/claude-swap on the linux host and ~/.claude-swap-backup
    # on the Macs; a hardcoded one reads as an empty log on the other half of
    # the fleet, and this check would report that as quiet.
    try:
        log = store() / "pin-proxy/daemon.log"
    except SystemExit:
        return []
    text = _daemon_log_text(log)
    if text is None:
        return []
    cutoff = time.time() - since_s
    out = []
    for line in text.splitlines():
        if "a live view times out on stalls like this" not in line:
            continue
        m = re.match(r"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)Z\]", line)
        if not m:
            continue
        try:
            # timegm, NOT mktime. The stamp is UTC; mktime reads a struct as
            # LOCAL, and `- time.timezone` does not undo it because that
            # constant ignores DST. The pair was off by exactly one hour here,
            # which pushed every RECENT line out of the window and made this
            # report "no slow request in the last hour" while the daemon was
            # writing one every ninety seconds. A clock bug that leans one way
            # is a check that only ever fires when nothing is wrong.
            when = calendar.timegm(
                time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            continue
        if when >= cutoff:
            out.append((m.group(1), line.split("] ", 1)[-1]))
    return out


def pin_slow_lines(since_s: float = 3600.0) -> list[str]:
    """The recorded lines alone. Prefer `pin_slow_events` — see SlowEvent."""
    return [text for _, text in _pin_slow_records(since_s)]


def slow_reporter_armed() -> bool:
    """Is the pin actually writing slow-request lines on this machine?

    `slow_report_ms()` in the pin says it plainly — "OFF UNTIL SOMEONE ASKS."
    No `remoteControl.debugSlowMs` and no `CSWAP_PIN_SLOW_MS` means no line is
    ever written, so an empty log is the SWITCH being off and not the fleet
    being quiet. Requirement 6's whole subject is an intermittent tail; a row
    that cannot tell those apart reports a machine as clean for the one reason
    that proves nothing.

    Not academic: the setting is armed on the linux host and is not in the
    committed dotfiles, so both Macs are in exactly that state.

    The env override is checked FIRST because it arms the reporter without
    touching settings — reading settings alone would call an armed reporter
    disarmed, which is this same conflation with the sign flipped.
    """
    if os.environ.get("CSWAP_PIN_SLOW_MS"):
        return True
    try:
        st = json.loads((store() / "settings.json").read_text())
    except (OSError, ValueError, SystemExit):
        return False
    return bool((st.get("remoteControl") or {}).get("debugSlowMs"))


class SlowEvent(typing.NamedTuple):
    """One recorded slow round trip, and how many it stands for.

    `events` is 1 plus whatever the pin suppressed behind it. The pin emits at
    most one of these lines a minute and folds the rest into "; N more in the
    last minute", so COUNTING LINES IS BOUNDED AT 60/HOUR however bad the hour
    is, and it also falls whenever the reporter happens to be quiet for
    reasons that have nothing to do with the stall.

    Measured 2026-08-20 on this log: 85 lines before a change and 6 after,
    which read exactly like a fix. The events were 134 and 22.
    """

    stamp: str
    ms: float
    events: int


_SLOW_MS = re.compile(r"took (\d+)ms")
_SLOW_MORE = re.compile(r"; (\d+) more in the last minute")


def pin_slow_events(since_s: float = 3600.0) -> list[SlowEvent]:
    """`pin_slow_lines` with the suppressed siblings counted, and timestamps.

    Report events with their timestamps rather than a rate: a rate needs a
    stationary process, and this one swings two orders of magnitude inside an
    hour (5-minute buckets from 12/h to 1320/h on an unchanged fleet). A
    before/after ratio taken from it retracted twice in one night, on both
    sides of the investigation.

    An absent or unreadable log yields nothing, which is NOT the same as a log
    that recorded nothing — same caveat as `pin_slow_lines`, which this reuses
    so the window arithmetic has exactly one implementation.
    """
    out = []
    for stamp, text in _pin_slow_records(since_s):
        ms = _SLOW_MS.search(text)
        if not ms:
            continue
        more = _SLOW_MORE.search(text)
        out.append(SlowEvent(stamp, float(ms.group(1)),
                             1 + (int(more.group(1)) if more else 0)))
    return out


# Enough samples that a tail of a few percent is characterised rather than
# gambled on. Measured on a mac: 3 of 600 round trips crossed 2.4s, so five
# probes miss it ~97 times in 100 and FAIL the whole fleet on the other three.
_STALL_PROBES = 20
_STALL_WARN_MS = 1500.0
_STALL_FAIL_MS = 5000.0


DEAF_PHRASE = "post but hold no inbound stream"
CLEAR_PHRASE = "every posting bridge holds an inbound stream"
MUTE_PHRASE = "cannot say whether any bridge is deaf"


def deaf_transitions() -> list[tuple[str, str]]:
    """`(utc_stamp, kind)` for every inbound-stream transition on record.

    THE POPUP FOLLOWS A LOST EAR, NOT A SLOW REQUEST. This row used to be
    driven by round-trip latency over 1500ms, and that metric is now
    falsified for this purpose: through a ten-hour window in which the pin
    logged slow round trips at 60-80 an hour, a person watching claude.ai
    reported no disconnect popup at all. Latency was crying wolf on a fleet
    that was, by the requirement's own subject, healthy.

    What DOES map to the popup is a bridge that posts and holds no inbound
    stream — the web view has nothing to receive on. The pin already writes
    that, on CHANGE, so each line is a transition rather than a sample.

    No window: the question this row answers is "has it STAYED good", so the
    whole record is the evidence and the caller decides what recency means.
    """
    try:
        log = store() / "pin-proxy/daemon.log"
    except SystemExit:
        return []
    text = _daemon_log_text(log)
    if text is None:
        return []
    out = []
    for line in text.splitlines():
        kind = (CLEAR_PHRASE if CLEAR_PHRASE in line else
                DEAF_PHRASE if DEAF_PHRASE in line else
                MUTE_PHRASE if MUTE_PHRASE in line else None)
        if kind is None:
            continue
        m = re.match(r"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)Z\]", line)
        if m:
            out.append((m.group(1), kind))
    out.sort()
    return out


def check_no_stall(port: int) -> None:
    """Has any bridge LOST its inbound stream? That is what the popup follows.

    The browser's message is the web client's own and nothing local can
    observe it. The closest local fact is not latency — see
    `deaf_transitions` for why that was retired as the verdict — it is the
    pin's own record of a bridge that posts and holds no ear. Latency stays
    in the line as CONTEXT, clearly not the verdict.
    """
    lat = []
    for _ in range(_STALL_PROBES):
        t = time.perf_counter()
        st, _ = api("/v1/code/sessions?limit=1", port, timeout=30)
        dt = (time.perf_counter() - t) * 1000
        if st == 200:
            lat.append(dt)
    # EVENTS WITH TIMESTAMPS, never a count and never a rate. The pin emits at
    # most one of these lines a minute, so a line count tops out at 60/hour
    # however bad the hour is; and the underlying process is not stationary
    # enough for a rate to mean anything — 5-minute buckets on an unchanged
    # fleet ran from 12/h to 1320/h, and before/after ratios taken from it were
    # retracted on both sides of the investigation. A worst case with the
    # instant it happened can be checked against a deploy, a peer's probe
    # window, or an outage. A rate cannot.
    logged = pin_slow_events()
    # AN EMPTY LOG HAS TWO CAUSES and only one of them is good news. The pin's
    # slow-request report is off unless `remoteControl.debugSlowMs` is set, so
    # on a machine without it there is nothing to find and the row would read
    # as a clean fleet — on the one requirement whose subject is a tail that
    # only shows up sometimes.
    if not logged and not slow_reporter_armed():
        over = sum(1 for x in lat if x > _STALL_WARN_MS)
        row("6 팝업제거", "UNPROVEN",
            f"{len(lat)} probe(s) answered, {over} over "
            f"{_STALL_WARN_MS:.0f}ms — but the pin's slow-request report is "
            "NOT ARMED on this machine (remoteControl.debugSlowMs unset, "
            "CSWAP_PIN_SLOW_MS unset), so its log is silent by configuration "
            "rather than by health. A 20-probe window cannot characterise an "
            "intermittent tail on its own; arm the report to make this row "
            "mean anything")
        return
    if logged:
        w = max(logged, key=lambda e: e.ms)
        tail = (f"; the pin recorded {sum(e.events for e in logged)} slow "
                f"round trip(s) in the last hour across {len(logged)} log "
                f"line(s), worst {w.ms:.0f}ms at {w.stamp}Z")
    else:
        tail = ""
    if lat:
        lat.sort()
        med, worst = lat[len(lat) // 2], lat[-1]
        ctx = (f" [context, not the verdict: median {med:.0f}ms, worst "
               f"{worst:.0f}ms{tail}]")
    else:
        ctx = f" [context, not the verdict: no probe answered{tail}]"

    # THE VERDICT IS THE LOST EAR. A bridge that posts and holds no inbound
    # stream is the state a live claude.ai view has nothing to receive on;
    # a 1500ms round trip is not, and reporting it as one kept this row WARN
    # through ten hours that the person watching the browser called stable.
    trans = deaf_transitions()
    if not trans:
        row("6 팝업제거", "UNPROVEN",
            "the pin has recorded no inbound-stream verdict at all, so "
            "nothing here has been evaluated — an empty record is not a "
            f"quiet fleet{ctx}")
        return
    recent = [t for t in trans if (_line_age_min(f"[{t[0]}Z]") or 1e9) <= 60]
    deaf_recent = [t for t in recent if t[1] == DEAF_PHRASE]
    if deaf_recent:
        row("6 팝업제거", "FAIL",
            f"{len(deaf_recent)} bridge(s) lost their inbound stream in the "
            f"last hour (newest {deaf_recent[-1][0]}Z) — that is the state a "
            f"live view shows the disconnect popup for{ctx}")
        return
    last_deaf = [t for t in trans if t[1] == DEAF_PHRASE]
    since = (f"none since {last_deaf[-1][0]}Z" if last_deaf
             else f"none in the whole record, which starts {trans[0][0]}Z")
    row("6 팝업제거", "PASS",
        f"no bridge has lost its inbound stream in the last hour — {since}, "
        f"across {len(trans)} transition(s) on record. This is the state the "
        f"popup follows, so a regression shows up here{ctx}")


def newest_binary() -> pathlib.Path | None:
    vs = []
    for p in glob.glob(str(HOME / ".local/share/claude/versions/*")):
        b = pathlib.Path(p)
        if re.fullmatch(r"\d+\.\d+\.\d+", b.name):
            vs.append(b)
    return max(vs, key=lambda b: [int(x) for x in b.name.split(".")]) if vs \
        else None


def main() -> int:
    port = pin_port()
    if port is None:
        print("no pin daemon recorded — every network probe would be "
              "UNPROVEN, not failing")
        return 2
    check_rc_survives()
    check_names_restored(port)
    check_reconnect_possible(newest_binary())
    check_attachment(port)
    check_bidirectional(port)
    check_no_stall(port)

    width = max(len(r) for r, _, _ in ROWS)
    bad = 0
    for req, verdict, detail in ROWS:
        if verdict == "FAIL":
            bad += 1
        print(f"  {req:<{width}}  {verdict:<9} {detail}")
    print()
    counts: dict[str, int] = {}
    for _, v, _ in ROWS:
        counts[v] = counts.get(v, 0) + 1
    print("  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
