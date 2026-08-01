"""Account-pin proxy.

A local MITM forward proxy that swaps the ``Authorization`` bearer to a pinned
account's token on the Remote-Control and Artifact routes, so those operations
stay on one account while inference follows whatever cswap has swapped onto
disk. Everything else (inference at ``/v1/messages``, OAuth, telemetry, …) is
relayed untouched, and non-anthropic hosts are blind-tunnelled.

The daemon lifecycle here — fixed port across respawns, FIFO refcount, config
fingerprint, idle teardown — follows the one in claude-code-cache-fix ("CCF"
in the comments below), whose forward-proxy mode solves the same shape of
problem in front of Claude Code. Nothing in this module requires it: a
comment naming CCF is citing where a decision came from, not a dependency.
"""

from __future__ import annotations

import base64
import datetime as _dt
import itertools
import json
import os
import re
import selectors
import select
import socket
import sys
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from claude_swap import oauth


def parse_upstream_proxy(value: str | None) -> tuple[str, int] | None:
    """Parse the proxy that was on ``HTTPS_PROXY`` before we displaced it.

    Returns ``(host, port)`` to CONNECT through (a corporate proxy, another
    local MITM, …), or ``None`` when there was none — in which case the proxy
    dials the upstream directly. A bare ``host:port`` (no scheme) is accepted;
    a scheme-only URL defaults to port 80.
    """
    if not value:
        return None
    split = urlsplit(value if "://" in value else f"//{value}")
    host = split.hostname
    if not host:
        return None
    return host, split.port or 80


def _read_upstream(certdir: Path, key: str) -> str | None:
    """One field out of the upstream record, or None when it is absent."""
    try:
        raw = json.loads((Path(certdir) / _UPSTREAM_FILE).read_text())
    except (OSError, ValueError):
        return None
    return (raw.get(key) or None) if isinstance(raw, dict) else None


def read_upstream_hint(certdir: Path) -> tuple[str, int] | None:
    """The egress proxy the LAST launch was using, as recorded on disk.

    The daemon outlives the launch that spawned it, and a session's own
    ``HTTPS_PROXY`` is fixed at exec — so the daemon cannot ask "what should I
    chain through now?" of anything but this file. Every launch re-stamps it
    (``ensure_proxy``), so an egress proxy that moved ports or came up after the daemon
    is picked up on the next connection rather than bypassed for the daemon's
    whole life.

    Returns ``None`` when the file is absent or records "no proxy" — the same
    thing a direct dial means.
    """
    return parse_upstream_proxy(_read_upstream(certdir, "proxy"))


def write_upstream_hint(
    certdir: Path, value: str | None, ca: str | None = None
) -> None:
    """Record the egress proxy for the daemon to chain through (see above).

    ``ca`` records the CA that proxy signs with, so a later launch that cannot
    see it (a plain shell, where a launcher's CA only exists at exec time) can
    still merge it.

    A ``value`` of None means "this launch could not see a proxy", which is NOT
    the same as "there is no proxy": `cswap pin` normally runs in an ordinary
    shell, while the launcher sets HTTPS_PROXY only in the environment it execs
    Claude Code with. Recording that as "none" would drop a live upstream —
    measured: a re-pin from a plain shell blanked a recorded proxy and the daemon
    started bypassing it. So a previously recorded proxy is kept unless a
    launch positively reports a different one.
    """
    path = Path(certdir) / _UPSTREAM_FILE
    tmp = path.with_suffix(".tmp")
    keep_ca = read_upstream_ca(certdir) if ca is None else ca
    if value:
        keep_proxy = value
    else:
        prev = read_upstream_hint(certdir)
        keep_proxy = f"http://{prev[0]}:{prev[1]}" if prev else ""
    try:
        tmp.write_text(json.dumps({"proxy": keep_proxy, "ca": keep_ca or ""}))
        tmp.replace(path)
    except OSError:
        pass


def read_upstream_ca(certdir: Path) -> str | None:
    """The CA of the egress proxy, as last recorded. See above."""
    return _read_upstream(certdir, "ca")


_WIRE_KEYS = ("HTTPS_PROXY", "https_proxy", "NODE_EXTRA_CA_CERTS")
_WIRE_MARK = "_cswapPinWiredKeys"


def _merged_ca(ca_path: Path, existing: str | None) -> Path:
    """Our CA plus whatever the session already trusted, in one file.

    ``NODE_EXTRA_CA_CERTS`` names a single file, so writing ours over an
    existing value silently drops that trust. When another CA is in play — the
    upstream cache proxy's, a corporate MITM's — hosts IT re-signs stop
    verifying, which is how a pinned session ends up unable to reach the
    updater. Merge instead; fall back to ours alone if the merge cannot be
    written.
    """
    ca_path = Path(ca_path)
    other = (
        existing
        or os.environ.get("NODE_EXTRA_CA_CERTS")
        # A launcher's CA exists only in the environment it execs Claude Code
        # with, which `cswap pin` never sees. Fall back to what a launch
        # recorded (see write_upstream_hint).
        or read_upstream_ca(ca_path.parent)
    )
    bundle = ca_path.parent / "ca-bundle.pem"
    if not other or Path(other) == ca_path:
        return ca_path
    if Path(other) == bundle:
        # Already the merged file (a launch inside a pinned session inherits it
        # from our own env block). Returning ca_path here would UN-merge it and
        # lose the upstream proxy's CA on every later session.
        return bundle
    other_path = Path(other)
    # Rebuild only when an input is newer than the output — the inputs are
    # immutable per launch, so the steady state is two stats instead of
    # rewriting the bundle on every launch (same trade CCF's ensure makes).
    try:
        if (
            not bundle.exists()
            or ca_path.stat().st_mtime_ns > bundle.stat().st_mtime_ns
            or other_path.stat().st_mtime_ns > bundle.stat().st_mtime_ns
        ):
            bundle.write_bytes(
                ca_path.read_bytes() + b"\n" + other_path.read_bytes()
            )
    except OSError:
        return ca_path
    return bundle


CA_TRUST_DIR = "ca-trust.d"
CA_TRUST_FILE = "ca-trust.pem"


def _trust_file(ca_path: Path, existing: str | None) -> Path:
    """The single file to name in ``NODE_EXTRA_CA_CERTS``.

    Prefers the shared merged bundle when a launcher has built one: it already
    contains every component's CA plus the ambient roots, so a proxy added
    later is trusted without cswap knowing it exists. Falls back to merging
    ours with whatever the caller already trusted, and to ours alone when there
    is nothing else — which is the no-launcher, no-other-MITM case and behaves
    exactly as before.
    """
    try:
        from claude_swap.paths import get_claude_config_home

        shared = get_claude_config_home() / CA_TRUST_FILE
        if shared.is_file() and shared.stat().st_size > 0:
            ours = Path(ca_path).read_bytes().strip()
            body = shared.read_bytes()
            # Carrying our CA is necessary but not sufficient. An unbalanced
            # BEGIN/END anywhere in the file makes Node reject the WHOLE extras
            # bundle — every component CA and every corporate root at once —
            # and it says so only in a stderr warning, so the session dies on
            # "unable to verify the first certificate" with no visible cause.
            # Checking that we are in there cannot see that; count the markers.
            #
            # A bundle that is BALANCED and CONTAINS us but has silently lost
            # other roots is deliberately NOT guarded here. A consumer cannot
            # tell "narrowed" from "correctly small": measured across the three
            # machines this runs on, a legitimate bundle is 2 certs on one and
            # 132 on another, so any size floor that catches narrowing on one
            # host rejects a healthy bundle on the next. Only the builder holds
            # the previous state that makes narrowing a *regression* rather
            # than a fact, which is why it keeps the last good bundle instead.
            # The two cases below are also a different severity class: both
            # leave the session unable to verify its OWN proxy, so every
            # request dies. Narrowing keeps our chain intact and costs someone
            # else's. Do not add a cert-count floor here.
            if (
                ours
                and ours in body
                and body.count(b"-----BEGIN CERTIFICATE-----")
                == body.count(b"-----END CERTIFICATE-----")
            ):
                return shared
    except Exception:
        pass
    # No shared bundle: merge with what THIS env trusts. Deliberately not
    # _merged_ca, which also consults the ambient process environment and a
    # recorded upstream CA — wire_env is handed the environment it must
    # describe, and reaching past it would wire a session to trust something
    # its caller never mentioned.
    if not existing or Path(existing) == Path(ca_path):
        return Path(ca_path)
    bundle = Path(ca_path).parent / "ca-bundle.pem"
    try:
        bundle.write_bytes(Path(ca_path).read_bytes() + Path(existing).read_bytes())
        return bundle
    except OSError:
        return Path(ca_path)


def publish_ca(ca_path: Path, name: str = "cswap-pin") -> Path | None:
    """Publish our CA where any component's launcher can pick it up.

    ``NODE_EXTRA_CA_CERTS`` names ONE file, so every MITM in the chain that
    writes it as an overwrite silently drops the others. Two already do it for
    the same host, and each new one repeats the fight — which is how a pinned
    session ended up verifying everything it SENDS while every Remote Control
    SSE reconnect failed with ``unable to verify the first certificate``
    (measured on work-mac: 13 attempts, 0 connects, while worker/heartbeat and
    client/presence answered 200 in the same process).

    So publish instead of overwrite: one file per component under
    ``<claude-config>/ca-trust.d/``, named after the component, and nobody
    touches anybody else's. A launcher concatenates the directory; a component
    that only needs to be trusted just drops its file. Adding a proxy stops
    being a negotiation.

    Deliberately knows nothing about which proxies exist: with no launcher and
    no other MITM the directory is simply unread, and behaviour is unchanged.
    Best-effort — trust plumbing must never block a launch.

    Written ATOMICALLY, which the contract needs rather than merely prefers: a
    builder reads this directory while N producers write it on their own
    schedules, and a reader that catches a half-written PEM does not get a
    partial bundle — Node refuses the WHOLE extras file
    (``PEM routines::bad end line``, on stderr, not an error) and then trusts
    no component CA and no corporate root at all. The session dies on
    ``unable to verify the first certificate`` with the cause in a warning
    nobody reads. A truncate-then-write is exactly what produces that state.
    """
    try:
        from claude_swap.paths import get_claude_config_home

        ours = Path(ca_path).read_bytes().strip()
        if not ours:
            return None
        out = get_claude_config_home() / CA_TRUST_DIR / f"{name}.pem"
        out.parent.mkdir(parents=True, exist_ok=True)
        # Idempotent: rewriting on every launch would churn the mtime the
        # launcher's own rebuild check keys on.
        if out.exists() and out.read_bytes().strip() == ours:
            return out
        # Same directory, so the rename cannot cross a filesystem and stays
        # atomic; the pid keeps two concurrent launches off each other's temp.
        tmp = out.with_name(f"{out.name}.{os.getpid()}.tmp")
        try:
            tmp.write_bytes(ours + b"\n")
            os.replace(tmp, out)
        finally:
            tmp.unlink(missing_ok=True)
        return out
    except Exception:
        return None


def heal(backup_root: Path) -> bool:
    """Bring the pin back if it is pinned but not serving. True when it did.

    RECOVERY WITHOUT A SESSION RESTART. Everything else in this module reacts
    to a launch: ``ensure_proxy`` runs when a NEW session starts, so if the
    daemon dies while sessions are up, nothing brings it back — and if the dead
    wiring has blocked every session, no new one can start to trigger it. That
    is a deadlock, and it is exactly what happened on work-mac: a human had to
    re-pin by hand.

    So this is callable from anything that already runs periodically (the
    status line does, every few seconds) and needs no switcher: the pinned
    identity comes from settings.json and the slot from the account registry,
    both on disk. Cheap when healthy — a state read plus one loopback connect,
    and it returns immediately.

    The port is REBOUND, not reallocated: the daemon reclaims the port recorded
    in proxy.json, else port.hint. That is what makes live sessions recover on
    their own — they are already wired to that address, so a daemon returning
    to it is picked up by the next request with no restart and nothing to
    reconnect by hand.

    Serialized by the same spawn lock ``ensure_proxy`` takes, so N status lines
    across N sessions elect ONE spawner instead of racing.
    """
    backup_root = Path(backup_root)
    certdir = backup_root / "pin-proxy"
    try:
        pin = load_pin(backup_root)
    except Exception:
        return False
    if not pin:
        return False  # nothing pinned — not our business
    email = pin[0]
    if _read_alive_port(certdir) is not None:
        return False  # already serving
    # Resolve the slot the way the status line does: identity is stored by
    # email because slots move (`cswap move`), so the number comes from the
    # registry rather than being cached with the pin.
    try:
        seq = json.loads((backup_root / "sequence.json").read_text(encoding="utf-8"))
        accounts = seq.get("accounts") or {}
        account_num = next(
            (num for num, rec in accounts.items()
             if (rec.get("email") if isinstance(rec, dict) else rec) == email),
            None,
        )
    except Exception:
        account_num = None
    if not account_num:
        return False  # dangling pin: its slot is gone, nothing to serve
    try:
        with _spawn_lock(certdir):
            # Re-check under the lock — another caller may have just spawned.
            if _read_alive_port(certdir) is not None:
                return False
            port = _spawn_daemon(account_num, email, certdir)
        if port is None:
            # Could not start. Make sure a stale wiring is not left behind to
            # block sessions; better unpinned than unusable.
            unwire_if_dead(certdir)
            return False
        wire_global_config(port, certdir / "ca.pem")
        return True
    except Exception:
        return False


def unwire_if_dead(certdir: Path) -> bool:
    """Strip a pin wiring whose daemon is gone. True when it removed one.

    The teardown path restores ``.claude.json`` itself, but it only runs when
    the daemon exits in an orderly way. A SIGKILL, an OOM kill, a crash — or a
    daemon that never started at all, which is what happened on work-mac when
    ``cryptography`` vanished from its environment — leaves the env block
    naming a port nothing listens on. Claude Code applies that block at boot,
    so every session from then on dials a dead proxy and retries forever while
    the upstream proxies are perfectly healthy behind it.

    Called at launch, before anything reads the wiring, so a broken pin costs
    the PIN and never the session. The check is the same one
    ``_read_alive_port`` makes — a recorded pid that is alive AND a port that
    answers — because either alone lies: a wedged process keeps its pid, and a
    port can be inherited by something else entirely.

    Deliberately does NOT try to revive the daemon. That is ``ensure_proxy``'s
    job and it needs the switcher; this runs on paths that may not have one,
    and a launch must never block on starting a background service.
    """
    try:
        st = read_daemon_state(certdir)
    except Exception:
        st = None
    if st:
        try:
            if _pid_alive(int(st["pid"])):
                with socket.create_connection(
                    ("127.0.0.1", int(st["port"])), timeout=1
                ):
                    return False  # serving — leave the wiring alone
        except (OSError, KeyError, TypeError, ValueError):
            pass

    # NO RECORD IS NOT PROOF OF DEATH. `_spawn_daemon` UNLINKS proxy.json as
    # its first act, so between that unlink and a failed spawn the state file
    # is missing while the original daemon is still happily serving. Deciding
    # from the record alone unwired a live pin on linux: daemon 4035232 had
    # been up 38h, pid alive, port answering, and the env block was stripped
    # anyway because proxy.json had just been deleted out from under this
    # check. (It fires on a code change, because ensure_proxy matches on a
    # FINGERPRINT: same daemon, new fingerprint, so it tries to replace one
    # that is fine, and the spawn fails on the port the healthy daemon holds.)
    #
    # So ask the WIRING itself, which is the thing we are about to remove: if
    # the port it names still answers, something is serving on it and the
    # wiring is correct regardless of what any file says.
    port = _wired_port()
    if port is not None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return False  # the wired address is live — do not touch it
        except OSError:
            pass

    try:
        return wire_global_config(None, None)
    except Exception:
        return False


def _wired_port() -> int | None:
    """The pin port currently named in the global config, or None.

    Read straight off the env block rather than from our own state, so it stays
    truthful while the state file is absent (see ``unwire_if_dead``).
    """
    try:
        from claude_swap.paths import get_global_config_path

        raw = json.loads(get_global_config_path().read_text(encoding="utf-8"))
        env = raw.get("env") if isinstance(raw, dict) else None
        if not isinstance(env, dict):
            return None
        val = env.get("CSWAP_PIN_PORT")
        return int(val) if val is not None else None
    except Exception:
        return None


def wire_global_config(port: int | None, ca_path: Path | None) -> bool:
    """Route hand-launched ``claude`` sessions through the pin proxy.

    Claude Code applies the ``env`` block of its global config into
    ``process.env`` at startup, so a session the user starts themselves — no
    cswap, no wrapper, no shell edit — picks the pin up. That block lives in
    ``.claude.json``, the same file cswap already rewrites to swap accounts,
    so this touches nothing new: not ``settings.json`` (Claude Code's own),
    not a shell rc, not a shim on PATH.

    Only keys THIS function wrote are ever modified, tracked by name in
    ``_WIRE_MARK``. A proxy the user (or their launcher) set themselves is
    left exactly as found, and clearing the pin restores it rather than
    deleting it — the ordering matters, because the env block is applied on
    top of the process environment and would otherwise silently displace a
    wrapper's own proxy.

    Passing ``port=None`` unwires. Returns True when the file changed.

    Not retroactive: a session already running keeps the environment it was
    exec'd with (only a ``settings.json`` change re-applies env to a live
    process, and that file is not ours to write). New sessions are wired.
    """
    from claude_swap.claude_locks import claude_config_lock
    from claude_swap.paths import get_global_config_path

    path = get_global_config_path()
    # Claude Code writes this file concurrently, and we replace it whole — a
    # write landing between our read and our rename would be discarded along
    # with the account, project history and settings it carried. Hold the same
    # lock every other writer in this codebase takes, across read AND write.
    try:
        with claude_config_lock(timeout=5):
            return _wire_global_config_locked(path, port, ca_path)
    except Exception:
        # A lock we cannot take is a reason to skip the write, not to fail a
        # launch: the pin degrades to "not wired", which is the fail-open
        # behaviour the rest of this module is built on.
        return False


def _wire_global_config_locked(
    path: Path, port: int | None, ca_path: Path | None
) -> bool:
    """The read-modify-write of :func:`wire_global_config`, under its lock."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(raw, dict):
        return False

    env = raw.get("env")
    env = dict(env) if isinstance(env, dict) else {}
    before = dict(env)
    ours = raw.get(_WIRE_MARK)
    ours = list(ours) if isinstance(ours, list) else []

    # Drop what we wrote last time, restoring anything we displaced.
    saved = raw.get(f"{_WIRE_MARK}Saved")
    saved = dict(saved) if isinstance(saved, dict) else {}
    for key in ours:
        env.pop(key, None)
    for key, value in saved.items():
        env[key] = value

    if port is None or ca_path is None:
        raw.pop(_WIRE_MARK, None)
        raw.pop(f"{_WIRE_MARK}Saved", None)
    else:
        # The CA lives in the cert dir, so its parent IS the cert dir — which
        # is where the proxy credential lives too. Deriving it here keeps the
        # public signature unchanged for every caller.
        proxy = _proxy_url(port, Path(ca_path).parent)
        wanted = {
            "HTTPS_PROXY": proxy,
            "https_proxy": proxy,
            # A launcher that sets ALL_PROXY leaves it naming the proxy we
            # chain THROUGH, so the session runs with two proxy vars pointing
            # at different hops. curl resolves that in our favour — measured,
            # https_proxy=A + ALL_PROXY=B dials A, and B only when A is unset
            # — but the split is one a client is free to resolve the other
            # way, and it is unreadable for anyone diagnosing a route. Claim
            # it so every var names the same hop. Scoped to this file, which
            # Claude Code applies to itself; the shell path deliberately does
            # not create one (see wire_env).
            "ALL_PROXY": proxy,
            # Node takes exactly ONE file here, so replacing an existing CA
            # blinds the session to every host the proxy behind us re-signs.
            # Measured: with only our CA, `downloads.claude.ai` (MITM'd by the
            # upstream cache proxy) failed to verify and the session showed
            # "Auto-update failed · Run claude doctor".
            "NODE_EXTRA_CA_CERTS": str(
                _merged_ca(ca_path, env.get("NODE_EXTRA_CA_CERTS"))
            ),
            # Self-loop marker. Claude Code applies this block into
            # process.env, which its Bash-tool children inherit — so a `cswap`
            # run from inside a pinned session sees our own proxy as its
            # ambient one. Without the marker it records THAT as the upstream
            # and the daemon starts CONNECTing to itself.
            "CSWAP_PIN_PORT": str(port),
        }
        # Remember what we are about to displace, so unwiring is lossless.
        raw[f"{_WIRE_MARK}Saved"] = {
            k: env[k] for k in wanted if k in env
        }
        env.update(wanted)
        raw[_WIRE_MARK] = list(wanted)

    if env == before and _WIRE_MARK not in raw and not ours:
        return False
    if env:
        raw["env"] = env
    else:
        raw.pop("env", None)
    try:
        tmp = path.with_suffix(".cswap-tmp")
        tmp.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        return False
    return True


def _ambient_proxy(
    env: dict[str, str] | None = None, certdir: Path | None = None
) -> str | None:
    """The egress proxy this launch inherited, or ``None`` for a direct dial.

    Skips a value that already points at OUR daemon: a shell that ran
    ``pin-env`` (or a re-launch inside a pinned session) exports the pin proxy
    itself, and recording that would make the daemon CONNECT to itself — every
    request looping until the socket dies.
    """
    src = os.environ if env is None else env
    value = src.get("HTTPS_PROXY") or src.get("https_proxy")
    parsed = parse_upstream_proxy(value)
    if parsed is None:
        # Nothing in OUR environment — but a launcher may still put a proxy in
        # the session's, and our env block displaces it. `cswap pin` runs in a
        # plain shell where that value does not exist yet, so ask the config
        # what the last session was actually told to use.
        return _wired_over_proxy()
    host, port = parsed
    if host in _LOOPBACK and port == _self_port(src):
        return _wired_over_proxy()
    # This shell has A proxy — but not necessarily the one Claude Code runs
    # behind. A launcher (cc-wrapper) starts a per-session cache proxy and
    # points HTTPS_PROXY at THAT; an ordinary shell, and every ssh shell, only
    # has the machine-wide egress proxy the launcher itself chains to. Taking
    # the shell's value then silently drops the launcher's proxy out of the
    # chain: measured on work-mac, where `cswap pin` run over ssh recorded
    # privoxy:8118 while CCF on :9901 (whose own upstream IS 8118) was left
    # bypassed for every pinned session. Prefer the recorded one when it is
    # still serving — it is the inner link, and it reaches this one anyway.
    # Two places can name the inner proxy: what our env block displaced on a
    # previous launch, and what a previous launch recorded as the chain. Try
    # the displaced value first — it is the most direct evidence — then the
    # recorded one, which is the only source on a machine where our block has
    # never displaced anything (measured: work-mac, where every shell exports
    # the machine-wide proxy, so the displaced value is empty and re-pinning
    # from any shell kept dropping the launcher's proxy out of the chain).
    for prev in (_wired_over_proxy(), _recorded_upstream(certdir)):
        prev_parsed = parse_upstream_proxy(prev)
        if (
            prev_parsed is not None
            and prev_parsed != parsed
            and prev_parsed[0] in _LOOPBACK
            and prev_parsed[1] != _self_port(src)
            and _port_is_serving(*prev_parsed)
        ):
            return prev
    return value


def _recorded_upstream(certdir: Path | None) -> str | None:
    """The chain a previous launch recorded, as a URL. See the caller."""
    if certdir is None:
        return None
    prev = read_upstream_hint(certdir)
    return f"http://{prev[0]}:{prev[1]}" if prev else None


def _proxy_url(port: int, certdir: Path | None) -> str:
    """The proxy URL to hand a client, carrying the credential when there is one.

    Userinfo in the URL is how every client we wire (Node, curl, python) is
    told to send ``Proxy-Authorization`` — measured: the real Claude Code
    client sends ``Proxy-Authorization: Basic`` on CONNECT when HTTPS_PROXY
    carries user:pass, and sends nothing when it does not. That measurement is
    the whole reason this can be enforced without cutting every session off.

    No secret (a cert dir we could not write) yields the bare URL, so the pin
    keeps working unauthenticated rather than becoming unusable.
    """
    if certdir is not None:
        secret = read_proxy_secret(certdir)
        if secret:
            from urllib.parse import quote

            return f"http://cswap:{quote(secret, safe='')}@127.0.0.1:{port}"
    return f"http://127.0.0.1:{port}"


def _port_is_serving(host: str, port: int) -> bool:
    """Whether something still accepts connections there. Cheap and local."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _wired_over_proxy() -> str | None:
    """The proxy our env block is currently displacing, if any.

    Recorded by :func:`wire_global_config` when it wrote over a value that was
    already there. Without this, wiring from a shell that has no proxy (the
    normal case: a launcher sets one only when it execs Claude Code) would
    record "no upstream" and the pinned session would bypass that launcher's
    proxy entirely.
    """
    from claude_swap.paths import get_global_config_path

    try:
        raw = json.loads(get_global_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    saved = raw.get(f"{_WIRE_MARK}Saved") if isinstance(raw, dict) else None
    if isinstance(saved, dict):
        value = saved.get("HTTPS_PROXY") or saved.get("https_proxy")
        if value:
            return value
    return None


def _self_port(env: dict[str, str]) -> int | None:
    """Our own daemon's port as this environment records it, if any."""
    try:
        return int(env.get("CSWAP_PIN_PORT", ""))
    except ValueError:
        return None


_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})

_UPSTREAM_FILE = "upstream.json"

_WORKER_SUBTREE = re.compile(r"^/v1/(code/)?sessions/[^/]+/worker(/|$|\?)")


def is_pinned_route(path: str) -> bool:
    """Whether a request path's bearer must be swapped to the pinned account.

    True for the routes whose server-side ownership is decided by the OAuth
    bearer — Remote-Control session lifecycle, Artifact ("frame") deploys,
    and Ultrareview (a claude.ai capability gated on the same bearer).
    False for everything else, most importantly ``/v1/messages`` (which must
    keep billing the currently-swapped inference account).

    ``/v1/sessions/<id>/...`` is the RC session-lifecycle sibling of
    ``/v1/code/sessions`` — reconnect unarchives via ``/v1/sessions/{id}/
    unarchive`` (measured). It MUST swap too: if unarchive keeps the disk
    bearer while the bridge is swapped, the session's ownership splits and the
    reconnect resolves on the disk account, so the pinned account never sees
    it. The trailing ``/`` keeps a bare ``/v1/sessions`` list out.

    **The ``/worker`` subtree is deliberately excluded.** Those calls do not
    carry the OAuth token at all: the worker authenticates with a session JWT
    (binary: ``auth:"session-jwt"`` → ``Ter()``/``Kb()``), minted per session
    and carrying its own ``session_id``/``account_uuid`` claims. Swapping that
    Authorization for the pinned OAuth token makes the server reject every
    worker call — measured live as a 403 storm on ``GET/PUT .../worker`` while
    ``POST .../client/presence`` (genuinely OAuth) returned 200 in the same
    trace, leaving Remote Control stuck in a reconnect loop.

    Ownership is still pinned, because the JWT's own issuance is: ``/bridge``
    is OAuth-authenticated and IS swapped, so it mints a worker JWT for the
    pinned account (verified by decoding it). After that the JWT must travel
    untouched.
    """
    if _WORKER_SUBTREE.search(path):
        return False
    return (
        path.startswith("/v1/code/sessions")
        or path.startswith("/v1/sessions/")
        or path.startswith("/api/frame/")
        or path.startswith("/v1/ultrareview/")
    )


@dataclass(frozen=True)
class CertBundle:
    """Paths to the generated MITM material.

    ``ca_path`` is what the client trusts via ``NODE_EXTRA_CA_CERTS``;
    ``leaf_path``/``leaf_key_path`` back the server-side TLS context.
    """

    ca_path: Path
    leaf_path: Path
    leaf_key_path: Path


# 100 years — the proxy's certs are ephemeral local trust; a long life avoids
# spurious expiry mid-session and matches CCF's 10-year leaf.
_CERT_DAYS = 3650


def ensure_ca(ca_dir: Path, host: str) -> CertBundle:
    """Generate (once) a root CA and a leaf cert for ``host`` under ``ca_dir``.

    Idempotent: an existing CA is reused, so the client keeps trusting the same
    root across restarts. The CA carries a SubjectKeyIdentifier and
    BasicConstraints CA:TRUE; the leaf carries a SAN for ``host``, serverAuth
    EKU, and an AuthorityKeyIdentifier derived from the CA. The leaf AKI is
    NOT optional here: OpenSSL (Python's ssl and Node both link it) rejects a
    leaf without one — "Missing Authority Key Identifier" — even though
    ``openssl verify`` on the file alone passes. Deriving the AKI requires the
    CA SKI, which is why the CA must carry it.
    """
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_pem = ca_dir / "ca.pem"
    ca_key = ca_dir / "ca.key"
    leaf_pem = ca_dir / "leaf.pem"
    leaf_key = ca_dir / "leaf.key"

    if ca_pem.exists() and ca_key.exists():
        ca_cert = x509.load_pem_x509_certificate(ca_pem.read_bytes())
        ca_priv = serialization.load_pem_private_key(ca_key.read_bytes(), password=None)
    else:
        ca_cert, ca_priv = _make_ca()
        ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        _write_key(ca_key, ca_priv)

    if not (leaf_pem.exists() and leaf_key.exists()):
        leaf_cert, leaf_priv = _make_leaf(host, ca_cert, ca_priv)
        leaf_pem.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
        _write_key(leaf_key, leaf_priv)

    return CertBundle(ca_path=ca_pem, leaf_path=leaf_pem, leaf_key_path=leaf_key)


def _make_ca() -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cswap pin-proxy CA")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=_CERT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            # OpenSSL 3 (Python 3.14's ssl, Node) rejects a signing CA that
            # lacks keyCertSign — "CA cert does not include key usage
            # extension". CCF's openssl-generated CA happened to carry it;
            # be explicit.
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _make_leaf(
    host: str, ca_cert: x509.Certificate, ca_priv: rsa.RSAPrivateKey
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=_CERT_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
        .sign(ca_priv, hashes.SHA256())
    )
    return cert, key


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)


def resolve_pin_token(
    credentials: str,
    refresh: Callable[[str], "oauth.RefreshOutcome"],
) -> tuple[str | None, str | None]:
    """Return a live access token for the pinned account, refreshing if needed.

    ``credentials`` is the pinned account's stored credential JSON. If its
    access token is still valid the token is returned unchanged with no
    rotation (second element ``None``). If it is near/at expiry, ``refresh`` is
    invoked; on success the rotated credential JSON is returned as the second
    element so the caller can persist it, and the new access token as the
    first. On refresh failure (or no data) the token is ``None`` so the proxy
    can fall back to leaving the request's original bearer in place.
    """
    data = oauth.extract_oauth_data(credentials)
    if not data:
        return None, None
    access = data.get("accessToken")
    if access and not oauth.is_oauth_token_expired(data.get("expiresAt")):
        return access, None

    outcome = refresh(credentials)
    if not outcome.credentials:
        return None, None
    new_data = oauth.extract_oauth_data(outcome.credentials) or {}
    return new_data.get("accessToken"), outcome.credentials


def load_pin(backup_root: Path) -> tuple[str, str] | None:
    """Read the pinned account identity from settings.json.

    Returns ``(email, organizationUuid)`` or ``None`` when nothing is pinned.
    Identity is stored by (email, org) — slot numbers move (``cswap move``).
    """
    from claude_swap import settings as _settings

    raw = _settings._read_raw(_settings.settings_path(backup_root))
    section = raw.get("remoteControl")
    if not isinstance(section, dict):
        return None
    email = section.get("pinnedEmail")
    if not email:
        return None
    return email, section.get("pinnedOrganizationUuid", "") or ""


def save_pin(backup_root: Path, email: str | None, org_uuid: str | None) -> None:
    """Persist (or clear, with ``email=None``) the pin in settings.json.

    Lives in its own ``remoteControl`` section; ``save_settings`` preserves
    unknown sections, so autoswitch writes never clobber it.
    """
    from claude_swap import settings as _settings

    path = _settings.settings_path(backup_root)
    raw = _settings._read_raw(path)
    if email:
        raw["remoteControl"] = {
            "pinnedEmail": email,
            "pinnedOrganizationUuid": org_uuid or "",
        }
    else:
        raw.pop("remoteControl", None)
    _settings.atomic_write_json(path, raw)


def live_remote_control_sessions() -> list[str]:
    """Names of sessions that currently hold a Remote Control binding.

    Ownership of an RC session is fixed by the bearer that created it, so a
    re-pin cannot move one that is already open — reconnecting inside it can
    (that mints a new session under the new pin). Knowing which sessions those
    are is what lets `cswap pin` say so instead of guessing.

    Claude Code records one file per live session with a ``bridgeSessionId``
    that is set only while RC is connected. Best-effort: an unreadable or
    absent registry just yields nothing.
    """
    from claude_swap.paths import get_claude_config_home

    names: list[str] = []
    try:
        entries = sorted((get_claude_config_home() / "sessions").glob("*.json"))
    except OSError:
        return names
    for path in entries:
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict) and rec.get("bridgeSessionId"):
            names.append(str(rec.get("name") or rec.get("sessionId") or path.stem))
    return names


def apply_pin(switcher, email: str | None, org_uuid: str | None) -> bool:
    """Set (or clear, with ``email=None``) the pin AND bring the world in line.

    Storing the pin is only half the job: hand-launched sessions read the
    proxy out of the global config, so a pin that is saved but not wired does
    nothing, and — worse — a pin CLEARED but not unwired leaves that config
    pointing at a proxy which idle-tears-down, breaking egress for every new
    `claude` with no way back but editing the file by hand.

    Both entry points (the CLI and the TUI menu) go through here so they
    cannot drift apart again. Returns whether a proxy is now serving.
    """
    save_pin(switcher.backup_dir, email, org_uuid)
    if not email:
        wire_global_config(None, None)
        return False
    # Mint the proxy credential HERE, not in the daemon. This is the one path
    # that also rewrites the wiring, so the gate and the URL that satisfies it
    # arrive together. A daemon respawn must never arm it by itself — sessions
    # already running carry the pre-credential URL and would start getting 407.
    # An existing secret is reused, so re-pinning does not invalidate live
    # sessions either.
    certdir = switcher.backup_dir / "pin-proxy"
    try:
        certdir.mkdir(parents=True, exist_ok=True)
        ensure_proxy_secret(certdir)
    except OSError:
        pass  # unwritable cert dir: serve unauthenticated rather than not at all
    return ensure_proxy(switcher) is not None


def make_pin_token_provider(switcher, account_num: str, email: str):
    """Build the ``pin_token_provider`` callable for :class:`PinProxy`.

    Reads the pinned account's credential from cswap's backup store and
    returns a live access token, refreshing (and persisting the rotation back
    to the store) when expired. Returns ``None`` — meaning "leave the
    request's bearer alone" — when the pinned account is currently the ACTIVE
    account (its live credential is already on disk and owned by the client;
    the backup copy may be stale) or when no usable token can be produced.

    **Which account is pinned is re-read from disk per request**, not frozen
    at spawn. Switching accounts in cswap never asks you to restart a session,
    and re-pinning should not either: a live session holds only the proxy's
    address, so the daemon can start serving a different account underneath it
    the moment ``cswap pin`` writes one. ``account_num``/``email`` are the
    fallback for when the pin cannot be resolved (a removed account).

    **Refresh is serialized.** The provider runs once per pinned request and
    each MITM connection is its own thread, so an expiry under load would
    otherwise have N threads POST the SAME one-time refresh token
    concurrently: one wins and the rest come back ``invalid_grant``, with the
    last writer persisting a credential whose grant was already consumed —
    exactly the lineage-death shape cswap exists to prevent. A thread that
    waited on the lock re-reads the store first and uses the winner's
    rotation instead of refreshing again.
    """
    refresh_lock = threading.Lock()

    def _live_token(creds: str) -> str | None:
        data = oauth.extract_oauth_data(creds)
        if not data:
            return None
        access = data.get("accessToken")
        if access and not oauth.is_oauth_token_expired(data.get("expiresAt")):
            return access
        return None

    def _current_target() -> tuple[str, str] | None:
        """The account to pin RIGHT NOW, re-read so `cswap pin <other>` takes
        effect without restarting anything. Falls back to the one this daemon
        was spawned for when the pin is unreadable, and returns None when the
        pin was cleared outright (leave every bearer alone)."""
        from claude_swap.exceptions import AccountNotFoundError, ConfigError

        try:
            pin = load_pin(switcher.backup_dir)
        except Exception:
            return account_num, email
        if pin is None:
            return None
        try:
            num, mail, _ = switcher.resolve_account(pin[0])
            return num, mail
        except (AccountNotFoundError, ConfigError, Exception):
            return account_num, email

    def provider() -> str | None:
        target = _current_target()
        if target is None:
            return None
        num, mail = target
        if switcher.current_account_number() == num:
            return None
        creds = switcher.read_account_credentials(num, mail)
        if not creds:
            return None
        token = _live_token(creds)
        if token:
            return token  # common path: no lock, no network

        with refresh_lock:
            # Someone may have rotated it while we waited — re-read and reuse.
            creds = switcher.read_account_credentials(num, mail) or creds
            token = _live_token(creds)
            if token:
                return token
            token, rotated = resolve_pin_token(
                creds, oauth.try_refresh_oauth_credentials
            )
            if rotated:
                switcher.persist_backup_credentials(num, mail, rotated)
            return token

    def pin_is_noop() -> bool:
        """True when returning no token is the CORRECT answer, not a failure.

        ``provider`` returns None for two opposite reasons and the caller
        cannot tell them apart: the credential could not be read (bad — every
        pinned request goes out unpinned), or there is deliberately nothing to
        swap. The second happens whenever the pinned account IS the active
        account — the live bearer already belongs to it — and whenever the pin
        was cleared outright.

        Without this split the fail-open warning cries wolf. Measured on
        personal-mac: pinned account == active account, so the provider
        correctly returned None on the very first request and the daemon
        logged "the pinned account token could not be read ... on macOS this
        is usually a daemon started outside the GUI session". Nothing was
        wrong; the keychain read was fine (rc=0, 509 bytes). It cost the
        reader ten minutes down a keychain rabbit hole, and a warning that
        fires when nothing is wrong is worse than no warning at all — this one
        exists to be believed on the day it is real.
        """
        target = _current_target()
        if target is None:
            return True  # pin cleared: leaving every bearer alone IS the job
        return switcher.current_account_number() == target[0]

    provider.pin_is_noop = pin_is_noop
    return provider


def _pin_is_noop(provider) -> bool:
    """Ask a token provider whether None means "nothing to do" right now.

    Tolerates a provider without the hook — tests inject bare lambdas, and a
    plain callable must keep working — by answering False, which is the old
    behaviour (treat None as a failure).
    """
    try:
        return bool(getattr(provider, "pin_is_noop", None) and provider.pin_is_noop())
    except Exception:
        return False


def ensure_proxy(switcher) -> tuple[int, Path] | None:
    """Make sure a pin proxy is serving for the pinned account.

    Returns ``(port, ca_path)`` to wire into the child env, or ``None`` when
    no pin is set (or the pinned account no longer exists — a dangling pin
    must never block a launch). Reuses a live daemon recorded in
    ``<backup>/pin-proxy/proxy.port`` (one proxy shared across sessions);
    otherwise spawns one.
    """
    from claude_swap.exceptions import AccountNotFoundError, ConfigError

    pin = load_pin(switcher.backup_dir)
    if not pin:
        return None
    email, _org = pin
    try:
        account_num, email, _ = switcher.resolve_account(email)
    except (AccountNotFoundError, ConfigError):
        return None
    certdir = switcher.backup_dir / "pin-proxy"
    certdir.mkdir(parents=True, exist_ok=True)
    # Re-stamp the egress proxy on EVERY launch, before any reuse decision.
    # This is what makes the daemon follow the environment instead of the
    # environment that happened to exist when it spawned: a wrapper that sets
    # a proxy, one that moved ports, or one that went away entirely.
    write_upstream_hint(
        certdir,
        _ambient_proxy(certdir=certdir),
        os.environ.get("NODE_EXTRA_CA_CERTS"),
    )
    fp = daemon_fingerprint(account_num, email)

    ca = certdir / "ca.pem"
    # Generate the CA here rather than leaving it to the daemon: publishing has
    # to happen before the client is exec'd, and on the very first launch the
    # daemon has not run yet, so there would be nothing to publish. ensure_ca is
    # idempotent, so this only ever does work once.
    try:
        ensure_ca(certdir, UPSTREAM_HOST)
    except Exception:
        pass
    # Publish on EVERY launch, not only when another CA happens to be in play.
    # A launcher builds its merged bundle from this directory as it starts us,
    # so a CA published later would miss that build, and a component whose cert
    # dir was wiped must reappear on the next launch rather than stay silently
    # absent.
    publish_ca(ca)

    # Fast path (no lock): a fresh, current daemon is reused as-is.
    port = _read_alive_port(certdir, fingerprint=fp)
    if port is not None:
        wire_global_config(port, ca)
        return port, ca

    # Slow path: take an exclusive lock so concurrent launches elect ONE
    # spawner (CCF's mkdir election). Re-check under the lock — another launch
    # may have spawned while we waited.
    with _spawn_lock(certdir):
        port = _read_alive_port(certdir, fingerprint=fp)
        if port is not None:
            wire_global_config(port, ca)
            return port, ca
        # A daemon exists but is stale (wrong account, or redeployed code) —
        # recycle it before spawning, so a redeploy/repin takes effect instead
        # of a stale daemon serving forever.
        stale = read_daemon_state(certdir)
        if stale and _pid_alive(int(stale["pid"])):
            # Save the port BEFORE the kill: the daemon unlinks its own state
            # on TERM, so afterwards there is nothing left to reclaim from and
            # the successor would take a fresh port — stranding every session
            # already wired to the old one.
            if isinstance(stale.get("port"), int):
                _write_port_hint(certdir, stale["port"])
            _kill_daemon(int(stale["pid"]))
        port = _spawn_daemon(account_num, email, certdir)
        if port is None:
            # The spawn failed. Anything still wired in .claude.json may name a
            # port nothing serves, and Claude Code applies that block at boot —
            # so a stale entry would take the SESSION down, not just the pin.
            #
            # unwire_if_dead re-checks liveness itself and leaves a SERVING
            # daemon alone, which matters here: "our spawn failed" is not the
            # same as "nothing is serving". A concurrent launch may have won
            # the race and started one, and a spawn can fail precisely because
            # a healthy daemon already owns the port.
            unwire_if_dead(certdir)
            return None
    # Re-point hand-launched sessions at the port that is actually serving.
    # Done on every launch, not just on pin: an idle teardown followed by a
    # respawn would otherwise leave .claude.json naming a dead port, and a
    # session wired to a dead port leaves WITHOUT the pin instead of failing.
    wire_global_config(port, ca)
    return port, ca


def _spawn_lock(certdir: Path):
    """Exclusive file lock serializing daemon spawns (one elected spawner)."""
    import fcntl
    from contextlib import contextmanager

    @contextmanager
    def _locked():
        lockf = open(Path(certdir) / ".spawn.lock", "w")
        try:
            fcntl.flock(lockf, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(lockf, fcntl.LOCK_UN)
            finally:
                lockf.close()

    return _locked()


def _kill_daemon(pid: int) -> None:
    """TERM a daemon, then escalate to KILL if it does not exit — so a daemon
    that ignores TERM (or hangs mid-teardown) never lingers as an orphan
    holding a port. Mirrors CCF's recycle_supervisor bounded-wait-then-force."""
    import time

    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError:
        return
    for _ in range(20):  # up to ~2s for a clean exit
        if not _pid_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)  # SIGKILL escalation
    except OSError:
        return
    for _ in range(10):  # up to ~1s for the port to actually free
        if not _pid_alive(pid):
            return
        time.sleep(0.1)


def _pin_daemon_pids(certdir: Path) -> list[int]:
    """Pids of every running pin_proxy daemon serving THIS certdir. Matched on
    the daemon's argv (``-m claude_swap.pin_proxy ... <certdir>``) via ps, so a
    daemon for another backup dir is never touched."""
    import subprocess

    target = str(Path(certdir).resolve())
    pids: list[int] = []
    try:
        out = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            capture_output=True, text=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return pids
    for line in out.splitlines():
        line = line.strip()
        if "claude_swap.pin_proxy" not in line:
            continue
        if target not in line:
            continue
        head = line.split(None, 1)[0]
        try:
            pids.append(int(head))
        except ValueError:
            continue
    return pids


def _sweep_orphan_daemons(certdir: Path, keep_pid: int) -> None:
    """Kill every pin_proxy daemon for ``certdir`` except ``keep_pid`` — orphans
    that fell out of proxy.json (a redeploy/recycle replaced them but they
    didn't die) hold ports and never idle-teardown. Best-effort; never raises."""
    for pid in _pin_daemon_pids(certdir):
        if pid != keep_pid and pid != os.getpid():
            _kill_daemon(pid)


def _install_signal_teardown(cleanup) -> None:
    """Register SIGTERM/SIGINT so a recycle/cc-update TERM runs ``cleanup``
    (stop the server, remove the state file) instead of a bare default kill —
    the daemon leaves no stale state or bound port behind."""
    import signal

    def _handler(signum, frame):
        try:
            cleanup()
        finally:
            os._exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # not on the main thread (tests) — best effort


_STATE_FILE = "proxy.json"
_FIFO_NAME = "refcount.fifo"
_LOG_NAME = "daemon.log"
_LOG_MAX_BYTES = 64 * 1024


def refcount_fifo_path(certdir: Path) -> Path:
    """Path of the refcount FIFO. Sessions hold a write fd on it; the daemon
    reads it and exits when the last holder closes (CCF's FIFO refcount)."""
    return Path(certdir) / _FIFO_NAME


def daemon_log_path(certdir: Path) -> Path:
    """Where the detached daemon's stderr goes.

    The daemon has no terminal, so a warning it writes to stderr reaches
    nobody unless it is given a destination here. Measured on three machines:
    with ``stderr=DEVNULL`` every fail-open was silent by construction, which
    is precisely what :meth:`PinProxy._warn_unpinnable` exists to prevent.
    """
    return Path(certdir) / _LOG_NAME


def _open_daemon_log(certdir: Path):
    """Open :func:`daemon_log_path` for append, or fall back to DEVNULL.

    Truncates once it passes ``_LOG_MAX_BYTES`` — a daemon that cannot mint
    warns once per process, but nothing stops a supervisor respawning it, and
    an unbounded log in the cert dir is its own defect. Returns a file object
    the caller owns; a directory that cannot be written degrades to discarding
    output rather than failing the spawn, because a pin must never block a
    launch.
    """
    import subprocess

    path = daemon_log_path(certdir)
    try:
        if path.exists() and path.stat().st_size > _LOG_MAX_BYTES:
            path.unlink()
        return open(path, "a", buffering=1, encoding="utf-8", errors="replace")
    except OSError:
        return subprocess.DEVNULL


_FIRST_HOLDER_TIMEOUT = 300.0


def _is_claimed(certdir: Path) -> bool:
    """True when the global wiring names THIS daemon, holder or no holder.

    A FIFO holder is not the only way to claim a daemon, and it is not even the
    common one. Only ``wire_env`` and ``pin-env`` open the refcount FIFO; the
    ``.claude.json`` env block — the path every hand-launched ``claude`` takes
    — routes a session through the pin without ever touching it. So a healthy,
    fully-used daemon sits at ZERO holders indefinitely: measured on linux,
    daemon 4035232 serving 36301 for 1d17h with not one holder anywhere in
    ``/proc/*/fd``. To the first-holder timeout that is indistinguishable from
    the orphan it exists to reap, and it would tear the live pin down.

    The wiring itself is the missing claim. If ``.claude.json`` points sessions
    at our port, we are the thing they are pointed at, and that is a reference
    whether or not anyone opened the FIFO. It also separates the two
    populations exactly: a crashed spawn or a killed test leaves a daemon on a
    certdir nothing was ever wired to, so those still time out as before.
    """
    try:
        st = read_daemon_state(certdir)
        if not st or int(st["pid"]) != os.getpid():
            return False  # not our record — say nothing about our own liveness
        return _wired_port() == int(st["port"])
    except Exception:
        return False


def watch_refcount(
    fifo: str | Path, on_last_holder_gone, first_holder_timeout: float | None = None
) -> None:
    """Block on ``fifo`` until every write-holder closes, then call
    ``on_last_holder_gone``. This is exactly CCF's supervisor `cat FIFO`:
    a READ-ONLY open blocks until the first writer appears, and the subsequent
    read returns EOF (b"") only once all writer fds have closed. A read-only
    reader must NOT also hold a write end (that would mask EOF), which is why
    sessions open O_RDWR while the daemon opens read-only here.

    A daemon that NEVER gets a first holder must still die. The read-only open
    blocks forever when no writer ever appears, and "forever" is not a corner
    case: it is what happens whenever a daemon is spawned and its session dies
    before attaching (a crash between spawn and attach, a killed test). The
    process then holds its port and never idle-teardowns — measured, three such
    daemons left over from one test run, each on a ``/tmp/pytest-*`` certdir the
    per-certdir orphan sweep deliberately cannot see.

    So the FIRST open is bounded: O_NONBLOCK returns immediately (EOF-looking,
    not blocking) instead of parking forever, and we poll for a writer up to
    ``first_holder_timeout``. Once a holder has attached we switch to the
    blocking semantics above, which are the ones that give a correct EOF.
    Timeout with no holder AND no wiring claiming us => tear down, exactly as
    if the last holder left. The wiring check is not optional: zero holders is
    the STEADY STATE of a healthy daemon serving globally wired sessions, so
    without it this timeout kills the working pin (see ``_is_claimed``).
    """
    timeout = _FIRST_HOLDER_TIMEOUT if first_holder_timeout is None else first_holder_timeout
    # O_NONBLOCK on a read-only FIFO open never blocks (POSIX), so this cannot
    # park the way the plain open did. select() then tells us when a writer has
    # actually attached; before that a read would just return EOF forever.
    fd = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
    try:
        import select
        import time as _time

        # Detect a holder by REOPENING for write, never by reading. A holder
        # that attaches and stays silent — which is the normal case, the fd IS
        # the reference — writes nothing, so waiting for bytes reports "no
        # holder" for a session that is perfectly alive and tears it down.
        # (Caught by test_daemon_exits_when_all_holders_close.)
        #
        # O_WRONLY|O_NONBLOCK on a FIFO succeeds only while a READER is open,
        # and we are that reader, so it always succeeds here and says nothing.
        # The usable signal is the opposite one: with our read fd open, a
        # non-blocking read returns EOF (b"") when there is no writer and
        # EAGAIN when a writer exists but has sent nothing. EAGAIN is exactly
        # "a holder is attached and quiet".
        deadline = _time.monotonic() + timeout
        while True:
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                break  # writer present, no data — a live silent holder
            if data != b"":
                break  # writer present and chatty (an attach ping)
            # EOF: no writer at all yet.
            if _time.monotonic() >= deadline:
                # ...which is NOT the same as "nobody is using me". A globally
                # wired session never opens the FIFO, so check the wiring
                # before concluding we are an orphan (see ``_is_claimed``).
                if _is_claimed(Path(fifo).parent):
                    deadline = _time.monotonic() + timeout  # re-arm and re-check
                    continue
                on_last_holder_gone()  # nobody ever attached — do not linger
                return
            select.select([fd], [], [], 0.05)
        # Back to blocking reads: with a writer present, EOF now means what the
        # refcount needs it to mean (every holder closed), which a non-blocking
        # read cannot distinguish from "no data yet".
        os.set_blocking(fd, True)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        while True:
            data = os.read(fd, 65536)  # blocks; returns b"" at EOF (no writers)
            if data == b"":
                on_last_holder_gone()
                return
            # A holder wrote an attach ping; drain and keep waiting.
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


_SECRET_FILE = "proxy.secret"


def proxy_secret_path(certdir: Path) -> Path:
    """Where the daemon's proxy credential lives (0600, in the cert dir)."""
    return Path(certdir) / _SECRET_FILE


def read_proxy_secret(certdir: Path) -> str | None:
    """The daemon's proxy credential, or None when it has none.

    None means "this daemon predates the credential" and every caller must
    treat it as no-auth-required. A pin that starts rejecting traffic after an
    upgrade is a worse failure than the one the credential prevents.
    """
    try:
        val = proxy_secret_path(certdir).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return val or None


def ensure_proxy_secret(certdir: Path) -> str:
    """Mint (once) the credential a client must present to use this proxy.

    THE PROBLEM: the daemon listens on unauthenticated loopback and swaps the
    Authorization header of any request matching a pinned route. Loopback
    carries no identity — the kernel does not check uid on a TCP connect — so
    any process that can reach the port can CONNECT to api.anthropic.com with
    a junk bearer and receive one minted from the pinned account's real
    credential. cswap's own store is 0700/0600 precisely so that credential
    cannot be read; the proxy hands out its effect to anyone who asks.

    Loopback is not the boundary people assume. On a single-user laptop the
    exposure is other processes running AS that user, which is a smaller
    step-up than it sounds (a sandboxed tool, a compromised npm postinstall,
    any code the user runs but does not trust with their Claude account). On a
    shared or multi-account host it is other logins outright. Neither is
    covered by file permissions, because the port is not a file.

    So: a per-daemon secret, written 0600 next to the CA key that already
    lives at 0600, and handed to clients through the same wiring that already
    tells them the port. A client that can read the secret is a client that
    could read the cert dir anyway — the credential adds nothing for an
    attacker who already has that, and everything against one who does not.

    Idempotent: an existing secret is reused, so a respawn does not invalidate
    the wiring live sessions are already using.
    """
    import secrets

    path = proxy_secret_path(certdir)
    existing = read_proxy_secret(certdir)
    if existing:
        return existing
    token = secrets.token_urlsafe(32)
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    try:
        # 0600 from creation, never briefly world-readable: the umask decides
        # the mode of a plain write, and a 022 umask would publish this at
        # 0644 in the window before any chmod.
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, token.encode("ascii"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        # Cannot persist it — fail OPEN rather than block the pin. An
        # unauthenticated proxy is the status quo; a proxy nobody can use is a
        # regression.
        try:
            tmp.unlink()
        except OSError:
            pass
        return ""
    return token


def _proxy_authorized(headers: list[tuple[str, str]], secret: str | None) -> bool:
    """Whether a CONNECT may use this proxy.

    No secret configured => authorized, so a daemon from before this change
    (or one that could not write its secret) keeps serving. Comparison is
    constant-time; the value is a bearer for the pinned account in all but
    name.
    """
    import hmac

    if not secret:
        return True
    for key, value in headers:
        if key.lower() != "proxy-authorization":
            continue
        scheme, _, param = value.partition(" ")
        if scheme.lower() != "basic":
            continue
        try:
            decoded = base64.b64decode(param.strip(), validate=True).decode(
                "utf-8", "replace"
            )
        except Exception:
            continue
        # user:pass — the secret is the password; the user part is cosmetic.
        _, _, presented = decoded.partition(":")
        if hmac.compare_digest(presented, secret):
            return True
    return False


_PORT_HINT_FILE = "port.hint"


def _write_port_hint(certdir: Path, port: int) -> None:
    """Remember the port to rebind across a respawn (see ``_spawn_daemon``)."""
    try:
        (Path(certdir) / _PORT_HINT_FILE).write_text(str(port))
    except OSError:
        pass


def read_port_hint(certdir: Path) -> int | None:
    """The port a previous daemon served on, recorded across its teardown.

    ``proxy.json`` is deleted before a respawn (a stale record must never read
    as live), so the port to reclaim is carried here instead.
    """
    try:
        return int((Path(certdir) / _PORT_HINT_FILE).read_text().strip())
    except (OSError, ValueError):
        return None


def write_daemon_state(certdir: Path, port: int, pid: int, fingerprint: str) -> None:
    """Record the live daemon's identity atomically (temp-then-rename)."""
    import json

    tmp = Path(certdir) / f"{_STATE_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps({"port": port, "pid": pid, "fingerprint": fingerprint}))
    os.replace(tmp, Path(certdir) / _STATE_FILE)


def read_daemon_state(certdir: Path) -> dict | None:
    """The recorded daemon state (``{port, pid, fingerprint}``), or None if the
    file is absent or corrupt."""
    import json

    try:
        data = json.loads((Path(certdir) / _STATE_FILE).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "port" not in data or "pid" not in data:
        return None
    return data


def daemon_fingerprint(account_num: str = "", email: str = "") -> str:
    """Identity of the daemon's CODE, so a redeploy of pin_proxy.py makes a
    running daemon stale and the launcher recycles it — mirrors CCF's
    fingerprint staleness (cachefix-ensure).

    The pinned account is deliberately NOT part of this. It is re-read per
    request (see :func:`make_pin_token_provider`), so re-pinning takes effect
    under a live daemon; including it here would recycle the daemon on every
    `cswap pin`, and a recycle is exactly what a live session should not need.
    The parameters are kept for call-site compatibility and ignored.
    """
    import hashlib

    try:
        code_mtime = os.stat(__file__).st_mtime_ns
    except OSError:
        code_mtime = 0
    return hashlib.sha256(str(code_mtime).encode()).hexdigest()[:16]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_alive_port(certdir: Path, fingerprint: str | None = None) -> int | None:
    """Port of a live recorded daemon whose pid is alive, its port answers, and
    (when ``fingerprint`` is given) its fingerprint matches. Else None."""
    st = read_daemon_state(certdir)
    if not st:
        return None
    if fingerprint is not None and st.get("fingerprint") != fingerprint:
        return None
    if not _pid_alive(int(st["pid"])):
        return None
    try:
        with socket.create_connection(("127.0.0.1", int(st["port"])), timeout=1):
            return int(st["port"])
    except OSError:
        return None


def _spawn_daemon(account_num: str, email: str, certdir: Path) -> int | None:
    """Start the proxy daemon detached; wait for its state file. None on failure.

    Creates the refcount FIFO up front so a session can attach a holder the
    instant the daemon comes up (no gap where the daemon sees zero holders and
    tears itself down).
    """
    import subprocess
    import sys
    import time

    certdir = Path(certdir)
    # Hand the outgoing port to the new daemon before clearing the state it
    # lives in: it rebinds that port so live sessions — whose HTTPS_PROXY was
    # fixed at exec — keep reaching the proxy instead of a dead address (and
    # a session on a dead address leaves WITHOUT the pin, silently).
    prev = read_daemon_state(certdir)
    if isinstance(prev, dict) and isinstance(prev.get("port"), int):
        _write_port_hint(certdir, prev["port"])
    for f in (certdir / _STATE_FILE, certdir / "proxy.port"):
        try:
            f.unlink()
        except FileNotFoundError:
            pass
    fifo = refcount_fifo_path(certdir)
    if not fifo.exists():
        try:
            os.mkfifo(fifo)
        except FileExistsError:
            pass
    # stderr goes to a file, not DEVNULL: the daemon is detached and has no
    # terminal, so _warn_unpinnable would otherwise write into nothing and
    # every fail-open would stay silent — the exact outcome that warning
    # exists to prevent. stdout stays discarded; the daemon prints nothing
    # there and a log that also carries chatter buries the one line worth
    # reading.
    log = _open_daemon_log(certdir)
    try:
        subprocess.Popen(
            [sys.executable, "-m", "claude_swap.pin_proxy", account_num, email, str(certdir)],
            stdout=subprocess.DEVNULL,
            stderr=log,
            start_new_session=True,
        )
    finally:
        # The child holds its own dup of the fd; ours would otherwise leak on
        # every spawn.
        if hasattr(log, "close"):
            log.close()
    for _ in range(100):  # up to ~10s (first run generates RSA keys)
        port = _read_alive_port(certdir)
        if port is not None:
            # New daemon is serving and recorded in proxy.json — sweep any
            # orphan pin daemons for this certdir that aren't the keeper, so a
            # recycle that left the old one alive never accumulates.
            st = read_daemon_state(certdir)
            keep = int(st["pid"]) if st else -1
            _sweep_orphan_daemons(certdir, keep_pid=keep)
            return port
        time.sleep(0.1)
    return None


def daemon_main(account_num: str, email: str, certdir: Path) -> None:
    """Entry point for the detached proxy process (``-m claude_swap.pin_proxy``).

    Chains through whatever egress proxy the most recent launch recorded in
    ``upstream.json`` (corporate, another local MITM, or none), re-read per
    connection so a proxy
    that restarts on another port is followed rather than bypassed. Records
    ``proxy.json`` (port/pid/fingerprint) once listening, serves a ``/health``
    probe, and self-terminates when the last refcount holder closes the FIFO
    (idle teardown).
    """
    from claude_swap.switcher import ClaudeAccountSwitcher

    certdir = Path(certdir)
    switcher = ClaudeAccountSwitcher()
    # NOT minted here. A daemon respawn (a fingerprint recycle, a deploy) must
    # not be able to turn the gate on: a live session's HTTPS_PROXY is fixed at
    # exec time, so a session wired before the credential existed carries a URL
    # without one and would start getting 407 on its next request — the upgrade
    # cutting off the very sessions it protects. Measured on linux before
    # landing this: .claude.json wired "http://127.0.0.1:36301" (no userinfo)
    # with pid 142172 live on it.
    #
    # ``apply_pin`` mints it instead, so the gate arms exactly when the wiring
    # is rewritten to carry it. PinProxy only ever READS the value.
    proxy = PinProxy(
        certdir=certdir,
        pin_token_provider=make_pin_token_provider(switcher, account_num, email),
        rediscover_chain=True,
    )
    proxy.start()
    write_daemon_state(
        certdir, proxy.port, os.getpid(), daemon_fingerprint(account_num, email)
    )

    fifo = refcount_fifo_path(certdir)
    if not fifo.exists():
        try:
            os.mkfifo(fifo)
        except FileExistsError:
            pass

    done = threading.Event()

    def _teardown():
        # Last session closed its holder (or a signal arrived) — stop serving
        # and clean up our state so a launcher never reuses a dead record.
        proxy.stop()
        try:
            (certdir / _STATE_FILE).unlink()
        except OSError:
            pass
        # Put ``.claude.json`` back the way we found it. Without this the env
        # block keeps naming the port we just stopped serving, and Claude Code
        # applies that block at boot — so EVERY session started afterwards
        # dials a dead proxy and retries forever, with privoxy and the cache
        # proxy both healthy and unreachable behind it. Measured on work-mac:
        # "Unable to connect to API (ConnectionRefused), attempt 14/300", and
        # the only cure was a human re-pinning by hand.
        #
        # An optional feature must not be able to take the required path down
        # with it. wire_global_config(None, None) restores whatever proxy the
        # user or their launcher had before we wrote ours, which is exactly
        # what `pin --clear` already does — the call simply never ran on the
        # path where the daemon goes away by itself.
        try:
            wire_global_config(None, None)
        except Exception:
            pass  # teardown is best-effort; never raise on the way out
        done.set()

    # A recycle/cc-update TERM runs the same cleanup as an idle teardown.
    _install_signal_teardown(_teardown)

    threading.Thread(
        target=watch_refcount, args=(fifo, _teardown), daemon=True
    ).start()
    done.wait()  # lives until the last refcount holder closes (or a signal)


def wire_env(
    env: dict[str, str],
    port: int,
    ca_path: Path,
    open_refcount: bool = True,
) -> dict[str, str]:
    """Return a copy of ``env`` routed through the pin proxy.

    Sets ``HTTPS_PROXY``/``https_proxy`` to the proxy and makes Node trust our
    MITM CA. Node's ``NODE_EXTRA_CA_CERTS`` takes exactly one file, so when the
    session already trusts another CA (a corporate MITM, another local proxy)
    the two PEMs are merged into
    ``<ca dir>/ca-bundle.pem`` — never replaced.

    ``open_refcount`` controls the refcount holder. In-process callers
    (session.py, which execs claude and hands off its own fds) pass True: we
    open an inheritable write fd on the FIFO here so the exec'd claude keeps it.
    The shell path (pin-env) passes False — the SHELL must open the fd (this
    process exits immediately, so a fd we opened would close and tear the daemon
    down at once); pin-env emits the `exec {fd}<>fifo` for the shell instead.
    """
    out = dict(env)
    # Same derivation as the global config path: the CA's directory is the
    # cert dir, which holds the proxy credential.
    proxy = _proxy_url(port, Path(ca_path).parent)
    out["HTTPS_PROXY"] = proxy
    out["https_proxy"] = proxy
    # Rewrite an ALL_PROXY the caller already had; never create one. It is a
    # fallback consulted only when the scheme-specific vars are absent (curl,
    # measured: https_proxy=A + ALL_PROXY=B dials A), and we always set those
    # — so an absent one costs nothing, while a launcher's own would name the
    # hop we chain through and read as a contradiction. Creating one here
    # would be worse than useless: this env can be eval'd into the user's
    # SHELL (pin-env), where an ALL_PROXY we invented would send that shell's
    # git, uv and gh through an account-pinning MITM built for one client.
    for key in ("ALL_PROXY", "all_proxy"):
        if key in out:
            out[key] = proxy
    # Marks this env as already pinned, so a nested launch records the proxy
    # we chain THROUGH as upstream rather than us (see _ambient_proxy).
    out["CSWAP_PIN_PORT"] = str(port)
    out["NODE_EXTRA_CA_CERTS"] = str(
        _trust_file(ca_path, env.get("NODE_EXTRA_CA_CERTS"))
    )

    # Attach this launch as a refcount holder: open a write fd on the FIFO and
    # mark it inheritable so the exec'd claude keeps it open for its lifetime.
    # The daemon's reader sees EOF only when every such fd closes → idle
    # teardown. O_RDWR so the open never blocks even if the daemon died.
    fifo = refcount_fifo_path(Path(ca_path).parent)
    out["CSWAP_PIN_FIFO"] = str(fifo)
    if open_refcount and fifo.exists():
        try:
            fd = os.open(str(fifo), os.O_RDWR)
            os.set_inheritable(fd, True)
            out["CSWAP_PIN_REFCOUNT_FD"] = str(fd)
        except OSError:
            pass
    return out


UPSTREAM_HOST = "api.anthropic.com"
UPSTREAM_PORT = 443


class PinProxy:
    """A CONNECT forward proxy that MITMs api.anthropic.com and swaps the
    Authorization bearer to a pinned token on the RC/Artifact routes.

    Non-anthropic CONNECTs are blind-tunnelled (optionally through the upstream
    proxy that was on HTTPS_PROXY before us). The anthropic connection is
    terminated with our leaf cert, the decrypted request is inspected, and —
    on a pinned route — its Authorization is replaced before being re-issued
    to the real upstream over TLS.
    """

    def __init__(
        self,
        certdir: Path,
        pin_token_provider: "Callable[[], str | None]",
        upstream: tuple[str, int] | None = None,
        chain_proxy: tuple[str, int] | None = None,
        host: str = "127.0.0.1",
        rediscover_chain: bool = False,
    ):
        self._certdir = Path(certdir)
        self._pin_token_provider = pin_token_provider
        # Where the MITM'd anthropic request is really sent. Defaults to the
        # real upstream; tests point it at a fake server.
        self._upstream = upstream or (UPSTREAM_HOST, UPSTREAM_PORT)
        # A proxy to CONNECT through for egress (a corporate proxy, another
        # local MITM). Fixed when rediscover_chain is False (tests); otherwise
        # re-read from the on-disk hint per connection, so the daemon follows
        # an egress proxy that moved or came up after it did.
        self._chain = chain_proxy
        self._rediscover_chain = rediscover_chain
        self._host = host
        # The credential a client must present on CONNECT. Read, never minted,
        # here: the daemon entry point mints it before wiring so the value the
        # clients are handed and the value we check are the same one. Empty or
        # missing => no auth required (a pre-upgrade daemon, or a cert dir we
        # could not write) — see ``ensure_proxy_secret``.
        self._secret = read_proxy_secret(self._certdir)
        self._bundle = ensure_ca(self._certdir, UPSTREAM_HOST)
        self._server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._server_ctx.load_cert_chain(
            str(self._bundle.leaf_path), str(self._bundle.leaf_key_path)
        )
        self._srv: socket.socket | None = None
        # Per-connection upstream socket. Each MITM connection is served on
        # its own thread, so a thread-local keeps one upstream per client.
        self._local = threading.local()
        self._conn_seq = itertools.count(1)
        self._stop = False
        self.port = 0
        # Opt-in request tracing: CSWAP_PIN_DEBUG=<path> logs one line per
        # request (method, path, whether it matched a pinned route and was
        # swapped). Off by default; used to diagnose routing end to end.
        debug_path = os.environ.get("CSWAP_PIN_DEBUG")
        self._debug = open(debug_path, "a") if debug_path else None

    def start(self) -> None:
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Reclaim the port a previous daemon recorded, when it is free. A
        # running session's HTTPS_PROXY is fixed at exec time, so coming back
        # on a fresh port strands every live session on a dead one — and its
        # requests then leave WITHOUT the pin instead of failing loudly
        # (measured: an RC session created that way was owned by the active
        # account while the pin still looked healthy).
        prev = read_daemon_state(self._certdir)
        want = prev.get("port") if isinstance(prev, dict) else None
        if not isinstance(want, int):
            # A respawn deletes proxy.json before starting us, so the port to
            # reclaim arrives via the hint the spawner left instead.
            want = read_port_hint(self._certdir)
        for candidate in ([want] if isinstance(want, int) and want > 0 else []) + [0]:
            try:
                self._srv.bind((self._host, candidate))
                break
            except OSError:
                continue  # taken by something else — fall through to an
                          # ephemeral port
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self._stop = True
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass

    # -- internals ----------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle_client, args=(conn,), daemon=True
            ).start()

    def _handle_client(self, conn: socket.socket) -> None:
        # A per-CONNECTION id, not a thread id: threads are pooled and reused,
        # so tagging with get_ident() made two sequential connections share a
        # tag and the log could no longer pair a request with its response —
        # which read as "this request never answered" and sent a live
        # investigation down the wrong path twice. Assigned here rather than in
        # _mitm so a blind tunnel gets one too, on the same counter.
        self._local.cid = next(self._conn_seq)
        try:
            line = _read_line(conn)
            if not line:
                conn.close()
                return
            parts = line.split(" ")
            if parts[0] == "CONNECT":
                target = parts[1]  # host:port
                # Keep the CONNECT headers rather than draining them: the
                # proxy credential arrives here and nowhere else.
                connect_headers: list[tuple[str, str]] = []
                while True:
                    h = _read_line(conn)
                    if h in ("", None):
                        break
                    if ":" in h:
                        k, v = h.split(":", 1)
                        connect_headers.append((k.strip(), v.strip()))
                # A caller that cannot present the credential gets nothing —
                # not the MITM (which would mint a bearer for it) and not the
                # blind tunnel (which would make us an open forward proxy for
                # any host). See ``ensure_proxy_secret``.
                if not _proxy_authorized(connect_headers, self._secret):
                    self._refuse_unauthorized(conn)
                    return
                host = target.rsplit(":", 1)[0]
                if host != UPSTREAM_HOST:
                    self._blind_tunnel(target, conn)
                    return
                self._mitm(conn)
                return
            if len(parts) >= 2 and parts[1].startswith("/health"):
                # Local health probe (origin-form GET /health to our own port).
                # Lets a statusline/cc-update probe tell the pin proxy apart
                # from another local proxy and read the chain it forwards to.
                self._serve_health(conn)
                return
            if len(parts) >= 2 and "://" in parts[1]:
                # Absolute-form request (plain-proxy mode, no CONNECT). The
                # native auto-updater and telemetry use axios this way; dropping
                # them is what pins the "Auto-update failed" banner. Relay
                # verbatim through the chain — no MITM, no swap.
                self._plain_relay(line, conn)
                return
            conn.close()
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    def _refuse_unauthorized(self, conn: socket.socket) -> None:
        """407 a CONNECT that did not present the proxy credential.

        407 rather than a silent close so a misconfigured client says what is
        wrong instead of retrying forever against a proxy that looks dead —
        that failure mode cost a day when a dead port produced
        "ConnectionRefused, attempt 14/300" and nothing named the cause.
        """
        try:
            conn.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Basic realm="cswap-pin"\r\n'
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

    def _warn_unpinnable(self) -> None:
        """Say once, on stderr, that the pin is not being applied.

        The swap fails open on purpose, so nothing else marks this: requests
        keep succeeding, the daemon keeps answering /health, and the only
        visible consequence arrives later as Remote Control sessions owned by
        the wrong account with no way to transfer them. Measured: a daemon that
        could not reach its credential store served every pinned route
        unswapped and 19 sessions had to be rebuilt by hand.

        Once per daemon, not per request — a pinned session makes these calls
        continuously and a line each would bury the signal it is meant to be.
        """
        if getattr(self, "_warned_unpinnable", False):
            return
        self._warned_unpinnable = True
        try:
            sys.stderr.write(
                "cswap pin: the pinned account's token could not be read, so "
                "requests are going out UNPINNED. Remote Control sessions "
                "created now will belong to the active account permanently. "
                "On macOS this is usually a daemon started outside the GUI "
                "session, which cannot read the keychain; re-run `cswap pin` "
                "from a normal terminal.\n"
            )
            sys.stderr.flush()
        # Only a broken stderr — a bare `except Exception` here swallowed a
        # missing import and left the warning silently dead, which is the same
        # class of bug this warning exists to surface.
        except OSError:
            pass

    def _serve_health(self, conn: socket.socket) -> None:
        import json

        # Report the chain the relay would actually use, not the one this
        # daemon was constructed with — those diverge the moment the egress
        # proxy moves, and a health probe that says "no chain" while every
        # request goes through one sends the next diagnosis the wrong way.
        current = self._current_chain()
        chain = f"{current[0]}:{current[1]}" if current else None
        # Whether the pin can actually be APPLIED, not merely that a daemon is
        # up. The swap fails open by design — a request whose token cannot be
        # minted still goes out, on the disk bearer — so a daemon that cannot
        # read its own credential store serves unpinned traffic while every
        # visible signal stays green. Measured: a daemon started over ssh
        # cannot reach the macOS keychain, and 13 of 13 pinned routes went out
        # unswapped; the RC sessions born in that window are owned by the
        # active account forever, and nothing said so.
        #
        # "No token" is not the same as "cannot mint one". With the pinned
        # account already active there is deliberately nothing to swap, and
        # reporting can_pin=false there tells a monitor the pin is broken on
        # the one machine where it has nothing to do.
        try:
            can_pin = bool(self._pin_token_provider()) or _pin_is_noop(
                self._pin_token_provider
            )
        except Exception:
            can_pin = False
        body = json.dumps(
            {"pin_proxy": True, "port": self.port, "chain": chain, "can_pin": can_pin}
        )
        try:
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("latin1")
                + body.encode("latin1")
            )
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _plain_relay(self, request_line: str, conn: socket.socket) -> None:
        """Forward an absolute-form proxy request through the chain (or direct).

        Rewrites the request line to origin-form and dials the target host —
        via the chain proxy if one is set (still absolute-form to it, as a
        plain proxy expects), else straight to the origin.
        """
        rl = request_line.split(" ")
        method, url = rl[0], rl[1] if len(rl) > 1 else "/"
        headers = []
        parsed: list[tuple[str, str]] = []
        while True:
            h = _read_line(conn)
            if h in ("", None):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                parsed.append((k.strip(), v.strip()))
                # Never forward OUR proxy credential onward. This path relays
                # the client's headers verbatim to the chain (CCF, a corporate
                # proxy), which would hand them a working credential for the
                # pinned account's proxy. It is hop-by-hop by definition
                # (RFC 9110): it authenticates to THIS proxy and stops here.
                if k.strip().lower() == "proxy-authorization":
                    continue
            headers.append(h)
        # Same gate as CONNECT: an unauthenticated caller must not be able to
        # use us as a forward proxy just by choosing absolute-form.
        if not _proxy_authorized(parsed, self._secret):
            self._refuse_unauthorized(conn)
            return
        split = urlsplit(url)
        host, port = split.hostname, split.port or 80
        # Re-read like every other egress site: the daemon is constructed with
        # chain_proxy=None, so reading self._chain here meant this path ALWAYS
        # dialled the origin direct — bypassing the egress proxy on exactly the
        # traffic (auto-updater, telemetry) it was added to rescue, and hard
        # failing where there is no direct route out.
        chain = self._current_chain()
        try:
            if chain:
                up = socket.create_connection(chain, timeout=15)
                # A plain proxy takes the absolute-form line as-is.
                head = f"{method} {url} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
            else:
                up = socket.create_connection((host, port), timeout=15)
                path = split.path or "/"
                if split.query:
                    path += "?" + split.query
                head = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        except OSError:
            conn.close()
            return
        try:
            up.sendall(head.encode("latin1"))
            _pump(conn, up)
        finally:
            try:
                up.close()
            except OSError:
                pass

    def _mitm(self, conn: socket.socket) -> None:
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        tls = self._server_ctx.wrap_socket(conn, server_side=True)
        try:
            while True:
                if not self._handle_one_request(tls):
                    break
        finally:
            self._drop_upstream()
            try:
                tls.close()
            except OSError:
                pass

    def _handle_one_request(self, tls: ssl.SSLSocket) -> bool:
        request_line = _read_line(tls)
        if not request_line:
            return False
        _parts = request_line.split(" ")
        method, path = _parts[0], _parts[1] if len(_parts) > 1 else "/"
        headers: list[tuple[str, str]] = []
        while True:
            h = _read_line(tls)
            if h in ("", None):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                headers.append((k.strip(), v.strip()))
        body = _read_body(tls, headers)

        pinned = is_pinned_route(path)
        swapped = False
        if pinned:
            token = self._pin_token_provider()
            if token:
                headers = [
                    (k, f"Bearer {token}") if k.lower() == "authorization" else (k, v)
                    for k, v in headers
                ]
                swapped = True
            else:
                # Fail-open: the request still goes, on the disk bearer. That is
                # deliberate — a pin that cannot resolve must never block work —
                # but it is silent, and silence here is expensive. A Remote
                # Control session created on this path is owned by the ACTIVE
                # account permanently; the server fixes ownership at /bridge and
                # there is no transfer. Measured: a daemon that could not reach
                # the credential store served 13 pinned routes unswapped, and
                # every RC session born in that window had to be recreated by
                # hand. Say it once per daemon so the cause is on the record
                # before the consequence shows up days later.
                #
                # ...unless None is the RIGHT answer. When the pinned account
                # is the active one there is nothing to swap, and warning then
                # trains the reader to disbelieve the warning (see
                # ``pin_is_noop``).
                if not _pin_is_noop(self._pin_token_provider):
                    self._warn_unpinnable()
        if self._debug:
            hdrs = " | ".join(
                f"{k}: {v[:60]}" for k, v in headers
                if k.lower() in (
                    "connection", "upgrade", "accept", "sec-websocket-key",
                    "sec-websocket-version", "cache-control", "content-type",
                )
            )
            self._debug.write(
                f"[c{getattr(self._local, 'cid', 0)}] "
                f"{method} {path} pinned={pinned} swapped={swapped} :: {hdrs}\n"
            )
            self._debug.flush()

        # Opt-in: when CSWAP_PIN_SHAPE names a file, record the message-array
        # SHAPE of a /v1/messages request — role order and content-block types
        # only, never text. A 400 like "role 'system' must precede an
        # 'assistant' message or end the array" is a claim about that order,
        # and the array is assembled at send time, so it exists nowhere on disk:
        # this proxy is the only place it can be observed. Structure alone is
        # enough to locate the offending position and keeps prompt text out of
        # the log.
        shape_path = os.environ.get("CSWAP_PIN_SHAPE")
        if shape_path and body and path.startswith("/v1/messages"):
            try:
                payload = json.loads(body)
                shape = [
                    (m.get("role"),
                     [b.get("type") for b in m["content"]]
                     if isinstance(m.get("content"), list) else "str")
                    for m in (payload.get("messages") or [])
                ]
                with open(shape_path, "a") as fh:
                    fh.write(json.dumps({
                        "cid": getattr(self._local, "cid", 0),
                        "n": len(shape),
                        "roles": [r for r, _ in shape],
                        "head": shape[:4],
                        "tail": shape[-4:],
                        "has_output_config": any(
                            "output_config" in m for m in (payload.get("messages") or [])
                        ),
                    }) + "\n")
            except Exception:
                pass

        keep = self._forward(method, path, headers, body, tls)
        # A client that asked to close gets closed regardless of the upstream.
        for k, v in headers:
            if k.lower() == "connection" and "close" in v.lower():
                keep = False
        return keep

    def _forward(self, method, path, headers, body, client: ssl.SSLSocket) -> bool:
        """Relay one request upstream and stream the response back.

        Returns whether the MITM connection may carry another request. The RC
        worker pipelines heartbeat/poll/stream requests over ONE connection,
        so closing after the first turned every /remote-control into a
        reconnect loop ("Transport closed: server rejected connection") even
        though each individual route swapped correctly.

        The upstream socket is kept open across requests (one upstream
        connection per MITM connection) — reconnecting per request would make
        an SSE stream impossible to hold.
        """
        up = self._upstream_conn()
        try:
            # A WebSocket handshake must keep Connection/Upgrade even though
            # they are hop-by-hop: strip them and the server sees a plain GET
            # and answers 403 — which is exactly how RC failed through this
            # proxy. Detect the upgrade and relay those headers verbatim.
            upgrading = any(
                k.lower() == "upgrade" and v.strip() for k, v in headers
            )
            out = [f"{method} {path} HTTP/1.1".encode("latin1")]
            sent_host = False
            for k, v in headers:
                kl = k.lower()
                if kl.startswith("proxy-"):
                    continue
                if kl in _HOP_BY_HOP and not (
                    upgrading and kl in ("connection", "upgrade")
                ):
                    continue
                if kl == "host":
                    v = UPSTREAM_HOST
                    sent_host = True
                out.append(f"{k}: {v}".encode("latin1"))
            if not sent_host:
                out.append(f"Host: {UPSTREAM_HOST}".encode("latin1"))
            up.sendall(b"\r\n".join(out) + b"\r\n\r\n" + (body or b""))
            self._trace_upgrade = upgrading
            if upgrading:
                # 101 turns the connection into an opaque byte stream (RC's
                # WebSocket): relay the handshake response, then pump both
                # directions until either side closes. Nothing further on this
                # connection is HTTP, so the request loop must end.
                if _relay_upgrade(up, client):
                    _pump(up, client)
                self._drop_upstream()
                return False
            return _relay_response(up, client, getattr(self._local, "cid", 0))
        except (OSError, ssl.SSLError):
            self._drop_upstream()
            return False

    def _upstream_conn(self) -> ssl.SSLSocket:
        """The live upstream TLS socket for this MITM connection, dialing on
        first use. Reused across requests so keep-alive and SSE work."""
        up = getattr(self._local, "up", None)
        if up is None:
            raw = self._connect_upstream()
            up = self._upstream_ctx().wrap_socket(raw, server_hostname=UPSTREAM_HOST)
            self._local.up = up
        return up

    def _drop_upstream(self) -> None:
        up = getattr(self._local, "up", None)
        if up is not None:
            try:
                up.close()
            except OSError:
                pass
            self._local.up = None

    def _upstream_ctx(self) -> ssl.SSLContext:
        """TLS context for the hop to the real api.anthropic.com.

        When we chain through a LOOPBACK proxy (any local MITM), that
        hop re-signs api.anthropic.com with its own CA whose path we can't know
        portably — and it terminates on localhost, having itself verified the
        real upstream. So we skip cert verification for a loopback chain,
        exactly as the real client (Node) does by trusting that CA blindly.
        For a direct dial or a remote proxy, full verification stays on:
        system roots (real cert) + our own CA (test fakes) + any corp CA on
        NODE_EXTRA_CA_CERTS.
        """
        chain = self._current_chain()
        if chain and chain[0] in _LOOPBACK:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        ctx = ssl.create_default_context()
        # Python 3.13+ VERIFY_X509_STRICT rejects a leaf with no Authority Key
        # Identifier; a corp MITM leaf may lack one. Chain-of-trust stays on.
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        ctx.load_verify_locations(cafile=str(self._bundle.ca_path))
        extra = os.environ.get("NODE_EXTRA_CA_CERTS")
        if extra:
            try:
                ctx.load_verify_locations(cafile=extra)
            except (OSError, ssl.SSLError):
                pass
        return ctx

    def _current_chain(self) -> tuple[str, int] | None:
        """The egress proxy to CONNECT through, re-read per connection.

        Not a snapshot: a local egress proxy can restart on another port, or
        come up only after this daemon did. Binding the chain once at spawn
        would leave the daemon bypassing it — and where that proxy is the only
        route out, bypassing it is a hard failure, not a performance note.
        ``rediscover_chain=False`` keeps tests explicit.
        """
        if not self._rediscover_chain:
            return self._chain
        return read_upstream_hint(self._certdir)

    def _connect_upstream(self) -> socket.socket:
        """Dial the upstream (through the chain when there is one).

        The 15s budget covers CONNECTING only. It is cleared before the socket
        carries requests, because ``create_connection``'s timeout stays on the
        socket and would then apply to every read — and the Remote Control
        inbound channel is a LONG POLL that deliberately holds its response
        open until the phone/web sends something. With the timeout left on,
        that poll died every 15s and no inbound message ever reached the CLI,
        while heartbeats (which answer at once) kept succeeding — so the
        session looked healthy and was silently deaf.
        """
        chain = self._current_chain()
        if chain:
            try:
                raw = socket.create_connection(chain, timeout=15)
            except OSError:
                # The recorded chain is gone. The hint is kept across launches
                # that cannot see a proxy (a plain `cswap pin` shell has none),
                # so it cannot expire on its own — fall through to a direct
                # dial rather than failing every request until someone re-pins
                # from a shell that happens to have the new address.
                raw = None
            if raw is not None:
                raw.sendall(
                    f"CONNECT {self._upstream[0]}:{self._upstream[1]} HTTP/1.1\r\n"
                    f"Host: {self._upstream[0]}:{self._upstream[1]}\r\n\r\n".encode(
                        "latin1"
                    )
                )
                status = _read_line(raw)
                while True:
                    h = _read_line(raw)
                    if h in ("", None):
                        break
                if not status or " 200" not in status:
                    raw.close()
                    raise OSError(f"upstream CONNECT failed: {status}")
                raw.settimeout(None)
                return raw
        sock = socket.create_connection(self._upstream, timeout=15)
        sock.settimeout(None)
        return sock

    @staticmethod
    def _tunnel_is_open(up: socket.socket) -> bool:
        """Whether a just-established tunnel is actually carrying, not EOF.

        A CONNECT 200 means the proxy ACCEPTED the request, not that it reached
        the host: privoxy answers optimistically and dials afterwards, closing
        the socket when that dial fails. Peek for a closed read end — no client
        byte has been sent yet, so a readable socket here can only mean EOF.
        Never blocks: a healthy idle tunnel has nothing to read and reports not
        ready, which is exactly the "open" answer.
        """
        try:
            ready, _, _ = select.select([up], [], [], 0.35)
            if not ready:
                return True  # nothing to read == still open, the normal case
            return bool(up.recv(1, socket.MSG_PEEK))
        except OSError:
            return False

    def _blind_tunnel(self, target: str, conn: socket.socket) -> None:
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s else 443
        chain = self._current_chain()
        # Trace the tunnel too. Remote Control receives over a WebSocket to the
        # ingress host the /bridge response names — NOT api.anthropic.com — so
        # it lands here, not in the MITM. Logging only the MITM made an absent
        # inbound channel look identical to a healthy one: the routes CC sends
        # (worker/events, heartbeat) were all 200 in the trace while the
        # channel CC *receives* on left no line at all.
        if _TRACE is not None:
            _TRACE.write(
                f"[c{getattr(self._local, 'cid', 0)}] CONNECT {target} "
                f"tunnelled (no pin: bearer never seen)\n"
            )
            _TRACE.flush()
        up = None
        if chain:
            # Try the chain first, but never let it be the only answer. Remote
            # Control RECEIVES over a WebSocket to the ingress host named in the
            # /bridge response — a host the egress proxy has no rule for, and
            # which a filtering proxy (privoxy with per-domain forwards, a
            # corporate MITM) may refuse outright. Closing here made that
            # refusal invisible: the session kept heartbeating and posting
            # events through the MITM path at 200, the pin still read as
            # applied, and nothing sent from claude.ai ever arrived. Measured
            # on work-mac, where the same session on a machine whose chain let
            # the host through received normally.
            try:
                up = socket.create_connection(chain, timeout=15)
                up.sendall(
                    f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode("latin1")
                )
                status = _read_line(up)
                while True:
                    h = _read_line(up)
                    if h in ("", None):
                        break
                if not status or " 200" not in status:
                    # Refused BY the chain (not a transport failure) — the one
                    # case where a direct dial is both correct and necessary.
                    if _TRACE is not None:
                        _TRACE.write(
                            f"[c{getattr(self._local, 'cid', 0)}] chain refused "
                            f"{target} ({(status or '').strip()}) — dialling direct\n"
                        )
                        _TRACE.flush()
                    up.close()
                    up = None
            except OSError:
                up = None
        if up is not None and not self._tunnel_is_open(up):
            # A 200 is not proof the chain reached the host. privoxy answers
            # CONNECT optimistically and only then dials; when that dial fails
            # it closes, so the tunnel is EOF the instant we look. Measured on
            # work-mac against the RC ingress: "200 Connection established"
            # followed by UNEXPECTED_EOF_WHILE_READING on the first TLS byte.
            # Trusting the status alone made Remote Control silently deaf —
            # everything Claude Code SENDS still went through the MITM path at
            # 200 while the receive channel was a dead socket.
            if _TRACE is not None:
                _TRACE.write(
                    f"[c{getattr(self._local, 'cid', 0)}] chain answered 200 but "
                    f"the tunnel to {target} was already EOF — dialling direct\n"
                )
                _TRACE.flush()
            up.close()
            up = None
        if up is None:
            try:
                up = socket.create_connection((host, port), timeout=15)
            except OSError:
                conn.close()
                return
        # Connect budget only — a tunnel is long-lived by definition, and a
        # read timeout left on it would tear down an idle-but-healthy stream.
        up.settimeout(None)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _pump(conn, up)


_TRACE = (
    open(os.environ["CSWAP_PIN_DEBUG"], "a")
    if os.environ.get("CSWAP_PIN_DEBUG")
    else None
)

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
}


def _read_line(sock) -> str | None:
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            return None if not buf else buf.decode("latin1")
        if b == b"\n":
            if buf.endswith(b"\r"):
                buf.pop()
            return buf.decode("latin1")
        buf += b


def _read_body(sock, headers) -> bytes:
    length = 0
    for k, v in headers:
        if k.lower() == "content-length":
            try:
                length = int(v)
            except ValueError:
                length = 0
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return bytes(body)


def _relay_upgrade(up: ssl.SSLSocket, client: ssl.SSLSocket) -> bool:
    """Relay an upgrade handshake response verbatim; True when it was a 101.

    Headers pass through untouched (Connection/Upgrade included — the client
    needs them to accept the switch), and any bytes already read past the
    header terminator are forwarded so no frame is lost.
    """
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        try:
            chunk = up.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            chunk = b""
        if not chunk:
            return False
        buf += chunk
    if _TRACE is not None:
        _TRACE.write(
            "    <-UPGRADE "
            + bytes(buf).split(b"\r\n\r\n")[0].decode("latin1", "replace")[:400]
            + "\n"
        )
        _TRACE.flush()
    client.sendall(bytes(buf))
    return buf.split(b"\r\n", 1)[0].split(b" ")[1:2] == [b"101"]


def _relay_response(up: ssl.SSLSocket, client: ssl.SSLSocket, cid: int = 0) -> bool:
    """Stream one upstream response to the client; return whether the
    connection may be reused for another request.

    Response framing decides where this response ends, which is what makes
    keep-alive possible at all:

    - ``Content-Length``: exactly that many body bytes.
    - ``Transfer-Encoding: chunked``: until the terminating zero-length chunk.
    - neither (SSE / ``text/event-stream``, or a close-delimited body): pipe
      until EOF, then the connection is spent.

    Bytes are forwarded as they arrive, so an SSE stream reaches the client
    event-by-event instead of being buffered whole.
    """
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        try:
            chunk = up.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            chunk = b""
        if not chunk:
            break
        buf += chunk
    head, sep, rest = bytes(buf).partition(b"\r\n\r\n")
    if not sep:
        return False
    lines = head.split(b"\r\n")
    status_line = lines[0] if lines and lines[0] else b"HTTP/1.1 502 Bad Gateway"
    if _TRACE is not None:
        _TRACE.write(
            f"[c{cid}]     <- "
            f"{status_line.decode('latin1', 'replace')}\n"
        )
        _TRACE.flush()
    out = [status_line]
    length: int | None = None
    chunked = False
    keep = not status_line.startswith(b"HTTP/1.0")
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        kl = k.strip().lower()
        vl = v.strip().lower()
        if kl == b"content-length":
            try:
                length = int(v.strip())
            except ValueError:
                length = None
        elif kl == b"transfer-encoding" and b"chunked" in vl:
            chunked = True
        elif kl == b"connection" and b"close" in vl:
            keep = False
        if kl in _HOP_BY_HOP:
            continue
        out.append(line)
    client.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)

    if chunked:
        return _pipe_chunked(up, client, bytearray(rest)) and keep
    if length is not None:
        remaining = length - len(rest)
        while remaining > 0:
            try:
                chunk = up.recv(min(65536, remaining))
            except (ConnectionResetError, ssl.SSLError, OSError):
                return False
            if not chunk:
                return False
            client.sendall(chunk)
            remaining -= len(chunk)
        return keep
    # No framing: body runs to EOF (SSE and close-delimited replies).
    while True:
        try:
            chunk = up.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        client.sendall(chunk)
    return False


def _pipe_chunked(up: ssl.SSLSocket, client: ssl.SSLSocket, buf: bytearray) -> bool:
    """Forward a chunked body verbatim until the terminating 0-length chunk.

    Parses only enough to find the end of the body (so the next response on
    this connection starts at the right offset); every byte is relayed as-is.
    """
    while True:
        while b"\r\n" not in buf:
            try:
                chunk = up.recv(65536)
            except (ConnectionResetError, ssl.SSLError, OSError):
                return False
            if not chunk:
                return False
            client.sendall(chunk)
            buf += chunk
        line, _, tail = bytes(buf).partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return False
        need = size + 2  # chunk data + trailing CRLF
        buf = bytearray(tail)
        while len(buf) < need:
            try:
                chunk = up.recv(65536)
            except (ConnectionResetError, ssl.SSLError, OSError):
                return False
            if not chunk:
                return False
            client.sendall(chunk)
            buf += chunk
        buf = bytearray(buf[need:])
        if size == 0:
            return True


def _pump(a: socket.socket, b: socket.socket) -> None:
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ)
    sel.register(b, selectors.EVENT_READ)
    try:
        while True:
            for key, _ in sel.select(timeout=60):
                src = key.fileobj
                dst = b if src is a else a
                data = src.recv(65536)
                if not data:
                    return
                dst.sendall(data)
    except OSError:
        return
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

if __name__ == "__main__":  # pragma: no cover — exercised as a subprocess
    import sys as _sys

    daemon_main(_sys.argv[1], _sys.argv[2], Path(_sys.argv[3]))
