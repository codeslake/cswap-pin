"""Account-pin proxy.

A local MITM forward proxy that swaps the ``Authorization`` bearer to a pinned
account's token on the Remote-Control and Artifact routes, so those operations
stay on one account while inference follows whatever cswap has swapped onto
disk. Everything else (inference at ``/v1/messages``, OAuth, telemetry, …) is
relayed untouched, and non-anthropic hosts are blind-tunnelled.

The daemon lifecycle here — fixed port across respawns, FIFO refcount, config
fingerprint, idle teardown — follows the one used by local cache proxies ("the cache proxy"
in the comments below), whose forward-proxy mode solves the same shape of
problem in front of Claude Code. Nothing in this module requires it: a
comment naming a peer implementation cites where a decision came from,
not a dependency.
"""

from __future__ import annotations

import base64
import datetime as _dt
import glob
import itertools
import json
import os
import warnings
import re
import selectors
import select
import socket
import stat
import sys
import ssl
import threading
import time
from dataclasses import dataclass
from typing import NamedTuple
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cswap_pin._host import require

oauth = require("oauth")


class _Chain(NamedTuple):
    """The egress proxy to CONNECT through.

    A ``(host, port)`` NamedTuple so every existing comparison, unpack and
    ``chain[0]`` keeps working, carrying the two things a bare pair threw
    away: the credential the URL supplied, and whether the hop itself is
    TLS. Dropping those sent an unauthenticated cleartext CONNECT to
    authenticated and https:// corporate proxies — 407, or a plaintext dial
    into a TLS port — which breaks ALL pinned traffic in those environments.

    ``socket.create_connection`` takes exactly a 2-tuple, so call sites pass
    ``chain.address`` rather than the chain itself.
    """

    host: str
    port: int
    auth: str | None = None   # value for Proxy-Authorization, already encoded
    tls: bool = False         # the hop to the proxy is itself TLS

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port

    def connect_headers(self) -> str:
        return f"Proxy-Authorization: {self.auth}\r\n" if self.auth else ""


def parse_upstream_proxy(value: str | None) -> _Chain | None:
    """Parse the proxy that was on ``HTTPS_PROXY`` before we displaced it.

    Returns the chain to CONNECT through (a corporate proxy, another local
    MITM, …), or ``None`` when there was none — in which case the proxy dials
    the upstream directly. A bare ``host:port`` (no scheme) is accepted; the
    default port follows the scheme (443 for https, else 80) rather than
    always being 80, which pointed every https:// proxy at the wrong port.
    """
    if not value:
        return None
    split = urlsplit(value if "://" in value else f"//{value}")
    host = split.hostname
    if not host:
        return None
    tls = split.scheme == "https"
    auth = None
    if split.username:
        # userinfo is percent-encoded in a URL; the header carries the
        # decoded bytes.
        raw = f"{unquote(split.username)}:{unquote(split.password or '')}"
        auth = "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return _Chain(host, split.port or (443 if tls else 80), auth, tls)


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


def _probe_next_hop(value: str | None, timeout: float = 1.0) -> str | None:
    """The proxy the recorded hop is ITSELF chaining to, asked of that hop.

    A local cache proxy reports its own upstream on ``/health`` while it is
    alive, and that is the only moment the answer can be trusted — so this is
    called at hint-writing time (a launch), never from the relay. Returns None
    whenever the hop does not answer or does not name one: a hop that cannot be
    confirmed NOW must not be recorded, because a stale next hop costs a dial
    before the walk reaches the no-chain decision.

    Loopback only. The next hop matters for a chain of local proxies; asking a
    remote corporate proxy for a /health it does not serve would spend the
    timeout on every launch.
    """
    import http.client

    hop = parse_upstream_proxy(value)
    if hop is None or hop.host not in _LOOPBACK or hop.tls:
        return None
    try:
        conn = http.client.HTTPConnection(hop.host, hop.port, timeout=timeout)
        try:
            conn.request("GET", "/health")
            body = json.loads(conn.getresponse().read())
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 — an absent probe is "no next hop"
        return None
    if not isinstance(body, dict):
        return None
    nxt = body.get("https_proxy") or body.get("HTTPS_PROXY")
    if not isinstance(nxt, str) or not nxt:
        return None
    parsed = parse_upstream_proxy(nxt)
    # A hop naming ITSELF would make the walk retry the address that just
    # failed, which is a loop rather than a fallback.
    if parsed is None or parsed.address == hop.address:
        return None
    return nxt


def _chain_hops(certdir: Path) -> list[_Chain]:
    """Every recorded hop, outermost LAST — the order to try them in.

    The relay dials the first and falls through to the next when a hop is not
    usable. A single-hop record (nothing behind it was confirmed) yields one
    entry, which is what every caller did before the chain was recorded.
    """
    hops = []
    for value in (_read_upstream(certdir, "proxy"), _read_upstream(certdir, "next")):
        hop = parse_upstream_proxy(value)
        if hop is not None and hop not in hops:
            hops.append(hop)
    return hops


def write_upstream_hint(
    certdir: Path, value: str | None, ca: str | None = None,
    next_hop: str | None = None,
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
    # THE CHAIN, NOT ONE HOP. A recorded hop that dies must fall through to the
    # hop behind it; falling through to a direct dial is not "no proxy" on a
    # machine whose direct route is a TLS-inspecting corporate proxy.
    #
    # A PROBE THAT COULD NOT ASK IS NOT AN ANSWER OF "NONE". ``_probe_next_hop``
    # returns None both when the hop reports no upstream AND when the hop is not
    # answering — and the second case is exactly when the chain is about to be
    # needed. Writing "" there erased the outer hop at the moment the inner one
    # died, leaving a single-hop chain that falls straight to a direct dial.
    #
    # Keep what a previous launch confirmed; only a launch that positively
    # reports a different hop replaces it.
    keep_next = next_hop or _read_upstream(certdir, "next") or ""
    if value:
        keep_proxy = value
    else:
        # KEEP THE RAW STRING. Rebuilding the URL from the parsed pair threw
        # away the two fields _Chain exists to carry: the credential and the
        # https scheme. And this is the NORMAL path — `cswap pin` from a plain
        # shell reports no proxy, and ensure_proxy re-stamps on every launch —
        # so an authenticated or TLS corporate proxy survived exactly until the
        # next re-pin, then every pinned request 407'd. Measured:
        #   https://bob:***@corp.proxy:8443 -> http://corp.proxy:8443
        keep_proxy = _read_upstream(certdir, "proxy") or ""
    try:
        tmp.write_text(json.dumps(
            {"proxy": keep_proxy, "ca": keep_ca or "", "next": keep_next}
        ))
        tmp.replace(path)
    except OSError:
        pass


def read_upstream_ca(certdir: Path) -> str | None:
    """The CA of the egress proxy, as last recorded. See above."""
    return _read_upstream(certdir, "ca")


_WIRE_KEYS = ("HTTPS_PROXY", "https_proxy", "NODE_EXTRA_CA_CERTS")
_WIRE_MARK = "_cswapPinWiredKeys"

# -- where the receipt lives -------------------------------------------------
#
# The `env` block stays in `.claude.json` — Claude Code reads it there at boot,
# so that file IS the interface and nothing about it can move. The RECEIPT
# (which keys are ours, and what they displaced) is bookkeeping only cswap
# reads, and it belongs with cswap's other state: `.claude.json` is the user's
# file, and `_cswapPinWiredKeys` / `_cswapPinWiredKeysSaved` are two opaque
# keys a human editing it can only trip over.
#
# READ BOTH, WRITE NEW — no cutover. An OLDER cswap-pin, or an older
# claude-swap, still reads and writes the config key; both keep working
# because every reader here consults the sidecar first and falls back to the
# config. The config keys are REMOVED on the next write by a new pin, so a
# box converges by being used rather than by a migration step.


def _ledger_path(config_path: Path) -> Path:
    """The sidecar receipt for ``config_path``, under the account store.

    KEYED BY CONFIG PATH, because there are two configs: `~/.claude.json` and
    the `CLAUDE_CONFIG_DIR` copy a session terminal uses. One sidecar for both
    would let the second wiring's receipt overwrite the first's, and unwiring
    would restore the wrong displaced values into the wrong file — strictly
    worse than the config key it replaces, which at least travelled WITH its
    own config.
    """
    import hashlib

    from cswap_pin._host import require

    root = Path(require("paths").get_backup_root())
    key = hashlib.sha256(str(config_path).encode("utf-8")).hexdigest()[:16]
    return root / "pin-wiring" / f"{key}.json"


def _read_ledger(config_path: Path, raw: dict) -> dict:
    """The receipt for ``config_path``: sidecar first, config as fallback.

    A sidecar that EXISTS and says "not wired" is an answer, not a miss — an
    unwire writes exactly that. Falling through to the config there would
    resurrect a receipt the unwire deliberately emptied.
    """
    try:
        side = json.loads(_ledger_path(config_path).read_text(encoding="utf-8"))
        if isinstance(side, dict) and _WIRE_MARK in side:
            return side
    except Exception:  # noqa: BLE001 — absent/unreadable: fall back
        pass
    return raw if isinstance(raw, dict) else {}


def _write_ledger(config_path: Path, ledger: dict) -> None:
    """Record the receipt beside cswap's other state. Never raises.

    Best-effort ON PURPOSE. The config write is what strands a session when it
    fails; this one only costs a receipt, and a missing receipt degrades to
    the pre-existing behaviour — the next wire re-derives it, and `--clear`
    still finds the wiring through the config keys an older pin left.
    """
    tmp = None
    try:
        path = _ledger_path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(ledger, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 — see the docstring
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


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
    # THE THIRD DOOR. `_publish_ca` refuses an empty `ours` and so does
    # `_trust_file`'s salvage arm; this one gated on mtime and never on
    # content, then concatenated `ca_path.read_bytes()` regardless. An empty
    # ca.pem satisfies every one of those conditions. Measured, with a control
    # so a zero is not read as "this fixture never merges":
    #
    #   ours                blocks out   carries ours
    #   real CA (control)        2           True
    #   EMPTY                    1           False
    #
    # and the return value goes straight into the session's
    # NODE_EXTRA_CA_CERTS — so the session would trust the UPSTREAM proxy's CA
    # while unable to verify OUR proxy, the hop it is actually routed through.
    # Returning `ca_path` is the same fallback every other error here takes.
    if Path(other) == bundle and (
        not _read_or_empty(ca_path).strip()
        or _carries(_read_or_empty(bundle), ca_path)
    ):
        # Already the merged file (a launch inside a pinned session inherits it
        # from our own env block). Returning ca_path here would UN-merge it and
        # lose the upstream proxy's CA on every later session.
        #
        # GATED ON CONTENT, not on the path alone. This branch used to return
        # `bundle` on a filename match without ever opening it — the only path
        # in this function with neither a content nor a freshness check.
        # Measured, control first:
        #
        #   bundle state           returned       exists  blocks  carries LIVE
        #   CONTROL healthy        ca-bundle.pem   True     2       True
        #   EMPTY                  ca-bundle.pem   True     0       False
        #   STALE (dead CA only)   ca-bundle.pem   True     2       False
        #   TORN                   ca-bundle.pem   True     0       False
        #   ABSENT                 ca-bundle.pem   FALSE    -       n/a
        #
        # The stale row needs nobody to do anything wrong: `ensure_ca`
        # regenerates the CA whenever `_certs_consistent` is False (expiry
        # renews 30 days early, a partial cert-dir wipe, a mismatched pair),
        # and `ca-bundle.pem` is not in the consistency set, so it survives
        # carrying the RETIRED CA. Falling through rebuilds it from the live
        # `ca.pem`, which is what the mtime check below would have done had it
        # been reached.
        #
        # EXCEPT WHEN WE HAVE NO CA AT ALL. An empty `ca.pem` means there is no
        # proxy of ours to verify, so "the bundle does not carry our CA" is
        # vacuously true and is not a reason to throw the bundle away — the
        # alternative wires an EMPTY file and costs the session every upstream
        # root for nothing. That is the case 0.1.21 fixed (0.1.20 wired 0 CAs
        # where 0.1.19 wired 2); a first pass at this guard un-fixed it, caught
        # by that release's own test.
        #
        # AHEAD OF THE EMPTY-CA GUARD, deliberately. 0.1.20 put the guard first
        # and made this case strictly worse than 0.1.19: an empty ca.pem in a
        # nested launch returned ca.pem and wired ZERO CAs, while the good
        # bundle sat on disk untouched. Measured — 0.1.19 wired 2, 0.1.20
        # wired 0. Returning a merge we did not build from the empty file
        # costs nothing and keeps every upstream root.
        return bundle
    try:
        if not ca_path.read_bytes().strip():
            return ca_path
    except OSError:
        return ca_path
    other_path = Path(other)
    # Rebuild only when an input is newer than the output — the inputs are
    # immutable per launch, so the steady state is two stats instead of
    # rewriting the bundle on every launch (the same trade a sibling proxy's ensure makes).
    #
    # AND ON CONTENT, for the same reason the un-merge branch above needed it.
    # mtime answers "did an input change since we built this", which is not
    # "does this still carry our CA". A regenerated CA leaves a bundle that is
    # NEWER than both inputs — the salvage arm writes the same filename in the
    # same launch — so the freshness test passes while the file carries the
    # retired CA. Measured: stale bundle, live ca.pem, rebuild SKIPPED.
    try:
        if (
            not bundle.exists()
            or not _carries(_read_or_empty(bundle), ca_path)
            or ca_path.stat().st_mtime_ns > bundle.stat().st_mtime_ns
            or other_path.stat().st_mtime_ns > bundle.stat().st_mtime_ns
        ):
            _write_bundle_atomically(
                bundle,
                _drop_unreadable_blocks(
                    _join_pem(ca_path.read_bytes(), other_path.read_bytes())
                ),
            )
    except OSError:
        return ca_path
    return bundle


def _read_or_empty(path: Path) -> bytes:
    """The file's bytes, or empty when it cannot be read.

    An absent or unreadable bundle is "carries nothing", not an error: the
    caller's next move is to rebuild it either way.
    """
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _carries(body: bytes, ca_path: Path) -> bool:
    """Is the certificate at ``ca_path`` one of the blocks in ``body``?

    A DER comparison, not a subject-name one: `_make_ca` gives every cswap-pin
    CA the identical subject `CN=cswap pin-proxy CA`, so a name check would
    accept a RETIRED CA of our own — the exact case this is written to catch.

    Goes through `_load_cert` at both sites (``want`` and each block), not a
    raw `x509.load_pem_x509_certificate`. A bare load treats
    `CryptographyDeprecationWarning` as a parse failure under any ambient
    warnings-as-errors filter, same as the bug `_load_cert`'s guard exists to
    fix — `_make_ca` never mints a zero-serial CA (it uses
    `x509.random_serial_number()`, which per RFC 5280 is never 0), but
    ``ca_path`` can name a CA a DIFFERENT MITM published into the shared trust
    dir, and that one is not ours to constrain.
    """
    want_cert = _load_cert(_read_or_empty(ca_path))
    if want_cert is None:  # no CA to look for: nothing carries it
        return False
    want = want_cert.public_bytes(serialization.Encoding.DER)
    for label, _head, _end, block in _pem_blocks(body):
        if label != b"CERTIFICATE":
            continue
        cert = _load_cert(block)
        if cert is None:  # a block no loader reads is not a match
            continue
        if cert.public_bytes(serialization.Encoding.DER) == want:
            return True
    return False


_LOAD_CERT_LOCK = threading.Lock()


def _load_cert(block: bytes):
    """Parse a CERTIFICATE block, or None when no loader could read it.

    WARNINGS ARE NOT PARSE FAILURES, and a bare `except Exception` cannot tell
    them apart: `CryptographyDeprecationWarning` subclasses `UserWarning` ->
    `Warning` -> `Exception`, so any ambient filter that promotes warnings to
    errors turns a LOADABLE certificate into a dropped one. Measured on this
    box's real 125-block ambient store:

        default filter   125 source -> 125 kept
        python -W error  125 source -> 119 kept

    The six are zero-serial roots (Starfield Services Root G2 among them, the
    anchor for Amazon-fronted endpoints), and openssl and python `ssl` both
    accept every one. Counts on the other two machines: 8 and 11.

    Nothing promotes the warning today. The reason this is a guard rather than
    a note is that ambient `-W error` (or an equivalent `filterwarnings`
    entry the caller's process installs) is a real, measured case on this
    box, and the floor is `cryptography>=42.0` with no ceiling — a future
    minor version can add more categories the SAME way. What this guard does
    NOT cover: the warning's own text is a scheduled promise — "Loading this
    certificate will cause an exception in a future release" — and
    `simplefilter("ignore")` suppresses a *warning*, not an *exception*.
    Measured: once cryptography makes good on that promise and raises
    directly, this guard drops the cert exactly as the unguarded `except`
    does today, because there is no warning left for it to ignore. The
    floor stops that upgrade from happening silently underfoot (see
    `pyproject.toml`), but this guard will not survive it.

    LOCKED, because `warnings.catch_warnings()` snapshots and restores
    process-global state (`warnings.filters`, `showwarning`,
    `_showwarnmsg_impl`) and this function is reachable from the daemon's
    `watch_refcount` thread concurrently with per-connection `_serve_client`
    threads. Measured (forced, deterministic interleave, not GIL timing
    luck): thread B enters, waits for thread A to install its own
    `simplefilter("ignore")`, then exits — restoring B's PRE-ignore snapshot
    — before A's load runs, so A's own "ignore" is gone when A's warning
    fires and A's certificate is dropped. `except Warning:` does not fix
    this or the "no test can detect the guard's removal" gap either: it
    would still race, and when a warning fires as an error the load
    ABORTS — there is no certificate object for a handler to hand back.
    Locking the whole guarded section removes the interleave rather than
    trying to detect it after the fact.
    """
    with _LOAD_CERT_LOCK, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return x509.load_pem_x509_certificate(block)
        except Exception:  # noqa: BLE001 — no loader can read it: not a block
            return None


def _parseable_blocks(body: bytes) -> list[bytes]:
    """Every block a loader can read, RESUMING PAST DAMAGE rather than stopping.

    `_pem_blocks` ends its scan at the first damaged marker — every damage arm
    is `yield ...; return` — so iterating it once yields only the prefix. That
    is correct for a PREDICATE (a torn file is refused whole) and wrong for a
    REPAIR, which has to look at what is behind the tear.

    Extracted from `_salvage_bundle`, which had this loop and was the only
    caller that resumed. `_drop_unreadable_blocks` iterated `_pem_blocks`
    directly and silently kept only the prefix. Measured on
    `/etc/ssl/certs/ca-certificates.crt`, 125 blocks:

        ambient store        before   after
        CONTROL untouched      125     125
        tear at idx 0            0     124   (`_salvage_bundle` reaches 125
                                              only because it re-appends
                                              `ours`; this filter has no
                                              such append and cannot)
        tear at idx 5            5     124
        tear at idx 62          62     124

    Five roots instead of 125, in a file that LOADS CLEANLY — so nothing
    downstream flags it: not torn, so the predicate says usable and the node
    oracle says True, our CA being at index 0 ahead of everything lost.
    """
    kept: list[bytes] = []
    offset = 0
    while offset < len(body):
        stopped = False
        for label, head, _end, block in _pem_blocks(body[offset:]):
            if label is None:
                # RESUME AT THE NEXT MARKER, not one byte past this one. A
                # WELDED block's own BEGIN sits at `head`, so `head + 1` skips
                # the very block salvage exists to recover — measured, the
                # welded third-party CA was dropped again.
                # RESUME AT THE DAMAGED BLOCK'S OWN BEGIN, not past it. For a
                # WELD that BEGIN sits at `head` itself, and restarting there
                # makes it a clean line start — which is the whole repair.
                # Measured: skipping past it dropped the third-party CA on the
                # RIGHT of the weld, the defect this arm exists to fix.
                if block == b"weld" and head:
                    offset += head        # its BEGIN is here: recoverable
                else:
                    nxt = body.find(b"-----BEGIN ", offset + head + 1)
                    if nxt == -1:
                        stopped = False
                        break
                    offset = nxt          # this marker is damaged: move on
                stopped = True
                break
            if label == b"CERTIFICATE":
                if _load_cert(block) is None:
                    continue
            else:
                body_only = block.split(b"-----", 2)[-1].rsplit(b"-----END", 1)[0]
                if not _armor_decodes(body_only):
                    continue
            kept.append(block)
        if not stopped:
            break
    return kept


def _drop_unreadable_blocks(body: bytes) -> bytes:
    """Every block that parses, in order, and nothing that does not.

    THE ONLY FILTER APPLIED AT EMISSION, and it is not the "drop what we do not
    recognise" that `_join_pem` argues against. It drops what NO LOADER CAN
    READ, which is a different set: an unrecognised label is kept (the block
    parses, we simply have no opinion on it), a torn one is not.

    Why emission and not just refusal. Measured by a peer session against the
    REAL client binary (Bun/BoringSSL, not node), with a CA supplied through a
    mechanism we never touch:

        SSL_CERT_DIR=certdir, NODE_EXTRA_CA_CERTS unset      CONNECTS
        SSL_CERT_DIR=certdir, NODE_EXTRA_CA_CERTS=DAMAGED    FAILS

    A fatal block in OUR file takes down a CA we did not supply and cannot see.
    So a torn merge does not merely cost the session the corporate roots it was
    carrying — it poisons trust the user configured elsewhere. `_join_pem`'s
    verbatim pass-through was written when the cost of a bad block was thought
    to be that block; it is the whole store.

    `_salvage_bundle` already had this property by construction: it reassembles
    from parsed blocks via `_parseable_blocks`, so it cannot emit damage.
    Measured, its two sibling emission sites did not:

        CONTROL _merged_ca healthy         blocks=2 DAMAGED=False
        _merged_ca + torn ambient          blocks=1 DAMAGED=True
        _trust_file tail + torn existing   blocks=1 DAMAGED=True

    `blocks=1` there is a TWO-block fixture losing its bad half, not a repair
    rate. On a real store the same code kept only the PREFIX before the tear —
    5 of 125 for damage at index 5 — until both sites were routed through
    `_parseable_blocks`, which resumes. See that function; the count is the
    thing this table does not report and the reason the truncation shipped.

    Both concatenate `read_bytes()` with no inspection of the other file, and
    the other file is the ambient store — uncontrolled by us.
    """
    # NO `else body` FALLBACK. 0.1.22 ended this `_join_pem(*kept) if kept else
    # body`, which returned the input verbatim whenever nothing parsed — the
    # exact file this function exists to never emit. Measured:
    #
    #     input               kept  damaged  returned verbatim
    #     healthy (CONTROL)     1    False       True
    #     nothing parses        0    True        True   <-- the hole
    #     empty / no markers    0    False       True
    #
    # The fallback was written for the last row, where handing the input back
    # is right because there is no damage in it, and it silently covered the
    # row that matters. `b""` is the honest answer when every block is
    # unreadable: both callers write this to a bundle whose only purpose is to
    # be loaded, and an empty file loads as zero extras instead of discarding
    # every trust source the user configured.
    #
    # AND ONLY WHEN THERE IS DAMAGE TO REMOVE. A file with no PEM markers at
    # all is not a torn bundle — it is something we do not understand, and
    # `_join_pem`'s rule applies: pass it through rather than silently narrow
    # what the caller asked to merge. Filtering unconditionally deleted the
    # whole file for any marker-free input, which is a different failure from
    # the one this exists to prevent.
    #
    # KNOWN GAP, measured and deliberately left: when NOTHING parses, this
    # returns the input unchanged — damage included. That is the one shape it
    # does not repair:
    #
    #     input               kept  damaged  returned verbatim
    #     healthy (CONTROL)     1    False       True
    #     nothing parses        0    True        True   <-- the gap
    #     empty / no markers    0    False       True
    #
    # Returning `b""` there closes it and costs more than it buys: an
    # unterminated tail (a BEGIN with no END) reports the same way as a torn
    # block, so the empty answer also fired on inputs that were merely shaped
    # unusually — measured, it emptied both `wire_env`'s and
    # `wire_global_config`'s merges and cost the session every CA in them.
    # Separating "torn" from "shaped unusually" needs a distinction `_pem_blocks` does
    # not currently make. Both cases still lose every CA in the file, so the
    # gap is a failure to REPAIR, not a new failure introduced here.
    kept = _parseable_blocks(body)
    return _join_pem(*kept) if kept else body


def _join_pem(*parts: bytes) -> bytes:
    """Concatenate PEM files so no block's terminator welds onto the next.

    A byte concatenation of two PEM files whose first does not end in a newline
    produces::

        -----END CERTIFICATE----------BEGIN CERTIFICATE-----

    openssl rejects that block and node then loads ZERO CAs — the session
    silently loses all trust. Same outcome as a torn write, and the atomic
    publish does NOT help: the fused file is written completely and correctly,
    it is just invalid.

    Measured: all three inputs on this fleet happen to end in a newline today
    (our ca.pem, the shared ca-trust.pem, the system store), which is why this
    has never fired. That is a property of the inputs, not of this code, and
    one of those inputs is the ambient CA store — uncontrolled by us, and
    deliberately passed through verbatim rather than filtered (dropping blocks
    we do not recognise would silently narrow the bundle, which no reader can
    detect).

    Raised by a peer implementation, whose read-side guard was accepting the fused
    shape until e28abd0; their END matcher used ``indexOf``, so trailing
    content on the marker line passed.

    Adds a newline only where one is missing, so a file that already ends
    cleanly is byte-identical to a plain concatenation — the bundle is
    compared against the ambient store by certificate count elsewhere, and
    padding would be a gratuitous difference.
    """
    out = bytearray()
    for part in parts:
        if not part:
            continue
        out += part
        if not part.endswith(b"\n"):
            out += b"\n"
    return bytes(out)


def _write_bundle_atomically(bundle: Path, body: bytes) -> None:
    """Publish a CA bundle by temp-then-rename. Never write it in place.

    A bundle is read by whoever launches next, so a writer that dies mid-write
    leaves a TORN file that the next session names in ``NODE_EXTRA_CA_CERTS``.
    Node aborts the entire extras load on any block it cannot decode — every
    component CA and every corporate root at once — and says so only in a
    stderr warning, so the session fails with "unable to verify the first
    certificate" and nothing points at the bundle.

    A BEGIN/END balance check does not cover this. Truncate just after an END
    marker and the file is BALANCED with a corrupt base64 payload inside; that
    shape passes the count and still costs the session all its trust.
    (Measured by a peer implementation against their read-side guard, which now
    rejects it — but a reader's guard is a backstop, and the cause is here.)

    ``os.replace`` is atomic on POSIX and Windows, so a reader sees either the
    old bundle or the new one, never half of one.
    """
    tmp = bundle.with_suffix(f".{os.getpid()}.tmp")
    try:
        tmp.write_bytes(body)
        os.replace(tmp, bundle)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


CA_TRUST_DIR = "ca-trust.d"
CA_TRUST_FILE = "ca-trust.pem"


# WHAT COUNTS AS THE START OF A PEM BLOCK. One pattern, because the predicate
# and the salvage scanner are meant to be the same scan and drifted apart once
# already.
#
# Three properties, each of which a naive version gets wrong:
#
#   1. A WELDED marker is still a block. This read `^-----BEGIN ...` and a
#      publisher that wrote no trailing newline produces
#      `-----END CERTIFICATE----------BEGIN CERTIFICATE-----`, where the second
#      marker does not start a line. Both scanners were blind to it, so the
#      predicate found nothing wrong and returned True while node — which does
#      not require the anchor — could not decode the fused line and truncated
#      there. Measured on 0.1.12 with node present: 3 blocks declared, 2 seen,
#      both judges True, wired as-is, node loaded 1. With node ABSENT (the
#      normal case here, cswap is Python) and OUR CA as the welded one, node
#      loaded ZERO — the session could not verify the proxy it was routed
#      through. `_join_pem` already guards this shape in what WE write; the
#      readers were never taught to see it in what someone else wrote.
#
#   2. A marker QUOTED IN PROSE is not a block. Dropping the left anchor
#      outright makes `# see -----BEGIN CERTIFICATE-----` a block — measured, 2
#      found where there is 1 — which is the false ACCEPT the anchor was there
#      for. So the left side is constrained to a line start or a welded
#      `-----`, not to nothing.
#
#   3. CRLF still reads. `\r?` stays: a `$`-only anchor made every CRLF bundle
#      invisible, which reads as "carries no CA" and drops the whole shared
#      file — the false REJECT that costs every sibling component its trust.
#
# Verified against all four shapes (plain LF, CRLF, welded, prose) before it
# replaced the anchored version.
_BEGIN_MARKER = rb"(?:^|-----)-----BEGIN ([A-Z0-9 ]+)-----([ \t]*)(\r?\n|\Z|.)"

def _find_end(body: bytes, label: bytes, start: int, limit: int) -> int:
    """Where ``-----END <label>-----`` TERMINATES ITS LINE, or -1.

    A bare `find` was not enough, and the gap is the same class as the welded
    BEGIN: openssl requires the terminator to end its line, so trailing text
    (`-----END CERTIFICATE-----garbage`) is not a terminator to it — it rejects
    the block and node loads ZERO extras with `PEM routines::bad end line`.
    The scanner walked straight past and called the file usable. Measured with
    node ABSENT, which is the arm with no oracle to veto it: predicate True,
    session trusts nothing, including its own CA.

    Trailing whitespace IS allowed, and `\r` with it: a builder concatenating
    files leaves CRLF, openssl loads those happily, and refusing them is the
    false reject that costs every sibling component its trust.

    A sibling implementation reached this from the other side — their END
    matcher used `indexOf`, so trailing content passed, fixed in e28abd0.
    """
    needle = b"-----END " + label + b"-----"
    at = body.find(needle, start, limit)
    while at != -1:
        rest = body[at + len(needle) : limit]
        stripped = rest.lstrip(b" \t\r")
        if not stripped or stripped.startswith(b"\n"):
            return at
        at = body.find(needle, at + 1, limit)
    return -1


_ORACLE_SENTINEL = b"\x02"
_ORACLE_TIMEOUT_S = 10.0


def _bundle_loads_in_node(bundle: Path, ca_path: Path) -> bool | None:
    """Ask node whether it will VERIFY OUR LEAF when handed this bundle.

    THREE OUTCOMES, never two:

        True   node completed a TLS handshake against a leaf we signed
        False  node refused it
        None   THE ORACLE WAS NOT CONSULTED — the caller must decide alone

    STOP PREDICTING, ASK. `_bundle_is_usable` predicts what node's loader will
    accept from file syntax, and a predicate over syntax is a losing race.
    Measured against node's real loader, ours called a bundle usable that node
    reads as ZERO extra CAs — and we hand that file to a session as
    NODE_EXTRA_CA_CERTS, so it trusts nothing: not our CA, not a sibling
    proxy's, not the corporate roots.

    ASK THE CONTRACT, NOT A PROXY FOR IT. The first version of this asked
    `tls.getCACertificates("extra")` — a census of what was loaded. That API
    landed in node v22.15, so on anything older the probe wrote nothing, the
    sentinel was absent, and EVERY verdict was None. The caller reads None as
    "could not ask" and falls back, so on those runtimes the oracle was not
    conservative, it was ABSENT — and it looked like a working guard on a dev
    box running a new node. A sibling implementation shipped that exact bug and
    measured it (v20.19 undefined, v22.14 undefined, v22.15 function).

    "Will you verify our leaf" is answerable on every node back to v12, and it
    is the question that actually matters: a session's failure mode is a failed
    handshake, not a wrong census. It also makes the verdict immune to bundle
    SIZE — a census echoed every certificate back on stdout, so a large
    corporate bundle could overflow the pipe and become None.

    None is the point of this function, not an afterthought: an oracle that
    could not ask must not answer. Returning False when node is merely absent
    would drop a healthy machine to its own CA and take every corporate root
    with it — the exact damage this exists to prevent, caused by the fix.

    THE LEAF LIVES BESIDE OUR CA, NOT BESIDE THE BUNDLE. The first version
    looked for `leaf.pem` next to the file under test, which is right for the
    tests (they write the bundle into the certdir) and wrong for every real
    launch: the shared `ca-trust.pem` lives in the Claude config home while our
    leaf lives in the pin-proxy certdir. So in production the leaf was never
    found, every verdict was None, and the predicate the oracle exists to
    correct went on deciding alone — an oracle that was green in tests and
    absent in the field. Takes the CA PATH now, so the question is set up from
    where the answer actually lives.
    """
    import shutil
    import subprocess
    import tempfile

    node = shutil.which("node")
    if not node:
        return None
    # The leaf must be signed by the CA we are asking about, or the handshake
    # answers a different question.
    try:
        ca_dir = Path(ca_path).parent
        leaf_pem, leaf_key = ca_dir / "leaf.pem", ca_dir / "leaf.key"
        if not (leaf_pem.exists() and leaf_key.exists()):
            return None
        # ...and that leaf must actually be OURS, else a passing handshake
        # proves nothing about the CA in question. A SUBJECT-NAME comparison
        # cannot tell: `_make_ca` gives every cswap-pin CA the identical
        # subject `CN=cswap pin-proxy CA`, so a leaf from any OTHER cswap-pin
        # certdir — a different key entirely — would pass a name check.
        # Measured consequence: a certdir whose leaf is signed by a different
        # CA, plus a bundle carrying only that foreign CA, yielded True and
        # wired a session to a proxy it cannot verify. Verify the SIGNATURE
        # instead, same shape as `_certs_consistent`.
        leaf = x509.load_pem_x509_certificate(leaf_pem.read_bytes())
        ca_cert = x509.load_pem_x509_certificate(Path(ca_path).read_bytes())
        ca_cert.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
    except Exception:  # noqa: BLE001 — cannot set the question up: not an answer
        return None

    probe = (
        "const tls=require('tls'),fs=require('fs');"
        "const s=tls.createServer("
        "{key:fs.readFileSync(process.argv[2]),cert:fs.readFileSync(process.argv[3])},"
        "c=>c.end());"
        "s.listen(0,'127.0.0.1',()=>{"
        "const c=tls.connect({host:'127.0.0.1',port:s.address().port,"
        "servername:'api.anthropic.com'},()=>{"
        "process.stdout.write('\\x02OK');c.destroy();s.close();});"
        "c.on('error',()=>{process.stdout.write('\\x02NO');s.close();});});"
    )
    # The child must not inherit anything that answers a DIFFERENT question.
    #
    # `*_proxy` was already stripped: the child would otherwise route its own
    # loopback connect through us while we are deciding what to trust. (That
    # filter also catches NODE_USE_ENV_PROXY, which node >= 24 honours.)
    #
    # But two more change what a successful handshake MEANS, and neither ends
    # in `_proxy`. Measured against a bundle carrying NO CA at all:
    #
    #     NODE_TLS_REJECT_UNAUTHORIZED unset   verdict False   (correct)
    #     NODE_TLS_REJECT_UNAUTHORIZED=0       verdict True    (a lie)
    #
    # A True from that state is not "this bundle verifies our leaf", it is
    # "this node was told not to check" — and `_trust_file` then wires the
    # shared file on a verdict about nothing. NODE_OPTIONS is the same class:
    # it can carry --use-openssl-ca and friends, so the child would consult a
    # different trust store than the one under test.
    #
    # Raised by a peer implementation, whose probe had the mirror-image gap: they
    # cleared these two and not the proxy family.
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    for leak in ("NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"):
        env.pop(leak, None)
    env["NODE_EXTRA_CA_CERTS"] = str(bundle)
    try:
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "probe.js"
            script.write_text(probe, encoding="utf-8")
            r = subprocess.run(
                [node, str(script), str(leaf_key), str(leaf_pem)],
                capture_output=True,
                env=env,
                timeout=_ORACLE_TIMEOUT_S,
            )
    except Exception:  # noqa: BLE001 — cannot ask: not an answer
        return None
    # EXIT STATUS CANNOT SEPARATE "it answered no" FROM "it never ran". The
    # sentinel written before the verdict is the only proof the probe reached
    # its own conclusion.
    if not r.stdout.startswith(_ORACLE_SENTINEL):
        return None
    return r.stdout[len(_ORACLE_SENTINEL):].startswith(b"OK")



def _armor_decodes(body: bytes) -> bool:
    """Whether openssl will read this non-certificate block's armor.

    ONE FUNCTION, because the predicate and salvage must agree and had
    already drifted: 0.1.16 fixed the slice in both and the emptiness in
    neither, so a block openssl refuses was kept by both readers.

    `base64.b64decode(..., validate=True)` is necessary and NOT sufficient —
    it accepts three shapes openssl rejects, each measured against node with
    a corp root beside the block (correct answer 2, node loaded 1):

        empty / whitespace-only body   no openssl warning at all
        `QUFB=`  (5 chars)             bad base64 decode
        a blank line before END        bad end line

    The first is the dangerous one: the session loses every corporate root
    with nothing on stderr to say why. openssl needs at least one whole
    4-character quantum and will not tolerate a blank line before the
    terminator, which is exactly what the three conditions encode.

    `validate=True` stays: a body carrying stray dashes (what a concatenating
    builder produces on a torn seam) is accepted without it.
    """
    import base64

    data = b"".join(body.split())
    if not data or len(data) % 4:
        return False
    # THE BLANK-LAST-LINE RULE LIVES IN `_pem_blocks` NOW, not here. It was
    # added in this arm first, which is exactly why it missed: a CERTIFICATE
    # never reaches this function, and the real bundle is 132 CERTIFICATE
    # blocks and nothing else. Measured, `_armor_decodes` was called ZERO
    # times on the file this machine loads. Keeping a copy here would be dead
    # code — `_pem_blocks` refuses the shape before yielding, verified — and a
    # dead guard is worse than none: it reads as protection.
    try:
        base64.b64decode(data, validate=True)
    except Exception:  # noqa: BLE001
        return False
    return True


def _pem_blocks(body: bytes):
    """Every block whose BEGIN **and** END each own their line.

    ONE SCANNER FOR BOTH READERS. A PEM marker has two edges, and this file
    fixed them one at a time: welds on the left of BEGIN, then a terminator
    on the right of END. The other two were never guarded, and both landed in
    the dangerous direction — measured, node deciding:

        END welded to the base64 line   predicate True, node loaded 1 of 2
                                        (OUR CA gone: cannot verify our proxy)
        BEGIN carrying trailing text    predicate True, node loaded 2 of 3
                                        (fires with node PRESENT too — our CA
                                         is after the damage, so the handshake
                                         still succeeds and cannot veto)

    Four edges, two readers, and they had already drifted apart once. Yielding
    from one place is what stops the next edge from being fixed in only one of
    them.

    HANDS OUT BYTES VERBATIM, never a repaired copy. The predicate used to
    rebuild the terminator (`body[head:end] + b"-----END ...-----\n"`), which
    REPAIRS a fused block for the parser — cryptography read it happily and
    the predicate then answered True about a file that is still fused on disk.
    A reader that reconstructs what it is judging cannot judge it.

    Yields ``(label, head, body_end, block)``: `head` is the BEGIN, `body_end`
    is where the terminator starts, `block` is the whole thing including its
    END line. A malformed block is simply not yielded; the callers decide what
    that means, which differs between them (refuse vs skip).
    """
    import re as _re

    begin = _re.compile(_BEGIN_MARKER, _re.M)
    pos = 0
    while True:
        m = begin.search(body, pos)
        if not m:
            return
        label = m.group(1)
        nxt = begin.search(body, m.end())
        limit = body.index(b"-----BEGIN ", nxt.start()) if nxt else len(body)
        head = body.index(b"-----BEGIN ", m.start())
        # A WELDED BEGIN means the file is already fused: openssl cannot read a
        # marker sharing a line with the previous END, whatever the blocks
        # around it look like.
        if head != m.start():
            # A WELD: this block's own BEGIN is at `head`, so a caller that
            # restarts THERE sees a clean line start and recovers it.
            yield None, head, -1, b"weld"
            return
        # AND THE BEGIN MUST END ITS OWN LINE. The marker now MATCHES a BEGIN
        # carrying trailing text instead of skipping past it — skipping made
        # the block INVISIBLE, so the predicate never saw it and approved a
        # file node truncates at. Group 3 is the byte that follows: a newline
        # or end-of-input is a real marker, anything else is damage.
        if m.group(3) not in (b"\n", b"\r\n", b""):
            # The marker itself is damaged; restarting here would re-reject it
            # forever. Only a LATER block can be recovered.
            yield None, head, -1, b"marker"
            return
        end = _find_end(body, label, m.end(), limit)
        if end == -1:
            yield None, head, -1, b""
            return
        # AND THE END MUST START ITS OWN LINE. `_find_end` bounds the RIGHT
        # side of the terminator; this is the left. A terminator welded onto
        # the last base64 character is what openssl refuses while a rebuilt
        # copy parses fine.
        if end > 0 and body[end - 1 : end] != b"\n":
            yield None, head, -1, b""
            return
        # AND THE LINE BEFORE THE TERMINATOR MUST CARRY SOMETHING. openssl
        # refuses a blank-or-whitespace-only last line whatever the LABEL is,
        # and this is the only place both labels and both readers pass
        # through. It lived in `_armor_decodes` — the NON-certificate arm —
        # so a CERTIFICATE went to `x509.load_pem_x509_certificate` instead,
        # and cryptography parses the shape happily. Measured: the real
        # bundle is 132 CERTIFICATE blocks and ZERO others, so
        # `_armor_decodes` was called 0 times on the file this machine
        # actually loads. A whitespace line before the first END gave
        # predicate True and node extras=0 of 133 — the whole extras load
        # dropped, so the session could not verify its own proxy.
        line = body[max(0, body.rfind(b"\n", 0, end - 1) + 1) : end - 1]
        if line.strip() == b"":
            yield None, head, -1, b""
            return
        term = b"-----END " + label + b"-----"
        yield label, head, end, body[head : end + len(term)] + b"\n"
        pos = end


def _salvage_bundle(body: bytes, ours: bytes) -> bytes:
    """Every block of ``body`` node can actually load, plus our own CA.

    REFUSING THE BUNDLE MUST NOT COST THE CORPORATE ROOTS. The old fallback
    for an unusable shared bundle was "our CA alone", which on a corporate
    network is a session that can verify our proxy and nothing else — every
    https destination fails. That made the oracle's verdict a cliff: a single
    torn block, or merely having no node on PATH, and the machine lost 131
    working roots to protect against one broken one.

    Node's failure mode is what makes salvage the right answer rather than a
    hedge — and it is TRUNCATE, not abort. Measured on this host (node
    v24.11.1), asking two independent questions about the same ours+TORN+corp
    bundle — how many extras did the loader keep, and will it complete a
    handshake against our leaf:

        bundle                    node v24.11.1 extras   handshake vs our leaf
        ours + corp (healthy)     2                      OK
        ours + TORN + corp        1   <- corp LOST       OK      <-- the hole

    node keeps every block BEFORE the first undecodable one and drops
    everything from there on, including blocks that are themselves perfectly
    valid. That is exactly why a handshake-only verdict ("will you verify our
    leaf") is not sufficient proof the bundle survived intact: with our CA
    ahead of the tear, the handshake still succeeds while roots after the tear
    vanished silently. Dropping only the bad block is not a guess about
    intent, it is the minimum edit that turns a file node truncates into the
    same file node loads whole.

    Deliberately drops nothing else. A block that decodes is kept verbatim,
    including CRLs and key blocks a real corporate bundle carries — narrowing
    what we do not understand is how a reader silently shrinks a bundle, which
    `_bundle_is_usable`'s docstring already refuses to do.
    """
    import base64
    import re as _re

    kept: list[bytes] = []
    # THE SCANNER STOPS AT DAMAGE; SALVAGE MUST NOT. Its whole job is to keep
    # every block that still decodes, and a healthy root sitting AFTER the
    # damage is exactly what the session loses otherwise — the narrowing this
    # file refuses everywhere else. So walk the body in segments, restarting
    # one byte past each broken marker, rather than recursing.
    kept = _parseable_blocks(body)
    # Ours goes in unconditionally — a bundle that dropped it is exactly the
    # case where the session could not verify the proxy it is routed through.
    if not _bundle_is_usable(b"".join(kept), ours):
        kept.append(ours.strip() + b"\n")
    return _join_pem(*kept)


def _bundle_is_usable(body: bytes, ours: bytes) -> bool:
    """Would Node actually LOAD this bundle, and does it carry our CA?

    Counting ``BEGIN``/``END`` markers cannot answer the first question, and
    the gap is not academic: measured on this host against a real TLS
    handshake through ``NODE_EXTRA_CA_CERTS``, a bundle with a torn
    certificate BEFORE ours passes the marker count and node refuses the whole
    extras load — so the session cannot verify the very proxy it is routed
    through and every request dies. That is the dangerous direction, and the
    marker count waved it through.

    Node does NOT abort the whole extras load on one undecodable block — it
    TRUNCATES at the first one and keeps everything before it. Measured on
    this host (node v24.11.1), asking two independent questions about the
    same ours+TORN+corp bundle — how many extras did the loader keep, and
    will it complete a handshake against our leaf:

        bundle                    node v24.11.1 extras   handshake vs our leaf
        ours + corp (healthy)     2                      OK
        ours + TORN + corp        1   <- corp LOST       OK      <-- the hole

    That is why a handshake-only verdict is not sufficient: with our CA ahead
    of the tear, node still verifies our leaf (True) while every block after
    the tear, including corporate roots, is gone. So every block still has to
    be proven decodable here — not just ours, and not just the ones labelled
    CERTIFICATE — because a bundle that is usable in the sense this function
    means (nothing silently dropped anywhere in it) requires the WHOLE file
    to be clean, not merely the prefix node's loader happened to keep. What
    "decodable" means differs by label: a CERTIFICATE must parse as X.509
    (valid base64 is not enough, a well-formed body that is not a certificate
    still truncates the load from there on), while a CRL or a PUBLIC KEY
    needs only intact base64 armor. Demanding X.509 of those would reject the
    CRLs and key blocks a real corporate bundle legitimately carries — a
    false reject costs every sibling CA for the whole session, which is the
    failure this shared bundle exists to prevent.

    Identity is by DER, not by substring: a re-encoded or CRLF-normalized copy
    of our CA is still our CA, and a substring test calls it a stranger.

    Where it cannot tell, it REFUSES. Refusing costs one session's sibling
    CAs; accepting costs the session entirely. See
    a peer implementation, which measured this same guard
    wrong in both directions in the sibling implementation.
    """
    import base64
    import re as _re

    if not ours:
        return False  # an empty CA makes any containment test vacuous
    try:
        want = x509.load_pem_x509_certificate(ours).public_bytes(
            serialization.Encoding.DER
        )
    except Exception:  # noqa: BLE001 — our own CA is unreadable; trust nothing
        return False

    # `\r?$` because a bundle builder that concatenates files can leave CRLF
    # endings, and openssl loads those happily. A `$`-only anchor made every
    # CRLF bundle invisible to this scan — which reads as "carries no CA" and
    # drops the whole shared file, the false reject that costs every sibling
    # component its trust. Measured: a CRLF copy of our own CA was refused.
    carries_us = False
    seen_any = False
    for label, _head, _end, block in _pem_blocks(body):
        if label is None:
            return False  # malformed on either edge — node truncates there
        seen_any = True
        if label == b"CERTIFICATE":
            cert = _load_cert(block)
            if cert is None:
                return False
            der = cert.public_bytes(serialization.Encoding.DER)
            if der == want:
                carries_us = True
        else:
            # Not a certificate: node skips it, but only if the armor decodes.
            #
            # SPLIT ON THE DASHES, not on `-----\n`. `_find_end` and
            # `_BEGIN_MARKER` deliberately tolerate CRLF and trailing
            # whitespace on a marker line — refusing those is the false reject
            # that costs every sibling component its trust. A separator that
            # demands a bare LF therefore does not exist in those blocks:
            # `[-1]` returned the WHOLE block, `rsplit(b"-----END")` left
            # `b""`, and empty base64 decodes fine, so the check was a no-op.
            # Measured: `b'-----BEGIN X509 CRL-----\r\n!!!bad!!!\r\n---'` sliced
            # to `b''`. A CERTIFICATE is saved by its x509 parse; a CRL or key
            # block has only this, which is why a certificate-only test hides
            # it.
            body_only = block.split(b"-----", 2)[-1].rsplit(b"-----END", 1)[0]
            if not _armor_decodes(body_only):
                return False
    del seen_any
    return carries_us


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
        get_claude_config_home = require("paths").get_claude_config_home

        shared = get_claude_config_home() / CA_TRUST_FILE
        if shared.is_file() and shared.stat().st_size > 0:
            ours = Path(ca_path).read_bytes().strip()
            # SYMMETRIC WITH `_publish_ca`, and this is the site that needed it
            # more. Both read the same `ca_path` and treat the bytes as OUR CA;
            # `_publish_ca` refused an empty one and this arm did not. The
            # failures are not the same size: `_publish_ca` skipping a write
            # costs one file in `ca-trust.d` that the next launch rewrites,
            # while this arm decides what the SESSION gets. With an empty
            # `ours`, `_salvage_bundle` appends nothing — the append is gated
            # on `_bundle_is_usable(kept, ours)`, and that answers False here
            # by its own vacuity guard rather than because containment failed.
            # Measured before this line existed:
            #
            #   salvage(peer, ours=b"")   1 block, ours ABSENT
            #
            # so the session trusted the peer's certificates and could not
            # verify the proxy it was routed through — the exact failure
            # `_bundle_is_usable` exists to prevent, arriving through the
            # REPAIR path.
            #
            # RETURN, NOT RAISE. 0.1.20 raised here and said in this comment
            # that it fell through to "our own path". It did not: the raise
            # landed in the blanket `except Exception: pass` below, and control
            # continued into the tail merge, which concatenates `ca_path`
            # unconditionally and produced the SAME bundle the guard was
            # written to prevent. Measured with `existing` set — the shape
            # every machine with `NODE_EXTRA_CA_CERTS` runs:
            #
            #   ours            returned         blocks  carries ours
            #   real (CONTROL)  ca-bundle.pem    2       True
            #   EMPTY           ca-bundle.pem    1       False
            #
            # Control flow by exception into a handler 90 lines away puts the
            # landing site out of the author's sight. Say where it goes.
            if not ours:
                return Path(ca_path)
            body = shared.read_bytes()
            # Carrying our CA is necessary but not sufficient. An unbalanced
            # BEGIN/END anywhere in the file makes Node reject the WHOLE extras
            # bundle — every component CA and every corporate root at once —
            # and it says so only in a stderr warning, so the session dies on
            # "unable to verify the first certificate" with no visible cause.
            # Checking that we are in there cannot see that; count the markers.
            #
            # A bundle that is BALANCED and CONTAINS us but has silently lost
            # other roots is deliberately NOT guarded here, and not because we
            # lack the information: a reader is the wrong PLACE to decide it.
            # Even holding the previous bundle, a shrink is legitimate whenever
            # a root was retired or a component uninstalled, and only the
            # builder knows which happened — so a reader acting on a shrink
            # would reject a correct bundle in exactly the cases the shrink was
            # intended. Measured across the three machines this runs on, a
            # legitimate bundle is 5 certs on one and 168 on another, so any
            # ABSOLUTE size floor that catches narrowing on one host rejects a
            # healthy bundle on the next. The builder keeps the last good
            # bundle for this reason; that is where the decision belongs.
            #
            # This comment previously read "2 certs on one and 132 on another".
            # The 132 was right for this host; the 2 was the COMPONENT COUNT
            # (ca-trust.d holds one PEM per component, one certificate
            # each), not a bundle size — two different quantities reported as
            # one measurement. The real spread, measured on all three by the
            # peer after this claim was quoted at them. The conclusion survives and is in
            # fact stronger, but it was not supported by the numbers cited.
            #
            # NOTE what this rules out and what it does not. It rules out an
            # ABSOLUTE floor in a READER. It does not rule out a builder
            # comparing its output against the inputs IT just read, which is a
            # per-build quantity rather than a constant and does not need to
            # hold across hosts.
            # The two cases below are also a different severity class: both
            # leave the session unable to verify its OWN proxy, so every
            # request dies. Narrowing keeps our chain intact and costs someone
            # else's. Do not add a cert-count floor here.
            # ASK THE LOADER FIRST, PREDICT ONLY IF IT CANNOT BE ASKED.
            #
            # `_bundle_is_usable` predicts what node's loader will accept from
            # file syntax, and measured against node's real loader it was wrong
            # in the dangerous direction: it called a bundle usable that node
            # reads as ZERO extra CAs, and we then hand that file to the
            # session as NODE_EXTRA_CA_CERTS. The session trusts nothing —
            # not our CA, not a sibling proxy's, not the corporate roots — so
            # every request fails to verify the proxy it is routed through.
            #
            # None from the oracle is NOT "unusable": it means the probe never
            # ran (no node on PATH, which is normal here — cswap is Python).
            # Answering "unusable" there would drop a healthy machine to its
            # own CA and take every corporate root with it, which is the exact
            # damage this is meant to prevent. So fall back to the predicate,
            # which is the only judge left, and say which arm decided.
            verdict = _bundle_loads_in_node(shared, Path(ca_path))
            if verdict is None:
                verdict = _bundle_is_usable(body, ours)
                _log_lifecycle(
                    f"ca-bundle: node not consulted, predicate says "
                    f"{'usable' if verdict else 'unusable'}"
                )
            elif verdict:
                # THE ORACLE'S True IS A VETO'S ABSENCE, NOT AN APPROVAL. It
                # only asked "will you verify our leaf", and node TRUNCATES
                # the extras load at the first bad block rather than aborting
                # it — so True survives even when every block after a tear,
                # including corporate roots placed after ours, was silently
                # dropped. Measured on the real 132-cert bundle with a tear
                # placed after our CA: 68 corporate roots lost while the
                # oracle still answered True. AND it with the predicate,
                # which inspects the WHOLE file: the oracle keeps its power to
                # REFUSE a file the predicate wrongly approves (0.1.9's fix,
                # must not regress), but loses the power to APPROVE a file
                # the predicate says is torn.
                verdict = _bundle_is_usable(body, ours)
            if verdict:
                return shared
            # REFUSED — but refusing the FILE must not mean refusing its
            # CONTENTS. Falling through to "our CA alone" costs the session
            # every corporate root to avoid one bad block, so keep every block
            # that does decode and drop only the ones that do not. That makes
            # both the False and the None arms cost at most the broken block.
            salvaged = Path(ca_path).parent / "ca-bundle.pem"
            salvage = _salvage_bundle(body, ours)
            _write_bundle_atomically(salvaged, salvage)
            _log_lifecycle(
                f"ca-bundle: {shared} refused, salvaged "
                f"{salvage.count(b'-----BEGIN')} of {body.count(b'-----BEGIN')} "
                f"blocks to {salvaged}"
            )
            return salvaged
    except Exception:
        # A SALVAGE-WRITE FAILURE (disk full, a read-only cert dir) LANDS
        # HERE TOO, same as a missing/corrupt shared bundle — and collapses
        # into "no shared bundle" rather than into an error the caller sees.
        # Measured whether that is still safe on every path that reaches it:
        # with `ours` already confirmed non-empty above, every branch below
        # this handler falls through to `return Path(ca_path)` — our own CA,
        # already on disk and already read once — even when door four's
        # write ALSO fails. The session never loses the ability to verify
        # ITS OWN proxy. What it loses is the corporate roots the shared or
        # merged bundle would have carried, which is the same "narrowing"
        # this file already treats as a builder-owned, not a reader-owned,
        # decision everywhere else (see `_bundle_is_usable`'s docstring and
        # `TestNarrowingIsDeliberatelyUnguarded`) — not a new failure mode
        # this `except` introduces.
        pass
    # No shared bundle: merge with what THIS env trusts. Deliberately not
    # _merged_ca, which also consults the ambient process environment and a
    # recorded upstream CA — wire_env is handed the environment it must
    # describe, and reaching past it would wire a session to trust something
    # its caller never mentioned.
    if not existing or Path(existing) == Path(ca_path):
        return Path(ca_path)
    # DOOR FOUR. Same shape as `_merged_ca`: reads `ca_path`, concatenates it
    # unconditionally, returns the merge. 0.1.20 guarded the salvage arm and
    # `_merged_ca` and shipped a commit titled "three doors" — this is the
    # fourth, and it is the one the other guards FALL INTO, because a refusal
    # above lands here rather than at a return.
    #
    # It is also the live path wherever `NODE_EXTRA_CA_CERTS` is already set,
    # which `wire_env` passes straight in as `existing`:
    #
    #   hostname -s            lambda-docker
    #   NODE_EXTRA_CA_CERTS    /etc/ssl/certs/ca-certificates.crt
    #
    # so the `if not existing` return above is never taken there and an empty
    # ca.pem produced a bundle carrying the corporate CA and nothing of ours.
    try:
        if not Path(ca_path).read_bytes().strip():
            return Path(ca_path)
    except OSError:
        return Path(ca_path)
    bundle = Path(ca_path).parent / "ca-bundle.pem"
    try:
        _write_bundle_atomically(
            bundle,
            _drop_unreadable_blocks(
                _join_pem(Path(ca_path).read_bytes(), Path(existing).read_bytes())
            ),
        )
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
    (measured: 13 attempts, 0 connects, while worker/heartbeat and
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
        get_claude_config_home = require("paths").get_claude_config_home

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


def _resolve_pinned_slot(backup_root: Path, email: str) -> str | None:
    """The slot number that currently holds ``email``, or None.

    Identity is stored by email because slots move (`cswap move`), so the
    number comes from the registry rather than being cached with the pin.
    None means a DANGLING pin — the account it names is gone — and every
    caller must treat that as "nothing to serve" rather than as an error.
    """
    try:
        seq = json.loads((backup_root / "sequence.json").read_text(encoding="utf-8"))
        accounts = seq.get("accounts") or {}
        return next(
            (num for num, rec in accounts.items()
             if (rec.get("email") if isinstance(rec, dict) else rec) == email),
            None,
        )
    except Exception:
        return None


def heal(backup_root: Path) -> bool:
    """Bring the pin back if it is pinned but not serving. True when it did.

    RECOVERY WITHOUT A SESSION RESTART. Everything else in this module reacts
    to a launch: ``ensure_proxy`` runs when a NEW session starts, so if the
    daemon dies while sessions are up, nothing brings it back — and if the dead
    wiring has blocked every session, no new one can start to trigger it. That
    is a deadlock, and it is exactly what was measured: a human had to
    re-pin by hand.

    So this needs no switcher: the pinned identity comes from settings.json and
    the slot from the account registry, both on disk. Cheap when healthy — a
    state read plus one loopback connect, and it returns immediately.

    WHO CALLS IT, stated because the previous answer here was wrong and cost 22
    hours. This used to say "callable from anything that already runs
    periodically (the status line does, every few seconds)". A status line is
    ONE MACHINE'S PERSONAL CONFIG, so recovery living there means every user
    without that hook has no recovery at all — the hook was removed on purpose,
    and this docstring was left as the only record of a design that no longer
    existed. The periodic caller today is :func:`_watch_own_code`, INSIDE the
    daemon, which needs no host cooperation. `heal` remains the launch-path
    repair and the manual one (``cswap pin --heal``); it is not on a timer.

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
    # AN UPGRADE MUST NOT WAIT FOR A LAUNCH. `ensure_proxy` recycles a stale
    # daemon, but it only runs when a NEW session starts — so installing a fix
    # left every running daemon on the old code until someone happened to open
    # a session. Measured: 0.1.3 landed on disk at 22:11 and the daemon was
    # still the 20:04 process running 0.1.1 half an hour later, on a box where
    # the whole point of the release was that upgrading no longer costs a
    # session anything. The installer changes files; nothing told the daemon.
    #
    # This function already runs every few seconds from the status line, which
    # makes it the one periodic caller that can notice. It just never asked:
    # `_read_alive_port` without a fingerprint reads a stale daemon as healthy.
    # Ask WITH one, and an upgrade takes effect on its own, on the same port,
    # with no session restarted and no command typed.
    #
    # Deliberately NOT reusing the ensure_proxy fast path: this must be the
    # slow, locked path so the recycle is serialized against every other
    # status line on the box.
    # RESOLVE THE SLOT BEFORE KILLING ANYTHING. The recycle below used to run
    # first, and the account lookup afterwards — so a DANGLING pin (the pinned
    # email no longer in sequence.json: `cswap remove`, a slot rename, a
    # restored registry) killed a perfectly healthy daemon and then returned at
    # `if not account_num`, before the spawn AND before `unwire_if_dead`.
    #
    # Measured against a real process holding a real socket, with a real kill:
    #   0.1.3  heal=False  killed=no   -> daemon kept serving
    #   0.1.4  heal=False  killed=YES  -> port dead, .claude.json still naming it
    # which is the ConnectionRefused outage this module documents twice, caused
    # by the code meant to prevent it. A dangling pin must be a no-op, exactly
    # as it was before the recycle existed.

    fp = daemon_fingerprint()
    alive = _read_alive_port(certdir, fingerprint=fp)
    # `_read_alive_port` returns None for an `unpinnable` daemon REGARDLESS of
    # fingerprint, so "fingerprinted read failed but a bare read succeeded" is
    # true for a daemon running the NEWEST code that merely cannot read its
    # credential (the macOS keychain rc=36 case). Recycling that daemon does
    # not fix it: the successor re-marks itself unpinnable and the next tick
    # recycles again — measured, 5 ticks 5 kills, no convergence, each one
    # costing live sessions their in-flight requests.
    #
    # Ask the record directly instead of inferring staleness from two probes
    # that differ for more than one reason.
    # RESOLVED BEFORE ANY KILL. A dangling pin (the account gone from the
    # registry) has nothing to spawn afterwards, so recycling first and looking
    # the slot up after left the wiring naming a port nobody serves — the
    # outage this recycle exists to prevent, caused by the recycle. Measured
    # with a real kill: 0.1.3 left the daemon alive; 0.1.4 killed it.
    #
    # It does NOT gate the serving-but-unwired re-wire below, which needs no
    # registry: gating that made an unreadable sequence.json block a repair
    # that would otherwise have worked (measured: serving daemon on 33967, the
    # config left `{}`).
    account_num = _resolve_pinned_slot(backup_root, email)

    stale_st = read_daemon_state(certdir)
    stale_fp = (stale_st or {}).get("fingerprint")
    recycled = False
    # `stale_fp is None` is a record with no fingerprint at all, which
    # `read_daemon_state` accepts (it requires only port and pin). Excluding it
    # made such a daemon IMMORTAL — it can never match the current fingerprint,
    # so it is stale by definition, and 0.1.5 recycled it. Treat a missing
    # fingerprint as stale, which is what it means.
    if alive is None and stale_fp != fp and _read_alive_port(certdir) is not None:
        # Serving, but running code we no longer ship. Recycle it: the spawn
        # below rebinds the SAME port, so live sessions never see the swap.
        #
        # NOT WITHOUT A SLOT. A dangling pin (its account gone from the
        # registry) has nothing to spawn afterwards, so killing here would
        # leave the wiring naming a port nobody serves — the outage this
        # recycle exists to prevent, caused by the recycle.
        if not account_num:
            return False
        try:
            with _spawn_lock(certdir):
                if _read_alive_port(certdir, fingerprint=fp) is not None:
                    return False  # another status line just did it
                stale = read_daemon_state(certdir)
                # "Alive" is not "still ours" — a pid is reused freely, so ask
                # whether it is a pin daemon for THIS certdir before signalling
                # it. Same gate ensure_proxy uses; when identity cannot be
                # established (no ``ps``) this kills nothing rather than
                # killing on faith.
                if stale and int(stale.get("pid") or 0) in _pin_daemon_pids(certdir):
                    # Save the port BEFORE the kill. The daemon unlinks its own
                    # state on TERM, so afterwards there is nothing to reclaim
                    # from and the successor would take a FRESH port — which
                    # strands every session already wired to the old one, the
                    # exact damage this recycle exists to avoid.
                    if isinstance(stale.get("port"), int):
                        _write_port_hint(certdir, stale["port"])
                    _kill_daemon(int(stale["pid"]))
                    # ONLY AFTER A KILL. `recycled` decides whether the spawn
                    # guard below is fingerprinted, and setting it merely for
                    # ENTERING this branch made a no-op recycle look like a
                    # real one: with no `ps` (the documented blind spot) the
                    # identity gate kills nothing, and heal then spawned a
                    # successor over a daemon that is still serving. Measured:
                    # killed=[] spawned=['1'].
                    recycled = True
        except Exception:  # noqa: BLE001 — a heal must never raise
            return False
        # Fall through to the spawn path below, which reclaims that port.
    if alive is not None:
        # SERVING IS NOT THE SAME AS WIRED. A daemon can be up while
        # ``.claude.json`` names nothing — `pin --clear` raced a respawn, a
        # heal unwired it and the daemon came back, or (measured) an unwire ran
        # against a live daemon. Returning False here left that state
        # permanent: the proxy served on a port no session was told about, and
        # only a hand-typed `cswap pin <n>` restored it.
        #
        # Re-wiring is the whole point of a heal. It costs one config read when
        # the wiring is already correct, and it is what makes the pin come back
        # BY ITSELF once the daemon is healthy again.
        if _wired_port() == alive:
            return False  # serving AND wired — genuinely nothing to do
        try:
            wire_global_config(alive, certdir / "ca.pem")
            return True
        except Exception:  # noqa: BLE001 — a heal must never raise
            return False
    # The SPAWN needs a slot, and a dangling pin has none. Gated here rather
    # than at the top so the serving-but-unwired re-wire above still runs: that
    # path needs no registry, and gating it made an unreadable sequence.json
    # block a repair that would otherwise have worked.
    if not account_num:
        return False  # dangling pin: its slot is gone, nothing to serve
    try:
        with _spawn_lock(certdir):
            # Re-check under the lock — another caller may have just spawned.
            #
            # WITH THE FINGERPRINT. A bare liveness check re-reads the very
            # daemon the recycle above was for: its state file outlives a kill
            # that did not complete (and, when a caller stubs the kill, always),
            # so heal would bail here and the obsolete daemon would serve
            # forever — the exact staleness this path exists to end. Asking for
            # the current fingerprint means "someone spawned a daemon running
            # the code we ship", which is the only thing that makes this a no-op.
            # ANYTHING SERVING IS ENOUGH — unless we just recycled.
            #
            # A fingerprinted check here loops forever on a daemon that runs
            # CURRENT code but is marked `unpinnable` (it cannot read the
            # credential — the macOS keychain rc=36 case). `_read_alive_port`
            # returns None for that daemon whatever the fingerprint, so a
            # fingerprinted guard reads "nothing is serving", spawns a
            # successor that re-marks itself unpinnable, and the next tick does
            # it again. Measured: 5 ticks, 5 respawns, no convergence.
            #
            # heal's job is "make the pin serve". Something IS serving, so heal
            # is done — the pin is fail-open and a respawn cannot fix a
            # credential it also cannot read.
            #
            # The exception is the branch above: it killed the daemon whose
            # record this would find, and a kill that did not complete leaves
            # that record behind. There the fingerprint is the right question,
            # because only a successor running OUR code means the work is done.
            probe = (
                _read_alive_port(certdir, fingerprint=fp)
                if recycled
                else _read_alive_port(certdir)
            )
            if probe is not None:
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
    daemon that never started at all, which is what was measured when
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
        get_global_config_path = require("paths").get_global_config_path

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
    claude_config_lock = require("claude_locks").claude_config_lock
    get_global_config_path = require("paths").get_global_config_path

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
    # THE RECEIPT, from wherever the last writer put it. See `_ledger_path`:
    # it moved out of `.claude.json` into the account store, and BOTH are read
    # because an older cswap-pin still writes the config key.
    prev = _read_ledger(path, raw)
    ours = prev.get(_WIRE_MARK)
    ours = list(ours) if isinstance(ours, list) else []

    # Drop what we wrote last time, restoring anything we displaced.
    saved = prev.get(f"{_WIRE_MARK}Saved")
    saved = dict(saved) if isinstance(saved, dict) else {}
    for key in ours:
        env.pop(key, None)
    for key, value in saved.items():
        env[key] = value

    ledger = {_WIRE_MARK: [], f"{_WIRE_MARK}Saved": {}}
    if port is None or ca_path is None:
        pass  # `ledger` above already records "not wired"
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
        displaced = {k: env[k] for k in wanted if k in env}
        env.update(wanted)
        ledger = {_WIRE_MARK: list(wanted), f"{_WIRE_MARK}Saved": displaced}

    if env == before and _WIRE_MARK not in raw and not ours:
        return False
    # THE CONFIG KEYS GO, whichever location we read from. They are where the
    # receipt USED to live; leaving them behind means an older claude-swap
    # keeps reading a stale copy of a receipt this write just replaced.
    raw.pop(_WIRE_MARK, None)
    raw.pop(f"{_WIRE_MARK}Saved", None)
    if env:
        raw["env"] = env
    else:
        raw.pop("env", None)
    try:
        # PID-SUFFIXED AND O_EXCL, like every other atomic write in this file.
        # A fixed name is two bugs: two processes wiring at once share it, and
        # O_CREAT's mode argument is IGNORED for a file that already exists —
        # so a leftover temp from an earlier crashed write dictates the final
        # mode, and the rename makes it permanent. Measured: config 0600 +
        # leftover tmp 0644 under umask 077 -> config 0644.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
        # 0600 from creation, and never wider than what we are replacing.
        # ``.claude.json`` carries primaryApiKey, inline MCP credentials and
        # (once the gate is armed) the proxy URL's own credential. A plain
        # write takes its mode from the umask, so a normal 022 would publish
        # all of that at 0644 — and because this is a rename, the mode
        # SURVIVES: wiring the pin permanently downgrades a 0600 config.
        # Measured: 0600 in, 0644 out.
        mode = _mode_of(path, default=0o600)
        try:
            tmp.unlink()  # our own pid's leftover; O_EXCL would reject it
        except OSError:
            pass
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, json.dumps(raw, indent=2).encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except OSError:
        return False
    # AFTER the config write, never before. This records what the config now
    # holds; writing it first and then failing the config write would claim a
    # wiring that is not there — and on an unwire, would drop the receipt for
    # proxy vars still in the file, leaving them unremovable except by hand.
    _write_ledger(path, ledger)
    return True


def _mode_of(path: Path, default: int) -> int:
    """The file's current permission bits, or ``default`` when it has none yet.

    Never widens: a config someone tightened to 0400 stays 0400, and a file
    that does not exist yet is created owner-only rather than at the umask.
    """
    try:
        return stat.S_IMODE(path.stat().st_mode) & 0o777
    except OSError:
        return default


def _ambient_chain(
    env: dict[str, str] | None = None, certdir: Path | None = None
) -> "tuple[str | None, str | None]":
    """``(hop, next_hop)`` as this launch can see them.

    When a launch prefers a recorded inner proxy over the one its own shell
    exports, the shell's value is not noise — it is the hop the inner one
    chains THROUGH, observed directly. Discarding it left the record
    single-hop, and a single-hop chain falls to a direct dial the moment its
    one hop blinks. Returning both is what lets the walk step past a dead
    inner proxy to the outer one.
    """
    src = os.environ if env is None else env
    shell_value = src.get("HTTPS_PROXY") or src.get("https_proxy")
    hop = _ambient_proxy(env, certdir)
    shell_parsed = parse_upstream_proxy(shell_value)
    hop_parsed = parse_upstream_proxy(hop)
    if (
        shell_parsed is None
        or hop_parsed is None
        or shell_parsed.address == hop_parsed.address
        or shell_parsed.port == _self_port(src)
    ):
        return hop, None
    return hop, shell_value


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
    if parsed.host in _LOOPBACK and parsed.port == _self_port(src):
        return _wired_over_proxy()
    # This shell has A proxy — but not necessarily the one Claude Code runs
    # behind. A launcher may start a per-session cache proxy and
    # points HTTPS_PROXY at THAT; an ordinary shell, and every ssh shell, only
    # has the machine-wide egress proxy the launcher itself chains to. Taking
    # the shell's value then silently drops the launcher's proxy out of the
    # chain: Measured: where `cswap pin` run over ssh recorded
    # the machine-wide proxy while the per-session cache proxy (whose own
    # upstream IS that same proxy) was left bypassed for every pinned session. Prefer the recorded one when it is
    # still serving — it is the inner link, and it reaches this one anyway.
    # Two places can name the inner proxy: what our env block displaced on a
    # previous launch, and what a previous launch recorded as the chain. Try
    # the displaced value first — it is the most direct evidence — then the
    # recorded one, which is the only source on a machine where our block has
    # never displaced anything (measured on a host where every shell exports
    # the machine-wide proxy, so the displaced value is empty and re-pinning
    # from any shell kept dropping the launcher's proxy out of the chain).
    for prev in (_wired_over_proxy(), _recorded_upstream(certdir)):
        prev_parsed = parse_upstream_proxy(prev)
        if (
            prev_parsed is not None
            and prev_parsed != parsed
            and prev_parsed[0] in _LOOPBACK
            and prev_parsed[1] != _self_port(src)
            and _port_is_serving(*prev_parsed.address)
        ):
            return prev
    return value


def _recorded_upstream(certdir: Path | None) -> str | None:
    """The chain a previous launch recorded, as a URL. See the caller."""
    if certdir is None:
        return None
    # Raw, for the same reason write_upstream_hint keeps it raw: this value
    # feeds back INTO the hint, so reconstructing it here launders the
    # credential out on the other side of the same round trip.
    return _read_upstream(certdir, "proxy") or None


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
    get_global_config_path = require("paths").get_global_config_path

    try:
        path = get_global_config_path()
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    # THROUGH `_read_ledger`, not `raw` directly. The receipt moved to the
    # account store; reading the config key alone would see nothing on any box
    # a new pin has already written, and this function's silence is what makes
    # a pinned session bypass the launcher's own proxy.
    saved = _read_ledger(path, raw).get(f"{_WIRE_MARK}Saved")
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


def _as_chain(value) -> "_Chain | None":
    """Coerce whatever named the chain into a ``_Chain``.

    The chain reaches the dial from several directions — the parsed hint, a
    constructor argument, a test's stub — and a plain ``(host, port)`` from
    any of them must simply mean "no credential, not TLS" rather than raising
    at the CONNECT. Normalizing at the point of USE covers all of them; doing
    it at one producer covers only that producer.
    """
    if value is None:
        return None
    return value if isinstance(value, _Chain) else _Chain(*value)


def _verifying_ctx(extra_ca: "Path | None" = None) -> ssl.SSLContext:
    """A verifying TLS context that trusts what THIS machine trusts.

    System roots, plus any corporate root on ``NODE_EXTRA_CA_CERTS`` — which
    is where the corporate root actually lives in the environments this
    package exists to work in. A bare ``create_default_context()`` trusts
    only public roots, so an https:// corporate proxy (signed by that same
    corporate root) fails to verify: the module is careful not to narrow the
    CLIENT's trust and would then have narrowed its own.
    """
    ctx = ssl.create_default_context()
    # Python 3.13+ VERIFY_X509_STRICT rejects a leaf with no Authority Key
    # Identifier; a corp MITM leaf may lack one. Chain-of-trust stays on.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    for cafile in (extra_ca, os.environ.get("NODE_EXTRA_CA_CERTS")):
        if not cafile:
            continue
        try:
            ctx.load_verify_locations(cafile=str(cafile))
        except (OSError, ssl.SSLError):
            pass  # unreadable/malformed: keep the roots we do have
    return ctx


class _TLSInTLS:
    """An inner TLS session carried over a socket that is ALREADY TLS.

    ``SSLContext.wrap_socket`` re-wraps the underlying FILE DESCRIPTOR, not the
    TLS stream, so calling it on an ``SSLSocket`` does not layer — it starts a
    second handshake in the clear on a socket whose peer is speaking TLS, and
    destroys the outer session doing it. Measured: the second wrap raises
    (UNEXPECTED_MESSAGE / ECONNRESET, depending on which side notices first)
    and the outer socket's ``fileno()`` is -1 afterwards, so the connection is
    unrecoverable and every pinned request through an ``https://`` egress
    proxy died at EOF with no response ever reaching the client.

    An ``https://`` proxy needs exactly that layering: the CONNECT rides the
    outer TLS, the origin's TLS rides inside it. Memory BIOs are the only way
    to get it — the inner session never touches the fd.

    Presents the subset of the socket surface this module uses upstream:
    ``sendall`` / ``recv`` / ``pending`` / ``settimeout`` / ``fileno`` /
    ``close``.
    """

    def __init__(self, ctx: ssl.SSLContext, sock, server_hostname: str) -> None:
        self._sock = sock
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._in, self._out, server_hostname=server_hostname)
        self._drive(self._obj.do_handshake)

    def _drive(self, fn, *args):
        """Run one SSLObject operation, moving bytes until it completes."""
        while True:
            try:
                out = fn(*args)
            except ssl.SSLWantReadError:
                self._flush()
                chunk = self._sock.recv(65536)
                if chunk:
                    self._in.write(chunk)
                else:
                    self._in.write_eof()
                continue
            except ssl.SSLWantWriteError:
                self._flush()
                continue
            self._flush()
            return out

    def _flush(self) -> None:
        data = self._out.read()
        if data:
            self._sock.sendall(data)

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            view = view[self._drive(self._obj.write, view) :]

    def recv(self, n: int = 65536, flags: int = 0) -> bytes:
        if flags:
            raise ValueError("flags are not supported on a layered TLS socket")
        try:
            return self._drive(self._obj.read, n)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            return b""

    def pending(self) -> int:
        return self._obj.pending()

    def settimeout(self, value) -> None:
        self._sock.settimeout(value)

    def gettimeout(self):
        return self._sock.gettimeout()

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def _wrap_upstream(ctx: ssl.SSLContext, sock, server_hostname: str):
    """TLS to the origin — layered when the socket underneath is already TLS."""
    if isinstance(sock, ssl.SSLSocket):
        return _TLSInTLS(ctx, sock, server_hostname)
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


# How long one HOP gets to accept and answer a CONNECT before it is treated as
# unusable and the walk moves to the hop behind it.
#
# NOT the same number as the upstream dial budget, and the difference is the
# point. A hop is on loopback and answers in well under a second (a real
# chain: ~260ms median, ~300ms worst for a hop that dials out itself, 0ms for
# a caching one). The upstream is across the internet and needs seconds.
#
# The budget matters because a hop can ACCEPT AND NEVER ANSWER — a process
# stopped by a signal, a listener bound before its logic is ready. Nothing
# raises, so only a deadline moves the walk on to the next hop; on the
# upstream's 15s that costs every request 15s and reads as a hang. 2s is
# ~7x the slowest healthy CONNECT, so a real hop is never cut.
_HOP_CONNECT_BUDGET_S = 2.0
# Reaching a hop and getting its answer are two different legs. The dial is
# loopback or LAN; the CONNECT reply waits for the hop's OWN outbound round
# trip to the upstream, so it carries real internet latency and needs a budget
# sized for that, not for the dial. Sharing one number cuts healthy hops.
_HOP_REPLY_BUDGET_S = 6.0

# HOW LONG TO WAIT OUT A HOP THAT IS RESTARTING, before falling through to a
# direct dial. Sized from the cache proxy's measured self-heal: ~1s to come
# back under a new pid, refusing (not hanging) throughout. A little over twice
# that leaves room for a slower box without turning a genuinely absent hop
# into a stall — a host with no chain at all never enters this loop, because
# an empty candidate list falls straight through.
_CHAIN_HEAL_GRACE_S = 2.5
# Refused dials are ~free, so poll often enough that the second the hop comes
# back is the second we use it.
_CHAIN_HEAL_POLL_S = 0.2


def _dial_chain(
    chain: "_Chain",
    timeout: float | None = None,
    extra_ca: "Path | None" = None,
) -> socket.socket:
    """Connect to the egress proxy, wrapping in TLS when the URL said https.

    Without this an ``https://`` proxy got a plaintext dial to what is a TLS
    port, so the handshake never happened and every pinned request failed in
    an environment where that proxy is the only route out.

    ``extra_ca`` is the CA recorded alongside the proxy in ``upstream.json``.
    Passing it matters because the daemon is spawned from a plain shell, which
    normally has no ``NODE_EXTRA_CA_CERTS`` — so a corporate root that exists
    only in the hint would otherwise never be consulted, and verification of
    the very proxy it describes would fail.
    """
    # READ THE BUDGET AT CALL TIME. As a default argument it was frozen at
    # import, so nothing could adjust it afterwards — not a future caller, and
    # not a test pointing the walk at a hop that never answers.
    if timeout is None:
        timeout = _HOP_CONNECT_BUDGET_S
    sock = socket.create_connection(chain.address, timeout=timeout)
    # create_connection leaves the DIAL budget on the socket, where it would
    # then bound every read. Reaching a hop and waiting for its answer are
    # different legs: the dial is loopback or LAN, the answer waits on the
    # hop's own outbound round trip. Hand back a socket already carrying the
    # budget for the leg that comes next, so no caller has to remember.
    sock.settimeout(_HOP_REPLY_BUDGET_S)
    if not chain.tls:
        return sock
    try:
        return _verifying_ctx(extra_ca).wrap_socket(sock, server_hostname=chain.host)
    except (OSError, ssl.SSLError):
        sock.close()
        raise


def _dial_with_no_chain(upstream: tuple[str, int], timeout: float = 15):
    """What to do when NO hop is usable and none is recorded behind them.

    THE ONE PLACE THIS DECISION IS MADE, deliberately. A direct dial is not
    "no proxy" on a machine whose direct route is a TLS-inspecting corporate
    proxy: the leaf it returns has no Authority Key Identifier, so a strict
    verifier refuses it and OAuth against claude.ai breaks with nothing on
    screen. Refusing instead would honour that — at the cost of the standing
    rule that a pin must never block traffic, and on a machine with no
    inspector the direct dial is simply correct.

    Dials. Changing it to refuse is this function's body and nothing else.
    """
    return socket.create_connection(upstream, timeout=timeout)


def _connect_ok(status: "str | None") -> bool:
    """Whether a CONNECT status line reports success.

    ``" 200" in status`` reads the whole line, reason phrase included, so a
    refusal that merely MENTIONS 200 was accepted as one. Measured on real
    shapes a filtering proxy emits: ``502 Bad Gateway (upstream returned
    200)``, ``403 Blocked by policy rule 200`` and ``HTTP/1.1 2000 Nonsense``
    all passed. The blind tunnel then pumped the proxy's HTML error page to
    the client as if it were the origin's TLS bytes, and the "chain refused →
    dial direct" rescue never ran.
    """
    parts = (status or "").split()
    return len(parts) >= 2 and parts[0].startswith("HTTP/") and parts[1] == "200"

_UPSTREAM_FILE = "upstream.json"

# Registration of THIS client, not ownership of the session.
_PRESENCE = re.compile(r"^/v1/(code/)?sessions/[^/]+/client/presence(/|$|\\?)")

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
    # ``client/presence`` is NOT ownership, it is REGISTRATION. It posts
    # {client_id, clear} and gets a poll interval back — it is how this CLI
    # tells the server "I am attached to this session, send me things". Swapped,
    # the server registers the PINNED account as the attached client while the
    # process actually listening is the active one, so inbound has nobody to go
    # to. Measured: presence was the only route being swapped in a live window
    # (3 calls, all 200) while Remote Control received nothing.
    #
    # The pin is about who OWNS the claude.ai-side assets, not about who is
    # sitting at the terminal. Registration must stay with the account whose
    # process will do the receiving.
    if _PRESENCE.search(path):
        return False
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
# spurious expiry mid-session and matches the 10-year leaf a sibling proxy issues.
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
    ca_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    ca_pem = ca_dir / "ca.pem"
    ca_key = ca_dir / "ca.key"
    leaf_pem = ca_dir / "leaf.pem"
    leaf_key = ca_dir / "leaf.key"

    # Serialized, because the CA test and the leaf test used to be independent
    # conditions over four separately-written files with nothing holding them
    # together. Two sessions starting in the same second (first pin, or after
    # a cert-dir wipe) could interleave so that ca.pem did not sign leaf.pem —
    # measured on repeated trials — and since this function is idempotent it
    # NEVER self-healed: every later launch reused the mismatched pair and
    # Node reported "unable to verify the first certificate" until a human
    # deleted the directory.
    with _spawn_lock(ca_dir, name=".ca.lock"):
        if not _certs_consistent(ca_pem, ca_key, leaf_pem, leaf_key, host):
            # Regenerate BOTH. Keeping a CA whose leaf must be reissued would
            # leave already-wired sessions trusting a root that no longer
            # matches what this proxy serves.
            ca_cert, ca_priv = _make_ca()
            _write_public(ca_pem, ca_cert.public_bytes(serialization.Encoding.PEM))
            _write_key(ca_key, ca_priv)
            leaf_cert, leaf_priv = _make_leaf(host, ca_cert, ca_priv)
            _write_public(leaf_pem, leaf_cert.public_bytes(serialization.Encoding.PEM))
            _write_key(leaf_key, leaf_priv)

    return CertBundle(ca_path=ca_pem, leaf_path=leaf_pem, leaf_key_path=leaf_key)


def _certs_consistent(
    ca_pem: Path, ca_key: Path, leaf_pem: Path, leaf_key: Path, host: str
) -> bool:
    """Whether the four files on disk form ONE usable, unexpired set.

    Every existence test here used to stand alone, so a dir holding a CA from
    one generation and a leaf from another passed. What the client actually
    needs is a single question: does the CA it will trust sign the leaf this
    proxy will serve, for this host, today. Answering it directly also covers
    expiry — the previous code tested only ``exists()``, so a CA reaching its
    ``not_valid_after`` would have been reused forever.
    """
    try:
        if not all(p.exists() for p in (ca_pem, ca_key, leaf_pem, leaf_key)):
            return False
        ca = x509.load_pem_x509_certificate(ca_pem.read_bytes())
        leaf = x509.load_pem_x509_certificate(leaf_pem.read_bytes())
        # `unsafe_skip_rsa_key_validation` skips OpenSSL's RSA_check_key, which
        # costs 27ms per key — 55ms of every single launch, measured, spent
        # re-proving the primality of a key THIS code generated and wrote 0600
        # into its own dir. The check defends against an ATTACKER-supplied key
        # (fault attacks on a key you did not make); it is not a corruption
        # check. PEM framing, DER structure, and the algorithm are still parsed
        # and still raise on a truncated or foreign file, which is the only
        # failure this function is asking about. Landed in cryptography 39.0,
        # well under the 42.0 floor above.
        serialization.load_pem_private_key(
            ca_key.read_bytes(), password=None, unsafe_skip_rsa_key_validation=True
        )
        lkey = serialization.load_pem_private_key(
            leaf_key.read_bytes(), password=None, unsafe_skip_rsa_key_validation=True
        )
        if lkey.public_key().public_numbers() != leaf.public_key().public_numbers():
            return False
        # Renew a month early: a cert that expires mid-session takes the
        # session with it, and regenerating is cheap.
        soon = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30)
        if min(ca.not_valid_after_utc, leaf.not_valid_after_utc) <= soon:
            return False
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if host not in san:
            return False
        ca.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )
        return True
    except AttributeError as exc:
        # NOT the same as a cert failure. A MISSING API means the CODE is wrong
        # for the cryptography that is installed — and "regenerate" is the
        # worst possible response: it is deterministic, so it fires on EVERY
        # launch and the daemon serves a leaf under a CA the session was never
        # handed. That is how a floor of `cryptography>=41.0` turned into
        # CERTIFICATE_VERIFY_FAILED on every request, silently, for anyone
        # whose resolver picked 41.x (`not_valid_after_utc` landed in 42.0).
        #
        # BUT ONLY FOR THE VERSION MISMATCH. The same AttributeError is raised
        # by a perfectly valid cert dir that simply is not RSA — this function
        # uses `public_numbers()` and PKCS1v15, so a self-consistent Ed25519
        # pair (a restored backup, someone's own openssl run) hit the re-raise
        # too. 0.1.3 returned False there and regenerated on the next launch;
        # propagating instead kills `PinProxy.__init__`, which does NOT fail
        # open, so the daemon dies at construction and can never repair a
        # directory the previous release healed by itself.
        #
        # Name the API this code requires. Absent -> the library moved, be
        # loud. Present -> the certs are simply of another kind, regenerate.
        if not hasattr(x509.Certificate, "not_valid_after_utc"):
            raise
        return False
    except TypeError:
        # Same reasoning, and the same narrow intent: a changed SIGNATURE in
        # the library. Anything a cert itself can cause is a cert failure.
        if not hasattr(x509.Certificate, "not_valid_after_utc"):
            raise
        return False
    except Exception:  # noqa: BLE001 — any failure to prove it means regenerate
        return False


def _write_public(path: Path, data: bytes) -> None:
    """A world-readable PEM, written whole or not at all.

    ``write_bytes`` on the live path leaves a truncated file readable by a
    concurrent reader; the temp-then-replace makes the swap atomic. The pid
    suffix is not decoration: ``O_CREAT``'s mode argument is IGNORED for a
    file that already exists, so a fixed temp name left behind by a crashed
    write would dictate the final mode and the rename would make it permanent.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


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
            # extension". an openssl-generated CA happened to carry it;
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
    """A private key that is never briefly world-readable.

    ``write_bytes`` then ``chmod`` creates the file at the process umask —
    0644 under the usual 022 — and the complete key bytes sit at that mode
    until the chmod lands. A reader that opens the path inside that window
    keeps a valid fd afterwards, so the later chmod does not close it. The CA
    key is the one secret here whose compromise no restart can undo, so it is
    created at 0600 and never exists at anything wider. Pid-suffixed and
    O_EXCL because ``O_CREAT``'s mode is IGNORED for an existing file: a
    leftover temp from a crashed write would otherwise dictate the mode.
    """
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    tmp = path.with_name(f"{path.name}.{os.getpid()}.cswap-tmp")
    try:
        tmp.unlink()
    except OSError:
        pass
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


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
    _settings = require("settings")

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

    Reads through the host's WRITE-side reader, which raises on a malformed
    file instead of degrading to ``{}``. ``_read_raw``'s degrade is right for
    a read — a corrupt settings file should not stop the app — but in a
    read-modify-write it means starting from empty and then writing back only
    the pin section, silently discarding autoswitch, UI and every unknown key
    from a file that was probably still hand-recoverable.
    """
    _settings = require("settings")

    path = _settings.settings_path(backup_root)
    # ``_read_raw_for_write`` is newer than this package's floor on the host,
    # so fall back rather than fail the pin outright on an older claude-swap.
    read = getattr(_settings, "_read_raw_for_write", None) or _settings._read_raw
    raw = read(path)
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
    get_claude_config_home = require("paths").get_claude_config_home

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


def _live_bridge_ids() -> set[str]:
    """Bridge ids whose owning process is still alive on THIS machine.

    A record alone is not liveness: Claude Code leaves the file behind when a
    session dies, so the registry accumulates. Measured here: 562 records, 293
    of them still ``connected`` server-side, 16 with a process.

    Both spellings, because the API renames the id it hands back:
    ``session_…`` locally, ``cse_…`` in the listing.
    """
    get_claude_config_home = require("paths").get_claude_config_home

    live: set[str] = set()
    try:
        entries = list((get_claude_config_home() / "sessions").glob("*.json"))
    except OSError:
        return live
    for path in entries:
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        bridge, pid = rec.get("bridgeSessionId"), rec.get("pid")
        if not bridge or not isinstance(pid, int) or not _pid_alive(pid):
            continue
        live.add(str(bridge))
        live.add(str(bridge).replace("session_", "cse_"))
    return live


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
        # DISARM. The gate is only meaningful while a pin exists, and leaving
        # the secret behind means "I turned the pin off" and "the proxy still
        # demands a credential" are both true at once — a state no user has a
        # model for. Worse, the next `cswap pin` re-arms it against sessions
        # wired in between, which is exactly the 407 storm this is fixed for.
        #
        # ABSENT AND REFUSED ARE NOT THE SAME OSError. FileNotFoundError means
        # there was never anything armed — fine, `False` is correct. Any other
        # OSError (permission denied, a read-only mount) means the secret is
        # STILL THERE and this function is about to return the exact `False`
        # a successful disarm would, which every caller reads as "nothing is
        # armed". RE-RAISE rather than log: logging still returns the false
        # `False`, and the caller's next decision — including the next `cswap
        # pin` re-arming against sessions wired in the meantime — is made on
        # that return value, not on a log line nobody is required to read.
        try:
            proxy_secret_path(switcher.backup_dir / "pin-proxy").unlink()
        except FileNotFoundError:
            pass  # never armed, or already disarmed: nothing to do
        return False
    # Mint the proxy credential HERE, not in the daemon. This is the one path
    # that also rewrites the wiring, so the gate and the URL that satisfies it
    # arrive together, at a moment an operator chose. A daemon respawn must
    # never arm it by itself: that would fire on a fingerprint recycle, a
    # deploy or an idle teardown, with nothing a human could connect to the
    # resulting failures. An existing secret is reused, so re-pinning does not
    # invalidate anything.
    certdir = switcher.backup_dir / "pin-proxy"
    # Arming is a ONE-WAY DOOR for every session already running, so count
    # them BEFORE minting — afterwards the connections are already being
    # refused and the number is gone. Only when the secret does not exist
    # yet: re-pinning reuses it and cuts off nobody.
    global _last_arm_cutoff
    _last_arm_cutoff = None
    if read_proxy_secret(certdir) is None:
        port = _read_alive_port(certdir)
        if port is not None:
            _last_arm_cutoff = clients_that_arming_would_cut_off(port)
    try:
        certdir.mkdir(parents=True, exist_ok=True)
        ensure_proxy_secret(certdir)
    except OSError:
        pass  # unwritable cert dir: serve unauthenticated rather than not at all
    return ensure_proxy(switcher) is not None


# Set by the last apply_pin: how many live clients that call's arming cut off,
# or None when it armed nothing (or could not measure). A module global rather
# than a return value because apply_pin's bool is load-bearing for two callers
# and the TUI menu; this is advisory, and a caller that ignores it is correct.
_last_arm_cutoff: int | None = None


def last_arm_cutoff() -> int | None:
    """Live clients cut off by the most recent :func:`apply_pin`, if any.

    None means nothing was armed — the usual case, since the secret is minted
    once and reused. A number means those sessions will 407 on their next
    request and only a relaunch fixes them, which is the thing an operator has
    to be told at the moment they can still act on it.
    """
    return _last_arm_cutoff


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

    **Across PROCESSES too.** A thread lock only binds this daemon, and this
    daemon is not the only thing that refreshes a backup slot: the usage
    collector and the autoswitcher do it from their own processes. Two
    processes POSTing one one-time grant is the same lineage death by a
    different door, so the refresh goes through the switcher's
    ``consume_backup_grant`` gate, which holds a per-slot FILE lock across
    re-read → POST → fingerprint-CAS. The gate persists the rotation itself;
    the thread lock stays because it is cheaper for the in-process case and
    keeps N threads off the file lock.
    """
    refresh_lock = threading.Lock()

    def _consume(creds: str, num: str, mail: str) -> "oauth.RefreshOutcome":
        """Refresh through the host's interprocess gate, direct POST as
        fallback. An older claude-swap has no gate; a pinned request must
        still be served, and a same-process race is still covered by
        ``refresh_lock``.

        The gate can answer ``consume-busy`` (another process holds the
        slot). That yields no token, so this request goes out unpinned and
        the next one retries — the same fail-open the provider already has
        for an unreadable credential, and strictly better than the direct
        POST it replaces, which answered ``invalid_grant`` and killed the
        lineage outright.
        """
        gate = getattr(switcher, "consume_backup_grant", None)
        if gate is None:
            return oauth.try_refresh_oauth_credentials(creds)
        outcome = gate(num, mail, creds)
        # Remember a DEFERRAL. "consume-busy" means another process holds the
        # slot right now, which is a race with the usage collector, not a
        # broken daemon — and the caller's only other signal is a None token,
        # which it reads as "this daemon cannot pin" and records permanently.
        if getattr(outcome, "error", None) == "consume-busy":
            _deferred.add(1)
        return outcome

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
        _exc = require("exceptions")
        AccountNotFoundError, ConfigError = _exc.AccountNotFoundError, _exc.ConfigError

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

    # A one-shot flag for the pass currently running: set when the refresh was
    # DEFERRED rather than failed, so pin_is_noop can say "no token, but do not
    # condemn this daemon". A set is used only for its atomic add/discard.
    _deferred: set[int] = set()

    def provider() -> str | None:
        _deferred.discard(1)
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
                creds, lambda c: _consume(c, num, mail)
            )
            # The gate persists internally (under the slot lock, CAS on the
            # refresh-token fingerprint). Persisting again here would write
            # back OUTSIDE that lock and could clobber a racing writer's
            # newer lineage — the exact failure the gate exists to prevent.
            if rotated and not hasattr(switcher, "consume_backup_grant"):
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
        if 1 in _deferred:
            # The refresh was DEFERRED, not failed: another process holds the
            # slot's consume lock (the usage collector polls on its own
            # schedule and contends for exactly this slot). This request goes
            # out unpinned and the next one retries — but the caller's only
            # other reading of a None token is "this daemon cannot pin", which
            # it records into proxy.json permanently, so one lost race would
            # condemn a healthy daemon for good.
            return True
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
    _exc = require("exceptions")
    AccountNotFoundError, ConfigError = _exc.AccountNotFoundError, _exc.ConfigError

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
    # ...and the hop BEHIND it, asked of that hop while it is answering. A
    # launch is the only moment that question has a trustworthy answer, and it
    # is what lets a dead hop fall through to the next one instead of to a
    # direct dial (see ``_probe_next_hop``).
    ambient, observed_next = _ambient_chain(certdir=certdir)
    # Two independent sources for the hop BEHIND this one, and they fail in
    # different conditions: the probe needs the inner hop to be answering,
    # while the shell's own proxy is visible whether or not it is. Prefer the
    # probe (it is what the hop reports about itself) and fall back to what
    # this launch observed directly.
    write_upstream_hint(
        certdir,
        ambient,
        os.environ.get("NODE_EXTRA_CA_CERTS"),
        next_hop=_probe_next_hop(ambient or _read_upstream(certdir, "proxy"))
        or observed_next,
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
    # spawner (an mkdir election). Re-check under the lock — another launch
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
        # "Alive" is not "still ours". An unclean exit leaves proxy.json
        # behind, and a pid is reused freely — so liveness alone would aim
        # SIGTERM (then SIGKILL) at whatever unrelated process inherited the
        # number. Ask whether the pid is a pin daemon for THIS certdir, which
        # is exactly what the orphan sweep already asks.
        #
        # When the identity cannot be established at all (no ``ps``), this
        # recycles nothing rather than killing on faith. The stale daemon
        # keeps its port, the successor binds an ephemeral one and the
        # wiring is rewritten to it — degraded, but nobody else's process
        # gets killed. The same blind spot already bounds the orphan sweep.
        if stale and int(stale["pid"]) in _pin_daemon_pids(certdir):
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


def _spawn_lock(certdir: Path, name: str = ".spawn.lock"):
    """Exclusive file lock serializing daemon spawns (one elected spawner).

    ``name`` picks which lock: cert generation takes its own so it cannot
    deadlock against a spawn that is itself waiting on cert generation.
    """
    import fcntl
    from contextlib import contextmanager

    @contextmanager
    def _locked():
        Path(certdir).mkdir(parents=True, exist_ok=True)
        lockf = open(Path(certdir) / name, "w")
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
    holding a port. Mirrors a supervisor recycle: bounded wait, then force.

    THE TERM BUDGET IS DERIVED FROM THE DRAIN, NOT CHOSEN. A daemon answering
    TERM runs ``stop(drain=_DRAIN_SECONDS)``, so a fixed 2s wait here SIGKILLed
    it mid-drain and the release's headline guarantee — in-flight requests
    survive an upgrade — held only for a signal sent by hand, never for the
    recycle the code itself performs. Measured against a real streaming client:
    the client received 4 of 10 SSE events and the drain marker was never
    written, because the process was killed before ``stop`` returned.

    Two independently-chosen timeouts that must be ordered is a bug that comes
    back every time either is tuned, so the ordering is computed. The slack
    covers teardown that is not draining (closing conns, unlinking state).
    """
    import time

    # A PID, NOT A GROUP. In ``kill(2)`` a pid of 0 addresses the CALLER'S OWN
    # process group and a negative pid addresses the group named by its
    # absolute value — so a derived-but-wrong 0 arriving here does not fail,
    # it SIGTERMs this daemon and whatever spawned it. Every caller today
    # derives its pid from ``ps`` output and cannot produce one, but that is a
    # property of the CALLERS, and a guard that lives in each of them is one
    # new call site away from being missed. A peer landed exactly here with
    # SIGKILL and took down its own test runner.
    if pid <= 0:
        return
    try:
        os.kill(pid, 15)  # SIGTERM
    except OSError:
        return
    # +2s of slack past the drain ceiling; the loop exits the moment it dies,
    # so a daemon with no live clients still returns in milliseconds.
    for _ in range(int(_DRAIN_SECONDS * 10) + 20):
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
        if not any(m in line for m in _DAEMON_MODULE_NAMES):
            continue
        # The certdir must be the LAST argv token, not merely present. This
        # gate decides whether to SIGTERM-then-SIGKILL, and a substring match
        # also selects anything that happens to MENTION both — a shell whose
        # command line quotes them, a wrapper, a grep. Measured: a probe shell
        # matched alongside the daemon it was probing for.
        head, _, rest = line.partition(" ")
        if not rest.rstrip().endswith(" " + target):
            continue
        # NOT THE HOLDER. Its argv is the daemon's plus one flag, so it passes
        # both gates above — and it is the one process here whose death takes
        # the port with it, which is the outage the holder exists to prevent.
        if f" {_HOLDER_MODULE_ARG} " in rest:
            continue
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
            # NAME THE SIGNAL. A TERM from a recycle and an idle teardown are
            # the same code path and left the same (empty) trace, so a daemon
            # that vanished could not be told from one that was killed.
            cleanup(f"signal {signal.Signals(signum).name}")
        except TypeError:
            cleanup()  # a cleanup that takes no reason (tests)
        finally:
            # A TERM IS A RECYCLE, NOT A RELEASE. Somebody wants this daemon
            # replaced — a redeploy, a repin, a fingerprint change — and under
            # a holder that means "put a successor on this socket", not "give
            # the port back". Exiting 0 here made the holder release the port:
            # measured, 186,206 refused connections across three SIGTERMs.
            #
            # THE HOLDER IS IDENTIFIED BY THE HAND-DOWN VARIABLES, not by
            # LISTEN_PID. That was the first version and it was always false —
            # the holder cannot know its child's pid before spawning, so it
            # uses the predecessor protocol instead (fd by number, guarded by
            # the parent's pid), and nothing ever set LISTEN_PID to ours.
            #
            # Only when a holder owns the socket: without one there is nothing
            # to interpret the code, and 0 is what every existing caller reads.
            os._exit(
                _RESTART_ME_CODE
                if held_by_a_holder()
                else 0
            )

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass  # not on the main thread (tests) — best effort


_DAEMON_MODULE = "cswap_pin.proxy"
# Same module, same certdir, one flag apart — which is why `_pin_daemon_pids`
# has to exclude it explicitly rather than by argv shape.
_HOLDER_MODULE_ARG = "--hold-port"

# The orphan sweep finds daemons by matching their argv, so during the split it
# must recognise BOTH module paths. A machine mid-cutover can have a daemon
# spawned by the OLD in-tree module still serving while the new package is
# installed; matching only the new name would make that daemon invisible to the
# sweep and leave it holding its port forever — the exact leak aab7246 fixed.
# The old name stays until every deployed machine has been re-pinned under
# cswap-pin; removing it early costs a leaked daemon, removing it late costs
# nothing.
_DAEMON_MODULE_NAMES = (_DAEMON_MODULE, "claude_swap.pin_proxy")

_STATE_FILE = "proxy.json"
# How long `_spawn_daemon` waits for a successor to publish. 10s because a
# FIRST run generates an RSA key pair before it can serve.
_SPAWN_WAIT_S = 10.0
# The pin's OWN settings, in the pin's OWN directory. `CSWAP_PIN_PORT` used to
# live in `~/.claude.json`'s env block, and it is the one entry there that
# Claude Code never reads — HTTPS_PROXY, https_proxy, ALL_PROXY and
# NODE_EXTRA_CA_CERTS are consumed by CC at boot; that number is consumed only
# by us. Settings for an optional feature do not belong in another program's
# exclusive file, and a user who wanted a fixed port had nowhere to say so.
_SETTINGS_FILE = "settings.json"
_FIFO_NAME = "refcount.fifo"
_LOG_NAME = "daemon.log"
_LOG_MAX_BYTES = 64 * 1024


def configured_port(certdir: Path) -> int | None:
    """The port the user asked us to serve on, or None for an ephemeral one.

    ONE SOURCE: ``settings.json``, written by ``cswap pin --set_port``.

    NOT ``CSWAP_PIN_PORT``: `wire_global_config` writes that name into
    `.claude.json` as the self-loop marker and Claude Code applies the block
    at boot, so inside a pinned session it is already the LIVE daemon's port.
    Reading it as config made the pin fight itself for a port it was on.

    0 is not a port to bind: `bind()` reads it as "choose one for me", so
    `--set_port 0` CLEARS the setting, which is how a dynamic port is asked
    for.
    """
    try:
        port = int(_settings_port(certdir))
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _settings_port(certdir: Path) -> object:
    """The persisted port, raw. Unreadable or absent is no opinion."""
    try:
        raw = json.loads(
            (Path(certdir) / _SETTINGS_FILE).read_text(encoding="utf-8")
        )
    except Exception:  # noqa: BLE001 — absent/unreadable/malformed: no opinion
        return None
    return raw.get("port") if isinstance(raw, dict) else None


def write_pin_settings(certdir: Path, *, port: int | None) -> None:
    """Persist the requested port, or drop it when ``port`` is None.

    READ-MODIFY-WRITE, not a truncate. This is a SETTINGS file: the next
    setting to land here would otherwise be erased by the next `--set_port`,
    which is the kind of loss nobody notices until the setting they set has
    quietly gone.
    """
    path = Path(certdir) / _SETTINGS_FILE
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
    except Exception:  # noqa: BLE001 — absent or garbage: start clean
        raw = {}
    if port is None:
        raw.pop("port", None)
    else:
        raw["port"] = int(port)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def refcount_fifo_path(certdir: Path) -> Path:
    """Path of the refcount FIFO. Sessions hold a write fd on it; the daemon
    reads it and exits when the last holder closes (a FIFO refcount)."""
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


def _log_lifecycle(what: str) -> None:
    """Record one daemon lifecycle event, with a timestamp, to stderr.

    The daemon's stderr IS ``daemon.log`` (see :func:`_open_daemon_log`), so
    this needs no file handling of its own and cannot fight the spawner for
    the fd.

    WHY THIS EXISTS. The log carried warnings only, so a daemon that started,
    served for hours and disappeared left a ZERO-BYTE file. When every session
    on a machine went down behind a dead pin, the log could not say when the
    daemon went away, or whether it was an idle teardown, a signal, or a crash
    — and with several agents working on the box at the time, the cause stayed
    unattributable. An outage you cannot attribute is one you cannot prevent.

    Never raises: a daemon must not die trying to record that it is dying.
    """
    try:
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"[{stamp}] pid={os.getpid()} {what}", file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001
        pass


# How long a departing daemon lets in-flight requests finish before it exits.
#
# A CEILING, not a wait: an idle daemon returns immediately, so this costs
# nothing in the common case. It is sized for a streaming `/v1/messages`
# response rather than for a whole conversation — the point is that an upgrade
# or a recycle does not cut a reply in half, not that the daemon lingers for a
# client that has gone quiet. A request still running at the end is cut, which
# is the same outcome as before this existed.
_DRAIN_SECONDS = 30.0

_FIRST_HOLDER_TIMEOUT = 300.0

# How long to wait before re-asking whether a daemon whose last FIFO holder
# left is still claimed. A blocking read on a writer-less FIFO returns EOF
# immediately and keeps doing so, so the re-check has to pace itself. The
# cost of waiting is an idle daemon lingering this much longer; the cost of
# not waiting is a busy loop.
_CLAIM_RECHECK_INTERVAL = 5.0


_WIRED_ONCE_MARKER = ".was-wired"


def _mark_wired_once(certdir: Path, port: int) -> None:
    """Record that the global wiring named ``port`` for THIS cert dir.

    On disk rather than in a process global: the qualification belongs to the
    daemon-and-certdir pair, and a module-level set is shared by everything in
    the interpreter. In tests that is a silent cross-contamination (one case
    wires a port, the next reuses the number for an orphan and inherits the
    qualification); in production a single process can serve more than one
    certdir over its life. Best-effort — a lost mark costs one skipped repair,
    which the next tick retries.
    """
    try:
        (certdir / _WIRED_ONCE_MARKER).write_text(str(port), encoding="utf-8")
    except OSError:
        pass


def _was_wired_once(certdir: Path, port: int) -> bool:
    try:
        return (certdir / _WIRED_ONCE_MARKER).read_text(encoding="utf-8").strip() == str(port)
    except OSError:
        return False


def _repair_wiring_if_ours(certdir: Path, port: int, live_clients=None) -> bool:
    """Re-point a pin wiring that names a DEAD port back at this daemon.

    RECOVERY HAS TO LIVE IN THE PACKAGE THAT HAS THE BUG. Until now the only
    thing that ever repaired a pin without a human was one developer's
    status line, spawning ``cswap pin --heal`` on a timer. A census of the
    host found exactly one caller of ``heal`` — the CLI, i.e. a person typing
    it. So anyone who installs cswap-pin and does not also install that
    person's dotfiles has NO automatic recovery: a wiring that points at a
    dead port stays broken, and what they see is "new sessions cannot reach
    the API", with nothing connecting that to the pin.

    The daemon is the right host because it needs no external timer, no TUI
    and no shell integration — it is already running, and it already re-reads
    the wiring every few seconds (``_is_claimed``, from ``watch_refcount``).
    That check asked "does the config still name me?" purely to decide
    whether to keep serving; the answer "no" was equally consistent with
    "someone unpinned" and with "the config is broken", and both were treated
    as the former.

    THE TWO ARE DISTINGUISHED BY WHETHER THE WIRED PORT ANSWERS:

      * it answers            -> another daemon owns the pin, or the user
                                 re-pinned elsewhere. NOT ours to touch.
      * nothing is wired      -> the pin was cleared. Leave it cleared.
      * wired, and DEAD       -> the wiring is broken and we are the daemon it
                                 should name. Repair it.

    Measured, and this is the state that motivated it: a config rewritten to
    port 52000 while this daemon served 36301. Every running session was fine
    (their env is fixed at exec) and every NEW session inherited a port
    nothing listened on. The daemon was healthy the whole time, so nothing
    that watches the daemon could see it.

    Never raises: a repair that can crash the refcount watcher would trade a
    broken wiring for a dead pin.
    """
    try:
        # ONLY A REAL, SERVING DAEMON MAY REPAIR. ``live_clients`` is the
        # daemon's own connection counter, handed in by the process that owns
        # the listening socket — so its presence IS the proof that a server
        # exists here. A bare refcount watcher with no server (a test harness,
        # a helper thread) must never rewrite a user's config: it cannot honour
        # the port it would advertise.
        #
        # Measured: without this, a leaked watcher thread from one test kept
        # running past its fixture and rewrote the NEXT test's config to a port
        # nothing served — the same class of cross-contamination as writing to
        # a live config, one scope up.
        if live_clients is None:
            return False
        # ONLY A DAEMON THE WIRING ONCE NAMED MAY RECLAIM IT. Without this the
        # repair is indistinguishable from a hijack, and it disables the orphan
        # reaper outright: a daemon left behind by a crashed spawn — one the
        # config never named — would see a wiring it does not match, call it
        # "broken", and rewrite the user's config to point at ITSELF. It then
        # counts as claimed forever and never times out. Measured: two reaper
        # tests went red, and the shape they describe is a real leak, not a
        # fixture artifact.
        #
        # Being wired at least once is what separates the two populations. The
        # daemon this exists for was serving a wiring that named it and then
        # lost it; an orphan never had one.
        if not _was_wired_once(certdir, port):
            return False
        wired = _wired_port()
        if wired is None or wired == port:
            return False  # unpinned, or already correct — not our business
        # Does the port the config names actually answer? If it does, someone
        # else legitimately owns the pin and rewriting would steal it.
        try:
            with socket.create_connection(("127.0.0.1", wired), timeout=1):
                return False
        except OSError:
            pass  # dead, as expected for the broken case
        # And the record must still be OURS — checked by the caller, but the
        # connect above took time, so re-read rather than trust the gap.
        st = read_daemon_state(certdir)
        if not st or int(st.get("pid") or 0) != os.getpid():
            return False
        if int(st.get("port") or 0) != port:
            return False
        wire_global_config(port, certdir / "ca.pem")
        _log_lifecycle(f"repaired a wiring that named dead port {wired} -> {port}")
        return True
    except Exception:  # noqa: BLE001 — never break the watcher
        return False


def _is_claimed(certdir: Path, live_clients=None) -> bool:
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

    A LIVE CONNECTION IS ALSO A CLAIM, and it is the one that matters when the
    pin is turned OFF. `cswap pin --clear` removes the wiring, so the two
    checks above both go false at once — and the daemon tore itself down while
    real sessions were still talking to it. Their HTTPS_PROXY is fixed at exec,
    so they could not be told; they got ConnectionRefused and retried forever
    (measured: 312 processes, `attempt 6/300`, plus "Auto-update failed").

    That is the same root as the 407 — env cannot be updated in a running
    process — pointing the other way: arming broke them, and disarming broke
    them too. A daemon someone is actually connected to is not idle, whatever
    the config says, so serving that traffic until it drains is what makes
    turning the pin off as harmless as turning it on.

    ``live_clients`` is that question asked of the daemon itself (its own
    connection count). It must be, because the socket-scan answer is
    Linux-only: on macOS it returns None, and None was being read as "not
    claimed" — turning the one check that protects a live session into a
    guaranteed false on the platform where the pin is used most.
    """
    try:
        st = read_daemon_state(certdir)
        if not st or int(st["pid"]) != os.getpid():
            return False  # not our record — say nothing about our own liveness
        port = int(st["port"])
        if _wired_port() == port:
            # Remember it, because this is the ONLY moment that proves we are
            # the pin's daemon rather than an orphan. See _repair_wiring_if_ours.
            _mark_wired_once(certdir, port)
            return True
        # A SUCCESSFUL REPAIR IS ITSELF A CLAIM. Discarding this return value
        # meant the daemon re-pointed the wiring at itself and then, in the
        # same call, reported "nobody references me" — and `watch_refcount`
        # answers that by tearing the daemon down, running
        # `wire_global_config(None, None)` and undoing the repair microseconds
        # after making it. The wiring was broken-but-pointing-somewhere before;
        # afterwards there is no daemon and no pin at all.
        #
        # It is the LIKELY path on macOS, not a corner: the socket scan below
        # reads /proc/net/tcp, which macs do not have, so only `live_clients()
        # > 0` can save it — and a repair fires precisely when new sessions
        # cannot reach the daemon, i.e. when that count is trending to zero.
        # Measured through the real watch_refcount loop:
        #     events: [('wire', 34209), ('TEARDOWN', None)]
        if _repair_wiring_if_ours(certdir, port, live_clients):
            return True
        # Ask the daemon itself first. It is the only source that answers on
        # every platform: the socket scan below reads /proc/net/tcp, which
        # BOTH MACS lack, and its None was being coerced to "not claimed" —
        # so on macOS a hand-launched session with a live connection was
        # counted as idle and `pin --clear` tore its proxy out from under it.
        if live_clients is not None:
            try:
                if live_clients() > 0:
                    return True
            except Exception:
                pass
        live = clients_that_arming_would_cut_off(port)
        if live is None:
            # Unmeasurable, and the daemon's own count said zero (or was not
            # offered). Nothing established a claim; the caller's timeout
            # decides. Distinct from a measured zero only in that we cannot
            # corroborate it.
            return False
        return bool(live)
    except Exception:
        return False


def watch_refcount(
    fifo: str | Path,
    on_last_holder_gone,
    first_holder_timeout: float | None = None,
    live_clients=None,
) -> None:
    """Block on ``fifo`` until every write-holder closes, then call
    ``on_last_holder_gone``. This is a supervisor holding `cat FIFO`:
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

    **Both exits ask that question.** The claim check used to guard only the
    first-holder timeout, so a daemon that HAD holders tore down the moment
    the last one closed — no matter that the global wiring still named it or
    that connections were still draining on it. Those sessions cannot be told
    (their ``HTTPS_PROXY`` is fixed at exec), so they got ConnectionRefused
    and retried forever. Teardown now means "no holder and nothing else
    claims us", whichever door it arrives by.
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
                if _is_claimed(Path(fifo).parent, live_clients):
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
    import time as _time

    try:
        while True:
            data = os.read(fd, 65536)  # blocks; returns b"" at EOF (no writers)
            if data == b"":
                # A FIFO holder is not the only claim, and the first-holder
                # timeout above already knows that — this end did not. The
                # last WRAPPER-launched session closing says nothing about
                # the globally-wired and hand-launched sessions that never
                # open the FIFO at all, nor about live connections still
                # draining. Tearing down on their behalf strands them on an
                # HTTPS_PROXY fixed at exec: the ConnectionRefused loop
                # ``_is_claimed`` exists to prevent, arriving by the one door
                # that never asked it.
                if _is_claimed(Path(fifo).parent, live_clients):
                    _time.sleep(_CLAIM_RECHECK_INTERVAL)
                    continue  # still referenced — keep serving, re-check
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


def clients_that_arming_would_cut_off(port: int) -> int | None:
    """How many live processes are talking to the proxy right now.

    Arming the gate rejects every client whose ``HTTPS_PROXY`` carries no
    credential, and that variable is fixed at exec — a running session cannot
    be updated in place. So the honest question before minting a secret is
    "who is using this port", and the answer has to reach the operator, or the
    docstring's "pair it with a relaunch" is advice nobody can act on.

    COUNTS SOCKETS, NOT ENVIRONMENTS. A previous version of this counted
    processes whose ``/proc/<pid>/environ`` named the port, and that number was
    a different set entirely: 214 by environ against 7 actually connected, with
    an overlap of ZERO. ``environ`` is an exec-time snapshot and Claude Code
    applies ``.claude.json``'s env block at boot, so it keeps naming whatever
    the launcher had. An operator reading "214 sessions will break" concludes
    catastrophe and never arms the gate; a wrong number in the one channel
    meant to inform a decision is worse than no number.

    Returns None where it cannot be measured rather than 0 — a silent zero
    reads as "nobody is affected", which is the same lie in the other
    direction. Linux only: both macs answer no ``/proc/net/tcp``.
    """
    try:
        rows = Path("/proc/net/tcp").read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
        return None
    target = f":{port:04X}"
    inodes = set()
    for line in rows:
        f = line.split()
        # state 01 = ESTABLISHED. Match the LOCAL side: these are the peers
        # connected to us, not our own listening socket (state 0A).
        if len(f) > 9 and f[3] == "01" and f[2].endswith(target):
            inodes.add(f[9])
    if not inodes:
        return 0
    pids = set()
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith("socket:[") and link[8:-1] in inodes:
            pids.add(fd.split("/")[2])
    return len(pids)


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


def write_daemon_state(
    certdir: Path, port: int, pid: int, fingerprint: str, handover: bool = False
) -> None:
    """Record the live daemon's identity atomically (temp-then-rename).

    ``handover`` marks the record as "a successor is being spawned for this
    daemon right now". It is the ONE arbitration point across the three paths
    that share the daemon lifecycle — the code watchdog, the refcount idle
    teardown and the SIGTERM handler — because all three already read this
    file and none of them can see the others' locals. The mark says: nothing
    is serving on this record, and whoever is departing must not unwire.
    """
    import json

    rec = {"port": port, "pid": pid, "fingerprint": fingerprint}
    if handover:
        rec["handover"] = True
    tmp = Path(certdir) / f"{_STATE_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(rec))
    os.replace(tmp, Path(certdir) / _STATE_FILE)


def mark_daemon_unpinnable(certdir: Path) -> None:
    """Record that THIS daemon cannot read the pinned account's credential.

    Only the running daemon can discover this, and only ensure_proxy can act
    on it — it reuses any daemon whose fingerprint matches, so without a mark
    a blind daemon is reused forever and `cswap pin` keeps reporting success
    over a pin that never applies. Rewrites the state file in place, keeping
    port/pid/fingerprint, and only when the record is ours.
    """
    import json

    path = Path(certdir) / _STATE_FILE
    try:
        st = json.loads(path.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(st, dict) or st.get("pid") != os.getpid():
        return
    st["unpinnable"] = True
    tmp = Path(certdir) / f"{_STATE_FILE}.{os.getpid()}.tmp"
    tmp.write_text(json.dumps(st))
    os.replace(tmp, path)


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
    running daemon stale and the launcher recycles it — mirrors the fingerprint
    staleness a sibling proxy's ensure step uses.

    The pinned account is deliberately NOT part of this. It is re-read per
    request (see :func:`make_pin_token_provider`), so re-pinning takes effect
    under a live daemon; including it here would recycle the daemon on every
    `cswap pin`, and a recycle is exactly what a live session should not need.
    The parameters are kept for call-site compatibility and ignored.
    """
    import hashlib

    # THE CONTENT, NOT ITS mtime. mtime is a proxy for "is this the same code"
    # and it is wrong in BOTH directions, measured:
    #
    #   new content + PRESERVED mtime  -> MISSED. `rsync -a`, `cp -p`, `tar -p`
    #       and a restored backup all preserve it, so a real deploy through any
    #       of those left the old daemon serving — the stale daemon this
    #       fingerprint exists to end.
    #   same content + touched mtime   -> SPURIOUS. A no-op reinstall recycled
    #       a healthy daemon and cost a handover for nothing.
    #
    # A peer proxy in the same chain hit the mirror of this by comparing PATHS:
    # it caught a relocated install and missed `git pull` in place, which is the
    # commonest deploy there is. Both are the same mistake — answering a
    # cheaper question than the one that matters.
    #
    # NO TORN READ TO GUARD AGAINST, because this hashes the file it is
    # ALREADY IMPORTING rather than a hash someone else publishes. An installer
    # replaces it by rename — measured: `pip install --force-reinstall` changes
    # the inode, so a reader either sees the whole old file or the whole new
    # one. A design that writes a hash to a SIDE FILE does need temp+rename
    # there, since a reader catching a partial write compares against a
    # truncated hash and retires a healthy process.
    #
    # Reading the file costs one stat + one read per check (the watchdog polls
    # on an interval, not per request), against a mistake that costs an outage.
    try:
        code = Path(__file__).read_bytes()
    except OSError:
        # UNREADABLE IS NOT UNCHANGED. Return something stable-but-distinct so
        # a daemon does not read "no fingerprint" as "same as mine" and serve
        # stale code forever; the next successful read re-establishes it.
        code = b""
    return hashlib.sha256(code).hexdigest()[:16]


def _pid_alive(pid: int) -> bool:
    """Whether ``pid`` names a process we could signal. Nothing else.

    A PID MUST BE POSITIVE, and refusing the rest is the whole guard. In
    ``kill(2)`` a pid of 0 addresses the CALLER'S OWN PROCESS GROUP and a
    negative pid addresses the group named by its absolute value — so
    ``os.kill(0, 0)`` is a permission check on ourselves that ALWAYS
    succeeds, and this answered True for a process that cannot exist.

    A peer hit the same primitive one signal number away: a pid parse that
    yielded 0 turned ``kill(pid, SIGKILL)`` into ``kill(0, SIGKILL)`` and
    SIGKILLed its own test runner. Here the kill sites are gated on
    ``_pin_daemon_pids`` so 0 cannot reach one, which makes this a wrong
    ANSWER rather than an outage — and a wrong answer a later caller would
    inherit as a fact.
    """
    if pid <= 0:
        return False
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
    # A handover in flight means the recorded daemon has already stopped
    # serving and its successor has not published yet. The pid is still alive
    # and the port may already answer — reclaimed by that successor — so both
    # liveness checks below would read the record as healthy and hand the
    # spawner its own predecessor.
    if st.get("handover"):
        return None
    if fingerprint is not None and st.get("fingerprint") != fingerprint:
        return None
    # A daemon that has proven it cannot read the pinned credential is not a
    # daemon worth reusing. It answers /health, serves every request, and
    # silently applies no pin — so reusing it makes `cswap pin` report success
    # forever while Remote Control sessions keep landing on the wrong account.
    # Only the caller asking for a SPECIFIC fingerprint is spawning a pin, so
    # only that caller recycles; a bare liveness probe still sees it.
    if fingerprint is not None and st.get("unpinnable"):
        return None
    if not _pid_alive(int(st["pid"])):
        return None
    try:
        with socket.create_connection(("127.0.0.1", int(st["port"])), timeout=1):
            return int(st["port"])
    except OSError:
        return None


def wanted_port(certdir: Path) -> "int | None":
    """The port this pin should serve on, in precedence order.

    Shared by the daemon's own bind and by :class:`PortHolder`, which binds
    the same address on the daemon's behalf. Two copies of this order is how
    a holder comes to hold one port while the daemon reclaims another.

    1. what a human configured (``--set_port``): a standing instruction
    2. the port the last daemon recorded
    3. the hint a respawn left (it deletes ``proxy.json`` before starting us)
    4. what ``.claude.json`` names — the only record that survives a wiped
       cert dir, and the number live sessions are actually dialling
    """
    want = configured_port(certdir)
    if isinstance(want, int):
        return want
    prev = read_daemon_state(certdir)
    if isinstance(prev, dict) and isinstance(prev.get("port"), int):
        return prev["port"]
    want = read_port_hint(certdir)
    if isinstance(want, int):
        return want
    return _wired_port()


_SELF_HEAL_ENV = "CSWAP_PIN_SELF_HEAL"
# "I am going, put a successor on this socket." A daemon serving on a holder's
# socket exits with this instead of 0 when it was TERM'd rather than idle: the
# holder keeps the port and respawns, so a redeploy loads new code without the
# address ever unbinding. A plain 0 still means "released — do not restart".
_RESTART_ME_CODE = 75  # EX_TEMPFAIL, and nothing else in this file uses it
# The ladder a daemon that keeps dying costs: one attempt every ~5s rather than
# four a second, so a persistently broken build does not spin the box while the
# port it holds stays answering.
_HOLD_RESTART_BASE_S = 0.25
_HOLD_RESTART_MAX_S = 5.0
# How long the holder waits for the port it was told to take. The predecessor
# is usually mid-teardown, so this is a handoff, not a contest.
_HOLD_BIND_WAIT_S = 3.0


class PortHolder:
    """Owns the pin's port, and restarts the daemon under it.

    THE CASE EVERY HANDOVER MISSES IS A CRASH. `release_listener(hand_down=True)`
    keeps the port bound across a planned restart, but it is cooperative: the
    outgoing daemon stops accepting and passes the socket on. A `kill -9`, an
    OOM kill, or a segfault skips all of that, and the port is then unowned —
    which for a live session is permanent, because its ``HTTPS_PROXY`` was
    fixed at exec and is never re-read. Measured outage: sessions on a dead
    36301 do not fail loudly, their requests leave WITHOUT the pin.

    So the socket is bound by a process that does not serve requests and has
    almost nothing to crash: it binds, spawns, waits. The daemon accepts on the
    inherited descriptor, so there is no relay, no extra hop, and no copy —
    the connection the client makes is the connection the daemon serves.

    A RELAY WOULD ALSO WORK and is what the cache proxy does (it has no way to
    pass a socket to its child). Here the socket-activation path already
    exists — ``_inherited_listener`` — so holding the port costs one bind and
    the daemon is unchanged.

    ``CSWAP_PIN_SELF_HEAL=off`` disables the restart, because a respawner
    fighting a human who is debugging the daemon is worse than a dead port.
    """

    def __init__(self, certdir: Path, account_num: str, email: str,
                 port: int | None = None):
        self._certdir = Path(certdir)
        self._account = account_num
        self._email = email

        # ADOPT A HANDED-DOWN SOCKET RATHER THAN BINDING. A predecessor that is
        # recycling passes its still-LISTENING socket down, and it has not let
        # go of the port — so a holder that tried to bind would lose the race
        # and fall back to an ephemeral one, taking the port out of the holder
        # exactly when an upgrade is in flight. Measured on two live machines:
        # 53749 -> 54264 and 36301 -> 45357, both stranding every session.
        #
        # Adopting has no race to lose: the descriptor is already bound and
        # already listening, and the predecessor stopped accepting on it before
        # passing it over.
        adopted = _handed_down_listener()
        if adopted is not None:
            self._srv = adopted
            self.port = self._srv.getsockname()[1]
            self.daemon_pid = None
            self._stop = False
            self._failures = 0
            self._thread = None
            self._proc = None
            return

        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # THE SAME PORT THE DAEMON WOULD HAVE TAKEN. The holder binds on its
        # behalf, so it has to resolve the address the same way — otherwise a
        # live session's HTTPS_PROXY names a port the holder does not hold.
        if port is None:
            want = wanted_port(self._certdir)
            port = want if isinstance(want, int) and want > 0 else 0
        # WAIT FOR THE PORT WE WERE ASKED FOR. The predecessor may still be
        # letting go of it — this runs immediately after a daemon closed its
        # listener — and falling straight to an ephemeral port would strand
        # every session whose HTTPS_PROXY names the old one. Measured: the
        # holder bound 35051 while 36311 was being reclaimed, one moment later.
        deadline = time.monotonic() + _HOLD_BIND_WAIT_S
        while port:
            try:
                self._srv.bind(("127.0.0.1", port))
                break
            except OSError:
                if time.monotonic() >= deadline:
                    # REFUSE, do not serve somewhere else. A holder exists to
                    # keep ONE address answering; on any other port it is a
                    # healthy-looking daemon that no session can reach, while
                    # `.claude.json` still names the number they were given.
                    # Measured on the personal Mac, doing exactly this: 29,999
                    # refused connections with the pin reporting success.
                    #
                    # An ephemeral fallback IS right at a cold start (port 0
                    # below) — there nothing is wired yet and any port will do.
                    # It is wrong once we have been told which port to take,
                    # because that instruction came from the live sessions.
                    self._srv.close()
                    raise OSError(
                        f"port {port} is taken — refusing to hold a different "
                        f"one, which the sessions wired to {port} cannot reach"
                    )
                time.sleep(0.05)
        if not port:
            self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(128)
        self.port = self._srv.getsockname()[1]
        self.daemon_pid: int | None = None
        self._stop = False
        self._failures = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        # The FIRST spawn happens here, not in the thread: `start()` returning
        # has to mean a daemon exists, or a caller that immediately reads
        # `daemon_pid` (or asks the port for a health probe) races the
        # supervisor's first loop iteration.
        self._spawn()
        self._thread = threading.Thread(target=self._supervise, daemon=True)
        self._thread.start()

    def _self_heal_on(self) -> bool:
        return os.environ.get(_SELF_HEAL_ENV, "").lower() not in ("off", "0", "no")

    def _spawn(self) -> None:
        """Start a daemon on our socket, via the socket-activation convention.

        LISTEN_PID names the CHILD, which we cannot know before it exists —
        so it is set from the child itself, in a preexec hook. The parent's own
        pid there would make ``_inherited_listener`` refuse the fd (that guard
        is what stops a grandchild adopting a descriptor it does not have) and
        the daemon would bind a fresh port, which is the stranding this class
        exists to prevent.
        """
        import subprocess
        import sys

        fd = self._srv.fileno()
        # THE PREDECESSOR PROTOCOL, not the systemd one. `LISTEN_PID` has to
        # name the CHILD, which cannot be known before it exists — and writing
        # it from `preexec_fn` does nothing, because Popen has already captured
        # the environment by then (measured: the child bound a fresh port every
        # time). `_handed_down_listener` was built for exactly this: the fd is
        # named by NUMBER and guarded by the PARENT's pid, which we do know.
        env = {k: v for k, v in os.environ.items() if k != "LISTEN_PID"}
        env["LISTEN_FDS"] = "0"
        env[_HANDDOWN_FD_ENV] = str(fd)
        env[_HANDDOWN_FROM_ENV] = str(os.getpid())
        # A HOLDER, not a predecessor. Both pass a listening socket down and
        # both use the variables above, but only this one is still alive
        # afterwards to put a successor on the socket — which is what makes a
        # TERM here a recycle rather than a release. A predecessor handing over
        # is itself going away, so its child must exit 0 as it always has.
        env[_HELD_BY_ENV] = str(os.getpid())
        log = _open_daemon_log(self._certdir)
        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", _DAEMON_MODULE, self._account,
                 self._email, str(self._certdir)],
                env=env,
                pass_fds=(fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
            )
        finally:
            if hasattr(log, "close"):
                log.close()
        self.daemon_pid = proc.pid
        self._proc = proc

    def _supervise(self) -> None:
        while not self._stop:
            code = self._proc.wait()
            if self._stop:
                return
            # A CLEAN EXIT IS A DECISION, NOT A FAILURE. The pin tears itself
            # down when the last refcount holder closes the FIFO — that is the
            # whole idle-teardown design. Restarting it would make the port
            # this class holds immortal too, and the daemon would respawn
            # forever with nobody to serve.
            #
            # Exit status is the only thing that separates them: 0 means the
            # daemon chose to go (teardown, SIGTERM handler), anything else
            # means it was killed or crashed.
            if code == 0:
                _log_lifecycle(
                    f"daemon {self.daemon_pid} exited cleanly — releasing port "
                    f"{self.port}"
                )
                try:
                    self._srv.close()
                except OSError:
                    pass
                return
            if code == _RESTART_ME_CODE:
                # A REDEPLOY, not a teardown. Respawn at once and skip the
                # backoff: this exit was asked for, so treating it as a failure
                # would make every update wait out a ladder rung.
                _log_lifecycle(
                    f"daemon {self.daemon_pid} asked for a successor — "
                    f"restarting on the held port {self.port}"
                )
                self._failures = 0
                self._spawn()
                continue
            if not self._self_heal_on():
                _log_lifecycle(
                    f"daemon {self.daemon_pid} exited and {_SELF_HEAL_ENV}=off — "
                    f"the port stays bound but nothing is serving it"
                )
                return
            self._failures += 1
            _log_lifecycle(
                f"daemon {self.daemon_pid} exited; restarting under the held "
                f"port {self.port}"
            )
            time.sleep(min(
                _HOLD_RESTART_BASE_S * 2 ** min(self._failures, 5),
                _HOLD_RESTART_MAX_S,
            ))
            if self._stop:
                return
            self._spawn()

    def kill_daemon_for_test(self) -> None:
        """SIGKILL the supervised daemon — the crash this class is for.

        Through the Popen, never through the pid: see ``stop``.
        """
        proc = getattr(self, "_proc", None)
        if proc is not None and getattr(proc, "returncode", 0) is None:
            try:
                proc.kill()
            except (OSError, ValueError):
                pass

    def stop(self) -> None:
        self._stop = True
        # KILL THE CHILD WE STARTED, not a number we are holding. `daemon_pid`
        # is only meaningful while the Popen it came from is ours — and a pid
        # is reused freely, so signalling it after the child is gone aims at
        # whatever inherited the number. Measured: with `_spawn` stubbed in a
        # test, this SIGTERM'd the pytest-xdist worker running it, and the run
        # died with "cannot send (already closed?)" rather than a failure.
        #
        # `Popen.terminate` cannot make that mistake: it signals the process
        # object, and CPython refuses once it has been reaped.
        proc = getattr(self, "_proc", None)
        if proc is not None and getattr(proc, "returncode", 0) is None:
            try:
                proc.terminate()
                proc.wait(timeout=_DRAIN_SECONDS + 2)
            except (OSError, ValueError):
                pass
            except Exception:  # noqa: BLE001 — TimeoutExpired: escalate
                try:
                    proc.kill()
                except (OSError, ValueError):
                    pass
        try:
            self._srv.close()
        except OSError:
            pass


def run_service(certdir: Path, account_num: str, email: str,
                port: int | None = None) -> PortHolder:
    """Hold the pin's port and keep a daemon serving on it."""
    holder = PortHolder(certdir, account_num, email, port=port)
    holder.start()
    return holder


def holder_main(account_num: str, email: str, certdir: Path,
                port: int | None = None) -> None:
    """Entry point for the detached holder (``-m cswap_pin.proxy --hold-port``)."""
    try:
        holder = run_service(Path(certdir), account_num, email, port=port)
    except OSError as exc:
        # SOMEBODY ELSE IS ALREADY ON OUR PORT, which is usually a healthy pin
        # — a concurrent launch won the election, or the predecessor has not
        # finished draining. Serve as a plain daemon instead of dying: it will
        # reclaim the port when it frees, and one unheld daemon is what every
        # release before this one shipped.
        _log_lifecycle(f"holder could not take the port ({exc}) — serving unheld")
        daemon_main(account_num, email, Path(certdir))
        return
    _log_lifecycle(f"holding port {holder.port} for account {account_num}")

    def _cleanup(reason: str = "signal") -> None:
        _log_lifecycle(f"holder stopping ({reason})")
        holder.stop()

    _install_signal_teardown(_cleanup)
    # The supervisor thread IS the service; this process has nothing else to
    # do. Joining it means the holder exits exactly when it stops supervising
    # — a clean daemon exit (idle teardown) or a self-heal switched off.
    if holder._thread is not None:
        holder._thread.join()


def _spawn_daemon(
    account_num: str, email: str, certdir: Path, listen_fd: int | None = None
) -> int | None:
    """Start the proxy daemon detached; wait for its state file. None on failure.

    Creates the refcount FIFO up front so a session can attach a holder the
    instant the daemon comes up (no gap where the daemon sees zero holders and
    tears itself down).

    ``listen_fd`` is a still-LISTENING socket the caller has stopped accepting
    on, passed to the successor so the port is never unbound. Handing the port
    NUMBER over instead leaves a hole nothing in this package can close: the
    successor is a fresh interpreter (~50ms to reach ``bind()``) and a
    listening port cannot be co-bound, with SO_REUSEADDR or SO_REUSEPORT.
    """
    import subprocess
    import sys
    import time

    certdir = Path(certdir)
    # RESOLVED BEFORE ANYTHING IS REWRITTEN. Everything below mutates the very
    # files `wanted_port` reads — proxy.json is marked handover, proxy.port is
    # unlinked — so asking afterwards gives a different, wrong answer, and a
    # holder started with it binds an address no live session is dialling.
    # Measured: holder on 46021 while 44733 was the port being reclaimed.
    want_port = wanted_port(certdir)
    if not (isinstance(want_port, int) and want_port > 0):
        want_port = 0
    # Hand the outgoing port to the new daemon before clearing the state it
    # lives in: it rebinds that port so live sessions — whose HTTPS_PROXY was
    # fixed at exec — keep reaching the proxy instead of a dead address (and
    # a session on a dead address leaves WITHOUT the pin, silently).
    prev = read_daemon_state(certdir)
    if isinstance(prev, dict) and isinstance(prev.get("port"), int):
        _write_port_hint(certdir, prev["port"])
    # MARKED, NOT DELETED, and this is the whole arbitration. Deleting it made
    # the successor's own liveness poll safe (it can no longer match the
    # predecessor's entry) at the cost of blinding every OTHER reader for the
    # ~10s the spawn takes: with no record, `_release_daemon_state` reports "not
    # superseded" and a teardown arriving from the refcount watcher or from
    # SIGTERM unwires a successor that comes up perfectly healthy and never
    # rewires. The mark answers both: the record still names who is departing,
    # and every reader that asks "is anything serving here" is told no.
    if isinstance(prev, dict) and isinstance(prev.get("pid"), int):
        try:
            write_daemon_state(
                certdir, prev.get("port") or 0, prev["pid"],
                prev.get("fingerprint") or "", handover=True,
            )
        except OSError:
            pass
    else:
        try:
            (certdir / _STATE_FILE).unlink()
        except FileNotFoundError:
            pass
    try:
        (certdir / "proxy.port").unlink()
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
    # SCRUB, THEN SET. A daemon that was itself handed a socket still carries
    # these variables in its own environment, and a spawn that passes no fd
    # would hand that stale pair to the child verbatim — naming a descriptor
    # the child does not have. The ppid guard already refuses it, but an
    # environment that lies is one pid-reuse away from being believed, and
    # nothing needs it to survive the process it was addressed to.
    env = {k: v for k, v in os.environ.items()
           if k not in (_HANDDOWN_FD_ENV, _HANDDOWN_FROM_ENV)}
    pass_fds: tuple[int, ...] = ()
    if listen_fd is not None:
        # NAME THE NUMBER. `Popen(pass_fds=...)` does not renumber — measured,
        # a parent's fd 9 arrives as the child's fd 9 and its fd 3 is EBADF —
        # so the systemd "first fd is 3" convention cannot express this and the
        # successor is told which descriptor to look at. The origin pid is the
        # guard: these variables reach every descendant but the fd does not, so
        # a grandchild without it must not adopt whatever that number became.
        env[_HANDDOWN_FD_ENV] = str(listen_fd)
        env[_HANDDOWN_FROM_ENV] = str(os.getpid())
        pass_fds = (listen_fd,)
    # EVERY SPAWN LANDS UNDER A HOLDER, cold start and handover alike.
    #
    # The cold start needs one because nothing owns the address yet: the
    # daemon would bind it itself and a `kill -9` would take the port down
    # with it, stranding every session whose HTTPS_PROXY was fixed at exec.
    #
    # THE HANDOVER NEEDS ONE FOR A DIFFERENT REASON, learned by doing it twice
    # in one day on live machines. An old daemon notices its code changed and
    # hands its listening socket to a successor — using the handover ITS OWN
    # VERSION implements. If that successor runs unheld, the port has left the
    # holder for good:
    #
    #     wmac  12:57  53749 -> served UNHELD on 54264
    #     lmd42 13:03  36301 -> 45357, and .claude.json followed it there
    #
    # A README saying "upgrade carefully" was the first answer and it is not
    # one: a deploy is not a procedure someone follows, it is whatever the
    # running code does. The holder here ADOPTS the socket it was handed
    # rather than binding a fresh one, so it cannot lose the race that made
    # the cold-start holder fall back — there is nothing to race for.
    argv = [sys.executable, "-m", _DAEMON_MODULE, _HOLDER_MODULE_ARG,
            str(want_port if want_port else 0), account_num, email,
            str(certdir)]
    try:
        try:
            subprocess.Popen(
                argv,
                env=env,
                pass_fds=pass_fds,
                # GIVE THE CHILD ITS OWN STDIN. Without this it inherits the
                # parent's fd 0, and a daemon spawning its successor is not a
                # CLI: whatever fd 0 became in a long-lived detached process is
                # what the child gets. A child whose fd 0 is unusable dies in
                # interpreter startup, before any of its own code runs, so it
                # cannot report why — the failure is a bare init_sys_streams
                # with no Python frame and the handover produces no successor.
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
                start_new_session=True,
            )
        finally:
            # The child holds its own dup of the fd; ours would otherwise leak
            # on every spawn.
            if hasattr(log, "close"):
                log.close()
        # NAMED so a test can shorten it. It was inlined, and a test that
        # stubs Popen (no child ever appears) then paid the full 10s — 10% of
        # the whole suite in one case that is only asserting what the spawn
        # PASSES, not that it works.
        for _ in range(int(_SPAWN_WAIT_S * 10)):
            port = _read_alive_port(certdir)
            if port is not None:
                # New daemon is serving and recorded in proxy.json — sweep any
                # orphan pin daemons for this certdir that aren't the keeper, so
                # a recycle that left the old one alive never accumulates.
                st = read_daemon_state(certdir)
                keep = int(st["pid"]) if st else -1
                _sweep_orphan_daemons(certdir, keep_pid=keep)
                return port
            time.sleep(0.1)
    except BaseException:
        # A spawn that RAISES (fork() EAGAIN under a post-deploy herd) leaves
        # no successor, so the mark must not outlive it — see below.
        _clear_handover_mark(certdir)
        raise
    # NO SUCCESSOR CAME. The mark says "one is coming", and leaving it would
    # tell the caller's own teardown it has been superseded — so the wiring
    # would be kept pointing at a port nobody serves, which is the outage the
    # unwire exists to prevent.
    _clear_handover_mark(certdir)
    return None


def _clear_handover_mark(certdir: Path) -> None:
    """Drop a marked record once the spawn it describes has failed.

    The mark means "a successor is coming"; leaving it after nothing came would
    make the caller's own teardown read "superseded" and keep the wiring
    pointing at a port nobody serves. The record described a daemon that has
    already stopped, so there is nothing left to preserve — the port to reclaim
    lives in the hint (see ``read_port_hint``).
    """
    st = read_daemon_state(certdir)
    if not (st and st.get("handover")):
        return
    try:
        (Path(certdir) / _STATE_FILE).unlink()
    except OSError:
        pass


def _release_daemon_state(certdir: Path) -> bool:
    """Drop ``proxy.json`` if it still names us. True when it names SOMEONE
    ELSE — i.e. we were superseded and must touch nothing further.

    A successor publishes its own state (and rewires the config to its port)
    before sweeping the orphans it replaces, so a departing daemon's cleanup
    can land on the record of the daemon that is now serving. Deleting that
    makes a LIVE daemon invisible: the next launch reads no state and spawns
    another one on top of it.

    A HANDOVER IN FLIGHT COUNTS AS SUPERSEDED. `_spawn_daemon` marks the record
    before it forks and the successor replaces it once it is serving, so for
    the length of that spawn the record still names US and yet the wiring
    belongs to a daemon that is about to own it. Reading only the pid there
    unwired a healthy successor, and nothing rewires afterwards:
    `_repair_wiring_if_ours` declines when nothing is wired at all. The mark is
    what the three lifecycle paths — this teardown's two callers and the
    watchdog that set it — share, because none of them can see the others'
    locals.

    A REFUSED delete (permission denied, a read-only mount) is not the same
    outcome as an ABSENT file, and both used to return the same `False` a
    successful release does. A refused delete leaves the file naming OUR
    (about-to-exit) pid, and the next daemon start reads it to decide which
    port to reclaim — believing a daemon it can never reach. RE-RAISE, so
    the caller (the departing daemon's teardown) is not told this succeeded.
    """
    try:
        st = read_daemon_state(certdir)
        if st and st.get("handover"):
            return True
        if st and int(st["pid"]) != os.getpid():
            return True
    except (ValueError, KeyError, TypeError):
        pass  # state file is garbage, not ours to protect — fall through
    try:
        (Path(certdir) / _STATE_FILE).unlink()
    except FileNotFoundError:
        pass  # already gone: nothing to release
    return False


_CODE_WATCH_INTERVAL_S = 30.0
# Consecutive failed handovers before the watchdog stops trying. A ceiling on
# NEVER-SUCCEEDING, not on total recycles: a daemon that hands over cleanly
# and later goes stale again starts from zero. Without one, a successor that
# can never start (a broken deploy, a missing dependency) is retried forever
# — and a peer measured exactly that shape at ~3.75 attempts/sec on the other
# side of this seam, with the port held the whole time so nothing refused and
# nobody noticed.
_HANDOVER_ATTEMPTS = 5


def _watch_own_code(
    server,
    account_num: str,
    email: str,
    certdir: Path,
    done,
    teardown,
    interval: float = _CODE_WATCH_INTERVAL_S,
    _own_fingerprint: str | None = None,
) -> None:
    """Hand over to a successor when this module's code is replaced on disk.

    WHY THIS LIVES IN THE DAEMON. Every other entry point reacts to a LAUNCH:
    `ensure_proxy` recycles a stale daemon, but only when a new session starts.
    A machine whose sessions are all already running never launches, so an
    upgrade never reaches the process. Measured: a daemon served
    for 22 hours on code that had been replaced 19 hours earlier, across six
    releases, dialling direct instead of chaining — every claude.ai handshake
    got the corporate MITM leaf and OAuth login was broken the whole time.

    `heal` already detects exactly this and recycles correctly; it was
    evaluated against that live daemon and every one of its gates passed. It
    never ran because its only caller is a human typing `cswap pin --heal`.
    The periodic caller used to be a status-line hook, and removing that was
    RIGHT: a status line is one machine's personal config, so recovery living
    there means every user without that hook has no recovery at all. This is
    the replacement, and it needs no host-side hook of any kind — the daemon
    is the one process guaranteed to be running when its own code goes stale.

    `daemon_fingerprint` hashes this module's mtime, so re-calling it IS the
    detector; nothing new is needed to sense staleness.

    THE ORDER IS LOAD-BEARING:

      1. stop and drain — the port must be free before the successor binds it,
         and draining is what keeps a recycle from cutting live requests.
      2. `_spawn_daemon` — it already hands the outgoing port to the successor
         and blocks until that successor is serving and has published its own
         state, so live sessions (whose HTTPS_PROXY was fixed at exec) keep
         reaching the same address.
      3. on success, DO NOT unwire. The successor owns the wiring now; tearing
         it down would strip the config it just wrote and send every new
         session to no proxy at all.
      4. on failure, unwire. We have already stopped serving, so leaving the
         config naming this port is the ConnectionRefused outage `_teardown`
         exists to prevent — reached by the recycle itself.

    NOT gated on the daemon being idle: a busy daemon is exactly the one that
    must upgrade, and the drain in step 1 is what protects its in-flight work.
    """
    own = _own_fingerprint if _own_fingerprint is not None else daemon_fingerprint()
    attempts = 0
    # Waiting on `done` rather than sleeping, so a normal teardown ends this
    # thread at once instead of after a full interval.
    while not done.wait(interval):
        # ONE EXIT, TAKEN ON EVERY PATH. 0.1.27 had three exits and one of them
        # took neither: `_spawn_daemon` RAISING (fork() EAGAIN under a
        # post-deploy herd) landed in the guard below, which logged and
        # returned with the server already stopped, nothing unwired, and `done`
        # never set — so the process stayed alive serving nothing while
        # `.claude.json` named its port and `daemon_main` blocked on
        # `done.wait()` forever. Measured: stop=yes teardown=no done=no.
        #
        # `handed_over` is the whole arbitration: True means a successor owns
        # the wiring and we must NOT unwire; False after we have stopped means
        # nobody is serving and we MUST. The `finally` applies that once,
        # rather than each branch remembering to.
        stopped = handed_over = False
        try:
            if daemon_fingerprint() == own:
                continue
            # UNDER A HOLDER THERE IS NOTHING TO HAND OVER. The holder already
            # owns this socket and will put the successor on it, so the whole
            # release-spawn-drain dance below is not merely unnecessary — it
            # takes the port OUT of the holder, and the successor is then one
            # failed bind away from stranding every session.
            #
            # Measured on lmd42, 76 minutes of broken pin reported as healthy:
            #   10:13:07 handing over to a successor
            #   10:13:15 successor holder: could not take 36301 — serving
            #            UNHELD on 33349
            #   10:18:15 33349: idle teardown — unwired .claude.json
            if held_by_a_holder():
                _log_lifecycle(
                    "code on disk changed — exiting for the holder to replace"
                )
                # DRAIN FIRST, exactly as the handover path does. The holder
                # cannot start the successor until we release the socket, but
                # in-flight requests are still ours to finish.
                server.release_listener()
                server.await_inflight(_DRAIN_SECONDS)
                os._exit(_RESTART_ME_CODE)
            _log_lifecycle("code on disk changed — handing over to a successor")
            # SERIALIZED, like every other spawn caller (`heal`,
            # `ensure_proxy`). Without it, a deploy replaces proxy.py and every
            # daemon on the box goes stale in the same instant, so their timers
            # fire together and two unserialized spawns leave one successor
            # orphaned — invisible to the sweep, holding a port forever. Taken
            # BEFORE the stop so a loser waits with its server still up rather
            # than dead.
            with _spawn_lock(certdir):
                # Another daemon may have recycled us while we queued.
                if daemon_fingerprint() == own:
                    continue
                # RELEASE THE PORT, THEN DRAIN — in that order, and with the
                # successor started in between. `stop(drain=N)` closes the
                # listener FIRST and only then waits up to N seconds for
                # in-flight requests, so the port sat unbound for the whole
                # drain and every new connection was refused. Measured on
                # a live daemon: handover at T, successor serving at T+31 s, with
                # a peer's request dying inside it.
                #
                # Dropping the listener without draining lets the successor
                # bind immediately; the in-flight requests are still ours to
                # finish, so the drain happens after, while the new daemon is
                # already accepting. A supervisor-held port makes both moot —
                # this is what the package does when it owns the socket itself.
                #
                # AND THE SOCKET GOES WITH IT, which is what makes the handover
                # gapless rather than merely short. Releasing the port and
                # letting the successor rebind it still costs the successor's
                # start-up: measured on a live box, 6 refused requests over
                # 0.27s, and no drain fix moved it, because a listening port
                # cannot be co-bound (SO_REUSEADDR and SO_REUSEPORT both
                # refused) and a fresh interpreter needs ~50ms to reach
                # `bind()`. Passing the listening socket down leaves the port
                # bound the whole time, so arrivals queue in the backlog
                # instead: 0 refused. `release_listener` joins the accept loop
                # first — two processes accepting on one socket split the
                # connections, and the one that has stopped serving drops its
                # share.
                handed_fd = server.release_listener(hand_down=True)
                stopped = True
                spawned = _spawn_daemon(
                    account_num, email, certdir, listen_fd=handed_fd
                )
                server.await_inflight(_DRAIN_SECONDS)
                if spawned is not None:
                    _log_lifecycle("successor is serving — leaving the wiring to it")
                    # OUR COPY OF THE FD STAYS OPEN, deliberately. This process
                    # returns from here into its own exit, and closing a
                    # listening descriptor two processes hold is only ever
                    # dangerous in the other direction: close it a moment too
                    # early and the port is gone. Nothing here accepts on it —
                    # `release_listener` joined the accept loop before handing
                    # it over.
                    handed_over = True
                    return
                _log_lifecycle("successor did not come up")
            # TRY AGAIN, BOUNDED. Returning here left the thread dead with the
            # code on disk still new, so the daemon served the stale code
            # forever — the 22-hour outage this watchdog exists to end,
            # reached one failed spawn later instead of by having no watchdog.
            # The machine this is FOR is the one whose sessions never
            # relaunch, so nothing else will ever try.
            #
            # And bounded rather than endless, for the failure a peer measured
            # on the other side of this seam: an unbounded respawn against a
            # child that can never start ran at ~3.75/sec with the port held
            # the whole time, so callers waited out a 15s deadline instead of
            # failing over in 0ms. A start failure is QUIETER once the port
            # survives it, which is exactly why it needs a ceiling.
            #
            # The counter is on CONSECUTIVE failures, so a daemon that
            # recycles cleanly years apart still gets its full budget each
            # time — the ceiling is on never-succeeding, not on total tries.
            attempts += 1
            if attempts >= _HANDOVER_ATTEMPTS:
                _log_lifecycle(
                    f"{attempts} handovers failed in a row — staying on the "
                    f"current code, still serving"
                )
                return
            continue
        except Exception as exc:  # noqa: BLE001 — a watchdog must never raise
            # A raise here used to kill the thread silently and put the daemon
            # back in the state this whole release exists to end: correct
            # recycle machinery with nothing driving it.
            _log_lifecycle(f"code watch failed: {exc!r}")
            return
        finally:
            if stopped and not handed_over:
                # KEEP SERVING THE OLD CODE RATHER THAN NOTHING. A recycle that
                # cannot start a successor has no reason to end the pin: this
                # process is intact, it merely stopped listening, and the code
                # it runs is the code that was working a moment ago. Unwiring
                # here left a machine unpinned until a human re-pinned it by
                # hand — measured, hours — while the alternative costs only
                # running one release behind until the next attempt.
                if _resume_serving(server):
                    _log_lifecycle(
                        "successor did not come up — resumed serving the old "
                        "code, still on the recorded port"
                    )
                    # Clearing the flag is what keeps `done` unset below; a
                    # `return` here would do the same but swallows any
                    # in-flight exception, and Python 3.14 warns about it.
                    stopped = False
                else:
                    # Could not get the listener back either. Now the config
                    # really does name a port nothing answers, so fall back.
                    _log_lifecycle("no successor and could not resume — unwiring")
                    try:
                        teardown("failed handover")
                    except Exception as exc:  # noqa: BLE001
                        _log_lifecycle(
                            f"COULD NOT unwire after a failed handover: {exc!r}"
                        )
            if stopped:
                # Either way this daemon is finished. `done` releases
                # `daemon_main`'s `done.wait()`; leaving it unset is what made
                # the raise path a permanent zombie.
                done.set()


def _inherited_listener() -> "socket.socket | None":
    """The listening socket a supervisor handed us, or None to bind our own.

    The systemd socket-activation convention: ``LISTEN_FDS`` counts the fds
    passed starting at 3, and ``LISTEN_PID`` names who they were passed TO.

    LISTEN_PID is not optional. The variables are inherited by every
    descendant, so a grandchild that trusts ``LISTEN_FDS`` alone serves on
    whatever its own fd 3 happens to be — a log file, a pipe, another
    process's socket — and the port goes unserved with no error anywhere.

    Anything not a listening TCP socket is refused rather than adopted, and
    refusing means we bind our own port: a supervisor that passed us the wrong
    thing must not be able to take the pin down with it.
    """
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    try:
        count = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return None
    if count < 1:
        return None
    try:
        sock = socket.socket(fileno=3)
    except OSError:
        return None
    try:
        if sock.type != socket.SOCK_STREAM:
            raise OSError("not a stream socket")
        # getsockname() answers on a bound socket; accept() would block, so the
        # listening state is proven by asking the socket itself.
        # A PROBE THAT CANNOT ANSWER IS NOT A "NO". `SO_ACCEPTCONN` is
        # readable on Linux and NOT on Darwin — measured, same call:
        # linux 1, darwin OSError 42 "Protocol not available". Treating that
        # raise as "not listening" refused every handover on macOS and the
        # successor bound a FRESH port, which is the stranding this whole
        # path exists to prevent (live sessions have the old port fixed at
        # exec). Measured on wmac: "ignoring the handed-down fd 3: [Errno 42]"
        # then "serving on port 58062" while the wiring named 53749.
        #
        # `getsockname()` below still proves it is a bound TCP socket on both
        # platforms, so only the redundant option is allowed to be absent.
        try:
            listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except OSError:
            # ASK THE SOCKET INSTEAD. A non-blocking accept() answers on both
            # platforms and cannot consume a connection we would then drop:
            # a LISTENING socket with an empty queue raises EAGAIN
            # (BlockingIOError), and one that never listened raises EINVAL.
            # Measured on both. The timeout is restored either way — the
            # accept loop sets its own, and leaving a socket non-blocking
            # would turn every accept into a busy spin.
            prev = sock.gettimeout()
            try:
                sock.settimeout(0)
                conn, _ = sock.accept()
                conn.close()  # it WAS listening, and a client was waiting
                listening = 1
            except BlockingIOError:
                listening = 1  # listening, queue empty — the normal case
            except OSError:
                listening = 0  # EINVAL: never listened
            finally:
                sock.settimeout(prev)
        if not listening:
            raise OSError("not listening")
        sock.getsockname()
    except OSError as exc:
        _log_lifecycle(f"ignoring the passed fd 3: {exc}")
        sock.detach()  # not ours — leave the fd as the supervisor left it
        return None
    return sock


_HANDDOWN_FD_ENV = "CSWAP_PIN_LISTEN_FD"
_HANDDOWN_FROM_ENV = "CSWAP_PIN_LISTEN_FROM"
# Set by a HOLDER only, naming itself. Distinguishes "my parent is still there
# and will start my successor" from "my predecessor handed me its socket on the
# way out" — the two look identical in the variables above, and they mean
# opposite things when this daemon is TERM'd.
_HELD_BY_ENV = "CSWAP_PIN_HELD_BY"


def _successor_is_serving() -> bool:
    """Is SOMEBODY ELSE serving the wired port?

    The teardown asks the port rather than a file, because a successor that
    came up while we drained is real and unwiring past it would strip a
    working pin — measured: unwire at 19:16:35, successor serving at 19:16:36,
    a live session retrying in between.

    BUT A HOLDER'S SOCKET IS NOT SOMEBODY ELSE. Under a holder,
    `release_listener` DETACHES rather than closes (the port is not ours to
    take down), so the socket we just stopped serving is still bound and
    listening — and a listen-only socket completes a TCP handshake. The probe
    therefore answered "served" about our own corpse: the unwire was skipped,
    the daemon exited 0, the holder released the port on that clean exit, and
    `.claude.json` was left naming an address nothing listens on. That is the
    ConnectionRefused-forever outage this whole guard exists to prevent,
    reached through the guard itself.

    So a port that answers counts only when it is NOT the one our own holder
    is holding for us.
    """
    live = _wired_port()
    if live is None or not _port_answers(live):
        return False
    return not held_by_a_holder()


def held_by_a_holder(ppid: int | None = None, env=None) -> bool:
    """Whether a holder owns this daemon's socket and will outlive it.

    The distinction the whole restart story turns on. A PREDECESSOR that hands
    its socket down is leaving, so its successor owns the port and must hand it
    on in turn. A HOLDER is still there and will put the next daemon on the
    same socket — so this daemon has nothing to hand over and should simply go.
    """
    env = os.environ if env is None else env
    ppid = os.getppid() if ppid is None else ppid
    return env.get(_HELD_BY_ENV) == str(ppid)


def _handed_down_listener() -> "socket.socket | None":
    """The listening socket our PREDECESSOR passed us, or None to bind our own.

    A separate path from :func:`_inherited_listener`, and it has to be. That
    one implements the systemd convention, where the first passed fd is
    number 3 — but `subprocess.Popen(pass_fds=...)` does NOT renumber:
    measured, a parent's fd 9 arrives as the child's fd 9 and its fd 3 is
    EBADF. A predecessor cannot use the systemd variables to say what it
    passed, so it names the number instead.

    ``_HANDDOWN_FROM_ENV`` is the same guard ``LISTEN_PID`` is, one level
    over: the variables reach every descendant, and a grandchild does NOT
    inherit the fd (Popen closes what it does not pass), so a bare number
    would name whatever that descriptor became — a log file, a pipe, another
    socket. Requiring it to have come from our own parent is what makes the
    number meaningful. Anything not a listening TCP socket is refused, and
    refusing means we bind our own port: a bad hand-down must not be able to
    take the pin down with it.
    """
    origin = os.environ.get(_HANDDOWN_FROM_ENV)
    if not origin or origin != str(os.getppid()):
        return None
    try:
        fd = int(os.environ.get(_HANDDOWN_FD_ENV, ""))
    except ValueError:
        return None
    if fd < 0:
        return None
    try:
        sock = socket.socket(fileno=fd)
    except OSError:
        return None
    try:
        if sock.type != socket.SOCK_STREAM:
            raise OSError("not a stream socket")
        # A PROBE THAT CANNOT ANSWER IS NOT A "NO". `SO_ACCEPTCONN` is
        # readable on Linux and NOT on Darwin — measured, same call:
        # linux 1, darwin OSError 42 "Protocol not available". Treating that
        # raise as "not listening" refused every handover on macOS and the
        # successor bound a FRESH port, which is the stranding this whole
        # path exists to prevent (live sessions have the old port fixed at
        # exec). Measured on wmac: "ignoring the handed-down fd 3: [Errno 42]"
        # then "serving on port 58062" while the wiring named 53749.
        #
        # `getsockname()` below still proves it is a bound TCP socket on both
        # platforms, so only the redundant option is allowed to be absent.
        try:
            listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except OSError:
            # ASK THE SOCKET INSTEAD. A non-blocking accept() answers on both
            # platforms and cannot consume a connection we would then drop:
            # a LISTENING socket with an empty queue raises EAGAIN
            # (BlockingIOError), and one that never listened raises EINVAL.
            # Measured on both. The timeout is restored either way — the
            # accept loop sets its own, and leaving a socket non-blocking
            # would turn every accept into a busy spin.
            prev = sock.gettimeout()
            try:
                sock.settimeout(0)
                conn, _ = sock.accept()
                conn.close()  # it WAS listening, and a client was waiting
                listening = 1
            except BlockingIOError:
                listening = 1  # listening, queue empty — the normal case
            except OSError:
                listening = 0  # EINVAL: never listened
            finally:
                sock.settimeout(prev)
        if not listening:
            raise OSError("not listening")
        sock.getsockname()
    except OSError as exc:
        _log_lifecycle(f"ignoring the handed-down fd {fd}: {exc}")
        sock.detach()  # not ours — leave the descriptor as we found it
        return None
    return sock


def _port_answers(port: int, timeout: float = 0.5) -> bool:
    """Whether something accepts on ``port`` right now, on loopback.

    A connect, not a request: the question is whether a session dialling this
    address would be refused, and that is answered by the accept alone. Kept
    short because it runs on a teardown path — a pin must never make an exit
    slow — and treated as "nobody" on any error, since a port we cannot reach
    is one a session cannot reach either.
    """
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _resume_serving(server) -> bool:
    """Put a stopped server back on its own port. True if it is listening again.

    ``stop()`` closes the listener but leaves the object usable, and ``start()``
    already reclaims the recorded port rather than taking a fresh one — so a
    resume is a restart of the listener, not of the process. The port matters
    more than the uptime: a running session's HTTPS_PROXY was fixed at exec, so
    coming back anywhere else is the same outage as not coming back.
    """
    try:
        server._stop = False
        server.start()
    except Exception as exc:  # noqa: BLE001 — the caller has a fallback
        _log_lifecycle(f"could not resume serving: {exc!r}")
        return False
    want = read_daemon_state(server._certdir)
    recorded = want.get("port") if isinstance(want, dict) else None
    if isinstance(recorded, int) and recorded > 0 and server.port != recorded:
        # Listening, but not where the live sessions are pointed. That is not a
        # resume, it is a second outage wearing the same log line.
        _log_lifecycle(
            f"resumed on {server.port} but sessions expect {recorded}"
        )
        return False
    return True


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
    ClaudeAccountSwitcher = require("switcher").ClaudeAccountSwitcher

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
    # A start line means the log is never empty for a daemon that ran, so
    # "no teardown line" becomes evidence of a CRASH rather than of nothing.
    _log_lifecycle(f"serving on port {proxy.port} for account {account_num}")

    fifo = refcount_fifo_path(certdir)
    if not fifo.exists():
        try:
            os.mkfifo(fifo)
        except FileExistsError:
            pass

    done = threading.Event()

    def _teardown(reason: str = "refcount") -> None:
        # Last session closed its holder (or a signal arrived) — stop serving
        # and clean up our state so a launcher never reuses a dead record.
        _log_lifecycle(f"stopping ({reason})")
        # DRAIN, because this is the only place that decides whether an upgrade
        # or a recycle costs sessions their in-flight requests. The signal path
        # ends in os._exit(0), so anything still being served when this returns
        # is cut mid-response — measured as ConnectionResetError at a client
        # reading a streaming reply. An idle daemon returns from here at once.
        proxy.stop(drain=_DRAIN_SECONDS)
        _log_lifecycle(f"drained, {proxy.live_client_count()} client(s) still open")
        # ``done`` must be set on EVERY exit from here: ``daemon_main`` blocks
        # on it and the signal path ends in ``os._exit(0)``, so an exception
        # escaping before it leaves the server stopped, ``.claude.json`` naming
        # a dead port, and the process alive forever holding both.
        try:
            try:
                superseded = _release_daemon_state(certdir)
            except OSError as exc:
                # The record could not be dropped, which is NOT evidence a
                # successor owns it. Treat it as "no successor" so the unwire
                # below still runs: leaving the config naming a port this
                # daemon is about to stop serving is the outage, and a stale
                # record is the smaller fault of the two.
                _log_lifecycle(f"could not release daemon state: {exc!r}")
                superseded = False
            if superseded:
                # A successor owns the state now. Unwiring here would strip the
                # config it just wrote and send every new session to no proxy
                # at all, so the departing daemon leaves the wiring alone.
                return
            # ASK THE PORT, DO NOT INFER FROM A FILE. Our own listener is
            # already closed by the drain above, so anything still answering
            # the wired address is SOMEBODY ELSE serving it — a successor that
            # came up while we were draining, or a supervisor holding the port
            # on our behalf. Unwiring then removes the config of a working pin,
            # and every session that dials during the gap gets
            # ConnectionRefused. Measured: unwire at 19:16:35, the
            # successor serving at 19:16:36, and a live session retrying.
            #
            # The state-file arbitration above cannot see this: a successor
            # publishes its record and rewires only once it is serving, so
            # between our decision and its publication the files say we are
            # alone while the port says otherwise.
            if _successor_is_serving():
                _log_lifecycle(
                    f"port {_wired_port()} is still served — leaving the "
                    f"wiring alone"
                )
                return
            # Put ``.claude.json`` back the way we found it. Without this the env
            # block keeps naming the port we just stopped serving, and Claude Code
            # applies that block at boot — so EVERY session started afterwards
            # dials a dead proxy and retries forever, with every proxy behind it
            # healthy and unreachable behind it. Measured:
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
                _log_lifecycle("unwired .claude.json — sessions fall back")
            except Exception as exc:  # noqa: BLE001
                # NAME THE FAILURE. If the unwire does not happen, every session
                # started afterwards dials a port nothing serves, and that is the
                # outage this whole path exists to prevent. Silently swallowing it
                # is what made one such outage unattributable for hours.
                _log_lifecycle(f"COULD NOT unwire .claude.json: {exc!r}")
        finally:
            done.set()

    # A recycle/cc-update TERM runs the same cleanup as an idle teardown.
    _install_signal_teardown(_teardown)

    threading.Thread(
        target=_watch_own_code,
        args=(proxy, account_num, email, certdir, done, _teardown),
        daemon=True,
    ).start()

    threading.Thread(
        target=watch_refcount,
        args=(fifo, _teardown),
        # The daemon's own connection count, so "is anyone using me" has an
        # answer on macOS too (/proc/net/tcp does not exist there).
        kwargs={"live_clients": proxy.live_client_count},
        daemon=True,
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
        # Whether egress is currently bypassing the chain, and through which
        # hop when it is not — see _note_egress.
        self._egress_direct = False
        self._egress_hop: "tuple[str, int] | None" = None
        # The last hop fault reported, so a steadily-down hop costs one line
        # instead of one per connection — see _note_hop_unusable.
        self._hop_fault: "tuple[tuple[str, int], str] | None" = None
        # The credential a client must present on CONNECT is re-read per
        # connection, not cached here — ``_current_secret``. Caching it made
        # the gate arm on the next RESPAWN rather than when the secret was
        # written, which is the opposite of what the deploy needs (measured by
        # the cswap owner: `cswap pin` minted the secret and rewired, but
        # ensure_proxy reused the live daemon, so it kept serving with the
        # None it had captured at construction).
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
        # Clients connected right now. The daemon's own count, because the
        # /proc-based probe is Linux-only and its None reads as "idle" on the
        # machines that cannot answer (see ``_serve_client``).
        self._live_clients = 0
        self._live_lock = threading.Lock()
        # One bridge sweep at a time. A session opening fires several calls in
        # a burst; without this each would start its own listing.
        self._bridge_sweeping = False
        self._sweep_lock = threading.Lock()
        # The connections themselves, not just a count. `stop()` has to CLOSE
        # them before the process exits — see the note there on why a drained
        # request still ends in RST without this.
        self._open_conns: set = set()
        self._stop = False
        # True when a supervisor handed us the listening socket. Then the port
        # is not ours to close — see start() and stop().
        self._inherited = False
        # The accept loop, held so a handover can JOIN it rather than merely
        # signal it: two processes accepting on one socket split the
        # connections between them, and the one that has stopped serving drops
        # its share.
        self._accept_thread: threading.Thread | None = None
        # The descriptor handed to a successor, kept only so it can be closed
        # if the spawn fails and we resume serving.
        self._handed_fd: int | None = None
        self.port = 0
        # Opt-in request tracing: CSWAP_PIN_DEBUG=<path> logs one line per
        # request (method, path, whether it matched a pinned route and was
        # swapped). Off by default; used to diagnose routing end to end.
        debug_path = os.environ.get("CSWAP_PIN_DEBUG")
        self._debug = open(debug_path, "a") if debug_path else None

    def start(self) -> None:
        if self._handed_fd is not None:
            # WE HANDED THIS DOWN AND NOBODY TOOK IT — the spawn failed, and
            # this is the resume. The socket never stopped listening, so there
            # is no port to reclaim and no window to lose: take the descriptor
            # back and start accepting on it again.
            fd, self._handed_fd = self._handed_fd, None
            try:
                self._srv = socket.socket(fileno=fd)
                self.port = self._srv.getsockname()[1]
            except OSError as exc:
                _log_lifecycle(f"could not take back the handed-down fd: {exc}")
                self._srv = None
            else:
                self._inherited = False
                self._start_accept_loop()
                return
        handed = _handed_down_listener()
        if handed is not None:
            # OUR PREDECESSOR'S SOCKET, still listening. It stopped accepting
            # before it passed this down, so connections that arrived during
            # our start-up are waiting in the backlog rather than refused —
            # which is the whole 0.27s gap, closed. The port was never
            # unbound, so there is nothing to reclaim and nothing to race.
            self._srv = handed
            # OURS TO CLOSE ONLY IF NOBODY IS STILL HOLDING IT. A predecessor
            # that handed this over is on its way out, so the socket becomes
            # ours. A HOLDER is not: it is still there and will put a successor
            # on this very socket, so closing it on our way out unbinds the
            # port the holder exists to keep. Measured: 201,909 refused
            # connections across three planned restarts.
            self._inherited = held_by_a_holder()
            self.port = self._srv.getsockname()[1]
            self._start_accept_loop()
            return
        inherited = _inherited_listener()
        if inherited is not None:
            # A SUPERVISOR OWNS THE PORT. It bound the socket before we existed
            # and will hold it after we exit, so the port answers whether this
            # process is starting, restarting, hung, or gone — the failure mode
            # a same-port reclaim can only recover from, never prevent.
            #
            # This is the systemd socket-activation convention (LISTEN_FDS /
            # LISTEN_PID, first fd = 3), not an agreement with any particular
            # supervisor: anything implementing it can hold our port, and we
            # name none of them.
            self._srv = inherited
            self._inherited = True
            self.port = self._srv.getsockname()[1]
            self._start_accept_loop()
            return
        self._inherited = False
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Reclaim the port a previous daemon recorded, when it is free. A
        # running session's HTTPS_PROXY is fixed at exec time, so coming back
        # on a fresh port strands every live session on a dead one — and its
        # requests then leave WITHOUT the pin instead of failing loudly
        # (measured: an RC session created that way was owned by the active
        # account while the pin still looked healthy).
        # WHAT THE USER ASKED FOR WINS, ahead of every reclaim below. The
        # reclaim order exists to keep LIVE sessions attached across a
        # respawn; a configured port is a standing instruction about where
        # this pin serves, and honouring it only when no record happened to
        # survive would make `--set_port` do nothing on the machines that
        # matter — the ones that have been running.
        #
        # The cost is real and belongs to whoever sets it: moving the port
        # strands sessions whose HTTPS_PROXY was fixed at exec, exactly as the
        # note below describes. That is why nothing here CHANGES the port on
        # its own; it changes only when a human says so.
        want = wanted_port(self._certdir)
        for candidate in ([want] if isinstance(want, int) and want > 0 else []) + [0]:
            try:
                self._srv.bind((self._host, candidate))
                break
            except OSError:
                continue  # taken by something else — fall through to an
                          # ephemeral port
        self._srv.listen(64)
        self.port = self._srv.getsockname()[1]
        # SAY SO WHEN A CONFIGURED PORT WAS NOT HONOURED. The fall-through
        # above is right — a pin must serve rather than refuse — but silence
        # turns "the port I set is not being used" into a mystery whose only
        # symptom is a number that does not match. Everything the reader needs
        # is the two numbers and the reason.
        asked = configured_port(self._certdir)
        if isinstance(asked, int) and asked != self.port:
            _log_lifecycle(
                f"configured port {asked} is not available — serving on "
                f"{self.port} instead"
            )
        self._start_accept_loop()

    def _start_accept_loop(self) -> None:
        """Run the accept loop on a thread we can JOIN, not merely signal.

        Kept as a handle because exactly one process may be accepting on a
        socket at a time. The kernel hands each connection to ONE of the fd
        holders that calls ``accept()``, so a predecessor still inside its
        loop dequeues connections it has already stopped serving — measured
        by a peer on a launcher that kept accepting alongside its child:
        19 of 60 requests lost in steady state, no restart involved.
        """
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def release_listener(self, hand_down: bool = False) -> "int | None":
        """Stop accepting, leaving open connections alone. The fd if handed down.

        The half of :meth:`stop` a handover needs FIRST. ``stop(drain=N)``
        closes the listener and then waits N seconds before returning, so the
        successor could not bind until the drain was over and the port was
        unbound for all of it — measured at 31 s on a live box, with a peer's
        request refused inside the window.

        Splitting it lets the successor take the port immediately while the
        requests already in flight here keep running; :meth:`await_inflight`
        collects them afterwards.

        ``hand_down`` goes one step further and is what closes the gap
        entirely. Closing the port and letting the successor rebind it is
        instant in the kernel (a rebind after close measured 0.0000s), but the
        successor is a fresh interpreter and takes ~50ms to reach ``bind()`` —
        and neither ``SO_REUSEADDR`` nor ``SO_REUSEPORT`` will co-bind a port
        that is still listening, so that window cannot be overlapped away.
        Measured on a live box: 6 refused requests over 0.27s per handover,
        unchanged by every drain fix. Passing the SOCKET down instead leaves
        the port bound the whole time, so arrivals queue in the backlog:
        0 refused.

        Either way this returns only once our accept loop has ENDED. A
        signalled-but-running loop would keep winning connections from a
        socket it no longer serves.
        """
        self._stop = True
        srv, self._srv = self._srv, None
        # JOIN, do not merely set the flag. The loop polls with a 0.5s
        # timeout, so it can be inside `accept()` right now — and an accept
        # that succeeds after we have handed the socket down takes a
        # connection away from the successor and drops it.
        t = getattr(self, "_accept_thread", None)
        if t is not None and t is not threading.current_thread():
            # WAKE IT, do not wait out its poll. The loop uses a 0.5s accept
            # timeout to notice `_stop`, so a bare join paid up to that on
            # EVERY stop — measured at 502 ms, and the test suite alone stops
            # ~50 servers, which was 25 s of pure waiting. One loopback
            # connect makes accept() return at once; the loop sees `_stop` and
            # ends. Harmless if it races the socket closing, hence the guard.
            if srv is not None:
                try:
                    with socket.create_connection(
                        srv.getsockname(), timeout=0.2
                    ):
                        pass
                except OSError:
                    pass
            t.join(timeout=5.0)
        self._accept_thread = None
        if srv is not None and hand_down:
            if self._inherited:
                # NOT OURS TO PASS ON. A supervisor holds this port across our
                # restarts; handing its socket to a child we do not control
                # would leave that child accepting on it after we are gone.
                self._srv = srv
                return None
            fd = srv.detach()  # leave it LISTENING and open for the successor
            os.set_inheritable(fd, True)
            self._handed_fd = fd
            return fd
        self._srv = srv
        if self._srv and self._inherited:
            # NOT OURS TO CLOSE — a supervisor holds this port precisely so it
            # keeps answering across our restarts.
            #
            # DETACH, do not just drop the reference. Dropping it hands the
            # socket to CPython's finalizer, which closes the fd — measured:
            # fd 3 gone with errno 9 and the supervisor's port refusing
            # immediately afterwards, which is the exact outage this branch
            # exists to prevent. ``detach`` gives up the object and leaves the
            # descriptor open, the same way _inherited_listener refuses a bad
            # fd without closing it.
            try:
                self._srv.detach()
            except OSError:
                pass
            self._srv = None
            return None
        elif self._srv:
            # SHUTDOWN BEFORE CLOSE. A thread blocked in ``accept()`` keeps the
            # listening socket alive across a bare ``close()``: measured, the
            # port stayed "Address already in use" while ``fileno()`` was
            # already -1, so the successor could not reclaim the recorded port
            # and came up on a fresh one — stranding every session whose
            # HTTPS_PROXY was fixed at exec.
            try:
                self._srv.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # never listened, or already down
            try:
                self._srv.close()
            except OSError:
                pass
            self._srv = None
        return None

    def await_inflight(self, budget: float) -> None:
        """Wait up to ``budget`` for open connections to finish, then cut them.

        A CEILING, not a wait: zero clients returns at once. Kept separate from
        releasing the port so a handover can do this while its successor is
        already accepting.
        """
        if budget > 0:
            deadline = time.monotonic() + budget
            while time.monotonic() < deadline:
                if self.live_client_count() == 0:
                    break
                time.sleep(0.05)
        self._close_open_connections()

    def stop(self, drain: float = 0.0) -> None:
        """Stop accepting, and optionally let in-flight requests FINISH.

        Closing the listener is instant and correct — a new connection should
        go to whoever takes the port next. The connections already open are a
        different matter: they are carrying REQUESTS, and this proxy sits on
        `HTTPS_PROXY`, so one of them is very likely a `/v1/messages` response
        streaming into a session right now.

        Measured before this existed: with the listener closed and the process
        calling ``os._exit(0)`` a moment later, a client mid-response got
        ``ConnectionResetError`` — 34 connections were open on the live daemon
        at the time. That turned "upgrade the pin" into "every session routed
        through it loses whatever it was doing", which is the thing an
        optional feature must never be able to do.

        ``drain`` is a CEILING, not a wait: the common case is zero clients and
        returns at once. A request that outlives the budget is still cut, but
        the budget exists so that the normal case — a few seconds of streaming
        — completes.
        """
        self.release_listener()
        self.await_inflight(drain)

    def _close_open_connections(self) -> None:
        """Close every open connection, write end first.

        Draining alone is not enough and the difference is not subtle:
        measured, a request that had transferred every one of its bytes STILL
        reached the client as ConnectionResetError, because the teardown path
        ends in ``os._exit(0)`` and a process exiting without closing its
        sockets makes the kernel answer with RST instead of FIN. The data had
        arrived; the client threw it away over the reset. One
        ``shutdown(SHUT_WR)`` per connection turns that into a clean EOF.
        """
        with self._live_lock:
            conns, self._open_conns = list(self._open_conns), set()
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    # -- internals ----------------------------------------------------------

    def _accept_loop(self) -> None:
        # Hold the socket, not the attribute: stop() clears ``_srv`` when a
        # supervisor owns the port (closing it there would drop the port), and
        # reading the attribute each pass would then raise AttributeError in a
        # daemon thread instead of ending the loop.
        srv = self._srv
        # A bounded wait so ``_stop`` is noticed without needing the listener
        # closed underneath us — which is the only wake-up available when the
        # socket is not ours to close.
        srv.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            # A timeout on the LISTENER is inherited by every socket it
            # accepts, which would then cut a quiet-but-healthy stream. The
            # wait above is about noticing shutdown, not about the client.
            conn.settimeout(None)
            threading.Thread(
                target=self._serve_client, args=(conn,), daemon=True
            ).start()

    def _sweep_bridges_after_connect(self, token: str) -> None:
        """Sweep superseded bridges, right after this session opened one.

        THE EVENT, NOT A TIMER. A duplicate is created at exactly one moment:
        a session opens an RC bridge while an older bridge of the same name is
        still `connected`. That is when the sidebar becomes a coin flip, and
        it is the only moment worth spending an API listing on. A periodic
        sweep would wake a quiet daemon for hours to find nothing, and would
        still leave the window between ticks — the one time it matters.

        The pin sees this event for free: every RC lifecycle call is a route
        it already swaps the bearer on, so `/v1/code/sessions` succeeding IS
        the notification. Nothing polls and nothing extra is dialled.

        In a thread, and never awaited: the client's response must not wait on
        a listing, and a hanging API call must not hold a request open.
        `_bridge_sweeping` keeps a burst of session calls from starting N
        sweeps beside each other.
        """
        with self._sweep_lock:
            if self._bridge_sweeping:
                return
            self._bridge_sweeping = True

        def _run():
            try:
                self.sweep_superseded_bridges(token)
            except Exception:  # noqa: BLE001 — never take the daemon down
                pass
            finally:
                with self._sweep_lock:
                    self._bridge_sweeping = False

        threading.Thread(target=_run, daemon=True).start()

    def _serve_client(self, conn: socket.socket) -> None:
        """``_handle_client`` with the connection counted for its lifetime.

        The daemon knows who is talking to it better than any external probe
        can, and portably: the ``/proc/net/tcp`` scan behind
        ``clients_that_arming_would_cut_off`` answers None on macOS, where it
        was then read as "nobody is connected" and let the idle watcher stop
        a daemon mid-conversation.
        """
        with self._live_lock:
            self._live_clients += 1
            self._open_conns.add(conn)

        def _release():
            with self._live_lock:
                self._live_clients -= 1
                self._open_conns.discard(conn)

        # HANDED OVER, NOT FINISHED. A handler that turns the connection into
        # an opaque tunnel gives its thread back and passes this teardown to
        # the pump, which runs it at EOF — so the connection stays counted for
        # its whole life without a thread sitting on it. Measured before this:
        # 300 connections cost 304 threads, exactly 1:1, which is how a dead
        # upstream reached 27,491.
        self._local.release = _release
        detached = False
        try:
            detached = bool(self._handle_client(conn))
        finally:
            if not detached:
                _release()
            self._local.release = None

    def live_client_count(self) -> int:
        """How many clients are connected right now. Never None: this is a
        count the daemon keeps itself, not an inference about the OS."""
        with self._live_lock:
            return self._live_clients

    def _bridge_api(self, method: str, path: str, token: str, timeout: float = 30.0):
        """One call to the sessions API, over the daemon's own egress.

        NOT THROUGH OUR OWN PORT. `/v1/code/sessions` is a PINNED ROUTE, so a
        call routed through this daemon re-enters the swap path and is
        indistinguishable from a session's own request — it overwrote the
        bearer a real retry was using, caught by
        `case_a_403_on_a_swapped_route_is_retried_unswapped`.

        NOR A PLAIN DIRECT DIAL. Measured on this host: a fresh
        `create_default_context()` to api.anthropic.com fails
        CERTIFICATE_VERIFY_FAILED, because the direct route is a TLS-inspecting
        corporate proxy. `_connect_upstream` + `_upstream_ctx` are the pair
        that already solves both — the chain walk and the trust that matches
        whichever hop answered — so this reuses them rather than becoming a
        third egress path with its own copy of the same decisions.

        None means "could not ask", NEVER "nothing there": a sweep that read a
        failed call as an empty listing would close every bridge on the
        account.
        """
        raw = None
        try:
            raw, via_loopback = self._connect_upstream()
            up = _wrap_upstream(self._upstream_ctx(via_loopback), raw, UPSTREAM_HOST)
            up.settimeout(timeout)
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {UPSTREAM_HOST}\r\n"
                f"Authorization: Bearer {token}\r\n"
                "anthropic-beta: oauth-2025-04-20\r\n"
                "anthropic-version: 2023-06-01\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n\r\n"
            )
            up.sendall(req.encode("latin1"))
            status_line = _read_line(up) or ""
            headers = []
            while True:
                h = _read_line(up)
                if h in ("", None):
                    break
                if ":" in h:
                    k, v = h.split(":", 1)
                    headers.append((k.strip(), v.strip()))
            body = _read_body(up, headers)
            try:
                code = int(status_line.split(" ")[1])
            except (IndexError, ValueError):
                return None
            if code >= 400:
                return None
            return json.loads(body) if body else {}
        except Exception:  # noqa: BLE001 — could not ask
            return None
        finally:
            if raw is not None:
                try:
                    raw.close()
                except OSError:
                    pass

    def _list_bridges(self, token: str):
        """Every session on the pinned account, paginated. None when it failed.

        PAGINATION IS NOT OPTIONAL: the first page is 100 of ~560 here, and a
        sweep that saw only page one would treat every later bridge as absent.
        """
        out, cursor = [], None
        for _ in range(40):
            path = "/v1/code/sessions?limit=100"
            if cursor:
                path += "&cursor=" + quote(cursor)
            page = self._bridge_api("GET", path, token)
            if page is None:
                return None if not out else out
            out.extend(page.get("data") or [])
            cursor = page.get("next_cursor")
            if not cursor:
                break
        return out

    def sweep_superseded_bridges(self, token: str) -> int:
        """Close bridges that a NEWER bridge of the same name has replaced.

        THREE CONDITIONS, ALL REQUIRED. Each alone closes something in use;
        the measurement that ruled each one out is named with it.

        1. ``connection_status == "connected"``. Only a connected bridge
           competes for a message; a disconnected one costs nothing and
           closing it would only destroy history.

        2. ``status == "archived"``. A session that merely ENDED stays
           ``active`` — 186 of them here — so ``active`` cannot mean "gone".

        3. A NEWER BRIDGE SHARES ITS TITLE. This is what makes it safe.
           ``archived`` alone is also what the user gets by archiving a
           conversation they mean to return to: of 269 archived-and-connected
           bridges here, 202 are the newest thing carrying their title, and
           closing those would delete exactly what someone put away on
           purpose. The other 67 are the shape this exists for.

        "NO PROCESS ON THIS MACHINE" IS DELIBERATELY NOT A CONDITION. The pin
        exists so ONE account holds every machine's bridges, so this host sees
        the other machines' sessions and cannot check their pids. It would
        have been destructive: ``pmac-inbound-demo`` and ``pinverify-pmac``
        have no process here and were both LIVE on via-personal-mac when this
        was measured. Local liveness is used only as a NEGATIVE guard — never
        close something running here — never as evidence anything is dead.

        Nor is a title shared between two LIVE bridges a reason to close
        either: two windows both named ``cswap`` that each opened RC are two
        sessions in use, and that is for the human to fix with `/rename`.
        """
        sessions = self._list_bridges(token)
        if sessions is None:
            return 0  # could not ask — certainly not "delete everything"

        live = _live_bridge_ids()
        newest: dict[str, str] = {}
        for item in sessions:
            title = (item.get("title") or "").strip()
            if title:
                stamp = item.get("last_event_at") or ""
                if stamp > newest.get(title, ""):
                    newest[title] = stamp

        closed = 0
        for item in sessions:
            sid, title = item.get("id"), (item.get("title") or "").strip()
            if not sid or not title or sid in live:
                continue
            if item.get("connection_status") != "connected":
                continue
            if item.get("status") != "archived":
                continue
            if (item.get("last_event_at") or "") >= newest[title]:
                continue  # the newest of its name — someone put this away
            if self._bridge_api(
                "DELETE", f"/v1/code/sessions/{sid}", token
            ) is not None:
                closed += 1
        if closed:
            _log_lifecycle(f"closed {closed} superseded remote-control bridges")
        return closed

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
                # A PIN THAT IS SET IS A PIN THAT APPLIES.
                #
                # The gate this replaces demanded a credential carried in
                # HTTPS_PROXY, which is fixed at exec. That made turning the
                # pin on a destructive act (407 for every session that
                # predated the credential — measured: 313 processes), and
                # softening it to "serve them unpinned" only traded one
                # failure for another: the pin silently did not apply to the
                # sessions the user was looking at.
                #
                # Neither is what the feature is for. `cswap pin 1` means
                # Remote Control and Artifacts belong to account 1, for every
                # session on this machine, now — not for sessions launched
                # afterwards.
                #
                # WHAT THE CREDENTIAL BOUGHT, precisely: the proxy listens on
                # loopback and the kernel does not check uid on a TCP connect,
                # so any process that can reach the port could obtain a bearer
                # for the pinned account. But the secret lives at 0600 in the
                # cert dir, so every process running AS THIS USER can read it
                # — the sandboxed tool, the npm postinstall — which is the
                # threat the docstring named. It only ever excluded a
                # DIFFERENT login on a shared host. These are single-user
                # machines; there is no such login to exclude, and the cost
                # was the feature not working.
                #
                # THE BLIND TUNNEL IS NOT GATED EITHER, and keeping it gated
                # was my error. "Do not be an open forward proxy" assumes the
                # port is reachable; this one binds 127.0.0.1 only, so the
                # population it could refuse is the same-user processes that
                # can read the 0600 secret anyway.
                #
                # What it actually cost: every host that is NOT api.anthropic.com
                # takes this path — git, pip, npm, the auto-updater. Measured
                # with the pin on and a session wired before the credential:
                #   api.anthropic.com  200
                #   github.com         407
                #   pypi.org           407
                #   registry.npmjs.org 407
                # So turning the pin on severed general internet for every live
                # session while leaving Claude itself working, which reads as
                # "the network broke" and not as "the pin did something".
                host = target.rsplit(":", 1)[0]
                if host != UPSTREAM_HOST:
                    return self._blind_tunnel(target, conn)
                return self._mitm(conn)
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

    def _current_secret(self) -> str | None:
        """The credential to require RIGHT NOW, or None to require none.

        Re-read per connection, like ``_current_chain`` does for the egress
        proxy, so a secret written under a running daemon takes effect without
        a respawn. Caching it at construction meant the gate armed on the next
        RESPAWN instead — a fingerprint recycle, a deploy, an idle teardown —
        with nothing a human would connect to the resulting 407s.

        Arming DOES cut off sessions wired before the credential existed —
        their ``HTTPS_PROXY`` is fixed at exec time and cannot be updated in
        place (measured: 67 such sessions on linux). That is unavoidable, not
        a bug to design around: nothing in a request distinguishes one of them
        from an attacker, so any rule that keeps serving them keeps the hole
        open. What matters is that it happens WHEN AN OPERATOR ASKS, in one
        step they can pair with a relaunch, instead of silently on some later
        respawn. Hence: minted by ``apply_pin``, enforced from that instant.
        """
        return read_proxy_secret(self._certdir) or None

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
        # RECORD IT, do not only say it. The advice this prints — "re-run
        # `cswap pin` from a normal terminal" — cannot work on its own:
        # ensure_proxy reuses any daemon whose fingerprint matches, so the
        # re-run finds this same blind daemon and returns it. Measured on
        # macOS: `cswap pin 1` from a GUI tmux window left pid 56790 (spawned
        # over ssh, keychain rc=36) serving, unchanged, still unpinnable.
        #
        # Written to the state file so the NEXT ensure_proxy can see what only
        # this process could learn, and recycle instead of reusing.
        try:
            mark_daemon_unpinnable(self._certdir)
        except Exception:  # noqa: BLE001 — advisory; never break a request
            pass
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
                # the client's headers verbatim to the chain (a cache proxy, a corporate
                # proxy), which would hand them a working credential for the
                # pinned account's proxy. It is hop-by-hop by definition
                # (RFC 9110): it authenticates to THIS proxy and stops here.
                if k.strip().lower() == "proxy-authorization":
                    continue
            headers.append(h)
        # STILL A HARD GATE here, unlike CONNECT. This path is plain-HTTP
        # forwarding to an arbitrary host: there is no bearer to withhold, so
        # "serve it unpinned" is not a weaker option — it just makes us an open
        # forward proxy. The CONNECT path could soften because refusing there
        # bought nothing the swap decision does not already buy.
        #
        # Nothing Claude Code does reaches here (it CONNECTs), so this refusal
        # cannot cut off the sessions the pin toggle is about.
        if not _proxy_authorized(parsed, self._current_secret()):
            self._refuse_unauthorized(conn)
            return
        split = urlsplit(url)
        # The scheme decides the port. Defaulting every scheme to 80 pointed
        # every https:// target at the wrong port, so those requests (the
        # auto-updater, telemetry) could not succeed at all.
        secure = split.scheme == "https"
        host, port = split.hostname, split.port or (443 if secure else 80)
        # Re-read like every other egress site: the daemon is constructed with
        # chain_proxy=None, so reading self._chain here meant this path ALWAYS
        # dialled the origin direct — bypassing the egress proxy on exactly the
        # traffic (auto-updater, telemetry) it was added to rescue, and hard
        # failing where there is no direct route out.
        # EVERY HOP, like the MITM path and the blind tunnel. Reading only the
        # first one meant a dead hop fell through to a dial at the ORIGIN,
        # skipping the hop behind it — and on a host with no direct route out
        # that is not a downgrade, it is a failure. This is the auto-updater's
        # and telemetry's path.
        up = head = None
        for chain in self._chain_candidates():
            try:
                up = _dial_chain(chain, extra_ca=self._chain_ca())
            except (OSError, ssl.SSLError):
                up = None
                continue
            # A plain proxy takes the absolute-form line as-is. Our own
            # credential for the chain rides here, not the client's.
            head = (
                f"{method} {url} HTTP/1.1\r\n"
                + "\r\n".join(headers)
                + "\r\n"
                + chain.connect_headers()
                + "\r\n"
            )
            break
        if up is None:
            try:
                up = socket.create_connection((host, port), timeout=15)
                if secure:
                    # An https:// origin dialled direct needs the handshake,
                    # verified. Without it we sent cleartext HTTP at a TLS
                    # port and the request simply failed.
                    up = _verifying_ctx().wrap_socket(up, server_hostname=host)
            except (OSError, ssl.SSLError):
                conn.close()
                return
            path = split.path or "/"
            if split.query:
                path += "?" + split.query
            head = f"{method} {path} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        try:
            # Connect budget only, same as the tunnel: _pump streams, and a
            # read timeout left on the socket tears down a response that is
            # merely quiet — an SSE gap or a slow origin — rather than dead.
            up.settimeout(None)
            up.sendall(head.encode("latin1"))
            _pump(conn, up)
        finally:
            try:
                up.close()
            except OSError:
                pass

    def _mitm(self, conn: socket.socket) -> bool:
        """Serve requests on this connection. True when it was HANDED OVER.

        A 101 turns the connection into an opaque stream that the shared pump
        owns from then on — so this frame must NOT close it, and its caller
        must not run the per-connection teardown that the pump will run at EOF.
        """
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        tls = self._server_ctx.wrap_socket(conn, server_side=True)
        self._local.detached = False
        try:
            while True:
                if not self._handle_one_request(tls):
                    break
        finally:
            if not getattr(self._local, "detached", False):
                self._drop_upstream()
                try:
                    tls.close()
                except OSError:
                    pass
        return bool(getattr(self._local, "detached", False))

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
        original_headers = list(headers)
        if pinned:
            token = self._pin_token_provider()
            if token:
                headers = [
                    (k, f"Bearer {token}") if k.lower() == "authorization" else (k, v)
                    for k, v in headers
                ]
                swapped = True
                # A SESSION WAS JUST OPENED — the one moment a duplicate can
                # appear. `POST /v1/code/sessions` is how a bridge is created,
                # so an older bridge of the same name becoming ambiguous
                # happens here and nowhere else. Sweeping on THIS instead of a
                # timer means a quiet daemon never wakes to find nothing, and
                # the fix lands when it is needed rather than up to an hour
                # later. Fired on the request rather than the response: the
                # sweep re-lists from the server anyway, so a create that
                # fails simply finds nothing new to supersede.
                if method == "POST" and path == "/v1/code/sessions":
                    self._sweep_bridges_after_connect(token)
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

        keep = self._forward(method, path, headers, body, tls, swapped=swapped)
        if keep is _AUTH_REJECTED:
            # THE SWAP ITSELF WAS REFUSED. Send it again as it arrived.
            #
            # A 401/403/404 is terminal to the client — SSETransport treats
            # those as permanent (M7y = new Set([401,403,404])), sets
            # state="closed", and never reconnects, so one misrouted request
            # kills Remote Control for the life of the process. Measured: a
            # /worker-swap experiment produced 26 such responses and severed
            # the inbound channel of four sessions that are still running
            # hours later with bridgeSessionId gone.
            #
            # That makes route classification a single point of permanent
            # failure, and no amount of care in the predicate removes the
            # risk. Retrying without the swap turns "I guessed wrong about
            # this route" into "this request went out unpinned", which is the
            # failure mode the whole module is already built to tolerate.
            self._drop_upstream()
            keep = self._forward(method, path, original_headers, body, tls)
        # A client that asked to close gets closed regardless of the upstream.
        for k, v in headers:
            if k.lower() == "connection" and "close" in v.lower():
                keep = False
        return keep

    def _forward(self, method, path, headers, body, client: ssl.SSLSocket,
                 swapped: bool = False) -> bool:
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
            # _read_body decoded a chunked body, and the transfer-coding
            # header is dropped just below (hop-by-hop), so the framing has
            # to be re-declared or the upstream reads a bodyless request.
            dechunked = any(
                k.lower() == "transfer-encoding" and "chunked" in v.lower()
                for k, v in headers
            )
            for k, v in headers:
                kl = k.lower()
                if kl.startswith("proxy-"):
                    continue
                if kl in _HOP_BY_HOP and not (
                    upgrading and kl in ("connection", "upgrade")
                ):
                    continue
                if kl == "content-length" and dechunked:
                    continue  # replaced below with the decoded length
                if kl == "host":
                    v = UPSTREAM_HOST
                    sent_host = True
                out.append(f"{k}: {v}".encode("latin1"))
            if dechunked:
                out.append(f"Content-Length: {len(body or b'')}".encode("latin1"))
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
                    # 101 = OPAQUE FROM HERE. Nothing further on this
                    # connection is HTTP, so the thread that carried the
                    # handshake has no work left: hand both sockets to the
                    # shared selector and give it back. This is the Remote
                    # Control WebSocket, which stays open for the whole
                    # session — the single longest-lived thing the pin holds.
                    self._local.up = None  # the pump owns it now
                    _pump_detached(up, client, getattr(self._local, "release", None))
                    self._local.detached = True
                    return False
                self._drop_upstream()
                return False
            return _relay_response(
                up, client, getattr(self._local, "cid", 0),
                reject_on_auth_error=swapped,
                # A HEAD response carries the headers of the GET it mirrors,
                # Content-Length included, but no body — only the request
                # method says so.
                method=method,
            )
        except (OSError, ssl.SSLError):
            self._drop_upstream()
            return False

    def _upstream_conn(self) -> ssl.SSLSocket:
        """The live upstream TLS socket for this MITM connection, dialing on
        first use. Reused across requests so keep-alive and SSE work."""
        up = getattr(self._local, "up", None)
        if up is None:
            # The context must describe the socket we ACTUALLY got, not the
            # chain we hoped for. _connect_upstream falls back to a direct
            # dial when the recorded chain is unreachable, and _upstream_ctx
            # re-reading the (still loopback) hint would then hand a
            # CERT_NONE context to a real internet connection carrying
            # account bearers.
            raw, via_loopback = self._connect_upstream()
            up = _wrap_upstream(
                self._upstream_ctx(via_loopback), raw, UPSTREAM_HOST
            )
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

    def _upstream_ctx(self, via_loopback: bool) -> ssl.SSLContext:
        """TLS context for the hop to the real api.anthropic.com.

        When we chain through a LOOPBACK proxy (any local MITM), that
        hop re-signs api.anthropic.com with its own CA whose path we can't know
        portably — and it terminates on localhost, having itself verified the
        real upstream. So we skip cert verification for a loopback chain,
        exactly as the real client (Node) does by trusting that CA blindly.
        For a direct dial or a remote proxy, full verification stays on:
        system roots (real cert) + our own CA (test fakes) + any corp CA on
        NODE_EXTRA_CA_CERTS.

        ``via_loopback`` is reported by the dial that actually happened, never
        re-derived from the hint. Reading the hint independently meant an
        unreachable loopback chain fell back to a DIRECT dial while this still
        answered CERT_NONE — an unverified connection to the real
        api.anthropic.com carrying account bearers, i.e. MITM-able exactly
        when the local chain is down.
        """
        if via_loopback:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        # Our own CA too, so a test's fake upstream verifies.
        return _verifying_ctx(self._bundle.ca_path)

    def _chain_ca(self) -> "Path | None":
        """The egress proxy's own CA, as recorded beside the proxy address.

        ``write_upstream_hint`` records it precisely so a later launch that
        cannot see the proxy's environment can still verify it. The daemon is
        one of those launches — it is spawned from whatever shell ran
        ``cswap pin``, which normally has no ``NODE_EXTRA_CA_CERTS`` — so
        without this the recorded CA was never consulted and an ``https://``
        corporate proxy failed verification against the public roots alone.
        """
        ca = read_upstream_ca(self._certdir)
        return Path(ca) if ca else None

    def _current_chain(self) -> tuple[str, int] | None:
        """The egress proxy to CONNECT through, re-read per connection.

        Not a snapshot: a local egress proxy can restart on another port, or
        come up only after this daemon did. Binding the chain once at spawn
        would leave the daemon bypassing it — and where that proxy is the only
        route out, bypassing it is a hard failure, not a performance note.
        ``rediscover_chain=False`` keeps tests explicit.
        """
        # Returned RAW; every consumer runs it through _as_chain, which they
        # must anyway — `_chain` is also assigned directly and this method is
        # stubbed outright in tests, so normalizing here covers neither.
        if not self._rediscover_chain:
            return self._chain
        return read_upstream_hint(self._certdir)

    def _connect_upstream(self) -> tuple[socket.socket, bool]:
        """Dial the upstream (through the chain when there is one).

        Returns ``(socket, via_loopback)``. The flag says how the socket was
        REALLY obtained, because the chain can be unreachable and the dial
        silently becomes direct — and the TLS context must follow the path
        taken, not the path recorded (see :meth:`_upstream_ctx`).

        The 15s budget covers CONNECTING only. It is cleared before the socket
        carries requests, because ``create_connection``'s timeout stays on the
        socket and would then apply to every read — and the Remote Control
        inbound channel is a LONG POLL that deliberately holds its response
        open until the phone/web sends something. With the timeout left on,
        that poll died every 15s and no inbound message ever reached the CLI,
        while heartbeats (which answer at once) kept succeeding — so the
        session looked healthy and was silently deaf.
        """
        # A HOP THAT IS RESTARTING IS NOT A HOP THAT IS GONE. Measured by the
        # cache proxy's own maintainer on the deployed build, hammering the
        # port continuously across a `kill -9` of its holder:
        #
        #     refused=32   accepted-then-silent=0   served=159
        #
        # It comes back in ~1s under a new pid, and it REFUSES for that whole
        # second rather than accepting and going quiet — the successor binds
        # only when it is ready to relay. A refused dial costs this walk
        # nothing, so waiting out that second is nearly free.
        #
        # WHY WAIT AT ALL, when there is already a DIRECT fallback: on the
        # machine this outage happened to, DIRECT is the corporate
        # TLS-inspecting proxy. Falling through to it saves one second and
        # sends the request through an inspector for as long as the hop is
        # away. Holding briefly keeps the chain the user configured.
        #
        # BOUNDED, and small. The window measured is ~1s; this allows a little
        # over twice that and then falls through exactly as before. It is not
        # a retry ladder — the hop's own restart is already bounded (its
        # maintainer killed the holder three times in a row: process count
        # unchanged, one replacement per death, no accumulation), so a ladder
        # here would only add a busy loop neither side intended.
        # NOTHING TO WAIT FOR IF THERE IS NO HOP. The grace exists for a hop
        # that is RESTARTING; an empty candidate list means this host has no
        # chain at all, and `_walk_chain_once` returns None instantly forever.
        # Entering the loop anyway cost 2.60s on EVERY upstream dial —
        # measured, so every new MITM connection and every bridge-sweep call —
        # on exactly the machines where the direct dial is the normal path.
        #
        # The constant's comment already claimed this ("a host with no chain
        # at all never enters this loop"); the code did not implement it, and
        # the comment was the half being believed.
        candidates = self._chain_candidates()
        if candidates:
            deadline = time.monotonic() + _CHAIN_HEAL_GRACE_S
            while True:
                sock = self._walk_chain_once()
                if sock is not None:
                    return sock
                if time.monotonic() >= deadline:
                    break
                time.sleep(_CHAIN_HEAL_POLL_S)
        # Every hop is still unusable after the grace period (or there was
        # never a hop): fall through to the unchained dial, which is what this
        # method has always ended in.
        sock = _dial_with_no_chain(self._upstream)
        sock.settimeout(None)
        self._note_egress(direct=True, configured=bool(candidates))
        return sock, False

    def _walk_chain_once(self) -> "tuple[socket.socket, bool] | None":
        """One pass over the chain. The socket and its loopback flag, or None
        when no hop was usable this time round."""
        candidates = self._chain_candidates()
        for chain in candidates:
            # A HOP THAT REFUSES AND A HOP THAT WILL NOT DIAL ARE ONE EVENT.
            # A dial that raises OSError, a CONNECT answered non-200, and a
            # hop that accepts and never answers all mean the same thing:
            # this hop is not usable, so try the one behind it. A cache proxy
            # that is RESTARTING produces the second and third shapes — its
            # listener is up before its proxy logic is.
            try:
                raw = _dial_chain(chain, extra_ca=self._chain_ca())
            except OSError as exc:
                # NAME WHY, even though the reaction is the same. "the hop
                # refused" and "the hop answered and was wrong" are one
                # decision here and two DIFFERENT FAULTS to whoever runs that
                # hop: the first says its port was down, the second says its
                # port was up and its logic was not. Collapsing them left the
                # log unable to tell a supervisor that kept the port alive
                # from one that never ran — which is the whole claim such a
                # supervisor makes.
                self._note_hop_unusable(chain.address, f"dial failed: {exc!r}")
                continue
            try:
                raw.sendall(
                    f"CONNECT {self._upstream[0]}:{self._upstream[1]} HTTP/1.1\r\n"
                    f"Host: {self._upstream[0]}:{self._upstream[1]}\r\n"
                    f"{chain.connect_headers()}\r\n".encode("latin1")
                )
                status = _read_line(raw)
                while True:
                    h = _read_line(raw)
                    if h in ("", None):
                        break
            except OSError:
                status = None
            if not _connect_ok(status):
                self._note_hop_unusable(
                    chain.address,
                    "accepted but did not tunnel: "
                    + (f"CONNECT -> {status!r}" if status else "no reply"),
                )
                try:
                    raw.close()
                except OSError:
                    pass
                continue
            raw.settimeout(None)
            self._note_egress(direct=False, hop=chain.address)
            return raw, chain.host in _LOOPBACK
        # NO HOP ANSWERED THIS PASS. The caller decides whether that is final:
        # a hop mid-restart refuses for ~1s and then serves again, so the
        # direct dial belongs after a grace period, not here. `candidates`
        # being empty (no chain configured at all) is still the caller's
        # distinction to make — see `_note_egress(configured=...)`.
        return None

    def _note_hop_unusable(self, hop: "tuple[str, int]", why: str) -> None:
        """Log WHY a hop was skipped, once per (hop, reason) transition.

        The walk falls through an unusable hop silently and carries on, so the
        only trace is which hop ended up carrying the request. That is not
        enough to attribute a failure: a hop whose PORT is dead and a hop that
        answers and refuses to tunnel are the same fall-through here and
        opposite faults for whoever runs it. One of them is what a supervisor
        holding that port exists to prevent; the other it cannot touch.

        Deduplicated on the transition like :meth:`_note_egress`, so a hop
        that is steadily down costs one line rather than one per connection.
        """
        state = (hop, why)
        if state == self._hop_fault:
            return
        self._hop_fault = state
        _log_lifecycle(f"hop {hop[0]}:{hop[1]} unusable — {why}")

    def _note_egress(
        self,
        *,
        direct: bool,
        hop: "tuple[str, int] | None" = None,
        configured: bool = True,
    ) -> None:
        """Log egress path changes; silence means the path is unchanged.

        A launch must never be blocked, so no hop reachable degrades to a
        direct dial rather than failing. That downgrade is invisible from the
        outside: requests keep succeeding and the session looks pinned while
        egress has left the path the user configured.

        WHICH HOP is part of the same question. The walk falls through a dead
        hop silently, so a request carried by the second hop and one carried by
        the first are indistinguishable in the log — an observer had to infer
        it afterwards from the TLS issuer. Record the transition only, so a
        steady chain still costs nothing per connection.

        ``configured`` SEPARATES "NOTHING IS SET UP" FROM "NOTHING ANSWERED",
        which used to be one sentence. On a host with no corporate proxy and
        no cache proxy there is no chain to walk, so a direct dial is the only
        thing a pin can do and it is the NORMAL path. Saying "no chain hop
        reachable, bypassing the configured proxy chain" there is false twice
        — nothing was unreachable, and there is no configured chain to bypass
        — and it is the STEADY STATE on such a machine, so a reader seeing it
        alone calls a healthy host degraded. The two need opposite responses:
        one is "go look at your egress proxy", the other is "this is how this
        machine is".
        """
        state = None if direct else hop
        if direct == self._egress_direct and state == self._egress_hop:
            return
        self._egress_direct, self._egress_hop = direct, state
        if direct and not configured:
            _log_lifecycle(
                "egress direct — no proxy chain is configured on this host"
            )
        elif direct:
            _log_lifecycle(
                "egress DIRECT — no chain hop reachable, bypassing the "
                "configured proxy chain"
            )
        else:
            where = f"{hop[0]}:{hop[1]}" if hop else "the proxy chain"
            _log_lifecycle(f"egress via {where}")

    def _chain_candidates(self) -> list[_Chain]:
        """The hops to try, in order. The re-read one first (it is the most
        current), then whatever a launch recorded behind it."""
        chain = _as_chain(self._current_chain())
        hops = [chain] if chain else []
        for hop in _chain_hops(self._certdir):
            if hop not in hops:
                hops.append(hop)
        return hops

    @staticmethod
    def _tunnel_is_open(up: socket.socket):
        """The tunnel if it is actually carrying, None if it is already EOF.

        A CONNECT 200 means the proxy ACCEPTED the request, not that it reached
        the host: a filtering proxy answers optimistically and dials afterwards, closing
        the socket when that dial fails. Look for a closed read end — no client
        byte has been sent yet, so a readable socket here can only mean EOF.
        Never blocks: a healthy idle tunnel has nothing to read and reports not
        ready, which is exactly the "open" answer.

        Reads rather than peeks, because ``MSG_PEEK`` is not available on
        every socket this receives: ``ssl.SSLSocket.recv`` rejects ANY non-zero
        flag with ``ValueError`` — which is not an ``OSError``, so the except
        below could not catch it and it escaped to the connection handler.
        An ``https://`` chain therefore did not merely fail this check, it
        killed the connection AND the direct-dial rescue this check exists to
        trigger. The byte a read consumes is pushed back via :class:`_Prefixed`
        so the caller's stream is unchanged; the socket is returned rather
        than a bool for exactly that reason.
        """
        try:
            ready, _, _ = select.select([up], [], [], 0.35)
            if not ready:
                return up  # nothing to read == still open, the normal case
            first = up.recv(1)
            return _Prefixed(up, first) if first else None
        except (OSError, ValueError):
            return None

    def _blind_tunnel(self, target: str, conn: socket.socket) -> None:
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s else 443
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
        # EVERY HOP, not just the first. This path used to read one hop and
        # fall straight to a direct dial, so the fall-through the MITM path
        # walks did not exist here — on the path where a missed hop is least
        # visible. Remote Control RECEIVES over a WebSocket to the ingress
        # host the /bridge response names, which is not api.anthropic.com and
        # therefore lands here: with the hop missed, the session keeps
        # heartbeating and posting through the MITM at 200 while nothing sent
        # from claude.ai arrives.
        #
        # Try each hop, but never let the chain be the only answer. A
        # filtering proxy (per-domain forwards, a corporate MITM) may refuse
        # the ingress host outright, and closing here made that refusal
        # invisible. Measured where the same session on a machine whose chain
        # let the host through received normally.
        for chain in self._chain_candidates():
            try:
                up = _dial_chain(chain, extra_ca=self._chain_ca())
                up.sendall(
                    f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                    f"{chain.connect_headers()}\r\n".encode("latin1")
                )
                status = _read_line(up)
                while True:
                    h = _read_line(up)
                    if h in ("", None):
                        break
                if not _connect_ok(status):
                    # Refused BY this hop (not a transport failure). Try the
                    # hop behind it; a direct dial is what happens only when
                    # none of them will carry it.
                    if _TRACE is not None:
                        _TRACE.write(
                            f"[c{getattr(self._local, 'cid', 0)}] chain refused "
                            f"{target} ({(status or '').strip()}) — next hop\n"
                        )
                        _TRACE.flush()
                    up.close()
                    up = None
                    continue
            except OSError:
                up = None
                continue
            break
        if up is not None and (carrying := self._tunnel_is_open(up)) is None:
            # A 200 is not proof the chain reached the host. a filtering proxy answers
            # CONNECT optimistically and only then dials; when that dial fails
            # it closes, so the tunnel is EOF the instant we look. Measured on
            # against a remote-control ingress: "200 Connection established"
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
        elif up is not None:
            up = carrying  # the peeked byte, pushed back in front of the stream
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
        # DETACHED: nothing after the 200 is ours to parse, so the thread that
        # built the tunnel has no work left. It hands the pair to the shared
        # selector along with its own teardown and returns.
        _pump_detached(conn, up, getattr(self._local, "release", None))
        return True


_TRACE = (
    open(os.environ["CSWAP_PIN_DEBUG"], "a")
    if os.environ.get("CSWAP_PIN_DEBUG")
    else None
)

class _AuthRejected:
    """Sentinel: the upstream refused the SWAPPED credential, nothing sent.

    Distinct from True/False, which both mean "the client already has its
    response". This says the opposite — the client has received NOTHING and
    the caller must retry.
    """

    __slots__ = ()

    def __bool__(self) -> bool:  # never mistaken for "keep the connection"
        return False


_AUTH_REJECTED = _AuthRejected()

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
}

# The response path parses raw bytes, and `b"transfer-encoding" in
# {str, ...}` is silently False — so that filter did nothing at all and
# every hop-by-hop header was relayed verbatim. It went unnoticed because
# the one case anybody would have caught (chunked) is the one case where
# forwarding the header happens to be RIGHT: we relay the chunk framing
# byte-for-byte, so it really is our hop's encoding too. The others
# (Keep-Alive, TE, Upgrade) describe the upstream's connection, not ours.
_HOP_BY_HOP_BYTES = {k.encode("latin1") for k in _HOP_BY_HOP}


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
    """The request body, decoded.

    Recognizing only ``Content-Length`` read ZERO bytes from a
    ``Transfer-Encoding: chunked`` request while the forwarder stripped the
    transfer-coding header (it is hop-by-hop), so the upstream received a
    bodyless request — every chunked message or artifact upload silently lost
    its payload.

    The body is materialized whole either way, which the retry path already
    requires: a swap the upstream refuses is re-sent unswapped, and a
    streamed body could not be replayed.
    """
    length = 0
    chunked = False
    for k, v in headers:
        kl = k.lower()
        if kl == "content-length":
            try:
                length = int(v)
            except ValueError:
                length = 0
        elif kl == "transfer-encoding" and "chunked" in v.lower():
            chunked = True
    if chunked:
        # Content-Length is ignored when a transfer-coding is present
        # (RFC 9112 §6.3), so decode and let the forwarder re-frame.
        return _read_chunked_body(sock)
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return bytes(body)


def _read_chunked_body(sock) -> bytes:
    """Decode a chunked request body to bytes, trailers discarded."""
    body = bytearray()
    while True:
        line = _read_line(sock)
        if line in ("", None):
            return bytes(body)
        try:
            size = int(line.split(";")[0].strip() or "0", 16)
        except ValueError:
            return bytes(body)
        if size == 0:
            # Consume the trailer section so the socket is left at the start
            # of the next request rather than mid-frame.
            while True:
                t = _read_line(sock)
                if t in ("", None):
                    break
            return bytes(body)
        need = size
        while need > 0:
            chunk = sock.recv(min(65536, need))
            if not chunk:
                return bytes(body)
            body += chunk
            need -= len(chunk)
        _read_line(sock)  # the CRLF terminating this chunk


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


def _status_has_no_body(status_line: bytes, method: str | None) -> bool:
    """Whether RFC 9110 says this response cannot carry a body.

    These are exactly the responses that legitimately arrive with neither
    Content-Length nor Transfer-Encoding, so without this they read as
    "close-delimited" and the relay blocks on recv until the upstream hangs
    up — which a keep-alive server never has to do.
    """
    if method and method.upper() == "HEAD":
        return True
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        code = int(parts[1])
    except ValueError:
        return False
    # 205 Reset Content is also required to carry no content (RFC 9110
    # §15.3.6). 1xx is deliberately NOT here: an interim response is not the
    # final one, and treating it as complete would leave the real status in
    # the upstream buffer for the next request to read — a desync. It gets
    # its own handling in _relay_response.
    return code in (204, 205, 304)


def _is_interim(status_line: bytes) -> bool:
    """A 1xx: an INTERIM response, to be forwarded and then read past."""
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return False
    try:
        return 100 <= int(parts[1]) < 200
    except ValueError:
        return False


class _Prefixed:
    """A socket with bytes pushed back in front of it.

    Reading a response head can consume the start of the NEXT one; a socket
    has no unread, so the leftover travels here instead.
    """

    def __init__(self, sock, prefix: bytes):
        self._sock = sock
        self._buf = bytearray(prefix)

    def recv(self, n: int) -> bytes:
        if self._buf:
            out, self._buf = bytes(self._buf[:n]), bytearray(self._buf[n:])
            return out
        return self._sock.recv(n)

    def __getattr__(self, name):
        return getattr(self._sock, name)


def _relay_response(
    up: ssl.SSLSocket,
    client: ssl.SSLSocket,
    cid: int = 0,
    reject_on_auth_error: bool = False,
    method: str | None = None,
) -> bool:
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
    # Nothing has reached the client yet, so a swap the upstream refused can
    # still be taken back. 401/403/404 are the three the client treats as
    # permanent; anything else is the origin's own answer and belongs to it.
    if reject_on_auth_error and any(
        status_line.startswith(b"HTTP/1.1 " + c) for c in (b"401", b"403", b"404")
    ):
        if _TRACE is not None:
            _TRACE.write(
                f"[c{cid}]     <- {status_line.decode('latin1', 'replace')}"
                " (swap refused — retrying unswapped)\n"
            )
            _TRACE.flush()
        return _AUTH_REJECTED
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
    bodyless = _status_has_no_body(status_line, method)
    interim = _is_interim(status_line)
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
        if kl in _HOP_BY_HOP_BYTES:
            continue
        out.append(line)
    if chunked:
        # Transfer-Encoding is hop-by-hop, so the loop above drops it — but
        # _pipe_chunked relays the chunk-size lines VERBATIM. Announcing no
        # framing while sending chunk syntax leaves the client to read
        # "1a\r\n" as body bytes, or to wait for a close that a keep-alive
        # upstream never sends. This IS our hop's encoding: re-declare it.
        out.append(b"Transfer-Encoding: chunked")
    if not keep:
        # Connection is hop-by-hop too, and `close` was read into `keep` and
        # then dropped — so the proxy was about to close while the client
        # still believed the connection reusable. Its next request then died
        # on a dead socket instead of opening a new one. (Before
        # _HOP_BY_HOP_BYTES the filter compared bytes to a str set and never
        # matched, so the header was forwarded by accident and this was
        # accidentally right.) Re-declare it for OUR hop, as with chunked.
        out.append(b"Connection: close")
    if interim:
        # An interim (1xx) response is followed by the real one on the same
        # connection. Returning here delivered the 103 as though it were the
        # answer and left the 200 in the buffer, so the next request read a
        # stale response. Forward it and loop for the final status.
        client.sendall(b"\r\n".join(out) + b"\r\n\r\n")
        if rest:
            # Bytes already read past this head belong to the next response;
            # they cannot be pushed back, so hand them to the recursion.
            return _relay_response(
                _Prefixed(up, rest), client, cid,
                reject_on_auth_error=reject_on_auth_error, method=method,
            )
        return _relay_response(
            up, client, cid,
            reject_on_auth_error=reject_on_auth_error, method=method,
        )
    if bodyless:
        # 204/304 (and 1xx) carry no body by definition and commonly send
        # neither Content-Length nor Transfer-Encoding. Falling through to
        # the close-delimited branch would block on recv until the upstream
        # closes — which a keep-alive server need not ever do — and the
        # client's request just hangs.
        client.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)
        return keep
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


def _drain_ready(src) -> bytes:
    """Everything readable right now, TLS buffer included.

    One TLS record can decrypt to more than a single ``recv`` returns, and a
    selector sees the SOCKET, not the SSL buffer — so bytes already decrypted
    and waiting are invisible to it. Measured: after a recv returning 10
    bytes, 90 more sat in the buffer while the selector reported not-readable.
    A long poll or SSE stream through such a tunnel stalls on data that has
    already arrived.
    """
    data = src.recv(65536)
    pending = getattr(src, "pending", None)
    while data and pending and pending():
        more = src.recv(65536)
        if not more:
            break
        data += more
    return data


class _PumpLoop:
    """ONE selector thread for EVERY tunnel, instead of one thread each.

    THE MEASURED PROBLEM. A connection spends almost its whole life here —
    a CONNECT tunnel is opaque from the 200 onward, and a WebSocket upgrade
    turns the MITM into the same thing — and it used to hold an OS thread for
    that entire time. Counted from outside the process, hop wedged:

        idle          4 threads
         50 conns ->  54 threads
        150 conns -> 154 threads
        300 conns -> 304 threads

    Exactly 1:1, which is how a dead upstream produced 27,491 threads and
    44,121 FDs in 40 minutes and took a 48-core box to load 16,483: the
    retry count IS the thread count. A ceiling was tried and removed — it
    turns the 257th retry into a refused connection and leaves the coupling.

    The multiplexing was always here; `_pump` already ran a selector over its
    two sockets. It just ran one per connection. Registering every pair with
    ONE selector is the same code with the thread removed, which is what an
    event loop would give and what the peer proxy in this chain measured on
    its own side: 84 connections, 11 threads, flat.

    NOT asyncio, deliberately. This module speaks blocking sockets in 53
    places — TLS MITM, CONNECT tunnels, the chain walk, fd hand-down — and
    every one of them carries a measurement that would have to be re-proved
    against a coroutine rewrite. The property the outage needs is "a
    connection is not a thread", and that is this class.
    """

    def __init__(self):
        self._sel = selectors.DefaultSelector()
        self._peer: dict = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        # A self-pipe so `add` wakes the selector instead of waiting out its
        # timeout: a tunnel registered a moment after `select()` blocked would
        # otherwise sit idle for the whole poll, which is a stall the client
        # sees as a hang.
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._sel.register(self._wake_r, selectors.EVENT_READ)

    def add(self, a, b, on_close=None) -> None:
        """Take over a pair of sockets. Returns AT ONCE.

        `on_close` runs when the tunnel ends — it is where the caller's own
        teardown goes, because the caller no longer has a thread to run it on.
        """
        with self._lock:
            self._peer[a] = (b, on_close)
            self._peer[b] = (a, on_close)
            for s in (a, b):
                try:
                    s.setblocking(False)
                    self._sel.register(s, selectors.EVENT_READ)
                except (OSError, ValueError, KeyError):
                    self._close_pair(a, b, on_close)
                    return
            if self._thread is None:
                self._thread = threading.Thread(target=self._run, daemon=True)
                self._thread.start()
        try:
            self._wake_w.send(b"\0")
        except OSError:
            pass

    def _close_pair(self, a, b, on_close) -> None:
        for s in (a, b):
            self._peer.pop(s, None)
            try:
                self._sel.unregister(s)
            except (KeyError, ValueError):
                pass
            try:
                s.close()
            except OSError:
                pass
        if on_close is not None:
            try:
                on_close()
            except Exception:  # noqa: BLE001 — never take the loop down
                pass

    def _run(self) -> None:
        while True:
            for key, _ in self._sel.select(timeout=60):
                src = key.fileobj
                if src is self._wake_r:
                    try:
                        self._wake_r.recv(65536)
                    except OSError:
                        pass
                    continue
                with self._lock:
                    entry = self._peer.get(src)
                    if entry is None:
                        continue
                    dst, on_close = entry
                    try:
                        data = _drain_ready(src)
                    except (BlockingIOError, ssl.SSLWantReadError):
                        continue  # nothing decrypted yet — wait for more
                    except OSError:
                        data = b""
                    if not data:
                        self._close_pair(src, dst, on_close)
                        continue
                    try:
                        # Blocking for the WRITE only. A non-blocking sendall
                        # can raise mid-buffer with no record of how much went
                        # out, and a tunnel that loses bytes silently is worse
                        # than one that waits: the peer is a local hop or an
                        # already-connected upstream, so this drains promptly.
                        dst.setblocking(True)
                        dst.sendall(data)
                        dst.setblocking(False)
                    except OSError:
                        self._close_pair(src, dst, on_close)


_PUMP = _PumpLoop()


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Shuttle bytes both ways until either side closes, BLOCKING.

    The shared selector does the waiting, so this thread is parked on an Event
    rather than on a socket — but it is still a thread. Prefer
    :func:`_pump_detached` on any path that can give its thread back; this
    remains for callers whose own frame must outlive the tunnel.
    """
    done = threading.Event()
    _PUMP.add(a, b, done.set)
    done.wait()


def _pump_detached(a: socket.socket, b: socket.socket, on_close=None) -> None:
    """Hand a tunnel to the shared selector and RETURN.

    This is where the thread is given back. A tunnel is opaque from the 200
    onward and lives for as long as the session does, so the thread that set
    it up has nothing left to do — it was only holding the connection open.
    `on_close` carries whatever teardown that frame would have run.
    """
    _PUMP.add(a, b, on_close)



if __name__ == "__main__":  # pragma: no cover — exercised as a subprocess
    import sys as _sys

    if _sys.argv[1:2] == [_HOLDER_MODULE_ARG]:
        holder_main(_sys.argv[3], _sys.argv[4], Path(_sys.argv[5]),
                    port=int(_sys.argv[2]))
    else:
        daemon_main(_sys.argv[1], _sys.argv[2], Path(_sys.argv[3]))
