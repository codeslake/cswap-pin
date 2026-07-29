"""Account-pin proxy.

A local MITM forward proxy that swaps the ``Authorization`` bearer to a pinned
account's token on the Remote-Control and Artifact routes, so those operations
stay on one account while inference follows whatever cswap has swapped onto
disk. Everything else (inference at ``/v1/messages``, OAuth, telemetry, …) is
relayed untouched, and non-anthropic hosts are blind-tunnelled.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import selectors
import socket
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

    Returns ``(host, port)`` to CONNECT through (CCF's ``127.0.0.1:9901``, a
    corporate proxy, …), or ``None`` when there was none — in which case the
    proxy dials the upstream directly. A bare ``host:port`` (no scheme) is
    accepted; a scheme-only URL defaults to port 80.
    """
    if not value:
        return None
    split = urlsplit(value if "://" in value else f"//{value}")
    host = split.hostname
    if not host:
        return None
    return host, split.port or 80


def read_upstream_hint(certdir: Path) -> tuple[str, int] | None:
    """The egress proxy the LAST launch was using, as recorded on disk.

    The daemon outlives the launch that spawned it, and a session's own
    ``HTTPS_PROXY`` is fixed at exec — so the daemon cannot ask "what should I
    chain through now?" of anything but this file. Every launch re-stamps it
    (``ensure_proxy``), so a CCF that moved ports or came up after the daemon
    is picked up on the next connection rather than bypassed for the daemon's
    whole life.

    Returns ``None`` when the file is absent or records "no proxy" — the same
    thing a direct dial means.
    """
    try:
        raw = json.loads((Path(certdir) / _UPSTREAM_FILE).read_text())
    except (OSError, ValueError):
        return None
    value = raw.get("proxy") if isinstance(raw, dict) else None
    return parse_upstream_proxy(value) if value else None


def write_upstream_hint(certdir: Path, value: str | None) -> None:
    """Record the egress proxy for the daemon to chain through (see above).

    Written on every launch, including when there is no proxy — "none" is
    itself the news when CCF has gone away.
    """
    path = Path(certdir) / _UPSTREAM_FILE
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps({"proxy": value or ""}))
        tmp.replace(path)
    except OSError:
        pass


_WIRE_KEYS = ("HTTPS_PROXY", "https_proxy", "NODE_EXTRA_CA_CERTS")
_WIRE_MARK = "_cswapPinWiredKeys"


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
    from claude_swap.paths import get_global_config_path

    path = get_global_config_path()
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
        proxy = f"http://127.0.0.1:{port}"
        wanted = {
            "HTTPS_PROXY": proxy,
            "https_proxy": proxy,
            "NODE_EXTRA_CA_CERTS": str(ca_path),
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


def _ambient_proxy(env: dict[str, str] | None = None) -> str | None:
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
        return _wired_over_proxy(src)
    host, port = parsed
    if host in _LOOPBACK and port == _self_port(src):
        return _wired_over_proxy(src)
    return value


def _wired_over_proxy(env: dict[str, str]) -> str | None:
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
    if not isinstance(saved, dict):
        return None
    value = saved.get("HTTPS_PROXY") or saved.get("https_proxy")
    return value or None


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


def make_pin_token_provider(switcher, account_num: str, email: str):
    """Build the ``pin_token_provider`` callable for :class:`PinProxy`.

    Reads the pinned account's credential from cswap's backup store and
    returns a live access token, refreshing (and persisting the rotation back
    to the store) when expired. Returns ``None`` — meaning "leave the
    request's bearer alone" — when the pinned account is currently the ACTIVE
    account (its live credential is already on disk and owned by the client;
    the backup copy may be stale) or when no usable token can be produced.

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

    def provider() -> str | None:
        if switcher.current_account_number() == account_num:
            return None
        creds = switcher.read_account_credentials(account_num, email)
        if not creds:
            return None
        token = _live_token(creds)
        if token:
            return token  # common path: no lock, no network

        with refresh_lock:
            # Someone may have rotated it while we waited — re-read and reuse.
            creds = switcher.read_account_credentials(account_num, email) or creds
            token = _live_token(creds)
            if token:
                return token
            token, rotated = resolve_pin_token(
                creds, oauth.try_refresh_oauth_credentials
            )
            if rotated:
                switcher.persist_backup_credentials(account_num, email, rotated)
            return token

    return provider


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
    # CCF, a CCF that moved ports, or a CCF that went away entirely.
    write_upstream_hint(certdir, _ambient_proxy())
    fp = daemon_fingerprint(account_num, email)

    ca = certdir / "ca.pem"

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
            _kill_daemon(int(stale["pid"]))
        port = _spawn_daemon(account_num, email, certdir)
        if port is None:
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


def refcount_fifo_path(certdir: Path) -> Path:
    """Path of the refcount FIFO. Sessions hold a write fd on it; the daemon
    reads it and exits when the last holder closes (CCF's FIFO refcount)."""
    return Path(certdir) / _FIFO_NAME


def watch_refcount(fifo: str | Path, on_last_holder_gone) -> None:
    """Block on ``fifo`` until every write-holder closes, then call
    ``on_last_holder_gone``. This is exactly CCF's supervisor `cat FIFO`:
    a READ-ONLY open blocks until the first writer appears, and the subsequent
    read returns EOF (b"") only once all writer fds have closed. A read-only
    reader must NOT also hold a write end (that would mask EOF), which is why
    sessions open O_RDWR while the daemon opens read-only here.
    """
    fd = os.open(str(fifo), os.O_RDONLY)  # blocks until the first holder attaches
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


def daemon_fingerprint(account_num: str, email: str) -> str:
    """Identity of the daemon config: pinned account + the proxy code's own
    mtime. A change in either (repin, or a redeploy of pin_proxy.py) makes a
    running daemon stale so the launcher recycles it — mirrors CCF's
    fingerprint staleness (cachefix-ensure)."""
    import hashlib

    try:
        code_mtime = os.stat(__file__).st_mtime_ns
    except OSError:
        code_mtime = 0
    raw = f"{account_num}\0{email}\0{code_mtime}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


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
    subprocess.Popen(
        [sys.executable, "-m", "claude_swap.pin_proxy", account_num, email, str(certdir)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
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
    ``upstream.json`` (CCF, corp, or none), re-read per connection so a CCF
    that restarts on another port is followed rather than bypassed. Records
    ``proxy.json`` (port/pid/fingerprint) once listening, serves a ``/health``
    probe, and self-terminates when the last refcount holder closes the FIFO
    (idle teardown).
    """
    from claude_swap.switcher import ClaudeAccountSwitcher

    certdir = Path(certdir)
    switcher = ClaudeAccountSwitcher()
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
    certdir: Path,
    open_refcount: bool = True,
) -> dict[str, str]:
    """Return a copy of ``env`` routed through the pin proxy.

    Sets ``HTTPS_PROXY``/``https_proxy`` to the proxy and makes Node trust our
    MITM CA. Node's ``NODE_EXTRA_CA_CERTS`` takes exactly one file, so when the
    session already trusts another CA (CCF, corp) the two PEMs are merged into
    ``certdir/ca-bundle.pem`` — never replaced.

    ``open_refcount`` controls the refcount holder. In-process callers
    (session.py, which execs claude and hands off its own fds) pass True: we
    open an inheritable write fd on the FIFO here so the exec'd claude keeps it.
    The shell path (pin-env) passes False — the SHELL must open the fd (this
    process exits immediately, so a fd we opened would close and tear the daemon
    down at once); pin-env emits the `exec {fd}<>fifo` for the shell instead.
    """
    out = dict(env)
    proxy = f"http://127.0.0.1:{port}"
    out["HTTPS_PROXY"] = proxy
    out["https_proxy"] = proxy
    # Marks this env as already pinned, so a nested launch records the proxy
    # we chain THROUGH as upstream rather than us (see _ambient_proxy).
    out["CSWAP_PIN_PORT"] = str(port)
    existing = env.get("NODE_EXTRA_CA_CERTS")
    if existing and Path(existing) != ca_path:
        bundle = Path(certdir) / "ca-bundle.pem"
        try:
            bundle.write_bytes(
                Path(ca_path).read_bytes() + Path(existing).read_bytes()
            )
            out["NODE_EXTRA_CA_CERTS"] = str(bundle)
        except OSError:
            out["NODE_EXTRA_CA_CERTS"] = str(ca_path)
    else:
        out["NODE_EXTRA_CA_CERTS"] = str(ca_path)

    # Attach this launch as a refcount holder: open a write fd on the FIFO and
    # mark it inheritable so the exec'd claude keeps it open for its lifetime.
    # The daemon's reader sees EOF only when every such fd closes → idle
    # teardown. O_RDWR so the open never blocks even if the daemon died.
    fifo = refcount_fifo_path(certdir)
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
        # A proxy to CONNECT through for egress (CCF 9901, corp proxy). Fixed
        # when rediscover_chain is False (tests); otherwise re-read from the
        # on-disk hint per connection, so the daemon follows a CCF that moved.
        self._chain = chain_proxy
        self._rediscover_chain = rediscover_chain
        self._host = host
        self._bundle = ensure_ca(self._certdir, UPSTREAM_HOST)
        self._server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._server_ctx.load_cert_chain(
            str(self._bundle.leaf_path), str(self._bundle.leaf_key_path)
        )
        self._srv: socket.socket | None = None
        # Per-connection upstream socket. Each MITM connection is served on
        # its own thread, so a thread-local keeps one upstream per client.
        self._local = threading.local()
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
        try:
            line = _read_line(conn)
            if not line:
                conn.close()
                return
            parts = line.split(" ")
            if parts[0] == "CONNECT":
                target = parts[1]  # host:port
                # Drain the rest of the CONNECT headers.
                while True:
                    h = _read_line(conn)
                    if h in ("", None):
                        break
                host = target.rsplit(":", 1)[0]
                if host != UPSTREAM_HOST:
                    self._blind_tunnel(target, conn)
                    return
                self._mitm(conn)
                return
            if len(parts) >= 2 and parts[1].startswith("/health"):
                # Local health probe (origin-form GET /health to our own port).
                # Lets a statusline/cc-update probe tell the pin proxy apart
                # from CCF and read the chain it forwards to.
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

    def _serve_health(self, conn: socket.socket) -> None:
        import json

        chain = f"{self._chain[0]}:{self._chain[1]}" if self._chain else None
        body = json.dumps({"pin_proxy": True, "port": self.port, "chain": chain})
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
        while True:
            h = _read_line(conn)
            if h in ("", None):
                break
            headers.append(h)
        split = urlsplit(url)
        host, port = split.hostname, split.port or 80
        try:
            if self._chain:
                up = socket.create_connection(self._chain, timeout=15)
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
        method, path = _split_request_line(request_line)
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
        if self._debug:
            hdrs = " | ".join(
                f"{k}: {v[:60]}" for k, v in headers
                if k.lower() in (
                    "connection", "upgrade", "accept", "sec-websocket-key",
                    "sec-websocket-version", "cache-control", "content-type",
                )
            )
            self._debug.write(
                f"{method} {path} pinned={pinned} swapped={swapped} :: {hdrs}\n"
            )
            self._debug.flush()

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
            return _relay_response(up, client)
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

        When we chain through a LOOPBACK proxy (CCF, or any local MITM), that
        hop re-signs api.anthropic.com with its own CA whose path we can't know
        portably — and it terminates on localhost, having itself verified the
        real upstream. So we skip cert verification for a loopback chain,
        exactly as the real client (Node) does by trusting the CCF CA blindly.
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

        Not a snapshot: CCF picks its port from a family (9901 + a walk range)
        and can be restarted, or come up only after this daemon did. Binding
        the chain once at spawn would leave the daemon bypassing CCF — with a
        corporate proxy behind it, that is a hard egress failure, not a
        performance note. ``rediscover_chain=False`` keeps tests explicit.
        """
        if not self._rediscover_chain:
            return self._chain
        return read_upstream_hint(self._certdir)

    def _connect_upstream(self) -> socket.socket:
        chain = self._current_chain()
        if chain:
            raw = socket.create_connection(chain, timeout=15)
            raw.sendall(
                f"CONNECT {self._upstream[0]}:{self._upstream[1]} HTTP/1.1\r\n"
                f"Host: {self._upstream[0]}:{self._upstream[1]}\r\n\r\n".encode("latin1")
            )
            status = _read_line(raw)
            while True:
                h = _read_line(raw)
                if h in ("", None):
                    break
            if not status or " 200" not in status:
                raw.close()
                raise OSError(f"upstream CONNECT failed: {status}")
            return raw
        return socket.create_connection(self._upstream, timeout=15)

    def _blind_tunnel(self, target: str, conn: socket.socket) -> None:
        host, _, port_s = target.rpartition(":")
        port = int(port_s) if port_s else 443
        chain = self._current_chain()
        try:
            if chain:
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
                    up.close()
                    conn.close()
                    return
            else:
                up = socket.create_connection((host, port), timeout=15)
        except OSError:
            conn.close()
            return
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


def _split_request_line(line: str) -> tuple[str, str]:
    parts = line.split(" ")
    return parts[0], parts[1] if len(parts) > 1 else "/"


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


def _relay_response(up: ssl.SSLSocket, client: ssl.SSLSocket) -> bool:
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
        _TRACE.write(f"    <- {status_line.decode('latin1', 'replace')}\n")
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
