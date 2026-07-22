"""Account-pin proxy.

A local MITM forward proxy that swaps the ``Authorization`` bearer to a pinned
account's token on the Remote-Control and Artifact routes, so those operations
stay on one account while inference follows whatever cswap has swapped onto
disk. Everything else (inference at ``/v1/messages``, OAuth, telemetry, …) is
relayed untouched, and non-anthropic hosts are blind-tunnelled.
"""

from __future__ import annotations

import datetime as _dt
import os
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


def is_pinned_route(path: str) -> bool:
    """Whether a request path's bearer must be swapped to the pinned account.

    True for the routes whose server-side ownership is set by the bearer and
    that we want pinned — Remote-Control code sessions and Artifact ("frame")
    deploys. False for everything else, most importantly ``/v1/messages`` (which
    must keep billing the currently-swapped inference account).
    """
    return path.startswith("/v1/code/sessions") or path.startswith("/api/frame/")


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
        _write_pem(ca_pem, ca_cert.public_bytes(serialization.Encoding.PEM))
        _write_key(ca_key, ca_priv)

    if not (leaf_pem.exists() and leaf_key.exists()):
        leaf_cert, leaf_priv = _make_leaf(host, ca_cert, ca_priv)
        _write_pem(leaf_pem, leaf_cert.public_bytes(serialization.Encoding.PEM))
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


def _write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)


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


def swap_authorization(headers: dict[str, str], pin_token: str) -> dict[str, str]:
    """Return ``headers`` with the ``Authorization`` bearer replaced by the pin.

    Only the Authorization value changes; every other header is preserved.
    """
    out = dict(headers)
    for name in out:
        if name.lower() == "authorization":
            out[name] = f"Bearer {pin_token}"
    return out


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
    """

    def provider() -> str | None:
        if switcher.current_account_number() == account_num:
            return None
        creds = switcher.read_account_credentials(account_num, email)
        if not creds:
            return None
        token, rotated = resolve_pin_token(creds, oauth.try_refresh_oauth_credentials)
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
    port = _read_alive_port(certdir)
    if port is None:
        port = _spawn_daemon(account_num, email, certdir)
        if port is None:
            return None
    return port, certdir / "ca.pem"


def _read_alive_port(certdir: Path) -> int | None:
    """Port of a live recorded daemon, else None. File format: ``port pid``."""
    try:
        port_s, pid_s = (certdir / "proxy.port").read_text().split()
        port, pid = int(port_s), int(pid_s)
        os.kill(pid, 0)  # raises if the pid is gone
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return port
    except (OSError, ValueError):
        return None


def _spawn_daemon(account_num: str, email: str, certdir: Path) -> int | None:
    """Start the proxy daemon detached; wait for its port file. None on failure."""
    import subprocess
    import sys
    import time

    port_file = certdir / "proxy.port"
    try:
        port_file.unlink()
    except FileNotFoundError:
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
            return port
        time.sleep(0.1)
    return None


def daemon_main(account_num: str, email: str, certdir: Path) -> None:
    """Entry point for the detached proxy process (``-m claude_swap.pin_proxy``).

    Chains to whatever HTTPS_PROXY was in cswap's environment (CCF, corp, or
    none) and serves until killed. Writes ``proxy.port`` once listening.
    """
    from claude_swap.switcher import ClaudeAccountSwitcher

    switcher = ClaudeAccountSwitcher()
    proxy = PinProxy(
        certdir=certdir,
        pin_token_provider=make_pin_token_provider(switcher, account_num, email),
        chain_proxy=parse_upstream_proxy(
            os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        ),
    )
    proxy.start()
    (certdir / "proxy.port").write_text(f"{proxy.port} {os.getpid()}")
    threading.Event().wait()  # serve forever; lifecycle is kill-based


def wire_env(
    env: dict[str, str], port: int, ca_path: Path, certdir: Path
) -> dict[str, str]:
    """Return a copy of ``env`` routed through the pin proxy.

    Sets ``HTTPS_PROXY``/``https_proxy`` to the proxy and makes Node trust our
    MITM CA. Node's ``NODE_EXTRA_CA_CERTS`` takes exactly one file, so when the
    session already trusts another CA (CCF, corp) the two PEMs are merged into
    ``certdir/ca-bundle.pem`` — never replaced.
    """
    out = dict(env)
    proxy = f"http://127.0.0.1:{port}"
    out["HTTPS_PROXY"] = proxy
    out["https_proxy"] = proxy
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
    ):
        self._certdir = Path(certdir)
        self._pin_token_provider = pin_token_provider
        # Where the MITM'd anthropic request is really sent. Defaults to the
        # real upstream; tests point it at a fake server.
        self._upstream = upstream or (UPSTREAM_HOST, UPSTREAM_PORT)
        # A proxy to CONNECT through for egress (CCF 9901, corp proxy).
        self._chain = chain_proxy
        self._host = host
        self._bundle = ensure_ca(self._certdir, UPSTREAM_HOST)
        self._server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._server_ctx.load_cert_chain(
            str(self._bundle.leaf_path), str(self._bundle.leaf_key_path)
        )
        self._srv: socket.socket | None = None
        self._stop = False
        self.port = 0

    def start(self) -> None:
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self._host, 0))
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
            if parts[0] != "CONNECT":
                conn.close()
                return
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
        except Exception:
            try:
                conn.close()
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
            try:
                tls.close()
            except OSError:
                pass

    def _handle_one_request(self, tls: ssl.SSLSocket) -> bool:
        request_line = _read_line(tls)
        if not request_line:
            return False
        method, path, _ = _split_request_line(request_line)
        headers: list[tuple[str, str]] = []
        while True:
            h = _read_line(tls)
            if h in ("", None):
                break
            if ":" in h:
                k, v = h.split(":", 1)
                headers.append((k.strip(), v.strip()))
        body = _read_body(tls, headers)

        if is_pinned_route(path):
            token = self._pin_token_provider()
            if token:
                headers = [
                    (k, f"Bearer {token}") if k.lower() == "authorization" else (k, v)
                    for k, v in headers
                ]

        status_line, resp_headers, resp_body = self._forward(method, path, headers, body)
        tls.sendall(status_line + b"\r\n")
        for k, v in resp_headers:
            tls.sendall(f"{k}: {v}\r\n".encode("latin1"))
        tls.sendall(b"\r\n")
        if resp_body:
            tls.sendall(resp_body)
        # Simplify: one request per MITM connection (Connection: close).
        return False

    def _forward(self, method, path, headers, body):
        raw = self._connect_upstream()
        ctx = ssl.create_default_context(cafile=str(self._bundle.ca_path))
        # The fake upstream (and the real one) present a cert for
        # api.anthropic.com; validate against our CA (which signed the fake's
        # leaf) — for the real upstream this is the system trust path instead.
        try:
            up = ctx.wrap_socket(raw, server_hostname=UPSTREAM_HOST)
        except ssl.SSLError:
            ctx2 = ssl.create_default_context()
            up = ctx2.wrap_socket(raw, server_hostname=UPSTREAM_HOST)
        try:
            out = [f"{method} {path} HTTP/1.1".encode("latin1")]
            sent_host = False
            for k, v in headers:
                kl = k.lower()
                if kl in _HOP_BY_HOP or kl.startswith("proxy-"):
                    continue
                if kl == "host":
                    v = UPSTREAM_HOST
                    sent_host = True
                out.append(f"{k}: {v}".encode("latin1"))
            if not sent_host:
                out.append(f"Host: {UPSTREAM_HOST}".encode("latin1"))
            out.append(b"Connection: close")
            up.sendall(b"\r\n".join(out) + b"\r\n\r\n" + (body or b""))
            resp = _read_all(up)
        finally:
            up.close()
        return _parse_response(resp)

    def _connect_upstream(self) -> socket.socket:
        chain = self._chain
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
        try:
            if self._chain:
                up = socket.create_connection(self._chain, timeout=15)
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


def _split_request_line(line: str) -> tuple[str, str, str]:
    parts = line.split(" ")
    if len(parts) < 3:
        return parts[0], parts[1] if len(parts) > 1 else "/", "HTTP/1.1"
    return parts[0], parts[1], parts[2]


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


def _read_all(sock) -> bytes:
    data = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
        except (ConnectionResetError, ssl.SSLError, OSError):
            # A peer that sends Content-Length then closes can surface as an
            # abrupt reset rather than a clean EOF; treat what we have as the
            # full response.
            break
        if not chunk:
            break
        data += chunk
    return bytes(data)


def _parse_response(raw: bytes):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0] if lines else b"HTTP/1.1 502 Bad Gateway"
    headers = []
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            kl = k.strip().lower()
            if kl in _HOP_BY_HOP:
                continue
            headers.append((k.strip().decode("latin1"), v.strip().decode("latin1")))
    return status_line, headers, body


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
