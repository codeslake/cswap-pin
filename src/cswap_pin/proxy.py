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
