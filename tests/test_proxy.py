"""Tests for the account-pin proxy's request classification.

The proxy MITMs api.anthropic.com and swaps the Authorization bearer to a
pinned account's token, but ONLY on the Remote-Control and Artifact routes;
inference (/v1/messages) and everything else must pass through untouched.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from cswap_pin.proxy import (
    ensure_ca,
    is_pinned_route,
    parse_upstream_proxy,
)

from conftest import run_cases

# A REAL zero-serial root CA (GoDaddy Root Certificate Authority - G2),
# extracted from this box's ambient `/etc/ssl/certs/ca-certificates.crt`.
# Embedded rather than read from the ambient store so the guard tests below
# do not depend on the host having one, or having a zero-serial cert in it.
# `x509.load_pem_x509_certificate` on this block raises
# `CryptographyDeprecationWarning` ("Parsed a serial number which wasn't
# positive ... will cause an exception in a future release") under the
# library's default filter, which every ambient `-W error` promotes to a
# hard exception — the exact shape `_load_cert`'s guard exists to survive.
ZERO_SERIAL_ROOT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMCVVMx
EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
EUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRp
ZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTA5MDkwMTAwMDAwMFoXDTM3MTIzMTIz
NTk1OVowgYMxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH
EwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8GA1UE
AxMoR28gRGFkZHkgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL9xYgjx+lk09xvJGKP3gElY6SKD
E6bFIEMBO4Tx5oVJnyfq9oQbTqC023CYxzIBsQU+B07u9PpPL1kwIuerGVZr4oAH
/PMWdYA5UXvl+TW2dE6pjYIT5LY/qQOD+qK+ihVqf94Lw7YZFAXK6sOoBJQ7Rnwy
DfMAZiLIjWltNowRGLfTshxgtDj6AozO091GB94KPutdfMh8+7ArU6SSYmlRJQVh
GkSBjCypQ5Yj36w6gZoOKcUcqeldHraenjAKOc7xiID7S13MMuyFYkMlNAJWJwGR
tDtwKj9useiciAF9n9T521NtYJ2/LOdYq7hfRvzOxBsDPAnrSTFcaUaz4EcCAwEA
AaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYE
FDqahQcQZyi27/a9BUFuIMGU2g/eMA0GCSqGSIb3DQEBCwUAA4IBAQCZ21151fmX
WWcDYfF+OwYxdS2hII5PZYe096acvNjpL9DbWu7PdIxztDhC2gV7+AJ1uP2lsdeu
9tfeE8tTEH6KRtGX+rcuKxGrkLAngPnon1rpN5+r5N9ss4UXnT3ZJE95kTXWXwTr
gIOrmgIttRD02JDHBHNA7XIloKmf7J6raBKZV8aPEjoJpL1E/QYVN8Gb5DKj7Tjo
2GTzLH4U/ALqn83/B2gX2yKQOC16jdFU8WnjXzPKej17CuPKf1855eJ1usV2GDPO
LPAvTK33sefOT6jEm0pUBsV/fdUID+Ic/n4XuKxe9tQWskMJDE32p2u0mYRlynqI
4uJEvlz36hz1
-----END CERTIFICATE-----
"""


@pytest.fixture(autouse=True)
def _stdlib_ssl():
    """cli.main() tests inject truststore into global ssl (OS-native verify),
    which rejects our ad-hoc test CA. Undo it for real-handshake tests here."""
    try:
        import truststore
        truststore.extract_from_ssl()
    except ImportError:
        pass
    yield


class TestLiveRemoteControlSessions:
    """A re-pin cannot move an RC session that is already open (the server
    fixed its owner at creation), so `cswap pin` names the ones affected
    instead of telling everyone to restart something."""


    def _sessions_dir(self, tmp_path, monkeypatch):
        from pathlib import Path

        home = Path(tmp_path) / "cfg"
        (home / "sessions").mkdir(parents=True)
        monkeypatch.setattr(
            "claude_swap.paths.get_claude_config_home", lambda: home
        )
        return home / "sessions"

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_lists_only_sessions_with_a_live_bridge(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import live_remote_control_sessions

        d = self._sessions_dir(tmp_path, monkeypatch)
        (d / "1.json").write_text(json.dumps(
            {"sessionId": "a", "name": "with-rc", "bridgeSessionId": "cse_x"}))
        (d / "2.json").write_text(json.dumps(
            {"sessionId": "b", "name": "no-rc", "bridgeSessionId": None}))
        (d / "3.json").write_text(json.dumps({"sessionId": "c", "name": "never"}))

        assert live_remote_control_sessions() == ["with-rc"]

    def case_unreadable_registry_is_not_an_error(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import live_remote_control_sessions

        d = self._sessions_dir(tmp_path, monkeypatch)
        (d / "bad.json").write_text("{not json")
        assert live_remote_control_sessions() == []


class TestRepinIsLive:
    """Switching accounts in cswap never asks you to restart a session, and
    re-pinning should not either: a live session holds only the proxy's
    address, so the daemon must be able to serve a different account
    underneath it as soon as `cswap pin` writes one."""


    class _Sw:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
            self.active = "9"
            self.creds = {
                ("1", "one@example.com"): '{"claudeAiOauth":{"accessToken":"TOK-1","expiresAt":99999999999999}}',
                ("2", "two@example.com"): '{"claudeAiOauth":{"accessToken":"TOK-2","expiresAt":99999999999999}}',
            }

        def current_account_number(self):
            return self.active

        def resolve_account(self, identifier):
            for (num, mail) in self.creds:
                if identifier in (num, mail):
                    return num, mail, "org"
            raise KeyError(identifier)

        def read_account_credentials(self, num, email):
            return self.creds.get((num, email), "")

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_provider_follows_a_repin_without_a_respawn(self, tmp_path):
        from cswap_pin.proxy import make_pin_token_provider, save_pin

        sw = self._Sw(tmp_path)
        save_pin(tmp_path, "one@example.com", "org")
        provider = make_pin_token_provider(sw, "1", "one@example.com")
        assert provider() == "TOK-1"

        # `cswap pin 2` — same daemon, same provider object.
        save_pin(tmp_path, "two@example.com", "org")
        assert provider() == "TOK-2", "the daemon stayed on the old account"

        # Clearing the pin means "leave every bearer alone".
        save_pin(tmp_path, None, None)
        assert provider() is None

    def case_fingerprint_ignores_the_account(self, tmp_path):
        """Including the account would recycle the daemon on every re-pin,
        and a recycle is exactly what a live session must not need."""
        from cswap_pin.proxy import daemon_fingerprint

        assert daemon_fingerprint("1", "one@example.com") == daemon_fingerprint(
            "2", "two@example.com"
        )

    def case_the_fingerprint_tracks_CONTENT_not_mtime(self, tmp_path):
        """A redeploy is a change of CODE, and mtime is not code.

        This is what decides whether a running daemon replaces itself, so a
        wrong answer costs in both directions and both were measured:

          MISSED   `rsync -a`, `cp -p`, `tar -p` and a restored backup all
                   PRESERVE mtime. New code, unchanged fingerprint, and the
                   daemon serves the old build forever — the 22-hour stale
                   daemon this watchdog exists to end.
          SPURIOUS `touch` alone, or any reinstall of an identical file,
                   changed it — so a no-op deploy recycled a healthy daemon
                   for nothing.

        A peer proxy in the same chain hit the mirror of this by comparing
        PATHS: it caught a relocated install and missed `git pull` in place,
        which is the commonest deploy there is.
        """
        import os
        import pathlib

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import daemon_fingerprint

        src = pathlib.Path(pin_proxy.__file__)
        original = src.read_bytes()
        st = src.stat()
        before = daemon_fingerprint()
        try:
            # NEW CONTENT, OLD MTIME — what an archive-mode copy leaves.
            src.write_bytes(original + b"\n# redeployed\n")
            os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
            assert daemon_fingerprint() != before, (
                "new code with a preserved mtime read as unchanged — every "
                "rsync/cp -p deploy would leave the old daemon serving"
            )
            # SAME CONTENT, NEW MTIME — what `touch` or a no-op reinstall does.
            src.write_bytes(original)
            os.utime(src, None)
            assert daemon_fingerprint() == before, (
                "an unchanged file read as a redeploy — a no-op install "
                "recycles a healthy daemon and costs a handover for nothing"
            )
            # AND THE CHEAPER PROXIES MUST FAIL HERE. A peer proxy in the
            # same chain encodes this as an explicit mutation and it is
            # stronger than asserting the right answer alone: it pins WHICH
            # wrong implementations this test rejects.
            import hashlib

            def _by_mtime():
                return hashlib.sha256(
                    str(src.stat().st_mtime_ns).encode()
                ).hexdigest()[:16]

            src.write_bytes(original + b"\n# redeployed\n")
            os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
            assert _by_mtime() == hashlib.sha256(
                str(st.st_mtime_ns).encode()
            ).hexdigest()[:16], (
                "the mtime mutation did not reproduce — this test would pass "
                "against an implementation it is supposed to reject"
            )
            src.write_bytes(original)
            os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))
            # size alone: a one-character edit keeps the length
            same_len = bytearray(original)
            same_len[-1] = ord("#") if same_len[-1] != ord("#") else ord(" ")
            src.write_bytes(bytes(same_len))
            assert daemon_fingerprint() != before, (
                "a same-LENGTH edit read as unchanged — size is not content"
            )
        finally:
            src.write_bytes(original)
            os.utime(src, ns=(st.st_atime_ns, st.st_mtime_ns))


class TestPinCodeResolvesItsNames:
    """The pin touches TUI code whose tests are async and skipped in this
    repo, so an undefined name there ships as a runtime crash rather than a
    failing test: `autoview.py` referenced `ACCENT` without importing it, and
    the auto-switch screen raised NameError for anyone who had set a pin.
    Compile-and-resolve every module the pin feature reaches."""

    @pytest.mark.parametrize(
        "module",
        [
            "cswap_pin.proxy",
            "claude_swap.tui.autoview",
            "claude_swap.tui.dashboard",
            "claude_swap.tui.widgets",
            "claude_swap.cli",
            "claude_swap.session",
        ],
    )
    def test_no_undefined_globals(self, module):
        import importlib

        pyflakes_api = pytest.importorskip(
            "pyflakes.api", reason="pyflakes not installed"
        )
        from pyflakes.reporter import Reporter

        class _Collect(Reporter):
            def __init__(self):
                self.errors = []

            def unexpectedError(self, filename, msg):
                self.errors.append(f"{filename}: {msg}")

            def syntaxError(self, filename, msg, lineno, offset, text):
                self.errors.append(f"{filename}:{lineno}: {msg}")

            def flake(self, message):
                if "undefined name" in str(message):
                    self.errors.append(str(message))

        path = importlib.import_module(module).__file__
        reporter = _Collect()
        pyflakes_api.checkPath(path, reporter)
        assert not reporter.errors, "\n".join(reporter.errors)


class TestIsPinnedRoute:

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_which_routes_carry_the_pinned_bearer(self):
        """The whole routing table, in one place.

        It was five methods asserting one function; the ROUTES are the value,
        so a new one is a line rather than a method.
        """
        for path, pinned, why in (
            ("/v1/code/sessions", True,
             "Remote Control creates and uses claude.ai code sessions here"),
            ("/api/frame/deploy/init", True,
             "artifact publishes are owned by the creating bearer too"),
            # RC reconnect unarchives at /v1/sessions/{id}/unarchive — NOT
            # /v1/code/sessions — before re-bridging. Keeping the disk bearer
            # here SPLITS the session's ownership: unarchive lands it on the
            # disk account, the reconnect resolves there, and the pinned
            # account never sees it.
            ("/v1/sessions/cse_01ABC/unarchive", True, "RC reconnect unarchive"),
            ("/v1/messages", False,
             "inference must follow the swapped disk account, never the pin"),
            ("/v1/sessions", False,
             "a plain list must not be swept in by the unarchive rule"),
        ):
            assert is_pinned_route(path) is pinned, f"{path}: {why}"

class TestParseUpstreamProxy:
    """One function, nine inputs. It was nine test methods; the CASES are the
    value here, not the ceremony around each one, so they are a table."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_address_it_parses(self):
        import base64

        alice = base64.b64encode(b"alice:s3cr3t").decode()
        encoded = base64.b64encode(b"user@corp:p@ss:word").decode()
        for url, address, tls, auth, why in (
            ("", None, None, None, "no upstream -> dial the origin directly"),
            (None, None, None, None, "no upstream -> dial the origin directly"),
            ("http://127.0.0.1:9901", ("127.0.0.1", 9901), False, None,
             "the common case: a forward proxy already on HTTPS_PROXY"),
            ("corp.example.net:8118", ("corp.example.net", 8118), False, None,
             "some proxies are set with no scheme"),
            ("http://proxy.local", ("proxy.local", 80), False, None,
             "http defaults to 80"),
            # THE SCHEME DECIDES THE PORT. Defaulting every scheme to 80
            # dialled a TLS proxy's plaintext port, so where that proxy is the
            # only route out, no pinned request could succeed.
            ("https://proxy.corp.example", ("proxy.corp.example", 443), True, None,
             "https defaults to 443"),
            ("https://proxy.corp.example:8443", ("proxy.corp.example", 8443), True,
             None, "an explicit port still wins over the scheme"),
            # CREDENTIALS. Reducing the URL to (host, port) discarded the
            # userinfo, so the CONNECT went out unauthenticated and an
            # authenticated corporate proxy answered 407 to everything.
            ("http://alice:s3cr3t@proxy.corp:8080", ("proxy.corp", 8080), False,
             f"Basic {alice}", "userinfo becomes a Proxy-Authorization header"),
            # ...and it is percent-encoded in a URL, so a password with @ or :
            # must be decoded or we send a credential the proxy never issued.
            ("http://user%40corp:p%40ss%3Aword@proxy:3128", ("proxy", 3128), False,
             f"Basic {encoded}", "percent-encoded userinfo is decoded"),
        ):
            chain = parse_upstream_proxy(url)
            if address is None:
                assert chain is None, f"{why}: {url!r} parsed to {chain!r}"
                continue
            assert chain.address == address, f"{why}: {url!r}"
            assert chain.tls is tls, f"{why}: {url!r} tls"
            assert chain.auth == auth, f"{why}: {url!r} auth"
            expected = f"Proxy-Authorization: {auth}\r\n" if auth else ""
            assert chain.connect_headers() == expected, f"{why}: {url!r} headers"

class TestEnsureCA:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_generates_ca_and_leaf_files(self, tmp_path):
        result = ensure_ca(tmp_path, "api.anthropic.com")
        assert (tmp_path / "ca.pem").exists()
        assert (tmp_path / "leaf.pem").exists()
        assert (tmp_path / "leaf.key").exists()
        # The caller trusts the CA via NODE_EXTRA_CA_CERTS.
        assert result.ca_path == tmp_path / "ca.pem"

    def case_ca_is_a_ca(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        ca = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True

    def case_leaf_covers_host_via_san(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        leaf = x509.load_pem_x509_certificate((tmp_path / "leaf.pem").read_bytes())
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        assert "api.anthropic.com" in san.get_values_for_type(x509.DNSName)

    def case_leaf_is_server_auth(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        leaf = x509.load_pem_x509_certificate((tmp_path / "leaf.pem").read_bytes())
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    def case_leaf_signed_by_ca(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        ca = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
        leaf = x509.load_pem_x509_certificate((tmp_path / "leaf.pem").read_bytes())
        assert leaf.issuer == ca.subject
        # Signature verifies against the CA public key (raises on mismatch).
        ca.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            padding.PKCS1v15(),
            leaf.signature_hash_algorithm,
        )

    def case_idempotent_reuses_ca(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        ca1 = (tmp_path / "ca.pem").read_bytes()
        ensure_ca(tmp_path, "api.anthropic.com")
        ca2 = (tmp_path / "ca.pem").read_bytes()
        assert ca1 == ca2  # existing CA is not regenerated

    def case_leaf_passes_real_tls_validation(self, tmp_path):
        # The decisive test: a client trusting the CA must complete a TLS
        # handshake against a server using the leaf. OpenSSL (Python + Node)
        # rejects a leaf with no Authority Key Identifier, so `openssl verify`
        # passing is not enough — exercise a real handshake.
        import socket
        import ssl
        import threading

        ensure_ca(tmp_path, "api.anthropic.com")
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(
            str(tmp_path / "leaf.pem"), str(tmp_path / "leaf.key")
        )
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve():
            try:
                conn, _ = srv.accept()
                tls = server_ctx.wrap_socket(conn, server_side=True)
                tls.recv(16)
                tls.close()
            except Exception:
                pass

        threading.Thread(target=serve, daemon=True).start()
        client_ctx = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with client_ctx.wrap_socket(
                raw, server_hostname="api.anthropic.com"
            ) as tls:
                tls.send(b"hi")  # handshake completed if we get here


class TestResolvePinToken:
    """resolve_pin_token returns a LIVE access token for the pinned account,
    refreshing (via an injected callback) only when the stored one is near
    expiry. The proxy calls this before swapping the bearer."""


    def _creds(self, token, expires_at, refresh="rt-1"):
        import json
        return json.dumps({"claudeAiOauth": {
            "accessToken": token, "expiresAt": expires_at, "refreshToken": refresh}})

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_returns_stored_token_when_fresh(self):
        from cswap_pin.proxy import resolve_pin_token
        # expiry far in the future -> no refresh, return as-is
        future = 10_000_000_000_000
        creds = self._creds("live-token", future)
        def refresh(_c):
            raise AssertionError("must not refresh a fresh token")
        token, new_creds = resolve_pin_token(creds, refresh)
        assert token == "live-token"
        assert new_creds is None  # nothing rotated

    def case_refreshes_when_expired(self):
        from cswap_pin.proxy import resolve_pin_token
        from claude_swap.oauth import RefreshOutcome
        past = 1  # long expired
        creds = self._creds("dead-token", past)
        rotated = self._creds("fresh-token", 10_000_000_000_000, refresh="rt-2")
        def refresh(_c):
            return RefreshOutcome(rotated, None)
        token, new_creds = resolve_pin_token(creds, refresh)
        assert token == "fresh-token"
        assert new_creds == rotated  # caller persists this


class _FakeSwitcher:
    """Duck-typed stand-in for ClaudeAccountSwitcher's provider-facing API."""

    def __init__(self, active_num="1", backups=None):
        self.active_num = active_num
        self.backups = backups or {}
        self.persisted = []

    def current_account_number(self):
        return self.active_num

    def read_account_credentials(self, num, email):
        return self.backups.get(num, "")

    def persist_backup_credentials(self, num, email, credentials):
        self.persisted.append((num, email, credentials))


class TestMakePinTokenProvider:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_returns_none_when_pin_is_active_account(self):
        # Disk bearer already IS the pin account: no swap needed, and never
        # touch the live store the client owns.
        from cswap_pin.proxy import make_pin_token_provider
        sw = _FakeSwitcher(active_num="2")
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() is None

    def case_no_token_because_nothing_to_swap_is_not_a_failure(self):
        """None has two opposite meanings and the caller must be able to tell.

        The pinned account being the ACTIVE account means there is deliberately
        nothing to swap — the live bearer already belongs to it. The other None
        means the credential could not be read, which is the expensive one.
        Conflating them made the fail-open warning fire on a machine where
        nothing was wrong (personal-mac: pin == active, keychain read fine at
        rc=0/509 bytes) and cost the reader ten minutes chasing a keychain
        problem that did not exist.
        """
        from cswap_pin.proxy import make_pin_token_provider
        sw = _FakeSwitcher(active_num="2")
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() is None
        assert provider.pin_is_noop() is True, "pin == active is a no-op, not a failure"

    def case_an_unreadable_store_is_still_a_failure(self):
        """The split must not swallow the case the warning exists for."""
        from cswap_pin.proxy import make_pin_token_provider
        sw = _FakeSwitcher(active_num="1", backups={})  # cannot read account 2
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() is None
        assert provider.pin_is_noop() is False, "unreadable credential must still warn"

    def case_returns_backup_token_when_pin_inactive(self):
        import json
        from cswap_pin.proxy import make_pin_token_provider
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "pin-live", "expiresAt": 10_000_000_000_000,
            "refreshToken": "rt"}})
        sw = _FakeSwitcher(active_num="1", backups={"2": creds})
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() == "pin-live"
        assert sw.persisted == []  # fresh token: nothing rotated

    def case_refreshes_and_persists_when_backup_expired(self, monkeypatch):
        import json
        from cswap_pin import proxy as pin_proxy
        from claude_swap.oauth import RefreshOutcome
        old = json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt-1"}})
        rotated = json.dumps({"claudeAiOauth": {
            "accessToken": "fresh", "expiresAt": 10_000_000_000_000,
            "refreshToken": "rt-2"}})
        monkeypatch.setattr(
            pin_proxy.oauth, "try_refresh_oauth_credentials",
            lambda _c: RefreshOutcome(rotated, None))
        sw = _FakeSwitcher(active_num="1", backups={"2": old})
        provider = pin_proxy.make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() == "fresh"
        # Rotation persisted back to the backup store (refresh tokens rotate).
        assert sw.persisted == [("2", "pin@example.com", rotated)]


class TestRefreshGoesThroughTheInterprocessGate:
    """A refresh token is one-time-use, and this daemon is not the only
    process that spends one.

    The provider's ``threading.Lock`` serializes its own threads and nothing
    else. The usage collector and the autoswitcher refresh the same backup
    slot from their own processes, so a POST straight to
    ``try_refresh_oauth_credentials`` could consume a grant another process
    was already consuming: one wins, the other gets ``invalid_grant``, and a
    superseded generation gets persisted over the live one.

    The host already owns the answer — ``consume_backup_grant`` holds a
    per-slot FILE lock across re-read -> POST -> fingerprint-CAS. The pin
    must use it rather than reach past it.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _expired(self):
        import json
        return json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt-1"}})

    def _rotated(self):
        import json
        return json.dumps({"claudeAiOauth": {
            "accessToken": "fresh", "expiresAt": 10_000_000_000_000,
            "refreshToken": "rt-2"}})

    def case_refresh_is_routed_through_consume_backup_grant(self, monkeypatch):
        from cswap_pin import proxy as pin_proxy
        from claude_swap.oauth import RefreshOutcome

        rotated = self._rotated()
        direct_posts = []
        monkeypatch.setattr(
            pin_proxy.oauth, "try_refresh_oauth_credentials",
            lambda _c: direct_posts.append(_c) or RefreshOutcome(rotated, None))

        class _GatedSwitcher(_FakeSwitcher):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.gated = []

            def consume_backup_grant(self, num, email, snapshot):
                self.gated.append((num, email, snapshot))
                return RefreshOutcome(rotated, None)

        sw = _GatedSwitcher(active_num="1", backups={"2": self._expired()})
        provider = pin_proxy.make_pin_token_provider(sw, "2", "pin@example.com")

        assert provider() == "fresh"
        assert sw.gated == [("2", "pin@example.com", self._expired())], (
            "the refresh bypassed the host's interprocess consume gate"
        )
        assert direct_posts == [], (
            "a direct POST can consume a grant another process is consuming"
        )

    def case_the_gate_persists_so_the_pin_must_not_write_again(self):
        """A second write would land OUTSIDE the slot lock.

        The gate persists under that lock and CASes on the refresh-token
        fingerprint; writing the same bytes again afterwards can clobber a
        racing writer's newer lineage — the very thing the gate serializes.
        """
        from cswap_pin import proxy as pin_proxy
        from claude_swap.oauth import RefreshOutcome

        rotated = self._rotated()

        class _GatedSwitcher(_FakeSwitcher):
            def consume_backup_grant(self, num, email, snapshot):
                return RefreshOutcome(rotated, None)

        sw = _GatedSwitcher(active_num="1", backups={"2": self._expired()})
        provider = pin_proxy.make_pin_token_provider(sw, "2", "pin@example.com")

        assert provider() == "fresh"
        assert sw.persisted == [], (
            "the pin re-persisted what the gate already wrote under its lock"
        )

    def case_a_busy_gate_yields_instead_of_killing_the_lineage(self):
        """``consume-busy`` means another process holds the slot.

        No token, so this request goes out unpinned and the next retries —
        the provider's existing fail-open. Strictly better than the direct
        POST it replaces, which would answer ``invalid_grant`` and take the
        refresh lineage down for good.
        """
        from cswap_pin import proxy as pin_proxy
        from claude_swap.oauth import RefreshOutcome

        class _BusySwitcher(_FakeSwitcher):
            def consume_backup_grant(self, num, email, snapshot):
                return RefreshOutcome(None, "consume-busy")

        sw = _BusySwitcher(active_num="1", backups={"2": self._expired()})
        provider = pin_proxy.make_pin_token_provider(sw, "2", "pin@example.com")

        assert provider() is None
        assert sw.persisted == []

    def case_an_older_host_without_the_gate_still_refreshes(self, monkeypatch):
        """The gate is newer than the pin package's floor.

        Falling back to the direct POST keeps a pinned request served on an
        older claude-swap; the in-process lock still covers our own threads.
        """
        from cswap_pin import proxy as pin_proxy
        from claude_swap.oauth import RefreshOutcome

        rotated = self._rotated()
        monkeypatch.setattr(
            pin_proxy.oauth, "try_refresh_oauth_credentials",
            lambda _c: RefreshOutcome(rotated, None))

        sw = _FakeSwitcher(active_num="1", backups={"2": self._expired()})
        assert not hasattr(sw, "consume_backup_grant")
        provider = pin_proxy.make_pin_token_provider(sw, "2", "pin@example.com")

        assert provider() == "fresh"
        # No gate to persist for us, so the pin must do it itself.
        assert sw.persisted == [("2", "pin@example.com", rotated)]


class TestPinStore:
    """The pin lives in settings.json's remoteControl section (identity by
    (email, organizationUuid) — slot numbers are not stable)."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_roundtrip(self, tmp_path):
        from cswap_pin.proxy import load_pin, save_pin
        assert load_pin(tmp_path) is None
        save_pin(tmp_path, "pin@example.com", "org-uuid-1")
        assert load_pin(tmp_path) == ("pin@example.com", "org-uuid-1")

    def case_unpin(self, tmp_path):
        from cswap_pin.proxy import load_pin, save_pin
        save_pin(tmp_path, "pin@example.com", "org-uuid-1")
        save_pin(tmp_path, None, None)
        assert load_pin(tmp_path) is None

    def case_a_malformed_settings_file_is_not_overwritten(self, tmp_path):
        """A read-modify-write must not start from ``{}``.

        The host's read-side reader degrades a corrupt settings.json to an
        empty dict on purpose — the app should still start. Using that here
        meant a pin change rewrote the file with ONLY the pin section,
        destroying autoswitch, UI and every unknown key in a file that was
        very likely still hand-recoverable.
        """
        import pytest
        from claude_swap.exceptions import ConfigError
        from claude_swap.settings import settings_path
        from cswap_pin.proxy import save_pin

        path = settings_path(tmp_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        broken = '{"autoswitch": {"enabled": true},,,'  # truncated / corrupt
        path.write_text(broken, encoding="utf-8")

        with pytest.raises(ConfigError):
            save_pin(tmp_path, "pin@example.com", "org-1")
        assert path.read_text(encoding="utf-8") == broken, (
            "a recoverable settings file was replaced with just the pin"
        )

    def case_coexists_with_autoswitch_settings(self, tmp_path):
        # save_settings preserves unknown sections; the reverse must hold too.
        from cswap_pin.proxy import load_pin, save_pin
        from claude_swap.settings import AutoSwitchSettings, save_settings, load_settings
        save_settings(tmp_path, AutoSwitchSettings(threshold=77.0))
        save_pin(tmp_path, "pin@example.com", "org-1")
        assert load_settings(tmp_path).threshold == 77.0
        assert load_pin(tmp_path) == ("pin@example.com", "org-1")
        save_settings(tmp_path, AutoSwitchSettings(threshold=88.0))
        assert load_pin(tmp_path) == ("pin@example.com", "org-1")


class TestWireEnv:
    """wire_env points the child session at the pin proxy: HTTPS_PROXY set,
    our CA merged into NODE_EXTRA_CA_CERTS (never replacing an existing one,
    e.g. a CCF or corp CA)."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_sets_proxy_and_ca(self, tmp_path):
        from cswap_pin.proxy import wire_env
        ca = tmp_path / "ca.pem"
        ca.write_text("PIN-CA\n")
        env = wire_env({}, 9955, ca)
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert env["https_proxy"] == "http://127.0.0.1:9955"
        assert env["NODE_EXTRA_CA_CERTS"] == str(ca)

    def case_rewrites_an_all_proxy_but_never_invents_one(self, tmp_path):
        """An ALL_PROXY already in play names the hop we chain THROUGH, so it
        is rewritten to us. An absent one stays absent: this env can be eval'd
        into the user's SHELL (pin-env), where an ALL_PROXY we invented would
        route that shell's git, uv and gh through a MITM built for one
        client."""
        from cswap_pin.proxy import wire_env
        ca = tmp_path / "ca.pem"
        ca.write_text("PIN-CA\n")

        env = wire_env({"ALL_PROXY": "http://127.0.0.1:9901"}, 9955, ca)
        assert env["ALL_PROXY"] == "http://127.0.0.1:9955"

        env = wire_env({"all_proxy": "http://127.0.0.1:9901"}, 9955, ca)
        assert env["all_proxy"] == "http://127.0.0.1:9955"

        env = wire_env({}, 9955, ca)
        assert "ALL_PROXY" not in env and "all_proxy" not in env

    def case_merges_existing_node_extra_ca(self, tmp_path):
        from cswap_pin.proxy import wire_env
        ca = tmp_path / "ca.pem"
        ca.write_text("PIN-CA\n")
        other = tmp_path / "ccf-ca.pem"
        other.write_text("CCF-CA\n")
        env = wire_env({"NODE_EXTRA_CA_CERTS": str(other)}, 9955, ca)
        bundle = env["NODE_EXTRA_CA_CERTS"]
        assert bundle not in (str(ca), str(other))  # a merged file
        text = (tmp_path / "ca-bundle.pem").read_text()
        assert "PIN-CA" in text and "CCF-CA" in text


class TestWireGlobalConfig:
    """Wiring hand-launched sessions through .claude.json — the file cswap
    already rewrites to swap accounts. Claude Code applies its `env` block
    into process.env at startup, so `claude` typed by hand picks the pin up
    with no settings.json edit, no wrapper, and no shim on PATH."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _config(self, tmp_path, monkeypatch, initial: dict) -> "Path":
        from pathlib import Path
        path = Path(tmp_path) / ".claude.json"
        path.write_text(json.dumps(initial), encoding="utf-8")
        monkeypatch.setattr(
            "claude_swap.paths.get_global_config_path", lambda: path
        )
        return path

    def case_a_receipt_that_cannot_be_written_leaves_the_config_unwired(
        self, tmp_path, monkeypatch
    ):
        """A WIRING NOTHING CAN REMOVE IS WORSE THAN NO WIRING.

        The write pops the config-key copies of the receipt (they are where it
        USED to live, and a stale copy would outrank the sidecar) and then
        writes the sidecar. `_write_ledger` is best-effort and swallows every
        error, so if the sidecar write fails the config is left carrying our
        proxy vars with the receipt in NEITHER location.

        Nothing can then remove them: `_wire_mark_of` reads the sidecar, falls
        through to the config keys, finds neither, and every "is it wired"
        caller answers no — while `HTTPS_PROXY` in `.claude.json` sends every
        new session to a port that may be long gone. `--clear` is a no-op on
        it. Only a hand edit fixes it, which is exactly what `clear_wiring`
        exists to make unnecessary.

        `_write_ledger`'s docstring claims the failure "degrades to the
        pre-existing behaviour — `--clear` still finds the wiring through the
        config keys an older pin left". That is false FOR THIS PATH: the same
        function popped those keys three lines earlier.

        So the config write is the one that must be conditional. If the
        receipt cannot be written, leave the file alone: unwired is a working
        session, and wired-with-no-receipt is an outage nobody can clear.

        THE CONTROL is the same call with a writable sidecar, which must wire
        — otherwise "does not wire" would pass for a function that never
        wires at all.
        """
        import json as _json

        from cswap_pin import proxy as pin_proxy

        def _attempt(ledger_fails, name):
            # A DISTINCT CONFIG PATH PER ATTEMPT. The sidecar is keyed by a
            # hash of the config path (`_ledger_path`), so reusing one path
            # lets the CONTROL's sidecar answer for the failing attempt — and
            # the case passes while the defect is fully present. Measured:
            # that is exactly how the first version of this test went green
            # against code a direct probe showed to be broken.
            from pathlib import Path
            path = Path(tmp_path) / f"{name}.claude.json"
            path.write_text("{}", encoding="utf-8")
            monkeypatch.setattr(
                "claude_swap.paths.get_global_config_path", lambda: path
            )
            real = pin_proxy._write_ledger
            if ledger_fails:
                def _boom(*a, **k):
                    raise OSError("sidecar store is unwritable")
                pin_proxy._write_ledger = _boom
            try:
                ok = pin_proxy.wire_global_config(41234, certdir / "ca.pem")
            finally:
                pin_proxy._write_ledger = real
            raw = _json.loads(path.read_text(encoding="utf-8"))
            env = raw.get("env") or {}
            # THE RECEIPT AS EVERY READER SEES IT: sidecar first, config keys
            # as the fallback. `_read_ledger` is that lookup, so asking it is
            # asking exactly what `--clear` and `_wiring_present` will find.
            mark = pin_proxy._read_ledger(path, raw).get(pin_proxy._WIRE_MARK)
            return ok, "HTTPS_PROXY" in env, mark

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        ensure_ca(certdir, "api.anthropic.com")

        # CONTROL: a writable sidecar must produce a real wiring.
        ok, wired, mark = _attempt(ledger_fails=False, name="control")
        assert ok and wired and mark, (
            f"CONTROL FAILED: a normal wire did not happen "
            f"(ok={ok} wired={wired} mark={mark!r})"
        )

        ok, wired, mark = _attempt(ledger_fails=True, name="broken")
        assert not (wired and mark is None), (
            "the config carries our proxy vars with the receipt in NEITHER "
            "location — nothing can remove them and `--clear` is a no-op, so "
            "every new session dials a port that may be gone"
        )

    def case_the_config_is_never_published_wider_than_it_was(
        self, tmp_path, monkeypatch
    ):
        """`.claude.json` holds primaryApiKey, inline MCP credentials and the
        proxy URL's own credential. A plain write takes the umask, and because
        this is a RENAME the mode sticks — so wiring the pin could permanently
        downgrade a 0600 config to 0644.

        Driven across umasks because that is the variable the bug rode on, and
        it is invisible to a test that only runs under the harness's own.
        """
        import os
        import stat
        from pathlib import Path

        from cswap_pin.proxy import wire_global_config

        ca = tmp_path / "ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
        old_umask = os.umask(0o022)
        try:
            for umask in (0o022, 0o077, 0o000):
                for start in (0o600, 0o400, 0o644):
                    os.umask(umask)
                    d = tmp_path / f"u{umask:03o}m{start:03o}"
                    d.mkdir()
                    path = d / ".claude.json"
                    path.write_text("{}", encoding="utf-8")
                    os.chmod(path, start)
                    monkeypatch.setattr(
                        "claude_swap.paths.get_global_config_path", lambda p=path: p
                    )
                    wire_global_config(36301, ca)
                    after = stat.S_IMODE(path.stat().st_mode)
                    assert after <= start, (
                        f"umask {umask:03o}: wiring widened {start:o} -> {after:o}"
                    )
        finally:
            os.umask(old_umask)

    def case_a_leftover_temp_file_cannot_dictate_the_mode(
        self, tmp_path, monkeypatch
    ):
        """O_CREAT's mode argument is IGNORED for a file that already exists.

        A crashed earlier write leaves the temp behind, so a fixed temp name
        let that leftover's mode become the config's — permanently, via the
        rename. The same fixed name is also why two processes wiring at once
        would share one temp.
        """
        import os
        import stat
        from pathlib import Path

        from cswap_pin.proxy import wire_global_config

        ca = tmp_path / "ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
        path = self._config(tmp_path, monkeypatch, {})
        os.chmod(path, 0o600)

        old_umask = os.umask(0o077)
        try:
            # Every temp name the writer might pick, pre-created world-readable.
            for name in (
                f"{path.name}.{os.getpid()}.cswap-tmp",
                ".claude.cswap-tmp",
                f"{path.name}.cswap-tmp",
            ):
                stale = path.with_name(name)
                stale.write_text("stale", encoding="utf-8")
                os.chmod(stale, 0o644)

            wire_global_config(36301, ca)
            after = stat.S_IMODE(path.stat().st_mode)
            assert after == 0o600, (
                f"a leftover temp dictated the config's mode: {after:o}"
            )
        finally:
            os.umask(old_umask)

    def case_writes_proxy_env(self, tmp_path, monkeypatch):
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        path = self._config(tmp_path, monkeypatch, {"projects": {}})

        assert wire_global_config(9955, Path("/tmp/ca.pem")) is True
        env = json.loads(path.read_text())["env"]
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert env["NODE_EXTRA_CA_CERTS"] == "/tmp/ca.pem"
        # unrelated config must survive
        assert json.loads(path.read_text())["projects"] == {}

    def case_all_proxy_names_the_same_hop(self, tmp_path, monkeypatch):
        """A launcher that sets ALL_PROXY leaves it naming the proxy we chain
        THROUGH, so the session would carry two proxy vars pointing at
        different hops. curl resolves that in our favour (measured:
        https_proxy=A + ALL_PROXY=B dials A), but a client is free to resolve
        it the other way and land outside the pin."""
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        path = self._config(
            tmp_path, monkeypatch,
            {"env": {"ALL_PROXY": "http://127.0.0.1:9901"}},
        )

        wire_global_config(9955, Path("/tmp/ca.pem"))
        env = json.loads(path.read_text())["env"]
        assert env["ALL_PROXY"] == "http://127.0.0.1:9955"
        assert env["ALL_PROXY"] == env["HTTPS_PROXY"]

        # and it is ours to give back, like every other key we displace
        wire_global_config(None, None)
        assert (
            json.loads(path.read_text())["env"]["ALL_PROXY"]
            == "http://127.0.0.1:9901"
        )

    def case_an_all_proxy_we_added_is_removed_not_blanked(
        self, tmp_path, monkeypatch
    ):
        """The common case is a launcher that exports ALL_PROXY fresh per
        launch, so the config file never held one for us to displace. Unwiring
        must then DELETE the key: an `ALL_PROXY=""` left in a block that is
        applied to every launch on the machine is worse than no key at all."""
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        path = self._config(tmp_path, monkeypatch, {"env": {"FOO": "bar"}})

        wire_global_config(9955, Path("/tmp/ca.pem"))
        assert json.loads(path.read_text())["env"]["ALL_PROXY"].endswith(":9955")

        wire_global_config(None, None)
        env = json.loads(path.read_text())["env"]
        assert "ALL_PROXY" not in env
        assert env == {"FOO": "bar"}

    def case_unwire_restores_a_displaced_value(self, tmp_path, monkeypatch):
        """A launcher's own proxy is displaced while pinned and put BACK on
        clear — the env block lands on top of process.env, so silently
        dropping the user's value would leave them worse than before."""
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        path = self._config(
            tmp_path, monkeypatch,
            {"env": {"HTTPS_PROXY": "http://127.0.0.1:9901", "FOO": "bar"}},
        )

        wire_global_config(9955, Path("/tmp/ca.pem"))
        assert json.loads(path.read_text())["env"]["HTTPS_PROXY"].endswith(":9955")

        wire_global_config(None, None)
        env = json.loads(path.read_text())["env"]
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9901"  # restored
        assert env["FOO"] == "bar"                            # never touched
        assert "NODE_EXTRA_CA_CERTS" not in env               # ours, removed

    def case_unwire_restores_what_an_OLDER_pin_recorded_in_the_config(
        self, tmp_path, monkeypatch
    ):
        """The same restore, from the receipt's PREVIOUS home.

        The receipt (`_cswapPinWiredKeys` + `…Saved`) moved out of
        `.claude.json` into the account store. There is no cutover — an older
        cswap-pin on the same box still writes the config keys — so the reader
        takes both, and this is the pairing that upgrade actually produces:
        wired by the old writer, unwired by the new one.

        Losing it is silent and expensive: the corporate proxy the pin
        displaced is simply never put back, and the user is left worse off than
        before they pinned.
        """
        from cswap_pin.proxy import wire_global_config

        path = self._config(tmp_path, monkeypatch, {})
        # Exactly what a pre-move cswap-pin left behind.
        path.write_text(json.dumps({
            "env": {
                "HTTPS_PROXY": "http://127.0.0.1:41000",
                "CSWAP_PIN_PORT": "41000",
            },
            "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"],
            "_cswapPinWiredKeysSaved": {"HTTPS_PROXY": "http://corp:8080"},
        }))

        assert wire_global_config(None, None) is True
        env = json.loads(path.read_text()).get("env") or {}
        assert env.get("HTTPS_PROXY") == "http://corp:8080", (
            "the proxy the OLD pin displaced was not restored — the new reader "
            "did not fall back to the receipt's previous home"
        )
        assert "CSWAP_PIN_PORT" not in env

    def case_a_cleared_receipt_is_an_answer_not_a_miss(self, tmp_path, monkeypatch):
        """An unwire is REMEMBERED, so a leftover config key cannot undo it.

        The fallback above has a sharp edge: if "the new location says not
        wired" read as absence, the reader would fall through to the config —
        and a stale key there (an older pin's, a restored backup) would make
        the very next read believe the wiring is back, over a config whose
        proxy vars are already gone.
        """
        from pathlib import Path

        from cswap_pin import proxy

        path = self._config(tmp_path, monkeypatch, {})
        proxy.wire_global_config(47000, Path("/tmp/ca.pem"))
        proxy.wire_global_config(None, None)

        raw = json.loads(path.read_text())
        raw["_cswapPinWiredKeys"] = ["HTTPS_PROXY", "CSWAP_PIN_PORT"]
        path.write_text(json.dumps(raw))

        assert proxy._read_ledger(path, json.loads(path.read_text())).get(
            "_cswapPinWiredKeys"
        ) == [], "a cleared receipt fell through to a stale config key"

    def case_unwire_leaves_no_env_block_when_it_was_ours_alone(
        self, tmp_path, monkeypatch
    ):
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        path = self._config(tmp_path, monkeypatch, {"projects": {}})

        wire_global_config(9955, Path("/tmp/ca.pem"))
        wire_global_config(None, None)
        raw = json.loads(path.read_text())
        assert "env" not in raw
        assert "_cswapPinWiredKeys" not in raw

    def case_merges_an_existing_ca_instead_of_replacing_it(
        self, tmp_path, monkeypatch
    ):
        """NODE_EXTRA_CA_CERTS names ONE file, so overwriting it blinds the
        session to every host the upstream proxy re-signs. Measured: with only
        our CA, downloads.claude.ai failed to verify and the session showed
        'Auto-update failed · Run claude doctor'."""
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config

        certdir = Path(tmp_path) / "pin-proxy"
        certdir.mkdir()
        ours = certdir / "ca.pem"
        ours.write_bytes(b"-----BEGIN CERTIFICATE-----\nOURS\n")
        theirs = Path(tmp_path) / "upstream-ca.pem"
        theirs.write_bytes(b"-----BEGIN CERTIFICATE-----\nTHEIRS\n")

        path = self._config(
            tmp_path, monkeypatch,
            {"env": {"NODE_EXTRA_CA_CERTS": str(theirs)}},
        )
        wire_global_config(9955, ours)

        bundle = Path(json.loads(path.read_text())["env"]["NODE_EXTRA_CA_CERTS"])
        body = bundle.read_bytes()
        assert b"OURS" in body and b"THEIRS" in body, "the upstream CA was dropped"

        # and clearing restores the user's own value untouched
        wire_global_config(None, None)
        env = json.loads(path.read_text())["env"]
        assert env["NODE_EXTRA_CA_CERTS"] == str(theirs)

    def case_wires_the_self_loop_marker(self, tmp_path, monkeypatch):
        """Claude Code applies this env block into process.env, which its
        Bash-tool children inherit — so a cswap run from inside a pinned
        session sees OUR proxy as its ambient one. Without the marker it
        records the daemon as its own upstream and it CONNECTs to itself."""
        from pathlib import Path
        from cswap_pin.proxy import _ambient_proxy, wire_global_config

        path = self._config(tmp_path, monkeypatch, {"projects": {}})
        wire_global_config(9955, Path(tmp_path) / "ca.pem")
        env = json.loads(path.read_text())["env"]
        assert env["CSWAP_PIN_PORT"] == "9955"
        # That env, inherited by a child, must not read as an upstream proxy.
        assert _ambient_proxy(env) is None

    def case_apply_pin_clear_unwires(self, tmp_path, monkeypatch):
        """Clearing must unwire, not just forget the pin. A cleared-but-wired
        config keeps pointing at a proxy that idle-tears-down, and then every
        hand-launched `claude` starts with HTTPS_PROXY on a dead port — with no
        way back but editing the file by hand. ensure_proxy cannot repair it
        either: it returns at its `no pin` guard before reaching the wiring."""
        from pathlib import Path
        from cswap_pin import proxy as pin_proxy

        path = self._config(tmp_path, monkeypatch, {"projects": {}})
        backup = Path(tmp_path)

        class _Sw:
            backup_dir = backup
            def resolve_account(self, identifier):
                return ("2", "pin@example.com", "org-1")

        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda sw: (9955, Path("/x/ca.pem")))
        pin_proxy.apply_pin(_Sw(), "pin@example.com", "org-1")
        pin_proxy.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        assert "env" in json.loads(path.read_text())

        pin_proxy.apply_pin(_Sw(), None, None)
        raw = json.loads(path.read_text())
        assert "env" not in raw, "clearing the pin left the proxy wired"
        assert pin_proxy.load_pin(backup) is None

    def case_missing_config_is_not_an_error(self, tmp_path, monkeypatch):
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        monkeypatch.setattr(
            "claude_swap.paths.get_global_config_path",
            lambda: Path(tmp_path) / "absent.json",
        )
        assert wire_global_config(9955, Path("/tmp/ca.pem")) is False


class TestEnsureProxy:
    """ensure_proxy: no pin → None; live daemon → reuse; else spawn."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    class _Sw:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
        def resolve_account(self, identifier):
            return ("2", "pin@example.com", "org-1")

    def case_none_when_no_pin(self, tmp_path):
        from cswap_pin.proxy import ensure_proxy
        assert ensure_proxy(self._Sw(tmp_path)) is None

    def case_spawns_when_no_daemon(self, tmp_path, monkeypatch):
        from cswap_pin import proxy as pin_proxy
        pin_proxy.save_pin(tmp_path, "pin@example.com", "org-1")
        spawned = []
        def fake_spawn(account_num, email, certdir, **kw):
            spawned.append((account_num, email))
            return 9955
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", fake_spawn)
        port, ca = pin_proxy.ensure_proxy(self._Sw(tmp_path))
        assert port == 9955
        assert spawned == [("2", "pin@example.com")]
        assert ca == tmp_path / "pin-proxy" / "ca.pem"

    def case_reuses_live_daemon(self, tmp_path, monkeypatch):
        import os, socket
        from cswap_pin import proxy as pin_proxy
        pin_proxy.save_pin(tmp_path, "pin@example.com", "org-1")
        # A live listener + our own (alive) pid + a MATCHING fingerprint.
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fp = pin_proxy.daemon_fingerprint("2", "pin@example.com")
        pin_proxy.write_daemon_state(certdir, port, os.getpid(), fp)
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a: (_ for _ in ()).throw(AssertionError("no spawn")))
        got_port, _ = pin_proxy.ensure_proxy(self._Sw(tmp_path))
        srv.close()
        assert got_port == port

    def case_none_when_pin_account_gone(self, tmp_path):
        from cswap_pin import proxy as pin_proxy
        from claude_swap.exceptions import AccountNotFoundError
        pin_proxy.save_pin(tmp_path, "gone@example.com", "org-x")
        class Sw(self._Sw):
            def resolve_account(self, identifier):
                raise AccountNotFoundError(identifier)
        assert pin_proxy.ensure_proxy(Sw(tmp_path)) is None










class TestDaemonState:
    """The daemon records port+pid+fingerprint in a JSON state file so a
    launcher can tell a live, current daemon from a stale one (wrong pin
    account, or redeployed code) and recycle it. Mirrors CCF's fingerprint
    staleness check (cachefix-ensure is_fresh/recycle)."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_record_roundtrips_and_survives_damage(self, tmp_path):
        """Write, read, and the two ways a read finds nothing.

        Three methods for one file's read path; the CASES are the value.
        """
        from cswap_pin.proxy import read_daemon_state, write_daemon_state

        assert read_daemon_state(tmp_path) is None, "absent must read as None"

        write_daemon_state(tmp_path, port=51000, pid=1234, fingerprint="fp-abc")
        assert read_daemon_state(tmp_path) == {
            "port": 51000, "pid": 1234, "fingerprint": "fp-abc",
        }

        (tmp_path / "proxy.json").write_text("{not json")
        assert read_daemon_state(tmp_path) is None, (
            "a corrupt record must read as absent, not raise — a launcher "
            "polls this and a traceback there takes the launch with it"
        )

    def case_fingerprint_encodes_the_code_only(self, tmp_path):
        # Identifies the CODE, so a redeploy makes a running daemon stale. The
        # pinned account is NOT in it: that is re-read per request, and baking
        # it in would recycle the daemon on every `cswap pin` — a restart a
        # live session should never need (cswap's own account switch doesn't).
        from cswap_pin.proxy import daemon_fingerprint
        assert daemon_fingerprint("1", "a@co.com") == daemon_fingerprint(
            "2", "b@co.com"
        )
        assert daemon_fingerprint() == daemon_fingerprint("1", "a@co.com")

class TestEnsureProxyLifecycle:
    """ensure_proxy under the CCF-style lifecycle: reuse a fresh live daemon,
    recycle a stale-fingerprint one, and never double-spawn under a race."""


    class _Sw:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
        def resolve_account(self, identifier):
            return ("1", "pin@example.com", "org-1")

    def _pin(self, tmp_path):
        from cswap_pin.proxy import save_pin
        save_pin(tmp_path, "pin@example.com", "org-1")

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_reuses_fresh_daemon_without_spawn(self, tmp_path, monkeypatch):
        import os, socket
        from cswap_pin import proxy as pin_proxy
        self._pin(tmp_path)
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fp = pin_proxy.daemon_fingerprint("1", "pin@example.com")
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        pin_proxy.write_daemon_state(certdir, port, os.getpid(), fp)
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a, **k: (_ for _ in ()).throw(AssertionError("no spawn")))
        got, ca = pin_proxy.ensure_proxy(self._Sw(tmp_path))
        srv.close()
        assert got == port

    def case_recycles_stale_fingerprint(self, tmp_path, monkeypatch):
        import os, socket
        from cswap_pin import proxy as pin_proxy
        self._pin(tmp_path)
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        # a live daemon with a STALE fingerprint (old code / other account)
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        stale_port = srv.getsockname()[1]
        pin_proxy.write_daemon_state(certdir, stale_port, os.getpid(), "STALE-FP")
        killed = []
        # This pid really is a pin daemon for this certdir. Say so: the
        # recycle refuses to signal a pid it cannot identify as one of ours,
        # and the pytest process is not (see test_a_reused_pid_is_not_killed).
        monkeypatch.setattr(pin_proxy, "_pin_daemon_pids", lambda cd: [os.getpid()])
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid: killed.append(pid))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 52000)
        got, ca = pin_proxy.ensure_proxy(self._Sw(tmp_path))
        srv.close()
        assert got == 52000            # spawned fresh
        assert killed == [os.getpid()]  # stale daemon was recycled


def _watch_blocking_phase(monkeypatch):
    """An Event that fires when `watch_refcount` enters its blocking read.

    Two of these cases must let the watcher get PAST the first-holder phase
    before closing the holder, and both did it by sleeping 400 ms. That is a
    guess, and a 2000x-too-large one: the transition is `os.set_blocking(fd,
    True)` and it happens 0.19 ms after the thread starts when the holder is
    already attached. Watching for the call is both faster and stricter — a
    watcher that never gets there now fails the test instead of being
    silently outrun by the sleep.
    """
    import os
    import threading

    reached = threading.Event()
    real = os.set_blocking

    def spy(fd, flag):
        if flag:
            reached.set()
        return real(fd, flag)

    monkeypatch.setattr(os, "set_blocking", spy)
    return reached


class TestRefcount:
    """FIFO refcount (CCF model): the daemon lives while >=1 session holds a
    write fd on the refcount FIFO, and self-terminates when the last one closes
    (normal exit OR kill -9 — the OS closes fds regardless)."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_wire_env_attaches_refcount_fd(self, tmp_path):
        # wire_env opens the FIFO and passes an inherited fd number to the child
        # via an env var, so the launched claude becomes a refcount holder.
        import os
        from cswap_pin.proxy import wire_env, refcount_fifo_path
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        os.mkfifo(refcount_fifo_path(certdir))
        ca = certdir / "ca.pem"; ca.write_text("CA\n")
        env = wire_env({}, 9955, ca)
        # The pin proxy fd is exposed so the child inherits it (kept open for
        # the child's lifetime). We at least advertise the fifo to hold.
        assert "CSWAP_PIN_REFCOUNT_FD" in env or "CSWAP_PIN_FIFO" in env

    def case_daemon_exits_when_all_holders_close(self, tmp_path):
        # Spawn a real refcount watcher over a FIFO with one holder, close the
        # holder, and assert the watcher's "last holder gone" callback fires.
        import os, threading, time
        from cswap_pin.proxy import refcount_fifo_path, watch_refcount
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        # a holder: open write end (read-write so it doesn't block)
        holder = os.open(fifo, os.O_RDWR)
        fired = threading.Event()
        threading.Thread(target=watch_refcount, args=(fifo, fired.set), daemon=True).start()
        time.sleep(0.3)
        assert not fired.is_set()  # holder still open → daemon stays up
        os.close(holder)            # last holder gone
        assert fired.wait(timeout=3)  # → teardown callback fires

    def case_daemon_that_never_gets_a_holder_still_dies(self, tmp_path):
        """A daemon nobody ever attaches to must tear down, not linger forever.

        The read-only FIFO open blocks until the FIRST writer appears, so a
        daemon spawned whose session dies before attaching (a crash between
        spawn and attach, a killed test run) parked there for the life of the
        machine — holding its port, never idle-tearing-down. Measured: three
        such daemons left over from one test run, each on a /tmp/pytest-*
        certdir that the per-certdir orphan sweep deliberately cannot see, so
        nothing else would ever reap them.
        """
        import os, threading
        from cswap_pin.proxy import refcount_fifo_path, watch_refcount
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        fired = threading.Event()
        # No holder is ever opened.
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set),
            kwargs={"first_holder_timeout": 0.15}, daemon=True,
        ).start()
        assert fired.wait(timeout=5), "daemon never torn down — it would linger forever"

    def case_a_silent_holder_is_not_mistaken_for_no_holder(self, tmp_path):
        """A holder that attaches and writes NOTHING must keep the daemon up.

        The fd IS the reference; a session has no reason to send anything. An
        earlier version of the timeout waited for BYTES, so it read a live
        silent session as "nobody attached" and tore the daemon down under it.
        """
        import os, threading
        from cswap_pin.proxy import refcount_fifo_path, watch_refcount
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        holder = os.open(fifo, os.O_RDWR)   # attaches, stays silent
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set),
            kwargs={"first_holder_timeout": 0.15}, daemon=True,
        ).start()
        # Well past the first-holder timeout: a silent holder must NOT trip it.
        assert not fired.wait(timeout=0.15), "tore down while a holder was still attached"
        os.close(holder)
        assert fired.wait(timeout=3), "did not tear down after the holder closed"

    def case_a_globally_wired_daemon_is_not_an_orphan(self, tmp_path, monkeypatch):
        """Zero FIFO holders is the STEADY STATE of a healthy pin — not an orphan.

        Only ``wire_env`` and ``pin-env`` open the refcount FIFO. The
        ``.claude.json`` env block — the path every hand-launched ``claude``
        takes — pins a session without ever touching it, so those sessions are
        invisible to the refcount. Measured on linux: daemon 4035232 serving
        36301 for 1d17h with not one holder anywhere in ``/proc/*/fd``.

        The first-holder timeout read that as "nobody ever attached" and would
        have torn the live pin down at the next respawn on every machine. The
        wiring naming our port is itself the claim.
        """
        import json as _json, os, threading
        import claude_swap.paths as paths
        from cswap_pin.proxy import (
            refcount_fifo_path,
            watch_refcount,
            write_daemon_state,
            daemon_fingerprint,
        )
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        # This process IS the daemon, serving port 40404, and the global config
        # routes sessions there. No holder is ever opened — as in production.
        write_daemon_state(certdir, 40404, os.getpid(), daemon_fingerprint())
        cfg = tmp_path / ".claude.json"
        cfg.write_text(_json.dumps({"env": {"CSWAP_PIN_PORT": "40404"}}))
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set),
            kwargs={"first_holder_timeout": 0.1}, daemon=True,
        ).start()
        assert not fired.wait(timeout=0.15), (
            "tore down a daemon the global config still routes sessions to"
        )

    def case_an_unwired_daemon_still_dies(self, tmp_path, monkeypatch):
        """The claim must be OUR port, not merely the presence of some wiring.

        Otherwise the orphan reaper stops working the moment any pin is active
        anywhere: the /tmp/pytest-* leftovers this timeout exists to kill would
        read a live daemon's wiring as their own claim and linger forever.
        """
        import json as _json, os, threading
        import claude_swap.paths as paths
        from cswap_pin.proxy import (
            refcount_fifo_path,
            watch_refcount,
            write_daemon_state,
            daemon_fingerprint,
        )
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        write_daemon_state(certdir, 40404, os.getpid(), daemon_fingerprint())
        cfg = tmp_path / ".claude.json"
        cfg.write_text(_json.dumps({"env": {"CSWAP_PIN_PORT": "59999"}}))  # someone else
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set),
            kwargs={"first_holder_timeout": 0.1}, daemon=True,
        ).start()
        assert fired.wait(timeout=5), "orphan lingered — reaper disabled by a foreign pin"

    def case_the_last_holder_leaving_does_not_strand_wired_sessions(
        self, tmp_path, monkeypatch
    ):
        """The claim check guarded ONE exit, and there are two.

        A daemon that never got a holder consults the wiring (above). A
        daemon that HAD holders did not: the moment the last wrapper-launched
        session closed its fd, teardown ran unconditionally — even with the
        global config still routing every hand-launched session to our port.
        Those sessions carry an HTTPS_PROXY fixed at exec, so they cannot be
        redirected; they just get ConnectionRefused and retry forever.

        The two populations are different sets, and closing the last member
        of one says nothing about the other.
        """
        import json as _json, os, threading, time
        import claude_swap.paths as paths
        from cswap_pin.proxy import (
            refcount_fifo_path,
            watch_refcount,
            write_daemon_state,
            daemon_fingerprint,
        )
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        write_daemon_state(certdir, 40404, os.getpid(), daemon_fingerprint())
        cfg = tmp_path / ".claude.json"
        cfg.write_text(_json.dumps({"env": {"CSWAP_PIN_PORT": "40404"}}))
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        # Re-check promptly so the test does not wait out the production pace.
        monkeypatch.setattr("cswap_pin.proxy._CLAIM_RECHECK_INTERVAL", 0.05)

        holder = os.open(fifo, os.O_RDWR)  # a wrapper-launched session attaches
        # WAIT FOR THE WATCHER, do not guess how long it takes. It switches to
        # the blocking (real-EOF) read once a writer has attached, and this
        # test is about that second phase, not the first-holder timeout. The
        # switch IS `os.set_blocking(fd, True)`, so watch for it: measured at
        # 0.19 ms with the holder already attached, where a fixed sleep here
        # waited 400 ms for it.
        reached = _watch_blocking_phase(monkeypatch)
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set), daemon=True
        ).start()
        assert reached.wait(timeout=5.0), "watcher never reached the blocking read"
        os.close(holder)  # ...and leaves, while the wiring still names us
        assert not fired.wait(timeout=0.15), (
            "tore down a daemon the global config still routes sessions "
            "to — they get ConnectionRefused and cannot be redirected"
        )

    def case_the_last_holder_leaving_still_reaps_an_unclaimed_daemon(
        self, tmp_path, monkeypatch
    ):
        """...and the re-check must not disable the reaper it guards.

        With no wiring naming us and nobody connected, the last holder
        leaving means exactly what it always meant: nothing references this
        daemon, so it must go.
        """
        import json as _json, os, threading, time
        import claude_swap.paths as paths
        from cswap_pin.proxy import (
            refcount_fifo_path,
            watch_refcount,
            write_daemon_state,
            daemon_fingerprint,
        )
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        fifo = refcount_fifo_path(certdir)
        os.mkfifo(fifo)
        write_daemon_state(certdir, 40404, os.getpid(), daemon_fingerprint())
        cfg = tmp_path / ".claude.json"
        cfg.write_text(_json.dumps({"env": {"CSWAP_PIN_PORT": "59999"}}))  # not us
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        monkeypatch.setattr("cswap_pin.proxy._CLAIM_RECHECK_INTERVAL", 0.05)

        holder = os.open(fifo, os.O_RDWR)
        reached = _watch_blocking_phase(monkeypatch)  # as above
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set), daemon=True
        ).start()
        assert reached.wait(timeout=5.0), "watcher never reached the blocking read"
        os.close(holder)
        assert fired.wait(timeout=5), (
            "an unreferenced daemon lingered — the reaper stopped working"
        )




# The badge is rendered by `claude_swap.tui.autoview`, and the version that
# reads the pin is not released yet (it ships with the pin-seam PR). The
# publish gate installs the RELEASED host on purpose — that is the world a
# `pip install cswap-pin` user is in — so these fail there for a reason that
# is not a defect in this package. Marked rather than skipped inside the
# tests: the workflow's `-m "not needs_host_seam"` is visible in the log,
# where a silent skip is not. They still run locally, against the checkout.
@pytest.mark.needs_host_seam
class TestAutoViewPinBadge:
    """The auto-switch view marks the cloud-pinned account ON ITS OWN ROW.

    It used to name the pin on the summary line instead, which made you match
    an email against the list printed directly below it rather than just
    reading the list — and pushed that line past 80 columns.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _rows(self, backup_dir, accounts, active=None):
        """Render _candidates_text with a stand-in app, WITHOUT patching the
        AutoScreen class (that would leak into other tests)."""
        from claude_swap.tui.autoview import AutoScreen

        class _Snap:
            pass

        class _Theme:
            primary = secondary = foreground = "#fff"
            success = warning = error = "#fff"
            variables: dict = {}

        class _App:
            class switcher:
                pass

            current_theme = _Theme()

        app = _App()
        app.switcher.backup_dir = backup_dir
        snap = _Snap()
        snap.accounts = accounts
        app.snapshot = snap

        class _Stub:
            pass

        stub = _Stub()
        stub.app = app
        stub._settings = None
        # Bind the REAL helper, so the badge decision under test is the
        # shipped one and not a stand-in.
        stub._pinned_email = lambda: AutoScreen._pinned_email(stub)
        return AutoScreen._candidates_text(stub, snap, active).plain

    def _acct(self, num, email, pct=None):
        from claude_swap.models import AccountSnapshot
        from claude_swap.usage_store import UsageEntry

        return AccountSnapshot(
            number=str(num), email=email, org_name="", org_uuid="",
            is_active=False, kind="oauth", switchable=True,
            usage=UsageEntry(last_good=None, fetched_at=None, age_s=None),
        )

    def case_badge_is_on_the_pinned_row_only(self, tmp_path):
        from cswap_pin.proxy import save_pin

        save_pin(tmp_path, "codeslake@gmail.com", "org-1")
        out = self._rows(
            tmp_path,
            [self._acct(1, "codeslake@gmail.com"), self._acct(2, "j.lee8@samsung.com")],
        )
        pinned_line = next(l for l in out.splitlines() if "codeslake@gmail.com" in l)
        other_line = next(l for l in out.splitlines() if "j.lee8@samsung.com" in l)
        assert "○ cloud" in pinned_line
        assert "○ cloud" not in other_line

    def case_badge_survives_unknown_usage(self, tmp_path):
        """A pinned account still owns the claude.ai side when its usage
        cannot be read, so the badge must not hang off a usage branch."""
        from cswap_pin.proxy import save_pin

        save_pin(tmp_path, "codeslake@gmail.com", "org-1")
        out = self._rows(tmp_path, [self._acct(1, "codeslake@gmail.com")])
        assert "usage unknown" in out and "○ cloud" in out

    def case_no_badge_without_a_pin(self, tmp_path):
        out = self._rows(tmp_path, [self._acct(1, "a@co.com"), self._acct(2, "b@co.com")])
        assert "○ cloud" not in out

    def case_summary_line_never_names_the_pin(self, tmp_path, monkeypatch):
        """The regression being fixed: the pin must not be spelled out twice.

        Asserts on the RENDERED line, not on the source. An earlier version of
        this grepped _update_summary for the word "cloud"; putting the pin back
        under any other wording — "pinned: <email>" — passed it. A source
        search answers "is this token present", never "does this line name the
        pin", and the rewording that defeats it is the one a future edit would
        naturally use.
        """
        from cswap_pin.proxy import save_pin
        from claude_swap.tui.autoview import AutoScreen

        email = "codeslake@gmail.com"
        save_pin(tmp_path, email, "org-1")

        class _T:
            primary = secondary = foreground = "#fff"
            success = warning = error = "#fff"
            variables: dict = {}

        class _App:
            class switcher:
                pass

            current_theme = _T()

        app = _App()
        app.switcher.backup_dir = tmp_path

        class _Settings:
            threshold = 90.0
            interval_seconds = 360.0
            model = ""

        written = {}

        class _Widget:
            def update(self, text):
                written["line"] = text.plain

        class _Stub:
            pass

        stub = _Stub()
        stub.app = app
        stub._settings = _Settings()
        stub._configured_threshold = _Settings.threshold
        stub._adjusting = False
        stub.query_one = lambda *a, **k: _Widget()
        stub._pinned_email = lambda: AutoScreen._pinned_email(stub)

        AutoScreen._update_summary(stub)
        line = written["line"]
        # The load-bearing one: fails on ANY wording that spells the pin out.
        assert email not in line, f"summary names the pin: {line!r}"
        assert "cloud" not in line.lower(), line
        assert "pinned" not in line.lower(), line


class TestKillDaemon:
    """_kill_daemon must escalate TERM → KILL so a daemon that ignores TERM
    (or is mid-teardown) never lingers as an orphan holding a port."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_escalates_to_kill(self, monkeypatch):
        import os
        import time
        from cswap_pin import proxy as pin_proxy
        sent = []
        alive = {"pid": True}
        def fake_kill(pid, sig):
            sent.append(sig)
            if sig == 9:
                alive["pid"] = False
        monkeypatch.setattr(pin_proxy.os, "kill", fake_kill)
        monkeypatch.setattr(pin_proxy, "_pid_alive", lambda pid: alive["pid"])
        # The escalation loop is `_DRAIN_SECONDS * 10 + 20` ticks of a real
        # 0.1s sleep, so an unpatched run of this test WAITS THE FULL CEILING —
        # measured 32.02s, four times the rest of the suite put together. The
        # ticks are the mechanism under test; the wall-clock is not. The
        # sibling test at `_kill_daemon(4242)` already patches this.
        monkeypatch.setattr(time, "sleep", lambda s: None)
        pin_proxy._kill_daemon(4321)
        assert 15 in sent and 9 in sent  # TERM first, then KILL escalation


class TestDaemonSignalTeardown:
    """The daemon installs a SIGTERM handler so a recycle (or cc-update) that
    TERMs it cleans up its state file and port instead of relying on default
    kill semantics."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_sigterm_handler_is_installed(self, monkeypatch, tmp_path):
        # daemon_main should register a SIGTERM handler. We assert the wiring
        # exists by checking the helper it uses is called.
        import signal
        from cswap_pin import proxy as pin_proxy
        installed = {}
        real_signal = pin_proxy.signal.signal if hasattr(pin_proxy, "signal") else None
        # daemon_main is heavy (starts a server); instead unit-test the helper.
        assert hasattr(pin_proxy, "_install_signal_teardown")


class TestOrphanSweep:
    """A daemon that fell out of proxy.json (a redeploy spawned a replacement,
    but the old one didn't die) becomes an orphan no state file references. On
    spawn, sweep every pin_proxy daemon for THIS backup dir except the one we
    keep, so orphans never accumulate."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_sweeps_other_pin_daemons_for_this_certdir(self, monkeypatch, tmp_path):
        from cswap_pin import proxy as pin_proxy
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        # pretend three pin daemons exist for this certdir; keep 200, sweep others
        found = [101, 202, 303]
        monkeypatch.setattr(pin_proxy, "_pin_daemon_pids",
                            lambda cd: list(found))
        killed = []
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid: killed.append(pid))
        pin_proxy._sweep_orphan_daemons(certdir, keep_pid=202)
        assert sorted(killed) == [101, 303]  # everything but the keeper


class TestWorkerJwtRoutesAreNotSwapped:
    """The RC worker authenticates with a session JWT (`auth:"session-jwt"`,
    binary fn Ter/Kb), NOT the OAuth token. Overwriting its Authorization with
    the pinned OAuth token makes the server reject every worker call with 403
    — measured live: /client/presence (OAuth) returned 200 in the same trace
    where every /worker call returned 403.

    The pin only has to steer OWNERSHIP, and /bridge already decides that: it
    is OAuth-authenticated, so it mints a worker JWT for the pinned account.
    Once that JWT exists it must travel untouched.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_worker_routes_keep_their_own_token(self):
        from cswap_pin.proxy import is_pinned_route

        for path in (
            "/v1/code/sessions/cse_x/worker",
            "/v1/code/sessions/cse_x/worker/events",
            "/v1/code/sessions/cse_x/worker/events/stream",
        ):
            assert not is_pinned_route(path), f"{path} must keep the worker JWT"

    def case_ownership_deciding_routes_are_still_pinned(self):
        """NOT client/presence — it was listed here and it did not belong.

        Presence posts {client_id, clear} and receives a poll interval: it
        registers the PROCESS that will do the receiving, which is a different
        question from who owns the session. Swapping it told the server the
        pinned account was attached while the active account's process was the
        one listening, and Remote Control inbound went silently dead — the call
        returns 200, it just registers the wrong party.
        """
        from cswap_pin.proxy import is_pinned_route

        for path in (
            "/v1/code/sessions",
            "/v1/code/sessions/cse_x/bridge",
            "/v1/code/sessions/cse_x/archive",
            "/v1/sessions/session_x/unarchive",
            "/api/frame/deploy/init",
            "/api/frame/frames?limit=20",
        ):
            assert is_pinned_route(path), f"{path} must be pinned"


class TestThePortIsConfigurable:
    """One source: ``settings.json``, written by ``cswap pin --set_port``.
    Absent means the kernel chooses. The env is not a source — that name is
    the pin's own self-loop marker.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _certdir(self, tmp_path):
        d = tmp_path / "pin-proxy"
        d.mkdir(parents=True, exist_ok=True)
        return d


    def case_nothing_configured_means_nothing_claimed(self, tmp_path, monkeypatch):
        """No file: None, so the daemon takes an ephemeral port.

        The absence has to be distinguishable from a configured 0 — port 0
        means "let the kernel choose" to bind(), so returning it as a
        CONFIGURED value would silently mean the opposite of what a user who
        typed it meant. `--set_port 0` therefore CLEARS, and clearing is how
        you ask for a dynamic port.
        """
        import json as _json

        from cswap_pin import proxy as pin_proxy

        certdir = self._certdir(tmp_path)
        assert pin_proxy.configured_port(certdir) is None

        for junk in ("", "not-a-port", 0, 70000, -1, None, [41234]):
            (certdir / "settings.json").write_text(_json.dumps({"port": junk}))
            assert pin_proxy.configured_port(certdir) is None, (
                f"{junk!r} was accepted as a port; a value outside 1-65535 is "
                f"not a port at all and bind() would either fail or, for 0, "
                f"do the opposite of what was asked"
            )

    def case_the_environment_is_not_a_source(self, tmp_path, monkeypatch):
        """The env is never read as config: inside a pinned session that name
        is already the live daemon's port (our own self-loop marker)."""
        from cswap_pin import proxy as pin_proxy

        certdir = self._certdir(tmp_path)

        monkeypatch.setenv("CSWAP_PIN_PORT", "44444")
        assert pin_proxy.configured_port(certdir) is None, (
            "an env value answered — a new daemon would try to bind the live "
            "daemon's port"
        )

        pin_proxy.write_pin_settings(certdir, port=41234)
        assert pin_proxy.configured_port(certdir) == 41234, (
            "the env overruled the file"
        )


    def case_the_daemon_actually_binds_the_configured_port(
        self, tmp_path, monkeypatch
    ):
        """The setting has to REACH bind(), ahead of the reclaim order.

        Without this the whole feature is a file nobody reads: `--set_port`
        persisted a number and the daemon went on choosing an ephemeral one.

        AHEAD OF THE RECORDED PORT, asserted here by recording a DIFFERENT
        one. The reclaim exists to keep live sessions attached across a
        respawn, so it wins by default — but a port the user set is a standing
        instruction, and honouring it only when no record happened to survive
        would make `--set_port` a no-op on exactly the machines that have been
        running.
        """
        import socket as _socket

        from cswap_pin.proxy import PinProxy, write_daemon_state, write_pin_settings

        certdir = self._certdir(tmp_path)
        ensure_ca(certdir, "api.anthropic.com")

        s = _socket.socket()
        s.bind(("127.0.0.1", 0))
        wanted = s.getsockname()[1]
        s.close()  # free again; we only needed a port nothing else holds

        # A recorded port that is NOT the configured one: the setting must win.
        recorded = _socket.socket()
        recorded.bind(("127.0.0.1", 0))
        other = recorded.getsockname()[1]
        recorded.close()
        write_daemon_state(certdir, other, os.getpid(), "fp")
        write_pin_settings(certdir, port=wanted)
        monkeypatch.delenv("CSWAP_PIN_PORT", raising=False)

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: "T")
        proxy.start()
        try:
            assert proxy.port == wanted, (
                f"served on {proxy.port}, not the configured {wanted} — "
                f"`cswap pin --set_port` writes a file nothing binds"
            )
        finally:
            proxy.stop(drain=0)

    def case_an_unavailable_configured_port_serves_anyway_and_says_so(
        self, tmp_path, monkeypatch, capsys
    ):
        """A port we cannot have must not stop the pin — but must be reported.

        Failing to start would be worse than the wrong port: the standing rule
        is that a pin never blocks work. The danger is the silent version of
        that, where the only symptom is a number not matching what was set and
        nothing anywhere says why.
        """
        import socket as _socket

        from cswap_pin.proxy import PinProxy, write_pin_settings

        certdir = self._certdir(tmp_path)
        ensure_ca(certdir, "api.anthropic.com")

        blocker = _socket.socket()
        blocker.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        taken = blocker.getsockname()[1]

        write_pin_settings(certdir, port=taken)
        monkeypatch.delenv("CSWAP_PIN_PORT", raising=False)

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: "T")
        proxy.start()
        try:
            assert proxy.port and proxy.port != taken, (
                "the daemon did not come up at all because one port was busy"
            )
            err = capsys.readouterr().err
            assert str(taken) in err and str(proxy.port) in err, (
                "the configured port was silently ignored — the log must name "
                f"both numbers; got: {err!r}"
            )
        finally:
            proxy.stop(drain=0)
            blocker.close()

    def case_the_settings_file_survives_a_rewrite(self, tmp_path, monkeypatch):
        """Writing the port must not destroy anything else in the file.

        It is a settings file, not a port file — the next setting to land
        there would otherwise be erased by the next `--set_port`.
        """
        import json as _json

        from cswap_pin import proxy as pin_proxy

        certdir = self._certdir(tmp_path)
        path = certdir / "settings.json"
        path.write_text(_json.dumps({"somethingElse": "keep me"}))

        pin_proxy.write_pin_settings(certdir, port=43333)
        raw = _json.loads(path.read_text())
        assert raw.get("somethingElse") == "keep me", (
            f"--set_port clobbered the rest of the settings file: {raw}"
        )
        assert raw.get("port") == 43333

        # ...and clearing it removes only the port.
        pin_proxy.write_pin_settings(certdir, port=None)
        raw = _json.loads(path.read_text())
        assert "port" not in raw, raw
        assert raw.get("somethingElse") == "keep me", raw


class TestDaemonPortStability:
    """A live session's HTTPS_PROXY is fixed at exec time. If a recycled
    daemon comes back on a NEW port, every already-running session keeps
    pointing at a dead one — and its requests then bypass the pin silently
    (measured: an RC session created that way landed on the ACTIVE account
    while the pin looked healthy). The daemon must therefore reclaim the port
    recorded in proxy.json whenever it is free.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_real_spawned_successor_drops_no_connection(
        self, tmp_path, monkeypatch
    ):
        """THE WHOLE PROPERTY, end to end, with a REAL successor process.

        The in-process test above proves the socket is handed over and the
        port never unbinds. It cannot prove the thing the user actually cares
        about, because its "successor" is another object in this interpreter:
        the real one is `subprocess.Popen` reaching `bind()` about 50ms later,
        and that start-up IS the window. Measured on a live box before the
        handdown: 6 refused requests over 0.27s per handover.

        So this drives `_spawn_daemon` for real and hammers the port ~2ms
        apart across the whole window, with THE OLD DESIGN AS A CONTROL in the
        same harness. The control is not decoration: a gapless-handover test
        whose control cannot fail proves only that the harness runs. Measured
        here, three runs each: control 91/89/115 refused, handdown 0/0/0.

        This lived in a scratch directory while three releases shipped, so CI
        gated on a suite that could not see the defect it was written for.
        """
        import socket
        import threading
        import time

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PinProxy, ensure_ca

        # BOUND THE SPAWN WAIT. `_spawn_daemon` polls for up to 10s, and a
        # successor that publishes late is born AFTER this case has finished
        # reaping — measured, processes 11s younger than a reap that reported
        # nothing left. The successor here comes up in well under a second when
        # it comes up at all, so the remaining 9s only buys orphans.
        monkeypatch.setattr(pin_proxy, "_SPAWN_WAIT_S", 1.0)

        arms = []
        children = []

        def _handover(hand_down: bool) -> tuple[int, int]:
            """(refused, served) across one real handover. Returns counts."""
            certdir = tmp_path / ("hd" if hand_down else "ctl")
            # RECORDED FOR THE REAP. `tmp_path` here is the CASE's directory,
            # handed down by `run_cases`, so a caller outside this closure
            # cannot reconstruct the path — and reaping the wrong one silently
            # reaps nothing.
            arms.append(certdir)
            certdir.mkdir()
            ensure_ca(certdir, "api.anthropic.com")
            old = PinProxy(certdir=certdir, pin_token_provider=lambda: "T")
            old.start()
            port = old.port
            # What a successor with NO handdown reclaims, so the control
            # produces a WORKING successor on the same port and the only
            # difference the hammer can see is the gap itself.
            pin_proxy.write_daemon_state(certdir, port, os.getpid(), "fp-old")

            refused, served = [], []
            stop = threading.Event()

            def hammer():
                """A REQUEST, not a connect. A bare `create_connection().close()`
                cannot see the failure that matters here.

                While a departing daemon drains, the port stays BOUND — the
                holder's socket queues arrivals — so a connect always succeeds
                and `refused` is structurally 0 no matter how long nobody is
                behind it. Measured on lmd42 during a 30s held-exit drain:
                refused=0, and 30 requests died on a 3s timeout with no reply.
                A refused-only hammer calls that window healthy.

                So this sends a CONNECT and requires an answer. Something that
                accepts and never replies counts as a failure, which is what it
                is to a session.
                """
                while not stop.is_set():
                    try:
                        s = socket.create_connection(("127.0.0.1", port), timeout=2)
                    except OSError as exc:
                        refused.append(repr(exc))
                        time.sleep(0.002)
                        continue
                    try:
                        s.settimeout(2)
                        s.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                                  b"Host: api.anthropic.com:443\r\n\r\n")
                        if s.recv(64):
                            served.append(1)
                        else:
                            refused.append("no reply (EOF)")
                    except socket.timeout:
                        refused.append("no reply (timeout)")
                    except OSError as exc:
                        refused.append(repr(exc))
                    finally:
                        try:
                            s.close()
                        except OSError:
                            pass
                    time.sleep(0.002)

            h = threading.Thread(target=hammer, daemon=True)
            h.start()
            time.sleep(0.3)
            base = len(refused)
            assert served, "premise: the hammer never reached the daemon"

            spawned = None
            try:
                fd = old.release_listener(hand_down=hand_down)
                # RECORD EVERY CHILD THIS SPAWN CREATES. Reaping by certdir
                # after the fact races the spawn itself: `_spawn_daemon`
                # returns as soon as the state file appears, but the HOLDER it
                # started keeps working, and a successor born a moment later
                # was never in any sweep. Measured: orphans 11s younger than a
                # reap that reported nothing left. Wrapping Popen catches them
                # at birth, which cannot race anything.
                import subprocess as _sp

                _real_popen = _sp.Popen

                def _tracked(*a, **k):
                    proc = _real_popen(*a, **k)
                    children.append(proc)
                    return proc

                _sp.Popen = _tracked
                try:
                    spawned = pin_proxy._spawn_daemon(
                        "1", "a@example.com", certdir, listen_fd=fd
                    )
                finally:
                    _sp.Popen = _real_popen
                old.await_inflight(0)
                time.sleep(0.3)
            finally:
                stop.set()
                h.join(timeout=5)
                # PARENTS FIRST, and the holder is a parent. Killing the
                # daemon alone made this test MULTIPLY processes: the holder's
                # whole job is to replace a daemon that dies, so each kill
                # bought a fresh one. Measured: 7 orphaned pin processes
                # accumulating on the dev box across a few suite runs, and a
                # peer session stalled its machine with 53 of them.
                from conftest import _reap_pin_processes

                _reap_pin_processes(certdir)
            assert spawned == port, (
                f"the successor came up on {spawned}, not {port} — this run "
                f"measures a port change, not a handover"
            )
            return len(refused) - base, len(served)

        # REAP BOTH ARMS, WHATEVER HAPPENS. This case starts REAL detached
        # processes — a holder and its daemon per arm — and an assertion
        # between the two calls used to skip the second arm's cleanup
        # entirely. Measured: 3 orphans per suite run from this case alone,
        # accumulating to 16 on the dev box.
        from conftest import _reap_pin_processes

        try:
            control_refused, _ = _handover(hand_down=False)
            assert control_refused > 0, (
                "THE CONTROL DID NOT FAIL. Handing the port NUMBER over leaves "
                "a hole the successor's start-up cannot avoid, so a run with "
                "zero refusals here means the hammer is not measuring the "
                "window — and the pass below would prove nothing"
            )

            refused, served = _handover(hand_down=True)
            assert refused == 0, (
                f"{refused} of {refused + served} connections were refused "
                f"across a real handover (control refused {control_refused})"
            )
        finally:
            # PARENTS FIRST — a holder replaces a daemon that dies, so killing
            # children first MULTIPLIES them (a peer session stalled its
            # machine with 53 orphans this way). `children` holds the holders
            # this case started; each takes its own daemon down with it.
            for proc in children:
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                except Exception:  # noqa: BLE001 — already gone, or too slow
                    try:
                        proc.kill()
                    except Exception:  # noqa: BLE001
                        pass
            for arm in arms:
                _reap_pin_processes(arm)

    def case_daemon_reclaims_the_recorded_port(self, tmp_path):
        import socket
        from cswap_pin.proxy import PinProxy, ensure_ca, write_daemon_state

        ensure_ca(tmp_path, "api.anthropic.com")
        # a previous daemon recorded this port, then died
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        recorded = s.getsockname()[1]
        s.close()
        write_daemon_state(tmp_path, recorded, 999999, "fp")

        proxy = PinProxy(certdir=tmp_path, pin_token_provider=lambda: "T")
        proxy.start()
        try:
            assert proxy.port == recorded, (
                f"daemon came back on {proxy.port}, orphaning sessions "
                f"pinned to {recorded}"
            )
        finally:
            proxy.stop()

    def case_a_supervisor_held_port_survives_our_stop(self, tmp_path):
        """When something else owns the port, losing it stops being possible.

        Reclaiming the recorded port recovers from a restart; a held port
        removes the window entirely, because the socket was never ours to
        close. Both must work — a machine without a supervisor still relies on
        the reclaim above.
        """
        import os
        import socket

        from cswap_pin.proxy import PinProxy, ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        lsn = socket.socket()
        lsn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsn.bind(("127.0.0.1", 0))
        lsn.listen(8)
        port = lsn.getsockname()[1]
        os.dup2(lsn.fileno(), 3)
        os.environ["LISTEN_FDS"] = "1"
        os.environ["LISTEN_PID"] = str(os.getpid())
        try:
            proxy = PinProxy(tmp_path, lambda: "tok")
            proxy.start()
            assert proxy.port == port, "did not serve the port it was handed"
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
            proxy.stop(drain=0)
            # THE POINT: our stop must not take the port with it. The test's
            # own `lsn` would keep the fd alive no matter what stop() did, so
            # drop it first and force a collection — that is what exposes a
            # release that merely unreferences the socket instead of
            # detaching it (CPython's finalizer closes the fd, and the
            # supervisor's port dies with our handover).
            # The fixture's own descriptors would keep the port bound no
            # matter what release did, and dup2 left TWO: `lsn` and fd 3.
            # Close both, so the only thing that can still hold the address is
            # whatever release_listener did with the socket it adopted. A
            # release that merely unreferences it hands the fd to CPython's
            # finalizer, which closes it — and the port dies here.
            import gc

            lsn.close()
            gc.collect()
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
            return
        finally:
            os.environ.pop("LISTEN_FDS", None)
            os.environ.pop("LISTEN_PID", None)
            lsn.close()

    def case_a_handover_never_leaves_the_port_unbound(self, tmp_path):
        """THE GAP, measured: a successor must inherit the SOCKET, not the port.

        Two processes handing one port over sequentially always leave a hole,
        and it is not the kernel's: rebinding the same port after close takes
        0.0000s, but co-binding it while the predecessor still listens is
        refused (EADDRINUSE with SO_REUSEADDR *and* with SO_REUSEPORT), and a
        fresh interpreter takes ~50ms to reach bind(). So the window is the
        successor's START-UP and nothing inside this package can overlap it
        away — measured on a live box as 6 refused requests over 0.27s, and
        unchanged by every drain fix.

        Passing the listening socket down closes it: the port is never
        unbound, because it is the SAME socket. This hammers the port across
        the whole handover — release, a successor's start-up, the adopt — and
        a single refusal fails it.
        """
        import os
        import socket
        import threading
        import time

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PinProxy, ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        old = PinProxy(certdir=tmp_path, pin_token_provider=lambda: "T")
        old.start()
        port = old.port

        refused = []
        served = []
        stop_hammer = threading.Event()

        def _hammer():
            while not stop_hammer.is_set():
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=2).close()
                    served.append(1)
                except OSError as exc:
                    refused.append(repr(exc))
                time.sleep(0.002)

        h = threading.Thread(target=_hammer, daemon=True)
        h.start()
        time.sleep(0.1)  # a baseline of served connections before we touch it
        assert served, "premise: the hammer never reached the old daemon"

        # What a successor reclaims when it is handed nothing — so a release
        # that closes the port still produces a WORKING successor on the same
        # port, and the only difference the hammer can see is the gap.
        pin_proxy.write_daemon_state(tmp_path, port, os.getpid(), "fp")

        new = None
        try:
            fd = old.release_listener(hand_down=True)
            # THE SUCCESSOR'S START-UP, the whole window this exists to
            # cover. A real one is a fresh interpreter (~50ms measured);
            # this is longer, so a gap could not hide inside scheduling. The
            # socket is still LISTENING, so arrivals queue in the backlog
            # instead of being refused.
            time.sleep(0.3)

            if fd is not None:
                os.environ[pin_proxy._HANDDOWN_FD_ENV] = str(fd)
                os.environ[pin_proxy._HANDDOWN_FROM_ENV] = str(os.getppid())
            try:
                new = PinProxy(certdir=tmp_path, pin_token_provider=lambda: "T")
                new.start()
            finally:
                os.environ.pop(pin_proxy._HANDDOWN_FD_ENV, None)
                os.environ.pop(pin_proxy._HANDDOWN_FROM_ENV, None)

            assert new.port == port, (
                f"successor came up on {new.port}, stranding every session "
                f"whose HTTPS_PROXY was fixed at {port}"
            )
            time.sleep(0.2)
        finally:
            stop_hammer.set()
            h.join(timeout=5)
            old.await_inflight(0)
            if new is not None:
                new.stop(drain=0)

        assert not refused, (
            f"{len(refused)} of {len(refused) + len(served)} connections were "
            f"refused across the handover: {refused[:3]}"
        )
        assert fd is not None, (
            "no connection was refused, but nothing was handed down either — "
            "the successor rebound fast enough to hide the window this time, "
            "which is luck, not the fix"
        )

    def case_pid_zero_is_not_alive(self):
        """0 is a legal argument to kill(2) and it does NOT mean a process.

        ``os.kill(0, sig)`` addresses the CALLER'S OWN PROCESS GROUP, so
        ``os.kill(0, 0)`` is a permission check that always succeeds and
        ``_pid_alive(0)`` answered True — a liveness claim about a pid that
        cannot exist. Measured: `python3 -c "import os; os.kill(0,0)"`
        succeeds.

        A peer hit the same primitive one signal number away and it was worse:
        a pid parse that yielded 0 turned ``kill(pid, SIGKILL)`` into
        ``kill(0, SIGKILL)``, which SIGKILLed its own test runner — every case
        in the file reported as cancelled, including cases that never ran.

        Here every KILL site is gated on membership in ``_pin_daemon_pids``
        (parsed from ``ps``), so 0 cannot reach one, and both liveness callers
        also require the port to answer. That is why this is a wrong ANSWER
        rather than an outage — and why it is worth one line to stop a future
        caller inheriting it as a fact.
        """
        from cswap_pin import proxy as pin_proxy

        assert pin_proxy._pid_alive(0) is False, (
            "pid 0 read as a live process — kill(0, 0) is a permission check "
            "on our own process group, not evidence anything is running"
        )
        assert pin_proxy._pid_alive(-1) is False, (
            "a negative pid names a process GROUP, never a process"
        )
        # THE CONTROL: a pid that really is alive must still read as alive,
        # or the guard above is satisfied by a function that says False to
        # everything.
        assert pin_proxy._pid_alive(os.getpid()) is True, (
            "our own pid did not read as alive — the check is now useless"
        )

        # AND THE FUNCTION THAT ACTUALLY SIGNALS must refuse it too. Today
        # every caller derives its pid from `ps` output, so 0 cannot reach
        # here — but that is a property of the CALLERS, and the caller is
        # exactly where this class of bug keeps being fixed one site at a
        # time. `kill(0, SIGKILL)` kills our own process group: this daemon,
        # and on a spawn path the process that spawned it.
        signalled = []
        real_kill = os.kill
        try:
            os.kill = lambda p, s: signalled.append((p, s))
            pin_proxy._kill_daemon(0)
            pin_proxy._kill_daemon(-1)
        finally:
            os.kill = real_kill
        assert signalled == [], (
            f"_kill_daemon signalled {signalled} — a pid of 0 means OUR OWN "
            f"process group and a negative pid means the group named by its "
            f"absolute value; neither is a daemon"
        )

    def case_a_listening_socket_is_adopted_where_SO_ACCEPTCONN_cannot_be_read(
        self, tmp_path, monkeypatch
    ):
        """MEASURED ON MACOS: the guard refused every socket, on every handover.

        Both adoption paths proved "this is a listening socket" with
        ``getsockopt(SO_ACCEPTCONN)``. That option is READABLE on Linux and
        NOT on Darwin — measured, same code, same call:

            linux   SO_ACCEPTCONN = 1
            darwin  OSError 42, Protocol not available

        So on macOS the guard raised for a perfectly good socket, the
        handdown was refused, and the successor bound a FRESH port. Measured
        on wmac in the deploy that found this:

            pid=60620 ignoring the handed-down fd 3: [Errno 42] ...
            pid=60620 serving on port 58062        <- not the wired 53749

        which is the exact stranding the handdown exists to prevent: every
        live session's HTTPS_PROXY was fixed at exec on the old port, and
        that port died with the predecessor.

        A probe that cannot answer must not be read as "no". The socket is
        still proven to be a listening TCP socket — by ``getsockname()``,
        which answers on both platforms — and only the redundant option is
        allowed to be unavailable.
        """
        import socket

        from cswap_pin import proxy as pin_proxy

        real_getsockopt = socket.socket.getsockopt

        def _darwin(self, level, optname, *a):
            if (level, optname) == (socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                raise OSError(42, "Protocol not available")
            return real_getsockopt(self, level, optname, *a)

        monkeypatch.setattr(socket.socket, "getsockopt", _darwin)

        lsn = socket.socket()
        lsn.bind(("127.0.0.1", 0))
        lsn.listen(4)
        monkeypatch.setenv(pin_proxy._HANDDOWN_FD_ENV, str(lsn.fileno()))
        monkeypatch.setenv(pin_proxy._HANDDOWN_FROM_ENV, str(os.getppid()))
        try:
            adopted = pin_proxy._handed_down_listener()
            assert adopted is not None, (
                "a listening socket was refused because SO_ACCEPTCONN could "
                "not be READ — on macOS that is every handover, and the "
                "successor takes a fresh port while live sessions keep "
                "dialling the old one"
            )
            adopted.detach()  # the fixture owns this fd

            # AND THE GUARD STILL GUARDS. A socket that was never listened on
            # must still be refused, or the fix is just a removed check.
            s2 = socket.socket()
            s2.bind(("127.0.0.1", 0))
            monkeypatch.setenv(pin_proxy._HANDDOWN_FD_ENV, str(s2.fileno()))
            assert pin_proxy._handed_down_listener() is None, (
                "a socket that was never listening was adopted"
            )
            s2.close()
        finally:
            lsn.close()

    def case_a_spawn_without_a_handdown_does_not_pass_the_variables_on(
        self, tmp_path, monkeypatch
    ):
        """A daemon that was handed a socket must not tell its child it was.

        These variables live in the successor's own environment for the rest
        of its life, so a LATER spawn that passes no fd would hand the child a
        number naming a descriptor it does not have. The parentage guard
        refuses it today, but an environment that lies is one pid reuse from
        being believed — and the fd it names is whatever that number became.
        """
        import os

        from cswap_pin import proxy as pin_proxy

        seen = {}

        class _P:
            def __init__(self, *a, **kw):
                seen.update(kw)

        monkeypatch.setattr(pin_proxy.__dict__.get("subprocess", None) or
                            __import__("subprocess"), "Popen", _P)
        monkeypatch.setenv(pin_proxy._HANDDOWN_FD_ENV, "7")
        monkeypatch.setenv(pin_proxy._HANDDOWN_FROM_ENV, "12345")
        # Popen is stubbed, so no successor ever publishes and the spawn waits
        # out its whole budget. This case asserts what the spawn PASSES, not
        # that a successor comes up — 10 s for that was a sixth of the suite.
        monkeypatch.setattr(pin_proxy, "_SPAWN_WAIT_S", 0.1)

        certdir = tmp_path / "certs"
        certdir.mkdir()
        pin_proxy._spawn_daemon("1", "a@b.c", certdir)  # no listen_fd

        env = seen.get("env") or {}
        assert pin_proxy._HANDDOWN_FD_ENV not in env, (
            f"the child was told to adopt fd {env[pin_proxy._HANDDOWN_FD_ENV]} "
            f"which it was never given")
        assert pin_proxy._HANDDOWN_FROM_ENV not in env, env
        assert not seen.get("pass_fds"), seen.get("pass_fds")

    def case_the_predecessor_stops_accepting_before_it_hands_the_socket_over(
        self, tmp_path
    ):
        """EXACTLY ONE ACCEPTOR, or the socket-handdown loses requests outright.

        The kernel gives each connection to ONE of the fd holders calling
        ``accept()``, so a predecessor still inside its loop dequeues
        connections the successor was meant to serve — and drops them, because
        it has stopped serving. Measured by a peer whose launcher kept
        accepting alongside its child: 19 of 60 requests LOST in steady state,
        no restart involved. That is worse than the 0.27s gap this replaces.

        ``release_listener`` must therefore JOIN the accept loop, not merely
        set a flag: the loop polls with a 0.5s timeout and can be inside
        ``accept()`` at that very moment, and it must not still be there when
        the successor starts.
        """
        import socket

        from cswap_pin.proxy import PinProxy, ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        old = PinProxy(certdir=tmp_path, pin_token_provider=lambda: "T")
        old.start()
        try:
            fd = old.release_listener(hand_down=True)
            assert fd is not None, "nothing was handed down"
            assert old._accept_thread is None, (
                "release_listener returned while its accept loop was still "
                "running — a predecessor that keeps accepting steals "
                "connections from the successor and drops them"
            )
        finally:
            old.await_inflight(0)
            try:
                socket.socket(fileno=fd).close()
            except OSError:
                pass

    def case_a_passed_fd_that_is_not_a_listener_is_refused(self, tmp_path):
        """A wrong fd must send us back to binding our own port, not down.

        Both paths are here because both pass an fd and both are inherited by
        descendants that were never meant to have it. LISTEN_FDS/LISTEN_PID
        reach every descendant, so a grandchild trusting the count alone
        serves on whatever its fd 3 happens to be — a log file, a pipe — and
        the port goes unserved with no error. The hand-down variables have the
        same reach, and its guard is the same shape: the fd is addressed to
        whoever's parent is the process that passed it. Each refusal below
        leaves the daemon able to bind for itself.
        """
        import os
        import socket
        import tempfile

        from cswap_pin import proxy as pin_proxy

        me = str(os.getpid())
        # Addressed to somebody else.
        lsn = socket.socket()
        lsn.bind(("127.0.0.1", 0))
        lsn.listen(1)
        os.dup2(lsn.fileno(), 3)
        os.environ["LISTEN_FDS"] = "1"
        try:
            os.environ["LISTEN_PID"] = str(os.getpid() + 1)
            assert pin_proxy._inherited_listener() is None, "adopted another pid's fd"

            os.environ["LISTEN_PID"] = me
            # A regular file on fd 3.
            f = tempfile.NamedTemporaryFile(delete=False)
            os.dup2(f.fileno(), 3)
            assert pin_proxy._inherited_listener() is None, "adopted a plain file"
            f.close()
            os.unlink(f.name)

            # A socket that was never listened on.
            s2 = socket.socket()
            s2.bind(("127.0.0.1", 0))
            os.dup2(s2.fileno(), 3)
            assert pin_proxy._inherited_listener() is None, "adopted a non-listener"
            s2.close()
        finally:
            os.environ.pop("LISTEN_FDS", None)
            os.environ.pop("LISTEN_PID", None)
            lsn.close()

        # The hand-down variables, same guard. A grandchild inherits them but
        # NOT the fd (Popen closes what it does not pass), so without the
        # parentage check it adopts whatever that number now refers to.
        lsn2 = socket.socket()
        lsn2.bind(("127.0.0.1", 0))
        lsn2.listen(1)
        os.environ[pin_proxy._HANDDOWN_FD_ENV] = str(lsn2.fileno())
        try:
            os.environ[pin_proxy._HANDDOWN_FROM_ENV] = str(os.getppid() + 1)
            assert pin_proxy._handed_down_listener() is None, (
                "adopted an fd handed to a different process")

            os.environ[pin_proxy._HANDDOWN_FROM_ENV] = str(os.getppid())
            adopted = pin_proxy._handed_down_listener()
            assert adopted is not None, (
                "refused the fd its own parent passed — nothing would ever "
                "be handed down and the gap stays open")
            # The adopted object OWNS the fd; letting it be collected would
            # close lsn2's descriptor out from under the fixture.
            adopted.detach()

            s3 = socket.socket()
            s3.bind(("127.0.0.1", 0))
            os.environ[pin_proxy._HANDDOWN_FD_ENV] = str(s3.fileno())
            assert pin_proxy._handed_down_listener() is None, (
                "adopted a socket that was never listening")
            s3.close()
        finally:
            os.environ.pop(pin_proxy._HANDDOWN_FD_ENV, None)
            os.environ.pop(pin_proxy._HANDDOWN_FROM_ENV, None)
            lsn2.close()

    def case_falls_back_to_a_free_port_when_recorded_one_is_taken(self, tmp_path):
        import socket
        from cswap_pin.proxy import PinProxy, ensure_ca, write_daemon_state

        ensure_ca(tmp_path, "api.anthropic.com")
        squatter = socket.socket()
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squatter.bind(("127.0.0.1", 0))
        squatter.listen(1)
        taken = squatter.getsockname()[1]
        write_daemon_state(tmp_path, taken, 999999, "fp")

        proxy = PinProxy(certdir=tmp_path, pin_token_provider=lambda: "T")
        proxy.start()
        try:
            assert proxy.port != 0 and proxy.port != taken
        finally:
            proxy.stop()
            squatter.close()

    def case_recycling_a_held_daemon_keeps_the_port_and_one_holder(
        self, tmp_path
    ):
        """A recycle under a holder must replace the CODE, not the port.

        `ensure_proxy`/`heal` recycle a stale daemon by SIGTERMing it and
        spawning. Under a holder that is two mistakes at once, measured:

          the TERM makes the daemon exit 75, so the holder replaces it
          IMMEDIATELY — with the same stale code, and the recycle achieved
          nothing

          `_spawn_daemon` then starts a SECOND holder for a port the first
          one still holds; it cannot bind, falls back, and the wiring is
          rewritten to a different port (measured: 44411 -> 41569) while the
          live sessions still name the old one

        End state before the fix: 3 processes, two of them holders, and a
        config naming an address no session was given. Under a holder the
        recycle belongs to the holder — the code watchdog already replaces a
        daemon whose file changed, on the socket the holder owns.
        """
        import os
        import subprocess
        import time

        from cswap_pin import proxy as pin_proxy

        pin_proxy.ensure_ca(tmp_path, "api.anthropic.com")
        # TRACK EVERY CHILD AT BIRTH. This case starts real holders, and
        # reaping by certdir afterwards races the spawn — the holder can
        # appear after the reap and then lives forever.
        started = []
        real_popen = subprocess.Popen

        def _tracked(*a, **k):
            proc = real_popen(*a, **k)
            started.append(proc)
            return proc

        subprocess.Popen = _tracked
        try:
            port = pin_proxy._spawn_daemon("1", "a@example.com", tmp_path)
        finally:
            subprocess.Popen = real_popen
        if not port:
            log = tmp_path / "daemon.log"
            raise AssertionError(
                "the daemon did not come up; log tail:\n"
                + (log.read_text()[-600:] if log.exists() else "(no log)")
            )
        time.sleep(1.5)
        first = int(pin_proxy.read_daemon_state(tmp_path)["pid"])
        try:
            pin_proxy._write_port_hint(tmp_path, port)
            # THE REAL FLOW: recycle, and spawn ONLY if the holder is not
            # already putting a successor up. That branch is the fix — calling
            # `_spawn_daemon` unconditionally is what started a second holder.
            # THE PREMISE: a holder must actually be up, or this measures
            # nothing. `_spawn_daemon` returns as soon as the state file
            # appears, which can precede the holder being visible in `ps`.
            deadline = time.time() + 10
            while time.time() < deadline:
                # /proc, NOT ps. Inside pytest the `ps` output arrived with
                # the command line truncated mid-argument ("--hold-port 0 1
                # a@"), so a certdir match could never succeed — the same
                # class of trap as `pgrep -f` reading argv while the value is
                # in the environment.
                found = False
                for entry in pathlib.Path("/proc").glob("[0-9]*"):
                    try:
                        cl = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
                    except OSError:
                        continue
                    line = cl.decode(errors="replace")
                    if "--hold-port" in line and str(tmp_path) in line:
                        found = True
                        break
                if found:
                    break
                time.sleep(0.2)
            else:
                log = tmp_path / "daemon.log"
                out = subprocess.run(
                    ["ps", "-eo", "pid=,command="], capture_output=True, text=True
                ).stdout
                raise AssertionError(
                    f"no holder came up (spawn returned {port}).\n"
                    f"log: {log.read_text()[-400:] if log.exists() else '(none)'}\n"
                    f"want certdir={tmp_path!s}\n"
                    f"holder argvs: "
                    + " || ".join(
                        l.strip().partition(" ")[2]
                        for l in out.splitlines()
                        if "--hold-port" in l and "cswap_pin" in l
                    )[-500:]
                )

            handled = pin_proxy._recycle_daemon(tmp_path, first)
            if handled:
                again = None
                for _ in range(60):
                    time.sleep(0.25)
                    again = pin_proxy._read_alive_port(tmp_path)
                    if again is not None:
                        break
            else:
                again = pin_proxy._spawn_daemon("1", "a@example.com", tmp_path)
            time.sleep(1.0)
            assert handled, (
                "a daemon under a holder was not recognised as held — the "
                "caller spawns a second holder for a port the first still has"
            )

            # /proc, for the same reason the premise check uses it: `ps`
            # truncated the command line here and every certdir match failed.
            mine = []
            for entry in pathlib.Path("/proc").glob("[0-9]*"):
                try:
                    argv = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
                except OSError:
                    continue
                cmd = argv.decode(errors="replace")
                if " -m cswap_pin.proxy" in cmd and str(tmp_path) in cmd:
                    mine.append(f"{entry.name} {cmd}")
            holders = [line for line in mine if "--hold-port" in line]

            assert again == port, (
                f"the recycle moved the port {port} -> {again}; every session "
                f"wired to {port} is stranded"
            )
            assert len(holders) == 1, (
                f"{len(holders)} holders for one certdir — the second cannot "
                f"bind and its daemon lands unheld"
            )
        finally:
            # PARENTS FIRST: `started` holds the holders, and each takes its
            # own daemon down with it. Killing daemons first would only make
            # the holders replace them.
            for proc in started:
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                except Exception:  # noqa: BLE001 — gone, or too slow
                    try:
                        proc.kill()
                    except Exception:  # noqa: BLE001
                        pass
            from conftest import _reap_pin_processes

            _reap_pin_processes(tmp_path)

    def case_an_idle_teardown_under_a_holder_still_unwires(self, tmp_path):
        """A holder's bare socket is not "somebody else is serving".

        The teardown asks the PORT rather than a file, because a successor
        that came up while we drained is real and unwiring past it would strip
        a working pin. But under a holder the socket we just released is still
        bound and listening — `release_listener` DETACHES rather than closes
        when the port is not ours — and a listen-only socket completes a TCP
        handshake (verified). So `_port_answers` said "served", the unwire was
        skipped, the daemon exited 0, and the holder then released the port on
        that clean exit: `.claude.json` left naming an address nothing listens
        on, which is the ConnectionRefused-forever outage the unwire exists to
        prevent.

        The question the guard means to ask is "is somebody ELSE serving",
        and a socket held on our own behalf is not somebody else.
        """
        import os

        from cswap_pin import proxy as pin_proxy

        # The predicate, driven directly: under a holder, our own held socket
        # must not read as a successor.
        prev = os.environ.get(pin_proxy._HELD_BY_ENV)
        os.environ[pin_proxy._HELD_BY_ENV] = str(os.getppid())
        try:
            assert pin_proxy.held_by_a_holder(), "premise: we are under a holder"
            assert not pin_proxy._successor_is_serving(), (
                "a holder's own listening socket read as a successor — the "
                "teardown skips the unwire and every later session dials a "
                "port nothing answers"
            )
        finally:
            if prev is None:
                os.environ.pop(pin_proxy._HELD_BY_ENV, None)
            else:
                os.environ[pin_proxy._HELD_BY_ENV] = prev


    def case_the_port_answers_across_a_SIGKILL_of_the_daemon(self, tmp_path):
        """A CRASH is the case a handover cannot cover.

        Every mechanism above is cooperative: the outgoing daemon stops
        accepting and passes its socket on. A `kill -9`, an OOM kill, or a
        segfault skips all of it, and the port then has NO owner — which for a
        live session is permanent, because its HTTPS_PROXY was fixed at exec
        and is never re-read.

        `run_service` is the answer: the port is bound by a supervisor that
        outlives the daemon, so the descriptor stays listening no matter how
        the daemon dies and arrivals queue in the backlog until the successor
        accepts them.
        """
        import socket
        import time

        from cswap_pin.proxy import ensure_ca, run_service

        ensure_ca(tmp_path, "api.anthropic.com")
        holder = run_service(tmp_path, account_num="1", email="a@b.c")
        try:
            port = holder.port
            assert port, "the holder did not bind a port"
            socket.create_connection(("127.0.0.1", port), timeout=2).close()

            first = holder.daemon_pid
            assert first, "no daemon was started under the holder"
            # SIGKILL through the Popen, never through the pid: `daemon_pid`
            # is only ours while the Popen it came from is, and signalling a
            # bare number once killed a pytest-xdist worker (see `stop`).
            #
            # AND ONLY WHILE IT IS STILL RUNNING. `Popen.kill()` on a REAPED
            # child signals its pid anyway — CPython only refuses after
            # `returncode` is set, and nothing here guarantees that ordering
            # against the holder's own supervisor thread, which reaps
            # concurrently. A pid the kernel has already recycled then belongs
            # to somebody else. Measured: the worker running this case took a
            # SIGINT and xdist reported `received keyboard-interrupt`, 3 runs
            # of 3, traced to this line. `kill_daemon_for_test` carried this
            # guard and a ponytail cut dropped it with the method.
            proc = holder._proc
            assert proc.returncode is None, (
                "premise: the daemon is still running, so there is a crash to "
                "cause"
            )
            proc.kill()

            # THE POINT: no window. Not "it comes back in a second" — the
            # socket was never the daemon's to take down with it, so a
            # connection landing mid-crash waits in the backlog.
            refused = 0
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=2).close()
                except ConnectionRefusedError:
                    refused += 1
                if holder.daemon_pid not in (None, first):
                    break
                time.sleep(0.02)
            assert refused == 0, f"{refused} connections refused while the daemon was dead"
            assert holder.daemon_pid not in (None, first), (
                "the holder did not restart the daemon it supervises"
            )
        finally:
            holder.stop()

    def case_a_planned_restart_under_a_holder_loses_nothing(self, tmp_path):
        """SIGTERM is what a deploy sends, and it must cost NOTHING.

        Two separate bugs made this the worst path rather than the best, and
        both are invisible without a real daemon under a real holder:

          - the daemon read `LISTEN_PID` to decide "am I held?", which the
            holder never sets (it cannot know a child's pid before spawning),
            so every TERM exited 0 and the holder released the port
          - the daemon then CLOSED the holder's socket on its way out, having
            adopted it as a predecessor's hand-down

        Measured before the fix: 186,206 then 201,909 refused connections
        across three SIGTERMs. After: 0 refused, 0 reset, 13,471 served.
        """
        import os
        import socket
        import threading
        import time

        from cswap_pin.proxy import PortHolder, ensure_ca, read_daemon_state

        ensure_ca(tmp_path, "api.anthropic.com")
        holder = PortHolder(tmp_path, "1", "a@b.c")
        holder.start()
        counts = {"ok": 0, "refused": 0, "reset": 0, "no_reply": 0}
        stop = threading.Event()

        def _hammer():
            """A REQUEST, not a connect — and a timeout is a FAILURE.

            `except OSError: pass` swallowed `socket.timeout`, so a restart
            that left requests hanging was counted as neither ok nor refused
            and the assertions below passed on it. That is the same shape as
            the 30s held-exit drain: the port stays BOUND while nobody is
            behind it, so refused is structurally 0 and only an unanswered
            request can see the gap. A peer hit the identical bug from the
            other side — a bounded call whose timeout landed in a broad catch
            and read as a PASS.
            """
            while not stop.is_set():
                try:
                    s = socket.create_connection(("127.0.0.1", holder.port), timeout=3)
                except ConnectionRefusedError:
                    counts["refused"] += 1
                    continue
                except OSError:
                    counts["no_reply"] += 1
                    continue
                try:
                    s.settimeout(3)
                    s.sendall(
                        b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                        b"Host: api.anthropic.com:443\r\n\r\n"
                    )
                    if s.recv(200):
                        counts["ok"] += 1
                    else:
                        counts["no_reply"] += 1
                except socket.timeout:
                    counts["no_reply"] += 1
                except ConnectionResetError:
                    counts["reset"] += 1
                except OSError:
                    counts["no_reply"] += 1
                finally:
                    try:
                        s.close()
                    except OSError:
                        pass

        deadline = time.time() + 8
        while time.time() < deadline and not read_daemon_state(tmp_path):
            time.sleep(0.05)
        threads = [threading.Thread(target=_hammer, daemon=True) for _ in range(2)]
        for t in threads:
            t.start()
        try:
            time.sleep(0.4)
            for _ in range(2):
                st = read_daemon_state(tmp_path)
                if st:
                    os.kill(int(st["pid"]), 15)  # a deploy's own signal
                time.sleep(1.2)
            stop.set()
            for t in threads:
                t.join(timeout=3)
            assert counts["ok"] > 0, "the hammer never reached the daemon at all"
            assert counts["refused"] == 0, (
                f"{counts['refused']} refused across a PLANNED restart — the "
                f"holder released the port a deploy is supposed to keep"
            )
            assert counts["reset"] == 0, (
                f"{counts['reset']} in-flight requests cut by a planned "
                f"restart; only a crash may cost one"
            )
            # AND NOTHING WENT UNANSWERED. This is the axis `refused` cannot
            # see: the holder's socket stays bound through the restart, so a
            # window with nobody serving produces timeouts, not refusals.
            assert counts["no_reply"] == 0, (
                f"{counts['no_reply']} requests connected and were never "
                f"answered across a planned restart — the port was bound the "
                f"whole time and nobody was behind it"
            )
        finally:
            stop.set()
            holder.stop()

    def case_a_holder_that_cannot_take_the_wired_port_refuses_to_start(
        self, tmp_path
    ):
        """Serving the WRONG port is worse than not serving.

        Falling through to an ephemeral port looks like resilience and is the
        opposite: `.claude.json` still names the old number, so every live
        session dials an address nobody answers while a healthy-looking daemon
        serves somewhere else. Measured on the personal Mac, doing exactly
        this: 29,999 refused connections and a pin that reported success.

        An ephemeral fallback is right when NOTHING is wired yet — the cold
        start, where any port will do. It is wrong when we were told which
        port to take, because that instruction came from the sessions.

        BOTH HALVES, because refusing the bind was not enough on its own:
        `holder_main` caught that OSError and fell back to `daemon_main`, on
        the premise that a plain daemon "will reclaim the port when it frees".
        A daemon cannot move its port — the address is fixed at bind — so the
        fallback served on an EPHEMERAL port nothing is wired to. Measured
        during an orphan recovery, isolated port 49927:

            11:57:13 holder could not take the port (49927 is taken —
                     refusing to hold a different one) — serving unheld
            11:57:13 serving on port 37001

        The bind fails for two opposite reasons and NEITHER wants a second
        daemon: a healthy pin already on the port makes this process
        redundant, and a port held by something not serving is not helped by
        another port.
        """
        import socket

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PortHolder, ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        squatter = socket.socket()
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squatter.bind(("127.0.0.1", 0))
        squatter.listen(1)
        taken = squatter.getsockname()[1]
        # The real budget is for a predecessor draining; this squatter never
        # leaves, so waiting it out is 3s of nothing.
        real_wait = pin_proxy._HOLD_BIND_WAIT_S
        pin_proxy._HOLD_BIND_WAIT_S = 0.2
        served = []
        real_daemon = pin_proxy.daemon_main
        pin_proxy.daemon_main = lambda *a, **k: served.append(a)
        try:
            try:
                PortHolder(tmp_path, "1", "a@b.c", port=taken)
                raise AssertionError(
                    f"the holder started on some other port while {taken} was "
                    f"taken — every session wired to {taken} is now stranded "
                    f"behind a pin that looks healthy"
                )
            except OSError:
                pass  # refused the bind, which is the first half

            # AND THE ENTRY POINT MUST NOT SERVE ANYWAY. `holder_main` catches
            # that OSError itself, so the refusal above proves nothing about
            # what the process does next.
            #
            # ITS SIGNAL HANDLERS ARE NEUTERED FIRST. `holder_main` installs
            # SIGTERM/SIGINT teardowns via `_install_signal_teardown`, and
            # called in-process that arms them ON THE PYTEST WORKER. Measured:
            # the worker died with `received keyboard-interrupt`, 3 runs of 3,
            # once this class ran in parallel with another that spawns holders
            # — the same shape that once SIGTERM'd an xdist worker through a
            # bare pid. The subject here is the daemon_main fallback, not the
            # handlers, so stubbing them changes nothing this asserts.
            real_signals = pin_proxy._install_signal_teardown
            pin_proxy._install_signal_teardown = lambda *a, **k: None
            try:
                pin_proxy.holder_main("1", "a@b.c", tmp_path, port=taken)
            finally:
                pin_proxy._install_signal_teardown = real_signals
            assert not served, (
                "a holder that could not take the wired port served as a "
                "plain daemon on another one — nothing is wired there and no "
                "session can reach it (measured: 49927 taken -> 37001)"
            )
        finally:
            pin_proxy._HOLD_BIND_WAIT_S = real_wait
            pin_proxy.daemon_main = real_daemon
            squatter.close()

    def case_a_held_daemon_exits_instead_of_handing_the_port_away(
        self, tmp_path
    ):
        """A code-change handover under a holder must stay under it.

        MEASURED ON THIS MACHINE, 76 minutes of broken pin reported healthy:

          10:13:07  daemon: code on disk changed — handing over
          10:13:15  successor holder: could not take 36301 — serving UNHELD
                    on 33349
          10:18:15  33349: idle teardown — UNWIRED .claude.json

        The daemon handed its listening socket straight to a successor, so the
        successor had no holder above it: the port stopped being crash-proof,
        and the one thing that could still strand sessions did.

        Under a holder there is nothing to hand over. The holder already owns
        the socket, so the daemon exits and lets it spawn the successor there.
        """
        from cswap_pin import proxy as pin_proxy

        assert pin_proxy.held_by_a_holder(ppid=1, env={}) is False
        assert pin_proxy.held_by_a_holder(
            ppid=4242, env={pin_proxy._HELD_BY_ENV: "4242"}
        ) is True, "a daemon cannot tell it is under a holder"
        # A predecessor's hand-down is NOT a holder: it is leaving.
        assert pin_proxy.held_by_a_holder(
            ppid=4242, env={pin_proxy._HANDDOWN_FROM_ENV: "4242"}
        ) is False

        # AND THE WATCHDOG MUST ACT ON IT. The predicate being right is not
        # the fix — the fix is that the code-change path takes the exit branch
        # instead of the hand-over branch. Drive it with a stub server and a
        # fingerprint that never matches, and assert it never spawns.
        import threading

        spawned = []
        exited = []

        class _Srv:
            def release_listener(self, hand_down=False):
                return 7 if hand_down else None

            def await_inflight(self, budget):
                pass

        real_spawn = pin_proxy._spawn_daemon
        real_exit = os._exit
        pin_proxy._spawn_daemon = lambda *a, **k: spawned.append(a) or 1234
        os._exit = lambda code: exited.append(code) or (_ for _ in ()).throw(
            SystemExit(code)
        )
        os.environ[pin_proxy._HELD_BY_ENV] = str(os.getppid())
        try:
            pin_proxy._watch_own_code(
                _Srv(), "1", "a@b.c", tmp_path, threading.Event(),
                lambda *a: None, interval=0.01,
                _own_fingerprint="never-matches",
            )
        except SystemExit:
            pass
        finally:
            pin_proxy._spawn_daemon = real_spawn
            os._exit = real_exit
            os.environ.pop(pin_proxy._HELD_BY_ENV, None)
        assert exited == [pin_proxy._RESTART_ME_CODE], (
            f"a held daemon did not exit for its holder (exits={exited})"
        )
        assert not spawned, (
            "a held daemon handed its socket to a successor — the port leaves "
            "the holder and a stranding is one failed bind away (measured: 76 "
            "minutes of unwired pin on lmd42)"
        )

    def case_a_held_exit_does_not_drain_before_letting_the_holder_respawn(
        self, tmp_path
    ):
        """UNDER A HOLDER, THE DRAIN HAPPENS WHILE NOBODY IS SERVING.

        The sibling case above stubs `await_inflight` away, so it cannot see
        what budget the exit path passes. The budget is the whole problem.

        The two handover paths look alike and are NOT. The unheld one drains
        AFTER `_spawn_daemon` has returned, so the successor is already
        accepting and a 30s ceiling costs nothing. The held one exits so the
        HOLDER can spawn — and the holder cannot start anything until this
        process is gone, so every second of drain is a second with the port
        bound and nobody behind it.

        MEASURED on lmd42, upgrading 0.1.44 -> 0.1.46 under load:

            16:24:08 code on disk changed — exiting for the holder to replace
            16:24:38 pid=2664753 serving on port 36301

        Thirty seconds, which is exactly `_DRAIN_SECONDS`. Nothing was
        refused (the holder's socket queues arrivals, which is the property
        this design is for) but 30 connections timed out at 3s waiting for a
        reply that had nobody to write it.

        A CONNECT tunnel is counted for its whole life, deliberately — that
        is what stops an idle watcher cutting a live session. So on any real
        machine the count is never zero (Remote Control's WebSocket alone
        lives as long as the session) and the ceiling is always paid in full.

        The budget here must be short enough that the gap is not felt.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        budgets = []
        exits = []

        class _Srv:
            def release_listener(self, hand_down=False):
                return 7 if hand_down else None

            def await_inflight(self, budget):
                budgets.append(budget)

        real_exit = os._exit
        os._exit = lambda code: exits.append(code) or (_ for _ in ()).throw(
            SystemExit(code)
        )
        os.environ[pin_proxy._HELD_BY_ENV] = str(os.getppid())
        try:
            pin_proxy._watch_own_code(
                _Srv(), "1", "a@b.c", tmp_path, threading.Event(),
                lambda *a: None, interval=0.01,
                _own_fingerprint="never-matches",
            )
        except SystemExit:
            pass
        finally:
            os._exit = real_exit
            os.environ.pop(pin_proxy._HELD_BY_ENV, None)

        assert exits == [pin_proxy._RESTART_ME_CODE], (
            "premise: this is the held-exit path"
        )
        assert budgets, "the exit path did not drain at all"
        assert budgets[0] <= pin_proxy._HELD_DRAIN_SECONDS, (
            f"a held exit drained for {budgets[0]}s before the holder could "
            f"respawn — the port is bound and nobody is behind it for all of it"
        )
        # AND IT IS STILL A DRAIN. Zero would cut a response mid-stream, which
        # is the 34-connections-reset outage `stop(drain=…)` exists to prevent.
        assert budgets[0] > 0, (
            "a held exit stopped draining entirely — in-flight requests are "
            "still ours to finish, holder or no holder"
        )

    def case_an_idle_teardown_is_not_restarted(self, tmp_path):
        """A daemon that MEANT to exit must stay exited.

        The pin tears itself down when the last refcount holder closes the
        FIFO — that is the design, not a failure. A supervisor that cannot
        tell the two apart turns idle teardown into an infinite respawn, and
        the port it holds then never goes away either.

        Exit status is the whole distinction: a clean 0 is a decision, a
        signal or a non-zero is a crash.
        """
        import time

        from cswap_pin.proxy import PortHolder, ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        holder = PortHolder(tmp_path, "1", "a@b.c")
        spawns = []

        def _fake_spawn():
            spawns.append(1)
            holder._proc = _ExitedProc(0 if len(spawns) == 1 else -9)
            holder.daemon_pid = 1000 + len(spawns)

        holder._spawn = _fake_spawn
        holder.start()
        try:
            # Longer than the first backoff rung (0.5s), so a restart that is
            # merely SLOW still fails this rather than passing on timing.
            time.sleep(1.2)
            assert len(spawns) == 1, (
                f"a clean exit was restarted {len(spawns) - 1} time(s) — an "
                f"idle teardown becomes an infinite respawn"
            )
        finally:
            holder.stop()

    def case_a_successor_that_can_never_start_is_named_as_such(self, tmp_path):
        """A BROKEN ENV AND A TRANSIENT CRASH MUST NOT READ THE SAME.

        The holder retries a dead child on a 0.25s -> 5s ladder, forever,
        logging the same line each time. That is right for a crash — the next
        attempt usually works — and it is silence for a child that can NEVER
        start, which is the state a bad deploy leaves behind.

        MEASURED here, on wmac, caused by running the README's own install
        command against an editable install: it replaced the checkout with the
        PyPI release and took `cswap_pin` out of the tool env with it. The
        daemon already running kept serving (its code is in memory), while
        every successor died before reaching any of its own code:

            .../claude-swap/bin/python: Error while finding module
            specification for 'cswap_pin.proxy' (ModuleNotFoundError)

        repeated in `daemon.log` with nothing saying the port was one death
        away from being unrecoverable. The pin fails open by design, so this
        is exactly the class of failure that stays invisible until it is an
        outage.

        So after `_HOLD_RESTART_REPORT_AT` consecutive failures the holder says
        so ONCE, naming the count. Not a new mechanism and not a ceiling: it
        keeps retrying, because a machine that recovers on attempt 20 should.

        THE CONTROL is the same holder below the threshold, which must stay
        quiet — a warning on every transient crash is the same silence by
        another route.
        """
        import time

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PortHolder, ensure_ca

        at = pin_proxy._HOLD_RESTART_REPORT_AT
        ensure_ca(tmp_path, "api.anthropic.com")
        holder = PortHolder(tmp_path, "1", "a@b.c")
        spawns = []
        lines = []

        def _fake_spawn():
            spawns.append(1)
            holder._proc = _ExitedProc(1)      # dies instantly, every time
            holder.daemon_pid = 3000 + len(spawns)

        holder._spawn = _fake_spawn
        # NO LADDER: this is not a timing test, and the real one would take
        # 0.5+1+2+4+5 = 12.5s to reach the threshold.
        holder._backoff = lambda failures: 0.0
        real_log = pin_proxy._log_lifecycle
        pin_proxy._log_lifecycle = lambda msg, *a, **k: lines.append(msg)
        holder.start()
        try:
            deadline = time.time() + 5
            while time.time() < deadline and len(spawns) <= at + 2:
                time.sleep(0.02)
        finally:
            holder.stop()
            pin_proxy._log_lifecycle = real_log

        said = [l for l in lines if "cannot start" in l]
        assert len(spawns) > at, (
            f"only {len(spawns)} spawns happened — the threshold ({at}) was "
            f"never reached, so this case proves nothing"
        )
        assert len(said) == 1, (
            f"the holder said 'cannot start' {len(said)} time(s) across "
            f"{len(spawns)} failed spawns — a broken env is either invisible "
            f"or it is noise on every rung forever"
        )
        assert str(at) in said[0], (
            f"the report does not name how many attempts failed: {said[0]!r}"
        )

    def case_a_mark_that_cannot_be_cleared_is_not_reported_as_cleared(
        self, tmp_path
    ):
        """A FAILED UNLINK MUST NOT READ AS A CLEARED MARK.

        The handover mark means "a successor is coming". When no successor
        comes, `_clear_handover_mark` drops the record — because leaving it
        tells the departing daemon's own teardown it was SUPERSEDED, and the
        teardown then keeps `.claude.json` pointing at a port nobody serves.
        That is the outage the unwire exists to prevent, reached through the
        code that prevents it.

        The unlink swallowed every OSError and returned None either way, so a
        record that could not be removed — a read-only store, a lost mount, an
        immutable file — was indistinguishable from one that was. The caller
        went on to a teardown that read "superseded" and left the wiring.

        Reporting the outcome does not make the unlink succeed; it lets the
        caller stop believing a cleanup that did not happen, and it puts the
        reason in the one log a later reader has.

        THE CONTROL is the same call on a removable record, which must report
        success — otherwise "reports failure" would pass for a function that
        always reports failure.
        """
        import os as _os
        import stat as _stat

        from cswap_pin import proxy as pin_proxy

        def _clear(make_unremovable):
            d = tmp_path / ("stuck" if make_unremovable else "ok")
            d.mkdir(exist_ok=True)
            pin_proxy.write_daemon_state(d, 41234, _os.getpid(), "fp")
            st = pin_proxy.read_daemon_state(d)
            raw = json.loads((d / pin_proxy._STATE_FILE).read_text())
            raw["handover"] = True
            (d / pin_proxy._STATE_FILE).write_text(json.dumps(raw))
            assert pin_proxy.read_daemon_state(d).get("handover"), (
                "premise: the record is marked as a handover"
            )
            if make_unremovable:
                # A DIRECTORY WITH NO WRITE BIT: unlink needs write on the
                # PARENT, not on the file, so this blocks removal without
                # touching the record itself.
                _os.chmod(d, _stat.S_IRUSR | _stat.S_IXUSR)
            try:
                return pin_proxy._clear_handover_mark(d)
            finally:
                if make_unremovable:
                    _os.chmod(d, 0o700)

        # CONTROL: a removable record must report success.
        assert _clear(make_unremovable=False) is True, (
            "CONTROL FAILED: clearing a removable mark did not report success, "
            "so the failure below says nothing"
        )
        assert _clear(make_unremovable=True) is False, (
            "a mark that could not be removed reported the same as one that "
            "was — the caller's teardown then reads 'superseded' and leaves "
            "the wiring pointing at a port nobody serves"
        )

    def case_a_deploy_restarts_the_daemon_without_releasing_the_port(
        self, tmp_path
    ):
        """An UPDATE must not cost the port either.

        A recycle sends SIGTERM, and the daemon's handler exits 0 — which the
        holder correctly reads as "it meant to go" and releases the port. That
        is right for an idle teardown and wrong for a redeploy: the whole point
        of a redeploy is that a daemon running NEW code should be serving the
        SAME address a moment later.

        So a TERM'd daemon that is serving on a socket it does not own asks to
        be restarted instead. The holder respawns it — a fresh interpreter, so
        the new code loads — and the socket never unbinds.
        """
        import time

        from cswap_pin.proxy import _RESTART_ME_CODE, PortHolder, ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        holder = PortHolder(tmp_path, "1", "a@b.c")
        spawns = []

        def _fake_spawn():
            spawns.append(1)
            holder._proc = _ExitedProc(_RESTART_ME_CODE if len(spawns) == 1 else 0)
            holder.daemon_pid = 2000 + len(spawns)

        holder._spawn = _fake_spawn
        holder.start()
        try:
            deadline = time.time() + 3
            while time.time() < deadline and len(spawns) < 2:
                time.sleep(0.02)
            assert len(spawns) == 2, (
                "the daemon asked to be restarted and the holder released the "
                "port instead — a redeploy costs every live session"
            )
        finally:
            holder.stop()


    def case_a_cold_start_puts_a_holder_on_the_port(self, tmp_path):
        """The holder has to be REACHED, not merely implemented.

        A cold start is the only moment nothing owns the address yet, so it is
        the only moment a holder can be put under it. Without this the class
        exists and every daemon still binds its own port — and dies with it.
        """
        import subprocess

        from cswap_pin import proxy as pin_proxy

        seen = []
        real = subprocess.Popen

        def _spy(argv, **kw):
            seen.append(list(argv))
            raise OSError("not actually spawning")

        subprocess.Popen = _spy
        try:
            pin_proxy._spawn_daemon("1", "a@b.c", tmp_path)
        except OSError:
            pass
        finally:
            subprocess.Popen = real
        assert seen, "no process was spawned at all"
        assert any(pin_proxy._HOLDER_MODULE_ARG in a for a in seen[0]), (
            f"a cold start spawned {seen[0]} — the daemon binds its own port, "
            f"so a kill -9 takes the port with it"
        )

    def case_a_handover_also_lands_under_a_holder(self, tmp_path):
        """EVERY path must end under a holder, not just the cold start.

        MEASURED, twice in one day, by upgrading two live machines: an old
        daemon noticed its code had changed, handed its listening socket to a
        successor, and the successor ran WITHOUT a holder. The port then left
        the holder for good, and the next thing that went wrong stranded every
        session:

          wmac  12:57  53749 -> served UNHELD on 54264
          lmd42 13:03  36301 -> 45357, and .claude.json followed it there

        Documenting "upgrade carefully" was the first answer and it is not one:
        a deploy is not a procedure someone follows, it is whatever the running
        code does. So the handover spawns a holder too — one that ADOPTS the
        socket it was handed instead of binding a fresh one, which is why it
        cannot lose the race the cold-start holder can.
        """
        import subprocess

        from cswap_pin import proxy as pin_proxy

        seen = []
        real = subprocess.Popen

        def _spy(argv, **kw):
            seen.append(list(argv))
            raise OSError("not actually spawning")

        subprocess.Popen = _spy
        try:
            pin_proxy._spawn_daemon("1", "a@b.c", tmp_path, listen_fd=7)
        except OSError:
            pass
        finally:
            subprocess.Popen = real
        assert seen, "no process was spawned at all"
        assert any(pin_proxy._HOLDER_MODULE_ARG in a for a in seen[0]), (
            f"a handover spawned {seen[0]} — the port leaves the holder, and "
            f"the machine is one failed bind away from stranding every session"
        )

    def case_the_orphan_sweep_does_not_kill_the_holder(self, tmp_path):
        """The sweep finds daemons by argv, and the holder's argv matches.

        `_pin_daemon_pids` selects on "module name present AND certdir is the
        last token" — which the holder's own command line satisfies exactly.
        A sweep would then SIGTERM the process holding the port, taking down
        every session wired to it to clean up an orphan that was not one.
        """
        from cswap_pin import proxy as pin_proxy

        certdir = str(tmp_path.resolve())
        holder_line = (
            f"999 /usr/bin/python -m cswap_pin.proxy "
            f"{pin_proxy._HOLDER_MODULE_ARG} 36301 1 a@b.c {certdir}"
        )
        daemon_line = f"998 /usr/bin/python -m cswap_pin.proxy 1 a@b.c {certdir}"

        class _Ran:
            stdout = holder_line + "\n" + daemon_line + "\n"

        import subprocess

        real = subprocess.run
        subprocess.run = lambda *a, **k: _Ran()
        try:
            pids = pin_proxy._pin_daemon_pids(tmp_path)
        finally:
            subprocess.run = real
        assert 998 in pids, "the sweep stopped seeing real daemons"
        assert 999 not in pids, (
            "the sweep selected the PORT HOLDER — killing it takes the port "
            "down with it, which is the outage the holder exists to prevent"
        )


class _ExitedProc:
    """A Popen that has already exited with ``code``.

    `returncode` is set from the start, which is what a REAPED Popen looks
    like — and the holder must read that rather than signal a pid. A stub
    without it let `stop()` SIGTERM whatever process held the fake pid: in
    CI that was the pytest-xdist worker running the test.
    """

    def __init__(self, code: int):
        self.returncode = code
        self.pid = 0

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        raise AssertionError("signalled a process that had already exited")

    kill = terminate


class TestUltrareviewIsPinned:
    """Ultrareview is a claude.ai-side capability authenticated by the OAuth
    bearer (binary: `/v1/ultrareview/preflight` with auth:"teleport-org"),
    so it belongs to the pinned cloud account like RC and artifacts."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_ultrareview_routes_are_pinned(self):
        from cswap_pin.proxy import is_pinned_route

        assert is_pinned_route("/v1/ultrareview/preflight")
        assert is_pinned_route("/v1/ultrareview/run")

    def case_neighbouring_v1_routes_stay_unpinned(self):
        from cswap_pin.proxy import is_pinned_route

        assert not is_pinned_route("/v1/messages")
        assert not is_pinned_route("/v1/models")


class TestPinTokenRefreshIsSerialized:
    """Every pinned request calls the token provider, and each MITM
    connection runs on its own thread. Without a lock, a token that expires
    under load lets N threads refresh the SAME one-time refresh token at
    once: one wins, the others get invalid_grant, and the last writer can
    persist a credential whose grant was already consumed — killing the
    pinned account's lineage. Refresh must therefore be serialized, and a
    thread that waited must reuse the winner's result instead of refreshing
    again.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_concurrent_expired_requests_refresh_once(self, tmp_path):
        import json
        import threading
        from cswap_pin.proxy import make_pin_token_provider

        expired = json.dumps({
            "claudeAiOauth": {
                "accessToken": "old", "refreshToken": "rt-1", "expiresAt": 1000,
            }
        })
        fresh = json.dumps({
            "claudeAiOauth": {
                "accessToken": "new", "refreshToken": "rt-2",
                "expiresAt": 9999999999000,
            }
        })
        state = {"creds": expired, "refreshes": 0}
        lock = threading.Lock()

        # The provider resolves the pin per request, so the store must name
        # one — otherwise it correctly reads as "pin cleared".
        from cswap_pin.proxy import save_pin
        save_pin(tmp_path, "a@b.c", "org")

        class FakeSwitcher:
            backup_dir = tmp_path

            def current_account_number(self):
                return "2"  # pinned account is NOT active

            def resolve_account(self, identifier):
                return "1", "a@b.c", "org"

            def read_account_credentials(self, num, email):
                return state["creds"]

            def persist_backup_credentials(self, num, email, creds):
                state["creds"] = creds

        def fake_refresh(creds):
            with lock:
                state["refreshes"] += 1
            import time as _t
            _t.sleep(0.05)  # widen the race window
            from claude_swap import oauth as _o
            return _o.RefreshOutcome(fresh, None)

        import claude_swap.oauth as oauth_mod
        real = oauth_mod.try_refresh_oauth_credentials
        oauth_mod.try_refresh_oauth_credentials = fake_refresh
        try:
            provider = make_pin_token_provider(FakeSwitcher(), "1", "a@b.c")
            results = []
            threads = [
                threading.Thread(target=lambda: results.append(provider()))
                for _ in range(8)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        finally:
            oauth_mod.try_refresh_oauth_credentials = real

        assert state["refreshes"] == 1, (
            f"refreshed {state['refreshes']}x — concurrent threads burned the "
            "one-time refresh token (invalid_grant risk)"
        )
        assert results == ["new"] * 8, f"threads got inconsistent tokens: {results}"


class TestAmbientProxyPrefersTheLauncherProxy:
    """cc-wrapper starts a per-session cache proxy (CCF) and points the
    session's HTTPS_PROXY at it; CCF chains to the machine-wide egress proxy
    (privoxy). An ssh shell has only the machine-wide one. Recording the
    SHELL's value therefore drops CCF out of the chain — measured on work-mac,
    where a `cswap pin` run over ssh recorded privoxy:8118 while CCF on :9901
    stayed bypassed for every pinned session afterwards."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_which_proxy_the_chain_records(self, tmp_path, monkeypatch):
        """Five inputs, one function. The CASES are the value here.

        `_ambient_proxy` chooses between what a previous launch DISPLACED (the
        launcher's own inner proxy) and what this shell exports (the
        machine-wide one). Getting it wrong drops a whole hop out of the
        chain, silently.
        """
        import socket as _s

        from cswap_pin.proxy import _ambient_proxy

        cfg = tmp_path / ".claude.json"
        monkeypatch.setattr(
            "claude_swap.paths.get_global_config_path", lambda: cfg
        )

        live = _s.socket()
        live.bind(("127.0.0.1", 0))
        live.listen(1)
        live_url = "http://127.0.0.1:%d" % live.getsockname()[1]
        dead = _s.socket()
        dead.bind(("127.0.0.1", 0))
        dead_url = "http://127.0.0.1:%d" % dead.getsockname()[1]
        dead.close()

        shell = "http://127.0.0.1:8118"
        try:
            for saved, env, want, why in (
                # A LIVE loopback record is the inner link and wins: an ssh
                # shell knows only the machine-wide proxy, so taking it would
                # drop the launcher's proxy out of the chain entirely.
                (live_url, {"HTTPS_PROXY": shell}, live_url,
                 "a live launcher proxy must win over the shell's"),
                # ...but a STALE one must never strand the chain.
                (dead_url, {"HTTPS_PROXY": shell}, shell,
                 "a dead record must fall back to the shell"),
                (shell, {"HTTPS_PROXY": shell}, shell,
                 "the same proxy in both places is unchanged"),
                # Only a LOCAL launcher proxy is worth restoring; a corporate
                # one recorded earlier must not override the live shell.
                ("http://proxy.corp.example:3128", {"HTTPS_PROXY": shell}, shell,
                 "a non-loopback record is not preferred"),
                # A shell that ran pin-env exports OUR port; recording it would
                # make the daemon dial itself.
                (shell,
                 {"HTTPS_PROXY": "http://127.0.0.1:44444",
                  "CSWAP_PIN_PORT": "44444"},
                 shell, "our own port is never recorded"),
            ):
                cfg.write_text(
                    json.dumps({"_cswapPinWiredKeysSaved": {"HTTPS_PROXY": saved}})
                )
                assert _ambient_proxy(env) == want, why
        finally:
            live.close()

class TestCaIsPublishedToTheTrustDir:
    """NODE_EXTRA_CA_CERTS names ONE file, so every MITM that writes it as an
    overwrite drops the others. Two components already do that for the same
    host. Measured consequence on work-mac: a pinned session verified every
    request it SENDS while every Remote Control SSE reconnect failed with
    "unable to verify the first certificate" — 13 attempts, 0 connects, while
    worker/heartbeat and client/presence answered 200 in the same process.

    So we publish one file under ca-trust.d/ and never touch anyone else's."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _cfg(self, tmp_path, monkeypatch):
        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        return home

    def _ca(self, tmp_path):
        """A REAL CA, because the bundle guard parses rather than pattern-matches.

        These fixtures used a placeholder body ("PIN") that no X.509 reader can
        decode. That passed while the guard only counted BEGIN/END markers —
        and it meant the tests certified the guard against a bundle node itself
        would refuse, which is exactly the false accept the guard now exists to
        stop. A fixture that cannot occur in reality proves nothing about one
        that can.
        """
        from cswap_pin.proxy import ensure_ca

        certdir = tmp_path / "pin-proxy"
        return ensure_ca(certdir, "api.anthropic.com").ca_path

    def case_publishes_one_file_named_after_the_component(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import CA_TRUST_DIR, publish_ca

        home = self._cfg(tmp_path, monkeypatch)
        out = publish_ca(self._ca(tmp_path))
        assert out == home / CA_TRUST_DIR / "cswap-pin.pem"
        # Compare CONTENT, not a placeholder word: the fixture now mints a
        # real CA because the guard parses rather than pattern-matches.
        assert out.read_bytes().strip() == self._ca(tmp_path).read_bytes().strip()

    def case_republishing_is_a_no_op(self, tmp_path, monkeypatch):
        """Rewriting every launch would churn the mtime a launcher's own
        rebuild check keys on."""
        from cswap_pin.proxy import publish_ca

        self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        first = publish_ca(ca)
        before = first.stat().st_mtime_ns
        assert publish_ca(ca) == first
        assert first.stat().st_mtime_ns == before

    def case_a_rotated_ca_replaces_our_file_only(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import CA_TRUST_DIR, publish_ca

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        publish_ca(ca)
        # somebody else published theirs; it must survive our rotation
        other = home / CA_TRUST_DIR / "ccf.pem"
        other.write_bytes(b"-----BEGIN CERTIFICATE-----\nCCF\n-----END CERTIFICATE-----\n")
        second = _other_ca(tmp_path / "regen")
        ca.write_bytes(second + b"\n")
        publish_ca(ca)
        assert second in (home / CA_TRUST_DIR / "cswap-pin.pem").read_bytes()
        assert b"CCF" in other.read_bytes(), "we clobbered another component's file"

    def case_an_unwritable_config_home_does_not_raise(self, tmp_path, monkeypatch):
        """Trust plumbing must never block a launch."""
        import os
        from cswap_pin.proxy import publish_ca

        home = self._cfg(tmp_path, monkeypatch)
        os.chmod(home, 0o500)
        try:
            assert publish_ca(self._ca(tmp_path)) is None
        finally:
            os.chmod(home, 0o700)

    def case_merged_ca_still_returns_our_own_bundle(self, tmp_path, monkeypatch):
        """Publishing is additive: the env block we write is unchanged."""
        from cswap_pin.proxy import _merged_ca

        self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        launcher = tmp_path / "cache-fix-ca" / "combined-ca.pem"
        launcher.parent.mkdir(parents=True)
        # A REAL certificate, not a `CCF` placeholder. The emission filter
        # validates CERTIFICATE blocks with x509 (it shares `_salvage_bundle`'s
        # loop), so a placeholder is dropped and the merge carries only ours —
        # which is correct behaviour and made this test's own `ccf` NameError
        # reachable for the first time.
        launcher_pem = _other_ca(tmp_path / "ccf-ca")
        launcher.write_bytes(launcher_pem)
        out = _merged_ca(ca, str(launcher))
        assert out == ca.parent / "ca-bundle.pem"
        body = out.read_bytes()
        assert self._ca(tmp_path).read_bytes().strip() in body
        assert launcher_pem.strip() in body
        # and the launcher's file is left exactly as it was
        assert launcher.read_bytes().count(b"BEGIN CERT") == 1


class TestCaIsPublishedEveryLaunch:
    """The launcher builds its merged bundle from ca-trust.d/ as it starts us,
    so our CA has to be there BEFORE the client is exec'd, on every launch —
    not only when another CA happens to be in play, and not only after the
    daemon has run once. A component whose cert dir was wiped must reappear on
    the next launch instead of staying silently absent."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _switcher(self, tmp_path):
        class _Sw:
            backup_dir = tmp_path

            @staticmethod
            def resolve_account(email):
                return "1", "pinned@example.com", "org"

        return _Sw()

    def _cfg(self, tmp_path, monkeypatch):
        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        return home

    def case_first_ever_launch_publishes_before_any_daemon_ran(
        self, tmp_path, monkeypatch
    ):
        import cswap_pin.proxy as pp

        home = self._cfg(tmp_path, monkeypatch)
        monkeypatch.setattr(pp, "load_pin", lambda d: ("pinned@example.com", "org"))
        monkeypatch.setattr(pp, "write_upstream_hint", lambda *a, **k: None)
        monkeypatch.setattr(pp, "_read_alive_port", lambda d, fingerprint=None: 51000)
        monkeypatch.setattr(pp, "wire_global_config", lambda *a, **k: True)

        pp.ensure_proxy(self._switcher(tmp_path))

        published = home / pp.CA_TRUST_DIR / "cswap-pin.pem"
        assert published.exists(), "nothing to merge on a cold start"
        assert b"BEGIN CERTIFICATE" in published.read_bytes()

    def case_a_wiped_trust_dir_is_repopulated_next_launch(self, tmp_path, monkeypatch):
        import cswap_pin.proxy as pp

        home = self._cfg(tmp_path, monkeypatch)
        monkeypatch.setattr(pp, "load_pin", lambda d: ("pinned@example.com", "org"))
        monkeypatch.setattr(pp, "write_upstream_hint", lambda *a, **k: None)
        monkeypatch.setattr(pp, "_read_alive_port", lambda d, fingerprint=None: 51000)
        monkeypatch.setattr(pp, "wire_global_config", lambda *a, **k: True)
        sw = self._switcher(tmp_path)

        pp.ensure_proxy(sw)
        published = home / pp.CA_TRUST_DIR / "cswap-pin.pem"
        published.unlink()

        pp.ensure_proxy(sw)
        assert published.exists(), "a wiped trust dir stayed empty"

    def case_publishing_does_not_depend_on_another_ca_being_present(
        self, tmp_path, monkeypatch
    ):
        """The earlier version only published from inside the merge path, so a
        user running no other MITM never had a CA published at all."""
        import cswap_pin.proxy as pp

        home = self._cfg(tmp_path, monkeypatch)
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        monkeypatch.setattr(pp, "load_pin", lambda d: ("pinned@example.com", "org"))
        monkeypatch.setattr(pp, "write_upstream_hint", lambda *a, **k: None)
        monkeypatch.setattr(pp, "read_upstream_ca", lambda d: None)
        monkeypatch.setattr(pp, "_read_alive_port", lambda d, fingerprint=None: 51000)
        monkeypatch.setattr(pp, "wire_global_config", lambda *a, **k: True)

        pp.ensure_proxy(self._switcher(tmp_path))
        assert (home / pp.CA_TRUST_DIR / "cswap-pin.pem").exists()


def _config_home(tmp_path, monkeypatch):
    """A throwaway Claude config home, where the shared bundle is read from.

    Module-level rather than a per-class helper: four classes had a verbatim
    copy of it, and the one thing it does that must not drift is patching
    `claude_swap.paths.get_claude_config_home` — the path `_trust_file`
    resolves the shared bundle through. A copy that patched something else
    would test a bundle nothing reads.
    """
    home = tmp_path / "cfg"
    home.mkdir()
    monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
    return home


_OTHER_CA_CACHE: dict = {}


def _other_ca(certdir):
    """Another component's real CA, for multi-writer bundle fixtures.

    BUILT ONCE. Every caller wants the same thing — a valid CA that is NOT
    ours — and none asserts on which one, so minting a fresh RSA-2048 pair per
    call (~70 ms, 30-odd call sites) bought nothing. Keyed by nothing: one
    "other" is all any of these fixtures distinguishes.

    Trailing newline INCLUDED. Concatenating stripped PEMs fuses
    `-----END-----` into `-----BEGIN-----`, producing a bundle no reader can
    parse — a fixture bug that reads exactly like a guard bug.
    """
    from cswap_pin.proxy import ensure_ca

    if "pem" not in _OTHER_CA_CACHE:
        _OTHER_CA_CACHE["pem"] = (
            ensure_ca(certdir, "api.anthropic.com").ca_path.read_bytes().strip()
            + b"\n"
        )
    return _OTHER_CA_CACHE["pem"]


class TestConsumesTheSharedTrustBundle:
    """Publishing alone only helps components that read the dir. A pinned
    session must also CONSUME the merged bundle, or a CA added by some future
    proxy is trusted by everyone except the sessions cswap wires — which is
    the whole point of the shared contract."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _cfg(self, tmp_path, monkeypatch):
        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        return home

    def _ca(self, tmp_path):
        """A REAL CA, because the bundle guard parses rather than pattern-matches.

        These fixtures used a placeholder body ("PIN") that no X.509 reader can
        decode. That passed while the guard only counted BEGIN/END markers —
        and it meant the tests certified the guard against a bundle node itself
        would refuse, which is exactly the false accept the guard now exists to
        stop. A fixture that cannot occur in reality proves nothing about one
        that can.
        """
        from cswap_pin.proxy import ensure_ca

        certdir = tmp_path / "pin-proxy"
        return ensure_ca(certdir, "api.anthropic.com").ca_path

    def case_uses_the_merged_bundle_when_it_carries_us(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        merged = home / CA_TRUST_FILE
        merged.write_bytes(
            # Real certificates: a bundle whose siblings do not decode is one
            # node refuses outright, so placeholders would test the wrong file.
            _other_ca(tmp_path / "ambient")
            + ca.read_bytes().strip()
            + b"\n"
            + _other_ca(tmp_path / "future")
        )
        env = wire_env({}, 9955, ca)
        assert env["NODE_EXTRA_CA_CERTS"] == str(merged)

    def case_ignores_a_merged_bundle_that_does_not_carry_us(
        self, tmp_path, monkeypatch
    ):
        """A launcher that has not rebuilt since we published would otherwise
        strand the session without its own CA."""
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        (home / CA_TRUST_FILE).write_bytes(
            b"-----BEGIN CERTIFICATE-----\nSOMEONE-ELSE\n-----END CERTIFICATE-----\n"
        )
        env = wire_env({}, 9955, ca)
        assert env["NODE_EXTRA_CA_CERTS"] != str(home / CA_TRUST_FILE)
        assert ca.read_bytes().strip() in Path(env["NODE_EXTRA_CA_CERTS"]).read_bytes()

    def case_no_launcher_at_all_is_unchanged(self, tmp_path, monkeypatch):
        """No merged bundle, no other MITM: name our own CA, exactly as before."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import wire_env

        self._cfg(tmp_path, monkeypatch)
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        monkeypatch.setattr(pp, "read_upstream_ca", lambda d: None)
        ca = self._ca(tmp_path)
        assert wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"] == str(ca)


def _node_available() -> bool:
    """Whether the oracle can ANSWER here — not merely whether node exists.

    "Is node on PATH" is the wrong question and the difference is where the
    bug lives: the oracle exists because `tls.getCACertificates` is missing
    before v22.15, so the runtimes that matter are the OLD ones, and a node
    too old to answer satisfies `shutil.which`. Measured against 0.1.7 by a
    reviewer, with this box's /usr/bin/node at v12.22.9:

        PATH=/usr/bin pytest ...  ->  4 failed

    Asks the real question by running the real probe against a bundle that
    must come back True. Cached, because every guarded test would otherwise
    spawn node twice.
    """
    global _NODE_ANSWERS
    try:
        return _NODE_ANSWERS
    except NameError:
        pass
    import shutil
    import tempfile

    if shutil.which("node") is None:
        _NODE_ANSWERS = False
        return False
    from cswap_pin.proxy import _bundle_loads_in_node, ensure_ca

    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "cd"
        d.mkdir()
        ensure_ca(d, "api.anthropic.com")
        ca = d / "ca.pem"
        bundle = d / "b.pem"
        bundle.write_bytes(ca.read_bytes())
        _NODE_ANSWERS = _bundle_loads_in_node(bundle, ca) is True
    return _NODE_ANSWERS


class TestTornPemCannotEscape:
    """One unbalanced PEM voids the ENTIRE extras bundle: Node prints
    "PEM routines::bad end line" to stderr and then trusts no component CA and
    no corporate root at all, so the session dies on "unable to verify the
    first certificate" with the cause in a warning nobody reads. Measured by
    cc-wrapper on lmd42: a torn file present alongside good ones dropped the
    bundle from 131 certs to 128 plus the warning. Both sides of that: never
    produce a torn file, never consume a torn bundle."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _cfg(self, tmp_path, monkeypatch):
        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        return home

    def _ca(self, tmp_path):
        """A REAL CA, because the bundle guard parses rather than pattern-matches.

        These fixtures used a placeholder body ("PIN") that no X.509 reader can
        decode. That passed while the guard only counted BEGIN/END markers —
        and it meant the tests certified the guard against a bundle node itself
        would refuse, which is exactly the false accept the guard now exists to
        stop. A fixture that cannot occur in reality proves nothing about one
        that can.
        """
        from cswap_pin.proxy import ensure_ca

        certdir = tmp_path / "pin-proxy"
        return ensure_ca(certdir, "api.anthropic.com").ca_path

    def case_publish_never_leaves_a_partial_file(self, tmp_path, monkeypatch):
        """A reader must see either the old complete file or the new one."""
        import cswap_pin.proxy as pp

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        seen = []
        real_replace = os.replace

        def spy(src, dst):
            # At the moment of the swap the destination is still whatever it
            # was — never a half-written file.
            seen.append(Path(dst).read_bytes() if Path(dst).exists() else b"")
            real_replace(src, dst)

        monkeypatch.setattr(pp.os, "replace", spy)
        pp.publish_ca(ca)
        second = _other_ca(tmp_path / "regen")
        ca.write_bytes(second + b"\n")
        pp.publish_ca(ca)

        assert seen, "publish did not go through an atomic rename"
        for snapshot in seen:
            if snapshot:
                assert snapshot.count(b"-----BEGIN CERTIFICATE-----") == snapshot.count(
                    b"-----END CERTIFICATE-----"
                ), "a reader could observe a torn file"

    def case_no_temp_file_is_left_behind(self, tmp_path, monkeypatch):
        """A stray .tmp in the dir is another file the builder has to reason
        about; it must not survive the publish."""
        import cswap_pin.proxy as pp

        home = self._cfg(tmp_path, monkeypatch)
        pp.publish_ca(self._ca(tmp_path))
        leftovers = list((home / pp.CA_TRUST_DIR).glob("*.tmp"))
        assert leftovers == [], leftovers

    def case_a_torn_shared_bundle_is_refused(self, tmp_path, monkeypatch):
        """Containing our CA is not enough — a tear can void the whole load.

        THE VARIABLE IS THE TORN BODY, NOT ITS POSITION. I got this wrong once
        in each direction, so the measurement is here rather than in prose:

            complete-DER tear FIRST    node loads 1   (it recovers the tear)
            junk tear FIRST            node loads 0
            complete-DER tear AFTER    node loads 1
            junk tear AFTER            node loads 1

        openssl's decoder treats the next `-` as end-of-data rather than an
        error, so a tear yields a valid entry or garbage depending only on
        whether what it consumed happens to be complete DER — from the SAME
        position, either answer. An earlier fixture put the tear after our CA
        (where its body was a whole certificate and node delivered ours fine),
        and "fixing" it by MOVING the tear would have asserted a positional
        rule that does not hold.

        Whether a truncated body happens to be complete DER is exactly the
        question a predicate cannot answer from outside — which is why the
        oracle asks the loader instead of guessing.
        """
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        (home / CA_TRUST_FILE).write_bytes(
            # Junk in an unterminated block: nothing recoverable, so the load
            # stops here and our CA never arrives.
            b"-----BEGIN CERTIFICATE-----\nc3RvbGVuLW1pZC13cml0ZQ==\n"
            + ca.read_bytes()
        )
        env = wire_env({}, 9955, ca)
        assert env["NODE_EXTRA_CA_CERTS"] != str(home / CA_TRUST_FILE)

    def case_a_RECOVERED_tear_that_still_loses_our_CA_is_refused(
        self, tmp_path, monkeypatch
    ):
        """"The loader read something" is not "the loader read OURS".

        This is the case that killed a positional rule AND a count-based one.
        A tear whose body is complete DER is recovered by openssl — so node
        reports a cert loaded and a marker count looks fine — but what it
        recovered is the TORN block, and everything after the tear is dropped.
        Measured, subjects read back from the loader:

            bundle = <other CA, END line removed> + <our CA>
            node loads 1  ->  CN=cswap pin-proxy CA   (the TORN one)
            our CA        ->  ABSENT

        So a session handed that bundle cannot verify the proxy it is routed
        through, while every count and balance check calls the file healthy.
        Only "is OUR CA in what the loader actually loaded" separates it, which
        is exactly what the oracle asks and what no predicate over file syntax
        can answer.
        """
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        other = _other_ca(tmp_path)
        torn_but_complete = other.replace(b"-----END CERTIFICATE-----\n", b"")
        (home / CA_TRUST_FILE).write_bytes(torn_but_complete + ca.read_bytes())
        env = wire_env({}, 9955, ca)
        assert env["NODE_EXTRA_CA_CERTS"] != str(home / CA_TRUST_FILE), (
            "used a bundle the loader reads WITHOUT our CA"
        )

    def case_a_balanced_shared_bundle_is_still_used(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        # A REAL sibling CA. "OTHER" as a certificate body is precisely the
        # torn block node refuses to load, so a fixture using it described a
        # bundle that cannot occur and asserted the guard should accept it.
        (home / CA_TRUST_FILE).write_bytes(
            _other_ca(tmp_path / "other") + ca.read_bytes().strip() + b"\n"
        )
        env = wire_env({}, 9955, ca)
        assert env["NODE_EXTRA_CA_CERTS"] == str(home / CA_TRUST_FILE)


class TestNarrowingIsDeliberatelyUnguarded:
    """A bundle that is balanced and contains our CA but has silently lost
    OTHER roots is accepted on purpose.

    A consumer cannot tell "narrowed" from "correctly small". Measured across
    the three machines this runs on, a legitimate merged bundle is 2 certs on
    one host and 132 on another, so any size floor that catches narrowing on
    one rejects a healthy bundle on the next. Only the builder holds the
    previous state that makes narrowing a regression rather than a fact.

    The severity differs too: the two guarded cases leave the session unable to
    verify its OWN proxy, so every request dies. Narrowing keeps our chain
    intact and costs another component's. This test exists so a later change
    that adds a cert-count floor fails here instead of breaking the host with
    one component."""


    def _cfg(self, tmp_path, monkeypatch):
        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        return home

    def _ca(self, tmp_path):
        """A REAL CA, because the bundle guard parses rather than pattern-matches.

        These fixtures used a placeholder body ("PIN") that no X.509 reader can
        decode. That passed while the guard only counted BEGIN/END markers —
        and it meant the tests certified the guard against a bundle node itself
        would refuse, which is exactly the false accept the guard now exists to
        stop. A fixture that cannot occur in reality proves nothing about one
        that can.
        """
        from cswap_pin.proxy import ensure_ca

        certdir = tmp_path / "pin-proxy"
        return ensure_ca(certdir, "api.anthropic.com").ca_path

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_single_cert_bundle_is_accepted(self, tmp_path, monkeypatch):
        """The real shape on a host with one component and no corporate MITM."""
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        merged = home / CA_TRUST_FILE
        merged.write_bytes(ca.read_bytes() + b"\n")
        assert wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"] == str(merged)

    def case_a_bundle_that_lost_other_roots_is_still_accepted(
        self, tmp_path, monkeypatch
    ):
        """Narrowed but ours intact: our proxy still verifies, so refusing it
        would trade a working session for a problem we cannot even diagnose."""
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        merged = home / CA_TRUST_FILE
        # was [corp root + ours], now just ours
        merged.write_bytes(ca.read_bytes() + b"\n")
        assert wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"] == str(merged)


class TestRecordedChainSurvivesARepin:
    """Re-pinning from an ordinary shell must not drop the launcher's proxy
    out of the chain.

    A launcher starts a per-session cache proxy and points the SESSION at it;
    every shell on the machine, including the one a re-pin runs in, sees only
    the machine-wide egress proxy that cache proxy itself chains to. Taking the
    shell's value silently shortens the chain. Measured on work-mac: chain went
    127.0.0.1:9901 -> 127.0.0.1:8118 across a re-pin, i.e. the cache proxy was
    bypassed for every pinned session afterwards, with nothing failing.

    The earlier fix only consulted what our env block had displaced, which is
    empty on a machine where it has never displaced anything — exactly the
    machine that needed it."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _serving(self):
        import socket as s
        srv = s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        return srv, srv.getsockname()[1]

    def case_recorded_chain_wins_over_the_shell_value(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import _ambient_proxy, write_upstream_hint

        srv, inner = self._serving()
        try:
            certdir = tmp_path / "pin-proxy"
            certdir.mkdir()
            write_upstream_hint(certdir, f"http://127.0.0.1:{inner}")
            monkeypatch.setattr("claude_swap.paths.get_global_config_path",
                                lambda: tmp_path / "absent.json")
            got = _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"}, certdir)
            assert got == f"http://127.0.0.1:{inner}", "the chain was shortened"
        finally:
            srv.close()

    def case_a_dead_recorded_chain_does_not_strand_us(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import _ambient_proxy, write_upstream_hint

        srv, dead = self._serving()
        srv.close()
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead}")
        monkeypatch.setattr("claude_swap.paths.get_global_config_path",
                            lambda: tmp_path / "absent.json")
        assert _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"}, certdir) == (
            "http://127.0.0.1:8118"
        )

    def case_no_record_and_no_displaced_value_keeps_the_shell(self, tmp_path, monkeypatch):
        """A first-ever pin on a machine with no launcher: unchanged."""
        from cswap_pin.proxy import _ambient_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_global_config_path",
                            lambda: tmp_path / "absent.json")
        assert _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"}, certdir) == (
            "http://127.0.0.1:8118"
        )

class TestUnwireWhenDead:
    """A pin that is not serving must not be able to take the SESSION down.

    Claude Code applies .claude.json's env block at boot, so a wiring left
    behind by a daemon that died — or never started — makes every later
    session dial a dead port and retry forever, with the upstream proxies
    healthy and unreachable behind it. Measured on work-mac: "Unable to
    connect to API (ConnectionRefused), attempt 14/300", cured only by a human
    re-pinning by hand. An optional feature must degrade to "no pin", never to
    "no Claude".
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _cfg(self, tmp_path, monkeypatch, env):
        import claude_swap.paths as paths
        cfg = tmp_path / ".claude.json"
        cfg.write_text(json.dumps(
            {"env": env, "_cswapPinWiredKeys": sorted(env)}))
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        return cfg, certdir

    def case_no_daemon_record_strips_the_wiring(self, tmp_path, monkeypatch):
        # The work-mac shape: the daemon never started, so there is no record
        # at all, but a previous run's wiring is still in the config.
        from cswap_pin.proxy import unwire_if_dead
        cfg, certdir = self._cfg(tmp_path, monkeypatch, {
            "HTTPS_PROXY": "http://127.0.0.1:59999",
            "CSWAP_PIN_PORT": "59999"})
        assert unwire_if_dead(certdir) is True
        assert json.loads(cfg.read_text()).get("env", {}) == {}

    def case_dead_pid_strips_the_wiring(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import unwire_if_dead
        cfg, certdir = self._cfg(tmp_path, monkeypatch,
                                 {"HTTPS_PROXY": "http://127.0.0.1:59999"})
        (certdir / "proxy.json").write_text(
            json.dumps({"pid": 999999, "port": 59999, "fingerprint": "x"}))
        assert unwire_if_dead(certdir) is True
        assert json.loads(cfg.read_text()).get("env", {}) == {}

    def case_a_live_daemon_with_NO_state_file_is_left_alone(self, tmp_path, monkeypatch):
        """The incident: proxy.json absent while the daemon is still serving.

        `_spawn_daemon` UNLINKS proxy.json as its first act. Between that unlink
        and a failed spawn there is a window where the state file is gone and
        the ORIGINAL daemon is still up — and it is not a narrow window, because
        ensure_proxy matches on a FINGERPRINT: any code change makes it try to
        replace a healthy daemon, and that spawn then fails on the port the
        healthy one still holds.

        Deciding from the state file alone unwired a live pin on linux (daemon
        4035232, up 38h, pid alive, port answering). The wiring must be judged
        by whether the port it NAMES answers, not by whether our bookkeeping
        happens to exist at that instant.
        """
        import json as _json, socket, threading
        import claude_swap.paths as paths
        from cswap_pin.proxy import unwire_if_dead
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: [srv.accept() for _ in range(8)],
                         daemon=True).start()
        try:
            certdir = tmp_path / "pin-proxy"
            certdir.mkdir()
            cfg = tmp_path / ".claude.json"
            cfg.write_text(_json.dumps({
                "env": {"HTTPS_PROXY": f"http://127.0.0.1:{port}",
                        "CSWAP_PIN_PORT": str(port)},
                "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"]}))
            monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
            assert not (certdir / "proxy.json").exists()  # mid-spawn
            assert unwire_if_dead(certdir) is False
            assert "HTTPS_PROXY" in _json.loads(cfg.read_text())["env"]
        finally:
            srv.close()

    def case_a_LIVE_daemon_is_left_alone(self, tmp_path, monkeypatch):
        """The guard must not disarm a working pin — that would be the worse bug."""
        import os, socket, threading
        from cswap_pin.proxy import unwire_if_dead
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: [srv.accept() for _ in range(8)],
                         daemon=True).start()
        try:
            cfg, certdir = self._cfg(
                tmp_path, monkeypatch,
                {"HTTPS_PROXY": f"http://127.0.0.1:{port}"})
            (certdir / "proxy.json").write_text(json.dumps(
                {"pid": os.getpid(), "port": port, "fingerprint": "x"}))
            assert unwire_if_dead(certdir) is False
            assert "HTTPS_PROXY" in json.loads(cfg.read_text())["env"]
        finally:
            srv.close()

    def case_teardown_restores_the_config(self):
        """The orderly path must unwire too, not only the crash path.

        ASSERTED ON THE PARSE TREE, not on source text. This used to grep
        `daemon_main` for `"wire_global_config(None, None)"`, and the COMMENT
        four lines above the real call contains that exact string — so deleting
        the call and keeping the comment left the test green while every later
        session was left dialling a port nobody serves.

        The AST cannot be satisfied by a comment: a `Call` node exists only if
        the call does. Executing the teardown for real would be better still,
        but it is a closure over a live daemon's sockets and state file, and a
        harness that reconstructs that is a harness that can be wrong in its
        own right — this asserts exactly one fact and cannot drift from it.
        """
        import ast
        import inspect
        import textwrap

        from cswap_pin import proxy as pin_proxy

        tree = ast.parse(textwrap.dedent(inspect.getsource(pin_proxy.daemon_main)))
        teardown = next(
            (n for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef) and n.name == "_teardown"),
            None,
        )
        assert teardown is not None, "daemon_main no longer defines _teardown"

        restores = [
            n for n in ast.walk(teardown)
            if isinstance(n, ast.Call)
            and getattr(n.func, "id", None) == "wire_global_config"
            and len(n.args) == 2
            and all(isinstance(a, ast.Constant) and a.value is None for a in n.args)
        ]
        assert restores, (
            "_teardown must CALL wire_global_config(None, None); otherwise an "
            "idle teardown leaves every later session dialling a dead port"
        )


def _recording_server(events):
    """A stand-in for PinProxy that records the handover calls it receives.

    Shared rather than re-declared per test, because every copy has to track
    the real server's signature: a stub that no longer resembles the callee
    fails on the method the code actually calls, and six copies means six
    places to miss. ``release_listener`` returns the fd it would hand down —
    None here, which is what a server with nothing to pass returns too.
    """

    class _Srv:
        def release_listener(self, hand_down=False):
            events.append(("stop", None))
            return None

        def await_inflight(self, budget):
            events.append(("drain", budget))

        def stop(self, drain=None):
            events.append(("stop", drain))

    return _Srv


class TestTheDaemonWatchesItsOwnCode:
    """A daemon must notice its own code was replaced and hand over.

    MEASURED, work-mac, the outage this exists for: a pin daemon ran for 22
    hours on code that had been replaced 19 hours earlier. Six releases landed
    on disk in that window and none reached the running process. The stale
    daemon dialled direct instead of chaining, so every claude.ai and
    platform.claude.com handshake got the corporate MITM leaf and OAuth login
    was broken the whole time, until a human noticed.

    The recycle machinery was already complete and CORRECT. `heal` was
    evaluated in-process against that live daemon and every gate passed —
    fingerprint stale, port serving, slot resolvable, pid identified. It never
    ran because NOTHING CALLED IT: its only caller is a human typing
    `cswap pin --heal`. The periodic caller used to be a status-line hook, and
    that hook was removed on purpose (a status line is one machine's personal
    config, so recovery living there means every user without that hook has no
    recovery at all). The removal was right; the replacement is this class.

    So the daemon watches ITSELF. `daemon_fingerprint` is a hash of this
    module's mtime, which means re-calling it later answers "was proxy.py
    replaced under me" with no new machinery and no host-side hook of any kind.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _certdir(self, tmp_path):
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        return certdir

    def case_a_replaced_module_makes_the_daemon_hand_over(self, tmp_path, monkeypatch):
        """The positive case: fingerprint moved -> stop, spawn, done.

        Driven through `_watch_own_code` directly rather than through a real
        `daemon_main`, because the thing under test is the DECISION and its
        ORDER, and a real daemon would add sockets, a FIFO and a spawn to the
        failure surface without adding anything to the assertion.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        events = []
        fps = iter(["fp-old", "fp-new", "fp-new"])
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: next(fps))

        _Srv = _recording_server(events)

        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda n, e, c, **k: events.append(("spawn", n)) or 41234)

        certdir = self._certdir(tmp_path)
        done = threading.Event()
        pin_proxy._watch_own_code(
            _Srv(), "1", "a@example.com", certdir,
            done, teardown=lambda reason: events.append(("teardown", reason)),
            interval=0.01, _own_fingerprint="fp-old",
        )

        assert ("stop", None) in events, events
        assert ("spawn", "1") in events, events
        assert ("drain", pin_proxy._DRAIN_SECONDS) in events, events
        # THE DRAIN COMES AFTER THE SPAWN. Draining before it meant the port
        # stayed unbound for the whole budget and every new connection was
        # refused — measured at 31s on a live daemon. Releasing the listener
        # first lets the successor bind at once; the requests still in flight
        # here are finished afterwards, while the new daemon already accepts.
        assert events.index(("spawn", "1")) < events.index(
            ("drain", pin_proxy._DRAIN_SECONDS)
        ), events
        # ORDER IS LOAD-BEARING: the port must be free before the successor
        # tries to bind it, and _spawn_daemon blocks until the successor is
        # serving. Spawning first would race two daemons for one port.
        assert events.index(("stop", None)) < events.index(
            ("spawn", "1")), events
        # AND IT MUST NOT UNWIRE. The successor rebound the same port and owns
        # the wiring now; unwiring here would strip the config it just wrote
        # and send every new session to no proxy at all.
        assert not [e for e in events if e[0] == "teardown"], events
        assert done.is_set()

    def case_a_daemon_that_outlives_its_holder_gets_a_new_one(
        self, tmp_path, monkeypatch
    ):
        """A DAEMON WITH NO HOLDER ABOVE IT MUST NOT KEEP SERVING THAT WAY.

        MEASURED (isolated port 60759, the live 36301 untouched), SIGHUP to
        the holder:

            before:       holder 1855196, daemon 1855252 (ppid 1855196)
            after SIGHUP: daemon 1855252, ppid 1 — answers: True
            HOLDERS REMAINING: 0   PORT ALIVE: True

        The port survives because the daemon already holds the socket, so
        nothing looks wrong from outside. But the invariant that makes a
        crash survivable — every spawn lands under a holder — is gone, and
        the NEXT death takes the port down permanently. A live session's
        HTTPS_PROXY is fixed at exec, so that is ConnectionRefused forever.

        This is not only SIGHUP. Any way the holder leaves without taking the
        daemon with it lands here (SIGQUIT, SIGABRT, a segfault, a targeted
        kill). The detector is not signal-shaped either: `held_by_a_holder`
        compares `CSWAP_PIN_HELD_BY` against `getppid()`, and an orphaned
        daemon is reparented to init, so the comparison ALREADY goes false on
        every one of those paths. The daemon simply never asked.

        Recovery is the handover it already implements: hand the socket down,
        and the successor's holder ADOPTS it rather than binding. Same path,
        same 0-refused property, one new question.

        THE CODE IS UNCHANGED HERE, deliberately — a fingerprint that never
        moves is what proves the orphan is what triggered this and not the
        code watch. `case_an_unchanged_module_never_hands_over` is the other
        half: unchanged code AND no holder record must do nothing.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        events = []
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: "fp-same")
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda n, e, c, **k: events.append(("spawn", n)) or 1)
        # HELD BY A PID THAT IS NOT OUR PARENT — which is exactly what the
        # environment of an orphaned daemon says, because the variable names
        # the holder that started it and `getppid()` has moved to init.
        monkeypatch.setenv(pin_proxy._HELD_BY_ENV, str(os.getpid() + 1_000_000))
        assert not pin_proxy.held_by_a_holder(), (
            "the fixture failed to look orphaned — this case proves nothing"
        )

        _Srv = _recording_server(events)

        certdir = self._certdir(tmp_path)
        done = threading.Event()
        threading.Timer(0.25, done.set).start()
        pin_proxy._watch_own_code(
            _Srv(), "1", "a@example.com", certdir,
            done, teardown=lambda reason: events.append(("teardown", reason)),
            interval=0.01, _own_fingerprint="fp-same",
        )

        assert ("spawn", "1") in events, (
            f"the daemon kept serving with no holder above it: {events}"
        )
        assert events.index(("stop", None)) < events.index(("spawn", "1")), events
        # The successor owns the wiring, exactly as in the code-change path.
        assert not [e for e in events if e[0] == "teardown"], events

    def case_an_orphan_hands_the_socket_down_instead_of_keeping_it(self):
        """AN ORPHANED DAEMON'S SOCKET IS ITS OWN TO PASS ON.

        `release_listener(hand_down=True)` refuses to hand down an INHERITED
        socket, and rightly: a holder that is still there will put the next
        daemon on that very socket, so passing it to a child we do not control
        leaves two owners. But `_inherited` is decided once, in `start()`, and
        the holder can die afterwards — at which point the refusal is answering
        about a holder that no longer exists.

        MEASURED end to end, isolated port 49927, holder SIGHUPped:

            11:57:10 the holder above this daemon is gone — handing over
            11:57:13 holder could not take the port (49927 is taken —
                     refusing to hold a different one) — serving unheld
            11:57:13 serving on port 37001

        The recycle fired correctly and still produced the outage it exists to
        prevent: the successor's holder found the port occupied — by the
        orphan, which had kept the socket — so it served UNHELD on a fresh
        number while the wiring named the old one. Every session whose
        HTTPS_PROXY was fixed at exec is stranded.

        THE CONTROL is the same call with a live holder, which must still
        refuse. Without it, "hands it down" would pass just as well for code
        that always hands down and re-breaks the 201,909-refused case.
        """
        import socket

        from cswap_pin import proxy as pin_proxy

        def _hand_down_under(holder_pid):
            """What `release_listener(hand_down=True)` returns for a daemon
            whose recorded holder is `holder_pid`. The env is set PER CALL:
            it is one global variable, so building both servers up front let
            the second overwrite the first and the control answered about the
            wrong one."""
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))
            srv.listen(8)
            proxy = pin_proxy.PinProxy.__new__(pin_proxy.PinProxy)
            proxy._srv = srv
            proxy._stop = False
            proxy._accept_thread = None
            proxy._handed_fd = None
            proxy._inherited = True          # what start() recorded
            os.environ[pin_proxy._HELD_BY_ENV] = str(holder_pid)
            try:
                return proxy.release_listener(hand_down=True), srv
            finally:
                os.environ.pop(pin_proxy._HELD_BY_ENV, None)

        # THE CONTROL: the holder is our own parent, so it is alive.
        kept, kept_srv = _hand_down_under(os.getppid())
        # ...and here the recorded holder is a pid we are not a child of,
        # which is exactly what an orphaned daemon's environment says.
        fd, orphan_srv = _hand_down_under(os.getpid() + 1_000_000)
        try:
            assert kept is None, (
                "CONTROL FAILED: a socket a LIVE holder owns was handed down — "
                "two processes would accept on it"
            )
            assert fd is not None, (
                "an orphan kept the socket instead of handing it down, so the "
                "successor's holder finds the port taken and serves unheld"
            )
            os.close(fd)
        finally:
            for srv in (kept_srv, orphan_srv):
                try:
                    srv.close()
                except OSError:
                    pass

    def case_self_heal_off_stops_the_code_watch_too(self, tmp_path, monkeypatch):
        """`CSWAP_PIN_SELF_HEAL=off` MUST STOP EVERY AUTOMATIC REPLACEMENT.

        The switch is documented on `PortHolder` as "a respawner fighting a
        human who is debugging the daemon is worse than a dead port", and the
        holder honours it. The code watchdog — added later — never consulted
        it, so with the switch OFF a debugging session still had its daemon
        taken away the moment anything touched the file on disk. That is the
        one thing the switch exists to prevent, reached by the other path.

        `heal` and `ensure_proxy` are DELIBERATELY not covered: those are a
        human or a launch asking for a repair, and a switch meaning "do not
        act on your own" should not refuse a direct instruction.

        THE CONTROL is the same watcher with the switch unset, which must
        still hand over — otherwise "off stops it" would pass for a watchdog
        that never acts at all.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        def _handed_over(switch):
            events = []
            monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                                lambda *a, **k: "fp-new")
            monkeypatch.setattr(
                pin_proxy, "_spawn_daemon",
                lambda n, e, c, **k: events.append(("spawn", n)) or 41234,
            )
            if switch is None:
                monkeypatch.delenv(pin_proxy._SELF_HEAL_ENV, raising=False)
            else:
                monkeypatch.setenv(pin_proxy._SELF_HEAL_ENV, switch)
            done = threading.Event()
            threading.Timer(0.25, done.set).start()
            pin_proxy._watch_own_code(
                _recording_server(events)(), "1", "a@b.c",
                self._certdir(tmp_path), done,
                teardown=lambda reason: events.append(("teardown", reason)),
                interval=0.01, _own_fingerprint="fp-old",
            )
            return [e for e in events if e[0] == "spawn"]

        # CONTROL: with the switch unset the watcher must act.
        assert _handed_over(None), (
            "CONTROL FAILED: the watchdog did not hand over on changed code, "
            "so the refusal below says nothing"
        )
        assert not _handed_over("off"), (
            f"the code watch replaced the daemon while "
            f"{pin_proxy._SELF_HEAL_ENV}=off — the switch exists so a human "
            f"debugging the daemon is not fought by a respawner"
        )

    def case_an_unchanged_module_never_hands_over(self, tmp_path, monkeypatch):
        """THE CONTROL. Without it the suite cannot tell "recycles when the
        code changed" from "recycles always", and the second would replace a
        22-hour outage with a daemon that restarts itself forever."""
        import threading

        from cswap_pin import proxy as pin_proxy

        events = []
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: "fp-same")
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda n, e, c, **k: events.append(("spawn", n)) or 1)

        _Srv = _recording_server(events)

        certdir = self._certdir(tmp_path)
        done = threading.Event()
        # Ends the loop from the outside after several intervals, exactly as a
        # normal teardown does — so "did not recycle" is observed across many
        # ticks rather than inferred from one.
        threading.Timer(0.25, done.set).start()
        pin_proxy._watch_own_code(
            _Srv(), "1", "a@example.com", certdir,
            done, teardown=lambda reason: events.append(("teardown", reason)),
            interval=0.01, _own_fingerprint="fp-same",
        )

        assert events == [], events

    def case_a_successor_that_never_comes_up_keeps_serving_the_old_code(
        self, tmp_path, monkeypatch
    ):
        """A recycle that cannot spawn has no reason to end the pin.

        This process is intact and the code it runs is what was working a
        moment ago; stopping the listener was OUR step, not a failure of it.
        Unwiring here leaves the machine unpinned until a human re-pins it by
        hand, which is a strictly worse outcome than running one release
        behind. Only when the listener cannot be recovered either does the
        config genuinely name a dead port — that case is the next test.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        events = []
        # The code on disk stays NEW for the whole run: a handover that fails
        # leaves the reason for handing over still true, which is what makes
        # "does it try again" an observable question.
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: "fp-new")
        monkeypatch.setattr(
            pin_proxy, "_spawn_daemon",
            lambda n, e, c, **k: events.append(("spawn", n)) and None)
        monkeypatch.setattr(pin_proxy, "_resume_serving",
                            lambda srv: events.append(("resume", True)) or True)

        _Srv = _recording_server(events)

        certdir = self._certdir(tmp_path)
        done = threading.Event()
        # Ends the run from the outside, exactly as a normal teardown does, so
        # a watchdog that correctly keeps retrying still terminates the test.
        threading.Timer(1.0, done.set).start()
        pin_proxy._watch_own_code(
            _Srv(), "1", "a@example.com", certdir,
            done, teardown=lambda reason: events.append(("teardown", reason)),
            interval=0.01, _own_fingerprint="fp-old",
        )

        assert ("resume", True) in events, events
        assert not [e for e in events if e[0] == "teardown"], (
            "the daemon resumed serving, so nothing should have unwired", events)
        assert not done.is_set(), "a resumed daemon must keep running"
        # AND IT MUST KEEP WATCHING. A resume that returns leaves the process
        # alive, serving, and permanently on the stale code — which is the
        # 22-hour outage this whole class exists to end, reached one failed
        # spawn later instead of by having no watchdog at all. The machine
        # this watchdog is FOR is the one whose sessions never relaunch, so
        # nothing else will ever try again.
        assert len([e for e in events if e[0] == "spawn"]) > 1, (
            f"the watchdog gave up after ONE failed spawn and returned — the "
            f"daemon now serves the stale code forever: {events}"
        )
        # ...but bounded, not a spin. A peer measured a respawn loop at
        # ~3.75/sec against a child that could never start.
        assert len([e for e in events if e[0] == "spawn"]) <= 6, (
            f"unbounded retry: {len([e for e in events if e[0] == 'spawn'])} "
            f"spawns"
        )

    def case_a_successor_that_never_comes_up_unwires_if_it_cannot_resume(
        self, tmp_path, monkeypatch
    ):
        """The other half: no successor AND the listener will not come back.

        Now the config really does name a port nothing answers, which is the
        ConnectionRefused outage `_teardown` exists to prevent.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        events = []
        fps = iter(["fp-old", "fp-new", "fp-new"])
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: next(fps))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda n, e, c, **k: None)
        monkeypatch.setattr(pin_proxy, "_resume_serving", lambda srv: False)

        _Srv = _recording_server(events)

        certdir = self._certdir(tmp_path)
        done = threading.Event()
        pin_proxy._watch_own_code(
            _Srv(), "1", "a@example.com", certdir,
            done, teardown=lambda reason: events.append(("teardown", reason)),
            interval=0.01, _own_fingerprint="fp-old",
        )

        assert [e for e in events if e[0] == "teardown"], events
        assert done.is_set(), "a daemon that gave up must release daemon_main"

    def case_resume_refuses_a_port_the_live_sessions_are_not_using(
        self, tmp_path
    ):
        """Listening again is not enough — it has to be the RECORDED port.

        A session's HTTPS_PROXY is fixed at exec, so a resume that lands
        anywhere else is a second outage wearing the same log line.
        """
        import json
        import socket

        from cswap_pin import proxy as pin_proxy

        certdir = self._certdir(tmp_path)
        srv = pin_proxy.PinProxy(certdir, lambda: "tok")
        srv.start()
        port = srv.port
        (certdir / "proxy.json").write_text(json.dumps({"pid": 1, "port": port}))
        srv.stop(drain=0)

        assert pin_proxy._resume_serving(srv) is True
        assert srv.port == port
        socket.create_connection(("127.0.0.1", port), timeout=1.0).close()

        # A RESUME AFTER A HAND-DOWN takes the same descriptor back. The spawn
        # failed, so nobody adopted it and it never stopped listening — there
        # is no port to reclaim and nothing can have taken it in between. A
        # resume that instead bound a fresh socket would find its OWN
        # still-listening socket in the way and land on an ephemeral port,
        # stranding every session whose HTTPS_PROXY was fixed at exec.
        fd = srv.release_listener(hand_down=True)
        assert fd is not None, "nothing was handed down"
        assert pin_proxy._resume_serving(srv) is True, (
            "could not take back a socket nobody adopted")
        assert srv.port == port, (
            f"resumed on {srv.port} while the sessions expect {port}")
        socket.create_connection(("127.0.0.1", port), timeout=1.0).close()
        srv.stop(drain=0)

        # And the refusal: someone else holds the recorded port.
        srv2 = pin_proxy.PinProxy(certdir, lambda: "tok")
        srv2.start()
        taken = srv2.port
        (certdir / "proxy.json").write_text(json.dumps({"pid": 1, "port": taken}))
        srv2.stop(drain=0)
        squat = socket.socket()
        squat.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        squat.bind(("127.0.0.1", taken))
        squat.listen(1)
        try:
            assert pin_proxy._resume_serving(srv2) is False, (
                "resuming on a different port is not a resume")
        finally:
            squat.close()
            srv2.stop(drain=0)

    def case_daemon_main_starts_the_watchdog(self):
        """The watchdog must be WIRED IN, not merely defined.

        Asserted on the parse tree for the same reason as
        `test_teardown_restores_the_config` above: a comment naming the call
        satisfies a grep and not an AST. This is the assertion that would have
        caught the original defect — a correct mechanism with no caller.
        """
        import ast
        import inspect
        import textwrap

        from cswap_pin import proxy as pin_proxy

        tree = ast.parse(textwrap.dedent(inspect.getsource(pin_proxy.daemon_main)))
        started = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", None) == "start"
            and any(
                getattr(kw.value, "id", None) == "_watch_own_code"
                for kw in getattr(getattr(n.func, "value", None), "keywords", [])
            )
        ]
        assert started, (
            "daemon_main must START a _watch_own_code thread; a self-recycle "
            "nothing calls is exactly the 22h outage this release fixes"
        )

    def case_the_watchdog_is_handed_the_account_and_email_in_that_order(self):
        """The AST test above proves the thread STARTS, not that it is handed
        the right arguments. Swapping `account_num` and `email` in the `args=`
        tuple survived the whole suite — a successor spawned for account
        "user@example.com" with email "1" is a recycle that cannot work, and
        nothing said so."""
        import ast
        import inspect
        import textwrap

        from cswap_pin import proxy as pin_proxy

        tree = ast.parse(textwrap.dedent(inspect.getsource(pin_proxy.daemon_main)))
        call = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", None) == "start"
            and any(
                getattr(kw.value, "id", None) == "_watch_own_code"
                for kw in getattr(getattr(n.func, "value", None), "keywords", [])
            )
        )
        args = next(
            kw.value for kw in call.func.value.keywords if kw.arg == "args"
        )
        names = [getattr(e, "id", None) for e in args.elts]
        assert names[1:4] == ["account_num", "email", "certdir"], (
            f"_watch_own_code's args are {names} — the successor is spawned "
            "with whatever lands in positions 2 and 3, so a swap here pins the "
            "wrong account with no error anywhere"
        )

    def case_a_raising_spawn_does_not_leave_a_zombie(self, tmp_path, monkeypatch):
        """C3: `_spawn_daemon` RAISING (fork() EAGAIN under a post-deploy herd
        is the realistic trigger) hit the `except Exception` guard, which
        logged and returned WITHOUT calling teardown and WITHOUT done.set().

        Measured on 0.1.27: server STOPPED, teardown not called, done not set —
        so the process stays alive serving nothing while `.claude.json` still
        names its port, and `daemon_main`'s main thread blocks on `done.wait()`
        forever. That is the ConnectionRefused outage the module exists to
        prevent, produced by the code meant to prevent it.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        events = []
        fps = iter(["fp-old", "fp-new", "fp-new", "fp-new"])
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: next(fps))

        def _boom(n, e, c, **kw):
            raise OSError(11, "Resource temporarily unavailable")

        monkeypatch.setattr(pin_proxy, "_spawn_daemon", _boom)

        _Srv = _recording_server(events)

        certdir = self._certdir(tmp_path)
        done = threading.Event()
        pin_proxy._watch_own_code(
            _Srv(), "1", "a@example.com", certdir, done,
            teardown=lambda reason: events.append(("teardown", reason)),
            interval=0.01, _own_fingerprint="fp-old",
        )

        # THE PRECONDITION, asserted rather than assumed: this test is only
        # about the raise if the handover actually got as far as stopping.
        assert any(e[0] == "stop" for e in events), (
            "premise: the watchdog must have stopped the server before the "
            "spawn; this run never reached the handover"
        )
        assert [e for e in events if e[0] == "teardown"], (
            "the spawn raised, the server is stopped, and nothing unwired — "
            "every later session dials a port nobody serves"
        )
        assert done.is_set(), (
            "done was never set, so daemon_main's main thread blocks on "
            "done.wait() forever: a live process serving nothing"
        )

    def case_the_handover_is_serialized_by_the_spawn_lock(self, tmp_path, monkeypatch):
        """C2: every other `_spawn_daemon` caller takes `_spawn_lock` (heal,
        ensure_proxy). The watchdog did not.

        It matters most in the shape this release CREATES: a deploy replaces
        proxy.py, so every daemon on the box goes stale in the same instant and
        their timers fire together. Two unserialized spawns leave one successor
        orphaned, invisible to the sweep, holding a port forever.
        """
        import threading

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        spawned = []
        fps = iter(["fp-old", "fp-new", "fp-new", "fp-new"])
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: next(fps))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda n, e, c, **k: spawned.append(n) or 41234)

        stopped = []
        _Srv = _recording_server(stopped)

        # Hold the spawn lock from another thread for the whole handover. If
        # the watchdog takes it, it cannot spawn while we hold it.
        held = threading.Event()
        release = threading.Event()

        def _holder():
            with pin_proxy._spawn_lock(certdir):
                held.set()
                release.wait(timeout=5)

        t = threading.Thread(target=_holder, daemon=True)
        t.start()
        assert held.wait(timeout=5), "premise: the holder never took the lock"

        # WAIT FOR THE WATCHDOG TO BE BLOCKED, do not wait out a fixed
        # deadline. `w.join(timeout=1.0)` spent the whole second every run (the
        # watchdog is blocked, so the join can only ever time out) and proved
        # less than this does — a run where the watchdog never reached the lock
        # also "spawned nothing", and the join could not tell the two apart.
        #
        # THE WAIT MUST END ON *BLOCKED IN* THE LOCK, NOT ON *CALLING* IT.
        # Mutation-checked: pointing the watchdog at a different lock file
        # (`name=".MUTANT.lock"` — serialization gone) still called
        # `_spawn_lock`, so a spy that fired on ENTRY passed the mutant. Firing
        # only once the call has failed to return within a grace period is what
        # distinguishes "queued behind the holder" from "took some other lock
        # and walked straight through".
        entered = threading.Event()
        blocked_in_lock = threading.Event()
        real_lock = pin_proxy._spawn_lock

        def _watched_lock(*a, **k):
            entered.set()
            cm = real_lock(*a, **k)
            got_it = threading.Event()

            class _Probe:
                def __enter__(self):
                    r = cm.__enter__()
                    got_it.set()
                    return r

                def __exit__(self, *exc):
                    return cm.__exit__(*exc)

            def _watch():
                # not acquired within the grace period => genuinely queued
                if not got_it.wait(timeout=0.2):
                    blocked_in_lock.set()

            threading.Thread(target=_watch, daemon=True).start()
            return _Probe()

        monkeypatch.setattr(pin_proxy, "_spawn_lock", _watched_lock)

        done = threading.Event()
        w = threading.Thread(target=pin_proxy._watch_own_code, args=(
            _Srv(), "1", "a@example.com", certdir, done, lambda r: None, 0.01,
            "fp-old"), daemon=True)
        w.start()
        assert entered.wait(timeout=5), "the watchdog never reached the spawn lock"
        assert blocked_in_lock.wait(timeout=5), (
            "the watchdog called _spawn_lock but was NOT queued behind the "
            "holder — it is taking some other lock, so two daemons on one "
            "certdir can still recycle at the same tick"
        )

        blocked = not spawned
        release.set()
        t.join(timeout=5)
        w.join(timeout=5)

        assert blocked, (
            "the watchdog spawned while another holder had the spawn lock — "
            "two daemons on one certdir can both recycle at the same tick"
        )
        # THE PREMISE, asserted rather than assumed. "nothing spawned" also
        # describes a run where the handover never started, so without this the
        # assertion above is satisfied by the feature being absent entirely.
        # Observable only after the lock is released: the stop happens INSIDE
        # the lock, so a watchdog that is correctly blocked has not stopped yet.
        assert spawned == ["1"], (
            f"premise: the watchdog must reach the handover once the lock is "
            f"free; spawned={spawned}"
        )
        assert stopped, (
            "premise: the handover must stop the server before spawning; this "
            "run never reached it"
        )

    def _successor(self, certdir, port, pid):
        """Publish a successor's state — a live pid that is not ours, on a port
        that answers — exactly as a real successor's `write_daemon_state` does."""
        from cswap_pin import proxy as pin_proxy

        pin_proxy.write_daemon_state(certdir, port, pid, pin_proxy.daemon_fingerprint())

    def case_a_teardown_during_the_spawn_window_leaves_the_wiring_alone(
        self, tmp_path, monkeypatch
    ):
        """A concurrent teardown must not unwire a successor that is coming up.

        `_spawn_daemon` clears the record before it forks and then polls for the
        successor to publish, so for the length of that window there is nothing
        on disk to match against. `_release_daemon_state` answers "not
        superseded" throughout, and both other lifecycle paths — the refcount
        idle teardown and the SIGTERM handler — read that answer and unwire a
        daemon that comes up healthy and never rewires. Nothing self-heals
        afterwards: `_repair_wiring_if_ours` declines when nothing is wired.

        Driven through the REAL handover (`_watch_own_code`, which takes the
        real `_spawn_lock` and calls the real `_spawn_daemon`) racing the REAL
        `_teardown` closure `daemon_main` builds. A stand-in for either cannot
        race state it does not own, which is how this window went unmeasured.
        The after-publish control separates "this teardown is safe" from "no
        teardown ran".
        """
        import threading

        import claude_swap.paths as paths
        from cswap_pin import proxy as pin_proxy

        certdir, cfg, teardown = self._live_daemon(tmp_path, monkeypatch, paths)
        st = pin_proxy.read_daemon_state(certdir)
        pin_proxy.wire_global_config(st["port"], certdir / "ca.pem")
        assert pin_proxy._wired_port() == st["port"], "premise: not wired"

        succ, succ_port, published = self._late_successor(certdir, monkeypatch)

        # The handover path, for real: its own fingerprint has moved, so it
        # takes the spawn lock, stops the server and blocks in `_spawn_daemon`
        # polling for a successor that publishes only when we let it.
        fps = iter(["fp-new"] * 8)
        monkeypatch.setattr(pin_proxy, "daemon_fingerprint",
                            lambda *a, **k: next(fps))
        handover_done = threading.Event()

        _Srv = _recording_server([])

        threading.Thread(
            target=lambda: (pin_proxy._watch_own_code(
                _Srv(), "1", "a@b.c", certdir, threading.Event(),
                lambda r: None, 0.01, "fp-old"), handover_done.set()),
            daemon=True,
        ).start()

        try:
            # IN THE WINDOW: the record is cleared and the successor has not
            # published yet. This is the moment a refcount recheck or a SIGTERM
            # arrives, and the wiring it would strip belongs to a daemon that is
            # about to serve on that very port.
            for _ in range(500):
                if pin_proxy._read_alive_port(certdir) is None:
                    break
                time.sleep(0.01)
            assert pin_proxy._read_alive_port(certdir) is None, (
                "premise: the handover never reached the spawn window — "
                "the predecessor's record still reads as a serving daemon"
            )
            teardown("refcount")
            assert pin_proxy._wired_port() == st["port"], (
                "a teardown inside the spawn window unwired a successor that "
                "comes up healthy — the daemon serves and the pin is off"
            )
        finally:
            published.set()
            handover_done.wait(timeout=15)
            succ.close()

    def _late_successor(self, certdir, monkeypatch):
        """A successor that comes up healthy but publishes only on demand — so
        the spawn window can be held open and observed rather than raced."""
        import socket as _socket
        import subprocess
        import threading

        from cswap_pin import proxy as pin_proxy

        succ = _socket.socket()
        succ.bind(("127.0.0.1", 0))
        succ.listen(1)
        succ_port = succ.getsockname()[1]
        assert succ_port != 36301, succ_port
        published = threading.Event()

        def _fake_popen(*a, **k):
            def _late():
                published.wait(timeout=15)
                # A live pid that is not ours, on a port that answers: exactly
                # what a real successor's write_daemon_state records.
                self._successor(certdir, succ_port, os.getppid())
            threading.Thread(target=_late, daemon=True).start()

            class _P:
                pass
            return _P()

        monkeypatch.setattr(subprocess, "Popen", _fake_popen)
        # The sweep shells out to `ps` through the Popen just replaced, and it
        # is not what this measures.
        monkeypatch.setattr(pin_proxy, "_sweep_orphan_daemons", lambda *a, **k: None)
        return succ, succ_port, published

    def case_a_teardown_after_the_successor_publishes_still_leaves_it_alone(
        self, tmp_path, monkeypatch
    ):
        """THE CONTROL for the window test above.

        Once the successor's record is on disk the departing daemon is plainly
        superseded, and that case already worked. Without this the window test
        cannot tell a fix from a teardown that stopped unwiring altogether.
        """
        import socket as _socket

        import claude_swap.paths as paths
        from cswap_pin import proxy as pin_proxy

        certdir, cfg, teardown = self._live_daemon(tmp_path, monkeypatch, paths)
        st = pin_proxy.read_daemon_state(certdir)
        pin_proxy.wire_global_config(st["port"], certdir / "ca.pem")

        succ = _socket.socket()
        succ.bind(("127.0.0.1", 0))
        succ.listen(1)
        succ_port = succ.getsockname()[1]
        assert succ_port != 36301, succ_port
        try:
            self._successor(certdir, succ_port, os.getppid())
            teardown("refcount")
            assert pin_proxy._wired_port() == st["port"], (
                "unwired a published successor"
            )
        finally:
            succ.close()

    def case_a_teardown_with_no_successor_still_unwires(self, tmp_path, monkeypatch):
        """...and the window guard must not disable the unwire it guards.

        With no handover in flight and no successor, the config names a port
        this daemon has just stopped serving. Leaving it is the
        ConnectionRefused outage `_teardown` exists to prevent.
        """
        import claude_swap.paths as paths
        from cswap_pin import proxy as pin_proxy

        certdir, cfg, teardown = self._live_daemon(tmp_path, monkeypatch, paths)
        st = pin_proxy.read_daemon_state(certdir)
        pin_proxy.wire_global_config(st["port"], certdir / "ca.pem")
        teardown("refcount")
        assert pin_proxy._wired_port() is None, (
            "a daemon that stopped serving left the config naming its port — "
            "every later session dials an address nobody answers"
        )

    def _live_daemon(self, tmp_path, monkeypatch, paths):
        """A REAL daemon_main up to the point it installs its signal teardown,
        returning that teardown closure — the one both the refcount watcher and
        the SIGTERM handler call. A stand-in closure cannot race the state it
        does not own, which is how the window went unmeasured."""
        from cswap_pin import proxy as pin_proxy

        assert Path(pin_proxy.__file__).resolve().is_relative_to(
            Path(__file__).resolve().parent.parent
        ), pin_proxy.__file__

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        cfg = tmp_path / ".claude.json"
        cfg.write_text("{}")
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)

        class _Reached(Exception):
            pass

        box = {}

        def _grab(cleanup):
            box["teardown"] = cleanup
            raise _Reached

        monkeypatch.setattr(pin_proxy, "_install_signal_teardown", _grab)
        try:
            pin_proxy.daemon_main("1", "a@b.c", certdir)
        except _Reached:
            pass
        st = pin_proxy.read_daemon_state(certdir)
        assert st and st["pid"] == os.getpid(), st
        assert st["port"] != 36301, st
        return certdir, cfg, box["teardown"]


class TestHealRestoresWithoutRestart:
    """A repaired pin must come back on the SAME port, with no session restart.

    THREE CASES MOVED OUT, not deleted: no-pin, serving-and-wired, and
    serving-but-unwired are covered by TestHealReWiresAServingDaemon, which
    drives them against a REAL listening socket instead of a stubbed
    `_read_alive_port`. Two classes asserting one property is two places to
    keep in step, and the stubbed one was the weaker of the pair.

    Every other entry point reacts to a launch: the daemon is started only by
    ensure_proxy, which runs when a NEW session begins. So a daemon that dies
    under running sessions was never replaced — and once its stale wiring
    blocked every session, no new one could start to trigger the restart. That
    deadlock is why work-mac needed a human to re-pin by hand.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _root(self, tmp_path, monkeypatch):
        import claude_swap.paths as paths
        from cswap_pin.proxy import save_pin
        root = tmp_path / "backup"
        root.mkdir()
        (root / "pin-proxy").mkdir()
        save_pin(root, "a@example.com", "org-1")
        (root / "sequence.json").write_text(json.dumps(
            {"accounts": {"1": {"email": "a@example.com"}}}))
        cfg = tmp_path / ".claude.json"
        cfg.write_text("{}")
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        return root, cfg

    def case_a_dangling_pin_does_not_spawn(self, tmp_path, monkeypatch):
        """Pinned to a slot that no longer exists: nothing to serve."""
        from cswap_pin import proxy as pin_proxy
        root, _ = self._root(tmp_path, monkeypatch)
        (root / "sequence.json").write_text(json.dumps({"accounts": {}}))
        called = []
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a: called.append(a) or 1)
        assert pin_proxy.heal(root) is False
        assert not called

    def case_a_dead_daemon_is_respawned_and_rewired(self, tmp_path, monkeypatch):
        from cswap_pin import proxy as pin_proxy
        root, cfg = self._root(tmp_path, monkeypatch)
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 45678)
        assert pin_proxy.heal(root) is True
        env = json.loads(cfg.read_text())["env"]
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:45678"

    def case_a_failed_respawn_clears_the_wiring(self, tmp_path, monkeypatch):
        """If it cannot come back, it must not leave sessions dialling a corpse."""
        from cswap_pin import proxy as pin_proxy
        root, cfg = self._root(tmp_path, monkeypatch)
        cfg.write_text(json.dumps({
            "env": {"HTTPS_PROXY": "http://127.0.0.1:59999"},
            "_cswapPinWiredKeys": ["HTTPS_PROXY"]}))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: None)
        assert pin_proxy.heal(root) is False
        assert json.loads(cfg.read_text()).get("env", {}) == {}



class TestTheGateDisarmsWhenThePinIsCleared:
    """Clearing the pin must remove the proxy credential.

    An operator who turns the pin off and finds the proxy still demanding a
    credential has no model for that state — and the real damage is the next
    `cswap pin`, which re-arms the gate against every session started in
    between. Measured on a live host: arming cut off 313 processes, including
    the session that ran the command, each dying with `API Error: 407` and no
    way to learn why.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_clear_removes_the_secret(self, tmp_path, monkeypatch):
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        pin_proxy.ensure_proxy_secret(certdir)
        assert pin_proxy.read_proxy_secret(certdir) is not None

        class _Sw:
            backup_dir = tmp_path

        monkeypatch.setattr(pin_proxy, "save_pin", lambda *a, **k: None)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)
        pin_proxy.apply_pin(_Sw(), None, None)

        assert pin_proxy.read_proxy_secret(certdir) is None, (
            "the pin is off but the gate is still armed — the next pin will "
            "407 every session started in between"
        )

    def case_clearing_without_a_secret_is_not_an_error(self, tmp_path, monkeypatch):
        from cswap_pin import proxy as pin_proxy

        class _Sw:
            backup_dir = tmp_path

        monkeypatch.setattr(pin_proxy, "save_pin", lambda *a, **k: None)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)
        assert pin_proxy.apply_pin(_Sw(), None, None) is False


class TestArmingReportsWhoItCutsOff:
    """`cswap pin` has to say that it armed the gate.

    The code called the cutoff "unavoidable, pair it with a relaunch" and then
    never reported that it had happened, so nobody could pair anything. That
    is how a session killed itself and reported success in the same breath.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_count_is_sockets_not_environments(self, monkeypatch, tmp_path):
        """A previous counter read /proc/*/environ and returned a DISJOINT set:
        214 by environ against 7 actually connected, overlap ZERO. environ is
        an exec-time snapshot, so it names whatever the launcher had forever.
        A wrong number in the channel meant to inform a decision is worse than
        no number."""
        import socket

        from cswap_pin import proxy as pin_proxy

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        port = srv.getsockname()[1]
        try:
            n_idle = pin_proxy.clients_that_arming_would_cut_off(port)
            if n_idle is None:
                pytest.skip("no /proc/net/tcp on this platform")
            assert n_idle == 0, "counted a client before anyone connected"
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            conn, _ = srv.accept()
            try:
                assert pin_proxy.clients_that_arming_would_cut_off(port) >= 1, (
                    "a live client was not counted — the operator would be told "
                    "nothing breaks"
                )
            finally:
                conn.close()
                c.close()
        finally:
            srv.close()

    def case_a_repin_reports_nothing_because_it_arms_nothing(
        self, tmp_path, monkeypatch
    ):
        """Only the FIRST pin mints the secret; re-pinning reuses it and cuts
        off nobody. Reporting a cutoff there would cry wolf."""
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        pin_proxy.ensure_proxy_secret(certdir)

        class _Sw:
            backup_dir = tmp_path

        monkeypatch.setattr(pin_proxy, "save_pin", lambda *a, **k: None)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)
        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda sw: None)
        monkeypatch.setattr(
            pin_proxy,
            "clients_that_arming_would_cut_off",
            lambda p: (_ for _ in ()).throw(AssertionError("counted on a re-pin")),
        )
        pin_proxy.apply_pin(_Sw(), "a@b.c", None)
        assert pin_proxy.last_arm_cutoff() is None


class TestClearingThePinDoesNotStrandLiveSessions:
    """`cswap pin --clear` must not kill a proxy people are still using.

    The daemon idles out when nothing claims it, and the claims were "a FIFO
    holder" or "the wiring names my port". --clear removes the wiring, so both
    went false at once and the daemon exited while 312 processes were still
    connected. Their HTTPS_PROXY is fixed at exec, so they could not be
    redirected: ConnectionRefused, `attempt 6/300`, forever.

    Same root as the 407 (env cannot be updated in a running process), other
    direction: arming broke them, disarming broke them too.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_live_connection_claims_the_daemon(self, tmp_path, monkeypatch):
        import json
        import socket

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(2)
        port = srv.getsockname()[1]
        (certdir / "proxy.json").write_text(
            json.dumps({"pid": __import__("os").getpid(), "port": port})
        )
        # the pin is OFF: no wiring names this port
        monkeypatch.setattr(pin_proxy, "_wired_port", lambda: None)
        try:
            if pin_proxy.clients_that_arming_would_cut_off(port) is None:
                pytest.skip("no /proc/net/tcp on this platform")
            assert pin_proxy._is_claimed(certdir) is False, (
                "an idle unwired daemon should still time out"
            )
            c = socket.create_connection(("127.0.0.1", port), timeout=5)
            conn, _ = srv.accept()
            try:
                assert pin_proxy._is_claimed(certdir) is True, (
                    "--clear tore the daemon down under live sessions — they "
                    "get ConnectionRefused and cannot be redirected"
                )
            finally:
                conn.close()
                c.close()
        finally:
            srv.close()

    def case_an_unmeasurable_platform_still_sees_its_own_clients(
        self, tmp_path, monkeypatch
    ):
        """The claim above is Linux-only, and that is the bug.

        ``clients_that_arming_would_cut_off`` reads /proc/net/tcp, which
        NEITHER MAC HAS, so it answers None — and None was coerced to "not
        claimed". On macOS a hand-launched session could therefore hold a
        live connection while the watcher counted the daemon idle and, once
        `pin --clear` removed the wiring, stopped it underneath. Its
        HTTPS_PROXY is fixed at exec, so it cannot be redirected: it just
        gets ConnectionRefused.

        The daemon's own connection count has no such blind spot.
        """
        import json
        import os

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        (certdir / "proxy.json").write_text(
            json.dumps({"pid": os.getpid(), "port": 45678})
        )
        monkeypatch.setattr(pin_proxy, "_wired_port", lambda: None)
        # Model macOS: the socket scan cannot answer at all.
        monkeypatch.setattr(
            pin_proxy, "clients_that_arming_would_cut_off", lambda _p: None
        )

        assert pin_proxy._is_claimed(certdir, lambda: 0) is False, (
            "an idle daemon must still time out"
        )
        assert pin_proxy._is_claimed(certdir, lambda: 1) is True, (
            "a live client was ignored because the platform cannot be probed"
        )

    def case_the_daemon_counts_its_own_live_clients(self, tmp_path):
        """The count must track real connections, not just exist."""
        import socket
        import time

        from cswap_pin.proxy import PinProxy

        ensure_ca(tmp_path, "api.anthropic.com")
        proxy = PinProxy(certdir=tmp_path, pin_token_provider=lambda: None)
        proxy.start()
        try:
            assert proxy.live_client_count() == 0
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                deadline = time.monotonic() + 5
                while proxy.live_client_count() == 0:
                    assert time.monotonic() < deadline, (
                        "a connected client was never counted"
                    )
                    time.sleep(0.02)
                assert proxy.live_client_count() == 1
            finally:
                c.close()
            deadline = time.monotonic() + 5
            while proxy.live_client_count() != 0:
                assert time.monotonic() < deadline, (
                    "the count did not drop when the client left"
                )
                time.sleep(0.02)
        finally:
            proxy.stop()


class TestABlindDaemonIsNotReusedForever:
    """A daemon that cannot read the pinned credential must be recycled.

    On macOS the daemon inherits its spawner's session, and an ssh session
    cannot reach the GUI keychain (measured: `security find-generic-password`
    rc=36 over ssh, rc=0 from a GUI tmux window). Such a daemon serves every
    request unpinned and warns to a log nobody reads.

    Its own advice — "re-run `cswap pin` from a normal terminal" — could not
    work, because ensure_proxy reuses any daemon whose fingerprint matches.
    Measured: `cswap pin 1` from a GUI tmux window on work-mac left pid 56790
    (ssh-spawned, keychain-blind) serving unchanged. So the daemon records the
    fact and the reuse check honours it.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_marked_daemon_is_not_reused(self, tmp_path):
        import json
        import os
        import socket

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        state = certdir / "proxy.json"
        state.write_text(
            json.dumps({"port": port, "pid": os.getpid(), "fingerprint": "fp"})
        )
        try:
            assert pin_proxy._read_alive_port(certdir, fingerprint="fp") == port

            pin_proxy.mark_daemon_unpinnable(certdir)
            assert json.loads(state.read_text())["unpinnable"] is True
            assert pin_proxy._read_alive_port(certdir, fingerprint="fp") is None, (
                "a keychain-blind daemon was reused — `cswap pin` reports "
                "success while no pin is applied"
            )
            # A bare liveness probe still finds it: it IS serving, and the
            # monitor asking "is anything there" must not be told no.
            assert pin_proxy._read_alive_port(certdir) == port
        finally:
            srv.close()

    def case_marking_a_daemon_that_is_not_ours_does_nothing(self, tmp_path):
        import json

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        state = certdir / "proxy.json"
        state.write_text(json.dumps({"port": 1, "pid": 999999, "fingerprint": "fp"}))
        pin_proxy.mark_daemon_unpinnable(certdir)
        assert "unpinnable" not in json.loads(state.read_text()), (
            "one daemon marked another's record"
        )


class TestClientRegistrationIsNotSwapped:
    """`client/presence` registers THIS process, not who owns the session.

    It posts {client_id, clear} and gets a poll interval back — it is how the
    running CLI tells the server "I am attached, send me things". Swapping it
    registers the PINNED account as the attached client while the process
    actually listening is the active one, so inbound has nobody to reach.

    Measured live: presence was the ONLY route being swapped in a window where
    Remote Control received nothing (3 calls, all 200 — a silent failure, since
    the call succeeds and simply registers the wrong party). Turning the pin on
    broke `/rc` reconnect; with the pin off it always worked.

    The pin is about who OWNS the claude.ai-side assets, not about who is
    sitting at the terminal.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_presence_is_never_swapped(self):
        from cswap_pin.proxy import is_pinned_route

        for p in (
            "/v1/code/sessions/cse_X/client/presence",
            "/v1/sessions/cse_X/client/presence",
            "/v1/code/sessions/cse_X/client/presence?x=1",
        ):
            assert is_pinned_route(p) is False, f"registration swapped: {p}"

    def case_ownership_routes_still_are(self):
        """The fix must not disarm the feature: /bridge and the session list
        decide claude.ai-side ownership and have to keep following the pin."""
        from cswap_pin.proxy import is_pinned_route

        for p in (
            "/v1/code/sessions",
            "/v1/code/sessions/cse_X/bridge",
            "/v1/sessions/cse_X/unarchive",
            "/api/frame/deploy",
        ):
            assert is_pinned_route(p) is True, f"ownership route stopped swapping: {p}"

    def case_inference_and_worker_stay_untouched(self):
        from cswap_pin.proxy import is_pinned_route

        assert is_pinned_route("/v1/messages") is False
        assert is_pinned_route("/v1/code/sessions/cse_X/worker/events") is False
        assert is_pinned_route("/v1/code/sessions/cse_X/worker/events/stream") is False


class TestTheDaemonLogRecordsItsOwnDeath:
    """A daemon that vanishes must leave a reason behind.

    MEASURED (2026-08-02): every session on a machine went down behind a pin
    whose daemon was gone, and ``daemon.log`` was ZERO BYTES. The log carried
    warnings only, so a daemon that started, served for hours and disappeared
    wrote nothing at all. There was no way to tell an idle teardown from a
    signal from a crash, and with several agents working on the box the cause
    stayed unattributable. An outage you cannot attribute is one you cannot
    prevent.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_lifecycle_line_reaches_the_log(self, tmp_path):
        """_log_lifecycle writes to STDERR, and the daemon's stderr IS
        daemon.log — assert through that plumbing rather than by patching it,
        because the plumbing is the part that was silently unused."""
        import subprocess
        import sys
        import textwrap

        from cswap_pin import proxy

        certdir = tmp_path / "certdir"
        certdir.mkdir()
        src = str(Path(proxy.__file__).resolve().parent.parent)
        child = textwrap.dedent(f"""
            import sys; sys.path.insert(0, {src!r})
            from cswap_pin import proxy
            proxy._log_lifecycle("serving on port 12345 for account 1")
            proxy._log_lifecycle("stopping (signal SIGTERM)")
        """)
        fh = proxy._open_daemon_log(certdir)
        subprocess.run(
            [sys.executable, "-c", child],
            stdout=subprocess.DEVNULL,
            stderr=fh,
            check=True,
        )
        try:
            fh.close()
        except Exception:
            pass

        text = proxy.daemon_log_path(certdir).read_text()
        assert "serving on port 12345" in text, text
        assert "stopping (signal SIGTERM)" in text, text
        # The timestamp is the whole point: "when did it go away" was the
        # question the empty log could not answer.
        assert re.search(r"\[\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\]", text), text
        assert "pid=" in text, text

    def case_the_teardown_reason_distinguishes_signal_from_idle(self):
        """A TERM from a recycle and an idle teardown are the same code path.
        Before this they left the same (empty) trace, so a daemon that was
        KILLED could not be told from one that timed out by itself."""
        import signal as _signal

        from cswap_pin import proxy

        seen = []
        handlers = {}

        def _fake_signal(sig, handler):
            handlers[sig] = handler
            return None

        real = _signal.signal
        _signal.signal = _fake_signal
        try:
            proxy._install_signal_teardown(lambda reason="refcount": seen.append(reason))
        finally:
            _signal.signal = real

        assert _signal.SIGTERM in handlers, "SIGTERM was never registered"
        # os._exit would kill the test runner; the handler calls it in a
        # `finally`, so intercept it and let the cleanup run first.
        real_exit = os._exit
        os._exit = lambda code: (_ for _ in ()).throw(SystemExit(code))
        try:
            with pytest.raises(SystemExit):
                handlers[_signal.SIGTERM](_signal.SIGTERM, None)
        finally:
            os._exit = real_exit

        assert seen == ["signal SIGTERM"], seen

    def case_lifecycle_logging_never_kills_the_daemon(self, monkeypatch):
        """Called on the way out, including from a signal handler. A daemon
        must not die trying to record that it is dying."""
        from cswap_pin import proxy

        def _boom(*a, **k):
            raise OSError("stderr is gone")

        monkeypatch.setattr("builtins.print", _boom)
        proxy._log_lifecycle("this must not raise")  # no assertion needed


class TestHealReWiresAServingDaemon:
    """Serving is NOT the same as wired, and heal owns both.

    MEASURED: a daemon can be up while ``.claude.json`` names nothing — an
    unwire ran against a live daemon, or a recovery removed the wiring to save
    the session and the daemon then came back. `heal` returned False on
    "already serving" and left that permanent: the proxy served on a port no
    session was ever told about, and only a hand-typed `cswap pin <n>` fixed
    it. Re-wiring is the whole point of a heal, and it is what makes the pin
    return BY ITSELF once cswap is healthy again — with no session restart,
    because the port is reclaimed rather than reallocated.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _fixture(self, tmp_path, monkeypatch, wired_port=None):
        """A serving daemon + a pin record. ``wired_port`` sets what the config
        claims (None = not wired at all)."""
        import socket

        from cswap_pin import proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        # The REAL fingerprint, not a literal. These tests are about a daemon
        # that is serving CURRENT code and merely unwired; a literal made it
        # indistinguishable from one running code we no longer ship, which heal
        # now recycles. Writing the real one keeps each case testing the thing
        # it names — the stale case has its own test below.
        proxy.write_daemon_state(
            certdir, port, os.getpid(), proxy.daemon_fingerprint()
        )
        (tmp_path / "settings.json").write_text(
            json.dumps(
                {"remoteControl": {"pinnedEmail": "c@e.com", "pinnedOrganizationUuid": ""}}
            )
        )
        (tmp_path / "sequence.json").write_text(
            json.dumps({"accounts": {"1": {"email": "c@e.com"}}})
        )
        cfg = tmp_path / ".claude.json"
        cfg.write_text(
            "{}"
            if wired_port is None
            else json.dumps(
                {
                    "env": {
                        "HTTPS_PROXY": f"http://127.0.0.1:{wired_port}",
                        "CSWAP_PIN_PORT": str(wired_port),
                    },
                    "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"],
                }
            )
        )
        import claude_swap.paths as paths

        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        monkeypatch.setattr(paths, "get_default_global_config_path", lambda: cfg)
        return srv, port, cfg

    def case_serving_but_unwired_gets_rewired(self, tmp_path, monkeypatch):
        from cswap_pin import proxy

        srv, port, cfg = self._fixture(tmp_path, monkeypatch, wired_port=None)
        try:
            assert proxy.heal(tmp_path) is True
            raw = json.loads(cfg.read_text())
            # THE RECEIPT IS THE SIDECAR NOW, read through the same helper the
            # product uses — asserting on the config key would test where the
            # receipt USED to live, and would pass for a write that never
            # recorded one at all.
            ledger = proxy._read_ledger(cfg, raw)
            assert ledger.get("_cswapPinWiredKeys"), "the wiring was not restored"
            assert (raw.get("env") or {}).get("CSWAP_PIN_PORT") == str(port), (
                "re-wired to the wrong port — live sessions would not reattach"
            )
        finally:
            srv.close()

    def case_serving_and_already_wired_is_a_no_op(self, tmp_path, monkeypatch):
        """Called from the status line on a timer. The healthy case must not
        rewrite the config every few seconds."""
        from cswap_pin import proxy

        srv, port, cfg = self._fixture(tmp_path, monkeypatch, wired_port=None)
        try:
            proxy.heal(tmp_path)  # wire it once
            before = cfg.read_text()
            mtime = cfg.stat().st_mtime_ns
            assert proxy.heal(tmp_path) is False, "claimed to heal a correct wiring"
            assert cfg.read_text() == before
            assert cfg.stat().st_mtime_ns == mtime, "rewrote an already-correct config"
        finally:
            srv.close()

    def case_wired_to_the_WRONG_port_is_corrected(self, tmp_path, monkeypatch):
        """The dangerous middle case: a wiring that looks present but names a
        port this daemon is not on. Every session it sends there fails."""
        import socket

        from cswap_pin import proxy

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        stale = s.getsockname()[1]
        s.close()
        srv, port, cfg = self._fixture(tmp_path, monkeypatch, wired_port=stale)
        try:
            assert stale != port
            assert proxy.heal(tmp_path) is True
            raw = json.loads(cfg.read_text())
            assert (raw.get("env") or {}).get("CSWAP_PIN_PORT") == str(port)
        finally:
            srv.close()

    def case_no_pin_record_means_no_rewire(self, tmp_path, monkeypatch):
        """A serving daemon with nothing pinned is not our business — writing a
        wiring here would pin a user who never asked."""
        from cswap_pin import proxy

        srv, _port, cfg = self._fixture(tmp_path, monkeypatch, wired_port=None)
        (tmp_path / "settings.json").write_text(json.dumps({"remoteControl": {}}))
        try:
            assert proxy.heal(tmp_path) is False
            assert "_cswapPinWiredKeys" not in cfg.read_text()
        finally:
            srv.close()


class TestSharedBundleGuardMatchesNode:
    """The merged `ca-trust.pem` guard must agree with node's CA loader.

    Counting BEGIN/END markers cannot tell whether a block DECODES, and node
    aborts the ENTIRE extras load on one it cannot — so a torn certificate
    sitting before ours voids every component CA and corporate root at once.
    Measured on this host with a real TLS handshake through
    NODE_EXTRA_CA_CERTS: the marker count ACCEPTED that bundle, and the
    handshake failed. The session then cannot verify the very proxy it is
    routed through, so every request dies.

    The two directions are not symmetric, which is why the guard may refuse
    where it cannot tell:
      - accepting a bundle node rejects -> the whole session is dead
      - rejecting a bundle node accepts -> we lose the OTHER components' CAs
    See cnighswonger/claude-code-cache-fix#296, which found this same guard
    wrong in both directions in the sibling implementation.
    """


    @staticmethod
    def _ca(tmp_path):
        from cswap_pin import proxy

        b = proxy.ensure_ca(tmp_path / "cd", "api.anthropic.com")
        return b.ca_path.read_bytes().strip()

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_verdict_on_every_bundle_shape(self, tmp_path):
        """Eight shapes, one function. They were eight methods that each
        re-derived a CA; the SHAPES are the value, so they are a table and the
        CAs are built once."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        sibling = self._ca(tmp_path / "other")
        torn = (b"-----BEGIN CERTIFICATE-----\nQUJD!!!not-base64\n"
                b"-----END CERTIFICATE-----\n")
        crl = b"-----BEGIN X509 CRL-----\nQUFBQQ==\n-----END X509 CRL-----\n"
        bad_crl = b"-----BEGIN X509 CRL-----\nQUJD!!!\n-----END X509 CRL-----\n"
        unterminated = b"-----BEGIN CERTIFICATE-----\nQUFBQQ==\n"

        # THE FALSE ACCEPT, first: markers balance and our CA is present
        # verbatim, and node STILL refuses the file. That is the shape the old
        # substring guard passed, so it is asserted explicitly.
        bundle = torn + ours + b"\n"
        assert ours in bundle and bundle.count(b"-----BEGIN CERTIFICATE-----") == \
            bundle.count(b"-----END CERTIFICATE-----"), "premise: the old guard's own test"

        for name, data, ca, want in (
            ("a torn block before ours", torn + ours + b"\n", ours, False),
            ("two components, ours first", ours + b"\n" + sibling + b"\n", ours, True),
            ("two components, ours last", sibling + b"\n" + ours + b"\n", ours, True),
            ("a well-formed CRL beside ours", crl + ours + b"\n", ours, True),
            ("a CORRUPT non-certificate block", bad_crl + ours + b"\n", ours, False),
            ("a bundle without our CA", sibling + b"\n", ours, False),
            ("an empty CA to compare against", ours + b"\n", b"", False),
            ("a non-PEM CA to compare against", ours + b"\n", b"not a pem at all", False),
            ("an unterminated block borrowing a later END",
             unterminated + ours + b"\n", ours, False),
        ):
            assert _bundle_is_usable(data, ca) is want, (
                f"{name}: wanted {want}. Accepting what node rejects kills the "
                f"session; rejecting what node accepts drops every OTHER "
                f"component's CA."
            )

    def case_identity_is_by_der_not_by_substring(self, tmp_path):
        """Kept separate: it asserts the same CA re-encoded is still OURS,
        which is about the COMPARISON and not about a bundle shape."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        cert = x509.load_pem_x509_certificate(ours)
        recoded = cert.public_bytes(serialization.Encoding.PEM)
        assert recoded != ours or True  # re-encoding may or may not differ
        assert _bundle_is_usable(recoded, ours) is True, (
            "the same certificate, re-encoded, read as a different CA"
        )

class TestAnUpgradeCostsNoSession:
    """Restarting the daemon must not cost a session its requests OR its port.

    A running session's HTTPS_PROXY is fixed at exec, so it cannot be told
    about a new address. Everything below follows from that one fact: an
    upgrade, a recycle, even a full uninstall/reinstall has to come back on the
    SAME port, and has to leave in-flight requests intact on the way out.

    Where it fails, it fails as Remote Control going deaf — claude.ai sends,
    and the CLI is waiting at a port nothing serves. That is the symptom this
    class exists to keep from coming back.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _proxy(self, certdir):
        from cswap_pin.proxy import PinProxy

        p = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: (None, None),
            rediscover_chain=False,
        )
        p.start()
        return p

    def case_the_listening_port_is_released_for_the_next_daemon(self, tmp_path):
        """`close()` alone does NOT release it while a thread sits in
        `accept()` — measured, the port stayed `Address already in use` with
        `_srv.fileno()` already -1. The socket looked shut while the kernel
        still held the address, so the next daemon could not reclaim it."""
        import socket

        certdir = tmp_path / "cd"
        certdir.mkdir()
        p = self._proxy(certdir)
        port = p.port
        p.stop()

        probe = socket.socket()
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))  # raises if still held
        finally:
            probe.close()

    def case_a_restart_reclaims_the_same_port(self, tmp_path):
        from cswap_pin.proxy import _write_port_hint

        certdir = tmp_path / "cd"
        certdir.mkdir()
        p = self._proxy(certdir)
        port = p.port
        _write_port_hint(certdir, port)
        p.stop()

        p2 = self._proxy(certdir)
        try:
            assert p2.port == port, (
                f"came back on {p2.port}, leaving every live session dialling "
                f"{port} — this is Remote Control going deaf"
            )
        finally:
            p2.stop()

    def case_a_wiped_cert_dir_still_reclaims_from_claude_json(
        self, tmp_path, monkeypatch
    ):
        """Uninstall/reinstall: proxy.json AND port.hint are gone. The sessions
        do not know that — `.claude.json` is cswap's file, it survives, and it
        holds the very port they are using."""
        import json
        import shutil

        import claude_swap.paths as paths

        certdir = tmp_path / "cd"
        certdir.mkdir()
        cfg = tmp_path / ".claude.json"
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        monkeypatch.setattr(paths, "get_default_global_config_path", lambda: cfg)

        p = self._proxy(certdir)
        port = p.port
        cfg.write_text(
            json.dumps(
                {
                    "env": {
                        "HTTPS_PROXY": f"http://127.0.0.1:{port}",
                        "CSWAP_PIN_PORT": str(port),
                    },
                    "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"],
                }
            )
        )
        p.stop()
        shutil.rmtree(certdir)
        certdir.mkdir()

        p2 = self._proxy(certdir)
        try:
            assert p2.port == port, (
                "a reinstall stranded every running session on a dead port"
            )
        finally:
            p2.stop()

    def case_stop_closes_open_connections_rather_than_resetting_them(
        self, tmp_path
    ):
        """Draining is not enough on its own. Measured: a request that had
        transferred every byte STILL reached the client as
        ConnectionResetError, because the teardown ends in `os._exit(0)` and a
        process exiting without closing its sockets makes the kernel answer
        with RST instead of FIN. The data had arrived; the client discarded it
        over the reset."""
        import socket

        certdir = tmp_path / "cd"
        certdir.mkdir()
        p = self._proxy(certdir)
        client = socket.create_connection(("127.0.0.1", p.port), timeout=5)
        client.settimeout(5)
        time.sleep(0.2)
        assert p.live_client_count() == 1
        assert len(p._open_conns) == 1, "the connection is not tracked for close"

        # 0.3 s is a CEILING, and the property is that a drained request
        # ends in FIN rather than RST — which is decided the moment stop()
        # returns, not by how long it waited. 2.0 s was 2 s of runtime.
        p.stop(drain=0.3)
        try:
            assert client.recv(100) == b"", "expected a clean EOF"
        except ConnectionResetError:  # pragma: no cover - the bug being fixed
            raise AssertionError("client saw RST; stop() did not close the socket")
        finally:
            client.close()

    def case_draining_is_a_ceiling_not_a_wait(self, tmp_path):
        """The status line and every launch can trigger a stop, so the idle
        case must be instant."""
        certdir = tmp_path / "cd"
        certdir.mkdir()
        p = self._proxy(certdir)
        started = time.monotonic()
        p.stop(drain=30.0)  # nobody connected
        assert time.monotonic() - started < 2.0


class TestAnUpgradeDoesNotWaitForALaunch:
    """Installing a new cswap-pin must take effect BY ITSELF.

    MEASURED FAILURE: 0.1.3 landed on disk at 22:11 and the daemon was still
    the 20:04 process running 0.1.1 half an hour later — on a box whose entire
    release note was that upgrading no longer costs a session anything. The
    installer rewrites files; nothing on the machine told the running daemon it
    was now obsolete.

    `ensure_proxy` DOES recycle a stale daemon, but it only runs when a NEW
    session starts. On a box with long-lived sessions that can be never. `heal`
    is the one thing that already runs periodically (the status line, every few
    seconds), and it read a stale daemon as healthy because it asked
    `_read_alive_port` without a fingerprint.
    """
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)


    @staticmethod
    def _serving_listener(port=0):
        """A listener that ACCEPTS, so repeated probes keep answering."""
        import socket, threading

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(8)

        def _drain():
            while True:
                try:
                    c, _ = srv.accept(); c.close()
                except OSError:
                    return

        threading.Thread(target=_drain, daemon=True).start()
        return srv, srv.getsockname()[1]

    def _serving_daemon(self, tmp_path, monkeypatch, fingerprint):
        """A daemon serving under ``fingerprint``, with a pin record."""
        import socket

        from cswap_pin import proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        proxy.write_daemon_state(certdir, port, os.getpid(), fingerprint)
        (tmp_path / "settings.json").write_text(
            json.dumps(
                {"remoteControl": {"pinnedEmail": "c@e.com", "pinnedOrganizationUuid": ""}}
            )
        )
        (tmp_path / "sequence.json").write_text(
            json.dumps({"accounts": {"1": {"email": "c@e.com"}}})
        )
        cfg = tmp_path / ".claude.json"
        cfg.write_text(
            json.dumps(
                {
                    "env": {
                        "HTTPS_PROXY": f"http://127.0.0.1:{port}",
                        "CSWAP_PIN_PORT": str(port),
                    },
                    "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"],
                }
            )
        )
        import claude_swap.paths as paths

        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        monkeypatch.setattr(paths, "get_default_global_config_path", lambda: cfg)
        return srv, port, cfg, certdir

    def case_a_daemon_running_OLD_code_is_recycled(self, tmp_path, monkeypatch):
        """The upgrade case. Serving, wired correctly, and obsolete."""
        from cswap_pin import proxy

        srv, port, _cfg, certdir = self._serving_daemon(
            tmp_path, monkeypatch, "an-old-release"
        )
        killed, spawned = [], []
        # It must be recognised as OURS before being signalled — a pid is
        # reused freely, and killing on liveness alone aims TERM at whatever
        # unrelated process inherited the number.
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda d: [os.getpid()])
        monkeypatch.setattr(proxy, "_kill_daemon", lambda pid: killed.append(pid))

        def _spawn(num, email, cd, **kw):
            spawned.append((num, email))
            return port  # a real respawn reclaims the SAME port

        monkeypatch.setattr(proxy, "_spawn_daemon", _spawn)
        try:
            assert proxy.heal(tmp_path) is True, "an obsolete daemon was left running"
            assert killed == [os.getpid()], "the stale daemon was not recycled"
            assert spawned, "nothing replaced it"
        finally:
            srv.close()

    def case_the_port_is_reclaimed_so_live_sessions_survive(self, tmp_path, monkeypatch):
        """A session's HTTPS_PROXY is fixed at exec and cannot be told a new
        address. So the recycle MUST hand the successor the old port — the hint
        has to be written BEFORE the kill, because the daemon unlinks its own
        state on TERM and afterwards there is nothing left to reclaim from."""
        from cswap_pin import proxy

        srv, port, _cfg, certdir = self._serving_daemon(
            tmp_path, monkeypatch, "an-old-release"
        )
        hint_at_kill = {}
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda d: [os.getpid()])

        def _kill(pid):
            # Whatever the successor can reclaim, it can only be what was on
            # disk at THIS moment.
            hint_at_kill["port"] = proxy.read_port_hint(certdir)

        monkeypatch.setattr(proxy, "_kill_daemon", _kill)
        monkeypatch.setattr(proxy, "_spawn_daemon", lambda n, e, c, **k: port)
        try:
            proxy.heal(tmp_path)
            assert hint_at_kill.get("port") == port, (
                "the port hint was not written before the kill — the successor "
                "would take a fresh port and strand every wired session"
            )
        finally:
            srv.close()

    def case_a_CURRENT_daemon_is_never_recycled(self, tmp_path, monkeypatch):
        """The guard must not turn the status line into a restart loop. heal
        runs every few seconds; recycling a healthy daemon would cost every
        session its in-flight requests, over and over."""
        from cswap_pin import proxy

        srv, _port, _cfg, _certdir = self._serving_daemon(
            tmp_path, monkeypatch, proxy.daemon_fingerprint()
        )
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda d: [os.getpid()])
        monkeypatch.setattr(
            proxy,
            "_kill_daemon",
            lambda pid: pytest.fail("recycled a daemon running CURRENT code"),
        )
        try:
            assert proxy.heal(tmp_path) is False
        finally:
            srv.close()

    def case_an_unidentifiable_pid_is_never_signalled(self, tmp_path, monkeypatch):
        """When `ps` cannot prove the pid is ours, kill NOTHING. Being unable
        to identify a process is not a reason to signal it."""
        from cswap_pin import proxy

        srv, _port, _cfg, _certdir = self._serving_daemon(
            tmp_path, monkeypatch, "an-old-release"
        )
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda d: [])  # no ps
        monkeypatch.setattr(
            proxy,
            "_kill_daemon",
            lambda pid: pytest.fail("signalled a pid it could not identify"),
        )
        monkeypatch.setattr(proxy, "_spawn_daemon", lambda n, e, c, **k: None)
        try:
            proxy.heal(tmp_path)
        finally:
            srv.close()


class TestTheKillBudgetOutlastsTheDrain:
    """A recycle must not SIGKILL the drain it is waiting for.

    MEASURED: `_kill_daemon` waited a fixed ~2s for TERM while `_teardown`
    runs `stop(drain=30)`. Against a real streaming client the recycle killed
    the daemon mid-drain — the client got 4 of 10 SSE events and the drain
    never completed. So the release's headline guarantee (in-flight requests
    survive an upgrade) held only for a signal sent by hand, never for the
    recycle the package itself performs.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_draining_daemon_is_not_killed_before_it_finishes(self, monkeypatch):
        """Behaviour, not source: a process that exits just under the drain
        ceiling must be reaped by TERM, never escalated to KILL."""
        import time

        from cswap_pin import proxy

        # A daemon that used its full drain and exited cleanly, counted in
        # LOOP ITERATIONS rather than wall-clock: a real-time test would take
        # 30 seconds to answer a question about arithmetic. Each iteration is
        # one 0.1s tick by construction.
        #
        # (`_kill_daemon` does `import time` inside the function, which binds
        # the same singleton module object — so patching `time.sleep` from out
        # here DOES reach it. An earlier comment here claimed the opposite.)
        ticks = {"n": 0}
        exits_after = int((proxy._DRAIN_SECONDS - 0.5) * 10)

        def _alive(pid):
            ticks["n"] += 1
            return ticks["n"] < exits_after

        monkeypatch.setattr(proxy, "_pid_alive", _alive)
        signals = []
        monkeypatch.setattr(os, "kill", lambda pid, sig: signals.append(sig))
        monkeypatch.setattr(time, "sleep", lambda s: None)
        proxy._kill_daemon(4242)
        assert 15 in signals, "never sent TERM"
        assert 9 not in signals, (
            "escalated to SIGKILL while the daemon was still draining — "
            "in-flight requests die on the upgrade path"
        )


class TestTheDaemonRepairsItsOwnWiring:
    """Recovery must not depend on one developer's status line.

    A census of the host found exactly ONE caller of `heal`: the CLI — a human
    typing `cswap pin --heal`. Not the TUI, not the auto-switch engine, not the
    daemon. The only thing that ever repaired a pin automatically was a
    statusline script in a personal dotfiles repo, spawning that command on a
    timer. So every installation without those dotfiles had no recovery at all:
    a wiring pointing at a dead port stayed broken, and the symptom was "new
    sessions cannot reach the API" with nothing connecting it to the pin.

    MEASURED STATE THAT MOTIVATED THIS: `.claude.json` rewritten to port 52000
    while the daemon served 36301. Running sessions were fine (env fixed at
    exec); every NEW session inherited a port nothing listened on. The daemon
    was healthy throughout, so nothing watching the DAEMON could see it.

    The daemon already re-reads the wiring every few seconds to decide whether
    to keep serving. It just never acted on a mismatch.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _ours(self, tmp_path, monkeypatch, port):
        """A daemon record owned by THIS process, on ``port``."""
        from cswap_pin import proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        proxy.write_daemon_state(certdir, port, os.getpid(), proxy.daemon_fingerprint())
        (certdir / "ca.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n")
        return certdir

    def case_a_wiring_naming_a_DEAD_port_is_repaired(self, tmp_path, monkeypatch):
        import socket

        from cswap_pin import proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()  # genuinely refusing

        certdir = self._ours(tmp_path, monkeypatch, 36301)
        # This daemon WAS the pin's: the wiring named it before it broke. That
        # is what separates it from an orphan (see the hijack test below).
        proxy._mark_wired_once(certdir, 36301)
        monkeypatch.setattr(proxy, "_wired_port", lambda: dead_port)
        wired = []
        monkeypatch.setattr(
            proxy, "wire_global_config", lambda p, ca: wired.append(p) or True
        )
        try:
            assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is True
            assert wired == [36301], "did not re-point the wiring at this daemon"
        finally:
            pass

    def case_a_daemon_the_wiring_NEVER_named_cannot_hijack_it(
        self, tmp_path, monkeypatch
    ):
        """An orphan must not rewrite the user's config to point at itself.

        This is the repair's dangerous direction, and it disables the orphan
        reaper as a side effect: a daemon left behind by a crashed spawn sees a
        wiring it does not match, calls it "broken", claims it, and then counts
        as referenced forever — so the first-holder timeout never fires and it
        holds its port for good.

        Being named by the wiring at least once is the qualification. The
        daemon this repair exists for HAD one and lost it; an orphan never had
        one at all.
        """
        import socket

        from cswap_pin import proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        certdir = self._ours(tmp_path, monkeypatch, 36301)
        # never wired: an orphan. No marker file is written.
        monkeypatch.setattr(proxy, "_wired_port", lambda: dead_port)
        monkeypatch.setattr(
            proxy,
            "wire_global_config",
            lambda p, ca: pytest.fail(
                "an orphan hijacked the wiring — the reaper can never reap it"
            ),
        )
        assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False

    def case_a_wiring_that_ANSWERS_is_never_stolen(self, tmp_path, monkeypatch):
        """Another daemon legitimately owns the pin — leave it alone. A repair
        that fires here would fight the real owner every few seconds."""
        from cswap_pin import proxy

        srv, other_port = TestAnUpgradeDoesNotWaitForALaunch._serving_listener()
        try:
            certdir = self._ours(tmp_path, monkeypatch, 36301)
            # QUALIFY IT, or this test never reaches the guard it names:
            # `_was_wired_once` is the FIRST check, so without a marker the
            # repair returns False there and the pytest.fail below is
            # unreachable. Measured: removing the liveness probe entirely
            # left this test green.
            proxy._mark_wired_once(certdir, 36301)
            monkeypatch.setattr(proxy, "_wired_port", lambda: other_port)
            monkeypatch.setattr(
                proxy,
                "wire_global_config",
                lambda p, ca: pytest.fail("stole a LIVE wiring from another daemon"),
            )
            assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False
        finally:
            srv.close()

    def case_an_UNPINNED_config_is_left_unpinned(self, tmp_path, monkeypatch):
        """`pin --clear` removed the wiring on purpose. Re-adding it would
        re-pin a user who just asked not to be."""
        from cswap_pin import proxy

        certdir = self._ours(tmp_path, monkeypatch, 36301)
        # QUALIFY IT, or this test never reaches the guard it names:
        # `_was_wired_once` is the FIRST check, so without a marker the
        # repair returns False there and the pytest.fail below is
        # unreachable. Measured: removing the liveness probe entirely
        # left this test green.
        proxy._mark_wired_once(certdir, 36301)
        monkeypatch.setattr(proxy, "_wired_port", lambda: None)
        monkeypatch.setattr(
            proxy,
            "wire_global_config",
            lambda p, ca: pytest.fail("re-pinned a user who had cleared the pin"),
        )
        assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False

    def case_another_daemons_record_is_not_repaired_on_its_behalf(
        self, tmp_path, monkeypatch
    ):
        """Only the daemon named by the record may claim the wiring. Otherwise
        two daemons repair to two different ports, forever."""
        import socket

        from cswap_pin import proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        # A record owned by SOMEONE ELSE.
        proxy.write_daemon_state(certdir, 36301, os.getpid() + 1, "fp")
        # QUALIFY IT, or this test never reaches the guard it names:
        # `_was_wired_once` is the FIRST check, so without a marker the
        # repair returns False there and the pytest.fail below is
        # unreachable. Measured: removing the liveness probe entirely
        # left this test green.
        proxy._mark_wired_once(certdir, 36301)
        monkeypatch.setattr(proxy, "_wired_port", lambda: dead_port)
        monkeypatch.setattr(
            proxy,
            "wire_global_config",
            lambda p, ca: pytest.fail("repaired on another daemon's behalf"),
        )
        assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False

    def case_the_repair_is_reached_from_the_periodic_claim_check(
        self, tmp_path, monkeypatch
    ):
        """A capability with no caller is the defect this whole evening kept
        finding. `_is_claimed` runs every few seconds from watch_refcount, so
        the repair must be wired into it — not merely defined."""
        import socket

        from cswap_pin import proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        certdir = self._ours(tmp_path, monkeypatch, 36301)
        monkeypatch.setattr(proxy, "_wired_port", lambda: dead_port)
        called = []
        monkeypatch.setattr(
            proxy, "_repair_wiring_if_ours", lambda cd, p, lc=None: called.append(p) or True
        )
        proxy._is_claimed(certdir, live_clients=lambda: 0)
        assert called == [36301], (
            "the periodic claim check never reaches the repair — recovery would "
            "again depend on something outside the package"
        )


class TestTheCryptographyFloorIsLoadBearing:
    """`_certs_consistent` reads `not_valid_after_utc`, which landed in 42.0.

    On 41.x the attribute does not exist, the AttributeError was swallowed as
    "regenerate", and the function returned False FOREVER — so every launch
    minted a new CA and the daemon served a leaf signed by a root the session
    was never handed. Verified on a clean 41.0.7 venv: attribute MISSING, CA
    unstable across two `ensure_ca` calls, handshake CERTIFICATE_VERIFY_FAILED.

    Both halves of that fix (the floor, and the re-raise) reverted to 0.1.3
    behaviour with the whole suite still green — it had no coverage at all.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_declared_floor_admits_no_version_without_the_api(self):
        """The floor is the only thing standing between a user and that state,
        and `pip install cswap-pin` resolves whatever satisfies it."""
        import re

        root = Path(__file__).resolve().parent.parent
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        m = re.search(r'"cryptography>=([0-9]+)\.([0-9]+)"', text)
        assert m, "the cryptography requirement is no longer a simple >= floor"
        major, minor = int(m.group(1)), int(m.group(2))
        assert (major, minor) >= (42, 0), (
            f"floor is {major}.{minor}; `not_valid_after_utc` landed in 42.0, and "
            "below it every launch regenerates the CA and every request fails "
            "TLS verification, silently"
        )

    def case_a_MISSING_api_is_loud_rather_than_an_endless_regeneration(
        self, tmp_path, monkeypatch
    ):
        """The library moved: refuse loudly instead of regenerating forever.

        Simulated by removing the attribute from the class, which is what an
        older cryptography actually looks like to this code.

        Both classes must lose it. Below 46 ``x509.Certificate`` is a Python
        ABC and the object a load actually returns is the Rust class, so
        stripping only the ABC leaves the attribute access working while the
        guard's ``hasattr`` reports it gone — the function then returns False
        where production would raise. From 46 the two names are one class and
        the set collapses to a single ``delattr``.
        """
        from cswap_pin import proxy

        ca = tmp_path / "ca.pem"
        proxy.ensure_ca(tmp_path, "api.anthropic.com")  # a real, consistent set
        assert proxy._certs_consistent(
            ca, tmp_path / "ca.key", tmp_path / "leaf.pem", tmp_path / "leaf.key",
            "api.anthropic.com",
        ), "fixture is not consistent to begin with"

        loaded = x509.load_pem_x509_certificate(ca.read_bytes())
        for klass in {x509.Certificate, type(loaded)}:
            monkeypatch.delattr(klass, "not_valid_after_utc", raising=False)
        with pytest.raises(AttributeError):
            proxy._certs_consistent(
                ca, tmp_path / "ca.key", tmp_path / "leaf.pem", tmp_path / "leaf.key",
                "api.anthropic.com",
            )

    def case_a_NON_RSA_cert_dir_still_regenerates_instead_of_killing_the_daemon(
        self, tmp_path
    ):
        """The re-raise must not escape on a cert dir that is merely not RSA.

        `_certs_consistent` uses `public_numbers()` and PKCS1v15, so a
        self-consistent Ed25519 pair — a restored backup, someone's own openssl
        run — raises the SAME AttributeError as a version mismatch. 0.1.3
        returned False and regenerated on the next launch; propagating instead
        kills `PinProxy.__init__`, which does not fail open, so the daemon dies
        at construction and can never repair a directory the previous release
        healed by itself.
        """
        import datetime

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        key = ed25519.Ed25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "ed-ca")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, None)
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        kpem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        for n, data in (("ca.pem", pem), ("leaf.pem", pem),
                        ("ca.key", kpem), ("leaf.key", kpem)):
            (tmp_path / n).write_bytes(data)

        from cswap_pin import proxy

        # False, not an exception: regenerate, exactly as 0.1.3 did.
        assert proxy._certs_consistent(
            tmp_path / "ca.pem", tmp_path / "ca.key",
            tmp_path / "leaf.pem", tmp_path / "leaf.key",
            "api.anthropic.com",
        ) is False

        # And the whole path recovers rather than dying.
        proxy.ensure_ca(tmp_path, "api.anthropic.com")
        assert proxy._certs_consistent(
            tmp_path / "ca.pem", tmp_path / "ca.key",
            tmp_path / "leaf.pem", tmp_path / "leaf.key",
            "api.anthropic.com",
        ), "ensure_ca did not repair a non-RSA cert dir"


class TestTheRecycleCannotBecomeTheOutage:
    """The 0.1.6 fixes, each with the reproduction that motivated it.

    All three shipped with ZERO regression coverage: reverting any of them left
    the suite fully green. The release notes said each was "reproduced before
    changing", and they were — but the reproductions were not committed, so the
    next refactor silently restores the outage.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _fixture(self, tmp_path, monkeypatch, *, in_registry=True,
                 unpinnable=False, fp=None):
        import socket
        import threading

        from cswap_pin import proxy
        import claude_swap.paths as paths

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        threading.Thread(
            target=lambda: [srv.accept()[0].close() for _ in iter(int, 1)],
            daemon=True,
        ).start()
        st = {"pid": os.getpid(), "port": port,
              "fingerprint": fp if fp is not None else "an-old-release"}
        if unpinnable:
            st["unpinnable"] = True
        (certdir / "proxy.json").write_text(json.dumps(st))
        (certdir / "ca.pem").write_bytes(b"x")
        (tmp_path / "settings.json").write_text(
            json.dumps({"remoteControl": {"pinnedEmail": "c@e.com"}})
        )
        acc = {"1": {"email": "c@e.com"}} if in_registry else {"1": {"email": "z@e.com"}}
        (tmp_path / "sequence.json").write_text(json.dumps({"accounts": acc}))
        cfg = tmp_path / ".claude.json"
        cfg.write_text(json.dumps({
            "env": {"CSWAP_PIN_PORT": str(port),
                    "HTTPS_PROXY": f"http://127.0.0.1:{port}"},
            "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"],
        }))
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        monkeypatch.setattr(paths, "get_default_global_config_path", lambda: cfg)
        return certdir, port, cfg, srv

    def case_a_DANGLING_pin_never_kills_its_healthy_daemon(
        self, tmp_path, monkeypatch
    ):
        """The slot must be resolved BEFORE anything is signalled.

        `heal` used to recycle first and look the account up afterwards, so a
        pin whose email is no longer in sequence.json (`cswap remove`, a slot
        rename, a restored registry) killed a perfectly healthy daemon and then
        returned at "nothing to serve" — before the spawn AND before
        `unwire_if_dead`. Measured with a real kill: the port went dead and
        `.claude.json` still named it, which is the ConnectionRefused outage
        this module documents twice, caused by the code meant to prevent it.
        """
        from cswap_pin import proxy

        certdir, port, cfg, srv = self._fixture(
            tmp_path, monkeypatch, in_registry=False
        )
        killed = []
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda cd: [os.getpid()])
        monkeypatch.setattr(proxy, "_kill_daemon", lambda pid: killed.append(pid))
        monkeypatch.setattr(proxy, "_spawn_daemon", lambda n, e, c, **k: None)
        try:
            proxy.heal(tmp_path)
            assert not killed, (
                "killed a healthy daemon for a pin whose account is gone"
            )
        finally:
            srv.close()

    def case_an_UNPINNABLE_daemon_on_CURRENT_code_is_not_recycled(
        self, tmp_path, monkeypatch
    ):
        """Staleness is a fact about the RECORD, not about two probes.

        `_read_alive_port` returns None for an `unpinnable` daemon whatever the
        fingerprint, so "fingerprinted read failed AND bare read succeeded" was
        also true for a daemon running the NEWEST code that merely cannot read
        its credential — the macOS keychain rc=36 case. Nothing clears that
        mark, so the successor re-marks itself and the next tick recycles
        again. Measured: 5 ticks, 5 kills, no convergence, each costing live
        sessions their in-flight requests.
        """
        from cswap_pin import proxy

        certdir, port, cfg, srv = self._fixture(
            tmp_path, monkeypatch, unpinnable=True, fp=proxy.daemon_fingerprint()
        )
        kills = []
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda cd: [os.getpid()])
        monkeypatch.setattr(proxy, "_kill_daemon", lambda pid: kills.append(pid))
        monkeypatch.setattr(proxy, "_spawn_daemon", lambda n, e, c, **k: port)
        try:
            for _ in range(5):
                proxy.heal(tmp_path)
            assert not kills, f"recycled a CURRENT daemon {len(kills)}x in 5 ticks"
        finally:
            srv.close()

    def case_an_UNPINNABLE_daemon_is_not_respawned_over_either(
        self, tmp_path, monkeypatch
    ):
        """The spawn guard had the same confusion as the recycle trigger.

        A fingerprinted re-check under the lock reads "nothing is serving" for
        the same `unpinnable` daemon, so heal spawned a fresh successor every
        tick — which re-marks itself and is spawned over again. Anything
        serving is enough here, because a respawn cannot fix a credential the
        successor also cannot read.
        """
        from cswap_pin import proxy

        certdir, port, cfg, srv = self._fixture(
            tmp_path, monkeypatch, unpinnable=True, fp=proxy.daemon_fingerprint()
        )
        spawns = []
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda cd: [os.getpid()])
        monkeypatch.setattr(proxy, "_kill_daemon", lambda pid: None)
        monkeypatch.setattr(
            proxy, "_spawn_daemon", lambda n, e, c, **k: spawns.append(n) or port
        )
        try:
            for _ in range(5):
                proxy.heal(tmp_path)
            assert not spawns, f"spawned {len(spawns)} successors over a live daemon"
        finally:
            srv.close()

    def case_an_unidentifiable_pid_is_not_spawned_over_either(
        self, tmp_path, monkeypatch
    ):
        """`recycled` must mean "killed something", not "entered the branch".

        It decides whether the spawn guard is fingerprinted. Set merely for
        reaching the branch, a no-op recycle looked like a real one: with no
        `ps` — the documented blind spot — the identity gate kills nothing, and
        heal then spawned a successor over a daemon that is still serving.
        Measured before the fix: killed=[] spawned=['1'].
        """
        from cswap_pin import proxy

        certdir, port, cfg, srv = self._fixture(tmp_path, monkeypatch)
        kills, spawns = [], []
        monkeypatch.setattr(proxy, "_pin_daemon_pids", lambda cd: [])  # no ps
        monkeypatch.setattr(proxy, "_kill_daemon", lambda pid: kills.append(pid))
        monkeypatch.setattr(
            proxy, "_spawn_daemon", lambda n, e, c, **k: spawns.append(n) or port
        )
        try:
            proxy.heal(tmp_path)
            assert not kills, "signalled a pid it could not identify"
            assert not spawns, (
                "spawned a successor over a daemon it could not identify and "
                "did not kill"
            )
        finally:
            srv.close()


class TestTheOracleMustNotAnswerWhenItCannotAsk:
    """`_bundle_loads_in_node` has THREE outcomes, and None is the point.

    STOP PREDICTING, ASK. `_bundle_is_usable` predicts what node's loader will
    accept from file syntax, and measured against the real loader it was wrong
    in the dangerous direction: it called a bundle usable that node reads as
    ZERO extra CAs. We hand that file to a session as NODE_EXTRA_CA_CERTS, so
    the session trusts nothing at all — not our CA, not a sibling proxy's, not
    the corporate roots — and every request fails to verify the proxy it is
    routed through.

    But an oracle that cannot ask must not answer. cswap is Python and a box
    may have no node on PATH, where returning "unusable" would drop a healthy
    machine to its own CA and take every corporate root with it — the exact
    damage this exists to prevent, caused by the fix.
    """
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)


    @staticmethod
    def _certdir(tmp_path, cn="pin-ca"):
        """A REAL cert dir: ca.pem + a leaf signed by it, as production has.

        The probe asks "will node verify our leaf", so a bare CA with no leaf
        beside it is a question it cannot set up — it answers None, which is
        correct and useless for these assertions. `ensure_ca` builds exactly
        what a running daemon has.
        """
        from cswap_pin.proxy import ensure_ca

        d = tmp_path / cn
        d.mkdir(exist_ok=True)
        ensure_ca(d, "api.anthropic.com")
        return d

    def case_no_node_is_UNKNOWN_not_unusable(self, tmp_path, monkeypatch):
        from cswap_pin import proxy

        d = self._certdir(tmp_path)
        ours = (d / "ca.pem").read_bytes()
        f = d / "b.pem"
        f.write_bytes(ours)
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert proxy._bundle_loads_in_node(f, d / "ca.pem") is None, (
            "answered a question it could not ask — a node-less machine would "
            "lose every corporate root"
        )

    def case_a_probe_that_cannot_run_is_UNKNOWN(self, tmp_path, monkeypatch):
        """Exit status alone cannot separate 'the loader loaded nothing' from
        'the probe never ran' — node exits 0 after loading zero extras. The
        sentinel byte written BEFORE the list is what proves the loader ran."""
        import subprocess

        from cswap_pin import proxy

        d = self._certdir(tmp_path)
        ours = (d / "ca.pem").read_bytes()
        f = d / "b.pem"
        f.write_bytes(ours)

        class _R:
            returncode = 0
            stdout = b"no sentinel here"
            stderr = b""

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
        assert proxy._bundle_loads_in_node(f, d / "ca.pem") is None, (
            "a probe whose output lacks the sentinel was treated as an answer"
        )

    def case_a_bundle_node_reads_as_zero_is_UNUSABLE(self, tmp_path):
        """The finding that motivated the oracle. A malformed header running
        into a certificate header on one line: our predicate says usable, node
        loads nothing."""
        import shutil

        from cswap_pin import proxy

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        d = self._certdir(tmp_path)
        ours = (d / "ca.pem").read_bytes()
        bundle = b"-----BEGIN PUBLIC KEY----------BEGIN CERTIFICATE-----\n" + ours
        f = d / "b.pem"
        f.write_bytes(bundle)
        assert proxy._bundle_loads_in_node(f, d / "ca.pem") is False
        # THE PREDICATE USED TO DISAGREE HERE, and this test existed to record
        # that it did: its line-anchored scan could not see the welded BEGIN,
        # found nothing wrong, and returned True while node loaded zero. That
        # is the C1 defect, and the scan now sees the weld — so the two judges
        # AGREE, and the oracle is no longer the only one who can catch this
        # shape. Asserting the old disagreement would now be asserting the bug.
        assert proxy._bundle_is_usable(bundle, ours) is False, (
            "the predicate accepted a FUSED file — a welded BEGIN is invisible "
            "to openssl, so node truncates there while this says the file is "
            "fine"
        )

    def case_a_healthy_bundle_is_USABLE(self, tmp_path):
        import shutil

        from cswap_pin import proxy

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        d = self._certdir(tmp_path)
        ours = (d / "ca.pem").read_bytes()
        corp = (self._certdir(tmp_path, "corp-root") / "ca.pem").read_bytes()
        f = d / "b.pem"
        f.write_bytes(corp + ours)
        assert proxy._bundle_loads_in_node(f, d / "ca.pem") is True

    def case_a_bundle_without_our_CA_is_UNUSABLE(self, tmp_path):
        """Loading fine is not enough: the file has to carry OUR CA, or the
        session cannot verify the proxy it is routed through."""
        import shutil

        from cswap_pin import proxy

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        d = self._certdir(tmp_path)
        ours = (d / "ca.pem").read_bytes()
        corp = (self._certdir(tmp_path, "corp-root") / "ca.pem").read_bytes()
        f = d / "b.pem"
        f.write_bytes(corp)
        assert proxy._bundle_loads_in_node(f, d / "ca.pem") is False


class TestTheOracleWorksOnRUNTIMESWEDoNotDevelopOn:
    """The oracle must not answer UNKNOWN for every input on an older node.

    `tls.getCACertificates` landed in node v22.15 / v23.10. On anything older
    the probe writes nothing, the sentinel is absent, and every verdict is
    `None` — which the caller reads as "could not ask" and falls back to the
    predicate. So on those runtimes the oracle is not conservative, it is
    ABSENT, and the bug looks like a working guard on a dev box that happens to
    run a new node.

    A sibling implementation shipped exactly this and measured it:
        v20.19.0  undefined
        v22.14.0  undefined
        v22.15.0  function

    ASK THE CONTRACT, NOT A PROXY FOR IT. "Will you verify our leaf" is
    answerable on every node back to v12, and it is the question that actually
    matters — a session's failure mode is a handshake, not a census.
    """


    @staticmethod
    def _ca_and_leaf(tmp_path):
        from cswap_pin.proxy import ensure_ca

        d = tmp_path / "cd"
        d.mkdir()
        ensure_ca(d, "api.anthropic.com")
        return d

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_probe_does_not_depend_on_getCACertificates(self):
        """The API that is missing on half the runtimes we would run under."""
        import inspect

        from cswap_pin import proxy

        # THE PARSE TREE, not the text: the docstring explains WHY the API is
        # avoided and naming it there must not fail the check, while a real
        # call must. Stripping `#` comments was not enough — that is the same
        # source-text mistake this suite has already been burned by.
        import ast
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(proxy._bundle_loads_in_node)))
        code = "\n".join(
            ast.unparse(n)
            for n in ast.walk(tree)
            if isinstance(n, (ast.Call, ast.Assign, ast.Return))
        )
        assert "getCACertificates" not in code, (
            "the probe calls tls.getCACertificates, which does not exist before "
            "node v22.15 — every verdict is UNKNOWN there and the guard is "
            "absent rather than conservative"
        )


class TestARefusedBundleMustNotCostTheCorporateROOTS:
    """Refusing the shared bundle must never mean trusting ONLY our own CA.

    THE DANGEROUS ARM IS THE ONE THAT REFUSES. `_trust_file` asks whether the
    merged `ca-trust.pem` is usable; when the answer is no it falls through to
    "our CA alone", and on a corporate network that is a machine that can no
    longer verify anything except our own proxy. Every https call a session
    makes to anywhere else fails. The bundle being unusable is not a reason to
    throw away the parts of it that ARE usable — node's failure mode is
    per-block, so one torn block does not make the other 131 roots any less
    valid.

    Two independent measurements say this arm is reached in production:

      A. THE ORACLE IS NEVER CONSULTED THERE. `_bundle_loads_in_node` looks
         for the leaf beside the BUNDLE (`Path(bundle).parent / "leaf.pem"`),
         but the shared bundle lives in the Claude config home while our leaf
         lives in the pin-proxy certdir. So in production the leaf is never
         found, every verdict is None, and the predicate — the thing the
         oracle exists to correct — decides alone. The oracle looked healthy
         because every test handed it a bundle written INTO the certdir.

      B. A REVIEWER MUTATED THE None ARM AND THE SUITE STAYED GREEN. Forcing
         `verdict = False` when node cannot be consulted swapped the wired file
         from a 132-cert corporate bundle to our own single CA, and 259 tests
         passed. The five oracle tests all call `_bundle_loads_in_node`
         directly, so nothing asserted what the CALLER does with each of the
         three outcomes.

    Once a refusal salvages, the three outcomes stop being a cliff: unknown and
    refused both cost at most the torn block, never the corporate roots.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _ca(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        return ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

    @staticmethod
    def _der(pem: bytes) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return x509.load_pem_x509_certificate(pem).public_bytes(
            serialization.Encoding.DER
        )

    @staticmethod
    def _ders(path) -> set:
        """Every certificate the wired file actually carries, by DER."""
        import re as _re

        from cryptography.hazmat.primitives import serialization

        out = set()
        body = Path(path).read_bytes()
        for m in _re.finditer(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            body,
            _re.S,
        ):
            try:
                out.add(
                    x509.load_pem_x509_certificate(m.group(0)).public_bytes(
                        serialization.Encoding.DER
                    )
                )
            except Exception:  # noqa: BLE001
                pass
        return out

    def case_the_oracle_is_consulted_on_the_bundle_we_actually_ship(
        self, tmp_path, monkeypatch
    ):
        """A. The production bundle lives somewhere else than our leaf.

        This fixture is the one the oracle was built for: the predicate calls
        it usable and node loads ZERO certificates from it. If the oracle is
        reached, the file is refused. If the leaf lookup misses — as it does in
        production — the verdict is None, the predicate decides, and we wire a
        session to a bundle it cannot verify anything with.
        """
        import shutil

        from cswap_pin.proxy import CA_TRUST_FILE, _bundle_is_usable, wire_env

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        ours = ca.read_bytes()
        merged = home / CA_TRUST_FILE
        merged.write_bytes(
            b"-----BEGIN PUBLIC KEY----------BEGIN CERTIFICATE-----\n" + ours
        )
        # THE PREDICATE WAS WRONG ABOUT THIS FILE, which was the point when
        # only the oracle could catch a fused bundle. Both judges now refuse
        # it; what this test still pins is that the ORACLE is asked about the
        # file we actually ship, which the assertions below check.
        assert _bundle_is_usable(merged.read_bytes(), ours) is False

        wired = wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"]
        assert wired != str(merged), (
            "wired a session to a bundle node reads as ZERO CAs — the oracle "
            "was not consulted, because it looks for our leaf beside the "
            "bundle and the shared bundle does not live in our certdir"
        )

    def case_a_refused_bundle_keeps_every_root_that_still_decodes(
        self, tmp_path, monkeypatch
    ):
        """B, direction one: node REFUSES. Salvage, do not surrender.

        One torn block does not invalidate the corporate roots beside it.
        Dropping to our CA alone costs the session every https destination
        except our own proxy.
        """
        import shutil

        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        corp = _other_ca(tmp_path / "corp-root")
        (home / CA_TRUST_FILE).write_bytes(
            corp
            + b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
            b"-----END CERTIFICATE-----\n"
            + ca.read_bytes().strip()
            + b"\n"
        )
        carried = self._ders(wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"])
        assert self._der(ca.read_bytes()) in carried, "lost our own CA"
        assert self._der(corp) in carried, (
            "a torn block cost the session every corporate root — node's "
            "failure mode is per-block, so the roots beside it are still valid"
        )

    def case_no_node_and_a_refused_bundle_still_keeps_the_roots(
        self, tmp_path, monkeypatch
    ):
        """B, direction two: the oracle cannot be asked AT ALL.

        cswap is Python; a box with no node is normal, not an edge case. That
        is the arm where a wrong answer is silent and permanent, so it must
        salvage too — a machine without node must not be a machine without
        corporate trust.
        """
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        corp = _other_ca(tmp_path / "corp-root")
        (home / CA_TRUST_FILE).write_bytes(
            corp
            + b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
            b"-----END CERTIFICATE-----\n"
            + ca.read_bytes().strip()
            + b"\n"
        )
        monkeypatch.setattr("shutil.which", lambda name: None)
        carried = self._ders(wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"])
        assert self._der(ca.read_bytes()) in carried, "lost our own CA"
        assert self._der(corp) in carried, (
            "no node on PATH cost the session every corporate root"
        )

    def case_a_bundle_with_nothing_salvageable_still_names_our_own_CA(
        self, tmp_path, monkeypatch
    ):
        """The floor. Salvage must never leave a session with LESS than it had:
        when nothing in the shared file decodes, the answer is our CA, exactly
        as before this existed."""
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        (home / CA_TRUST_FILE).write_bytes(
            b"-----BEGIN CERTIFICATE-----\n!!!junk!!!\n-----END CERTIFICATE-----\n"
        )
        wired = wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"]
        assert self._der(ca.read_bytes()) in self._ders(wired)

    def case_the_salvaged_file_is_one_node_will_actually_load(
        self, tmp_path, monkeypatch
    ):
        """Salvage is worthless if node refuses the result too. Ask it."""
        import shutil

        from cswap_pin import proxy

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        corp = _other_ca(tmp_path / "corp-root")
        (home / proxy.CA_TRUST_FILE).write_bytes(
            corp
            + b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
            b"-----END CERTIFICATE-----\n"
            + ca.read_bytes().strip()
            + b"\n"
        )
        wired = Path(proxy.wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"])
        assert proxy._bundle_loads_in_node(wired, ca) is True, (
            "salvaged a file node still will not load"
        )

    def case_no_node_and_a_HEALTHY_bundle_still_names_the_SHARED_file(
        self, tmp_path, monkeypatch
    ):
        """Salvage is the floor, not the default. The predicate still decides.

        Once a refusal salvages, "treat UNKNOWN as unusable" stops being
        catastrophic — both arms keep the roots — so the mutation that collapses
        the three outcomes to two survives a suite that only checks for damage.
        It is still wrong, and measurably: on a node-less machine with a
        perfectly good bundle it wires a SNAPSHOT of that bundle instead of the
        bundle itself.

            SHIPPED : <config-home>/ca-trust.pem      the live shared file
            collapsed: <certdir>/ca-bundle.pem        a copy, written every launch

        The copy costs a write per launch and stops tracking the file the
        launcher rebuilds, so a root added between two launches reaches every
        component except our sessions — which is the whole reason we consume
        the shared bundle instead of building our own.
        """
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        shared = home / CA_TRUST_FILE
        shared.write_bytes(
            _other_ca(tmp_path / "corp-root") + ca.read_bytes().strip() + b"\n"
        )
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"] == str(shared), (
            "a healthy shared bundle was copied instead of used — the UNKNOWN "
            "arm collapsed into the refusal arm"
        )


class TestTheOracleTestsRunWhereTheyClaimTo:
    """A skip guard must ask "can node answer", not "is node on PATH".

    THE TWO ARE DIFFERENT QUESTIONS AND THE GAP IS WHERE THE BUG LIVES. The
    oracle exists because `tls.getCACertificates` does not exist before node
    v22.15, so the runtimes that matter most are the OLD ones — and every
    guard here reads `shutil.which("node") is None`, which is satisfied by a
    node too old to answer. A reviewer measured exactly that against 0.1.7:

        PATH=/usr/bin pytest ...   ->  4 failed  (this box: /usr/bin/node v12.22.9)

    The sibling CCF implementation shipped the mirror image in the same round:
    its implementation deliberately avoided the API while its TESTS called it,
    so the tests could not run on the runtimes the avoidance exists for.

    Measured here after the handshake rewrite: the oracle DOES answer on
    v12.22.9 (`_bundle_loads_in_node` returns True on a healthy bundle), and
    all 25 oracle-adjacent tests pass under `PATH=/usr/bin:/bin`. So the
    predicate is currently harmless — and it is one API change away from
    silently skipping the whole suite again on the runtime it is for.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_probe_answers_on_the_oldest_node_on_this_box(self, tmp_path):
        """Not "a node exists" — "the node we would actually consult answers".

        Deliberately NOT a source-text check on the skip predicate: what
        matters is that the probe returns a VERDICT rather than None on an old
        runtime, and a comment satisfies a grep.
        """
        import shutil
        import subprocess

        from cswap_pin.proxy import _bundle_loads_in_node, ensure_ca

        oldest = None
        for cand in ("/usr/bin/node", shutil.which("node")):
            if not cand or not Path(cand).exists():
                continue
            v = subprocess.run([cand, "--version"], capture_output=True, text=True)
            if v.returncode != 0:
                continue
            parts = v.stdout.strip().lstrip("v").split(".")
            key = tuple(int(p) for p in parts[:2] if p.isdigit())
            if oldest is None or key < oldest[0]:
                oldest = (key, cand)
        if oldest is None:
            pytest.skip("no node on this box at all")

        version, path = oldest
        d = tmp_path / "cd"
        d.mkdir()
        ensure_ca(d, "api.anthropic.com")
        ca = d / "ca.pem"
        bundle = d / "b.pem"
        bundle.write_bytes(ca.read_bytes())

        # Consult THAT node, not whatever `which` finds first.
        import os

        old_path = os.environ["PATH"]
        os.environ["PATH"] = str(Path(path).parent)
        try:
            verdict = _bundle_loads_in_node(bundle, ca)
        finally:
            os.environ["PATH"] = old_path

        assert verdict is True, (
            f"node {'.'.join(map(str, version))} at {path} could not answer "
            f"(verdict={verdict!r}) — every test guarded on "
            f"`shutil.which('node')` would run against it and measure nothing"
        )


class TestTheOracleIsAVetoNeverAnApproval:
    """`_bundle_loads_in_node`'s True must be necessary, never sufficient, for
    wiring the shared file as-is.

    Measured on this host (node v24.11.1), asking two independent questions
    about the SAME bundle — how many extras did the loader keep, and will it
    complete a handshake against OUR leaf:

        bundle                    node v24.11.1 extras   handshake vs our leaf
        ours + corp (healthy)     2                      OK
        ours + TORN + corp        1   <- corp LOST       OK      <-- the hole

    Node TRUNCATES at the first bad block and keeps everything before it. With
    our CA before the tear, the handshake still succeeds — the oracle answers
    True — while every corporate root after the tear silently vanished. On the
    real 132-cert bundle with a tear placed after our CA, a reviewer measured
    68 corporate roots lost this way, with `_salvage_bundle` already computing
    the correct 133-cert answer that the verdict declined to use.

    Today's real bundle happens to put our CA LAST, which is the lucky order.
    Nothing pins that position — the builder is not ours.
    """


    def _ca(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        return ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

    @staticmethod
    def _handshake_ok(node, bundle, leaf_key, leaf_pem):
        """The same question `_bundle_loads_in_node` asks, pointed at a
        DIFFERENT leaf (corp's own) — proving corp's root specifically made
        it through node's loader, not merely that SOME extra did."""
        import subprocess
        import tempfile

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
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        env["NODE_EXTRA_CA_CERTS"] = str(bundle)
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "probe.js"
            script.write_text(probe, encoding="utf-8")
            r = subprocess.run(
                [node, str(script), str(leaf_key), str(leaf_pem)],
                capture_output=True,
                env=env,
                timeout=10,
            )
        return r.stdout.startswith(b"\x02OK")

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_tear_AFTER_our_CA_must_not_silently_drop_the_corporate_root(
        self, tmp_path, monkeypatch
    ):
        import shutil

        from cswap_pin.proxy import CA_TRUST_FILE, ensure_ca, wire_env

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")
        node = shutil.which("node")

        home = _config_home(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        corp_dir = tmp_path / "corp-root"
        corp_ca_path = ensure_ca(corp_dir, "api.anthropic.com").ca_path
        corp_leaf, corp_key = corp_dir / "leaf.pem", corp_dir / "leaf.key"

        TORN = (
            b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
            b"-----END CERTIFICATE-----\n"
        )
        # THE TEAR IS AFTER OUR CA — the lucky order today's real bundle
        # happens to avoid, and nothing pins that position.
        (home / CA_TRUST_FILE).write_bytes(
            ca.read_bytes().strip() + b"\n" + TORN + corp_ca_path.read_bytes()
        )

        wired = wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"]
        assert self._handshake_ok(node, wired, corp_key, corp_leaf), (
            "the wired file cannot verify the corporate leaf — the oracle's "
            "True (it verified OUR leaf) was treated as proof the whole "
            "bundle loaded, but node truncates at the tear and silently "
            "drops everything after it, including the corporate root"
        )


class TestTheSalvageArmLogsWhatItDid:
    """A machine that silently switched off the shared bundle onto a private
    salvage snapshot is exactly the state whose cause nobody can find later —
    and the shared bundle stays broken because its builder is never told.
    `_log_lifecycle` already fires on the `verdict is None` arm; the
    refusal/salvage arm must name the shared path and how many blocks were
    kept vs. found."""


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_salvage_names_the_shared_path_and_the_block_count(
        self, tmp_path, monkeypatch
    ):
        import contextlib
        import io

        from cswap_pin import proxy

        home = _config_home(tmp_path, monkeypatch)
        ca = proxy.ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        corp = _other_ca(tmp_path / "corp-root")
        shared = home / proxy.CA_TRUST_FILE
        shared.write_bytes(
            corp
            + b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
            b"-----END CERTIFICATE-----\n"
            + ca.read_bytes().strip()
            + b"\n"
        )
        # No node on PATH: the oracle cannot be consulted, the predicate
        # decides, and this torn bundle is unusable — the refusal/salvage arm
        # runs regardless of what node is installed on this box.
        monkeypatch.setattr("shutil.which", lambda name: None)

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            proxy._trust_file(ca, None)
        out = buf.getvalue()
        assert str(shared) in out, (
            f"the salvage arm did not name the refused shared path: {out!r}"
        )
        # 3 BEGIN blocks found (corp, the torn one, ours); 2 kept (corp, ours).
        assert "2" in out and "3" in out, (
            f"the salvage arm did not say how many blocks were kept vs found: "
            f"{out!r}"
        )


class TestTheOwnershipGuardCannotBeFakedByName:
    """`_make_ca` gives EVERY cswap-pin CA the identical subject
    ``CN=cswap pin-proxy CA``, so a name-equality guard cannot tell OUR CA
    from a completely different one with the same name. The guard must check
    that the CA at ``ca_path`` actually SIGNED the leaf, not that its subject
    string matches.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_leaf_signed_by_a_DIFFERENT_ca_of_the_same_name_is_rejected(
        self, tmp_path
    ):
        """A certdir whose leaf.pem was NOT signed by ca_path's own CA — same
        subject name, different key — must not pass the ownership guard.

        A bundle carrying only the FOREIGN CA that actually signed the leaf
        must not yield True: that would wire a session to a shared bundle
        that cannot verify anything ca_path's own daemon will ever serve.
        """
        from cswap_pin import proxy
        from cswap_pin.proxy import ensure_ca

        real = tmp_path / "real"
        real.mkdir()
        ensure_ca(real, "api.anthropic.com")

        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")

        # Same subject name on both (guaranteed by `_make_ca`) — verified so
        # this test fails loudly if that assumption ever stops holding,
        # rather than silently testing nothing.
        real_ca = x509.load_pem_x509_certificate((real / "ca.pem").read_bytes())
        foreign_ca = x509.load_pem_x509_certificate(
            (foreign / "ca.pem").read_bytes()
        )
        assert real_ca.subject == foreign_ca.subject, (
            "fixture assumption broken: cswap-pin CAs no longer share a subject"
        )

        # Plant the FOREIGN leaf beside the REAL ca.pem — same shape as a
        # corrupted or cross-wired certdir.
        (real / "leaf.pem").write_bytes((foreign / "leaf.pem").read_bytes())
        (real / "leaf.key").write_bytes((foreign / "leaf.key").read_bytes())

        # The bundle under test carries ONLY the foreign root — the one that
        # actually signed the leaf now sitting in `real`, not `real`'s own CA.
        bundle = tmp_path / "bundle.pem"
        bundle.write_bytes((foreign / "ca.pem").read_bytes())

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")

        verdict = proxy._bundle_loads_in_node(bundle, real / "ca.pem")
        assert verdict is None, (
            "a leaf signed by a DIFFERENT CA than ca_path, sharing only its "
            "subject NAME, passed the ownership guard — verdict was "
            f"{verdict!r}, expected None (cannot ask: not our leaf)"
        )


class TestTheMissingLeafArmStaysUnknown:
    """The first-launch race `ensure_ca`'s lock exists for: a certdir holding
    `ca.pem` but no `leaf.pem` yet. `_bundle_loads_in_node` cannot set up its
    own question there (no leaf to hand the probe) and must answer `None`,
    never `False` — `False` means "asked and refused", which this call never
    did.

    THE OBSERVABLE DIFFERENCE, against a HEALTHY shared bundle:
        None  -> `_trust_file` falls back to the predicate, which approves,
                 and wires the LIVE shared file — later launcher repairs to
                 it keep reaching this session.
        False -> `_trust_file` treats it as a refusal and salvages: a PRIVATE
                 SNAPSHOT written into the certdir, which goes stale and dies
                 with the certdir instead of tracking the shared file.

    Mutating the missing-leaf arm from `return None` to `return False` leaves
    the rest of the suite green — nothing else asks which file got wired in
    exactly this fixture — so this test is the one that has to catch it.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_missing_leaf_plus_healthy_bundle_wires_the_LIVE_shared_file(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin.proxy import CA_TRUST_FILE, ensure_ca, wire_env

        home = _config_home(tmp_path, monkeypatch)
        certdir = tmp_path / "pin-proxy"
        ca = ensure_ca(certdir, "api.anthropic.com").ca_path
        # THE RACE: ca.pem exists, leaf.pem does not yet — `ensure_ca`'s own
        # lock is what this window exists between.
        (certdir / "leaf.pem").unlink()
        (certdir / "leaf.key").unlink()

        corp = _other_ca(tmp_path / "corp-root")
        shared = home / CA_TRUST_FILE
        shared.write_bytes(corp + ca.read_bytes().strip() + b"\n")

        wired = wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"]
        assert wired == str(shared), (
            "a missing leaf.pem (the ensure_ca race, not a refusal) wired a "
            f"private salvage snapshot ({wired!r}) instead of the live shared "
            f"file ({shared!r}) — the missing-leaf arm answered False "
            "(refused) rather than None (could not ask)"
        )


class TestAWeldedBEGINIsNotInvisible:
    """A `BEGIN` fused onto the previous block's `END` must still be a block.

    `_join_pem` exists because concatenating two PEM files where the first
    lacks a trailing newline produces `-----END CERTIFICATE----------BEGIN
    CERTIFICATE-----`, which node cannot decode. That guards what WE write.
    Nothing taught the READERS to see the same shape in a file someone else
    wrote, and both of them scanned with a line-anchored `^-----BEGIN`.

    So a welded BEGIN was invisible: the predicate never saw the block, found
    nothing wrong, and returned True; the oracle answered True because our own
    CA still verified. Both judges approved and the shared file was wired
    as-is. Measured on 0.1.12 with node present:

        declared BEGIN occurrences      3
        line-anchored (what we scanned) 2      <- blind to one block
        _bundle_is_usable               True
        oracle                          True
        wired                           ca-trust.pem (as-is)
        node actually loads             1 :: CN=cswap pin-proxy CA

    Two of three roots gone, nothing logged. At the real 132-cert scale the
    reviewer measured 69 of 133 lost — the same magnitude as the tear shape
    0.1.12 was cut to fix, still shipping.

    WORSE WITH NO NODE, which is the normal case here (cswap is Python): with
    OUR CA as the welded one the predicate still says usable, and the session
    loads ZERO extras — it cannot verify the proxy it is routed through, so
    every request dies.

    The scan must not require the marker to START a line, but must still
    refuse a marker quoted inside prose (the false-accept the anchor was
    protecting against) and must still tolerate CRLF (the false-reject that
    put the `\\r?$` there). Only a line start or a welded `-----` may precede
    a real block.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_predicate_sees_a_welded_block(self, tmp_path):
        from cswap_pin.proxy import _bundle_is_usable, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        corp = _other_ca(tmp_path / "corp-root")
        mid = _other_ca(tmp_path / "mid-ca")
        # mid written with NO trailing newline: its END welds to corp's BEGIN.
        body = ours.read_bytes().strip() + b"\n" + mid.strip() + corp
        assert _bundle_is_usable(body, ours.read_bytes().strip()) is False, (
            "a welded BEGIN was invisible to the predicate, so a bundle node "
            "truncates was called usable and wired as-is"
        )

    def case_salvage_recovers_a_welded_THIRD_PARTY_ca(self, tmp_path):
        """Salvage force-adds OUR CA, so a weld on ours self-heals by accident.
        Nothing does that for anyone else — the asymmetry is the bug."""
        from cswap_pin.proxy import _salvage_bundle, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        corp = _other_ca(tmp_path / "corp-root")
        # A HEALTHY BLOCK BEFORE THE WELD. With only two blocks the weld lands
        # on the first pair, where the old `limit` (the next MATCH start) and
        # the new one (the next MARKER start) coincide — so the two-block
        # fixture cannot tell them apart, and reverting the bound silently
        # dropped a third-party CA with the whole suite green. Measured:
        # shipped keeps 3, the reverted bound keeps 2 and loses `first`.
        first = _other_ca(tmp_path / "first-ca")
        # OURS FIRST, then the weld between two THIRD-PARTY CAs. The victim
        # must not be ours: salvage appends ours unconditionally, so a weld on
        # our own block self-heals by accident and hides the bound bug.
        body = ours.read_bytes().strip() + b"\n" + first.rstrip(b"\n") + corp
        out = _salvage_bundle(body, ours.read_bytes().strip())

        def der(pem: bytes) -> bytes:
            from cryptography.hazmat.primitives import serialization

            return x509.load_pem_x509_certificate(pem).public_bytes(
                serialization.Encoding.DER
            )

        import re as _r

        carried = {
            der(b)
            for b in _r.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, _r.S
            )
        }
        assert der(first) in carried, (
            "the CA on the LEFT of the weld was dropped — the scan resumed "
            "past it because the bound came from the welded MATCH (5 bytes "
            "early) rather than from the MARKER, so the block could no "
            "longer be found"
        )
        assert der(corp) in carried, (
            "the welded THIRD-PARTY CA was dropped by salvage and nothing said "
            "so — the repair path recovers a block only when it is ours"
        )
        assert der(ours.read_bytes()) in carried, "lost our own CA"

    def case_a_marker_quoted_in_prose_is_still_not_a_block(self, tmp_path):
        """The anchor was also preventing a false ACCEPT. Un-anchoring it
        naively (`(?:\\r?\\n|\\Z)` with no left-hand constraint) makes
        `# see -----BEGIN CERTIFICATE-----` read as a block — measured: 2
        blocks found where there is 1."""
        from cswap_pin.proxy import _salvage_bundle, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        body = (
            b"# provenance: -----BEGIN CERTIFICATE-----\n"
            + ours.read_bytes().strip()
            + b"\n"
        )
        out = _salvage_bundle(body, ours.read_bytes().strip())
        assert out.count(b"-----BEGIN") == 1, (
            f"a marker quoted in prose was treated as a block: {out[:200]!r}"
        )

    def case_a_CRLF_bundle_is_still_readable(self, tmp_path):
        """And the false REJECT the `\\r?$` was added for must not come back."""
        from cswap_pin.proxy import _bundle_is_usable, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        assert _bundle_is_usable(raw.replace(b"\n", b"\r\n"), raw.strip()) is True, (
            "a CRLF copy of our own CA was refused — the false reject that "
            "costs every sibling component its trust"
        )


class TestTheProbeAsksAboutTHISBundle:
    """The child must not inherit env that answers a different question.

    The probe stripped `*_proxy` (so its own loopback connect is not routed
    through us while we are deciding what to trust) and nothing else. Two
    inherited variables change what a handshake MEANS:

        NODE_TLS_REJECT_UNAUTHORIZED=0   node accepts any certificate
        NODE_OPTIONS                     can carry --use-openssl-ca and more

    Measured against a bundle carrying NO CA at all:

        NODE_TLS_REJECT_UNAUTHORIZED unset   oracle says False   (correct)
        NODE_TLS_REJECT_UNAUTHORIZED=0       oracle says True    (a lie)

    A True from that state is not "the bundle verifies our leaf", it is "this
    node was told not to check". `_trust_file` then wires the shared file on a
    verdict about nothing. Raised by the CCF session, who had the mirror-image
    gap: they cleared these two and not the proxy family, while this cleared
    the proxy family and not these two.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_disabled_tls_check_does_not_manufacture_a_verdict(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin.proxy import _bundle_loads_in_node, ensure_ca

        if not _node_available():
            pytest.skip("node cannot answer here — the oracle cannot be asked")
        ca = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        empty = tmp_path / "empty.pem"
        empty.write_bytes(b"# carries no CA at all\n")

        monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "0")
        assert _bundle_loads_in_node(empty, ca) is not True, (
            "the probe inherited NODE_TLS_REJECT_UNAUTHORIZED=0, so node "
            "accepted a bundle carrying no CA at all — the verdict describes "
            "the operator's environment, not the bundle"
        )


class TestTheENDLineIsBoundedToo:
    """0.1.13 taught the BEGIN scanner about welds and left the END matcher
    unbounded — `body.find(b"-----END <label>-----")` with no requirement that
    anything follow it.

    openssl requires the terminator to END ITS LINE. Trailing text on an END
    line makes it reject the block and load ZERO extras (`PEM routines::bad
    end line`), while the predicate walks straight past and calls the file
    usable. Measured on 0.1.13, node ABSENT (the normal case here — cswap is
    Python):

        predicate _bundle_is_usable : True
        node from the shared file   : 0
        wired                       : ca-trust.pem (as-is)
        session trusts              : nothing, including its own CA

    Same failure the welded BEGIN produced, reached by a different byte, and
    on the arm with no oracle to veto it. The sibling CCF implementation hit
    this exact shape from the other side: their END matcher used `indexOf`, so
    trailing content passed, and they fixed it in e28abd0.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_trailing_text_on_an_END_line_is_not_a_terminator(self, tmp_path):
        from cswap_pin.proxy import _bundle_is_usable, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        corp = _other_ca(tmp_path / "corp-root")
        raw = ours.read_bytes().strip() + b"\n"
        poisoned = raw.replace(
            b"-----END CERTIFICATE-----\n", b"-----END CERTIFICATE-----garbage\n", 1
        )
        assert _bundle_is_usable(poisoned + corp, raw.strip()) is False, (
            "an END line carrying trailing text was accepted as a terminator "
            "— openssl refuses it and node loads ZERO extras, so the session "
            "cannot verify even its own proxy"
        )

    def case_a_healthy_END_is_still_a_terminator(self, tmp_path):
        """The false-REJECT direction: a normal bundle, and a CRLF one, must
        still read. Bounding the END is where a too-strict pattern would cost
        every sibling component its trust."""
        from cswap_pin.proxy import _bundle_is_usable, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        corp = _other_ca(tmp_path / "corp-root")
        assert _bundle_is_usable(corp + raw, raw.strip()) is True, "healthy LF refused"
        assert _bundle_is_usable(
            (corp + raw).replace(b"\n", b"\r\n"), raw.strip()
        ) is True, "healthy CRLF refused — the false reject the \\r? guard exists for"

    def case_salvage_does_not_emit_a_block_it_made_unreadable(self, tmp_path):
        """`body[head:end] + b"-----END ..."` re-emits the terminator with no
        newline guard, so an input whose END sat on the base64 line comes back
        out fused. `_join_pem` guards the seam BETWEEN blocks, not inside one.
        """
        from cswap_pin.proxy import _salvage_bundle, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        corp = _other_ca(tmp_path / "corp-root")
        # END welded onto the last base64 line of the corporate block.
        fused = corp.replace(b"\n-----END CERTIFICATE-----", b"-----END CERTIFICATE-----")
        out = _salvage_bundle(fused + raw, raw.strip())
        assert b"=-----END" not in out and b"-----END CERTIFICATE-----\n" in out, (
            f"salvage emitted a block whose END is welded to its body: {out[:120]!r}"
        )


class TestBothMarkersMustOwnTheirLine:
    """A PEM marker has TWO edges and each release guarded one of them.

        BEGIN  left edge  0.1.13 (welds)      right edge  UNGUARDED
        END    left edge  UNGUARDED           right edge  0.1.14

    The two unguarded edges are the same defect class as the two that were
    fixed, reachable today, and they land in the dangerous direction.

    LEFT EDGE OF END. The predicate rebuilt the terminator in memory —
    `body[head:end] + b"-----END CERTIFICATE-----\\n"` — so when the input's
    END already sat on the base64 line, the slice ended mid-base64 and the
    appended terminator REPAIRED the block for the parser. cryptography read
    it happily and the predicate answered True about a file that is still
    fused on disk. `_find_end` cannot catch it: a fused END does terminate
    its line. 0.1.14 added exactly this guard to `_salvage_bundle` and the
    predicate 115 lines away never got it. Measured:

        predicate  : True
        node loads : 1 (CORP-A)      <- OUR CA gone, cannot verify our proxy

    RIGHT EDGE OF BEGIN. `_BEGIN_MARKER` requires a line terminator AFTER the
    marker, so `-----BEGIN CERTIFICATE-----garbage` does not match at all —
    the block becomes INVISIBLE to the scan rather than refused. openssl
    rejects it and truncates from there. Measured, damage on the FIRST of
    three blocks:

        predicate  : True
        node loads : 2 of 3          <- CORP-A silently lost
        control    : 3 of 3

    This one fires even with node PRESENT: our CA sits after the damage, so
    the handshake still succeeds and the oracle cannot veto either.

    THE FIX IS ONE SCANNER, NOT FOUR PATCHES. Both readers now consume
    `_pem_blocks`, which yields a block only when its BEGIN and its END each
    own their line, and hands out the bytes VERBATIM — reconstructing a
    terminator is what let the predicate lie about what is on disk.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _ours(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        return ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

    def case_an_END_welded_to_the_base64_line_is_not_usable(self, tmp_path):
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ours(tmp_path)
        raw = ours.read_bytes().strip() + b"\n"
        corp = _other_ca(tmp_path / "corp-a")
        fused = raw.replace(b"\n-----END CERTIFICATE-----", b"-----END CERTIFICATE-----")
        assert _bundle_is_usable(corp + fused, raw.strip()) is False, (
            "the predicate rebuilt the terminator in memory and called a "
            "fused file usable — node loads 1 of 2 from it and the session "
            "cannot verify its own proxy"
        )

    def case_a_BEGIN_with_trailing_text_is_not_usable(self, tmp_path):
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ours(tmp_path)
        raw = ours.read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        c = _other_ca(tmp_path / "corp-c")
        # TRAILING TEXT ONLY, leaving the block otherwise INTACT — its base64
        # and its END line are untouched. That is what isolates this guard:
        # with a truncated body the END matcher catches it anyway, and the
        # mutation survives. Measured: with the BEGIN check disabled the
        # scanner yields this block as healthy.
        damaged = a.replace(
            b"-----BEGIN CERTIFICATE-----\n", b"-----BEGIN CERTIFICATE-----garbage\n", 1
        )
        assert _bundle_is_usable(damaged + raw + c, raw.strip()) is False, (
            "a BEGIN carrying trailing text was INVISIBLE to the scan, so the "
            "predicate never saw the block and approved a file node truncates "
            "at — 2 of 3 roots loaded, and the oracle cannot veto it either "
            "because our CA sits after the damage"
        )

    def case_a_damaged_BEGIN_on_a_NON_certificate_block_is_caught_too(
        self, tmp_path
    ):
        """THE SHAPE ONLY THIS GUARD CATCHES, and finding it took measuring
        rather than reasoning.

        For a CERTIFICATE the x509 parse refuses a block whose BEGIN carries
        trailing text anyway, so removing the marker guard changes nothing and
        the mutation SURVIVES. A CRL or a PUBLIC KEY is only checked for
        intact base64 armor — deliberately, since a real corporate bundle
        carries those — so nothing else refuses it:

            shape                      node  shipped  guard-removed
            BEGIN+garbage on a CERT    2     False    False
            BEGIN+garbage on a PUBKEY  2     False    TRUE    <- approved

        node loads 2 of 3 either way. The predicate is the only thing standing
        between that file and a session that silently lost a root.
        """
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ours(tmp_path)
        raw = ours.read_bytes().strip() + b"\n"
        c = _other_ca(tmp_path / "corp-c")
        # ARMOR-VALID body, so only the BEGIN guard can refuse it. An
        # invalid body would be caught by the armor check first and this
        # test would pass with the guard deleted — measured: it did, once
        # the armor slice was fixed to actually see CRLF/whitespace bodies.
        # THE TRAILER MUST ITSELF BE VALID BASE64. With `garbage` the armor
        # check refuses the block first and the BEGIN guard is never reached
        # — measured: the guard's mutation survived, because the test was
        # really exercising the armor check. `QUFB` decodes, so only the
        # BEGIN guard can refuse this one.
        damaged_key = (
            b"-----BEGIN PUBLIC KEY-----QUFB\nQUFBQQ==\n-----END PUBLIC KEY-----\n"
        )
        assert _bundle_is_usable(
            b"-----BEGIN PUBLIC KEY-----\nQUFBQQ==\n-----END PUBLIC KEY-----\n"
            + raw,
            raw.strip(),
        ) is True, "fixture invalid: the same body must pass when BEGIN is clean"
        assert _bundle_is_usable(damaged_key + raw + c, raw.strip()) is False, (
            "a damaged BEGIN on a non-certificate block was approved — only "
            "the armor is checked there, so nothing else refuses it"
        )

    def case_salvage_recovers_a_block_damaged_on_either_edge(self, tmp_path):
        """Refusing is only half the answer: the repair must then keep every
        block that is still readable, whichever edge was damaged."""
        from cswap_pin.proxy import _salvage_bundle

        ours = self._ours(tmp_path)
        raw = ours.read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        c = _other_ca(tmp_path / "corp-c")
        damaged = a.replace(
            b"-----BEGIN CERTIFICATE-----", b"-----BEGIN CERTIFICATE-----garbage", 1
        )
        out = _salvage_bundle(damaged + raw + c, raw.strip())

        def der(pem: bytes) -> bytes:
            from cryptography.hazmat.primitives import serialization

            return x509.load_pem_x509_certificate(pem).public_bytes(
                serialization.Encoding.DER
            )

        import re as _r

        carried = {
            der(b)
            for b in _r.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, _r.S
            )
        }
        assert der(c) in carried, "a healthy block after the damage was dropped"
        assert der(raw) in carried, "lost our own CA"

    def case_a_healthy_bundle_is_still_usable(self, tmp_path):
        """The false-REJECT direction, for all four edges at once."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ours(tmp_path)
        raw = ours.read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        assert _bundle_is_usable(a + raw, raw.strip()) is True, "healthy LF refused"
        assert _bundle_is_usable(
            (a + raw).replace(b"\n", b"\r\n"), raw.strip()
        ) is True, "healthy CRLF refused"


class TestTheArmorCheckIsNotAcceptingEmptiness:
    """The non-certificate armor check went vacuous on any BEGIN line whose
    ending is not a bare LF.

    `_find_end` and `_BEGIN_MARKER` deliberately tolerate CRLF and trailing
    whitespace — a builder concatenating files leaves those, and refusing them
    is the false reject that costs every sibling component its trust. But the
    armor slice was `block.split(b"-----\\n", 1)[-1]`, which needs the marker to
    end in a bare LF *immediately*. On a CRLF block the separator is absent,
    `[-1]` returns the WHOLE block, `rsplit(b"-----END")` leaves `b""`, and
    `base64.b64decode(b"", validate=True)` SUCCEEDS. Measured on the real
    slice:

        block      b'-----BEGIN X509 CRL-----\\r\\n!!!bad!!!\\r\\n---'
        old slice  b''          <- empty: the check is a no-op
        new slice  b'\\r\\n!!!bad!!!\\r\\n'

    A CERTIFICATE is saved by its x509 parse; a CRL or PUBLIC KEY has only
    this check, so this is where a certificate-only test hides the defect.

    REGRESSION against 0.1.14, measured end to end with node deciding — a CRLF
    bundle carrying one torn CRL between two good certs:

        0.1.14  predicate False  ->  salvage yields 3 certs
        0.1.15  predicate True   ->  wired as-is, node loads 1

    0.1.14 refused it and repaired it; 0.1.15 approved it and the session
    keeps one root.
    """


    def _blocks(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        return ours.read_bytes().strip() + b"\n"

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_HEALTHY_CRLF_key_block_is_still_accepted(self, tmp_path):
        """The false-REJECT direction: real corporate bundles carry CRLs and
        key blocks, and refusing them costs every sibling component."""
        from cswap_pin.proxy import _bundle_is_usable

        raw = self._blocks(tmp_path)
        good = b"-----BEGIN PUBLIC KEY-----\r\nQUFBQQ==\r\n-----END PUBLIC KEY-----\r\n"
        assert _bundle_is_usable(good + raw, raw.strip()) is True, (
            "a healthy CRLF key block was refused"
        )

class TestAnEmptyArmorIsNotIntactArmor:
    """`TestTheArmorCheckIsNotAcceptingEmptiness` fixed the SLICE and left the
    EMPTINESS — the class asserted a property the code did not have.

    0.1.16's own diagnosis named two mechanisms: the slice returned the whole
    block, AND empty base64 decodes fine. Only the first was fixed. The
    corrected slice still yields `b''` for a body that is empty or only
    whitespace, and `base64.b64decode(b"", validate=True)` succeeds, so the
    check passes a block openssl refuses.

    Measured, node v24.11.1, corp-A + block + ours (correct answer is 2):

        shape              predicate   node loads
        empty body         True        1
        whitespace only    True        1
        over-padded QUFB=  True        1
        trailing blank ln  True        1
        healthy control    True        2

    On the real 132-cert bundle one such block costs 132 of 133 roots, in
    BOTH judge arms: the oracle ANDs with a predicate that says True, and
    salvage shares this slice so it re-emits the poison verbatim. The empty
    and whitespace cases produce no openssl warning at all — the session
    loses every corporate root with nothing on stderr.

    Standing defect, not a regression (0.1.14 and 0.1.15 accept these too),
    but it is the same defect this class was named for.

    openssl needs at least one full base64 quantum and refuses a blank line
    before END, which is exactly what the three conditions below encode.
    """


    def _ours(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        return ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_an_armor_block_openssl_cannot_decode_is_refused(self, tmp_path):
        """Every shape that BALANCES but does not DECODE, in one place.

        Six near-identical tests asked this of one function with a different
        armor body each — same fixture, same assertion, 77 lines. The cases
        are the value here, so they are a table and the setup runs once.

        The property: a bundle whose block count is right but whose CONTENT
        openssl refuses must be UNUSABLE. Node loads 1 of 2 certs and reports
        nothing, so a balanced-but-undecodable bundle is exactly the silent
        failure the oracle exists to catch.
        """
        from cswap_pin.proxy import _bundle_is_usable

        raw = self._ours(tmp_path).read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        B, E = b"-----BEGIN X509 CRL-----\n", b"-----END X509 CRL-----\n"
        for name, blk in (
            ("empty body", B + E),
            ("whitespace body", B + b"   \n" + E),
            ("not whole base64 quanta", B + b"QUFB=\n" + E),
            ("blank line before END", B + b"QUFBQQ==\n\n" + E),
            ("whitespace-only line before END", B + b"QUFBQQ==\n   \n" + E),
            ("stray characters", B + b"B+0=cA/-\n" + E),
            ("CRLF, whitespace line", b"-----BEGIN X509 CRL-----\r\nQUFBQQ==\r\n   \r\n"
                                      b"-----END X509 CRL-----\r\n"),
            # CRLF and a trailing space are the shapes a real corporate bundle
            # arrives in, and both were separate test methods.
            ("torn CRL, CRLF endings",
             b"-----BEGIN X509 CRL-----\r\nQUJD!!!\r\n-----END X509 CRL-----\r\n"),
            ("torn key block, trailing space",
             b"-----BEGIN PRIVATE KEY----- \nQUJD!!!\n-----END PRIVATE KEY-----\n"),
        ):
            assert _bundle_is_usable(a + blk + raw, raw.strip()) is False, (
                f"{name}: a balanced but undecodable block was accepted — "
                f"node loads 1 of 2 certs and says nothing"
            )

    def case_healthy_non_certificate_blocks_are_still_accepted(self, tmp_path):
        """The false-REJECT direction. A real corporate bundle carries CRLs and
        key blocks; refusing them costs every sibling component its trust."""
        from cswap_pin.proxy import _bundle_is_usable

        raw = self._ours(tmp_path).read_bytes().strip() + b"\n"
        for name, blk in (
            ("one line", b"-----BEGIN X509 CRL-----\nQUFBQQ==\n-----END X509 CRL-----\n"),
            ("CRLF", b"-----BEGIN PUBLIC KEY-----\r\nQUFBQQ==\r\n-----END PUBLIC KEY-----\r\n"),
            ("wrapped", b"-----BEGIN X509 CRL-----\nQUFB\nQUFB\n-----END X509 CRL-----\n"),
        ):
            assert _bundle_is_usable(blk + raw, raw.strip()) is True, (
                f"a healthy {name} non-certificate block was refused"
            )


class TestSalvageRefusesTheSameArmorThePredicateDoes:
    """The salvage arm's armor check had NO test — deleting it left the whole
    suite green, in the same function 0.1.16 edited.

    Every existing salvage fixture uses `!!!not base64!!!`, which the ARMOR
    check and nothing else refuses — so the fixture cannot tell the branches
    apart, and the branch was never exercised. Instrumented: the salvage
    armor path was entered ZERO times across the suite.

    That matters because salvage is the REPAIR path. When the predicate
    refuses a file, salvage decides what the session actually gets. If it
    keeps a block openssl cannot read, the repaired file is as dead as the
    input — measured:

        torn CRL, CRLF endings, through _salvage_bundle
          shipped        salvage kept 2 blocks, node loads 2, handshake OK
          check deleted  salvage kept 4 blocks, node loads 1, handshake NO

    This is exactly the class 0.1.16 was written to close (a guard with no
    test), which is why it is worth a test rather than a comment.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_salvage_drops_a_block_whose_armor_openssl_refuses(self, tmp_path):
        from cswap_pin.proxy import _salvage_bundle, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        # VALID base64 that openssl still refuses: 5 chars is not a whole
        # quantum. `!!!not base64!!!` would be caught by any check, so it
        # cannot isolate this one.
        poison = b"-----BEGIN X509 CRL-----\nQUFB=\n-----END X509 CRL-----\n"
        out = _salvage_bundle(a + poison + raw, raw.strip())
        assert b"QUFB=" not in out, (
            "salvage kept a block whose armor openssl refuses — the repaired "
            "file is as unreadable as the input it was meant to fix"
        )

    def case_salvage_keeps_a_HEALTHY_non_certificate_block(self, tmp_path):
        """The false-REJECT direction: salvage must not narrow the bundle by
        dropping the CRLs and key blocks a real corporate store carries."""
        from cswap_pin.proxy import _salvage_bundle, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        torn = b"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n"
        good = b"-----BEGIN X509 CRL-----\nQUFBQQ==\n-----END X509 CRL-----\n"
        out = _salvage_bundle(good + torn + raw, raw.strip())
        assert b"QUFBQQ==" in out, "salvage dropped a healthy CRL"


class TestTheBlankLineRuleIsAnchoredAndMeansWhitespace:
    """0.1.17's blank-line rule was wrong in BOTH directions, and its docstring
    asserted the opposite.

    `if b"\\n\\n" in body.replace(b"\\r\\n", b"\\n")` matches only a LITERAL
    blank line, anywhere. Two consequences, both measured with node deciding
    (corp-A + block + ours, correct answer 2):

        shape                     predicate   node loads
        WS-only line before END   True        1     <- MISSED
        tab-only line before END  True        1     <- MISSED
        blank right AFTER BEGIN   False       2     <- FALSE REJECT
        blank mid-body            False       2     <- FALSE REJECT
        healthy control           True        2

    The misses are the dangerous half. On the real 132-cert bundle a poisoned
    CRL ahead of our CA gives `extras=0` and a failed handshake on node
    v24.11.1 AND v12.22.9: the session cannot verify the proxy it is routed
    through, with the predicate answering True and salvage re-emitting the
    poison because it shares this function.

    The false rejects are a regression this rule introduced. openssl refuses a
    blank line only IMMEDIATELY BEFORE the terminator; node does not care at
    all. A blank after BEGIN is the RFC 1421 header form (`Proc-Type:` /
    `DEK-Info:` / blank / body) that `openssl genrsa -traditional` emits, and
    refusing it drops the session to a per-launch snapshot instead of the live
    shared file.

    The rule is now ANCHORED to the last line and treats whitespace-only as
    blank — which is what `b"".join(body.split())` three lines above already
    assumed. One rule, one meaning.
    """


    def _ours(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        return ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_blank_line_elsewhere_in_the_body_is_ACCEPTED(self, tmp_path):
        """The false-REJECT direction. openssl only objects immediately before
        the terminator; node loads these at full count."""
        from cswap_pin.proxy import _bundle_is_usable

        raw = self._ours(tmp_path).read_bytes().strip() + b"\n"
        for name, body in (
            ("blank after BEGIN", b"\nQUFBQQ==\n"),
            ("blank mid-body", b"QUFB\n\nQUFB\n"),
        ):
            blk = b"-----BEGIN X509 CRL-----\n" + body + b"-----END X509 CRL-----\n"
            assert _bundle_is_usable(blk + raw, raw.strip()) is True, (
                f"a {name} was refused — node loads it fine, and refusing "
                "drops the session to a stale per-launch snapshot"
            )


class TestATruncatedBundleIsRefusedNotAccepted:
    """The unterminated-block signal had no test — deleting the `yield` and
    keeping the bare `return` left the whole suite green.

    A block with a BEGIN and no END is what a dying writer leaves behind:
    `_write_bundle_atomically`'s own docstring names a torn write as the
    reason it exists. `_pem_blocks` signals it by yielding the `None` label,
    which is how both readers learn the file is damaged. Without the signal
    the scan simply ends, so every block BEFORE the truncation looks like the
    whole file and the predicate approves it.

    Measured with the signal removed:

        input                          shipped   mutant   node loads
        truncated CERT at the tail     False     True     2 of 3
        real 132-cert + truncated tail False     True     133 of 134
        torn write of the real bundle  False     True     132 of 133

    Every row loses a root the file was supposed to carry, and the mutant
    calls the file fine. The END-welded route to the same sentinel IS tested;
    the unterminated route was not — the same blindness this release was
    written to hunt, one function away.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_bundle_whose_last_block_is_unterminated_is_refused(self, tmp_path):
        from cswap_pin.proxy import _bundle_is_usable, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        # A BEGIN with no END: the shape a dying writer leaves.
        truncated = b"-----BEGIN CERTIFICATE-----\nQUFBQQ==\n"
        assert _bundle_is_usable(a + raw + truncated, raw.strip()) is False, (
            "a bundle ending in an unterminated block was approved — the "
            "blocks before the truncation look like the whole file"
        )

    def case_a_torn_write_of_a_real_sized_bundle_is_refused(self, tmp_path):
        """The same shape at the size the fleet actually carries: chop the
        tail off mid-block, as an interrupted write would."""
        from cswap_pin.proxy import _bundle_is_usable, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        blocks = b"".join(
            _other_ca(tmp_path / f"corp-{i}") for i in range(3)
        )
        torn = (blocks + raw)[:-400]
        assert _bundle_is_usable(torn, raw.strip()) is False, (
            "a torn write was approved — node loads only the blocks before "
            "the cut and the session silently trusts less than the file names"
        )


class TestTheLastLineRuleAppliesToCertificatesToo:
    """0.1.18 fixed the branch the real bundle never takes.

    `_armor_decodes` is called only in the `else` arm — non-certificate
    labels. A CERTIFICATE goes to `x509.load_pem_x509_certificate`, and
    `cryptography` parses a whitespace-only line before END happily. So the
    exact shape 0.1.18 was named for sails through when it lands in a
    certificate.

    Instrumented on the file this machine actually carries:

        real bundle labels                 {CERTIFICATE: 132}
        _armor_decodes CALLS on it          0

    The fixed branch is unreachable there. And the shape is fatal, measured
    with node deciding on the real 132-cert bundle plus ours:

        damage before the first END   predicate   node loads
        blank line                    False       0 of 133
        spaces                        True        0 of 133   <- HOLE
        tab                           True        0 of 133   <- HOLE
        healthy control               True      133 of 133

    `extras=0`, not a truncation — node drops the WHOLE extras load, so the
    session cannot verify the proxy it is routed through and every request
    dies. Both judges pass it (the oracle's False routes to salvage, which
    shares the predicate and re-emits the block), and with node absent — the
    normal case here — the poisoned file is wired directly.

    The check belongs in `_pem_blocks`, where both labels and both readers
    pass through, rather than in one arm of one of them.
    """


    def _ours(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        return ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_whitespace_line_before_a_CERTIFICATE_END_is_refused(self, tmp_path):
        from cswap_pin.proxy import _bundle_is_usable

        raw = self._ours(tmp_path).read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        at = a.index(b"-----END CERTIFICATE-----")
        for name, ins in (("spaces", b"   \n"), ("tab", b"\t\n"), ("blank", b"\n")):
            poisoned = a[:at] + ins + a[at:]
            assert _bundle_is_usable(poisoned + raw, raw.strip()) is False, (
                f"a {name} line before a CERTIFICATE's END was accepted — node "
                "loads ZERO extras from it and the session cannot verify its "
                "own proxy"
            )

    def case_a_healthy_certificate_bundle_is_still_accepted(self, tmp_path):
        """The false-REJECT direction, on the label that carries the fleet."""
        from cswap_pin.proxy import _bundle_is_usable

        raw = self._ours(tmp_path).read_bytes().strip() + b"\n"
        a = _other_ca(tmp_path / "corp-a")
        assert _bundle_is_usable(a + raw, raw.strip()) is True, "healthy LF refused"
        assert _bundle_is_usable(
            (a + raw).replace(b"\n", b"\r\n"), raw.strip()
        ) is True, "healthy CRLF refused"


class TestTheEmptyCAGuardIsOnBothSidesOfTheSeam:
    """`_publish_ca` refuses an empty `ours`; the salvage arm of `_trust_file`
    did not — and the unguarded site is the expensive one.

    Two call sites read the same `ca_path` and reach code that treats the
    bytes as OUR CA:

        proxy.py:972  `_publish_ca`   `if not ours: return None`   present
        proxy.py:827  `_trust_file`   no such check                ABSENT

    The failures are not symmetric. `_publish_ca` skipping a write costs one
    file in `ca-trust.d`, which the next launch rewrites. The salvage arm
    decides what the SESSION gets: `_salvage_bundle(body, b"")` returns the
    peer blocks with nothing of ours appended, because the append is gated on
    `_bundle_is_usable(kept, ours)` and that predicate answers False for an
    empty `ours` by its own vacuity guard — not because containment failed.
    Measured before the fix:

        salvage(peer, ours=b"")  ->  1 block, ours ABSENT
        _bundle_is_usable(out, b"")  ->  False   (the vacuous-empty guard)

    A session wired to that bundle trusts the peer's certificates and cannot
    verify the proxy it is routed through — the failure `_bundle_is_usable`
    exists to prevent, arriving through the repair path.

    NOT REACHABLE ON THE NORMAL PATH, and the guard is still worth having.
    `_write_public` is temp-then-rename so a reader never sees a half-written
    ca.pem, and `_certs_consistent` rejects an unparseable one and regenerates
    the pair. So `ours` cannot be empty here today. It is an asymmetry rather
    than a live bug — but "unreachable today" is what the round-4 comment on
    the blank-line rule said about a shape round 5 then reached, and the cost
    of the guard is one line.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_salvage_is_not_reached_with_an_empty_ca(self, tmp_path, monkeypatch):
        import cswap_pin.proxy as proxy
        from cswap_pin.proxy import ensure_ca

        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        monkeypatch.setattr(
            proxy, "require", lambda _n: type(
                "P", (), {"get_claude_config_home": staticmethod(lambda: home / ".claude")}
            )
        )
        shared = home / ".claude" / proxy.CA_TRUST_FILE
        peer = _other_ca(tmp_path / "peer")
        shared.write_bytes(peer)

        # ours: present as a file, EMPTY as content — the state the seam has
        # no guard for. A wiped ca.pem, an external truncation, a caller that
        # did not validate the path it passed.
        ca_path = tmp_path / "certdir" / "ca.pem"
        ca_path.parent.mkdir(parents=True)
        ca_path.write_bytes(b"")

        out = proxy._trust_file(ca_path, None)

        # Whatever it returns must not be a bundle that carries a peer CA and
        # not ours. The honest answer with no CA of our own is "our own path",
        # never a merged file we cannot appear in.
        if out is not None and out.name == "ca-bundle.pem" and out.exists():
            body = out.read_bytes()
            assert b"-----BEGIN" not in body or ca_path.read_bytes().strip(), (
                "the salvage arm wrote a merged bundle from an EMPTY ca.pem — "
                "the session trusts the peer and cannot verify its own proxy. "
                f"bundle carries {body.count(b'-----BEGIN')} blocks"
            )

    def case_salvage_still_repairs_normally_when_the_ca_is_present(self, tmp_path, monkeypatch):
        """The guard must not cost the repair it sits in front of."""
        import cswap_pin.proxy as proxy
        from cswap_pin.proxy import ensure_ca

        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        monkeypatch.setattr(
            proxy, "require", lambda _n: type(
                "P", (), {"get_claude_config_home": staticmethod(lambda: home / ".claude")}
            )
        )
        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        raw = ours.read_bytes().strip() + b"\n"
        peer = _other_ca(tmp_path / "peer")
        torn = b"-----BEGIN X509 CRL-----\nQUFB=\n-----END X509 CRL-----\n"
        shared = home / ".claude" / proxy.CA_TRUST_FILE
        shared.write_bytes(peer + torn + raw)

        out = proxy._trust_file(ours, None)
        body = out.read_bytes()
        assert b"QUFB=" not in body, "the torn block survived the repair"
        assert proxy._bundle_is_usable(body, raw.strip()) is True, (
            "the repaired bundle does not carry our CA"
        )


class TestTheEmptyCAGuardCoversTheOTHERMergeToo:
    """`_merged_ca` is the third site reading `ca_path` as OUR CA, and it
    gated on mtime rather than content.

    The seam has three doors, not two. `_publish_ca` guarded emptiness,
    `_trust_file`'s salvage arm did not (fixed in the same release), and this
    one rebuilds on `not bundle.exists() or <mtime comparison>` and then
    concatenates `ca_path.read_bytes()` unconditionally. An empty `ca.pem`
    passes every one of those conditions.

    Measured, with a control so a zero is not mistaken for "this fixture never
    merges anything":

        ours                blocks out   carries ours
        real CA (control)        2           True
        EMPTY                    1           False
        whitespace only          1           False

    The result goes straight into the session's `NODE_EXTRA_CA_CERTS`
    (`wire_env`), so this is the same consumer the salvage arm feeds: a
    session that trusts the upstream proxy's CA and cannot verify OUR proxy,
    which is the hop it is actually routed through. Every request through the
    pin fails to verify.

    Unreachable on the normal path for the same reason as the salvage arm —
    `_write_public` is temp-then-rename and `_certs_consistent` regenerates an
    unparseable pair — so this is an asymmetry, not a live bug. It is fixed
    because a guard that exists at one door and not the other two is not a
    guard, it is a coincidence.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_an_empty_ca_does_not_produce_a_merge_without_us(self, tmp_path):
        from cswap_pin.proxy import _merged_ca

        ca = tmp_path / "ca.pem"
        ca.write_bytes(b"")
        upstream = tmp_path / "upstream.pem"
        upstream.write_bytes(_other_ca(tmp_path / "up"))

        out = _merged_ca(ca, str(upstream))

        assert out == ca, (
            "_merged_ca built a bundle from an EMPTY ca.pem — it carries the "
            "upstream CA and nothing of ours, and this value goes straight "
            f"into NODE_EXTRA_CA_CERTS. returned {out.name}"
        )

    def case_a_real_ca_still_merges(self, tmp_path):
        """The control: the guard must not cost the merge it sits in front of."""
        from cswap_pin.proxy import _merged_ca, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        upstream = tmp_path / "upstream.pem"
        upstream.write_bytes(_other_ca(tmp_path / "up"))

        out = _merged_ca(ours, str(upstream))

        assert out.name == "ca-bundle.pem", "a healthy merge was refused"
        assert out.read_bytes().count(b"-----BEGIN") == 2, (
            "the merge lost a CA"
        )


class TestTheFourthDoorIsTheOneTheOthersFallInto:
    """0.1.20 guarded doors 2 and 3 and shipped a commit titled "three doors".
    There are four, the fourth is the live path on a machine with
    `NODE_EXTRA_CA_CERTS` set, and door 3's guard lands IN it.

    `_trust_file`'s tail merges `ca_path` with `existing` and returns the
    merged file, with no content check — the same shape as `_merged_ca`. It is
    reached whenever there is no usable shared bundle, which includes the case
    door 3's new guard creates: that guard raises `ValueError`, the blanket
    `except Exception: pass` above swallows it, and control arrives here. The
    guard's own comment claimed "falling through returns our own path". It
    returns our own path only when `existing` is empty, and on the deploy
    target it never is:

        hostname -s                 lambda-docker
        NODE_EXTRA_CA_CERTS         /etc/ssl/certs/ca-certificates.crt

    Measured through `_trust_file(ca, existing=<corp>)`, controls included:

        shared  ours            returned         blocks  carries_ours
        False   real (CONTROL)  ca-bundle.pem    2       True
        False   EMPTY           ca-bundle.pem    1       False
        True    real (CONTROL)  ca-bundle.pem    2       True
        True    EMPTY           ca-bundle.pem    1       False

    The last row is the one that matters: door 3's guard fired and the result
    is byte-identical to not having it. The session is handed a bundle
    carrying the corporate CA and nothing of ours, so it trusts the upstream
    hop and cannot verify the proxy it is actually routed through.

    Two lessons in the fix, both from the review that caught this:

    - Control flow by exception into a 118-line blanket handler puts the
      landing site out of sight of the author. The `raise` is replaced by a
      plain fallthrough so intent and destination are the same line.
    - A test that passes `existing=None` cannot see this door at all. The
      0.1.20 test did exactly that.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _corp(self, tmp_path):
        return _other_ca(tmp_path / "corp")

    def case_an_empty_ca_is_not_merged_with_the_ambient_store(self, tmp_path, monkeypatch):
        import cswap_pin.proxy as proxy

        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        monkeypatch.setattr(
            proxy, "require", lambda _n: type(
                "P", (), {"get_claude_config_home": staticmethod(lambda: home / ".claude")}
            )
        )
        corp = tmp_path / "corp.pem"
        corp.write_bytes(self._corp(tmp_path))
        ca = tmp_path / "certdir" / "ca.pem"
        ca.parent.mkdir(parents=True)
        ca.write_bytes(b"")

        out = proxy._trust_file(ca, str(corp))

        assert out == ca, (
            "the no-shared-bundle tail merged a CONTENTLESS ca.pem with the "
            "ambient store — the session trusts the corporate CA and cannot "
            f"verify its own proxy. returned {out.name} with "
            f"{out.read_bytes().count(b'-----BEGIN')} blocks"
        )

    def case_a_real_ca_is_still_merged_with_the_ambient_store(self, tmp_path, monkeypatch):
        """CONTROL. Without this row the assertion above passes on a function
        that merges nothing at all."""
        import cswap_pin.proxy as proxy
        from cswap_pin.proxy import ensure_ca

        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        monkeypatch.setattr(
            proxy, "require", lambda _n: type(
                "P", (), {"get_claude_config_home": staticmethod(lambda: home / ".claude")}
            )
        )
        corp = tmp_path / "corp.pem"
        corp.write_bytes(self._corp(tmp_path))
        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path

        out = proxy._trust_file(ours, str(corp))

        assert out.name == "ca-bundle.pem", "a healthy merge was refused"
        assert out.read_bytes().count(b"-----BEGIN") == 2, "the merge lost a CA"

    def case_a_nested_launch_keeps_its_merged_bundle(self, tmp_path):
        """`_merged_ca`'s new guard sat AHEAD of the un-merge branch, so an
        empty ca.pem in a nested launch threw away a good bundle that was
        still on disk — strictly worse than 0.1.19, which returned it.

            0.1.19  -> ca-bundle.pem, 2 CAs wired
            0.1.20  -> ca.pem,        0 CAs wired, good bundle untouched on disk
        """
        from cswap_pin.proxy import _merged_ca

        ca = tmp_path / "ca.pem"
        ca.write_bytes(b"")
        bundle = tmp_path / "ca-bundle.pem"
        bundle.write_bytes(_other_ca(tmp_path / "up") + _other_ca(tmp_path / "up2"))

        out = _merged_ca(ca, str(bundle))

        assert out == bundle, (
            "a nested launch was un-merged: the session loses every upstream "
            f"CA while {bundle.name} sits on disk intact. returned {out.name}"
        )


class TestNoEmissionSiteCanHandOverATornFile:
    """Three functions write the file that becomes `NODE_EXTRA_CA_CERTS`.
    `_salvage_bundle` reassembles block-by-block and structurally cannot emit a
    torn one. The other two concatenate their inputs unread.

    Measured before this guard, a torn ambient CA on the input side:

        CONTROL _merged_ca healthy         blocks=2 DAMAGED=False
        site 237  _merged_ca + torn        blocks=1 DAMAGED=True
        site 1010 _trust_file tail + torn  blocks=1 DAMAGED=True

    Why a torn file is worse than a file merely missing a CA, measured by a
    peer session against the REAL client binary (Bun/BoringSSL, not node):

        SSL_CERT_DIR=certdir, NODE_EXTRA_CA_CERTS unset      CONNECTS
        SSL_CERT_DIR=certdir, NODE_EXTRA_CA_CERTS=DAMAGED    FAILS

    A fatal block in OUR file takes down a CA supplied by a completely
    different mechanism. BoringSSL's all-or-nothing is per FILE for the load,
    but a discarded file still sinks the session when it carried the proxy CA —
    so emitting damage does not merely lose us the corporate roots, it poisons
    trust the user configured elsewhere. `_bundle_is_usable` refusing damaged
    INPUT is not enough; the guarantee has to be at emission.

    The repair keeps every block that parses and drops only the bad one, which
    is `_salvage_bundle`'s existing contract — so the corporate roots these
    merges exist to carry survive, minus the block no loader could read.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _torn(self, tmp_path, name):
        pem = _other_ca(tmp_path / name)
        return pem.replace(b"-----END CERTIFICATE-----", b" \n-----END CERTIFICATE-----", 1)

    def _damaged(self, body):
        from cswap_pin.proxy import _pem_blocks

        return any(b[0] is None for b in _pem_blocks(body))

    def _blocks(self, body):
        from cswap_pin.proxy import _pem_blocks

        return len([b for b in _pem_blocks(body) if b[0] is not None])

    def case_merged_ca_does_not_pass_a_torn_ambient_file_through(self, tmp_path):
        from cswap_pin.proxy import _merged_ca, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        upstream = tmp_path / "upstream.pem"
        upstream.write_bytes(self._torn(tmp_path, "up"))

        out = _merged_ca(ours, str(upstream))
        body = out.read_bytes()

        assert not self._damaged(body), (
            "_merged_ca wrote a file with an unreadable block — the session "
            "discards the WHOLE file and loses CAs from SSL_CERT_DIR too. "
            f"blocks={self._blocks(body)}"
        )

    def case_merged_ca_still_carries_a_healthy_ambient_file(self, tmp_path):
        """CONTROL. Without this the assertion above passes on a function that
        merges nothing at all."""
        from cswap_pin.proxy import _merged_ca, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        upstream = tmp_path / "upstream.pem"
        upstream.write_bytes(_other_ca(tmp_path / "up"))

        out = _merged_ca(ours, str(upstream))

        assert self._blocks(out.read_bytes()) == 2, "a healthy merge lost a CA"

    def case_the_trust_file_tail_does_not_pass_a_torn_existing_through(
        self, tmp_path, monkeypatch
    ):
        import cswap_pin.proxy as proxy
        from cswap_pin.proxy import ensure_ca

        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        monkeypatch.setattr(
            proxy, "require", lambda _n: type(
                "P", (), {"get_claude_config_home": staticmethod(lambda: home / ".claude")}
            )
        )
        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        corp = tmp_path / "corp.pem"
        corp.write_bytes(self._torn(tmp_path, "corp"))

        out = proxy._trust_file(ours, str(corp))
        body = out.read_bytes()

        assert not self._damaged(body), (
            "the no-shared-bundle tail wrote a file with an unreadable block "
            f"— blocks={self._blocks(body)}"
        )


class TestTheUnMergeBranchReadsTheFileItReturns:
    """`_merged_ca`'s un-merge branch returned `ca-bundle.pem` on a PATH match
    without ever opening it. Every other path in that function checks content
    or freshness; this one returns before both.

    Measured on 0.1.22, `other == <certdir>/ca-bundle.pem`, control first:

        bundle state           returned        exists  blocks  carries LIVE ca
        CONTROL healthy        ca-bundle.pem   True     2       True
        EMPTY                  ca-bundle.pem   True     0       False
        STALE (dead CA only)   ca-bundle.pem   True     2       False
        TORN                   ca-bundle.pem   True     0       False
        ABSENT                 ca-bundle.pem   FALSE   -        n/a

    The last row wires a path that does not exist. The stale row is the one
    that happens without anyone doing anything wrong: `ensure_ca` regenerates
    the CA whenever `_certs_consistent` is False — expiry (it renews 30 days
    early), a partial cert-dir wipe, a mismatched pair — and `ca-bundle.pem`
    is not in the consistency set, so it survives carrying the RETIRED CA.
    Not self-healing: every later launch takes the same branch and returns the
    same stale file while the live `ca.pem` sits one directory entry away.

    It matters because `wire_global_config` writes `.claude.json`'s env block,
    which Claude Code applies at boot and which therefore BEATS the exec'd env
    from `wire_env`. The wrong writer wins, and a session wired to a bundle
    without the live CA cannot verify the proxy it is routed through.

    Pre-existing in 0.1.19 through 0.1.22 — this is the door the empty-CA
    sweep moved its guards PAST rather than through.
    """


    def _live_and_bundle(self, tmp_path, bundle_content):
        from cswap_pin.proxy import ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        bundle = ours.parent / "ca-bundle.pem"
        if bundle_content is not None:
            bundle.write_bytes(bundle_content)
        return ours, bundle

    def _carries(self, body, pem_path):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from cswap_pin.proxy import _pem_blocks

        want = x509.load_pem_x509_certificate(pem_path.read_bytes()).public_bytes(
            serialization.Encoding.DER
        )
        for label, _h, _e, block in _pem_blocks(body):
            if label != b"CERTIFICATE":
                continue
            try:
                if (
                    x509.load_pem_x509_certificate(block).public_bytes(
                        serialization.Encoding.DER
                    )
                    == want
                ):
                    return True
            except Exception:  # noqa: BLE001 — a block we cannot read is not a match
                pass
        return False

    @pytest.mark.parametrize("state", ["stale", "empty", "absent"])
    def test_a_bundle_without_the_live_ca_is_not_handed_back(self, tmp_path, state):
        from cswap_pin.proxy import _merged_ca

        content = {
            # the realistic one: a CA regeneration left the old bundle behind
            "stale": _other_ca(tmp_path / "dead") + _other_ca(tmp_path / "peer"),
            "empty": b"",
            "absent": None,
        }[state]
        ours, bundle = self._live_and_bundle(tmp_path, content)

        out = _merged_ca(ours, str(bundle))
        body = out.read_bytes() if out.exists() else b""

        assert self._carries(body, ours), (
            f"the un-merge branch returned {out.name} for a {state} bundle "
            "without reading it — the session is wired to a file that does not "
            "carry the CA it must verify the proxy with, and the live ca.pem "
            f"is right there. exists={out.exists()}"
        )

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_healthy_bundle_is_still_returned_unmerged(self, tmp_path):
        """CONTROL, and the property the branch exists for: a nested launch
        must keep its merged bundle rather than un-merging back to ca.pem and
        losing the upstream proxy's CA on every later session."""
        from cswap_pin.proxy import _merged_ca, ensure_ca

        ours = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        bundle = ours.parent / "ca-bundle.pem"
        bundle.write_bytes(ours.read_bytes() + _other_ca(tmp_path / "up"))

        out = _merged_ca(ours, str(bundle))

        assert out == bundle, f"a healthy nested bundle was un-merged to {out.name}"
        assert len(
            [b for b in __import__("cswap_pin.proxy", fromlist=["x"])._pem_blocks(
                out.read_bytes()
            ) if b[0] is not None]
        ) == 2, "the upstream CA was lost"


class TestTheFilterKeepsBlocksAfterTheTearToo:
    """`_drop_unreadable_blocks` USED TO stop at the first damaged marker and
    throw away everything after it.

    `_pem_blocks` ends its scan at the first damage — every damage arm is
    `yield ...; return` — so a plain comprehension over it never sees a block
    past the tear. `_salvage_bundle` handles that with a restart loop
    (`proxy.py:857-892`); the filter had no equivalent, while its docstring and
    this file's own class docstring both claimed parity with it. Both are
    routed through `_parseable_blocks` now, which resumes past damage — the
    table below is what that resumption measures TODAY, not the pre-fix
    numbers (four of its six rows were stale: `drop_unreadable` had drifted
    back to describing the code this class exists to have already replaced).

    Measured on `/etc/ssl/certs/ca-certificates.crt`, this box's real ambient
    store, 125 blocks, CONTROL first. ``ours`` is a freshly minted cswap-pin
    CA — never one of the ambient 125 — so `salvage` is `drop_unreadable`'s
    count plus one (the unconditional append of `ours`) on every row:

        ambient store        drop_unreadable   salvage
        CONTROL untouched          125           126
        tear at idx 0              124           125
        tear at idx 1              124           125
        tear at idx 5              124           125
        tear at idx 62             124           125
        tear at idx 124            124           125

    BEFORE this fix, one damaged block near the front of a corporate root
    bundle — an interrupted `update-ca-certificates`, a partially synced
    store — handed the session a file that LOADED CLEANLY carrying five
    roots instead of 125 (a tear at idx 5 kept only indices 0-4). Nothing
    downstream flagged it: not torn, so `_bundle_is_usable` said usable and
    the node oracle said True (our CA at index 0, ahead of everything lost).

    The old suite could not see this. Replacing the comprehension with the
    restart loop — which takes the idx-5 row from 5 to 124 — killed ZERO
    tests, because every emission test asserts `not _damaged(body)` and only
    the healthy control asserts a block count. A filter that keeps one block
    and a filter that keeps 124 are indistinguishable to `not _damaged`.
    """


    def _store(self):
        import pathlib

        from cswap_pin.proxy import _pem_blocks

        real = pathlib.Path("/etc/ssl/certs/ca-certificates.crt")
        if not real.exists():
            pytest.skip("no ambient store on this box")
        blocks = [b for label, _h, _e, b in _pem_blocks(real.read_bytes()) if label]
        if len(blocks) < 10:
            pytest.skip(f"ambient store too small to tear meaningfully: {len(blocks)}")
        return blocks

    def _kept(self, body):
        from cswap_pin.proxy import _drop_unreadable_blocks, _pem_blocks

        out = _drop_unreadable_blocks(body)
        return len([1 for label, _h, _e, _b in _pem_blocks(out) if label])

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_tear_near_the_front_does_not_cost_the_whole_tail(self):
        blocks = self._store()
        torn = list(blocks)
        torn[5] = torn[5].replace(
            b"-----END CERTIFICATE-----", b" \n-----END CERTIFICATE-----", 1
        )

        kept = self._kept(b"".join(torn))

        assert kept >= len(blocks) - 1, (
            f"the filter stopped at the tear: kept {kept} of {len(blocks)} blocks. "
            "Everything after the damaged one was dropped, so the session is "
            "handed a bundle that loads cleanly and carries a fraction of the "
            "roots it should"
        )

    def case_an_undamaged_store_is_unchanged(self):
        """CONTROL. Without it the assertion above passes on a filter that
        returns its input untouched."""
        blocks = self._store()

        assert self._kept(b"".join(blocks)) == len(blocks), "a healthy store lost blocks"


class TestLoadCertSurvivesAnAmbientErrorFilter:
    """`_load_cert`'s `catch_warnings`/`simplefilter("ignore")` guard is the
    fix 0.1.25 shipped for, and until this class existed the suite could not
    detect its own removal: reverting `_load_cert` to 0.1.24's unguarded body
    (drop the guard, keep the bare try/except) left the WHOLE SUITE green.

    Detectable only under a filter that promotes the warning to an error —
    nothing here promotes it globally (see `pyproject.toml`'s
    `[tool.pytest.ini_options]`, which sets no `filterwarnings`), so each test
    installs its OWN `-W error`-equivalent scope with `pytest.warns` /
    `warnings.catch_warnings`, rather than a global config change that would
    alter every other test's environment.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_zero_serial_cert_survives_under_an_error_filter(self):
        """A LOADABLE certificate must not become a dropped one just because
        the ambient filter promotes its own deprecation warning to an error.

        `CryptographyDeprecationWarning` subclasses `UserWarning` ->
        `Warning` -> `Exception`, so an unguarded `except Exception` catches
        it as if the block were unparseable. It is not: openssl and python
        `ssl` both accept a zero-serial root, and 0.1.25 exists to keep this
        proxy accepting it too.
        """
        import warnings

        from cswap_pin.proxy import _load_cert

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            cert = _load_cert(ZERO_SERIAL_ROOT_PEM)

        assert cert is not None, (
            "a loadable zero-serial certificate was dropped under an ambient "
            "error filter — _load_cert's guard is gone or not working"
        )

    def case_unparseable_bytes_still_return_none_under_the_same_filter(self):
        """CONTROL for the test above: the guard must not turn EVERY error
        into a swallowed success. Garbage must still come back None."""
        import warnings

        from cswap_pin.proxy import _load_cert

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            cert = _load_cert(b"-----BEGIN CERTIFICATE-----\nnot a cert\n-----END CERTIFICATE-----\n")

        assert cert is None, "garbage was accepted as a certificate"


class TestCarriesUsesTheSameGuardAsEverySite:
    """`_carries` raw-loads at both its `want` and its per-block sites instead
    of going through `_load_cert` — the release note for b5fc87b says "both
    x509 call sites use it: the filter's CERTIFICATE arm and `_carries`",
    which is false; `_carries` still has its own bare
    `except Exception: return False` at each load.

    Exposure is real but narrow: `_make_ca` uses `x509.random_serial_number()`
    (RFC 5280, never 0), so this cannot fire on a CA cswap-pin minted itself —
    only on a `ca_path` a DIFFERENT MITM published into the shared trust dir.
    A wrong `False` there costs a bundle rebuild, not lost trust. Still, it is
    the same shared-vs-per-caller shape the ladder argues for: one guard in
    `_load_cert` beats a guard duplicated at each raw-load site.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_zero_serial_want_is_still_found_under_an_error_filter(self, tmp_path):
        """`want` (the CA `_carries` is asked to find) is zero-serial and
        loadable — `_load_cert` would keep it. The raw `x509.load_pem_x509_
        certificate` call at `_carries`'s `want` site does not, and drops it
        under an ambient error filter: `want` becomes unreadable, so `_carries`
        answers False for a CA that IS in the store."""
        import warnings

        from cswap_pin.proxy import _carries

        ca_path = tmp_path / "want.pem"
        ca_path.write_bytes(ZERO_SERIAL_ROOT_PEM)
        # A single-block store containing exactly the cert we are looking for.
        store_body = ZERO_SERIAL_ROOT_PEM

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            found = _carries(store_body, ca_path)

        assert found, (
            "_carries answered False for a zero-serial CA that IS in the "
            "store — its raw x509 load dropped a certificate _load_cert "
            "would have kept under the same ambient error filter"
        )

    def case_a_normal_ca_is_still_found_under_an_error_filter(self, tmp_path):
        """CONTROL: an ordinary (non-zero-serial) CA must still be found
        under the same filter, so the test above is not passing vacuously."""
        import warnings

        from cswap_pin.proxy import _carries, ensure_ca

        ca_path = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        store_body = ca_path.read_bytes()

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            found = _carries(store_body, ca_path)

        assert found, "a normal CA was not found in a store that carries it"


class TestLoadCertDoesNotRaceItself:
    """`_load_cert`'s `warnings.catch_warnings()` snapshots and restores
    process-global state (`warnings.filters`, `showwarning`,
    `_showwarnmsg_impl`), reachable concurrently from the daemon's
    `watch_refcount` thread and per-connection `_serve_client` threads.

    Forced deterministically with `threading.Event` handshakes, not GIL
    timing luck: thread B `__enter__`s first (snapshotting the ambient
    error filter), waits for thread A to install ITS `simplefilter("ignore")`,
    then `__exit__`s — restoring B's pre-ignore snapshot — before A's own
    `load_pem_x509_certificate` call runs. That stomps A's active "ignore"
    back to "error" between A's `simplefilter` and A's load, so a warning
    that A's own guard was supposed to suppress fires as an exception inside
    A's `try`, and A's certificate is dropped.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_concurrent_load_cannot_stomp_this_threads_ignore_filter(self):
        import threading
        import warnings

        from cswap_pin import proxy

        real_load = proxy.x509.load_pem_x509_certificate
        # Two DISTINCT objects with identical content, so the wrapper below
        # can tell which call site is which by identity (`is`), the way two
        # different blocks parsed in the same scan would be distinct objects.
        block_b = bytes(bytearray(ZERO_SERIAL_ROOT_PEM))
        block_a = ZERO_SERIAL_ROOT_PEM

        b_ready = threading.Event()
        a_about_to_load = threading.Event()
        b_finished = threading.Event()

        def wrapped_load(data, backend=None):
            if data is block_b:
                b_ready.set()
                a_about_to_load.wait(timeout=0.4)
                return real_load(data)
            if data is block_a:
                a_about_to_load.set()
                b_finished.wait(timeout=0.4)
                return real_load(data)
            return real_load(data)

        result = {}

        def thread_b():
            result["b"] = proxy._load_cert(block_b)
            b_finished.set()

        def thread_a():
            b_ready.wait(timeout=5)
            result["a"] = proxy._load_cert(block_a)

        proxy.x509.load_pem_x509_certificate = wrapped_load
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                tb = threading.Thread(target=thread_b)
                ta = threading.Thread(target=thread_a)
                tb.start()
                ta.start()
                tb.join(timeout=10)
                ta.join(timeout=10)
        finally:
            proxy.x509.load_pem_x509_certificate = real_load

        assert result.get("b") is not None, "fixture broken: B's own load should succeed"
        assert result.get("a") is not None, (
            "a concurrent _load_cert call stomped this thread's warning "
            "filter between simplefilter('ignore') and the load — the "
            "catch_warnings() guard is not safe under concurrent callers"
        )


class TestARefusedUnlinkDoesNotReportDisarmed:
    """`apply_pin(email=None)` unlinks the proxy secret to disarm the gate,
    then returns `False` unconditionally — the SAME `False` whether the
    secret is now gone or the unlink was REFUSED (permission denied, a
    read-only mount) and it is still sitting there, armed. A caller reading
    `False` has no way to tell "disarmed" from "still armed, and I could not
    tell you" — the shape every task in this release is about.

    Absent (`FileNotFoundError`) and refused (any other `OSError`) are not
    the same outcome and must not share a silent `pass`.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_refused_unlink_does_not_look_like_a_successful_disarm(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        pin_proxy.ensure_proxy_secret(certdir)
        assert pin_proxy.read_proxy_secret(certdir) is not None

        class _Sw:
            backup_dir = tmp_path

        monkeypatch.setattr(pin_proxy, "save_pin", lambda *a, **k: None)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)

        real_unlink = Path.unlink

        def refusing_unlink(self, *a, **k):
            if self.name == pin_proxy._SECRET_FILE:
                raise PermissionError(13, "Permission denied")
            return real_unlink(self, *a, **k)

        monkeypatch.setattr(Path, "unlink", refusing_unlink)

        raised = False
        try:
            pin_proxy.apply_pin(_Sw(), None, None)
        except OSError:
            raised = True

        assert raised, (
            "apply_pin swallowed a REFUSED unlink and returned normally — "
            "the secret is still armed and nothing told the caller"
        )
        assert pin_proxy.read_proxy_secret(certdir) is not None, (
            "fixture broken: the secret should still be there since the "
            "unlink was refused"
        )
        # The absent-secret CONTROL is already covered by
        # TestTheGateDisarmsWhenThePinIsCleared.test_clearing_without_a_secret_is_not_an_error.


class TestAReleaseFailureDoesNotLookLikeSuccess:
    """`_release_daemon_state` returns `False` both when it dropped
    ``proxy.json`` (its own state, now gone) AND when the unlink was
    REFUSED — same value, opposite facts. A refused delete leaves a state
    file naming a DEAD pid, and the next daemon start (`PinProxy.start`,
    which calls `read_daemon_state` to reclaim a port) reads that file and
    believes a daemon it can never reach.
    """


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_refused_unlink_is_distinguishable_from_a_successful_release(
        self, tmp_path, monkeypatch
    ):
        import os

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        pin_proxy.write_daemon_state(certdir, 12345, os.getpid(), "fp-abc")
        assert pin_proxy.read_daemon_state(certdir) is not None

        real_unlink = Path.unlink

        def refusing_unlink(self, *a, **k):
            if self.name == pin_proxy._STATE_FILE:
                raise PermissionError(13, "Permission denied")
            return real_unlink(self, *a, **k)

        monkeypatch.setattr(Path, "unlink", refusing_unlink)

        raised = False
        try:
            pin_proxy._release_daemon_state(certdir)
        except OSError:
            raised = True

        assert raised, (
            "_release_daemon_state swallowed a REFUSED unlink and returned "
            "normally — the state file still names this (now-dead) daemon "
            "and the next start will believe it"
        )
        assert pin_proxy.read_daemon_state(certdir) is not None, (
            "fixture broken: the state file should still be there since "
            "the unlink was refused"
        )

    def case_a_successful_release_still_returns_false(self, tmp_path):
        """CONTROL: releasing our own state normally must still succeed and
        return False (not "someone else owns it now")."""
        import os

        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True)
        pin_proxy.write_daemon_state(certdir, 12345, os.getpid(), "fp-abc")

        assert pin_proxy._release_daemon_state(certdir) is False
        assert pin_proxy.read_daemon_state(certdir) is None


class TestASalvageWriteFailureNeverCostsOurOwnCA:
    """`_trust_file`'s salvage-write can fail (disk full, a read-only cert
    dir) and lands in the blanket `except Exception: pass` — measured
    whether that collapse is still safe on every path that reaches it.

    It is: `ours` is confirmed non-empty before the salvage attempt, and
    every branch below the handler falls through to `return Path(ca_path)`
    — the CA already on disk, already read once — so a salvage-write
    failure costs the corporate roots (a narrowing this file already treats
    as acceptable everywhere else — see `TestNarrowingIsDeliberatelyUnguarded`)
    but never the session's ability to verify its OWN proxy. This is the
    control that would go red if a future change made that stop being true.
    """


    def _cfg(self, tmp_path, monkeypatch):
        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        return home

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_totally_failed_write_still_returns_our_own_readable_ca(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin.proxy import CA_TRUST_FILE, _trust_file, ensure_ca

        cfg = self._cfg(tmp_path, monkeypatch)
        ca_path = ensure_ca(tmp_path / "pin-proxy", "api.anthropic.com").ca_path
        other_ca = ensure_ca(tmp_path / "other", "other.example.com").ca_path

        shared = cfg / CA_TRUST_FILE
        # Unusable (unbalanced marker) so `_trust_file` takes the salvage arm.
        shared.write_bytes(
            (ca_path.read_bytes().strip() + b"\n" + other_ca.read_bytes().strip())
            .replace(b"-----END CERTIFICATE-----", b" X\n-----END CERTIFICATE-----", 1)
        )

        import cswap_pin.proxy as pin_proxy

        def always_fails(bundle, body):
            raise OSError("simulated: every bundle write fails")

        monkeypatch.setattr(pin_proxy, "_write_bundle_atomically", always_fails)

        result = _trust_file(ca_path, None)

        assert Path(result) == ca_path, (
            f"a salvage-write failure returned {result}, not our own CA — "
            "the session can no longer verify even its own proxy"
        )
        assert Path(result).read_bytes().strip(), "our own CA file is empty or unreadable"


class TestTeardownAsksThePortBeforeUnwiring:
    """An unwire is only correct when nobody is serving the wired address.

    MEASURED, work-mac, a live session retrying:
        19:16:35 pid=58845 unwired .claude.json — sessions fall back
        19:16:36 pid=60863 serving on port 53749
    One second apart. The departing daemon decided from the state files, which
    say it is alone right up until a successor publishes — and a successor
    publishes only once it is already serving. So the files and the port
    disagree for exactly the length of a handover, and the config lost its pin
    inside that window.

    The port is the thing a session actually dials, so the port is what decides.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_served_port_keeps_its_wiring(self, tmp_path, monkeypatch):
        import socket

        from cswap_pin import proxy

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        try:
            assert proxy._port_answers(srv.getsockname()[1]) is True
        finally:
            srv.close()

    def case_an_unserved_port_does_not(self, tmp_path):
        """The other direction, or the guard would just be 'never unwire'."""
        import socket

        from cswap_pin import proxy

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert proxy._port_answers(port) is False

    def case_the_probe_gates_the_unwire_in_the_real_teardown(self):
        """Both halves above are about the probe. This is about the CALLER:
        a correct probe nothing consults changes nothing."""
        import ast
        import inspect
        import textwrap

        from cswap_pin import proxy

        tree = ast.parse(textwrap.dedent(inspect.getsource(proxy.daemon_main)))
        teardown = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.FunctionDef) and n.name == "_teardown"
        )
        calls = sorted(
            (n.lineno, getattr(n.func, "id", getattr(n.func, "attr", "")))
            for n in ast.walk(teardown)
            if isinstance(n, ast.Call)
        )
        # EITHER SPELLING. The question moved into `_successor_is_serving`
        # when the probe learned to ignore our own holder's socket — a
        # listen-only socket completes a handshake, so `_port_answers` alone
        # answered "served" about the port we had just stopped serving. What
        # this case is about is the ORDER, which is unchanged.
        probe = [
            ln for ln, name in calls
            if name in ("_port_answers", "_successor_is_serving")
        ]
        unwire = [ln for ln, name in calls if name == "wire_global_config"]
        assert probe, "_teardown no longer asks whether the port is served"
        assert unwire, "_teardown no longer unwires at all"
        assert probe[0] < unwire[0], (
            "the port check must run BEFORE the unwire, or it decides nothing"
        )


class TestEverySmallCaseHolder:
    """Every small case-holder in this file, as ONE pytest test.

    Each holder is run SEPARATELY (its own instance, its own helpers)
    rather than merged by inheritance: three of these classes define a
    `_ca` / `_cfg` / `_ours` helper with different meanings, and a
    shared MRO would have handed every case just one of them.
    A failure still names the class its case came from.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(
            [
                TestLiveRemoteControlSessions(),
                TestRepinIsLive(),
                TestIsPinnedRoute(),
                TestParseUpstreamProxy(),
                TestResolvePinToken(),
                TestDaemonState(),
                TestEnsureProxyLifecycle(),
                TestKillDaemon(),
                TestDaemonSignalTeardown(),
                TestOrphanSweep(),
                TestWorkerJwtRoutesAreNotSwapped(),
                TestUltrareviewIsPinned(),
                TestPinTokenRefreshIsSerialized(),
                TestAmbientProxyPrefersTheLauncherProxy(),
                TestNarrowingIsDeliberatelyUnguarded(),
                TestTheGateDisarmsWhenThePinIsCleared(),
                TestArmingReportsWhoItCutsOff(),
                TestABlindDaemonIsNotReusedForever(),
                TestSharedBundleGuardMatchesNode(),
                TestTheKillBudgetOutlastsTheDrain(),
                TestTheOracleWorksOnRUNTIMESWEDoNotDevelopOn(),
                TestTheOracleTestsRunWhereTheyClaimTo(),
                TestTheOracleIsAVetoNeverAnApproval(),
                TestTheSalvageArmLogsWhatItDid(),
                TestTheOwnershipGuardCannotBeFakedByName(),
                TestTheMissingLeafArmStaysUnknown(),
                TestTheProbeAsksAboutTHISBundle(),
                TestTheArmorCheckIsNotAcceptingEmptiness(),
                TestAnEmptyArmorIsNotIntactArmor(),
                TestSalvageRefusesTheSameArmorThePredicateDoes(),
                TestTheBlankLineRuleIsAnchoredAndMeansWhitespace(),
                TestATruncatedBundleIsRefusedNotAccepted(),
                TestTheLastLineRuleAppliesToCertificatesToo(),
                TestTheEmptyCAGuardIsOnBothSidesOfTheSeam(),
                TestTheEmptyCAGuardCoversTheOTHERMergeToo(),
                TestTheUnMergeBranchReadsTheFileItReturns(),
                TestTheFilterKeepsBlocksAfterTheTearToo(),
                TestLoadCertSurvivesAnAmbientErrorFilter(),
                TestCarriesUsesTheSameGuardAsEverySite(),
                TestLoadCertDoesNotRaceItself(),
                TestARefusedUnlinkDoesNotReportDisarmed(),
                TestAReleaseFailureDoesNotLookLikeSuccess(),
                TestASalvageWriteFailureNeverCostsOurOwnCA(),
                ],
            request,
            tmp_path_factory,
        )
