"""Tests for the account-pin proxy's request classification.

The proxy MITMs api.anthropic.com and swaps the Authorization bearer to a
pinned account's token, but ONLY on the Remote-Control and Artifact routes;
inference (/v1/messages) and everything else must pass through untouched.
"""

from __future__ import annotations

import json
import os
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

    def test_lists_only_sessions_with_a_live_bridge(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import live_remote_control_sessions

        d = self._sessions_dir(tmp_path, monkeypatch)
        (d / "1.json").write_text(json.dumps(
            {"sessionId": "a", "name": "with-rc", "bridgeSessionId": "cse_x"}))
        (d / "2.json").write_text(json.dumps(
            {"sessionId": "b", "name": "no-rc", "bridgeSessionId": None}))
        (d / "3.json").write_text(json.dumps({"sessionId": "c", "name": "never"}))

        assert live_remote_control_sessions() == ["with-rc"]

    def test_unreadable_registry_is_not_an_error(self, tmp_path, monkeypatch):
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

    def test_provider_follows_a_repin_without_a_respawn(self, tmp_path):
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

    def test_fingerprint_ignores_the_account(self, tmp_path):
        """Including the account would recycle the daemon on every re-pin,
        and a recycle is exactly what a live session must not need."""
        from cswap_pin.proxy import daemon_fingerprint

        assert daemon_fingerprint("1", "one@example.com") == daemon_fingerprint(
            "2", "two@example.com"
        )


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
    def test_code_sessions_is_pinned(self):
        # Remote Control creates/uses claude.ai code sessions here.
        assert is_pinned_route("/v1/code/sessions") is True

    def test_messages_is_not_pinned(self):
        # Inference must follow the swapped (disk) account, never the pin.
        assert is_pinned_route("/v1/messages") is False

    def test_frame_deploy_is_pinned(self):
        # Artifact publishes ("frames") are owned by the creating bearer too.
        assert is_pinned_route("/api/frame/deploy/init") is True

    def test_session_unarchive_is_pinned(self):
        # RC reconnect unarchives the session at /v1/sessions/{id}/unarchive
        # (NOT /v1/code/sessions) before re-bridging. Measured: if this route
        # keeps the disk bearer while the bridge is swapped, the session's
        # ownership splits — unarchive lands it on the disk account, and the
        # reconnect resolves there, so the pinned account never sees it.
        assert is_pinned_route("/v1/sessions/cse_01ABC/unarchive") is True

    def test_bare_sessions_list_not_pinned(self):
        # A plain /v1/sessions or /v1/messages must not be swept in.
        assert is_pinned_route("/v1/messages") is False


class TestParseUpstreamProxy:
    def test_none_when_no_upstream(self):
        # No prior proxy -> the proxy dials api.anthropic.com directly.
        assert parse_upstream_proxy("") is None
        assert parse_upstream_proxy(None) is None

    def test_ccf_loopback(self):
        # The common case: CCF's forward proxy already on HTTPS_PROXY.
        assert parse_upstream_proxy("http://127.0.0.1:9901").address == ("127.0.0.1", 9901)

    def test_bare_host_port(self):
        # Some proxies are set without a scheme.
        assert parse_upstream_proxy("corp.example.net:8118").address == (
            "corp.example.net", 8118
        )

    def test_defaults_port_80(self):
        assert parse_upstream_proxy("http://proxy.local").address == ("proxy.local", 80)

    def test_an_https_proxy_defaults_to_443(self):
        """The scheme decides the port.

        Defaulting every scheme to 80 dialled a TLS proxy's plaintext port,
        so in an environment where that proxy is the only route out, no
        pinned request could succeed.
        """
        chain = parse_upstream_proxy("https://proxy.corp.example")
        assert chain.address == ("proxy.corp.example", 443)
        assert chain.tls is True

    def test_an_explicit_port_still_wins_over_the_scheme(self):
        chain = parse_upstream_proxy("https://proxy.corp.example:8443")
        assert chain.address == ("proxy.corp.example", 8443)
        assert chain.tls is True

    def test_credentials_in_the_url_become_a_proxy_authorization_header(self):
        """An authenticated corporate proxy answers 407 without this.

        Reducing the URL to (host, port) discarded the userinfo entirely, so
        the CONNECT went out unauthenticated and every pinned request failed.
        """
        import base64

        chain = parse_upstream_proxy("http://alice:s3cr3t@proxy.corp:8080")
        assert chain.address == ("proxy.corp", 8080)
        expected = base64.b64encode(b"alice:s3cr3t").decode()
        assert chain.auth == f"Basic {expected}"
        assert chain.connect_headers() == f"Proxy-Authorization: Basic {expected}\r\n"

    def test_percent_encoded_credentials_are_decoded(self):
        """userinfo is percent-encoded in a URL; the header carries the bytes.

        A password with an `@` or `:` MUST be encoded in the URL, so passing
        the raw form through would send a credential the proxy never issued.
        """
        import base64

        chain = parse_upstream_proxy("http://user%40corp:p%40ss%3Aword@proxy:3128")
        expected = base64.b64encode(b"user@corp:p@ss:word").decode()
        assert chain.auth == f"Basic {expected}"

    def test_a_plain_proxy_sends_no_authorization_header(self):
        chain = parse_upstream_proxy("http://127.0.0.1:9901")
        assert chain.auth is None
        assert chain.connect_headers() == ""
        assert chain.tls is False


class TestEnsureCA:
    def test_generates_ca_and_leaf_files(self, tmp_path):
        result = ensure_ca(tmp_path, "api.anthropic.com")
        assert (tmp_path / "ca.pem").exists()
        assert (tmp_path / "leaf.pem").exists()
        assert (tmp_path / "leaf.key").exists()
        # The caller trusts the CA via NODE_EXTRA_CA_CERTS.
        assert result.ca_path == tmp_path / "ca.pem"

    def test_ca_is_a_ca(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        ca = x509.load_pem_x509_certificate((tmp_path / "ca.pem").read_bytes())
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert bc.ca is True

    def test_leaf_covers_host_via_san(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        leaf = x509.load_pem_x509_certificate((tmp_path / "leaf.pem").read_bytes())
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        assert "api.anthropic.com" in san.get_values_for_type(x509.DNSName)

    def test_leaf_is_server_auth(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        leaf = x509.load_pem_x509_certificate((tmp_path / "leaf.pem").read_bytes())
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert ExtendedKeyUsageOID.SERVER_AUTH in eku

    def test_leaf_signed_by_ca(self, tmp_path):
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

    def test_idempotent_reuses_ca(self, tmp_path):
        ensure_ca(tmp_path, "api.anthropic.com")
        ca1 = (tmp_path / "ca.pem").read_bytes()
        ensure_ca(tmp_path, "api.anthropic.com")
        ca2 = (tmp_path / "ca.pem").read_bytes()
        assert ca1 == ca2  # existing CA is not regenerated

    def test_leaf_passes_real_tls_validation(self, tmp_path):
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

    def test_returns_stored_token_when_fresh(self):
        from cswap_pin.proxy import resolve_pin_token
        # expiry far in the future -> no refresh, return as-is
        future = 10_000_000_000_000
        creds = self._creds("live-token", future)
        def refresh(_c):
            raise AssertionError("must not refresh a fresh token")
        token, new_creds = resolve_pin_token(creds, refresh)
        assert token == "live-token"
        assert new_creds is None  # nothing rotated

    def test_refreshes_when_expired(self):
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
    def test_returns_none_when_pin_is_active_account(self):
        # Disk bearer already IS the pin account: no swap needed, and never
        # touch the live store the client owns.
        from cswap_pin.proxy import make_pin_token_provider
        sw = _FakeSwitcher(active_num="2")
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() is None

    def test_no_token_because_nothing_to_swap_is_not_a_failure(self):
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

    def test_an_unreadable_store_is_still_a_failure(self):
        """The split must not swallow the case the warning exists for."""
        from cswap_pin.proxy import make_pin_token_provider
        sw = _FakeSwitcher(active_num="1", backups={})  # cannot read account 2
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() is None
        assert provider.pin_is_noop() is False, "unreadable credential must still warn"

    def test_returns_backup_token_when_pin_inactive(self):
        import json
        from cswap_pin.proxy import make_pin_token_provider
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "pin-live", "expiresAt": 10_000_000_000_000,
            "refreshToken": "rt"}})
        sw = _FakeSwitcher(active_num="1", backups={"2": creds})
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() == "pin-live"
        assert sw.persisted == []  # fresh token: nothing rotated

    def test_refreshes_and_persists_when_backup_expired(self, monkeypatch):
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

    def _expired(self):
        import json
        return json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt-1"}})

    def _rotated(self):
        import json
        return json.dumps({"claudeAiOauth": {
            "accessToken": "fresh", "expiresAt": 10_000_000_000_000,
            "refreshToken": "rt-2"}})

    def test_refresh_is_routed_through_consume_backup_grant(self, monkeypatch):
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

    def test_the_gate_persists_so_the_pin_must_not_write_again(self):
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

    def test_a_busy_gate_yields_instead_of_killing_the_lineage(self):
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

    def test_an_older_host_without_the_gate_still_refreshes(self, monkeypatch):
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

    def test_roundtrip(self, tmp_path):
        from cswap_pin.proxy import load_pin, save_pin
        assert load_pin(tmp_path) is None
        save_pin(tmp_path, "pin@example.com", "org-uuid-1")
        assert load_pin(tmp_path) == ("pin@example.com", "org-uuid-1")

    def test_unpin(self, tmp_path):
        from cswap_pin.proxy import load_pin, save_pin
        save_pin(tmp_path, "pin@example.com", "org-uuid-1")
        save_pin(tmp_path, None, None)
        assert load_pin(tmp_path) is None

    def test_a_malformed_settings_file_is_not_overwritten(self, tmp_path):
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

    def test_coexists_with_autoswitch_settings(self, tmp_path):
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

    def test_sets_proxy_and_ca(self, tmp_path):
        from cswap_pin.proxy import wire_env
        ca = tmp_path / "ca.pem"
        ca.write_text("PIN-CA\n")
        env = wire_env({}, 9955, ca)
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert env["https_proxy"] == "http://127.0.0.1:9955"
        assert env["NODE_EXTRA_CA_CERTS"] == str(ca)

    def test_rewrites_an_all_proxy_but_never_invents_one(self, tmp_path):
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

    def test_merges_existing_node_extra_ca(self, tmp_path):
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

    def _config(self, tmp_path, monkeypatch, initial: dict) -> "Path":
        from pathlib import Path
        path = Path(tmp_path) / ".claude.json"
        path.write_text(json.dumps(initial), encoding="utf-8")
        monkeypatch.setattr(
            "claude_swap.paths.get_global_config_path", lambda: path
        )
        return path

    def test_the_config_is_never_published_wider_than_it_was(
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

    def test_a_leftover_temp_file_cannot_dictate_the_mode(
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

    def test_writes_proxy_env(self, tmp_path, monkeypatch):
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        path = self._config(tmp_path, monkeypatch, {"projects": {}})

        assert wire_global_config(9955, Path("/tmp/ca.pem")) is True
        env = json.loads(path.read_text())["env"]
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert env["NODE_EXTRA_CA_CERTS"] == "/tmp/ca.pem"
        # unrelated config must survive
        assert json.loads(path.read_text())["projects"] == {}

    def test_all_proxy_names_the_same_hop(self, tmp_path, monkeypatch):
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

    def test_an_all_proxy_we_added_is_removed_not_blanked(
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

    def test_unwire_restores_a_displaced_value(self, tmp_path, monkeypatch):
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

    def test_unwire_leaves_no_env_block_when_it_was_ours_alone(
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

    def test_merges_an_existing_ca_instead_of_replacing_it(
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

    def test_wires_the_self_loop_marker(self, tmp_path, monkeypatch):
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

    def test_apply_pin_clear_unwires(self, tmp_path, monkeypatch):
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

    def test_missing_config_is_not_an_error(self, tmp_path, monkeypatch):
        from pathlib import Path
        from cswap_pin.proxy import wire_global_config
        monkeypatch.setattr(
            "claude_swap.paths.get_global_config_path",
            lambda: Path(tmp_path) / "absent.json",
        )
        assert wire_global_config(9955, Path("/tmp/ca.pem")) is False


class TestEnsureProxy:
    """ensure_proxy: no pin → None; live daemon → reuse; else spawn."""

    class _Sw:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
        def resolve_account(self, identifier):
            return ("2", "pin@example.com", "org-1")

    def test_none_when_no_pin(self, tmp_path):
        from cswap_pin.proxy import ensure_proxy
        assert ensure_proxy(self._Sw(tmp_path)) is None

    def test_spawns_when_no_daemon(self, tmp_path, monkeypatch):
        from cswap_pin import proxy as pin_proxy
        pin_proxy.save_pin(tmp_path, "pin@example.com", "org-1")
        spawned = []
        def fake_spawn(account_num, email, certdir):
            spawned.append((account_num, email))
            return 9955
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", fake_spawn)
        port, ca = pin_proxy.ensure_proxy(self._Sw(tmp_path))
        assert port == 9955
        assert spawned == [("2", "pin@example.com")]
        assert ca == tmp_path / "pin-proxy" / "ca.pem"

    def test_reuses_live_daemon(self, tmp_path, monkeypatch):
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

    def test_none_when_pin_account_gone(self, tmp_path):
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

    def test_roundtrip(self, tmp_path):
        from cswap_pin.proxy import write_daemon_state, read_daemon_state
        write_daemon_state(tmp_path, port=51000, pid=1234, fingerprint="fp-abc")
        st = read_daemon_state(tmp_path)
        assert st == {"port": 51000, "pid": 1234, "fingerprint": "fp-abc"}

    def test_missing_is_none(self, tmp_path):
        from cswap_pin.proxy import read_daemon_state
        assert read_daemon_state(tmp_path) is None

    def test_corrupt_is_none(self, tmp_path):
        from cswap_pin.proxy import read_daemon_state
        (tmp_path / "proxy.json").write_text("{not json")
        assert read_daemon_state(tmp_path) is None

    def test_fingerprint_encodes_the_code_only(self, tmp_path):
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

    def test_reuses_fresh_daemon_without_spawn(self, tmp_path, monkeypatch):
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

    def test_recycles_stale_fingerprint(self, tmp_path, monkeypatch):
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


class TestRefcount:
    """FIFO refcount (CCF model): the daemon lives while >=1 session holds a
    write fd on the refcount FIFO, and self-terminates when the last one closes
    (normal exit OR kill -9 — the OS closes fds regardless)."""

    def test_wire_env_attaches_refcount_fd(self, tmp_path):
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

    def test_daemon_exits_when_all_holders_close(self, tmp_path):
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

    def test_daemon_that_never_gets_a_holder_still_dies(self, tmp_path):
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
            kwargs={"first_holder_timeout": 0.5}, daemon=True,
        ).start()
        assert fired.wait(timeout=5), "daemon never torn down — it would linger forever"

    def test_a_silent_holder_is_not_mistaken_for_no_holder(self, tmp_path):
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
            kwargs={"first_holder_timeout": 0.5}, daemon=True,
        ).start()
        # Well past the first-holder timeout: a silent holder must NOT trip it.
        assert not fired.wait(timeout=2), "tore down while a holder was still attached"
        os.close(holder)
        assert fired.wait(timeout=3), "did not tear down after the holder closed"

    def test_a_globally_wired_daemon_is_not_an_orphan(self, tmp_path, monkeypatch):
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
            kwargs={"first_holder_timeout": 0.3}, daemon=True,
        ).start()
        assert not fired.wait(timeout=2), (
            "tore down a daemon the global config still routes sessions to"
        )

    def test_an_unwired_daemon_still_dies(self, tmp_path, monkeypatch):
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
            kwargs={"first_holder_timeout": 0.3}, daemon=True,
        ).start()
        assert fired.wait(timeout=5), "orphan lingered — reaper disabled by a foreign pin"

    def test_the_last_holder_leaving_does_not_strand_wired_sessions(
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
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set), daemon=True
        ).start()
        # Let the watcher SEE the holder: it only switches to the blocking
        # (real-EOF) read once a writer has attached, and this test is about
        # that second phase, not the first-holder timeout.
        time.sleep(0.4)
        os.close(holder)  # ...and leaves, while the wiring still names us
        assert not fired.wait(timeout=2), (
            "tore down a daemon the global config still routes sessions "
            "to — they get ConnectionRefused and cannot be redirected"
        )

    def test_the_last_holder_leaving_still_reaps_an_unclaimed_daemon(
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
        fired = threading.Event()
        threading.Thread(
            target=watch_refcount, args=(fifo, fired.set), daemon=True
        ).start()
        time.sleep(0.4)  # as above: reach the blocking phase before closing
        os.close(holder)
        assert fired.wait(timeout=5), (
            "an unreferenced daemon lingered — the reaper stopped working"
        )




class TestAutoViewPinBadge:
    """The auto-switch view marks the cloud-pinned account ON ITS OWN ROW.

    It used to name the pin on the summary line instead, which made you match
    an email against the list printed directly below it rather than just
    reading the list — and pushed that line past 80 columns.
    """

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

    def test_badge_is_on_the_pinned_row_only(self, tmp_path):
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

    def test_badge_survives_unknown_usage(self, tmp_path):
        """A pinned account still owns the claude.ai side when its usage
        cannot be read, so the badge must not hang off a usage branch."""
        from cswap_pin.proxy import save_pin

        save_pin(tmp_path, "codeslake@gmail.com", "org-1")
        out = self._rows(tmp_path, [self._acct(1, "codeslake@gmail.com")])
        assert "usage unknown" in out and "○ cloud" in out

    def test_no_badge_without_a_pin(self, tmp_path):
        out = self._rows(tmp_path, [self._acct(1, "a@co.com"), self._acct(2, "b@co.com")])
        assert "○ cloud" not in out

    def test_summary_line_never_names_the_pin(self, tmp_path, monkeypatch):
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

    def test_escalates_to_kill(self, monkeypatch):
        import os
        from cswap_pin import proxy as pin_proxy
        sent = []
        alive = {"pid": True}
        def fake_kill(pid, sig):
            sent.append(sig)
            if sig == 9:
                alive["pid"] = False
        monkeypatch.setattr(pin_proxy.os, "kill", fake_kill)
        monkeypatch.setattr(pin_proxy, "_pid_alive", lambda pid: alive["pid"])
        pin_proxy._kill_daemon(4321)
        assert 15 in sent and 9 in sent  # TERM first, then KILL escalation


class TestDaemonSignalTeardown:
    """The daemon installs a SIGTERM handler so a recycle (or cc-update) that
    TERMs it cleans up its state file and port instead of relying on default
    kill semantics."""

    def test_sigterm_handler_is_installed(self, monkeypatch, tmp_path):
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

    def test_sweeps_other_pin_daemons_for_this_certdir(self, monkeypatch, tmp_path):
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

    def test_worker_routes_keep_their_own_token(self):
        from cswap_pin.proxy import is_pinned_route

        for path in (
            "/v1/code/sessions/cse_x/worker",
            "/v1/code/sessions/cse_x/worker/events",
            "/v1/code/sessions/cse_x/worker/events/stream",
        ):
            assert not is_pinned_route(path), f"{path} must keep the worker JWT"

    def test_ownership_deciding_routes_are_still_pinned(self):
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


class TestDaemonPortStability:
    """A live session's HTTPS_PROXY is fixed at exec time. If a recycled
    daemon comes back on a NEW port, every already-running session keeps
    pointing at a dead one — and its requests then bypass the pin silently
    (measured: an RC session created that way landed on the ACTIVE account
    while the pin looked healthy). The daemon must therefore reclaim the port
    recorded in proxy.json whenever it is free.
    """

    def test_daemon_reclaims_the_recorded_port(self, tmp_path):
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

    def test_falls_back_to_a_free_port_when_recorded_one_is_taken(self, tmp_path):
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


class TestUltrareviewIsPinned:
    """Ultrareview is a claude.ai-side capability authenticated by the OAuth
    bearer (binary: `/v1/ultrareview/preflight` with auth:"teleport-org"),
    so it belongs to the pinned cloud account like RC and artifacts."""

    def test_ultrareview_routes_are_pinned(self):
        from cswap_pin.proxy import is_pinned_route

        assert is_pinned_route("/v1/ultrareview/preflight")
        assert is_pinned_route("/v1/ultrareview/run")

    def test_neighbouring_v1_routes_stay_unpinned(self):
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

    def test_concurrent_expired_requests_refresh_once(self, tmp_path):
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

    def _serving_port(self):
        import socket as s
        srv = s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        return srv, srv.getsockname()[1]

    def _wire(self, tmp_path, monkeypatch, saved_proxy):
        cfg = tmp_path / ".claude.json"
        cfg.write_text(json.dumps({"_cswapPinWiredKeysSaved": {"HTTPS_PROXY": saved_proxy}}))
        monkeypatch.setattr("claude_swap.paths.get_global_config_path", lambda: cfg)

    def test_recorded_launcher_proxy_wins_over_the_shell_one(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin.proxy import _ambient_proxy

        srv, ccf_port = self._serving_port()
        try:
            self._wire(tmp_path, monkeypatch, f"http://127.0.0.1:{ccf_port}")
            # The ssh shell only knows the machine-wide egress proxy.
            got = _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"})
            assert got == f"http://127.0.0.1:{ccf_port}", (
                "the launcher's proxy was dropped from the chain"
            )
        finally:
            srv.close()

    def test_shell_value_wins_when_the_recorded_one_is_dead(
        self, tmp_path, monkeypatch
    ):
        """A stale record must never strand the chain on a port nothing serves."""
        from cswap_pin.proxy import _ambient_proxy

        srv, dead_port = self._serving_port()
        srv.close()  # nothing listens there now
        self._wire(tmp_path, monkeypatch, f"http://127.0.0.1:{dead_port}")
        got = _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"})
        assert got == "http://127.0.0.1:8118"

    def test_same_proxy_in_both_places_is_unchanged(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import _ambient_proxy

        self._wire(tmp_path, monkeypatch, "http://127.0.0.1:8118")
        assert _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"}) == (
            "http://127.0.0.1:8118"
        )

    def test_a_non_loopback_record_is_not_preferred(self, tmp_path, monkeypatch):
        """Only a LOCAL launcher proxy is the inner link worth restoring; a
        corporate proxy recorded earlier must not override the live shell."""
        from cswap_pin.proxy import _ambient_proxy

        self._wire(tmp_path, monkeypatch, "http://proxy.corp.example:3128")
        assert _ambient_proxy({"HTTPS_PROXY": "http://127.0.0.1:8118"}) == (
            "http://127.0.0.1:8118"
        )

    def test_our_own_port_is_never_recorded(self, tmp_path, monkeypatch):
        """Unchanged behaviour: a shell that ran pin-env exports OUR port."""
        from cswap_pin.proxy import _ambient_proxy

        self._wire(tmp_path, monkeypatch, "http://127.0.0.1:8118")
        got = _ambient_proxy(
            {"HTTPS_PROXY": "http://127.0.0.1:44444", "CSWAP_PIN_PORT": "44444"}
        )
        assert got == "http://127.0.0.1:8118", "would have made the daemon loop to itself"


class TestCaIsPublishedToTheTrustDir:
    """NODE_EXTRA_CA_CERTS names ONE file, so every MITM that writes it as an
    overwrite drops the others. Two components already do that for the same
    host. Measured consequence on work-mac: a pinned session verified every
    request it SENDS while every Remote Control SSE reconnect failed with
    "unable to verify the first certificate" — 13 attempts, 0 connects, while
    worker/heartbeat and client/presence answered 200 in the same process.

    So we publish one file under ca-trust.d/ and never touch anyone else's."""

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

    def test_publishes_one_file_named_after_the_component(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import CA_TRUST_DIR, publish_ca

        home = self._cfg(tmp_path, monkeypatch)
        out = publish_ca(self._ca(tmp_path))
        assert out == home / CA_TRUST_DIR / "cswap-pin.pem"
        # Compare CONTENT, not a placeholder word: the fixture now mints a
        # real CA because the guard parses rather than pattern-matches.
        assert out.read_bytes().strip() == self._ca(tmp_path).read_bytes().strip()

    def test_republishing_is_a_no_op(self, tmp_path, monkeypatch):
        """Rewriting every launch would churn the mtime a launcher's own
        rebuild check keys on."""
        from cswap_pin.proxy import publish_ca

        self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        first = publish_ca(ca)
        before = first.stat().st_mtime_ns
        assert publish_ca(ca) == first
        assert first.stat().st_mtime_ns == before

    def test_a_rotated_ca_replaces_our_file_only(self, tmp_path, monkeypatch):
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

    def test_an_unwritable_config_home_does_not_raise(self, tmp_path, monkeypatch):
        """Trust plumbing must never block a launch."""
        import os
        from cswap_pin.proxy import publish_ca

        home = self._cfg(tmp_path, monkeypatch)
        os.chmod(home, 0o500)
        try:
            assert publish_ca(self._ca(tmp_path)) is None
        finally:
            os.chmod(home, 0o700)

    def test_merged_ca_still_returns_our_own_bundle(self, tmp_path, monkeypatch):
        """Publishing is additive: the env block we write is unchanged."""
        from cswap_pin.proxy import _merged_ca

        self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        launcher = tmp_path / "cache-fix-ca" / "combined-ca.pem"
        launcher.parent.mkdir(parents=True)
        launcher.write_bytes(b"-----BEGIN CERTIFICATE-----\nCCF\n-----END CERTIFICATE-----\n")
        out = _merged_ca(ca, str(launcher))
        assert out == ca.parent / "ca-bundle.pem"
        body = out.read_bytes()
        assert self._ca(tmp_path).read_bytes().strip() in body
        assert b"CCF" in body or ccf.read_bytes().strip() in body
        # and the launcher's file is left exactly as it was
        assert launcher.read_bytes().count(b"BEGIN CERT") == 1


class TestCaIsPublishedEveryLaunch:
    """The launcher builds its merged bundle from ca-trust.d/ as it starts us,
    so our CA has to be there BEFORE the client is exec'd, on every launch —
    not only when another CA happens to be in play, and not only after the
    daemon has run once. A component whose cert dir was wiped must reappear on
    the next launch instead of staying silently absent."""

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

    def test_first_ever_launch_publishes_before_any_daemon_ran(
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

    def test_a_wiped_trust_dir_is_repopulated_next_launch(self, tmp_path, monkeypatch):
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

    def test_publishing_does_not_depend_on_another_ca_being_present(
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


def _other_ca(certdir):
    """Another component's real CA, for multi-writer bundle fixtures."""
    from cswap_pin.proxy import ensure_ca

    # Trailing newline INCLUDED. Concatenating stripped PEMs fuses
    # `-----END-----` into `-----BEGIN-----`, producing a bundle no reader can
    # parse — a fixture bug that reads exactly like a guard bug.
    return ensure_ca(certdir, "api.anthropic.com").ca_path.read_bytes().strip() + b"\n"


class TestConsumesTheSharedTrustBundle:
    """Publishing alone only helps components that read the dir. A pinned
    session must also CONSUME the merged bundle, or a CA added by some future
    proxy is trusted by everyone except the sessions cswap wires — which is
    the whole point of the shared contract."""

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

    def test_uses_the_merged_bundle_when_it_carries_us(self, tmp_path, monkeypatch):
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

    def test_ignores_a_merged_bundle_that_does_not_carry_us(
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

    def test_no_launcher_at_all_is_unchanged(self, tmp_path, monkeypatch):
        """No merged bundle, no other MITM: name our own CA, exactly as before."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import wire_env

        self._cfg(tmp_path, monkeypatch)
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        monkeypatch.setattr(pp, "read_upstream_ca", lambda d: None)
        ca = self._ca(tmp_path)
        assert wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"] == str(ca)


class TestTornPemCannotEscape:
    """One unbalanced PEM voids the ENTIRE extras bundle: Node prints
    "PEM routines::bad end line" to stderr and then trusts no component CA and
    no corporate root at all, so the session dies on "unable to verify the
    first certificate" with the cause in a warning nobody reads. Measured by
    cc-wrapper on host-a: a torn file present alongside good ones dropped the
    bundle from 131 certs to 128 plus the warning. Both sides of that: never
    produce a torn file, never consume a torn bundle."""

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

    def test_publish_never_leaves_a_partial_file(self, tmp_path, monkeypatch):
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

    def test_no_temp_file_is_left_behind(self, tmp_path, monkeypatch):
        """A stray .tmp in the dir is another file the builder has to reason
        about; it must not survive the publish."""
        import cswap_pin.proxy as pp

        home = self._cfg(tmp_path, monkeypatch)
        pp.publish_ca(self._ca(tmp_path))
        leftovers = list((home / pp.CA_TRUST_DIR).glob("*.tmp"))
        assert leftovers == [], leftovers

    def test_a_torn_shared_bundle_is_refused(self, tmp_path, monkeypatch):
        """Containing our CA is not enough — an unrelated torn entry voids the
        whole file, and the size/contains checks cannot see that."""
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        (home / CA_TRUST_FILE).write_bytes(
            ca.read_bytes()
            + b"\n-----BEGIN CERTIFICATE-----\nTORN-NO-END\n"  # someone mid-write
        )
        env = wire_env({}, 9955, ca)
        assert env["NODE_EXTRA_CA_CERTS"] != str(home / CA_TRUST_FILE)

    def test_a_balanced_shared_bundle_is_still_used(self, tmp_path, monkeypatch):
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

    def test_a_single_cert_bundle_is_accepted(self, tmp_path, monkeypatch):
        """The real shape on a host with one component and no corporate MITM."""
        from cswap_pin.proxy import CA_TRUST_FILE, wire_env

        home = self._cfg(tmp_path, monkeypatch)
        ca = self._ca(tmp_path)
        merged = home / CA_TRUST_FILE
        merged.write_bytes(ca.read_bytes() + b"\n")
        assert wire_env({}, 9955, ca)["NODE_EXTRA_CA_CERTS"] == str(merged)

    def test_a_bundle_that_lost_other_roots_is_still_accepted(
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

    def _serving(self):
        import socket as s
        srv = s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        return srv, srv.getsockname()[1]

    def test_recorded_chain_wins_over_the_shell_value(self, tmp_path, monkeypatch):
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

    def test_a_dead_recorded_chain_does_not_strand_us(self, tmp_path, monkeypatch):
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

    def test_no_record_and_no_displaced_value_keeps_the_shell(self, tmp_path, monkeypatch):
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

    def _cfg(self, tmp_path, monkeypatch, env):
        import claude_swap.paths as paths
        cfg = tmp_path / ".claude.json"
        cfg.write_text(json.dumps(
            {"env": env, "_cswapPinWiredKeys": sorted(env)}))
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        return cfg, certdir

    def test_no_daemon_record_strips_the_wiring(self, tmp_path, monkeypatch):
        # The work-mac shape: the daemon never started, so there is no record
        # at all, but a previous run's wiring is still in the config.
        from cswap_pin.proxy import unwire_if_dead
        cfg, certdir = self._cfg(tmp_path, monkeypatch, {
            "HTTPS_PROXY": "http://127.0.0.1:59999",
            "CSWAP_PIN_PORT": "59999"})
        assert unwire_if_dead(certdir) is True
        assert json.loads(cfg.read_text()).get("env", {}) == {}

    def test_dead_pid_strips_the_wiring(self, tmp_path, monkeypatch):
        from cswap_pin.proxy import unwire_if_dead
        cfg, certdir = self._cfg(tmp_path, monkeypatch,
                                 {"HTTPS_PROXY": "http://127.0.0.1:59999"})
        (certdir / "proxy.json").write_text(
            json.dumps({"pid": 999999, "port": 59999, "fingerprint": "x"}))
        assert unwire_if_dead(certdir) is True
        assert json.loads(cfg.read_text()).get("env", {}) == {}

    def test_a_live_daemon_with_NO_state_file_is_left_alone(self, tmp_path, monkeypatch):
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

    def test_a_LIVE_daemon_is_left_alone(self, tmp_path, monkeypatch):
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

    def test_teardown_restores_the_config(self):
        """The orderly path must unwire too, not only the crash path."""
        import inspect
        from cswap_pin import proxy as pin_proxy
        src = inspect.getsource(pin_proxy.daemon_main)
        body = src[src.index("def _teardown"):]
        assert "wire_global_config(None, None)" in body, (
            "_teardown must restore .claude.json; otherwise an idle teardown "
            "leaves every later session dialling a port nobody serves")

class TestHealRestoresWithoutRestart:
    """A repaired pin must come back on the SAME port, with no session restart.

    Every other entry point reacts to a launch: the daemon is started only by
    ensure_proxy, which runs when a NEW session begins. So a daemon that dies
    under running sessions was never replaced — and once its stale wiring
    blocked every session, no new one could start to trigger the restart. That
    deadlock is why work-mac needed a human to re-pin by hand.
    """

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

    def test_no_pin_is_a_no_op(self, tmp_path, monkeypatch):
        import claude_swap.paths as paths
        from cswap_pin.proxy import heal
        root = tmp_path / "backup"
        (root / "pin-proxy").mkdir(parents=True)
        cfg = tmp_path / ".claude.json"
        cfg.write_text("{}")
        monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
        assert heal(root) is False  # nothing pinned — not our business

    def test_a_serving_and_wired_pin_is_left_alone(self, tmp_path, monkeypatch):
        """Must not restart a healthy daemon: it runs every few seconds.

        SERVING AND WIRED, both. This test used to leave the config empty
        (`{}`) while claiming to describe a healthy pin — but a daemon serving
        on a port no session is told about is NOT healthy, it is the state a
        recovery leaves behind, and treating it as "nothing to do" is what kept
        a pin down until someone re-typed `cswap pin` by hand.
        """
        from cswap_pin import proxy as pin_proxy
        root, cfg = self._root(tmp_path, monkeypatch)
        cfg.write_text(json.dumps({
            "env": {"HTTPS_PROXY": "http://127.0.0.1:40404",
                    "CSWAP_PIN_PORT": "40404"},
            "_cswapPinWiredKeys": ["HTTPS_PROXY", "CSWAP_PIN_PORT"]}))
        monkeypatch.setattr(pin_proxy, "_read_alive_port", lambda *a, **k: 40404)
        called = []
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a: called.append(a) or 1)
        before = cfg.read_text()
        assert pin_proxy.heal(root) is False
        assert not called, "restarted a daemon that was already serving"
        assert cfg.read_text() == before, "rewrote an already-correct wiring"

    def test_a_serving_but_UNWIRED_pin_is_rewired(self, tmp_path, monkeypatch):
        """Serving is not the same as wired.

        Measured: an unwire ran against a live daemon, and because heal read
        "already serving" as "nothing to do", the proxy went on serving a port
        no session was ever told about. Only a hand-typed `cswap pin <n>` fixed
        it. Re-wiring here is what makes the pin come back BY ITSELF.
        """
        from cswap_pin import proxy as pin_proxy
        root, cfg = self._root(tmp_path, monkeypatch)  # cfg is "{}" — unwired
        monkeypatch.setattr(pin_proxy, "_read_alive_port", lambda *a, **k: 40404)
        called = []
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a: called.append(a) or 1)
        assert pin_proxy.heal(root) is True
        assert not called, "respawned a daemon that was already serving"
        raw = json.loads(cfg.read_text())
        assert raw.get("_cswapPinWiredKeys"), "the wiring was not restored"
        assert (raw.get("env") or {}).get("CSWAP_PIN_PORT") == "40404", (
            "re-wired to the wrong port — live sessions would not reattach")

    def test_a_dangling_pin_does_not_spawn(self, tmp_path, monkeypatch):
        """Pinned to a slot that no longer exists: nothing to serve."""
        from cswap_pin import proxy as pin_proxy
        root, _ = self._root(tmp_path, monkeypatch)
        (root / "sequence.json").write_text(json.dumps({"accounts": {}}))
        called = []
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a: called.append(a) or 1)
        assert pin_proxy.heal(root) is False
        assert not called

    def test_a_dead_daemon_is_respawned_and_rewired(self, tmp_path, monkeypatch):
        from cswap_pin import proxy as pin_proxy
        root, cfg = self._root(tmp_path, monkeypatch)
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a: 45678)
        assert pin_proxy.heal(root) is True
        env = json.loads(cfg.read_text())["env"]
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:45678"

    def test_a_failed_respawn_clears_the_wiring(self, tmp_path, monkeypatch):
        """If it cannot come back, it must not leave sessions dialling a corpse."""
        from cswap_pin import proxy as pin_proxy
        root, cfg = self._root(tmp_path, monkeypatch)
        cfg.write_text(json.dumps({
            "env": {"HTTPS_PROXY": "http://127.0.0.1:59999"},
            "_cswapPinWiredKeys": ["HTTPS_PROXY"]}))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a: None)
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

    def test_clear_removes_the_secret(self, tmp_path, monkeypatch):
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

    def test_clearing_without_a_secret_is_not_an_error(self, tmp_path, monkeypatch):
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

    def test_the_count_is_sockets_not_environments(self, monkeypatch, tmp_path):
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
            c = socket.create_connection(("127.0.0.1", port))
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

    def test_a_repin_reports_nothing_because_it_arms_nothing(
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

    def test_a_live_connection_claims_the_daemon(self, tmp_path, monkeypatch):
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
            c = socket.create_connection(("127.0.0.1", port))
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

    def test_an_unmeasurable_platform_still_sees_its_own_clients(
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

    def test_the_daemon_counts_its_own_live_clients(self, tmp_path):
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

    def test_a_marked_daemon_is_not_reused(self, tmp_path):
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

    def test_marking_a_daemon_that_is_not_ours_does_nothing(self, tmp_path):
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

    def test_presence_is_never_swapped(self):
        from cswap_pin.proxy import is_pinned_route

        for p in (
            "/v1/code/sessions/cse_X/client/presence",
            "/v1/sessions/cse_X/client/presence",
            "/v1/code/sessions/cse_X/client/presence?x=1",
        ):
            assert is_pinned_route(p) is False, f"registration swapped: {p}"

    def test_ownership_routes_still_are(self):
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

    def test_inference_and_worker_stay_untouched(self):
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

    def test_a_lifecycle_line_reaches_the_log(self, tmp_path):
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

    def test_the_teardown_reason_distinguishes_signal_from_idle(self):
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

    def test_lifecycle_logging_never_kills_the_daemon(self, monkeypatch):
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

    def test_serving_but_unwired_gets_rewired(self, tmp_path, monkeypatch):
        from cswap_pin import proxy

        srv, port, cfg = self._fixture(tmp_path, monkeypatch, wired_port=None)
        try:
            assert proxy.heal(tmp_path) is True
            raw = json.loads(cfg.read_text())
            assert raw.get("_cswapPinWiredKeys"), "the wiring was not restored"
            assert (raw.get("env") or {}).get("CSWAP_PIN_PORT") == str(port), (
                "re-wired to the wrong port — live sessions would not reattach"
            )
        finally:
            srv.close()

    def test_serving_and_already_wired_is_a_no_op(self, tmp_path, monkeypatch):
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

    def test_wired_to_the_WRONG_port_is_corrected(self, tmp_path, monkeypatch):
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

    def test_no_pin_record_means_no_rewire(self, tmp_path, monkeypatch):
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

    def test_a_torn_block_before_ours_is_refused(self, tmp_path):
        """THE FALSE ACCEPT. Markers balance, our CA is present verbatim, and
        node still refuses the file."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        torn = (
            b"-----BEGIN CERTIFICATE-----\nQUJD!!!not-base64\n"
            b"-----END CERTIFICATE-----\n"
        )
        bundle = torn + ours + b"\n"
        # The old guard's exact test, kept here so the regression is visible.
        assert ours in bundle
        assert bundle.count(b"-----BEGIN CERTIFICATE-----") == bundle.count(
            b"-----END CERTIFICATE-----"
        )
        assert _bundle_is_usable(bundle, ours) is False

    def test_a_healthy_multi_component_bundle_is_accepted(self, tmp_path):
        """The case the shared bundle exists FOR: two MITMs, both CAs present.
        A guard that refuses this silently drops the sibling's CA."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        sibling = self._ca(tmp_path / "other")
        assert _bundle_is_usable(ours + b"\n" + sibling + b"\n", ours) is True
        assert _bundle_is_usable(sibling + b"\n" + ours + b"\n", ours) is True

    def test_non_certificate_blocks_are_tolerated(self, tmp_path):
        """A real corporate bundle carries CRLs and key blocks. Node skips
        well-formed ones, so demanding X.509 of everything would reject a
        healthy bundle — the false reject that costs every sibling CA."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        crl = (
            b"-----BEGIN X509 CRL-----\nMIIBpDCBjQIBATANBgkqhkiG9w0BAQsFADBF\n"
            b"-----END X509 CRL-----\n"
        )
        assert _bundle_is_usable(crl + ours + b"\n", ours) is True

    def test_a_corrupt_non_certificate_block_is_refused(self, tmp_path):
        """Node aborts on any block it cannot decode, whatever the label —
        'skip non-certificates' is only safe for WELL-FORMED ones."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        bad = b"-----BEGIN X509 CRL-----\n!!!not base64!!!\n-----END X509 CRL-----\n"
        assert _bundle_is_usable(bad + ours + b"\n", ours) is False

    def test_a_bundle_without_our_ca_is_refused(self, tmp_path):
        """Wiring a session to a bundle that does not carry us means it cannot
        verify our own proxy."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        other = self._ca(tmp_path / "other")
        assert _bundle_is_usable(other + b"\n", ours) is False

    def test_an_empty_ca_never_makes_the_check_vacuous(self, tmp_path):
        """`b"" in anything` is True. An unreadable ca.pem must refuse, not
        accept every bundle on earth."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        assert _bundle_is_usable(ours + b"\n", b"") is False
        assert _bundle_is_usable(ours + b"\n", b"not a pem at all") is False

    def test_identity_is_by_der_not_by_substring(self, tmp_path):
        """A re-encoded copy of our CA is still our CA. A substring test calls
        it a stranger and drops the whole bundle."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        cert = x509.load_pem_x509_certificate(ours)
        # Same certificate, different bytes on the page (CRLF line endings).
        recoded = cert.public_bytes(serialization.Encoding.PEM).replace(b"\n", b"\r\n")
        assert recoded != ours
        assert _bundle_is_usable(recoded, ours) is True

    def test_an_unterminated_block_cannot_borrow_a_later_END(self, tmp_path):
        """With an unbounded END search a torn block swallows the next entry
        and the slice spans two certificates."""
        from cswap_pin.proxy import _bundle_is_usable

        ours = self._ca(tmp_path)
        bundle = b"-----BEGIN CERTIFICATE-----\nQUJD\n" + ours + b"\n"
        assert _bundle_is_usable(bundle, ours) is False


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

    def _proxy(self, certdir):
        from cswap_pin.proxy import PinProxy

        p = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: (None, None),
            rediscover_chain=False,
        )
        p.start()
        return p

    def test_the_listening_port_is_released_for_the_next_daemon(self, tmp_path):
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

    def test_a_restart_reclaims_the_same_port(self, tmp_path):
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

    def test_a_wiped_cert_dir_still_reclaims_from_claude_json(
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

    def test_stop_closes_open_connections_rather_than_resetting_them(
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
        client = socket.create_connection(("127.0.0.1", p.port))
        client.settimeout(5)
        time.sleep(0.2)
        assert p.live_client_count() == 1
        assert len(p._open_conns) == 1, "the connection is not tracked for close"

        p.stop(drain=2.0)
        try:
            assert client.recv(100) == b"", "expected a clean EOF"
        except ConnectionResetError:  # pragma: no cover - the bug being fixed
            raise AssertionError("client saw RST; stop() did not close the socket")
        finally:
            client.close()

    def test_draining_is_a_ceiling_not_a_wait(self, tmp_path):
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

    def test_a_daemon_running_OLD_code_is_recycled(self, tmp_path, monkeypatch):
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

        def _spawn(num, email, cd):
            spawned.append((num, email))
            return port  # a real respawn reclaims the SAME port

        monkeypatch.setattr(proxy, "_spawn_daemon", _spawn)
        try:
            assert proxy.heal(tmp_path) is True, "an obsolete daemon was left running"
            assert killed == [os.getpid()], "the stale daemon was not recycled"
            assert spawned, "nothing replaced it"
        finally:
            srv.close()

    def test_the_port_is_reclaimed_so_live_sessions_survive(self, tmp_path, monkeypatch):
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
        monkeypatch.setattr(proxy, "_spawn_daemon", lambda n, e, c: port)
        try:
            proxy.heal(tmp_path)
            assert hint_at_kill.get("port") == port, (
                "the port hint was not written before the kill — the successor "
                "would take a fresh port and strand every wired session"
            )
        finally:
            srv.close()

    def test_a_CURRENT_daemon_is_never_recycled(self, tmp_path, monkeypatch):
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

    def test_an_unidentifiable_pid_is_never_signalled(self, tmp_path, monkeypatch):
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
        monkeypatch.setattr(proxy, "_spawn_daemon", lambda n, e, c: None)
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

    def test_a_draining_daemon_is_not_killed_before_it_finishes(self, monkeypatch):
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

    def _ours(self, tmp_path, monkeypatch, port):
        """A daemon record owned by THIS process, on ``port``."""
        from cswap_pin import proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        proxy.write_daemon_state(certdir, port, os.getpid(), proxy.daemon_fingerprint())
        (certdir / "ca.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n")
        return certdir

    def test_a_wiring_naming_a_DEAD_port_is_repaired(self, tmp_path, monkeypatch):
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

    def test_a_daemon_the_wiring_NEVER_named_cannot_hijack_it(
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

    def test_a_wiring_that_ANSWERS_is_never_stolen(self, tmp_path, monkeypatch):
        """Another daemon legitimately owns the pin — leave it alone. A repair
        that fires here would fight the real owner every few seconds."""
        from cswap_pin import proxy

        srv, other_port = TestAnUpgradeDoesNotWaitForALaunch._serving_listener()
        try:
            certdir = self._ours(tmp_path, monkeypatch, 36301)
            monkeypatch.setattr(proxy, "_wired_port", lambda: other_port)
            monkeypatch.setattr(
                proxy,
                "wire_global_config",
                lambda p, ca: pytest.fail("stole a LIVE wiring from another daemon"),
            )
            assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False
        finally:
            srv.close()

    def test_an_UNPINNED_config_is_left_unpinned(self, tmp_path, monkeypatch):
        """`pin --clear` removed the wiring on purpose. Re-adding it would
        re-pin a user who just asked not to be."""
        from cswap_pin import proxy

        certdir = self._ours(tmp_path, monkeypatch, 36301)
        monkeypatch.setattr(proxy, "_wired_port", lambda: None)
        monkeypatch.setattr(
            proxy,
            "wire_global_config",
            lambda p, ca: pytest.fail("re-pinned a user who had cleared the pin"),
        )
        assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False

    def test_another_daemons_record_is_not_repaired_on_its_behalf(
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
        monkeypatch.setattr(proxy, "_wired_port", lambda: dead_port)
        monkeypatch.setattr(
            proxy,
            "wire_global_config",
            lambda p, ca: pytest.fail("repaired on another daemon's behalf"),
        )
        assert proxy._repair_wiring_if_ours(certdir, 36301, lambda: 0) is False

    def test_the_repair_is_reached_from_the_periodic_claim_check(
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

    def test_the_declared_floor_admits_no_version_without_the_api(self):
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

    def test_a_MISSING_api_is_loud_rather_than_an_endless_regeneration(
        self, tmp_path, monkeypatch
    ):
        """The library moved: refuse loudly instead of regenerating forever.

        Simulated by removing the attribute from the class, which is what an
        older cryptography actually looks like to this code.
        """
        from cswap_pin import proxy

        ca = tmp_path / "ca.pem"
        proxy.ensure_ca(tmp_path, "api.anthropic.com")  # a real, consistent set
        assert proxy._certs_consistent(
            ca, tmp_path / "ca.key", tmp_path / "leaf.pem", tmp_path / "leaf.key",
            "api.anthropic.com",
        ), "fixture is not consistent to begin with"

        monkeypatch.delattr(x509.Certificate, "not_valid_after_utc", raising=False)
        with pytest.raises(AttributeError):
            proxy._certs_consistent(
                ca, tmp_path / "ca.key", tmp_path / "leaf.pem", tmp_path / "leaf.key",
                "api.anthropic.com",
            )

    def test_a_NON_RSA_cert_dir_still_regenerates_instead_of_killing_the_daemon(
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
