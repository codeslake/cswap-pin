"""Tests for the account-pin proxy's request classification.

The proxy MITMs api.anthropic.com and swaps the Authorization bearer to a
pinned account's token, but ONLY on the Remote-Control and Artifact routes;
inference (/v1/messages) and everything else must pass through untouched.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from claude_swap.pin_proxy import (
    ensure_ca,
    is_pinned_route,
    parse_upstream_proxy,
    swap_authorization,
)


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


class TestSwapAuthorization:
    def test_replaces_bearer_with_pin_token(self):
        headers = {"authorization": "Bearer disk-account-token", "content-type": "application/json"}
        out = swap_authorization(headers, "pin-token")
        assert out["authorization"] == "Bearer pin-token"

    def test_leaves_other_headers_untouched(self):
        headers = {"authorization": "Bearer disk-account-token", "content-type": "application/json"}
        out = swap_authorization(headers, "pin-token")
        assert out["content-type"] == "application/json"


class TestParseUpstreamProxy:
    def test_none_when_no_upstream(self):
        # No prior proxy -> the proxy dials api.anthropic.com directly.
        assert parse_upstream_proxy("") is None
        assert parse_upstream_proxy(None) is None

    def test_ccf_loopback(self):
        # The common case: CCF's forward proxy already on HTTPS_PROXY.
        assert parse_upstream_proxy("http://127.0.0.1:9901") == ("127.0.0.1", 9901)

    def test_bare_host_port(self):
        # Some proxies are set without a scheme.
        assert parse_upstream_proxy("corp.example.net:8118") == ("corp.example.net", 8118)

    def test_defaults_port_80(self):
        assert parse_upstream_proxy("http://proxy.local") == ("proxy.local", 80)


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
        from claude_swap.pin_proxy import resolve_pin_token
        # expiry far in the future -> no refresh, return as-is
        future = 10_000_000_000_000
        creds = self._creds("live-token", future)
        def refresh(_c):
            raise AssertionError("must not refresh a fresh token")
        token, new_creds = resolve_pin_token(creds, refresh)
        assert token == "live-token"
        assert new_creds is None  # nothing rotated

    def test_refreshes_when_expired(self):
        from claude_swap.pin_proxy import resolve_pin_token
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
        from claude_swap.pin_proxy import make_pin_token_provider
        sw = _FakeSwitcher(active_num="2")
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() is None

    def test_returns_backup_token_when_pin_inactive(self):
        import json
        from claude_swap.pin_proxy import make_pin_token_provider
        creds = json.dumps({"claudeAiOauth": {
            "accessToken": "pin-live", "expiresAt": 10_000_000_000_000,
            "refreshToken": "rt"}})
        sw = _FakeSwitcher(active_num="1", backups={"2": creds})
        provider = make_pin_token_provider(sw, "2", "pin@example.com")
        assert provider() == "pin-live"
        assert sw.persisted == []  # fresh token: nothing rotated

    def test_refreshes_and_persists_when_backup_expired(self, monkeypatch):
        import json
        from claude_swap import pin_proxy
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


class TestPinStore:
    """The pin lives in settings.json's remoteControl section (identity by
    (email, organizationUuid) — slot numbers are not stable)."""

    def test_roundtrip(self, tmp_path):
        from claude_swap.pin_proxy import load_pin, save_pin
        assert load_pin(tmp_path) is None
        save_pin(tmp_path, "pin@example.com", "org-uuid-1")
        assert load_pin(tmp_path) == ("pin@example.com", "org-uuid-1")

    def test_unpin(self, tmp_path):
        from claude_swap.pin_proxy import load_pin, save_pin
        save_pin(tmp_path, "pin@example.com", "org-uuid-1")
        save_pin(tmp_path, None, None)
        assert load_pin(tmp_path) is None

    def test_coexists_with_autoswitch_settings(self, tmp_path):
        # save_settings preserves unknown sections; the reverse must hold too.
        from claude_swap.pin_proxy import load_pin, save_pin
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
        from claude_swap.pin_proxy import wire_env
        ca = tmp_path / "ca.pem"
        ca.write_text("PIN-CA\n")
        env = wire_env({}, 9955, ca, tmp_path)
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert env["https_proxy"] == "http://127.0.0.1:9955"
        assert env["NODE_EXTRA_CA_CERTS"] == str(ca)

    def test_merges_existing_node_extra_ca(self, tmp_path):
        from claude_swap.pin_proxy import wire_env
        ca = tmp_path / "ca.pem"
        ca.write_text("PIN-CA\n")
        other = tmp_path / "ccf-ca.pem"
        other.write_text("CCF-CA\n")
        env = wire_env({"NODE_EXTRA_CA_CERTS": str(other)}, 9955, ca, tmp_path)
        bundle = env["NODE_EXTRA_CA_CERTS"]
        assert bundle not in (str(ca), str(other))  # a merged file
        text = (tmp_path / "ca-bundle.pem").read_text()
        assert "PIN-CA" in text and "CCF-CA" in text


class TestEnsureProxy:
    """ensure_proxy: no pin → None; live daemon → reuse; else spawn."""

    class _Sw:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
        def resolve_account(self, identifier):
            return ("2", "pin@example.com", "org-1")

    def test_none_when_no_pin(self, tmp_path):
        from claude_swap.pin_proxy import ensure_proxy
        assert ensure_proxy(self._Sw(tmp_path)) is None

    def test_spawns_when_no_daemon(self, tmp_path, monkeypatch):
        from claude_swap import pin_proxy
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
        from claude_swap import pin_proxy
        pin_proxy.save_pin(tmp_path, "pin@example.com", "org-1")
        # A live listener + our own (alive) pid recorded in the port file.
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        (certdir / "proxy.port").write_text(f"{port} {os.getpid()}")
        monkeypatch.setattr(pin_proxy, "_spawn_daemon",
                            lambda *a: (_ for _ in ()).throw(AssertionError("no spawn")))
        got_port, _ = pin_proxy.ensure_proxy(self._Sw(tmp_path))
        srv.close()
        assert got_port == port

    def test_none_when_pin_account_gone(self, tmp_path):
        from claude_swap import pin_proxy
        from claude_swap.exceptions import AccountNotFoundError
        pin_proxy.save_pin(tmp_path, "gone@example.com", "org-x")
        class Sw(self._Sw):
            def resolve_account(self, identifier):
                raise AccountNotFoundError(identifier)
        assert pin_proxy.ensure_proxy(Sw(tmp_path)) is None


class TestSessionWiring:
    """Every launch path funnels through SessionManager._exec — the pin hook
    lives there so run/fast-path/exec_default all get proxy wiring."""

    def _manager(self, tmp_path):
        import logging
        from claude_swap.session import SessionManager

        class Sw:
            backup_dir = tmp_path
            _logger = logging.getLogger("test")

        return SessionManager(Sw())

    def test_exec_wires_pin_proxy_env(self, tmp_path, monkeypatch):
        from claude_swap import pin_proxy, session
        ca = tmp_path / "pin-proxy" / "ca.pem"
        ca.parent.mkdir()
        ca.write_text("CA\n")
        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda sw: (9955, ca))
        captured = {}
        def fake_execvpe(binary, argv, env):
            captured["env"] = env
            raise SystemExit(0)
        monkeypatch.setattr(session.os, "execvpe", fake_execvpe)
        with __import__("pytest").raises(SystemExit):
            self._manager(tmp_path)._exec("/bin/claude", [], env={"A": "1"})
        assert captured["env"]["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert captured["env"]["NODE_EXTRA_CA_CERTS"] == str(ca)
        assert captured["env"]["A"] == "1"

    def test_exec_untouched_without_pin(self, tmp_path, monkeypatch):
        from claude_swap import pin_proxy, session
        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda sw: None)
        captured = {}
        def fake_execvpe(binary, argv, env):
            captured["env"] = env
            raise SystemExit(0)
        monkeypatch.setattr(session.os, "execvpe", fake_execvpe)
        with __import__("pytest").raises(SystemExit):
            self._manager(tmp_path)._exec("/bin/claude", [], env={"A": "1"})
        assert captured["env"] == {"A": "1"}


class TestPinCommand:
    """`cswap pin [NUM|EMAIL] | pin --clear | pin` (status)."""

    def _seed(self, temp_home):
        from claude_swap.switcher import ClaudeAccountSwitcher
        switcher = ClaudeAccountSwitcher()
        switcher._setup_directories()
        switcher._init_sequence_file()
        data = switcher._get_sequence_data()
        data["accounts"]["2"] = {
            "email": "pin@co.com", "uuid": "u2",
            "organizationUuid": "org-2", "organizationName": "",
            "added": "2024-01-01T00:00:00Z",
        }
        data["sequence"] = [2]
        switcher._write_json(switcher.sequence_file, data)
        return switcher

    def test_pin_sets_and_status_shows(self, temp_home, capsys):
        from unittest.mock import patch
        from claude_swap import cli
        from claude_swap.pin_proxy import load_pin
        sw = self._seed(temp_home)
        with patch("os.geteuid", return_value=1000, create=True):
            cli._pin_command(["2"])
        assert load_pin(sw.backup_dir) == ("pin@co.com", "org-2")
        assert "pin@co.com" in capsys.readouterr().out
        with patch("os.geteuid", return_value=1000, create=True):
            cli._pin_command([])
        assert "pin@co.com" in capsys.readouterr().out

    def test_pin_clear(self, temp_home, capsys):
        from unittest.mock import patch
        from claude_swap import cli
        from claude_swap.pin_proxy import load_pin
        sw = self._seed(temp_home)
        with patch("os.geteuid", return_value=1000, create=True):
            cli._pin_command(["2"])
            cli._pin_command(["--clear"])
        assert load_pin(sw.backup_dir) is None

    def test_pin_unknown_account_errors(self, temp_home, capsys):
        import pytest
        from unittest.mock import patch
        from claude_swap import cli
        self._seed(temp_home)
        with patch("os.geteuid", return_value=1000, create=True):
            with pytest.raises(SystemExit) as exc:
                cli._pin_command(["999"])
        assert exc.value.code == 1
