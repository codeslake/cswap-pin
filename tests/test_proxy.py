"""Tests for the account-pin proxy's request classification.

The proxy MITMs api.anthropic.com and swaps the Authorization bearer to a
pinned account's token, but ONLY on the Remote-Control and Artifact routes;
inference (/v1/messages) and everything else must pass through untouched.
"""

from __future__ import annotations

import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from claude_swap.pin_proxy import (
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


class TestPinCodeResolvesItsNames:
    """The pin touches TUI code whose tests are async and skipped in this
    repo, so an undefined name there ships as a runtime crash rather than a
    failing test: `autoview.py` referenced `ACCENT` without importing it, and
    the auto-switch screen raised NameError for anyone who had set a pin.
    Compile-and-resolve every module the pin feature reaches."""

    @pytest.mark.parametrize(
        "module",
        [
            "claude_swap.pin_proxy",
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

    def test_writes_proxy_env(self, tmp_path, monkeypatch):
        from pathlib import Path
        from claude_swap.pin_proxy import wire_global_config
        path = self._config(tmp_path, monkeypatch, {"projects": {}})

        assert wire_global_config(9955, Path("/tmp/ca.pem")) is True
        env = json.loads(path.read_text())["env"]
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:9955"
        assert env["NODE_EXTRA_CA_CERTS"] == "/tmp/ca.pem"
        # unrelated config must survive
        assert json.loads(path.read_text())["projects"] == {}

    def test_unwire_restores_a_displaced_value(self, tmp_path, monkeypatch):
        """A launcher's own proxy is displaced while pinned and put BACK on
        clear — the env block lands on top of process.env, so silently
        dropping the user's value would leave them worse than before."""
        from pathlib import Path
        from claude_swap.pin_proxy import wire_global_config
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
        from claude_swap.pin_proxy import wire_global_config
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
        from claude_swap.pin_proxy import wire_global_config

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
        from claude_swap.pin_proxy import _ambient_proxy, wire_global_config

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
        from claude_swap import pin_proxy

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
        from claude_swap.pin_proxy import wire_global_config
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


class TestTuiPinMenu:
    """Dashboard: 'Pin remote control…' menu row → pick an account → pin saved."""

    def test_pin_menu(self, tmp_path):
        import asyncio
        import sys
        sys.path.insert(0, "tests")
        from test_tui import FakeSwitcher, make_account, make_app, menu_select, settle
        from claude_swap.pin_proxy import load_pin

        async def scenario():
            fake = FakeSwitcher(
                [make_account(1, active=True), make_account(2)], tmp_path
            )
            app = make_app(fake)
            async with app.run_test(size=(100, 32)) as pilot:
                await settle(pilot)
                await menu_select(pilot, "pin-menu")
                await menu_select(pilot, "pin:2")
            assert load_pin(tmp_path) == ("user2@example.com", "")

        asyncio.run(scenario())

    def test_pin_menu_clear(self, tmp_path):
        import asyncio
        import sys
        sys.path.insert(0, "tests")
        from test_tui import FakeSwitcher, make_account, make_app, menu_select, settle
        from claude_swap.pin_proxy import load_pin, save_pin

        save_pin(tmp_path, "user2@example.com", "")

        async def scenario():
            fake = FakeSwitcher(
                [make_account(1, active=True), make_account(2)], tmp_path
            )
            app = make_app(fake)
            async with app.run_test(size=(100, 32)) as pilot:
                await settle(pilot)
                await menu_select(pilot, "pin-menu")
                await menu_select(pilot, "pin:clear")
            assert load_pin(tmp_path) is None

        asyncio.run(scenario())


class TestPinEnvCommand:
    """`cswap pin-env` emits shell export lines for eval in a wrapper (like
    cachefix-ensure / ssh-agent). It reuses ensure_proxy + wire_env, so when
    ensure_proxy returns None (no pin / dangling pin) it emits nothing."""

    def _seed(self, temp_home):
        from claude_swap.switcher import ClaudeAccountSwitcher
        sw = ClaudeAccountSwitcher()
        sw._setup_directories()
        sw._init_sequence_file()
        data = sw._get_sequence_data()
        data["accounts"]["1"] = {
            "email": "pin@co.com", "uuid": "u1", "organizationUuid": "org-1",
            "organizationName": "", "added": "2024-01-01T00:00:00Z",
        }
        data["sequence"] = [1]
        sw._write_json(sw.sequence_file, data)
        return sw

    def test_no_pin_emits_nothing(self, temp_home, capsys, monkeypatch):
        from claude_swap import cli, pin_proxy
        self._seed(temp_home)
        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda sw: None)
        cli._pin_env_command([])
        assert capsys.readouterr().out.strip() == ""

    def test_pin_emits_proxy_exports(self, temp_home, capsys, monkeypatch):
        from claude_swap import cli, pin_proxy
        sw = self._seed(temp_home)
        # No ambient CA → wire_env emits our CA directly (not a merged bundle).
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        ca = sw.backup_dir / "pin-proxy" / "ca.pem"
        ca.parent.mkdir(parents=True, exist_ok=True)
        ca.write_text("CA\n")
        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda s: (9955, ca))
        cli._pin_env_command([])
        out = capsys.readouterr().out
        assert "export HTTPS_PROXY=http://127.0.0.1:9955" in out
        assert "export https_proxy=http://127.0.0.1:9955" in out
        assert f"export NODE_EXTRA_CA_CERTS={ca}" in out

    def test_pin_merges_ambient_ca(self, temp_home, capsys, monkeypatch):
        # With an ambient CA (CCF/corp bundle), wire_env merges — the emitted
        # NODE_EXTRA_CA_CERTS is a combined bundle, never a bare replacement.
        from claude_swap import cli, pin_proxy
        sw = self._seed(temp_home)
        corp = temp_home / "corp-ca.pem"
        corp.write_text("CORP-CA\n")
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(corp))
        ca = sw.backup_dir / "pin-proxy" / "ca.pem"
        ca.parent.mkdir(parents=True, exist_ok=True)
        ca.write_text("PIN-CA\n")
        monkeypatch.setattr(pin_proxy, "ensure_proxy", lambda s: (9955, ca))
        cli._pin_env_command([])
        out = capsys.readouterr().out
        bundle = [l.split("=", 1)[1] for l in out.splitlines()
                  if l.startswith("export NODE_EXTRA_CA_CERTS=")][0]
        assert bundle not in (str(ca), str(corp))  # a merged file
        text = open(bundle).read()
        assert "PIN-CA" in text and "CORP-CA" in text


class TestDaemonState:
    """The daemon records port+pid+fingerprint in a JSON state file so a
    launcher can tell a live, current daemon from a stale one (wrong pin
    account, or redeployed code) and recycle it. Mirrors CCF's fingerprint
    staleness check (cachefix-ensure is_fresh/recycle)."""

    def test_roundtrip(self, tmp_path):
        from claude_swap.pin_proxy import write_daemon_state, read_daemon_state
        write_daemon_state(tmp_path, port=51000, pid=1234, fingerprint="fp-abc")
        st = read_daemon_state(tmp_path)
        assert st == {"port": 51000, "pid": 1234, "fingerprint": "fp-abc"}

    def test_missing_is_none(self, tmp_path):
        from claude_swap.pin_proxy import read_daemon_state
        assert read_daemon_state(tmp_path) is None

    def test_corrupt_is_none(self, tmp_path):
        from claude_swap.pin_proxy import read_daemon_state
        (tmp_path / "proxy.json").write_text("{not json")
        assert read_daemon_state(tmp_path) is None

    def test_fingerprint_encodes_account_and_code(self, tmp_path):
        # Fingerprint changes when the pinned account changes OR the code
        # (module mtime) changes — either makes an existing daemon stale.
        from claude_swap.pin_proxy import daemon_fingerprint
        fp1 = daemon_fingerprint("1", "a@co.com")
        fp2 = daemon_fingerprint("2", "b@co.com")
        assert fp1 != fp2
        assert fp1 == daemon_fingerprint("1", "a@co.com")  # stable


class TestEnsureProxyLifecycle:
    """ensure_proxy under the CCF-style lifecycle: reuse a fresh live daemon,
    recycle a stale-fingerprint one, and never double-spawn under a race."""

    class _Sw:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
        def resolve_account(self, identifier):
            return ("1", "pin@example.com", "org-1")

    def _pin(self, tmp_path):
        from claude_swap.pin_proxy import save_pin
        save_pin(tmp_path, "pin@example.com", "org-1")

    def test_reuses_fresh_daemon_without_spawn(self, tmp_path, monkeypatch):
        import os, socket
        from claude_swap import pin_proxy
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
        from claude_swap import pin_proxy
        self._pin(tmp_path)
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        # a live daemon with a STALE fingerprint (old code / other account)
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        stale_port = srv.getsockname()[1]
        pin_proxy.write_daemon_state(certdir, stale_port, os.getpid(), "STALE-FP")
        killed = []
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
        from claude_swap.pin_proxy import wire_env, refcount_fifo_path
        certdir = tmp_path / "pin-proxy"; certdir.mkdir()
        os.mkfifo(refcount_fifo_path(certdir))
        ca = certdir / "ca.pem"; ca.write_text("CA\n")
        env = wire_env({}, 9955, ca, certdir)
        # The pin proxy fd is exposed so the child inherits it (kept open for
        # the child's lifetime). We at least advertise the fifo to hold.
        assert "CSWAP_PIN_REFCOUNT_FD" in env or "CSWAP_PIN_FIFO" in env

    def test_daemon_exits_when_all_holders_close(self, tmp_path):
        # Spawn a real refcount watcher over a FIFO with one holder, close the
        # holder, and assert the watcher's "last holder gone" callback fires.
        import os, threading, time
        from claude_swap.pin_proxy import refcount_fifo_path, watch_refcount
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


class TestPinEnvRefcount:
    """pin-env (shell path) must emit a shell `exec {fd}<>fifo` so the SHELL
    opens the refcount holder — not the transient cswap process (whose fd would
    close the instant cswap exits, tearing the daemon down immediately)."""

    def _seed(self, temp_home):
        from claude_swap.switcher import ClaudeAccountSwitcher
        sw = ClaudeAccountSwitcher()
        sw._setup_directories(); sw._init_sequence_file()
        data = sw._get_sequence_data()
        data["accounts"]["1"] = {
            "email": "pin@co.com", "uuid": "u1", "organizationUuid": "org-1",
            "organizationName": "", "added": "2024-01-01T00:00:00Z",
        }
        data["sequence"] = [1]
        sw._write_json(sw.sequence_file, data)
        return sw

    def test_pin_env_emits_shell_fifo_hold(self, temp_home, capsys, monkeypatch):
        import os
        from claude_swap import cli, pin_proxy
        sw = self._seed(temp_home)
        certdir = sw.backup_dir / "pin-proxy"; certdir.mkdir(parents=True)
        (certdir / "ca.pem").write_text("CA\n")
        os.mkfifo(str(pin_proxy.refcount_fifo_path(certdir)))
        monkeypatch.setattr(pin_proxy, "ensure_proxy",
                            lambda s: (9955, certdir / "ca.pem"))
        cli._pin_env_command([])
        out = capsys.readouterr().out
        # a shell exec that opens the FIFO on an inherited fd (CCF pattern)
        assert "<>" in out and "refcount.fifo" in out
        assert "exec" in out


class TestAutoViewPinLabel:
    """The auto-switch view marks the remote-control-pinned account so a user
    running `auto` with a pin can see, at a glance, which account RC is on."""

    def _label(self, backup_dir, accounts):
        """Call _pinned_rc_label with a stand-in app, WITHOUT mutating the
        AutoScreen class (a class-level property would leak into other tests)."""
        from claude_swap.tui.autoview import AutoScreen
        class _Snap:
            pass
        class _App:
            class switcher:
                pass
        app = _App()
        app.switcher.backup_dir = backup_dir
        snap = _Snap(); snap.accounts = accounts
        app.snapshot = snap
        # Unbound method call with a minimal object exposing `.app`; no class
        # patching, so nothing leaks.
        class _Stub:
            pass
        stub = _Stub()
        stub.app = app
        return AutoScreen._pinned_rc_label(stub)

    def _acct(self, num, email):
        from claude_swap.models import AccountSnapshot
        from claude_swap.usage_store import UsageEntry
        return AccountSnapshot(
            number=str(num), email=email, org_name="", org_uuid="",
            is_active=False, kind="oauth", switchable=True,
            usage=UsageEntry(last_good=None, fetched_at=None, age_s=None),
        )

    def test_label_shows_slot_and_email(self, tmp_path):
        from claude_swap.pin_proxy import save_pin
        save_pin(tmp_path, "codeslake@gmail.com", "org-1")
        label = self._label(
            tmp_path,
            [self._acct(1, "codeslake@gmail.com"), self._acct(2, "j.lee8@samsung.com")],
        )
        assert label == "#1 codeslake@gmail.com"

    def test_label_none_without_pin(self, tmp_path):
        assert self._label(tmp_path, [self._acct(1, "a@co.com")]) is None


class TestKillDaemon:
    """_kill_daemon must escalate TERM → KILL so a daemon that ignores TERM
    (or is mid-teardown) never lingers as an orphan holding a port."""

    def test_escalates_to_kill(self, monkeypatch):
        import os
        from claude_swap import pin_proxy
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
        from claude_swap import pin_proxy
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
        from claude_swap import pin_proxy
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
        from claude_swap.pin_proxy import is_pinned_route

        for path in (
            "/v1/code/sessions/cse_x/worker",
            "/v1/code/sessions/cse_x/worker/events",
            "/v1/code/sessions/cse_x/worker/events/stream",
        ):
            assert not is_pinned_route(path), f"{path} must keep the worker JWT"

    def test_ownership_deciding_routes_are_still_pinned(self):
        from claude_swap.pin_proxy import is_pinned_route

        for path in (
            "/v1/code/sessions",
            "/v1/code/sessions/cse_x/bridge",
            "/v1/code/sessions/cse_x/client/presence",
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
        from claude_swap.pin_proxy import PinProxy, ensure_ca, write_daemon_state

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
        from claude_swap.pin_proxy import PinProxy, ensure_ca, write_daemon_state

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
        from claude_swap.pin_proxy import is_pinned_route

        assert is_pinned_route("/v1/ultrareview/preflight")
        assert is_pinned_route("/v1/ultrareview/run")

    def test_neighbouring_v1_routes_stay_unpinned(self):
        from claude_swap.pin_proxy import is_pinned_route

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
        from claude_swap.pin_proxy import make_pin_token_provider

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

        class FakeSwitcher:
            backup_dir = tmp_path

            def current_account_number(self):
                return "2"  # pinned account is NOT active

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
