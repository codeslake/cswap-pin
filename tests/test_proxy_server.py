"""Integration tests for the pin proxy's actual MITM + swap + relay path.

A fake upstream HTTPS server stands in for api.anthropic.com. The proxy MITMs
it, and we assert the Authorization it forwards: swapped on pinned routes,
original on everything else.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
from pathlib import Path

import pytest

from claude_swap.pin_proxy import ensure_ca


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


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class _FakeUpstream:
    """A minimal TLS server that records the Authorization header it received
    and replies 200. Uses the same leaf cert the proxy MITMs with, so the
    proxy's own upstream TLS (servername api.anthropic.com) validates it."""

    def __init__(self, certdir: Path):
        self.seen_auth: str | None = None
        self.seen_path: str | None = None
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            try:
                tls = self._ctx.wrap_socket(conn, server_side=True)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                head = head.decode("latin1")
                # Read the full body before replying — closing early races the
                # proxy's body send into an RST (a real server reads it all).
                m = [l for l in head.lower().split("\r\n") if l.startswith("content-length:")]
                want = int(m[0].split(":")[1]) if m else 0
                while len(rest) < want:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
                lines = head.split("\r\n")
                self.seen_path = lines[0].split(" ")[1]
                for line in lines[1:]:
                    if line.lower().startswith("authorization:"):
                        self.seen_auth = line.split(":", 1)[1].strip()
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Content-Type: application/json\r\n\r\n{}"
                )
                tls.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        self._srv.close()


def _request_through_proxy(proxy_port: int, ca_path: Path, path: str, bearer: str):
    """Make an HTTPS request to api.anthropic.com<path> via the proxy (CONNECT),
    trusting the proxy's CA. Returns the response status."""
    ctx = ssl.create_default_context(cafile=str(ca_path))
    conn = http.client.HTTPSConnection(
        "api.anthropic.com", context=ctx, timeout=10
    )
    conn.set_tunnel("api.anthropic.com", 443)
    # Point the socket at the proxy instead of resolving api.anthropic.com.
    conn._create_connection = lambda *a, **k: socket.create_connection(
        ("127.0.0.1", proxy_port), timeout=10
    )
    conn.request("POST", path, body="{}", headers={"Authorization": f"Bearer {bearer}"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return resp.status


@pytest.fixture
def certdir(tmp_path):
    ensure_ca(tmp_path, "api.anthropic.com")
    return tmp_path


class TestPinProxyServer:
    def test_pinned_route_gets_swapped_bearer(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            )
            assert status == 200
            assert upstream.seen_auth == "Bearer PIN-TOKEN"
        finally:
            proxy.stop()
            upstream.stop()

    def test_inference_route_keeps_original_bearer(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/messages", bearer="disk-token",
            )
            assert status == 200
            # Inference must NOT be swapped — it bills the swapped account.
            assert upstream.seen_auth == "Bearer disk-token"
        finally:
            proxy.stop()
            upstream.stop()

    def test_upstream_signed_by_foreign_ca_via_node_extra(self, certdir, tmp_path, monkeypatch):
        # Chained through CCF, the "upstream" presents CCF's cert, not the
        # real one. The proxy must trust whatever NODE_EXTRA_CA_CERTS names.
        from claude_swap.pin_proxy import PinProxy

        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(foreign / "ca.pem"))
        upstream = _FakeUpstream(foreign)  # leaf signed by the FOREIGN CA
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200
        finally:
            proxy.stop()
            upstream.stop()


class _StreamingUpstream:
    """A TLS server that sends response headers + a first SSE event, then
    BLOCKS on ``release`` before sending the second event. Lets a test prove
    the proxy relays the first event before the response finishes — i.e. it
    streams instead of buffering to EOF."""

    def __init__(self, certdir: Path):
        self.release = threading.Event()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        try:
            conn, _ = self._srv.accept()
            tls = self._ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"8\r\nevent: a\r\n"
            )
            self.release.wait(timeout=10)
            tls.sendall(b"8\r\nevent: b\r\n0\r\n\r\n")
            tls.close()
        except Exception:
            pass

    def stop(self):
        self._srv.close()


class TestStreamingRelay:
    def test_first_event_arrives_before_upstream_finishes(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        upstream = _StreamingUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            # Raw client through the proxy so we can read incrementally.
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += raw.recv(1)
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                b"Authorization: Bearer t\r\n\r\n"
            )
            # Read until the first event lands. If the proxy buffered to EOF,
            # nothing arrives (upstream is blocked on release) → recv times out.
            tls.settimeout(5)
            got = b""
            while b"event: a" not in got:
                chunk = tls.recv(4096)
                assert chunk, "connection closed before first event"
                got += chunk
            # First event relayed while upstream still holds the second one.
            assert not upstream.release.is_set()
            upstream.release.set()
            while b"event: b" not in got:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"event: b" in got
            tls.close()
        finally:
            proxy.stop()
            upstream.stop()


class _LoopbackConnectProxy:
    """A localhost CONNECT proxy (stands in for CCF) that forwards to a fake
    upstream signed by a CA the pin proxy does NOT trust. Proves the pin proxy
    relays through a loopback MITM without being able to verify its cert."""

    def __init__(self, target: tuple[str, int]):
        self._target = target
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self.connects = 0
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        try:
            conn, _ = self._srv.accept()
            self.connects += 1
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += conn.recv(1)
            up = socket.create_connection(self._target, timeout=10)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            # blind-pipe both directions
            import select
            while True:
                r, _, _ = select.select([conn, up], [], [], 10)
                if not r:
                    break
                for s in r:
                    d = s.recv(65536)
                    if not d:
                        return
                    (up if s is conn else conn).sendall(d)
        except Exception:
            pass

    def stop(self):
        self._srv.close()


class TestLoopbackChainTrust:
    def test_relays_through_untrusted_loopback_mitm(self, certdir, tmp_path):
        from claude_swap.pin_proxy import PinProxy

        # Fake upstream signed by a FOREIGN CA the pin proxy has no way to trust.
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)
        chain = _LoopbackConnectProxy(("127.0.0.1", upstream.port))

        proxy = PinProxy(
            certdir=certdir,  # pin proxy's own CA != foreign CA
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            chain_proxy=("127.0.0.1", chain.port),
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200  # verification was skipped for the loopback hop
        finally:
            proxy.stop()
            chain.stop()
            upstream.stop()


class TestPortReclamationAcrossRespawn:
    """A respawn must come back on the SAME port. A live session's
    HTTPS_PROXY is fixed at exec, so a new port strands it on a dead
    address — and a request to a dead proxy leaves WITHOUT the pin rather
    than failing loudly. proxy.json is deleted before the respawn (a stale
    record must never read as live), so the port travels via a hint."""

    def test_rebinds_the_port_carried_across_the_state_deletion(self, certdir):
        """The real daemon is a separate process, so its listening socket is
        gone by the time the successor binds. Model that by taking a free
        port, recording it the way _spawn_daemon does, and checking the
        successor lands on it rather than an ephemeral one."""
        import socket as _socket
        from claude_swap.pin_proxy import PinProxy, _write_port_hint

        probe = _socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()  # now free, as after a daemon exits

        # What _spawn_daemon does: carry the port forward, drop the state.
        _write_port_hint(certdir, port)
        (certdir / "proxy.json").unlink(missing_ok=True)

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        proxy.start()
        try:
            assert proxy.port == port, (
                f"respawn landed on {proxy.port}, stranding sessions wired to {port}"
            )
        finally:
            proxy.stop()

    def test_recycling_a_stale_daemon_carries_its_port(self, tmp_path, monkeypatch):
        """The stale-recycle path kills the old daemon first, and the daemon
        unlinks its own state on TERM — so the port must be saved BEFORE the
        kill or there is nothing left to reclaim from. Measured live: a
        recycle moved 59704 -> 59857 while sessions stayed on 59704."""
        from claude_swap import pin_proxy

        backup = tmp_path
        certdir = backup / "pin-proxy"
        certdir.mkdir()
        pin_proxy.save_pin(backup, "pin@example.com", "org-1")
        pin_proxy.write_daemon_state(certdir, 51000, 4242, "STALE-fingerprint")

        class _Sw:
            backup_dir = backup
            def resolve_account(self, identifier):
                return ("1", "pin@example.com", "org-1")

        killed = []
        monkeypatch.setattr(pin_proxy, "_pid_alive", lambda pid: pid == 4242)
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid: killed.append(pid))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 51000)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)

        pin_proxy.ensure_proxy(_Sw())

        assert killed == [4242], "the stale daemon was not recycled"
        assert pin_proxy.read_port_hint(certdir) == 51000

    def test_spawn_carries_the_port_forward(self, tmp_path, monkeypatch):
        """_spawn_daemon must record the outgoing port BEFORE deleting the
        state file it lives in — the regression that let a recycle land on a
        fresh port while .claude.json still named the old one."""
        from claude_swap import pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pin_proxy.write_daemon_state(certdir, 54321, 999999, "fp")

        import subprocess as _subprocess
        monkeypatch.setattr(_subprocess, "Popen", lambda *a, **k: None)
        monkeypatch.setattr(pin_proxy, "_read_alive_port", lambda *a, **k: 54321)
        monkeypatch.setattr(pin_proxy, "_sweep_orphan_daemons", lambda *a, **k: None)
        pin_proxy._spawn_daemon("1", "pin@example.com", certdir)

        assert pin_proxy.read_port_hint(certdir) == 54321


class TestLongPollSurvives:
    """Remote Control's inbound channel is a long poll: GET .../worker holds
    its response open until the phone/web sends something. create_connection's
    timeout stays ON the socket, so it silently became a read deadline and
    killed that poll — heartbeats (answered at once) kept returning 200, so
    the session looked healthy while no inbound message ever arrived."""

    def test_upstream_socket_has_no_read_deadline(self, certdir):
        import socket as _socket
        import threading as _threading
        from claude_swap.pin_proxy import PinProxy

        # An upstream that accepts, then stays silent well past any dial budget.
        srv = _socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        held = []

        def _hold():
            c, _ = srv.accept()
            held.append(c)  # keep it open, send nothing

        _threading.Thread(target=_hold, daemon=True).start()

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", srv.getsockname()[1]),
        )
        try:
            up = proxy._connect_upstream()
            assert up.gettimeout() is None, (
                "a read deadline on the upstream kills the RC long poll"
            )
            up.close()
        finally:
            for c in held:
                c.close()
            srv.close()


class TestChainRediscovery:
    """The daemon outlives the launch that spawned it, and CCF picks its port
    from a family (9901 + walk range) and can restart. A chain bound once at
    spawn therefore goes stale — and a stale chain does not degrade, it
    BYPASSES the egress proxy, which behind a corporate proxy is a hard
    failure. The daemon re-reads the hint every connection instead."""

    def test_follows_a_chain_that_appears_after_the_daemon_started(
        self, certdir, tmp_path
    ):
        from claude_swap.pin_proxy import PinProxy, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)
        chain = _LoopbackConnectProxy(("127.0.0.1", upstream.port))

        # Daemon starts with NO chain recorded — a direct dial to the fake
        # upstream would fail TLS verification (foreign CA), so a request
        # succeeding proves it went through the loopback chain instead.
        write_upstream_hint(certdir, None)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        proxy.start()
        try:
            # A launch happens later and records the chain (what ensure_proxy
            # does on every launch).
            write_upstream_hint(certdir, f"http://127.0.0.1:{chain.port}")
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200
            assert chain.connects, "the daemon never used the newly-recorded chain"
        finally:
            proxy.stop()
            chain.stop()
            upstream.stop()

    def test_a_launch_that_sees_no_proxy_keeps_the_recorded_one(self, certdir):
        """`cswap pin` normally runs in an ordinary shell, while the launcher
        sets HTTPS_PROXY only in the env it execs Claude Code with. Treating
        "I can't see one" as "there is none" blanked a live upstream —
        measured: a re-pin from a plain shell dropped a recorded CCF and the
        daemon started bypassing it."""
        from claude_swap.pin_proxy import read_upstream_hint, write_upstream_hint

        write_upstream_hint(certdir, "http://127.0.0.1:9901")
        assert read_upstream_hint(certdir) == ("127.0.0.1", 9901)

        write_upstream_hint(certdir, None)  # a launch with nothing in its env
        assert read_upstream_hint(certdir) == ("127.0.0.1", 9901), (
            "a launch that could not see a proxy erased the recorded one"
        )

        # A launch that positively reports a DIFFERENT proxy still wins.
        write_upstream_hint(certdir, "http://127.0.0.1:9902")
        assert read_upstream_hint(certdir) == ("127.0.0.1", 9902)

    def test_falls_back_to_direct_when_the_recorded_chain_is_gone(
        self, certdir, tmp_path
    ):
        """The hint cannot expire on its own (see above), so a chain that dies
        must not wedge every request — the relay dials direct instead."""
        from claude_swap.pin_proxy import PinProxy, write_upstream_hint

        upstream = _FakeUpstream(certdir)
        # Point the chain at a port nothing is listening on.
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead_port}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        proxy.start()
        try:
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert status == 200, "a dead chain wedged the request"
        finally:
            proxy.stop()
            upstream.stop()

    def test_health_reports_the_chain_the_relay_would_use(self, certdir):
        """A probe that says "no chain" while every request goes through one
        sends the next diagnosis the wrong way. Measured after a cc-update
        recycle: /health said chain=null with CCF live and recorded on disk."""
        from claude_swap.pin_proxy import PinProxy, write_upstream_hint

        write_upstream_hint(certdir, None)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        proxy.start()
        try:
            write_upstream_hint(certdir, "http://127.0.0.1:9901")
            conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
            conn.request("GET", "/health")
            body = json.loads(conn.getresponse().read())
            conn.close()
            assert body["chain"] == "127.0.0.1:9901"
        finally:
            proxy.stop()

    def test_ignores_a_hint_pointing_at_our_own_port(self, tmp_path):
        """A shell that eval'd pin-env exports the pin proxy as HTTPS_PROXY.
        Recording that would make the daemon CONNECT to itself."""
        from claude_swap.pin_proxy import _ambient_proxy

        env = {"HTTPS_PROXY": "http://127.0.0.1:45678", "CSWAP_PIN_PORT": "45678"}
        assert _ambient_proxy(env) is None
        # A DIFFERENT loopback proxy (CCF) is a legitimate chain.
        env = {"HTTPS_PROXY": "http://127.0.0.1:9901", "CSWAP_PIN_PORT": "45678"}
        assert _ambient_proxy(env) == "http://127.0.0.1:9901"


class TestAbsoluteFormPassthrough:
    """The native auto-updater and telemetry use axios in plain-proxy mode:
    they send `GET http://host/path` (absolute-form, no CONNECT). The proxy
    must relay these through the chain, not drop them (dropping = the
    'Auto-update failed' banner). No MITM/swap — just forward."""

    def test_absolute_form_get_is_relayed(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        # A plain HTTP origin the "updater" fetches (absolute-form target).
        origin_seen = {}
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        oport = srv.getsockname()[1]

        def origin():
            try:
                c, _ = srv.accept()
                data = b""
                while b"\r\n\r\n" not in data:
                    data += c.recv(4096)
                origin_seen["req"] = data.decode("latin1").splitlines()[0]
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                c.close()
            except Exception:
                pass
        threading.Thread(target=origin, daemon=True).start()

        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: None)
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                f"GET http://127.0.0.1:{oport}/releases/latest HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{oport}\r\n\r\n".encode()
            )
            resp = b""
            raw.settimeout(5)
            while b"OK" not in resp:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                resp += chunk
            raw.close()
            assert b"200 OK" in resp
            assert origin_seen.get("req", "").startswith("GET /releases/latest")
        finally:
            proxy.stop()
            srv.close()


class TestHealthEndpoint:
    """The pin proxy answers GET /health (absolute-form or origin-form to its
    own port) so a statusline/cc-update probe can tell it apart from CCF and
    read the chain it forwards to (mirrors CCF's /health with https_proxy)."""

    def test_health_reports_pin_and_chain(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            chain_proxy=("127.0.0.1", 9901),
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            raw.sendall(
                b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            )
            raw.settimeout(5)
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw.recv(4096)
                if not chunk:
                    break
                resp += chunk
            body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
            # read a little more for the body
            try:
                body += raw.recv(4096)
            except OSError:
                pass
            raw.close()
            assert b"200" in resp.split(b"\r\n", 1)[0]
            data = json.loads(body.decode() or "{}")
            assert data.get("pin_proxy") is True
            assert data.get("chain") == "127.0.0.1:9901"
        finally:
            proxy.stop()


class _KeepAliveUpstream:
    """A TLS upstream that serves MULTIPLE requests per connection (HTTP/1.1
    keep-alive, like the real api.anthropic.com) and records each one.

    The RC worker holds one connection open and pipelines heartbeat/poll
    requests over it; a proxy that closes after the first request forces an
    endless reconnect loop ("Transport closed: server rejected connection").
    """

    def __init__(self, certdir: Path):
        self.paths: list[str] = []
        self.auths: list[str] = []
        self.conns = 0
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            self.conns += 1
            buf = b""
            while not self._stop:
                while b"\r\n\r\n" not in buf:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b"\r\n\r\n")
                text = head.decode("latin1")
                lines = text.split("\r\n")
                self.paths.append(lines[0].split(" ")[1])
                for line in lines[1:]:
                    if line.lower().startswith("authorization:"):
                        self.auths.append(line.split(":", 1)[1].strip())
                want = 0
                for line in lines[1:]:
                    if line.lower().startswith("content-length:"):
                        want = int(line.split(":")[1])
                while len(buf) < want:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                buf = buf[want:]
                # keep-alive reply: no Connection: close
                tls.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                    b"Content-Type: application/json\r\n\r\n{}"
                )
        except Exception:
            pass

    def stop(self):
        self._stop = True
        self._srv.close()


class TestKeepAlive:
    """The RC worker pipelines many requests over ONE connection. Closing
    after the first is what made /remote-control fail with 'Transport closed:
    server rejected connection' while every individual route swapped fine."""

    def test_multiple_requests_over_one_connection(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        up = _KeepAliveUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PINTOKEN",
            upstream=("127.0.0.1", up.port),
        )
        proxy.start()
        try:
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            conn = http.client.HTTPSConnection(
                "api.anthropic.com", context=ctx, timeout=10
            )
            conn.set_tunnel("api.anthropic.com", 443)
            conn._create_connection = lambda *a, **k: socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=10
            )
            # /bridge is OAuth-pinned; /worker keeps its session JWT;
            # /v1/messages keeps the inference account. All three pipelined
            # over ONE connection.
            sent = [
                "/v1/code/sessions/cse_x/bridge",
                "/v1/code/sessions/cse_x/worker",
                "/v1/messages",
            ]
            for p in sent:
                conn.request("GET", p, headers={"Authorization": "Bearer DISK"})
                r = conn.getresponse()
                r.read()
                assert r.status == 200, f"{p} failed on a reused connection"
            conn.close()
        finally:
            proxy.stop()
            up.stop()

        assert up.paths == sent, f"upstream saw {up.paths}"
        # pinned routes swapped, inference untouched — even when pipelined
        assert up.auths == ["Bearer PINTOKEN", "Bearer DISK", "Bearer DISK"]


class _WebSocketUpstream:
    """A TLS upstream that only accepts a proper WebSocket handshake.

    Mirrors the real /worker/events/stream contract: without `Connection:
    Upgrade` + `Upgrade: websocket` it answers 403, which is exactly what the
    RC transport reported ("Transport closed: server rejected connection
    (code 403)") when the proxy stripped those hop-by-hop headers.
    """

    def __init__(self, certdir: Path):
        self.saw_upgrade = False
        self.echo = b""
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head = buf.split(b"\r\n\r\n")[0].decode("latin1").lower()
            if "upgrade: websocket" in head and "connection:" in head:
                self.saw_upgrade = True
                tls.sendall(
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                )
                # after the upgrade the connection is a raw byte tunnel
                data = tls.recv(4096)
                self.echo = data
                tls.sendall(b"PONG")
            else:
                tls.sendall(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                )
        except Exception:
            pass

    def stop(self):
        self._stop = True
        self._srv.close()


class TestWebSocketUpgrade:
    """RC's transport is a WebSocket. Stripping Connection/Upgrade as
    hop-by-hop made the server answer 403 — the whole reason /remote-control
    never connected through the pin proxy."""

    def test_upgrade_headers_reach_upstream_and_tunnel_opens(self, certdir):
        from claude_swap.pin_proxy import PinProxy

        up = _WebSocketUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PINTOKEN",
            upstream=("127.0.0.1", up.port),
        )
        proxy.start()
        try:
            ctx = ssl.create_default_context(cafile=str(certdir / "ca.pem"))
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            raw.sendall(
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                b"Host: api.anthropic.com:443\r\n\r\n"
            )
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += raw.recv(4096)
            assert b"200" in resp.split(b"\r\n")[0]
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            tls.sendall(
                b"GET /v1/code/sessions/cse_x/worker/events/stream HTTP/1.1\r\n"
                b"Host: api.anthropic.com\r\n"
                b"Authorization: Bearer DISK\r\n"
                b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
                b"Sec-WebSocket-Version: 13\r\n"
                b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            )
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = tls.recv(4096)
                assert chunk, "proxy closed during the upgrade"
                head += chunk
            status = head.split(b"\r\n")[0]
            assert b"101" in status, f"expected 101, got {status!r}"
            # the tunnel must carry raw frames both ways after the upgrade
            tls.sendall(b"PING")
            assert tls.recv(4096) == b"PONG"
            tls.close()
        finally:
            proxy.stop()
            up.stop()

        assert up.saw_upgrade, "upstream never saw the Upgrade headers"


class TestBlindTunnelIsTraced:
    """Remote Control RECEIVES over a WebSocket to the ingress host named in
    the /bridge response, not to api.anthropic.com — so it is blind-tunnelled,
    never MITM'd. The tunnel used to log nothing, which made a session with no
    inbound channel at all read exactly like a healthy one: everything CC
    *sends* (worker/events, heartbeat, presence) showed 200 in the trace while
    the channel it *receives* on left no line. Diagnosing that cost a live
    debugging session; the tunnel must announce itself."""

    def test_tunnel_to_a_foreign_host_writes_a_trace_line(self, certdir, tmp_path):
        import claude_swap.pin_proxy as pp

        # A plain TCP peer standing in for the ingress host.
        peer = socket.socket()
        peer.bind(("127.0.0.1", 0))
        peer.listen(1)
        peer_port = peer.getsockname()[1]

        log = tmp_path / "trace.log"
        prev = pp._TRACE
        pp._TRACE = open(log, "a")
        try:
            proxy = pp.PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: "PINTOKEN",
                upstream=("127.0.0.1", 1),  # unused: we tunnel elsewhere
            )
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT ingress.example.com:{peer_port} HTTP/1.1\r\n"
                    f"Host: ingress.example.com:{peer_port}\r\n\r\n".encode()
                )
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                raw.close()
            finally:
                proxy.stop()
                peer.close()
            pp._TRACE.flush()
        finally:
            pp._TRACE.close()
            pp._TRACE = prev

        text = log.read_text()
        assert "CONNECT ingress.example.com" in text, (
            f"blind tunnel left no trace line; log was:\n{text}"
        )
        # It must also say the pin cannot apply there — that is the whole point.
        assert "no pin" in text, text


class TestBlindTunnelFallsBackWhenChainRefuses:
    """Remote Control RECEIVES over a WebSocket to the ingress host the /bridge
    response names — a host the egress proxy has no forwarding rule for. A
    filtering chain (privoxy with per-domain forwards, a corporate MITM) can
    refuse the CONNECT outright, and closing on that refusal made a session
    silently deaf: heartbeat and worker/events kept answering 200 through the
    MITM path, the pin still read as applied, and nothing sent from claude.ai
    ever arrived. Measured on work-mac against a machine whose chain did let
    the host through, where the same session received normally."""

    def _refusing_chain(self):
        """A proxy that answers every CONNECT with 403."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    while True:
                        line = c.recv(4096)
                        if not line or b"\r\n\r\n" in line:
                            break
                    c.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        return srv

    def test_direct_dial_when_the_chain_refuses_the_ingress_host(
        self, certdir, tmp_path
    ):
        import claude_swap.pin_proxy as pp

        chain = self._refusing_chain()

        # Stands in for the ingress host: accepts and echoes, proving the
        # tunnel reached it directly rather than dying at the chain.
        peer = socket.socket()
        peer.bind(("127.0.0.1", 0))
        peer.listen(2)
        peer_port = peer.getsockname()[1]
        reached = threading.Event()

        def serve_peer():
            try:
                c, _ = peer.accept()
            except OSError:
                return
            reached.set()
            try:
                data = c.recv(64)
                if data:
                    c.sendall(b"PONG")
            finally:
                c.close()

        threading.Thread(target=serve_peer, daemon=True).start()

        log = tmp_path / "trace.log"
        prev = pp._TRACE
        pp._TRACE = open(log, "a")
        try:
            proxy = pp.PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: "PINTOKEN",
                upstream=("127.0.0.1", 1),
            )
            # The recorded chain refuses everything.
            proxy._current_chain = lambda: ("127.0.0.1", chain.getsockname()[1])
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
                raw.sendall(
                    f"CONNECT 127.0.0.1:{peer_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{peer_port}\r\n\r\n".encode()
                )
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    assert chunk, "proxy closed instead of falling back to a direct dial"
                    resp += chunk
                assert b"200" in resp.split(b"\r\n")[0], resp[:80]
                raw.sendall(b"PING")
                assert raw.recv(16) == b"PONG", "tunnel did not reach the host"
                raw.close()
            finally:
                proxy.stop()
                peer.close()
                chain.close()
            pp._TRACE.flush()
        finally:
            pp._TRACE.close()
            pp._TRACE = prev

        assert reached.is_set(), "the ingress host was never dialled"
        assert "chain refused" in log.read_text(), log.read_text()
