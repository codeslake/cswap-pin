"""Integration tests for the pin proxy's actual MITM + swap + relay path.

A fake upstream HTTPS server stands in for api.anthropic.com. The proxy MITMs
it, and we assert the Authorization it forwards: swapped on pinned routes,
original on everything else.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest

from cswap_pin.proxy import ensure_ca


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

    def __init__(self, certdir: Path, reject_bearer: str | None = None):
        # reject_bearer: answer 403 to exactly this credential, 200 to any
        # other. Models an endpoint the pinned account may not use — the shape
        # that makes a misrouted swap terminal for the client.
        self.reject_bearer = reject_bearer
        self.seen_auth: str | None = None
        self.seen_path: str | None = None
        self.seen_body: bytes = b""
        self.seen_head: str = ""
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
                self.seen_body = bytes(rest)
                self.seen_head = head
                lines = head.split("\r\n")
                self.seen_path = lines[0].split(" ")[1]
                for line in lines[1:]:
                    if line.lower().startswith("authorization:"):
                        self.seen_auth = line.split(":", 1)[1].strip()
                if (
                    self.reject_bearer
                    and self.seen_auth == f"Bearer {self.reject_bearer}"
                ):
                    tls.sendall(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    tls.close()
                    continue
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
        from cswap_pin.proxy import PinProxy

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
        from cswap_pin.proxy import PinProxy

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
        from cswap_pin.proxy import PinProxy

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
        from cswap_pin.proxy import PinProxy

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


class _FramingUpstream:
    """A TLS server that answers with a caller-chosen raw response.

    Lets a test drive the exact framing shapes a real origin produces —
    chunked, 204, 304 — and then read the result with a REAL HTTP client,
    which is the only thing that proves the framing we forward is parseable.
    """

    def __init__(
        self,
        certdir: Path,
        response: bytes,
        keep_open: bool = True,
        parts: "list[bytes] | None" = None,
    ):
        # ``parts`` sends the response in separate writes with a gap. An
        # interim response is only interesting when the final one has NOT
        # arrived yet: sent in one write it rides along in the bytes already
        # read past the head, and reaches the client whatever the relay does.
        self.parts = parts
        self.response = response
        self.keep_open = keep_open
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(certdir / "leaf.pem"), str(certdir / "leaf.key"))
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(5)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._held = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(
                target=self._serve, args=(conn,), daemon=True
            ).start()

    def _serve(self, conn):
        try:
            tls = self._ctx.wrap_socket(conn, server_side=True)
            self._held.append(tls)
            # A keep-alive origin serves request after request on the same
            # connection and never closes on its own. That is what makes a
            # mis-framed bodyless response detectable: the relay blocks on
            # recv for a body that never comes, so the SECOND request on the
            # client's connection is never served.
            while not self._stop:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                if self.parts:
                    for i, part in enumerate(self.parts):
                        if i:
                            time.sleep(0.15)
                        tls.sendall(part)
                else:
                    tls.sendall(self.response)
                if not self.keep_open:
                    tls.close()
                    return
        except Exception:
            pass

    def stop(self):
        self._stop = True
        for t in self._held:
            try:
                t.close()
            except OSError:
                pass
        self._srv.close()


class TestResponseFramingIsParseable:
    """What we forward must be framed the way we CLAIM it is.

    The relay strips hop-by-hop headers (Transfer-Encoding among them) and
    then forwards chunk-size lines verbatim, so the client saw chunk syntax
    with no framing declared — free to read "1a\\r\\n" as payload or to wait
    for a close a keep-alive origin never sends. And 204/304 carry no body by
    definition but usually declare no framing either, so they fell into the
    read-until-EOF branch and hung.

    Every assertion here goes through http.client: a hand-rolled reader can
    agree with a hand-rolled writer and still be wrong.
    """

    def _connect(self, proxy_port, ca_path):
        ctx = ssl.create_default_context(cafile=str(ca_path))
        conn = http.client.HTTPSConnection(
            "api.anthropic.com", context=ctx, timeout=5
        )
        conn.set_tunnel("api.anthropic.com", 443)
        conn._create_connection = lambda *a, **k: socket.create_connection(
            ("127.0.0.1", proxy_port), timeout=5
        )
        return conn

    def _get(self, proxy_port, ca_path, method="GET"):
        conn = self._connect(proxy_port, ca_path)
        conn.request(method, "/v1/messages", headers={"Authorization": "Bearer t"})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp, body

    def _get_twice(self, proxy_port, ca_path, method="GET"):
        """Two requests on ONE connection.

        A bodyless response the relay mis-frames does not fail the FIRST
        request: http.client knows 204/304/HEAD carry no body and returns
        without waiting, while the relay thread is still blocked on recv for
        a body that will never come. The damage shows on the next request —
        the connection is never released back, so it never gets served. Only
        the second request can see the bug.
        """
        conn = self._connect(proxy_port, ca_path)
        out = []
        try:
            for _ in range(2):
                conn.request(
                    method, "/v1/messages", headers={"Authorization": "Bearer t"}
                )
                resp = conn.getresponse()
                out.append((resp, resp.read()))
        finally:
            conn.close()
        return out

    def _proxy(self, certdir, upstream):
        from cswap_pin.proxy import PinProxy

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        return proxy

    def test_a_chunked_response_stays_framed_as_chunked(self, certdir):
        upstream = _FramingUpstream(
            certdir,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        proxy = self._proxy(certdir, upstream)
        try:
            resp, body = self._get(proxy.port, certdir / "ca.pem")
            assert resp.status == 200
            assert body == b"hello world", (
                "chunk syntax reached the client as payload — the framing "
                "header was stripped while the chunk lines were kept"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def test_204_completes_without_waiting_for_a_close(self, certdir):
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 204 No Content\r\nDate: now\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem")
            assert [r.status for r, _ in got] == [204, 204], (
                "the relay blocked waiting for a body a 204 cannot have"
            )
            assert [b for _, b in got] == [b"", b""]
        finally:
            proxy.stop()
            upstream.stop()

    def test_304_completes_without_waiting_for_a_close(self, certdir):
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem")
            assert [r.status for r, _ in got] == [304, 304]
            assert [b for _, b in got] == [b"", b""]
        finally:
            proxy.stop()
            upstream.stop()

    def test_connection_close_is_relayed_not_swallowed(self, certdir):
        """`Connection` is hop-by-hop, so the filter drops it — but `close`
        was read into the keep-alive verdict and never re-declared. The proxy
        was about to close while the client still believed the connection
        reusable, so its next request died on a dead socket instead of
        opening a new one.

        Accidentally right before `_HOP_BY_HOP_BYTES`: the filter compared
        bytes against a str set and never matched, so the header rode along.
        """
        upstream = _FramingUpstream(
            certdir,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        proxy = self._proxy(certdir, upstream)
        try:
            conn = self._connect(proxy.port, certdir / "ca.pem")
            conn.request("GET", "/v1/messages", headers={"Authorization": "Bearer t"})
            resp = conn.getresponse()
            body = resp.read()
            assert (resp.status, body) == (200, b"ok")
            assert resp.getheader("Connection") == "close", (
                "the close signal was swallowed — the client will reuse a "
                "connection the proxy is closing"
            )
            assert resp.will_close, "http.client did not see the close"
            conn.close()
        finally:
            proxy.stop()
            upstream.stop()

    def test_a_keep_alive_response_is_not_marked_close(self, certdir):
        """...and the re-declaration must not fire on a healthy response, or
        every connection becomes single-use."""
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem")
            assert [r.status for r, _ in got] == [200, 200]
            assert all(r.getheader("Connection") is None for r, _ in got)
        finally:
            proxy.stop()
            upstream.stop()

    def _raw_exchange(self, proxy_port, ca_path, requests=1, stop_on=None):
        """Two requests through the proxy with a RAW TLS client.

        http.client cannot be the witness here: it discards interim (1xx)
        responses before returning, and its bodyless set is {204, 304} — it
        does not know 205, so it waits for a body a correct relay never
        sends. Both would report our own correct behaviour as a failure.
        """
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
        raw.sendall(
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
            b"Host: api.anthropic.com:443\r\n\r\n"
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += raw.recv(1)
        ctx = ssl.create_default_context(cafile=str(ca_path))
        tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
        try:
            got = b""
            for _ in range(requests):
                tls.sendall(
                    b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                    b"Authorization: Bearer t\r\n\r\n"
                )
                tls.settimeout(3)
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    try:
                        chunk = tls.recv(4096)
                    except (OSError, ssl.SSLError):
                        break
                    if not chunk:
                        break
                    got += chunk
                    if stop_on and stop_on in got:
                        break
                    if not stop_on and got.endswith(b"\r\n\r\n"):
                        break
            return got
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def test_an_interim_1xx_is_not_delivered_as_the_final_response(self, certdir):
        """A 1xx is INTERIM: the real response follows on the same connection.

        Treating it as complete delivered the 103 as the answer and left the
        200 in the upstream buffer, so the next request on that connection
        read a stale response — a desync, not just a wrong status.
        """
        upstream = _FramingUpstream(
            certdir,
            b"",
            parts=[
                b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            ],
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._raw_exchange(
                proxy.port, certdir / "ca.pem", stop_on=b"ok"
            )
            assert b"103 Early Hints" in got, "the interim head was dropped"
            assert b"200 OK" in got and got.endswith(b"ok"), (
                "the FINAL response never arrived — the interim was "
                f"delivered as the answer:\n{got!r}"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def test_205_reset_content_carries_no_body(self, certdir):
        """RFC 9110 §15.3.6 — same class as 204, and it was missing.

        Raw client: http.client's bodyless set is {204, 304}, so it would
        block waiting for a body that must not exist.
        """
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 205 Reset Content\r\nDate: now\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._raw_exchange(proxy.port, certdir / "ca.pem", requests=2)
            assert got.count(b"205 Reset Content") == 2, (
                "the relay blocked on a body a 205 cannot have, so the "
                f"second request was never served:\n{got!r}"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def test_a_head_response_does_not_wait_for_its_absent_body(self, certdir):
        """HEAD mirrors GET's headers — Content-Length included — with no
        body. Only the request method says so."""
        upstream = _FramingUpstream(
            certdir, b"HTTP/1.1 200 OK\r\nContent-Length: 12345\r\n\r\n"
        )
        proxy = self._proxy(certdir, upstream)
        try:
            got = self._get_twice(proxy.port, certdir / "ca.pem", method="HEAD")
            assert [r.status for r, _ in got] == [200, 200], (
                "the relay waited for a body the HEAD response does not carry"
            )
            assert [b for _, b in got] == [b"", b""]
        finally:
            proxy.stop()
            upstream.stop()


class TestChunkedRequestBodiesReachUpstream:
    """A chunked request arrived upstream with NO body.

    `_read_body` recognized only `Content-Length`, so it read zero bytes,
    while the forwarder stripped `Transfer-Encoding` (it is hop-by-hop). The
    upstream therefore saw a bodyless request and every chunked message or
    artifact upload silently lost its payload.
    """

    def test_a_chunked_body_is_decoded_and_reframed(self, certdir):
        from cswap_pin.proxy import PinProxy

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
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
                b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
                b"Authorization: Bearer t\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
                b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
            )
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                resp += chunk
            tls.close()
        finally:
            proxy.stop()
            upstream.stop()

        assert upstream.seen_body == b"hello world", (
            "the upstream received a bodyless request — the chunked payload "
            f"was dropped (got {upstream.seen_body!r})"
        )
        head = upstream.seen_head.lower()
        # The body is decoded, so the chunk framing must NOT be claimed...
        assert "transfer-encoding" not in head, (
            "a decoded body was announced as chunked — the upstream would "
            f"read the payload as a chunk-size line:\n{upstream.seen_head!r}"
        )
        # ...and the framing that IS true has to be declared, or a
        # standards-conforming upstream reads no body at all.
        assert "content-length: 11" in head, (
            "the decoded body was sent with no framing declared:\n"
            f"{upstream.seen_head!r}"
        )


class TestTheChainsCredentialIsSent:
    """An authenticated corporate proxy answers 407 without it.

    Reducing the inherited proxy URL to ``(host, port)`` discarded the
    userinfo, so every CONNECT went out unauthenticated — and where that
    proxy is the only route out, ALL pinned traffic fails.
    """

    def _recording_chain(self):
        """A CONNECT proxy that records the request head and then refuses.

        Refusing is enough: the credential rides on the CONNECT itself, so
        the head is captured before anything downstream matters.
        """
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        seen = []

        def loop():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = conn.recv(4096)
                        if not d:
                            break
                        buf += d
                    seen.append(buf.decode("latin1"))
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                finally:
                    conn.close()

        threading.Thread(target=loop, daemon=True).start()
        return srv, srv.getsockname()[1], seen

    def test_connect_carries_proxy_authorization(self, certdir):
        import base64

        from cswap_pin.proxy import PinProxy, write_upstream_hint

        srv, port, seen = self._recording_chain()
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            rediscover_chain=True,
        )
        write_upstream_hint(certdir, f"http://alice:s3cr3t@127.0.0.1:{port}")
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            raw.sendall(
                b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
            )
            deadline = time.monotonic() + 5
            while not seen and time.monotonic() < deadline:
                time.sleep(0.02)
            raw.close()
        finally:
            proxy.stop()
            srv.close()

        assert seen, "the proxy never reached the chain"
        expected = base64.b64encode(b"alice:s3cr3t").decode()
        assert f"Proxy-Authorization: Basic {expected}" in seen[0], (
            "the CONNECT went out unauthenticated — an authenticated "
            f"corporate proxy answers 407 to this:\n{seen[0]!r}"
        )


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
        from cswap_pin.proxy import PinProxy

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

    def test_a_dead_loopback_chain_does_not_disarm_verification(
        self, certdir, tmp_path
    ):
        """Skipping verification is a property of the HOP, not of the hint.

        The dial falls back to a direct socket when the recorded chain is
        unreachable. Deriving the TLS context from the (still loopback) hint
        instead of from the dial meant that fallback reached the real
        api.anthropic.com with CERT_NONE, carrying account bearers — a MITM
        window that opens exactly when the local proxy is down.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir()
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)  # cert the pin proxy cannot trust

        # A loopback chain that is recorded but NOT listening: bind a port,
        # learn it, close it. The hint stays loopback; the dial must fail.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        write_upstream_hint(certdir, f"http://127.0.0.1:{dead_port}")
        proxy.start()
        try:
            raw, via_loopback = proxy._connect_upstream()
            raw.close()
            assert via_loopback is False, (
                "the chain was unreachable, so this dial was direct"
            )
            assert (
                proxy._upstream_ctx(via_loopback).verify_mode is ssl.CERT_REQUIRED
            ), "a direct dial to the real upstream must verify the certificate"

            # End to end: the foreign-signed upstream must now be REJECTED.
            # The proxy drops the connection on a TLS failure, so "no reply"
            # and "a non-200 reply" are both the refusal this asserts; only a
            # 200 would mean the bad cert was accepted.
            try:
                status = _request_through_proxy(
                    proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
                )
            except (OSError, http.client.HTTPException):
                status = None
            assert status != 200, (
                "an untrusted cert was accepted on a direct dial"
            )
        finally:
            proxy.stop()
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
        from cswap_pin.proxy import PinProxy, _write_port_hint

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
        from cswap_pin import proxy as pin_proxy

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
        # 4242 is a pin daemon for THIS certdir — the recycle is legitimate.
        monkeypatch.setattr(pin_proxy, "_pin_daemon_pids", lambda cd: [4242])
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid: killed.append(pid))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 51000)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)

        pin_proxy.ensure_proxy(_Sw())

        assert killed == [4242], "the stale daemon was not recycled"
        assert pin_proxy.read_port_hint(certdir) == 51000

    def test_a_reused_pid_is_not_killed(self, tmp_path, monkeypatch):
        """Alive is not "still ours".

        An unclean exit leaves proxy.json behind, and the OS reuses pids
        freely. Recycling on liveness alone therefore aims SIGTERM — then
        SIGKILL — at whatever unrelated process inherited the number, purely
        because a dead daemon once had it.
        """
        from cswap_pin import proxy as pin_proxy

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
        # The pid is alive, but it is somebody else's process now: no pin
        # daemon for this certdir carries it.
        monkeypatch.setattr(pin_proxy, "_pid_alive", lambda pid: True)
        monkeypatch.setattr(pin_proxy, "_pin_daemon_pids", lambda cd: [])
        monkeypatch.setattr(pin_proxy, "_kill_daemon", lambda pid: killed.append(pid))
        monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 51000)
        monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *a, **k: True)

        pin_proxy.ensure_proxy(_Sw())

        assert killed == [], (
            "SIGTERM/SIGKILL sent to a process that is not our daemon"
        )

    def test_a_superseded_daemon_leaves_the_successors_state_alone(
        self, tmp_path
    ):
        """The other half of the same root: cleanup must check ownership too.

        _spawn_daemon publishes the successor's proxy.json and only THEN
        sweeps the orphans it replaces. So the old daemon's SIGTERM arrives
        after the file already names the successor — and an unconditional
        unlink deletes the record of the daemon that is currently serving.
        The next launch then reads no state and spawns another one on top.
        """
        import os as _os
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()

        # State published by the SUCCESSOR (a pid that is not ours).
        successor_pid = _os.getpid() + 1
        pin_proxy.write_daemon_state(certdir, 51000, successor_pid, "fp")

        assert pin_proxy._release_daemon_state(certdir) is True, (
            "a superseded daemon must report that it no longer owns the state"
        )
        st = pin_proxy.read_daemon_state(certdir)
        assert st is not None and int(st["pid"]) == successor_pid, (
            "the departing daemon deleted the serving successor's state"
        )

    def test_a_daemon_still_owning_its_state_clears_it(self, tmp_path):
        """The normal teardown must still leave nothing behind — a stale
        record reads as live and the next launch reuses a dead port."""
        import os as _os
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pin_proxy.write_daemon_state(certdir, 51000, _os.getpid(), "fp")

        assert pin_proxy._release_daemon_state(certdir) is False
        assert pin_proxy.read_daemon_state(certdir) is None

    def test_spawn_carries_the_port_forward(self, tmp_path, monkeypatch):
        """_spawn_daemon must record the outgoing port BEFORE deleting the
        state file it lives in — the regression that let a recycle land on a
        fresh port while .claude.json still named the old one."""
        from cswap_pin import proxy as pin_proxy

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
        from cswap_pin.proxy import PinProxy

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
            up, _via_loopback = proxy._connect_upstream()
            assert up.gettimeout() is None, (
                "a read deadline on the upstream kills the RC long poll"
            )
            up.close()
        finally:
            for c in held:
                c.close()
            srv.close()


class TestChainRediscovery:
    """The daemon outlives the launch that spawned it, and a cache proxy picks
    its port from a family and can restart. A chain bound once at spawn
    therefore goes stale — and a stale chain does not degrade, it BYPASSES the
    egress proxy. The daemon re-reads the hint every connection instead.

    AND A DEAD HOP FALLS THROUGH TO THE HOP BEHIND IT, never to a direct dial.
    Behind a corporate TLS-inspecting proxy a direct dial is not "no proxy",
    it is the inspector, and its leaf carries no Authority Key Identifier —
    so a strict verifier refuses it and OAuth against claude.ai fails with
    nothing on screen. Only the outermost proxy reaches the real leaf, which
    is why a hint recording ONE hop is not enough: when the recorded hop is an
    inner cache proxy and it goes away, the correct target is the outer proxy
    it was itself chaining to."""

    def test_follows_a_chain_that_appears_after_the_daemon_started(
        self, certdir, tmp_path
    ):
        from cswap_pin.proxy import PinProxy, write_upstream_hint

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
        from cswap_pin.proxy import read_upstream_hint, write_upstream_hint

        write_upstream_hint(certdir, "http://127.0.0.1:9901")
        assert read_upstream_hint(certdir).address == ("127.0.0.1", 9901)

        write_upstream_hint(certdir, None)  # a launch with nothing in its env
        assert read_upstream_hint(certdir).address == ("127.0.0.1", 9901), (
            "a launch that could not see a proxy erased the recorded one"
        )

        # A launch that positively reports a DIFFERENT proxy still wins.
        write_upstream_hint(certdir, "http://127.0.0.1:9902")
        assert read_upstream_hint(certdir).address == ("127.0.0.1", 9902)

    def test_the_kept_hint_keeps_its_CREDENTIAL_and_scheme(self, certdir):
        """Keeping the address is not keeping the chain.

        The keep-previous branch rebuilt the URL from the parsed pair, which
        threw away the two fields the chain exists to carry. And this is the
        NORMAL path — `cswap pin` from a plain shell reports no proxy, and
        ensure_proxy re-stamps on every launch — so on a machine whose only
        route out is an authenticated or https:// corporate proxy, the
        credential survived until the next re-pin and then every pinned
        request 407'd.
        """
        from cswap_pin.proxy import read_upstream_hint, write_upstream_hint

        write_upstream_hint(certdir, "https://bob:s3cr%40t@corp.proxy:8443")
        first = read_upstream_hint(certdir)
        assert first.auth and first.tls, first

        write_upstream_hint(certdir, None)  # the re-stamp every launch does
        kept = read_upstream_hint(certdir)
        assert kept == first, (
            f"the re-stamp laundered the chain: {first} -> {kept}"
        )

    def test_the_recorded_upstream_is_returned_raw(self, certdir):
        """_recorded_upstream feeds back INTO the hint, so reconstructing the
        URL there launders the credential on the other side of the same round
        trip."""
        from cswap_pin.proxy import _recorded_upstream, write_upstream_hint

        url = "https://bob:s3cr%40t@corp.proxy:8443"
        write_upstream_hint(certdir, url)
        assert _recorded_upstream(certdir) == url

    def test_falls_back_to_direct_when_the_recorded_chain_is_gone(
        self, certdir, tmp_path
    ):
        """The hint cannot expire on its own (see above), so a chain that dies
        must not wedge every request — the relay dials direct instead."""
        from cswap_pin.proxy import PinProxy, write_upstream_hint

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
        from cswap_pin.proxy import PinProxy, write_upstream_hint

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
        from cswap_pin.proxy import _ambient_proxy

        env = {"HTTPS_PROXY": "http://127.0.0.1:45678", "CSWAP_PIN_PORT": "45678"}
        assert _ambient_proxy(env) is None
        # A DIFFERENT loopback proxy (CCF) is a legitimate chain.
        env = {"HTTPS_PROXY": "http://127.0.0.1:9901", "CSWAP_PIN_PORT": "45678"}
        assert _ambient_proxy(env) == "http://127.0.0.1:9901"

    def _dead_port(self) -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        assert port != 36301, port
        return port

    def _refusing_chain(self):
        """Accepts the CONNECT and answers 502 — a restarting cache proxy,
        whose listener is up before its proxy logic is ready."""
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        assert srv.getsockname()[1] != 36301, srv.getsockname()
        seen = []

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                seen.append(1)
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        return srv, srv.getsockname()[1], seen

    def _proxy_over(self, certdir, tmp_path, first_url, next_url, monkeypatch):
        """A daemon whose recorded chain is ``first_url`` with ``next_url``
        behind it, pointed at an upstream signed by a CA it CANNOT trust.

        The foreign CA is the discriminator: verification is skipped only for a
        loopback hop, so a 200 proves the request went through a recorded hop
        and a refusal proves it did not.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir(exist_ok=True)
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)

        write_upstream_hint(certdir, first_url, next_hop=next_url)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
            rediscover_chain=True,
        )
        proxy.start()
        assert proxy.port != 36301, proxy.port
        return proxy, upstream

    def test_the_log_names_the_hop_that_carried_and_stays_quiet_after(
        self, certdir
    ):
        """Falling through a dead hop is silent, so a request carried by the
        second hop and one carried by the first read identically. An observer
        had to infer it afterwards from the TLS issuer.

        The transition is logged, not the state: a steady chain costs nothing
        per connection, and losing a hop is visible the moment it happens.
        """
        import contextlib
        import io

        from cswap_pin import proxy as pin_proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        good = socket.socket()
        good.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        good.bind(("127.0.0.1", 0))
        good.listen(4)
        good_port = good.getsockname()[1]

        def _answer():
            while True:
                try:
                    conn, _ = good.accept()
                except OSError:
                    return
                try:
                    conn.recv(8192)
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except OSError:
                    pass

        threading.Thread(target=_answer, daemon=True).start()
        try:
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")
            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", dead_port)),
                pin_proxy._as_chain(("127.0.0.1", good_port)),
            ]

            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            first = [l for l in buf.getvalue().splitlines() if "egress" in l]
            assert first, "the walk said nothing about which hop carried it"
            assert str(good_port) in first[0], first

            # The SAME hop again must be silent, or every connection logs.
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sock, _ = relay._connect_upstream()
                sock.close()
            assert not [
                l for l in buf.getvalue().splitlines() if "egress" in l
            ], "an unchanged chain logged again"

            # And with no hop left, the downgrade is named.
            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", dead_port))
            ]
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            assert any(
                "DIRECT" in l for l in buf.getvalue().splitlines()
            ), buf.getvalue()
        finally:
            good.close()

    def test_D1_a_chain_that_refuses_the_dial_uses_the_next_hop(
        self, certdir, tmp_path, monkeypatch
    ):
        """CCF is DOWN: nothing is listening on the recorded hop.

        The dial raises OSError and the code dropped to
        `socket.create_connection(self._upstream)` — a direct dial, i.e. the
        corporate inspector on this host. No error, nothing on screen.
        """
        outer = _LoopbackConnectProxy(("127.0.0.1", 0))
        dead = self._dead_port()
        proxy = upstream = None
        try:
            outer._target = None  # set below, once the upstream exists
            proxy, upstream = self._proxy_over(
                certdir, tmp_path,
                f"http://127.0.0.1:{dead}",
                f"http://127.0.0.1:{outer.port}",
                monkeypatch,
            )
            outer._target = ("127.0.0.1", upstream.port)
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert outer.connects == 1, (
                "the dead hop fell through to a DIRECT dial instead of to the "
                "hop behind it — on this host that is the corporate inspector"
            )
            assert status == 200, "the next hop was not usable"
        finally:
            if proxy:
                proxy.stop()
            if upstream:
                upstream.stop()
            outer.stop()

    def test_D2_a_chain_that_refuses_the_CONNECT_uses_the_next_hop(
        self, certdir, tmp_path, monkeypatch
    ):
        """CCF is RESTARTING: its listener is up, its proxy logic is not.

        `_connect_ok` is false, and the `raise OSError` that follows was caught
        by nobody — the `except OSError` wrapped only the dial. So a hop that
        accepts and then fails did not even reach the (wrong) direct fallback:
        it killed the request outright.
        """
        refusing, refusing_port, seen = self._refusing_chain()
        outer = _LoopbackConnectProxy(("127.0.0.1", 0))
        proxy = upstream = None
        try:
            outer._target = None
            proxy, upstream = self._proxy_over(
                certdir, tmp_path,
                f"http://127.0.0.1:{refusing_port}",
                f"http://127.0.0.1:{outer.port}",
                monkeypatch,
            )
            outer._target = ("127.0.0.1", upstream.port)
            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert seen, "premise: the refusing hop was never dialled"
            assert outer.connects == 1, (
                "a hop that ACCEPTED and then refused the CONNECT did not fall "
                "through at all — the OSError it raises is caught by nobody"
            )
            assert status == 200, "the next hop was not usable"
        finally:
            if proxy:
                proxy.stop()
            if upstream:
                upstream.stop()
            outer.stop()
            refusing.close()

    def test_the_next_hop_is_probed_from_the_cache_proxys_health(self, certdir):
        """Where the second hop comes from: the inner proxy reports its own
        upstream while it is alive, and a launch records both. Probed rather
        than inherited, because `cswap pin` runs in a plain shell that has
        neither value in its environment."""
        import cswap_pin.proxy as pp

        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        assert port != 36301, port

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    body = json.dumps(
                        {"status": "ok", "forward_proxy": True,
                         "https_proxy": "http://127.0.0.1:8118"}
                    ).encode()
                    c.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        b"Content-Length: " + str(len(body)).encode()
                        + b"\r\n\r\n" + body
                    )
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            nxt = pp._probe_next_hop(f"http://127.0.0.1:{port}")
            assert nxt == "http://127.0.0.1:8118"
            pp.write_upstream_hint(
                certdir, f"http://127.0.0.1:{port}", next_hop=nxt
            )
            assert pp._chain_hops(certdir)[-1].address == ("127.0.0.1", 8118)
        finally:
            srv.close()

    def test_a_cache_proxy_that_is_not_answering_records_no_next_hop(self, certdir):
        """Never record a stale hop. A hop that cannot be confirmed right now
        is worse than none: the walk would spend a dial on it before reaching
        the branch that decides what to do with no chain at all."""
        import cswap_pin.proxy as pp

        dead = self._dead_port()
        nxt = pp._probe_next_hop(f"http://127.0.0.1:{dead}")
        assert nxt is None
        pp.write_upstream_hint(certdir, f"http://127.0.0.1:{dead}", next_hop=nxt)
        hops = pp._chain_hops(certdir)
        assert [h.address for h in hops] == [("127.0.0.1", dead)], hops




class TestAbsoluteFormPassthrough:
    """The native auto-updater and telemetry use axios in plain-proxy mode:
    they send `GET http://host/path` (absolute-form, no CONNECT). The proxy
    must relay these through the chain, not drop them (dropping = the
    'Auto-update failed' banner). No MITM/swap — just forward."""

    def test_absolute_form_get_is_relayed(self, certdir):
        from cswap_pin.proxy import PinProxy

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
        from cswap_pin.proxy import PinProxy

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
        from cswap_pin.proxy import PinProxy

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
        from cswap_pin.proxy import PinProxy

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
        import cswap_pin.proxy as pp

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
        import cswap_pin.proxy as pp

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


class TestOptimisticConnectIsDetected:
    """A CONNECT 200 means the chain ACCEPTED the request, not that it reached
    the host. privoxy answers optimistically and dials afterwards, closing the
    socket when that dial fails — measured on work-mac against the Remote
    Control ingress: "200 Connection established" followed immediately by
    UNEXPECTED_EOF_WHILE_READING on the first TLS byte. Trusting the status
    made RC silently deaf: everything Claude Code SENDS kept going through the
    MITM path at 200 while the receive channel was a dead socket."""

    def _optimistic_chain(self):
        """Answers 200 to every CONNECT, then closes without connecting."""
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
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        d = c.recv(4096)
                        if not d:
                            break
                        buf += d
                    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                except OSError:
                    pass
                finally:
                    c.close()          # the dial "failed" — EOF at once

        threading.Thread(target=serve, daemon=True).start()
        return srv

    def test_falls_back_when_the_200_tunnel_is_already_eof(self, certdir, tmp_path):
        import cswap_pin.proxy as pp

        chain = self._optimistic_chain()

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
                if c.recv(64):
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
                    assert chunk, "proxy closed instead of re-dialling"
                    resp += chunk
                assert b"200" in resp.split(b"\r\n")[0], resp[:80]
                raw.sendall(b"PING")
                assert raw.recv(16) == b"PONG", (
                    "the tunnel was the chain's dead socket, not the host"
                )
                raw.close()
            finally:
                proxy.stop()
                peer.close()
                chain.close()
            pp._TRACE.flush()
        finally:
            pp._TRACE.close()
            pp._TRACE = prev

        assert reached.is_set(), "the host was never dialled directly"
        assert "already EOF" in log.read_text(), log.read_text()


class TestTheTrustFileActuallyVerifies:
    """Every other check on the CA-trust contract inspects file CONTENT — does
    the bundle contain our CA, are its BEGIN/END markers balanced. Both are
    necessary and neither is evidence: they are pre-flight guards, and only a
    completed handshake proves the file yields a working trust path to the
    proxy. Measured on lmd42 against the live daemon: with the merged bundle,
    TLS OK, issuer "cswap pin-proxy CA"; with no extra CA,
    UNABLE_TO_VERIFY_LEAF_SIGNATURE. This is that, in-process."""

    def _handshake(self, proxy_port: int, cafile) -> str:
        """CONNECT through the proxy and complete TLS, trusting only cafile."""
        raw = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
        raw.sendall(
            b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
            b"Host: api.anthropic.com:443\r\n\r\n"
        )
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                break
            resp += chunk
        assert b"200" in resp.split(b"\r\n")[0], resp[:80]
        ctx = ssl.create_default_context(cafile=str(cafile)) if cafile else (
            ssl.create_default_context()
        )
        try:
            tls = ctx.wrap_socket(raw, server_hostname="api.anthropic.com")
            issuer = dict(x[0] for x in (tls.getpeercert() or {}).get("issuer", ()))
            tls.close()
            return issuer.get("commonName", "?")
        except ssl.SSLError as e:
            raw.close()
            return f"FAIL:{e.reason}"

    def test_the_named_trust_file_verifies_the_proxy(self, certdir, tmp_path, monkeypatch):
        import cswap_pin.proxy as pp

        home = tmp_path / "cfg"
        home.mkdir()
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)

        proxy = pp.PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PINTOKEN",
            upstream=("127.0.0.1", 1),
        )
        proxy.start()
        try:
            ca = certdir / "ca.pem"
            # A merged bundle exactly as a launcher would build it: someone
            # else's root first, ours after.
            merged = home / pp.CA_TRUST_FILE
            merged.write_bytes(ca.read_bytes())
            chosen = pp._trust_file(ca, None)
            assert chosen == merged, "the contract's own selection did not pick it"

            # The point of the test: what NODE_EXTRA_CA_CERTS names must
            # actually verify the proxy, not merely mention it.
            assert self._handshake(proxy.port, chosen) == "cswap pin-proxy CA"
            # Control — without it the handshake must FAIL, or the assertion
            # above proves nothing.
            assert self._handshake(proxy.port, None).startswith("FAIL:")
        finally:
            proxy.stop()


class TestTheKillGateIdentifiesItsTarget:
    """`_pin_daemon_pids` decides who gets SIGTERM then SIGKILL.

    Every other test stubs it, so the matcher itself was never exercised —
    and it matched by plain substring over the whole `ps` line, which also
    selects anything that merely MENTIONS the module and the certdir: a
    shell whose command line quotes them, a wrapper, a grep.
    """

    def _pids(self, monkeypatch, lines, certdir):
        import subprocess as _sp

        from cswap_pin import proxy as pp

        class _R:
            stdout = "\n".join(lines)

        monkeypatch.setattr(_sp, "run", lambda *a, **k: _R())
        return pp._pin_daemon_pids(certdir)

    def test_the_certdir_must_be_the_last_argv_token(self, tmp_path, monkeypatch):
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        t = str(certdir.resolve())
        pids = self._pids(
            monkeypatch,
            [
                f" 111 python3 -m cswap_pin.proxy 1 a@b.c {t}",       # the daemon
                f" 222 /bin/zsh -c 'cswap_pin.proxy ... {t}' && ls",   # a shell
                f" 333 grep cswap_pin.proxy {t} /var/log/x",           # a grep
            ],
            certdir,
        )
        assert pids == [111], (
            f"the kill gate selected a process that only mentions the "
            f"daemon: {pids}"
        )

    def test_a_different_certdir_is_never_matched(self, tmp_path, monkeypatch):
        mine = tmp_path / "pin-proxy"; mine.mkdir()
        other = tmp_path / "other-proxy"; other.mkdir()
        pids = self._pids(
            monkeypatch,
            [f" 444 python3 -m cswap_pin.proxy 1 a@b.c {other.resolve()}"],
            mine,
        )
        assert pids == [], "a daemon for another backup dir was selected"


class TestFailOpenIsNotSilent:
    """The token swap fails OPEN by design — a pin that cannot resolve must
    never block work. The cost is that nothing marks it: requests keep
    succeeding, /health keeps answering, and the consequence surfaces days
    later as Remote Control sessions owned by the wrong account, which the
    server fixes at /bridge and never transfers. Measured: a daemon that could
    not reach its credential store served 13 of 13 pinned routes unswapped, and
    19 sessions had to be rebuilt by hand. Fail open, but say so."""

    def _proxy(self, certdir, provider):
        from cswap_pin.proxy import PinProxy
        return PinProxy(certdir=certdir, pin_token_provider=provider,
                        upstream=("127.0.0.1", 1))

    def _drive_pinned_request(self, proxy):
        """Run one PINNED request through the real swap path.

        The fail-open warning lives in ``_handle_one_request``, so asserting on
        ``_warn_unpinnable()`` directly proves nothing about whether a request
        reaches the guard. Feeds a fake TLS socket instead: the relay fails
        (upstream is port 1, deliberately dead), which is fine — the swap
        decision, and the warning, happen before the relay.
        """
        class _FakeTLS:
            def __init__(self):
                self._in = (
                    b"POST /v1/code/sessions HTTP/1.1\r\n"
                    b"Host: api.anthropic.com\r\n"
                    b"Authorization: Bearer disk-bearer\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                self.sent = b""

            def recv(self, n):
                out, self._in = self._in[:n], self._in[n:]
                return out

            def sendall(self, b):
                self.sent += b

            def close(self):
                pass

        try:
            proxy._handle_one_request(_FakeTLS())
        except Exception:
            pass  # relay to the dead upstream fails; the swap already happened
        return None

    def test_a_deferred_refresh_does_not_condemn_the_daemon(self, tmp_path):
        """"Busy right now" is not "cannot pin".

        The gate answers ``consume-busy`` when another process holds the
        slot's consume lock — the usage collector polls on its own schedule
        and contends for exactly this slot. That is a race to retry, and the
        provider's own docstring says so.

        But the only other reading of a None token is "this daemon cannot
        pin", which ``_warn_unpinnable`` records into proxy.json as
        ``unpinnable: True`` — and ``_read_alive_port`` then refuses to reuse
        that daemon FOREVER. One lost race would condemn a healthy daemon and
        print macOS-keychain advice for a Linux lock contention.
        """
        import json

        from claude_swap.oauth import RefreshOutcome
        from cswap_pin import proxy as pp

        expired = json.dumps({"claudeAiOauth": {
            "accessToken": "dead", "expiresAt": 1, "refreshToken": "rt"}})

        class _Busy:
            backup_dir = tmp_path
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return expired
            def resolve_account(self, i): return ("2", "pin@example.com", "org")
            def consume_backup_grant(self, n, e, snap):
                return RefreshOutcome(None, "consume-busy")

        pp.save_pin(tmp_path, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Busy(), "2", "pin@example.com")

        assert provider() is None, "a busy gate yields no token, by design"
        assert provider.pin_is_noop() is True, (
            "a deferral was reported as a failure — the daemon gets marked "
            "unpinnable and is never reused again"
        )

    def test_a_real_unreadable_credential_IS_still_a_failure(self, tmp_path):
        """...and the deferral must not swallow the case the warning exists
        for. An unreadable store still has to condemn."""
        from cswap_pin import proxy as pp

        class _Unreadable:
            backup_dir = tmp_path
            def current_account_number(self): return "1"
            def read_account_credentials(self, n, e): return ""
            def resolve_account(self, i): return ("2", "pin@example.com", "org")

        pp.save_pin(tmp_path, "pin@example.com", "org")
        provider = pp.make_pin_token_provider(_Unreadable(), "2", "pin@example.com")

        assert provider() is None
        assert provider.pin_is_noop() is False, (
            "an unreadable credential must still warn"
        )

    def test_warns_when_the_token_cannot_be_minted(self, certdir, monkeypatch):
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        self._proxy(certdir, lambda: None)._warn_unpinnable()
        err = buf.getvalue()
        assert "UNPINNED" in err
        assert "cswap pin" in err, "the message must name the fix"

    def test_the_spawned_daemon_has_somewhere_to_warn(self, certdir, monkeypatch):
        """The warning above is written to the daemon's stderr, and the daemon
        is spawned detached — so whether it reaches anyone is decided by
        spawn_daemon, not by the writer. Measured on all three machines: the
        daemon's fd 2 was /dev/null, meaning every fail-open was silent by
        construction while two tests above asserted the message "works" against
        a substituted stderr. A warning with no destination is the bug it
        exists to report."""
        import subprocess as _sp
        from cswap_pin import proxy as pp

        seen = {}

        class _FakePopen:
            def __init__(self, argv, **kw):
                seen.update(kw)
                seen["argv"] = argv

        monkeypatch.setattr(_sp, "Popen", _FakePopen)
        # Return a port on the first poll so spawn_daemon stops immediately —
        # we only care about how it tried to spawn, not about waiting out the
        # ~10s window for a daemon this test never starts.
        monkeypatch.setattr(pp, "_read_alive_port", lambda *a, **k: 4321)
        monkeypatch.setattr(pp, "read_daemon_state", lambda *a, **k: None)
        monkeypatch.setattr(pp, "_sweep_orphan_daemons", lambda *a, **k: None)
        pp._spawn_daemon("1", "a@b.c", certdir)

        assert seen["stderr"] is not _sp.DEVNULL, (
            "stderr=DEVNULL gives _warn_unpinnable nowhere to land"
        )
        log = pp.daemon_log_path(certdir)
        assert seen["stderr"].name == str(log), (
            f"expected the daemon's stderr on {log}, got {seen['stderr']!r}"
        )

    def test_the_warning_lands_in_that_log(self, certdir):
        """End to end through the real file object spawn_daemon opens: write
        the warning to it and read it back off disk. The two tests above pass a
        StringIO and so cannot see a destination that does not exist."""
        from cswap_pin import proxy as pp

        log = pp.daemon_log_path(certdir)
        handle = pp._open_daemon_log(certdir)
        try:
            p = self._proxy(certdir, lambda: None)
            with contextlib.redirect_stderr(handle):
                p._warn_unpinnable()
        finally:
            handle.close()
        body = log.read_text(encoding="utf-8")
        assert "UNPINNED" in body
        assert "cswap pin" in body

    def test_warns_only_once_per_daemon(self, certdir, monkeypatch):
        """A pinned session makes these calls continuously; a line each would
        bury the signal it exists to be."""
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        p = self._proxy(certdir, lambda: None)
        for _ in range(5):
            p._warn_unpinnable()
        assert buf.getvalue().count("UNPINNED") == 1

    def test_health_reports_whether_the_pin_can_apply(self, certdir):
        """A daemon being up is not the same as the pin working. The sweep
        needs the second fact, and only the daemon can answer it."""
        import json as _json, socket as _s
        for provider, expect in ((lambda: "TOK", True), (lambda: None, False)):
            p = self._proxy(certdir, provider)
            p.start()
            try:
                c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
                c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                body = buf.partition(b"\r\n\r\n")[2]
                while not body.endswith(b"}"):
                    d = c.recv(4096)
                    if not d:
                        break
                    body += d
                c.close()
                assert _json.loads(body)["can_pin"] is expect
            finally:
                p.stop()

    def test_a_noop_pin_does_not_warn(self, certdir, monkeypatch):
        """Nothing-to-swap must not fire the keychain warning.

        When the pinned account IS the active one the provider correctly
        returns no token: the live bearer already belongs to it. Warning there
        sends whoever reads the log after a macOS keychain fault that is not
        there. Measured on personal-mac after the 79a665a deploy: daemon.log
        carried "the pinned account token could not be read ... started
        outside the GUI session" while the keychain read was fine (rc=0, 509
        bytes), and it cost the reader ten minutes.

        Drives the real swap path rather than asserting on a method call, so
        it fails if the guard is put anywhere the request does not reach.
        """
        import io
        import sys as _sys

        def provider():
            return None
        provider.pin_is_noop = lambda: True

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        p = self._proxy(certdir, provider)
        # A pinned route with no token: the exact condition that warns.
        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" not in buf.getvalue(), "warned when nothing was wrong"

    def test_an_unreadable_store_still_warns(self, certdir, monkeypatch):
        """The quieting must not swallow the case the warning exists for."""
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        # No pin_is_noop hook: "cannot read" is the default reading of None.
        p = self._proxy(certdir, lambda: None)
        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" in buf.getvalue(), "went silent on a real fail-open"

    def test_a_noop_pin_reports_can_pin_on_health(self, certdir):
        """/health must not call a pin broken on the machine where it is a no-op.

        can_pin is what a fleet sweep reads. Reporting false where there is
        deliberately nothing to swap is a false alarm in the machine-readable
        channel, which is worse than the log line because nobody is there to
        judge it.
        """
        import json as _json, socket as _s

        def provider():
            return None
        provider.pin_is_noop = lambda: True

        p = self._proxy(certdir, provider)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            c.close()
            assert _json.loads(body)["can_pin"] is True, (
                "reported the pin as broken on a machine where it has nothing to do"
            )
        finally:
            p.stop()

    def test_a_raising_provider_reports_cannot_pin(self, certdir):
        """Health must never take the daemon down, whatever the store does."""
        import json as _json, socket as _s

        def boom():
            raise RuntimeError("keychain unavailable")

        p = self._proxy(certdir, boom)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            c.close()
            assert _json.loads(body)["can_pin"] is False
        finally:
            p.stop()


class TestProxyRequiresACredential:
    """The daemon listens on unauthenticated loopback and swaps the bearer of
    any request matching a pinned route. Loopback carries no identity — the
    kernel does not check uid on a TCP connect — so without a credential ANY
    local process can CONNECT with a junk bearer and get one minted from the
    pinned account. cswap keeps that credential at 0700/0600 precisely so it
    cannot be read; the proxy was handing out its effect to anyone who asked.
    """

    def _proxy(self, certdir, provider=lambda: "PINNED-TOKEN"):
        from cswap_pin.proxy import PinProxy
        return PinProxy(certdir=certdir, pin_token_provider=provider,
                        upstream=("127.0.0.1", 1))

    def _connect(self, port, cred=None, target="api.anthropic.com:443"):
        """Send one CONNECT and return the status line."""
        import base64, socket as _s
        c = _s.create_connection(("127.0.0.1", port), timeout=10)
        req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        if cred is not None:
            blob = base64.b64encode(f"cswap:{cred}".encode()).decode()
            req += f"Proxy-Authorization: Basic {blob}\r\n"
        req += "\r\n"
        c.sendall(req.encode())
        c.settimeout(5)
        try:
            data = c.recv(256)
        except OSError:
            data = b""
        c.close()
        return data.decode("latin1", "replace").split("\r\n")[0]

    def test_an_unauthenticated_connect_is_served_but_never_pinned(self, certdir):
        """The property is "no credential, no bearer" — NOT "no credential, no
        service".

        Refusing the connection protected the bearer, but it also made turning
        the pin ON destructive: HTTPS_PROXY is fixed at exec, so every session
        that started before the credential existed got 407 and only a relaunch
        fixed it (measured: 313 processes, including the one that ran the
        command). Serving unauthorized callers UNPINNED protects the same asset
        — they are simply not acted for — while a running session keeps working
        through a pin being turned on or off.
        """
        from cswap_pin.proxy import ensure_proxy_secret, _proxy_authorized
        ensure_proxy_secret(certdir)
        p = self._proxy(certdir)
        p.start()
        try:
            assert "407" not in self._connect(p.port), (
                "an unauthorized caller was cut off — turning the pin on kills "
                "every session that predates the credential"
            )
        finally:
            p.stop()
        # and the bearer is still withheld from it
        secret = ensure_proxy_secret(certdir)
        assert _proxy_authorized([], secret) is False
        assert _proxy_authorized(
            [("Proxy-Authorization", "Basic " + __import__("base64")
              .b64encode(f"cswap:{secret}".encode()).decode())], secret) is True

    def test_a_wrong_credential_is_served_but_never_pinned(self, certdir):
        from cswap_pin.proxy import ensure_proxy_secret, _proxy_authorized
        secret = ensure_proxy_secret(certdir)
        p = self._proxy(certdir)
        p.start()
        try:
            assert "407" not in self._connect(p.port, cred="not-the-secret")
        finally:
            p.stop()
        import base64
        wrong = base64.b64encode(b"cswap:not-the-secret").decode()
        assert _proxy_authorized(
            [("Proxy-Authorization", f"Basic {wrong}")], secret) is False

    def test_the_real_credential_is_accepted(self, certdir):
        """The credential must not lock out the sessions it is meant to serve.

        Getting past the gate means the CONNECT proceeds to the MITM, whose
        upstream is port 1 and therefore fails — a closed connection with no
        407 is the pass condition here.
        """
        from cswap_pin.proxy import ensure_proxy_secret
        secret = ensure_proxy_secret(certdir)
        p = self._proxy(certdir)
        p.start()
        try:
            assert "407" not in self._connect(p.port, cred=secret)
        finally:
            p.stop()

    def test_a_blind_tunnel_is_not_gated(self, certdir):
        """It used to be, on "otherwise we are an open forward proxy". That
        assumes the port is reachable; it binds 127.0.0.1 only, so the
        population it could refuse is the same-user processes that can read
        the 0600 secret anyway.

        What it cost is the reason it is gone. EVERY host that is not
        api.anthropic.com takes this branch — git, pip, npm, the auto-updater
        — so with the pin on, a session wired before the credential existed
        got 200 for Claude and 407 for the entire rest of the internet.
        Measured on lmd42: github.com, pypi.org and registry.npmjs.org all
        407 while api.anthropic.com was 200. That reads as "the network
        broke", and it broke this project's own `git push`.
        """
        from cswap_pin.proxy import ensure_proxy_secret
        ensure_proxy_secret(certdir)
        p = self._proxy(certdir)
        p.start()
        try:
            assert "407" not in self._connect(p.port, target="example.com:443"), (
                "turning the pin on severed general internet for live sessions"
            )
        finally:
            p.stop()

    def test_absolute_form_also_needs_the_credential(self, certdir):
        """The plain-proxy path must not be a way around the CONNECT gate."""
        import socket as _s
        from cswap_pin.proxy import ensure_proxy_secret
        ensure_proxy_secret(certdir)
        p = self._proxy(certdir)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n")
            c.settimeout(5)
            try:
                data = c.recv(256)
            except OSError:
                data = b""
            c.close()
            assert "407" in data.decode("latin1", "replace")
        finally:
            p.stop()

    def test_health_stays_open(self, certdir):
        """The statusline and cc-update probe /health with no credential.

        Gating it would make a working pin read as a dead one on every
        machine, which is the failure the liveness work just finished fixing.
        """
        import json as _json, socket as _s
        from cswap_pin.proxy import ensure_proxy_secret
        ensure_proxy_secret(certdir)
        p = self._proxy(certdir)
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            c.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    break
                buf += d
            body = buf.partition(b"\r\n\r\n")[2]
            while not body.endswith(b"}"):
                d = c.recv(4096)
                if not d:
                    break
                body += d
            c.close()
            assert _json.loads(body)["pin_proxy"] is True
        finally:
            p.stop()

    def test_a_daemon_without_a_secret_still_serves(self, certdir):
        """A pin that starts refusing traffic after an upgrade is worse than
        the exposure it closes. No secret on disk => no auth required."""
        p = self._proxy(certdir)  # nothing minted
        p.start()
        try:
            assert "407" not in self._connect(p.port)
        finally:
            p.stop()

    def test_the_secret_is_not_world_readable(self, certdir):
        import stat
        from cswap_pin.proxy import ensure_proxy_secret, proxy_secret_path
        ensure_proxy_secret(certdir)
        mode = proxy_secret_path(certdir).stat().st_mode
        assert not (mode & (stat.S_IRGRP | stat.S_IROTH)), (
            "the credential is readable by other users — it protects nothing"
        )

    def test_the_secret_is_stable_across_respawns(self, certdir):
        """A new secret each spawn would strand every live session: their
        HTTPS_PROXY is fixed at exec time and would carry the old one."""
        from cswap_pin.proxy import ensure_proxy_secret
        assert ensure_proxy_secret(certdir) == ensure_proxy_secret(certdir)

    def test_the_wiring_hands_clients_the_credential(self, certdir):
        """Measured: the real Claude Code client sends Proxy-Authorization on
        CONNECT only when HTTPS_PROXY carries user:pass. If the wiring does
        not embed it, enforcing auth cuts off every session."""
        from cswap_pin.proxy import ensure_proxy_secret, wire_env
        secret = ensure_proxy_secret(certdir)
        env = wire_env({}, 9955, certdir / "ca.pem", open_refcount=False)
        assert secret in env["HTTPS_PROXY"]
        assert "@127.0.0.1:9955" in env["HTTPS_PROXY"]

    def test_the_credential_is_not_forwarded_upstream(self, certdir):
        """It authenticates to THIS proxy and stops here (hop-by-hop).

        The absolute-form path relays client headers verbatim to the chain, so
        without stripping it we would hand CCF or a corporate proxy a working
        credential for the pinned account's proxy.
        """
        import socket as _s, base64, threading
        from cswap_pin.proxy import ensure_proxy_secret
        secret = ensure_proxy_secret(certdir)
        seen = []
        srv = _s.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        chain_port = srv.getsockname()[1]

        def accept():
            c, _ = srv.accept()
            buf = b""
            try:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
            except OSError:
                pass
            seen.append(buf.decode("latin1", "replace"))
            try:
                c.close()
            except OSError:
                pass

        t = threading.Thread(target=accept, daemon=True)
        t.start()
        p = self._proxy(certdir)
        p._chain = ("127.0.0.1", chain_port)
        p._rediscover_chain = False
        p.start()
        try:
            c = _s.create_connection(("127.0.0.1", p.port), timeout=10)
            blob = base64.b64encode(f"cswap:{secret}".encode()).decode()
            c.sendall(
                f"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n"
                f"Proxy-Authorization: Basic {blob}\r\n\r\n".encode()
            )
            t.join(timeout=5)
            c.close()
        finally:
            p.stop()
            srv.close()
        assert seen, "the relay never reached the chain"
        # Match on the header, not on the raw secret: it travels base64-encoded,
        # so `secret not in text` passes even when the credential IS forwarded.
        # (Measured — that assertion alone did not fail when the strip was
        # removed, and the chain had received the full Proxy-Authorization.)
        assert "proxy-authorization" not in seen[0].lower(), (
            "leaked our proxy credential to the chain"
        )
        assert base64.b64encode(f"cswap:{secret}".encode()).decode() not in seen[0]

    def test_a_secret_written_under_a_running_daemon_takes_effect(self, certdir):
        """The gate must arm when the secret is WRITTEN, not on a later respawn.

        Measured by the cswap owner on linux, which is why this test exists:
            07:04:19  daemon 3123508 respawned (no secret yet)
            07:04:27  cswap pin -> proxy.secret written, .claude.json rewired
                      daemon pid after the pin: 3123508 — THE SAME ONE
            raw CONNECT, no credential, after the pin: 200 Connection Established
        `cswap pin` goes through ensure_proxy, which reuses a live daemon with
        a matching fingerprint. Caching the secret at construction meant the
        running daemon held None and kept serving unauthenticated, so the gate
        actually armed on the NEXT respawn — a fingerprint recycle, a deploy,
        an idle teardown — with nothing a human would connect to the 407s.

        The observable changed since: arming no longer 407s an unauthorized
        caller, it serves it unpinned. So this asserts what the daemon READS.
        The per-connection re-read is the property; the refusal was only ever
        how we could see it.
        """
        from cswap_pin.proxy import ensure_proxy_secret
        p = self._proxy(certdir)
        p.start()                      # constructed with NO secret on disk
        try:
            assert p._current_secret() is None
            secret = ensure_proxy_secret(certdir)   # `cswap pin`, same daemon
            assert p._current_secret() == secret, (
                "the running daemon ignored the new secret — it would only "
                "arm on some later respawn"
            )
            assert "407" not in self._connect(p.port, cred=secret)
        finally:
            p.stop()

    def test_a_respawn_does_not_arm_the_gate(self, certdir, monkeypatch):
        """The upgrade must not cut off sessions wired before it.

        A live session's HTTPS_PROXY is fixed at exec time, so one started
        before this change carries a URL with no credential. If a daemon
        respawn (a fingerprint recycle, a deploy) minted the secret, every such
        session would start getting 407 on its next request. Measured on linux
        before landing this: .claude.json wired "http://127.0.0.1:36301" with
        no userinfo and pid 142172 live on it.

        Only apply_pin — the path that also REWRITES the wiring — may mint it,
        so the gate and the URL that satisfies it arrive together.
        """
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import proxy_secret_path
        monkeypatch.setattr(pp, "PinProxy", lambda **kw: (_ for _ in ()).throw(
            _StopDaemon()))
        try:
            pp.daemon_main("1", "a@b.c", certdir)
        except _StopDaemon:
            pass
        except Exception:
            pass
        assert not proxy_secret_path(certdir).exists(), (
            "a respawn minted the credential — every live session would 407"
        )

    def test_apply_pin_mints_the_credential(self, certdir, monkeypatch):
        """...and the path that rewrites the wiring DOES arm it."""
        import cswap_pin.proxy as pp
        from cswap_pin.proxy import apply_pin, proxy_secret_path

        class _Sw:
            backup_dir = certdir.parent

        monkeypatch.setattr(pp, "save_pin", lambda *a, **k: None)
        monkeypatch.setattr(pp, "ensure_proxy", lambda sw: None)
        apply_pin(_Sw(), "a@b.c", "org")
        assert proxy_secret_path(certdir.parent / "pin-proxy").exists()


class _StopDaemon(Exception):
    """Cuts daemon_main off once it is past the point under test."""


class TestTogglingThePinMidSessionActuallyWorks:
    """THE requirement, both halves: no restart, and the pin APPLIES.

    A session's HTTPS_PROXY is fixed at exec, so anything the daemon keys off
    that variable is unchangeable for a running session. The gate did key off
    it, so turning the pin on 407'd every session that predated the credential
    (measured: 313 processes, including the one that ran `cswap pin`).

    Softening that to "serve them unpinned" fixes the 407 and fails the
    feature: `cswap pin 1` would leave the sessions the user is looking at on
    the active account. Both halves have to hold at once —

        claude.ai side (RC / artifacts) -> PINNED account
        CLI side       (inference)      -> ACTIVE account

    — for a session that never carried a credential, across the toggle.
    """

    def test_rc_swaps_and_inference_does_not_for_an_uncredentialed_session(
        self, certdir
    ):
        from cswap_pin.proxy import PinProxy, ensure_proxy_secret

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            # `cswap pin 1` mints the secret under a session that has none.
            ensure_proxy_secret(certdir)

            assert _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            ) == 200
            assert upstream.seen_auth == "Bearer PIN-TOKEN", (
                "the pin did not apply to a session that predates it — "
                "`cswap pin` silently did nothing for the sessions in front "
                "of the user"
            )

            assert _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/messages", bearer="disk-token",
            ) == 200
            assert upstream.seen_auth == "Bearer disk-token", (
                "inference was billed to the pinned account"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def test_clearing_returns_rc_to_the_active_account(self, certdir):
        from cswap_pin.proxy import PinProxy, ensure_proxy_secret, proxy_secret_path

        upstream = _FakeUpstream(certdir)
        token = {"v": "PIN-TOKEN"}
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: token["v"],
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
            ensure_proxy_secret(certdir)
            _request_through_proxy(proxy.port, certdir / "ca.pem",
                                   "/v1/code/sessions", bearer="disk-token")
            assert upstream.seen_auth == "Bearer PIN-TOKEN"

            # `cswap pin --clear`: the record goes, so the provider yields
            # nothing and the route falls back to the request's own bearer.
            proxy_secret_path(certdir).unlink()
            token["v"] = None
            assert _request_through_proxy(
                proxy.port, certdir / "ca.pem",
                "/v1/code/sessions", bearer="disk-token",
            ) == 200
            assert upstream.seen_auth == "Bearer disk-token", (
                "clearing the pin left RC on the pinned account"
            )
        finally:
            proxy.stop()
            upstream.stop()

    def test_no_407_in_either_direction(self, certdir):
        """The 407 itself, asserted directly: a raw CONNECT with no credential
        must succeed before AND after arming."""
        import base64
        import socket as _s

        from cswap_pin.proxy import PinProxy, ensure_proxy_secret, proxy_secret_path

        upstream = _FakeUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: "PIN-TOKEN",
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()

        def raw_connect():
            c = _s.create_connection(("127.0.0.1", proxy.port), timeout=5)
            c.sendall(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n"
                      b"Host: api.anthropic.com:443\r\n\r\n")
            c.settimeout(5)
            try:
                line = c.recv(128).decode("latin1", "replace").split("\r\n")[0]
            except OSError:
                line = "(closed)"
            c.close()
            return line

        try:
            assert "407" not in raw_connect()
            ensure_proxy_secret(certdir)
            assert "407" not in raw_connect(), "arming the pin 407'd a live session"
            proxy_secret_path(certdir).unlink()
            assert "407" not in raw_connect(), "clearing the pin 407'd a live session"
        finally:
            proxy.stop()
            upstream.stop()


class TestAMisroutedSwapCannotKillASession:
    """A 401/403/404 caused by OUR swap must never reach the client.

    Those three are terminal in Claude Code: SSETransport treats them as
    permanent (M7y = new Set([401,403,404])), sets state="closed", and never
    reconnects — so ONE misrouted request ends Remote Control for the life of
    the process. Measured: a /worker-swap experiment produced 26 such
    responses and severed the inbound channel of four sessions that were still
    running hours later with bridgeSessionId gone.

    That makes the route predicate a single point of PERMANENT failure, and no
    amount of care in it removes the risk — a route we have not seen yet can
    always be classified wrong. Retrying without the swap turns "wrong about
    this route" into "this request went out unpinned", which is the failure
    the module is already built to tolerate.
    """

    @pytest.fixture
    def certdir(self, tmp_path):
        from cswap_pin.proxy import ensure_ca

        d = tmp_path / "pin-proxy"
        d.mkdir(parents=True)
        ensure_ca(d, "api.anthropic.com")
        return d

    def test_a_403_on_a_swapped_route_is_retried_unswapped(self, certdir):
        """The upstream refuses the pinned bearer; the client must still get a
        real answer, carrying its OWN bearer."""
        from cswap_pin.proxy import PinProxy

        seen = []

        class Upstream(_FakeUpstream):
            def handle(self, auth):  # pragma: no cover - shape only
                seen.append(auth)

        upstream = _FakeUpstream(certdir, reject_bearer="PIN-TOKEN")
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
            assert status != 403, (
                "a swap the upstream refused reached the client — that is "
                "terminal in SSETransport and ends Remote Control permanently"
            )
            assert upstream.seen_auth == "Bearer disk-token", (
                "the retry did not fall back to the request's own bearer"
            )
        finally:
            proxy.stop()
            upstream.stop()
