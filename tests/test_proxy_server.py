"""Integration tests for the pin proxy's actual MITM + swap + relay path.

A fake upstream HTTPS server stands in for api.anthropic.com. The proxy MITMs
it, and we assert the Authorization it forwards: swapped on pinned routes,
original on everything else.
"""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import pathlib
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest

from cswap_pin.proxy import ensure_ca

from conftest import PIN_STAMP, run_cases


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


_CA_CACHE: list = []




def _make_certdir(tmp_path):
    """A cert dir with a CA already in it.

    COPIED from one session-wide CA rather than generated. `ensure_ca` mints
    two RSA-2048 keys (~70 ms) and this runs for most of the file, so
    generating per case was the single largest cost in the suite. Nothing
    here asserts on a key's VALUE — the tests need a CA that signs its leaf,
    which a copy is.
    """
    import shutil

    from cswap_pin.proxy import ensure_ca

    if not _CA_CACHE:
        # NOTHING FAILS FROM A LEAK HERE, which is why the old one survived:
        # `mkdtemp` is reached once per PROCESS and xdist gives every worker
        # its own, so a loop of runs piles them up and no test asserts on
        # /tmp. Counted 1,619 in one hour of repeated runs when it was found,
        # and 1,627 twelve days after the "fix".
        #
        # UNDER PYTEST'S OWN TREE, not a fresh mkdtemp. `atexit` was the old
        # cleanup and it does not run on the exits this suite takes: a daemon
        # teardown ends in `os._exit(0)`, which skips handlers by definition,
        # and a killed xdist worker runs nothing. Measured — the sweep landed
        # 2026-08-06 and the newest orphan was dated 2026-08-18, 1,627 of them.
        #
        # `tmp_path` is `<basetemp>/<run>/<case>`, so its parent is the run
        # directory, and pytest reaps all but the last three runs itself. Same
        # mechanism that already removes every `tmp_path`, on every exit path
        # including the ones that execute no Python.
        src = pathlib.Path(tmp_path).parent / "ca-cache"
        src.mkdir(parents=True, exist_ok=True)
        ensure_ca(src, "api.anthropic.com")
        _CA_CACHE.append(src)
    for f in ("ca.pem", "ca.key", "leaf.pem", "leaf.key"):
        shutil.copy2(_CA_CACHE[0] / f, tmp_path / f)
    return tmp_path


# Built PER CASE by `run_cases`, because the cases WRITE into it (`upstream.json`,
# `proxy.json`) and a shared one let a case read what the previous one recorded.
case_fixtures = {"certdir": _make_certdir}


def _mkdir(p):
    p.mkdir(parents=True, exist_ok=True)
    return p


@pytest.fixture
def certdir(tmp_path):
    return _make_certdir(tmp_path)


class TestPinProxyServer:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_pinned_route_gets_swapped_bearer(self, certdir):
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

    def case_inference_route_keeps_original_bearer(self, certdir):
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

    def case_upstream_signed_by_foreign_ca_via_node_extra(self, certdir, tmp_path, monkeypatch):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_first_event_arrives_before_upstream_finishes(self, certdir):
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


    def case_a_recycle_mid_stream_does_not_cut_the_reply(self, certdir):
        """THE MEASUREMENT THE WHOLE DRAIN EXISTS FOR, taken end to end.

        Everything else about the drain is asserted on counters. This drives a
        REAL reply that is mid-body, performs the REAL teardown a recycle
        performs, and then reads the rest of the body off the wire. If the
        drain cuts, `event: b` never arrives and the client sees EOF or a
        reset — which is exactly what three sessions got on 2026-08-18 as
        "API Error: Connection lost mid-response".

        WHY THIS IS NOT ALREADY COVERED by `case_a_planned_restart_under_a_
        holder_loses_nothing`: that one sends a CONNECT and reads a short
        answer, so it proves no request went UNANSWERED. It cannot see a long
        answer being TRUNCATED, because its requests finish faster than any
        drain. The user's failure was the truncation, and nothing measured it —
        which is why "the mechanism is fixed" was as far as anyone could
        honestly go before this case existed.

        The old code fails here for a reason worth stating precisely: it
        waited on `live_client_count()`, this connection holds that count at
        1, so the wait ran to its ceiling and `_close_open_connections()` then
        cut the very stream it had spent the ceiling waiting for.
        """
        from cswap_pin.proxy import PinProxy

        upstream = _StreamingUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
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
            tls.settimeout(10)
            got = b""
            while b"event: a" not in got:
                chunk = tls.recv(4096)
                assert chunk, "connection closed before the reply even started"
                got += chunk

            # THE RECYCLE, MID-BODY. `stop(drain=...)` is what both handover
            # paths and `_teardown` call. Run it in a thread because a correct
            # drain BLOCKS here — it is waiting for this very reply — and the
            # reply cannot finish until the origin is released below.
            # THE TIMING IS THE DISCRIMINATOR, and a first version got it
            # wrong: it drained for 8s and released the origin after 0.3s, so
            # the reply finished long before ANY ceiling expired and the case
            # passed on the old code too. A control that passes proves
            # nothing, and it nearly shipped as proof.
            #
            # Here the reply needs ~1.5s and the drain budget is 1.0s. The old
            # drain waits on `live_client_count()`, which this connection
            # holds at 1, so it burns the whole 1.0s and then cuts a reply
            # that had 0.5s left. The fixed drain sees a request in flight and
            # returns only once it is done.
            done = threading.Event()

            def _recycle():
                proxy.stop(drain=1.0)
                done.set()

            def _finish_late():
                time.sleep(1.5)
                upstream.release.set()

            threading.Thread(target=_finish_late, daemon=True).start()
            threading.Thread(target=_recycle, daemon=True).start()
            while b"event: b" not in got:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"event: b" in got, (
                "the reply was CUT mid-stream by a recycle — this is the exact "
                "failure the drain exists to prevent, and the one three "
                "sessions hit on 2026-08-18")
            assert done.wait(timeout=10), "the drain never returned"
            tls.close()
        finally:
            proxy.stop()
            upstream.stop()

    def case_the_drain_outlasts_the_reply_it_is_waiting_for(self, certdir):
        """WHAT ACTUALLY CUTS IS `os._exit`, and the drain is what delays it.

        Measured, after the first version of the case above passed against the
        OLD drain too and therefore proved nothing:

            before wrap: raw.fileno() = 3
            after  wrap: raw.fileno() = -1     <- ssl.wrap_socket DETACHES
                         tls.fileno() = 3

        `_open_conns` holds the RAW accepted socket, whose fileno is -1 by the
        time anything is streaming. So `_close_open_connections()` closes
        objects that no longer own the connection: on the MITM path it cuts
        NOTHING, and the "cut N in-flight request(s)" line counts sockets it
        cannot reach. The reply dies when the process exits and the kernel
        closes the real fds.

        That makes the drain's only job DELAYING THE EXIT until the reply is
        done — and the thing to assert is therefore how long `await_inflight`
        blocks, not what it closes. A drain that returns while a reply is in
        flight is a reply cut, one `os._exit()` later.

        This is what `_HELD_DRAIN_SECONDS = 2.0` did on 2026-08-18:
            03:42:04 stopping (refcount)  ->  03:42:06 drained
        two seconds on the nose, with a reply streaming, then exit.
        """
        from cswap_pin.proxy import PinProxy

        upstream = _StreamingUpstream(certdir)
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", upstream.port),
        )
        proxy.start()
        try:
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
            tls.settimeout(20)
            got = b""
            while b"event: a" not in got:
                chunk = tls.recv(4096)
                assert chunk, "closed before the reply started"
                got += chunk

            assert proxy.inflight_requests() >= 1, (
                "precondition: the drain must have something to wait for, or "
                "this case measures nothing — which is how its predecessor "
                "passed against the old code")

            # The origin finishes at +1.5s. A correct drain must still be
            # blocking then, because that is the whole reason it exists.
            threading.Thread(
                target=lambda: (time.sleep(1.5), upstream.release.set()),
                daemon=True).start()

            # THE HANDOVER CEILING, not a literal — and driving the real one
            # is what answers the only objection to raising it. Ten minutes
            # sounds like ten minutes of teardown; it is not, because the loop
            # exits on zero owed. This waits for a reply that lands at +1.5s
            # under a 600s budget and must return there, not at the ceiling.
            from cswap_pin.proxy import _HANDOVER_DRAIN_SECONDS

            t0 = time.monotonic()
            proxy.await_inflight(_HANDOVER_DRAIN_SECONDS)
            waited = time.monotonic() - t0

            assert waited >= 1.4, (
                f"the drain returned after {waited:.2f}s while the reply was "
                f"still streaming. os._exit() lands next, and the reply dies "
                f"there — this is the 2.0s _HELD_DRAIN_SECONDS cut, reproduced")
            assert waited < 25, (
                f"waited {waited:.1f}s after the reply finished — the drain is "
                "counting something that never reaches zero again, so the "
                "600s handover ceiling would be paid in full on every recycle")
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

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

    def case_a_chunked_response_stays_framed_as_chunked(self, certdir):
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

    def case_204_completes_without_waiting_for_a_close(self, certdir):
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

    def case_304_completes_without_waiting_for_a_close(self, certdir):
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

    def case_connection_close_is_relayed_not_swallowed(self, certdir):
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

    def case_a_keep_alive_response_is_not_marked_close(self, certdir):
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

    def case_an_interim_1xx_is_not_delivered_as_the_final_response(self, certdir):
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

    def case_205_reset_content_carries_no_body(self, certdir):
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

    def case_a_head_response_does_not_wait_for_its_absent_body(self, certdir):
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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_chunked_body_is_decoded_and_reframed(self, certdir):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_connect_carries_proxy_authorization(self, certdir):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_relays_through_untrusted_loopback_mitm(self, certdir, tmp_path):
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

    def case_a_dead_loopback_chain_does_not_disarm_verification(
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_rebinds_the_port_carried_across_the_state_deletion(self, certdir):
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

    def case_recycling_a_stale_daemon_carries_its_port(self, tmp_path, monkeypatch):
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

    def case_a_reused_pid_is_not_killed(self, tmp_path, monkeypatch):
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

    def case_a_superseded_daemon_leaves_the_successors_state_alone(
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

    def case_a_daemon_still_owning_its_state_clears_it(self, tmp_path):
        """The normal teardown must still leave nothing behind — a stale
        record reads as live and the next launch reuses a dead port."""
        import os as _os
        from cswap_pin import proxy as pin_proxy

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pin_proxy.write_daemon_state(certdir, 51000, _os.getpid(), "fp")

        assert pin_proxy._release_daemon_state(certdir) is False
        assert pin_proxy.read_daemon_state(certdir) is None

    def case_spawn_carries_the_port_forward(self, tmp_path, monkeypatch):
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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_upstream_socket_has_no_read_deadline(self, certdir):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_follows_a_chain_that_appears_after_the_daemon_started(
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

    def case_a_launch_that_sees_no_proxy_keeps_the_recorded_one(self, certdir):
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

    def case_the_kept_hint_keeps_its_CREDENTIAL_and_scheme(self, certdir):
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

    def case_the_recorded_upstream_is_returned_raw(self, certdir):
        """_recorded_upstream feeds back INTO the hint, so reconstructing the
        URL there launders the credential on the other side of the same round
        trip."""
        from cswap_pin.proxy import _recorded_upstream, write_upstream_hint

        url = "https://bob:s3cr%40t@corp.proxy:8443"
        write_upstream_hint(certdir, url)
        assert _recorded_upstream(certdir) == url

    def case_falls_back_to_direct_when_the_recorded_chain_is_gone(
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

    def case_the_record_grows_and_refuses_a_hop_that_names_the_pin(
        self, certdir
    ):
        """WHAT THE DAEMON LEARNS ABOUT THE HOP BEHIND ITS OWN, and what it
        must refuse to learn.

        Two halves of one mechanism, so one case rather than two: the same
        `/health` stand-in answers both, and splitting them duplicated the
        server and the helper verbatim.

        1. THE RECORD MUST BE ABLE TO GROW AFTER THE LAUNCH THAT MADE IT.
        D1-D4 prove the walk USES a recorded next hop, and
        `case_the_next_hop_is_probed_from_the_cache_proxys_health` proves a
        LAUNCH records one. One was missing anyway: `_probe_next_hop` ran at
        hint-writing time and nowhere else, and `--ensure` — what an rc hook
        calls before every `claude` — routes to `heal`, which never re-stamps
        the hint. So the only chance to learn the outer hop was a launch that
        happened while the inner one was answering. Miss it once and the
        chain is single-hop for good. Measured, and it was the steady state:

            upstream.json {"proxy": "http://127.0.0.1:9901", ...} no "next",
            written 2026-08-04 01:32, unchanged a day later, while 9901's
            /health answered http://127.0.0.1:8118 the whole time

        When 9901 died the walk had one hop and went DIRECT — the corporate
        TLS inspector here, which 403s. The answer was one request away.

        2. A HOP THAT NAMES US IS A LOOP, NOT A NEXT HOP. `_probe_next_hop`
        guards a hop naming ITSELF, not one naming the PIN. That is what a
        peer session measured and fixed on its own side (dba90bd): a cache
        proxy launched from a shell that already exported the chain adopted
        the pin's port as its upstream, so the path became 9901 -> 36301 ->
        9901 and never reached privoxy. Measured here before the guard:

            hop reported: http://127.0.0.1:36301, own port 36301
            LOOP RECORDED: the pin would dial itself

        The peer's fix is not enough, because the RECORD OUTLIVES THE PROCESS:
        a chain learned during the polluted window keeps pointing here after
        the hop is repaired, and every version already on disk wrote records
        without the guard. So both ends — refuse to record one, and drop one
        already recorded before dialling.

        CONTROLS, one per claim: a hop reporting no upstream must record
        nothing (or "learned it" passes for code that records noise), a hop
        naming a different port must still be recorded (or "refuses a loop"
        passes for code that learns nothing), and dropping the loop must not
        drop the real hop with it.
        """
        import http.server
        import threading

        from cswap_pin.proxy import PinProxy, _read_upstream, write_upstream_hint

        class _Health(http.server.BaseHTTPRequestHandler):
            """A hop answering /health with whatever `answer` holds."""

            answer: dict = {}

            def do_GET(self):
                body = json.dumps(self.answer).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        def _learned(answer, my_port=0):
            """What the daemon records as `next` after asking a hop once."""
            _Health.answer = answer
            srv = http.server.HTTPServer(("127.0.0.1", 0), _Health)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            write_upstream_hint(
                certdir, f"http://127.0.0.1:{srv.server_address[1]}", next_hop="",
            )
            try:
                proxy = PinProxy(
                    certdir=certdir,
                    pin_token_provider=lambda: None,
                    upstream=("127.0.0.1", 1),
                    rediscover_chain=True,
                )
                proxy.port = my_port
                proxy.learn_next_hop()
                return _read_upstream(certdir, "next")
            finally:
                srv.shutdown()

        # CONTROL: a hop that names no upstream must leave the record alone.
        assert not _learned({"status": "ok"}), (
            "CONTROL FAILED: a hop reporting no upstream still got recorded"
        )
        # ...and a real one must be learned, unprompted.
        assert _learned({"https_proxy": "http://127.0.0.1:8118"}, 36301) == (
            "http://127.0.0.1:8118"
        ), (
            "a healthy hop was never asked what is behind it, so the chain "
            "stays single-hop and falls to DIRECT when that hop dies"
        )
        # A REFUSAL WRITES NOTHING, so a re-read returns whatever the line
        # above recorded. Assert on what is NOT written, not on an empty read.
        assert _learned(
            {"https_proxy": "http://127.0.0.1:36301"}, 36301
        ) != "http://127.0.0.1:36301", (
            "the pin recorded ITSELF as its own next hop — every request "
            "would dial back into this daemon (9901 -> 36301 -> 9901)"
        )

        # AND THE WALK REFUSES ONE ALREADY ON DISK, written by an older
        # version or during the polluted window.
        write_upstream_hint(
            certdir, "http://127.0.0.1:9901", next_hop="http://127.0.0.1:36301",
        )
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        proxy.port = 36301
        dialled = [c.address for c in proxy._chain_candidates()]
        assert ("127.0.0.1", 36301) not in dialled, (
            f"the walk would dial the pin's own port: {dialled}"
        )
        assert ("127.0.0.1", 9901) in dialled, (
            f"CONTROL FAILED: dropping the loop also dropped the real hop: "
            f"{dialled}"
        )

    def case_a_host_with_no_chain_pays_nothing_for_the_heal_grace(self, certdir):
        """The grace is for a hop that is RESTARTING, not for having no hop.

        `_CHAIN_HEAL_GRACE_S` waits out a cache proxy coming back under a new
        pid (~1s, measured). A host with no chain configured has nothing to
        wait for — `_walk_chain_once` returns None instantly on an empty
        candidate list — and the loop still slept out 13 polls before the
        direct dial that was always the answer.

        MEASURED: 2.60s per `_connect_upstream`, which is per new MITM
        connection AND per bridge-sweep API call, on exactly the machines
        (no corporate proxy, no cache proxy) where direct IS the normal path.

        The constant's own comment claimed the opposite — "a host with no
        chain at all never enters this loop, because an empty candidate list
        falls straight through" — so the code and the comment disagreed and
        the comment was the one being believed.
        """
        import time

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import PinProxy

        # THE SHIPPED GRACE, not the shrunken one conftest installs for speed.
        # With the test value (0.3s) the stall is 0.31s and reads as noise;
        # the defect is only visible at the value users actually run.
        keep = (pin_proxy._CHAIN_HEAL_GRACE_S, pin_proxy._CHAIN_HEAL_POLL_S)
        pin_proxy._CHAIN_HEAL_GRACE_S = 2.5
        pin_proxy._CHAIN_HEAL_POLL_S = 0.2

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        assert proxy._chain_candidates() == [], "premise: this host has no chain"

        started = time.monotonic()
        try:
            proxy._connect_upstream()
        except OSError:
            pass  # nothing listens on port 1; the TIMING is what is asserted
        finally:
            pin_proxy._CHAIN_HEAL_GRACE_S, pin_proxy._CHAIN_HEAL_POLL_S = keep
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, (
            f"a chainless host paid {elapsed:.2f}s of heal grace per upstream "
            f"dial — there was never a hop to wait for"
        )

    def case_a_hop_that_comes_back_is_waited_for_not_bypassed(self, certdir):
        """A hop RESTARTING is not a hop that is gone.

        Measured on the cache proxy's deployed build, hammered across a
        `kill -9` of its holder: refused=32, accepted-then-silent=0, served=159
        — it returns in ~1s under a new pid and REFUSES throughout. A refused
        dial costs the walk nothing, so waiting is nearly free, while the
        direct fallback on host-a is the corporate TLS inspector.
        """
        from cswap_pin.proxy import PinProxy

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        sentinel = object()
        attempts = []

        def _walk():
            attempts.append(1)
            return sentinel if len(attempts) >= 3 else None

        proxy._walk_chain_once = _walk
        # A CANDIDATE MUST EXIST for the grace to apply at all: an empty list
        # means "no chain on this host" and falls straight through, which is
        # the sibling case above.
        proxy._chain_candidates = lambda: [object()]
        assert proxy._connect_upstream() is sentinel, (
            "the relay bypassed a hop that came back inside the grace period"
        )
        assert len(attempts) == 3, f"walked {len(attempts)} times, expected 3"

    def case_a_socket_the_selector_cannot_drive_still_carries_bytes(self):
        """The fallback for an undrivable socket must not be the selector.

        `_pump_detached` asks `_PumpLoop.can_take` and falls back to `_pump`
        for a socket the selector cannot drive — an `https://` chain hop
        (`_TLSInTLS`), which has no `setblocking`. But `_pump` was rewritten
        to be `_PUMP.add` plus an Event, so the fallback re-entered the very
        call that cannot take it and raised the same AttributeError. Measured
        on the shipped code:

            can_take: False
            fallback RAISED: AttributeError ... has no attribute 'setblocking'

        AttributeError is not in `_handle_one_request`'s except tuple, so it
        escapes and kills the connection: behind a TLS egress proxy that is
        Remote Control's inbound WebSocket dying on every launch — the exact
        failure `can_take` was added to prevent.

        THE CONTROL is the same shuttle over a plain socketpair, which the
        selector CAN take. Without it a fallback that silently carried
        nothing would read as a pass.
        """
        import socket
        import threading

        from cswap_pin.proxy import _PumpLoop, _pump_detached

        class _NoSetblocking:
            """`_TLSInTLS`'s surface: no `setblocking`, hence undrivable."""

            def __init__(self, sock):
                self._sock = sock

            def sendall(self, data):
                return self._sock.sendall(data)

            def recv(self, n=65536):
                return self._sock.recv(n)

            def fileno(self):
                return self._sock.fileno()

            def close(self):
                return self._sock.close()

        def _carries(wrap):
            """Bytes both ways through one tunnel. Returns what arrived."""
            feed, a = socket.socketpair()
            b, sink = socket.socketpair()
            closed = threading.Event()
            threading.Thread(
                target=_pump_detached, args=(wrap(a), wrap(b), closed.set),
                daemon=True,
            ).start()
            try:
                feed.sendall(b"ping")
                sink.settimeout(3)
                try:
                    return sink.recv(16)
                except (socket.timeout, OSError):
                    return b""
            finally:
                for s in (feed, a, b, sink):
                    try:
                        s.close()
                    except OSError:
                        pass

        assert _PumpLoop.can_take(_NoSetblocking(socket.socket())) is False, (
            "the shim is drivable after all — this case proves nothing"
        )
        assert _carries(lambda s: s) == b"ping", (
            "CONTROL FAILED: a plain socketpair carried nothing, so the "
            "undrivable result below says nothing about the fallback"
        )
        assert _carries(_NoSetblocking) == b"ping", (
            "a socket the selector cannot drive carried nothing — the "
            "fallback routed back into the selector that had just refused it"
        )

    def case_one_stalled_peer_does_not_stop_every_other_tunnel(self, certdir):
        """The shared pump must not re-couple what it decoupled.

        Removing the thread-per-connection put every tunnel on ONE selector
        thread. If that thread can block inside a write while holding the lock
        that `add` also takes, a single peer that stops reading stalls every
        other tunnel and every new one — the same "one bad connection stops
        everything" property, moved from thread count to a global mutex.

        A peer that stops reading is not hypothetical: it is a wedged hop, a
        stalled upstream, or a client that stopped draining, which is the
        exact condition the outage this class was written for produced.
        """
        import socket
        import threading
        import time

        from cswap_pin.proxy import _PumpLoop

        pump = _PumpLoop()

        def _pair():
            a, b = socket.socketpair()
            return a, b

        # TUNNEL 1: its far end never reads, so the pump's write will block
        # once the socket buffer fills.
        feed_1, in_1 = _pair()
        out_1, stuck_1 = _pair()
        pump.add(in_1, out_1)
        # Fill until OUR OWN send would block: by then the pump is inside its
        # write to a peer that is not reading, which is the condition. A
        # timeout, not sendall, or this test wedges on the same buffer.
        feed_1.setblocking(False)
        try:
            for _ in range(256):
                feed_1.send(b"x" * 65536)
        except (BlockingIOError, OSError):
            pass
        time.sleep(0.3)

        # TUNNEL 2: perfectly healthy, added AFTER the stall exists.
        started = time.monotonic()
        feed_2, in_2 = _pair()
        out_2, sink_2 = _pair()
        pump.add(in_2, out_2)                  # must not block on tunnel 1
        add_took = time.monotonic() - started

        feed_2.sendall(b"ping")
        sink_2.settimeout(3)
        try:
            got = sink_2.recv(16)
        except socket.timeout:
            got = b""

        for s in (feed_1, in_1, out_1, stuck_1, feed_2, in_2, out_2, sink_2):
            try:
                s.close()
            except OSError:
                pass

        assert add_took < 1.0, (
            f"registering a new tunnel waited {add_took:.1f}s on an unrelated "
            f"stalled one — the lock is held across the write"
        )
        assert got == b"ping", (
            "a healthy tunnel carried nothing while another peer stopped "
            "reading — one stalled connection stops them all"
        )

    def case_connections_do_not_become_threads(self, tmp_path, monkeypatch):
        """CONNECTIONS MUST NOT BECOME THREADS.

        MEASURED OUTAGE, host-a: the cache hop died and the pin served 27,491
        threads / 44,121 FDs in 40 minutes; load on a 48-core box reached
        16,483 and it was rescued by hand. The mechanism, measured here on the
        daemon before this changed, hop wedged and counted from OUTSIDE the
        process:

            idle          4 threads
             50 conns ->  54 threads
            150 conns -> 154 threads
            300 conns -> 304 threads

        Exactly 1:1, so the retry count IS the thread count. A ceiling was
        tried and removed: it turns the 257th retry into a refused connection
        while the coupling stays.

        COUNTED FROM ANOTHER PROCESS, deliberately. Every in-process count is
        wrong here — `threading.active_count()` also counts this test's own
        opener threads, which are the same order of magnitude as the thing
        being measured, and it read "grew=0" while every connection had its
        own server thread.

        WHAT THIS TEST DOES NOT PROVE, stated because a green test that cannot
        fail is worse than no test. Reverting the detach in `_blind_tunnel`
        leaves this case PASSING, while the same control run through
        `tools/thread_probe.py` reports 305 threads against 5. The probe is the
        instrument; this is a smoke check that the daemon still serves 300
        concurrent tunnels without the count exploding. Why the two disagree is
        open — do not read a pass here as evidence the coupling is gone.
        """
        import os
        import socket
        import threading

        from cswap_pin import proxy as pin_proxy
        from cswap_pin.proxy import ensure_ca

        ensure_ca(tmp_path, "api.anthropic.com")
        # BOUND THE SPAWN WAIT. The default polls 10s for the child to
        # publish, and a holder that appears after this case has reaped lives
        # forever — measured, 2 orphans a run from exactly that window.
        monkeypatch.setattr(pin_proxy, "_SPAWN_WAIT_S", 1.5)
        # TRACK THE CHILD AT BIRTH. Reaping by certdir afterwards races the
        # spawn — `_spawn_daemon` returns when the state file appears, but the
        # HOLDER it started keeps going, and one born a moment later was in no
        # sweep. Measured: 2 orphans a run surviving a reap that found nothing.
        import subprocess as _sp

        started = []
        _real_popen = _sp.Popen

        def _tracked(*a, **k):
            proc = _real_popen(*a, **k)
            started.append(proc)
            return proc

        _sp.Popen = _tracked
        try:
            port = pin_proxy._spawn_daemon("1", "a@example.com", tmp_path)
        finally:
            _sp.Popen = _real_popen
        assert port, "the daemon did not come up"
        st = pin_proxy.read_daemon_state(tmp_path)
        pid = int(st["pid"])

        def _threads():
            try:
                with open(f"/proc/{pid}/status") as fh:
                    for line in fh:
                        if line.startswith("Threads:"):
                            return int(line.split()[1])
            except OSError:
                pass
            return -1

        if _threads() < 0:
            return  # not Linux: /proc is the only portable answer here

        # THE FAR END OF THE TUNNEL, local and idle. The outage's connections
        # were OPEN TUNNELS, not half-finished handshakes: pointing them at
        # `api.anthropic.com` instead measures `wrap_socket` waiting for a TLS
        # ClientHello this test never sends, which is a different thread and a
        # different bug.
        far = socket.socket()
        far.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        far.bind(("127.0.0.1", 0))
        far.listen(512)
        far_port = far.getsockname()[1]

        def _accept_forever():
            while True:
                try:
                    far.accept()
                except OSError:
                    return

        threading.Thread(target=_accept_forever, daemon=True).start()

        held, lock = [], threading.Lock()

        def _hold():
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=5)
                s.sendall(
                    f"CONNECT 127.0.0.1:{far_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{far_port}\r\n\r\n".encode()
                )
                if b"200" not in s.recv(200):
                    return
                with lock:
                    held.append(s)
                s.recv(65536)   # park on an OPEN tunnel
            except OSError:
                pass

        idle = _threads()
        try:
            deadline = time.time() + 20
            while time.time() < deadline and len(held) < 300:
                want = 300 - len(held)
                for t in [threading.Thread(target=_hold, daemon=True)
                          for _ in range(want)]:
                    t.start()
                for _ in range(40):
                    if len(held) >= 300:
                        break
                    time.sleep(0.05)
            # SETTLE FIRST. A connection mid-setup still has its thread —
            # it is handed to the shared pump only once the tunnel is open —
            # so counting the instant the last one lands measures the ramp,
            # not the steady state this is about. Measured: 26 threads while
            # connecting, 5 a moment later, for the same 300 tunnels.
            time.sleep(1)
            live, grew = len(held), _threads() - idle
            assert live >= 250, f"only {live} connections landed; not loaded"
            assert grew < 20, (
                f"{live} connections cost {grew} threads (idle was {idle}) — "
                f"connections still become threads, which is what took the box "
                f"down"
            )
        finally:
            for s in held:
                try:
                    s.close()
                except OSError:
                    pass
            # PARENTS FIRST. `_spawn_daemon` starts a HOLDER, whose job is
            # to replace a daemon that dies — so killing `pid` alone gets it
            # replaced, and this case leaked 38 processes in one suite run.
            for proc in started:          # PARENTS FIRST: these are holders
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
            far.close()

    def case_health_reports_the_chain_the_relay_would_use(self, certdir):
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

    def case_ignores_a_hint_pointing_at_our_own_port(self, tmp_path):
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
        # BACKLOG, NOT 4. A full accept queue makes `connect()` to a LISTENING
        # loopback socket time out rather than refuse, and the daemon then logs
        # `hop unusable — dial failed: TimeoutError`, never reaches accept, and
        # the case's premise (`seen`) is empty. That is what turned CI red on
        # macos-latest for 0.1.94 while 33 consecutive Linux runs were green:
        #     hop 127.0.0.1:49793 unusable — dial failed: TimeoutError('timed out')
        # Loopback refusal is instant on Linux, so the queue never built there.
        # This class drives 23 cases through the same helper on a shared
        # runner; 128 costs nothing and removes the queue as a variable.
        srv.listen(128)
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

    def case_the_log_names_the_hop_that_carried_and_stays_quiet_after(
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

    def case_a_host_with_no_proxy_chain_is_not_reported_as_degraded(
        self, certdir
    ):
        """"Nothing is configured" is not "nothing is reachable".

        On a host with no corporate proxy — and no cache proxy either — there
        is no chain to walk, so a direct dial is the ONLY thing a pin can do
        and it is the NORMAL path, not a downgrade. The line said otherwise:
        the same "no chain hop reachable, bypassing the configured proxy
        chain" that a genuinely dead hop produces. On such a host that
        sentence is the steady state and it is false twice over — nothing was
        unreachable, and there is no configured chain to bypass. Anyone
        reading it alone calls a healthy machine degraded.

        The two must be distinguishable in the log, because they need
        opposite responses: one is "go look at your egress proxy", the other
        is "this is how this machine is".
        """
        import contextlib
        import io

        from cswap_pin import proxy as pin_proxy

        # A reachable stand-in for the origin, so the direct dial COMPLETES
        # and the line under test is actually emitted.
        sink = socket.socket()
        sink.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sink.bind(("127.0.0.1", 0))
        sink.listen(4)
        def _accept_until_closed():
            """Accept and CLOSE, and stop when the listener goes.

            The comprehension this replaces held every accepted socket for the
            life of the session and raised out of the thread at teardown. A
            leaked descriptor per connection is affordable on a laptop and is
            not on a CI runner running four workers against a much smaller
            limit — and the way that failure arrives is a dead worker and an
            INTERNALERROR that names no test.
            """
            while True:
                try:
                    conn, _ = sink.accept()
                except OSError:
                    return  # the listener closed at test end; that is the exit
                conn.close()

        threading.Thread(target=_accept_until_closed, daemon=True).start()

        def _egress_line(candidates):
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")
            relay._chain_candidates = lambda: candidates
            relay._upstream = ("127.0.0.1", sink.getsockname()[1])
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            lines = [l for l in buf.getvalue().splitlines() if "egress" in l]
            return lines[-1] if lines else ""

        try:
            dead = socket.socket()
            dead.bind(("127.0.0.1", 0))
            dead_port = dead.getsockname()[1]
            dead.close()

            unconfigured = _egress_line([])
            degraded = _egress_line(
                [pin_proxy._as_chain(("127.0.0.1", dead_port))]
            )

            assert unconfigured, "a direct dial said nothing at all"
            assert degraded, "a dead hop said nothing at all"
            assert unconfigured != degraded, (
                f"a host with NO chain configured and a host whose chain is "
                f"DEAD produced the same line — the first is normal and the "
                f"second needs attention: {unconfigured!r}"
            )
            # And specifically: the normal case must not claim something was
            # unreachable, or that a configured chain was bypassed.
            assert "reachable" not in unconfigured, unconfigured
            assert "bypass" not in unconfigured, unconfigured
        finally:
            sink.close()

    def case_the_log_separates_a_refused_hop_from_one_that_answered_wrong(
        self, certdir
    ):
        """Two faults, one fall-through — and they belong to different owners.

        A hop whose PORT is dead and a hop that accepts and then will not
        tunnel are the same `continue` in the walk, and the log said the same
        nothing about both. They are opposite findings for whoever runs that
        hop: the first says its listener was down, the second says its
        listener was up and its logic was not. A supervisor that holds the
        port across restarts is a claim about exactly the first, so a log that
        cannot tell them apart cannot confirm or refute it.
        """
        import contextlib
        import io

        from cswap_pin import proxy as pin_proxy

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()

        # Up, and answers CONNECT with a refusal — a proxy mid-restart whose
        # listener is live before its proxy logic is.
        rude = socket.socket()
        rude.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rude.bind(("127.0.0.1", 0))
        rude.listen(4)
        rude_port = rude.getsockname()[1]

        def _refuse():
            while True:
                try:
                    conn, _ = rude.accept()
                except OSError:
                    return
                try:
                    conn.recv(8192)
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    conn.close()
                except OSError:
                    pass

        threading.Thread(target=_refuse, daemon=True).start()
        try:
            relay = pin_proxy.PinProxy(certdir, lambda: "tok")

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
            refused_lines = [
                l for l in buf.getvalue().splitlines()
                if f"{dead_port} unusable" in l
            ]
            assert refused_lines, (
                f"a hop whose port is dead was skipped silently: "
                f"{buf.getvalue()!r}")
            assert "dial failed" in refused_lines[0], refused_lines

            relay._chain_candidates = lambda: [
                pin_proxy._as_chain(("127.0.0.1", rude_port))
            ]
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                try:
                    sock, _ = relay._connect_upstream()
                    sock.close()
                except OSError:
                    pass
            wrong_lines = [
                l for l in buf.getvalue().splitlines()
                if f"{rude_port} unusable" in l
            ]
            assert wrong_lines, (
                f"a hop that answered and refused to tunnel was skipped "
                f"silently: {buf.getvalue()!r}")
            assert "dial failed" not in wrong_lines[0], (
                "a hop that ANSWERED was reported as a dead port — the two "
                "faults are indistinguishable again")
            assert "502" in wrong_lines[0], wrong_lines
        finally:
            rude.close()

    def case_D1_a_chain_that_refuses_the_dial_uses_the_next_hop(
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

    def case_D2_a_chain_that_refuses_the_CONNECT_uses_the_next_hop(
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
            # THE PREMISE IS SAMPLED, AND A SAMPLE LOSES A RACE. `seen` is
            # appended by the stub's accept thread, which runs on its own
            # schedule — the request can return before that thread is
            # scheduled, and on a loaded runner it does. Poll briefly instead
            # of reading it once: a hop that really was never dialled stays
            # empty for the whole window and still fails, loudly.
            deadline = time.monotonic() + 3.0
            while not seen and time.monotonic() < deadline:
                time.sleep(0.02)
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

    def case_a_plain_user_with_only_HTTPS_PROXY_still_chains_through_it(
        self, certdir, tmp_path, monkeypatch
    ):
        """NO cc-wrapper, NO launcher, NO upstream.json. Just a corp proxy.

        The composition every other test assumes is the one a plain
        `pip install` user never gets: something else wrote the chain record
        first. Here nothing has, and the only evidence a corp proxy exists is
        `HTTPS_PROXY` in the shell that runs `cswap pin`.

        If the pin ignored that, a user behind a corporate proxy would get
        pin -> DIRECT: a dead session where the firewall is closed, and a
        silent skip of inspection where it is open. Neither is acceptable for
        an optional feature, and neither is visible from outside.

        THE HOP MUST SEE THE TRAFFIC, not merely appear in a candidate list.
        A peer measured its own version of this with a fake proxy that
        ANSWERED the CONNECT instead of relaying it: the leg died before
        anything was logged and the fixture reported a bypass that was not
        happening. `_LoopbackConnectProxy` relays, and the assertion is on
        what it SAW.
        """
        from cswap_pin.proxy import PinProxy, _ambient_chain, write_upstream_hint

        foreign = tmp_path / "foreign"
        foreign.mkdir(exist_ok=True)
        ensure_ca(foreign, "api.anthropic.com")
        upstream = _FakeUpstream(foreign)
        corp = _LoopbackConnectProxy(("127.0.0.1", upstream.port))

        proxy = None
        try:
            # THE PLAIN SHELL, and nothing else. No upstream.json exists yet.
            assert not (certdir / "upstream.json").exists(), (
                "fixture invalid: something already recorded a chain, which is "
                "the very thing a plain user does not have"
            )
            env = {"HTTPS_PROXY": f"http://127.0.0.1:{corp.port}"}
            hop, next_hop = _ambient_chain(env=env, certdir=certdir)
            assert hop is not None, (
                "the pin saw a corp proxy in the shell and recorded nothing — "
                "every pinned request would bypass it"
            )
            # Exactly what `ensure_proxy` does with that answer.
            write_upstream_hint(certdir, hop, None, next_hop=next_hop)

            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                upstream=("127.0.0.1", upstream.port),
                rediscover_chain=True,
            )
            proxy.start()
            assert proxy.port != 36301, proxy.port

            status = _request_through_proxy(
                proxy.port, certdir / "ca.pem", "/v1/messages", bearer="t",
            )
            assert corp.connects == 1, (
                "a REAL request through the pin never reached the corp proxy "
                "the user's shell named — on a host behind a firewall that is "
                "a dead session, and where it is open it silently skips "
                "inspection"
            )
            assert status == 200, "the request did not complete through it"
        finally:
            if proxy:
                proxy.stop()
            upstream.stop()
            corp.stop()

    def case_D3_the_blind_tunnel_uses_the_next_hop_too(
        self, certdir, tmp_path, monkeypatch
    ):
        """THE REMOTE CONTROL PATH, and it walked no chain at all.

        D1 and D2 cover the MITM path (api.anthropic.com). Everything else —
        including the WebSocket Remote Control RECEIVES on, whose host comes
        from the /bridge response and is NOT api.anthropic.com — takes
        `_blind_tunnel`, which read ONE hop and fell straight to a direct
        dial. So the fall-through those two tests pin did not exist on the
        path where a missed hop is least visible: Claude Code keeps
        heartbeating and posting through the MITM at 200 while nothing sent
        from claude.ai arrives.

        A direct dial is not "no proxy" here. On a host whose direct route is
        a TLS-inspecting corporate proxy it is the inspector, and on a host
        with no direct route out it is a dead connection.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        dead = self._dead_port()
        # The hop BEHIND the dead one. A blind tunnel is opaque by
        # definition, so the discriminator is whether this hop is DIALLED at
        # all — not what comes back through it.
        inner = _LoopbackConnectProxy(("127.0.0.1", 1))
        proxy = None
        try:
            write_upstream_hint(
                certdir,
                f"http://127.0.0.1:{dead}",
                next_hop=f"http://127.0.0.1:{inner.port}",
            )
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                rediscover_chain=True,
            )
            proxy.start()
            assert proxy.port != 36301, proxy.port

            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                # A host that is NOT api.anthropic.com: the blind-tunnel path.
                c.sendall(
                    b"CONNECT rc-ingress.example.com:443 HTTP/1.1\r\n"
                    b"Host: rc-ingress.example.com:443\r\n\r\n"
                )
                # WAIT FOR THE HOP, NOT FOR A RESPONSE. The inner hop points at
                # port 1, so nothing ever answers and a recv here simply burns
                # its own timeout — 3.2 s of it. What the test asserts is that
                # the hop was DIALLED, so wait for exactly that.
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and inner.connects == 0:
                    time.sleep(0.01)
            finally:
                c.close()

            assert inner.connects == 1, (
                "the blind tunnel fell through a dead hop to a DIRECT dial "
                "instead of to the hop behind it — on a host with an "
                "inspecting egress proxy that IS the inspector, and Remote "
                "Control receives on this path"
            )
        finally:
            if proxy:
                proxy.stop()
            inner.stop()

    def case_D4_the_plain_relay_uses_the_next_hop_too(
        self, certdir, tmp_path, monkeypatch
    ):
        """The absolute-form path, the third one, with the same single hop.

        `GET http://host/x` from the auto-updater and telemetry takes this
        branch. It read one hop and, when that hop was dead, dialled the
        ORIGIN direct — the same wrong fall-through D1 fixed for the MITM path
        and D3 for the blind tunnel. On a host with no direct route out that
        is not a downgrade, it is a failure.
        """
        from cswap_pin.proxy import PinProxy, ensure_proxy_secret, write_upstream_hint

        secret = ensure_proxy_secret(certdir)
        dead = self._dead_port()
        inner = _LoopbackConnectProxy(("127.0.0.1", 1))
        proxy = None
        try:
            write_upstream_hint(
                certdir,
                f"http://127.0.0.1:{dead}",
                next_hop=f"http://127.0.0.1:{inner.port}",
            )
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                rediscover_chain=True,
            )
            proxy.start()
            assert proxy.port != 36301, proxy.port

            import base64

            cred = base64.b64encode(f"cswap:{secret}".encode()).decode()
            c = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
            try:
                c.sendall(
                    b"GET http://example.com/x HTTP/1.1\r\n"
                    b"Host: example.com\r\n"
                    + f"Proxy-Authorization: Basic {cred}\r\n\r\n".encode()
                )
                c.settimeout(10)
                try:
                    c.recv(256)
                except OSError:
                    pass
            finally:
                c.close()

            assert inner.connects == 1, (
                "the plain relay fell through a dead hop to a DIRECT dial at "
                "the ORIGIN instead of to the hop behind it — the auto-updater "
                "and telemetry take this path"
            )
        finally:
            if proxy:
                proxy.stop()
            inner.stop()

    def case_the_next_hop_is_probed_from_the_cache_proxys_health(self, certdir):
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

    def case_a_cache_proxy_that_is_not_answering_records_no_next_hop(self, certdir):
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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_absolute_form_get_is_relayed(self, certdir):
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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_health_reports_the_chain_and_whether_egress_uses_it(self, certdir):
        """/health carries BOTH the configured chain and what egress is doing.

        `chain` alone is not a health signal. It reports the hop the relay
        WOULD use, so a daemon that can reach no hop and is dialling DIRECT
        reported exactly what a healthy one did — every field was green
        through two measured outages, here and on the peer component.

        DIRECT is not degraded-but-fine on a corporate host: the direct route
        IS the TLS-inspecting proxy, and it answers 403. Owner's count on
        host-a for one day:

            egress DIRECT                61
            dial failed                 148
            accepted but did not tunnel  89
            egress via (healthy)        238

        61 is not an exception. The pin detected all four of that day's
        outages and wrote all four to daemon.log; nobody read it any of the
        four times, and a human repaired the chain by hand each time. The
        detection was already finished — only the wiring was missing.

        `egress` is null before the first dial, deliberately: "not dialled
        yet" and "we are direct" are different states, and a monitor that
        conflates them alarms on every daemon start. The three faults stay
        separate for the same reason — `dial failed` (no port), `accepted but
        did not tunnel` (up and looped) and DIRECT (chain given up on) are
        different incidents.

        THE CONTROL is a reachable hop, which must report itself rather than
        "direct" — otherwise the field would pass for one that says direct
        always.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        def _health(chain_target, **kw):
            if chain_target is not None:
                write_upstream_hint(certdir, chain_target)
            proxy = PinProxy(
                certdir=certdir,
                pin_token_provider=lambda: None,
                upstream=("127.0.0.1", 1),
                **kw,
            )
            proxy.start()
            try:
                raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
                raw.close()
                assert b"200" in resp.split(b"\r\n", 1)[0], resp[:40]
                return json.loads(body.decode() or "{}")
            finally:
                proxy.stop()

        # The configured chain, reported as configured.
        data = _health(None, chain_proxy=("127.0.0.1", 9901))
        assert data.get("pin_proxy") is True
        assert data.get("chain") == "127.0.0.1:9901"
        assert "egress" in data, (
            "/health reports the CONFIGURED chain and nothing about whether "
            "egress is actually using it — the field a monitor needs"
        )

        # CONTROL: a reachable hop must report ITSELF, not "direct".
        hop = _LoopbackConnectProxy(("127.0.0.1", 1))
        try:
            live = _health(f"http://127.0.0.1:{hop.port}", rediscover_chain=True)
            assert live.get("egress") != "direct", (
                f"CONTROL FAILED: a reachable hop was reported as DIRECT "
                f"({live.get('egress')!r}) — the field says direct always"
            )
        finally:
            hop.stop()

        # AND THE OUTAGE MUST OUTLIVE THE RECOVERY. `egress` is the state RIGHT
        # NOW, so a chain that breaks and comes back reads green to every probe
        # that arrives afterwards — which is every probe, because nobody is
        # watching at the instant it breaks. Measured on host-b
        # 2026-08-06, the fifth outage in the count above:
        #
        #   22:35:44Z  hop 9901 unusable — accepted but did not tunnel
        #   22:36:46Z  hop 8118 unusable — accepted but did not tunnel
        #   22:36:46Z  egress DIRECT
        #   22:36:47Z  egress via 127.0.0.1:9901       <- green again
        #
        # One second of green-again and the incident is gone. Nothing on this
        # host recorded that it happened except a log line, and a probe an hour
        # later reads a healthy daemon — which is how the four before it were
        # each repaired by hand without anyone knowing why.
        #
        # These are UTC; claude-swap.log is local. A session hunting an
        # unrelated artifact failure compared the two directly, matched this
        # outage to a symptom four hours away, and shipped it as the cause.
        # The field this test guards must not invite that: /health emits UTC.
        #
        # `direct_last` is the transition TIME, not a flag: "we went direct"
        # with no when cannot be told from an hour ago or a week ago, and the
        # only question a reader has is whether it explains what they are
        # looking at. Null until it happens — same reason `egress` is null
        # before the first dial.
        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            chain_proxy=("127.0.0.1", 9901),
        )
        assert proxy.direct_last is None, (
            "a daemon that has never gone direct must not claim it did"
        )
        proxy._note_egress(direct=True, configured=True)
        fell_at = proxy.direct_last
        assert fell_at is not None, "the DIRECT transition was not recorded"
        proxy._note_egress(direct=False, hop=("127.0.0.1", 9901))
        assert proxy.direct_last == fell_at, (
            "recovering to a healthy hop erased the outage — this is the bug: "
            "every probe after the flap sees a green daemon and the incident "
            "becomes invisible"
        )

        # A HOST WITH NO CHAIN AT ALL IS NOT AN OUTAGE. `configured=False` is
        # the steady state on a machine with no egress proxy; stamping it would
        # leave every such machine permanently reporting a fault it does not
        # have — the same conflation the `egress`-vs-null split already avoids.
        never = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
        )
        never._note_egress(direct=True, configured=False)
        assert never.direct_last is None, (
            "a host with no configured chain was recorded as having fallen "
            "back to direct — it never had a chain to fall back from"
        )

    def case_direct_last_is_a_wire_contract_another_repo_reads(self, certdir):
        """The JSON KEY and its TYPE, not the Python property.

        The case above asserts `proxy.direct_last`, an attribute of this
        object. The consumer is in ANOTHER REPOSITORY and reads
        `json["direct_last"]` off the wire — cswap_fork's .claude/verify.sh,
        the chain-egress check, running per host on every deploy. Renaming the
        key or changing its type breaks that consumer and leaves BOTH suites
        green, because nothing here has ever looked at the payload.

        `chain` and `egress` are already pinned by name: the case above
        asserts `data.get("chain") == ...` and `"egress" in data`, so a rename
        of either fails. `direct_last` had neither, and it is the field with
        the subtler failure — a retype still renders in the consumer's
        f-string and produces a plausible wrong answer instead of a crash.

        THE Z IS LOAD-BEARING. daemon.log is UTC while claude-swap.log is
        local; a session compared the two directly, matched an outage to a
        symptom four hours away and shipped it as the cause. A naive
        `isoformat()` drops the suffix and re-opens exactly that.

        NULL, NOT ABSENT, before the first fallback: `.get()` cannot tell
        those apart, so it has to be asserted at the source.
        """
        import datetime
        import json as _json

        from cswap_pin.proxy import PinProxy

        def _payload(proxy):
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
            finally:
                raw.close()
            return _json.loads(body.decode() or "{}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            chain_proxy=("127.0.0.1", 9901),
        )
        proxy.start()
        try:
            fresh = _payload(proxy)
            assert "direct_last" in fresh, (
                "/health dropped the direct_last KEY — the cross-repo "
                "chain-egress check reads it by that exact name"
            )
            assert fresh["direct_last"] is None, (
                f"a daemon that has never gone direct published "
                f"{fresh['direct_last']!r} — null is what 'not yet' looks like"
            )

            proxy._note_egress(direct=True, configured=True)
            fell = _payload(proxy)["direct_last"]
            assert isinstance(fell, str), (
                f"direct_last went out as {type(fell).__name__} ({fell!r}). A "
                f"retype breaks the consumer as hard as a rename, and worse: "
                f"an epoch float still renders in its message and reads as a "
                f"plausible timestamp"
            )
            assert fell.endswith("Z"), (
                f"direct_last published {fell!r} with no UTC marker. "
                f"daemon.log is UTC and claude-swap.log is local; a reader "
                f"already compared the two and blamed the wrong incident"
            )
            # Parses as a real instant, so "Z" cannot be satisfied by a string
            # that merely ends in one.
            datetime.datetime.strptime(fell, "%Y-%m-%dT%H:%M:%SZ")
        finally:
            proxy.stop()

    def case_health_names_who_holds_the_socket(self, certdir):
        """WHICH process owns the address, answered by the kernel, not a record.

        Nothing on the box published this and it cost a peer session a false
        finding: they read the ROLE off argv, which is fixed at exec, so a
        standby that ARMED and became the holder still reads `--standby`
        forever. They reported a machine as deviating when its triad was
        intact. proxy.json records the DAEMON pid, never the holder's.

        COMPUTED AT REQUEST TIME, NEVER STORED, and that is the whole design.
        A stored holder goes stale in exactly the event this field exists to
        report: the holder dies, a standby arms, and the record still names
        the dead one until the next daemon respawn. `held_by_a_holder()`
        compares the spawn-time marker against a LIVE `getppid()`, so the
        kernel owns the comparand and pid reuse cannot forge it — a reused pid
        would have to be this process's actual parent.

        NOT `getppid()` ALONE, which is the tempting one-liner. A daemon
        nobody holds — a bare `daemon_main`, a test harness — still has a
        parent, so the naive version names an unrelated process as the holder
        of a socket it has never heard of. `null` is the honest answer there,
        and it is also the useful one: no holder means this address dies with
        this process.

        NOT `ppid == 1` EITHER. A PR_SET_CHILD_SUBREAPER ancestor collects
        orphans instead of init, so an orphaned daemon never reads 1 — the
        same trap `_spawn_standby` already documents for the standby's arming
        predicate, where getting it wrong left the address ACCEPTING AND
        HANGING (a peer measured 15,010ms) rather than refusing.
        """
        import json as _json
        import os as _os

        from cswap_pin.proxy import _HELD_BY_ENV, PinProxy

        def _payload(proxy):
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
            try:
                raw.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                raw.settimeout(5)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = raw.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                body = resp.split(b"\r\n\r\n", 1)[1]
                try:
                    body += raw.recv(4096)
                except OSError:
                    pass
            finally:
                raw.close()
            return _json.loads(body.decode() or "{}")

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
        )
        proxy.start()
        try:
            # UNHELD: this test process was not spawned by a holder.
            unheld = _payload(proxy)
            assert "holder_pid" in unheld, (
                "/health does not say who holds the socket — the one question "
                "argv cannot answer and proxy.json does not record"
            )
            assert unheld["holder_pid"] is None, (
                f"a daemon nobody holds named {unheld['holder_pid']!r} as its "
                f"holder — that is just getppid(), and it points at a process "
                f"that has never heard of this socket"
            )

            # HELD: the marker names our real parent, which is what a holder
            # sets at spawn. CONTROL below proves the field is not simply
            # echoing getppid() regardless.
            real_ppid = _os.getppid()
            saved = _os.environ.get(_HELD_BY_ENV)
            _os.environ[_HELD_BY_ENV] = str(real_ppid)
            try:
                held = _payload(proxy)["holder_pid"]
            finally:
                if saved is None:
                    _os.environ.pop(_HELD_BY_ENV, None)
                else:
                    _os.environ[_HELD_BY_ENV] = saved
            assert held == real_ppid, (
                f"held daemon reported holder_pid={held!r}, expected the live "
                f"parent {real_ppid}"
            )

            # CONTROL: a marker naming somebody who is NOT our parent must not
            # be believed. This is the pid-reuse case in miniature — a stored
            # number that no longer refers to the process that stored it.
            _os.environ[_HELD_BY_ENV] = str(real_ppid + 1000000)
            try:
                stale = _payload(proxy)["holder_pid"]
            finally:
                if saved is None:
                    _os.environ.pop(_HELD_BY_ENV, None)
                else:
                    _os.environ[_HELD_BY_ENV] = saved
            assert stale is None, (
                f"a marker naming a non-parent was reported as the holder "
                f"({stale!r}) — the field trusted a record over the kernel"
            )
        finally:
            proxy.stop()

    def case_a_hop_that_self_heals_leaves_a_record(self, certdir):
        """A fall-through to a LATER hop, in a tense a later probe can read.

        `direct_last` covers the chain being abandoned entirely. It does not
        cover the chain being DEGRADED — the preferred hop dying and the walk
        carrying on through the one behind it. That is still egress through a
        configured proxy, so `direct` is False and nothing was stamped.

        MEASURED ON host-a, and this is the whole case:

            06:18:09Z  hop 9901 unusable — accepted but did not tunnel
            06:18:09Z  hop 9901 unusable — dial failed: ConnectionRefusedError
            06:18:09Z  egress via 127.0.0.1:8118      <- degraded
            06:18:10Z  egress via 127.0.0.1:9901      <- healthy again

        ONE SECOND. The peer's per-deploy chain check would have failed inside
        that window and no per-deploy probe can ever land in it. Afterwards the
        daemon reads green on every field, so the event is unreadable — which
        is `direct_last`'s own argument for existing, applied to a different
        hop. The sticky record was built for DIRECT and never generalised.

        DEGRADED IS DEFINED BY PREFERENCE, not by hop identity:
        `_chain_candidates()` returns the re-read current chain first and
        recorded next-hops behind it, so anything that is not candidates[0]
        means the preferred hop did not carry this request.

        CONTROL below is the healthy hop: it must NOT stamp, or the field
        would read as a permanent fault on every machine whose chain works.
        """
        from cswap_pin.proxy import PinProxy, write_upstream_hint

        # Two ports nothing listens on. The fake dial keys on them, so they
        # only have to be distinct and unused.
        _s = socket.socket(); _s.bind(("127.0.0.1", 0)); dead_port = _s.getsockname()[1]; _s.close()
        _s = socket.socket(); _s.bind(("127.0.0.1", 0)); live_port = _s.getsockname()[1]; _s.close()

        proxy = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            chain_proxy=("127.0.0.1", 9901),
        )
        assert proxy.hop_degraded_last is None, (
            "a daemon that has never fallen through claimed it had"
        )

        # CONTROL FIRST: the PREFERRED hop carrying the request must not stamp.
        # Without this the assertion below passes for a field that stamps on
        # every successful dial, which is the same as never stamping at all.
        proxy._note_egress(direct=False, hop=("127.0.0.1", 9901), preferred=True)
        assert proxy.hop_degraded_last is None, (
            "the preferred hop carrying traffic was recorded as degradation — "
            "the field would report a permanent fault on every healthy machine"
        )

        proxy._note_egress(direct=False, hop=("127.0.0.1", 8118), preferred=False)
        fell = proxy.hop_degraded_last
        assert fell is not None, (
            "the walk fell through to a later hop and nothing recorded it — "
            "this is the 06:18:09Z event, invisible one second later"
        )

        # AND IT MUST OUTLIVE THE RECOVERY, for the same reason direct_last
        # does: the probe that could read it arrives after the flap, always.
        proxy._note_egress(direct=False, hop=("127.0.0.1", 9901), preferred=True)
        assert proxy.hop_degraded_last == fell, (
            "recovering to the preferred hop erased the degradation — every "
            "probe after the flap sees a green daemon, which is the bug"
        )

        # AND THE WALK MUST ACTUALLY SAY SO. Everything above drives
        # `_note_egress` by hand, so it proves the STAMP and nothing about the
        # caller — `preferred=(i == 0)` could be inverted, or hardcoded True,
        # and every assertion above still passes while the field never fires
        # on a real dial. This drives `_walk_chain_once` itself with hop 0
        # dead and hop 1 answering.
        seen = {}

        # HELD, NOT CLOSED. Closing the peer before the walk writes its
        # CONNECT makes sendall raise EPIPE, which `_walk_chain_once` treats
        # as "hop unusable" — so the fixture reported hop 1 as dead too and
        # the walk returned None. The guard above caught it; without that
        # assertion this case would have gone green while proving nothing.
        peers = []

        def _fake_dial(chain, extra_ca=None):
            if chain.port == dead_port:
                raise OSError("refused")
            ours, theirs = socket.socketpair()
            theirs.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            peers.append(theirs)
            return ours

        import cswap_pin.proxy as _mod

        write_upstream_hint(
            certdir, f"http://127.0.0.1:{dead_port}",
            next_hop=f"http://127.0.0.1:{live_port}",
        )
        walker = PinProxy(
            certdir=certdir,
            pin_token_provider=lambda: None,
            upstream=("127.0.0.1", 1),
            rediscover_chain=True,
        )
        # BOUND TO `walker`, and it has to be spelled out: the first draft
        # captured `proxy._note_egress` — the OTHER object — so the walk
        # stamped a proxy nobody was asserting on and `hop_degraded_last`
        # read None on the one under test. Right call, wrong instance.
        _real_note = walker._note_egress

        def _spy(**kw):
            seen.update(kw)
            return _real_note(**kw)

        walker._note_egress = _spy
        saved_dial = _mod._dial_chain
        _mod._dial_chain = _fake_dial
        try:
            got = walker._walk_chain_once()
        finally:
            _mod._dial_chain = saved_dial
        assert got is not None, (
            "the walk found no usable hop — the fixture never reached hop 1, "
            "so anything it reports about preference is vacuous"
        )
        assert seen.get("hop") == ("127.0.0.1", live_port), (
            f"hop 1 was expected to carry, but the walk reported "
            f"{seen.get('hop')!r} — wrong subject, the preference claim below "
            f"would be about a hop that never carried anything"
        )
        assert seen.get("preferred") is False, (
            f"the walk skipped the preferred hop and told _note_egress "
            f"preferred={seen.get('preferred')!r} — the stamp is wired to a "
            f"flag the caller never sets correctly, so it can never fire in "
            f"production"
        )
        assert walker.hop_degraded_last is not None, (
            "a real fall-through through the real walk recorded nothing"
        )



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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_multiple_requests_over_one_connection(self, certdir):
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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_upgrade_headers_reach_upstream_and_tunnel_opens(self, certdir):
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


    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_tunnel_to_a_foreign_host_writes_a_trace_line(self, certdir, tmp_path):
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
                # WAIT FOR THE TRACE, NOT FOR A RESPONSE. `ingress.example.com`
                # does not resolve, so no response is ever coming and the old
                # `recv` loop simply raced the DNS resolver: it blocked until
                # its own 10s socket timeout while the resolver retried.
                # Measured, this test alone: 1 failure in 12 runs, the failing
                # one always ~10.3s against pass-times of 0.8-5.9s. The flake
                # was pre-existing and only became visible when a publish gate
                # started running the suite.
                #
                # The property under test is that the tunnel ANNOUNCES itself,
                # and that line is written before any dial — so waiting for it
                # tests the thing and waits on nothing else.
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    pp._TRACE.flush()
                    if "CONNECT ingress.example.com" in log.read_text():
                        break
                    time.sleep(0.02)
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_direct_dial_when_the_chain_refuses_the_ingress_host(
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


def _fake_pids(base: int, count: int) -> list[int]:
    """`count` pids starting at `base` that are NOT this process.

    A CASE THAT ANNOUNCES FOR A FAKE PID MUST NOT ANNOUNCE FOR OURS.
    `this_process_is_draining` reads the depth map filtered to our own pid, so
    a fixture that happens to pick our number makes this process look like it
    is handing over — and every relay in that worker then sheds keep-alives.

    Found on macOS CI 2026-08-18, where a `range(7000, 7009)` fixture collided
    with the runner's own pid: green on Linux, where pids are large, and red on
    a machine that hands out low ones. The block is shifted rather than
    filtered so the count stays exact.
    """
    import os

    if base <= os.getpid() < base + count:
        base += count
    return list(range(base, base + count))


class TestDrainReportsWhatItCut:
    """The drain line must say what was still open, not always zero.

    `await_inflight` ends with `_close_open_connections()`, which does
    `conns, self._open_conns = list(self._open_conns), set()` — it EMPTIES the
    set. The caller then logs `live_client_count()`, which reads that set. So
    "drained, N client(s) still open" is N=0 by construction, whatever it cut.

    Measured across all three machines' daemon logs: every non-zero value is
    from 2026-08-04/05 (`drained, 634 client(s)`, `6`, `7`, `8`, `4`); every
    value from 08-08 onward is 0. The ordering changed in between, and the one
    line that exists to say whether a recycle cost anything has been a constant
    ever since — while the user was losing a response mid-stream and nobody
    could tell from the log whether the pin did it.

    That is the shape where a fix deletes the evidence its own check reads.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_count_survives_the_cut(self, certdir):
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        err = io.StringIO()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            # OWED, NOT MERELY OPEN. This case used to put the connection in
            # `_open_conns` alone and assert the drain reported 1 — which
            # pinned the conflation rather than the behaviour: the loop waits
            # on owed answers and the message counted open sockets, so an
            # opaque tunnel that owed nobody anything was reported as a cut
            # request. Both numbers quoted to the user on 2026-08-18 (34, then
            # 30) came out of that gap.
            proxy._owe_answer(a, True)
            assert proxy.live_client_count() == 1, "precondition"
            with contextlib.redirect_stderr(err):
                cut = proxy.await_inflight(0.0)
            assert cut == 1, (
                "await_inflight must report what it cut; the set it counted is "
                "the set it just emptied")
            assert proxy.live_client_count() == 0, "and the set is emptied"
            # THE PATH THAT CUT SOMETHING TONIGHT WAS `_teardown`, not a code
            # handover — so the warning belongs in the one function all three
            # drains go through, or it misses the event that prompted it.
            assert "cut 1 in-flight request(s)" in err.getvalue(), err.getvalue()
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_an_idle_drain_reports_zero(self, certdir):
        """THE CONTROL. Without it, "reports what it cut" also passes on a
        version that returns a constant 1 — and "warns when it cut" also
        passes on one that warns every time."""
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            assert proxy.await_inflight(0.0) == 0
        # NOT SILENCE — a clean drain now says it drained clean, because "no
        # line" meant both that and "this daemon never drained at all".
        assert "cut" not in err.getvalue(), err.getvalue()
        assert "drained clean" in err.getvalue(), err.getvalue()

    def case_an_open_connection_with_no_request_does_not_hold_the_drain(self, certdir):
        """THE DEADLINE MUST STOP FIRING EVERY TIME, and this is why it did.

        The drain waited for the CONNECTION count to reach zero. It cannot:
        Remote Control's WebSocket is opaque after the 101 and lives as long as
        the session, so a connection is always open. The wait therefore always
        ran to the full ceiling and then cut EVERYTHING still open — including a
        `/v1/messages` stream that had started two seconds earlier. Measured on
        host-a 2026-08-18: one code change produced two full swaps 70s apart and
        three sessions took "API Error: Connection lost mid-response".

        The pin's own comment had already written down the premise — "Remote
        Control's WebSocket lives as long as the session does, so the count is
        never zero" — and nobody followed it to the conclusion that the ceiling
        is therefore paid in full on every single recycle.

        A LONG-LIVED CONNECTION WITH NO REQUEST IN FLIGHT IS NOT WORK. So the
        drain must count REQUESTS. Here: a connection is open, no request is in
        flight, and the drain must return AT ONCE rather than burn the budget.
        The budget is deliberately large so that a version still counting
        connections cannot pass by being fast.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            # OPEN, AND OWING NOTHING — an RC WebSocket after its 101, or a
            # keep-alive socket between requests. Both are connections nobody
            # is waiting on, and the drain must not hold for either. Modelled
            # by simply not putting it in `_owed`, which is what the accept
            # path does and then undoes at the 101 and between requests.
            assert proxy.live_client_count() == 1, "precondition: a conn is open"
            assert proxy.inflight_requests() == 0, (
                "precondition: a tunnel owes nobody an answer")
            started = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(20.0)
            waited = time.monotonic() - started
            assert waited < 2.0, (
                f"waited {waited:.1f}s for a connection carrying no request; "
                "the drain is still counting connections, so an RC WebSocket "
                "makes it pay the full ceiling on every recycle")
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_a_moving_reply_holds_the_drain_and_a_silent_one_does_not(
        self, certdir, monkeypatch
    ):
        """THE DISCRIMINATOR A DEADLINE CANNOT MAKE.

        Measured on host-a 2026-08-18, the 0.1.102 rollout:

            09:02:20Z cut 12 in-flight request(s) after 600.0s of a 600s budget
                      (12 mid-response, 0 before headers)

        Twelve replies were STILL STREAMING when the clock cut them. A wedged
        connection and a four-minute answer are identical to a deadline — which
        is why the deadline was there — and not identical to the connection:
        one is moving bytes and one is not.

        BOTH DIRECTIONS IN ONE CASE, because either alone passes on a version
        that always waits or always returns. The stall window is shrunk so this
        runs in seconds; the production value is ninety.
        """
        import cswap_pin.proxy as pp

        monkeypatch.setattr(pp, "_DRAIN_STALL_SECONDS", 0.3)

        # --- SILENT: owed, and nothing has moved since well before the drain.
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)
            proxy._note_response_started(a)
            time.sleep(0.4)                      # past the stall window
            t0 = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(30.0)
            silent_wait = time.monotonic() - t0
            assert silent_wait < 2.0, (
                f"waited {silent_wait:.1f}s on a connection that has sent "
                "nothing since before the drain began — that is a wedged "
                "socket holding the budget, which is what the stall window "
                "exists to end")
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

        # --- MOVING: the same shape, but bytes keep arriving for a while.
        proxy2 = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                             upstream=("127.0.0.1", 1))
        c, d = socket.socketpair()
        stop = threading.Event()
        try:
            with proxy2._live_lock:
                proxy2._open_conns.add(c)
            proxy2._owe_answer(c, True)

            def _stream():
                # A reply delivering a chunk every 100ms for a second, then
                # finishing — the shape the 600s ceiling was cutting.
                for _ in range(10):
                    if stop.is_set():
                        return
                    proxy2._note_response_started(c)
                    time.sleep(0.1)
                proxy2._owe_answer(c, False)     # the reply completed

            # AND THE WIRING FOR THE BEAT, on the drain that actually loops.
            # A marker refreshed by a function nothing calls is the fourth
            # orphaned guard tonight; the drain is the only thing that knows
            # it is still alive, so it is the only thing that can say so.
            beats = []
            real_beat = pp.beat_draining
            monkeypatch.setattr(pp, "_DRAINING_BEAT_SECONDS", 0.05)
            monkeypatch.setattr(
                pp, "beat_draining",
                lambda cd, pid=None, owed=None, live=None, quiet=None,
                **k: (beats.append(owed),
                      real_beat(cd, pid, owed, live, quiet, **k))[1])

            threading.Thread(target=_stream, daemon=True).start()
            t0 = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                cut = proxy2.await_inflight(30.0)
            moving_wait = time.monotonic() - t0

            assert sum(b is not None for b in beats) >= 2, (
                "only the drain's opening beat published what it owes. The "
                "count changes as replies land, so a loop beat that drops it "
                "leaves the sweep reading a number from minutes ago — and a "
                f"predecessor that has finished still looks expensive. beats={beats}")
            assert len(beats) >= 3, (
                f"the drain beat {len(beats)} time(s) while it waited a second "
                "on a moving reply. Without the beat the marker goes stale on "
                "its own TTL and the orphan sweep kills a daemon mid-reply")

            assert moving_wait > 0.8, (
                f"the drain returned after {moving_wait:.2f}s while bytes were "
                "still going to the client. A stall window shorter than the "
                "gaps in a live stream cuts exactly the replies it exists to "
                "protect")
            assert cut == 0, (
                f"cut {cut} — the reply finished on its own and the drain "
                "should have had nothing left to cut")
        finally:
            stop.set()
            for s_ in (c, d):
                try: s_.close()
                except OSError: pass

    def case_fake_pids_are_never_this_process(self, monkeypatch):
        """THE FIXTURE THAT MADE macOS CI RED, pinned.

        `this_process_is_draining` reads the depth map filtered to our own pid,
        so a case that announces for a made-up pid which HAPPENS to be ours
        makes this process look like it is handing over — and every relay in
        that worker then sheds keep-alives. Green on Linux, where pids are
        large; red on a runner that hands out low ones.

        The helper shifts the whole block rather than filtering, so the count
        a caller asked for is the count it gets.
        """
        import os

        import cswap_pin.proxy as pp  # noqa: F401 — the module under test's home

        monkeypatch.setattr(os, "getpid", lambda: 7003)
        got = _fake_pids(7000, 9)
        assert 7003 not in got, f"handed out our own pid: {got}"
        assert len(got) == 9, f"lost or gained a pid while avoiding ours: {got}"

        monkeypatch.setattr(os, "getpid", lambda: 999999)
        assert _fake_pids(7000, 9) == list(range(7000, 7009)), (
            "shifted when there was no collision — the block should only move "
            "to get out of our own way")

    def case_a_departing_daemon_stops_taking_new_requests(self, certdir):
        """`release_listener` SHEDS ARRIVALS; NOTHING SHED THE KEEP-ALIVES.

        A departing daemon stopped accepting new CONNECTIONS and kept accepting
        new REQUESTS on the ones it already held, indefinitely. From the
        client's side nothing was wrong with the socket, so it never
        reconnected — measured on host-a 2026-08-18, eleven sessions whose ONLY
        path to the pin was a process that had stopped being the front door.

        The reply still COMPLETES; the header only says "do not send another".
        The client then opens a fresh connection and lands on the successor
        through the shared listener, so sessions migrate one completed reply at
        a time.
        """
        import os as _os

        import cswap_pin.proxy as pp

        def _relay_once():
            up_a, up_b = socket.socketpair()
            cl_a, cl_b = socket.socketpair()
            try:
                def _upstream():
                    try:
                        up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                                     b"Content-Length: 2\r\n\r\nhi")
                        time.sleep(0.05)
                        up_b.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

                threading.Thread(target=_upstream, daemon=True).start()
                pp._relay_response(up_a, cl_a, 0)
                cl_a.shutdown(socket.SHUT_WR)
                got = b""
                while True:
                    chunk = cl_b.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                return got
            finally:
                for s_ in (up_a, up_b, cl_a, cl_b):
                    try:
                        s_.close()
                    except OSError:
                        pass

        # OUR OWN DEPTH, SET EXPLICITLY. Asserting the ambient value made this
        # case depend on what ran before it in the same worker — see
        # `_fake_pids`. The case is about the TRANSITION, so it establishes
        # both ends itself and puts back whatever it found.
        with pp._DRAINING_LOCK:
            saved = dict(pp._DRAINING_DEPTH)
            mine = f"{pp._DRAINING_PREFIX}{_os.getpid()}"
            for key in [k for k in pp._DRAINING_DEPTH
                        if k.rsplit("/", 1)[-1] == mine]:
                pp._DRAINING_DEPTH.pop(key)

        # SERVING: the connection stays reusable.
        assert not pp.this_process_is_draining(), "precondition"
        serving = _relay_once()
        assert b"hi" in serving, serving[:120]
        assert b"Connection: close" not in serving, (
            "a serving daemon told the client to stop reusing the connection; "
            "every request would then pay a fresh TLS handshake: "
            + serving[:200].decode("latin1"))

        # HANDING OVER: same reply, delivered in full, and the last one.
        # OUR OWN PID: the predicate asks whether THIS process is leaving, and
        # announcing on another pid's behalf must not answer yes for us.
        done = pp.announce_draining(certdir, _os.getpid())
        try:
            assert pp.this_process_is_draining(), "precondition"
            departing = _relay_once()
        finally:
            done()
            with pp._DRAINING_LOCK:
                pp._DRAINING_DEPTH.clear()
                pp._DRAINING_DEPTH.update(saved)

        assert b"hi" in departing, (
            "the reply was not delivered — this must shed the CONNECTION, "
            "never the answer: " + departing[:200].decode("latin1"))
        assert b"Connection: close" in departing, (
            "a departing daemon kept the connection reusable, so the client "
            "sends its next request into a process that has stopped being the "
            "front door and never reaches the successor: "
            + departing[:200].decode("latin1"))

    def case_a_keepalive_is_told_from_an_answer_by_NAME(self, certdir):
        """NO THRESHOLD, NO RATE, NO FRAME WIDTH — the protocol says which is
        which, and the pin has the plaintext because it is the MITM.

        FAILS SAFE, which is the whole reason this is shippable where a byte
        threshold was not. The test is "is EVERY event here a keepalive", so an
        event name nobody has seen counts as CONTENT and the drain keeps
        waiting. Phrased the other way — "does this contain a known content
        event" — the day a new event type is added it would cut live replies.
        """
        import cswap_pin.proxy as pp

        assert pp._is_only_keepalive(b"event: ping\ndata: {}\n\n") is True
        assert pp._is_only_keepalive(
            b"event: ping\ndata: {}\n\nevent: ping\ndata: {}\n\n") is True

        for content in (
            b"event: content_block_delta\ndata: {}\n\n",
            b"event: ping\ndata: {}\n\nevent: message_stop\ndata: {}\n\n",
            b"event: some_event_added_next_year\ndata: {}\n\n",
            b'{"id":"msg_1"}',
            b"data: {}\n\n",
            b"",
        ):
            assert pp._is_only_keepalive(content) is False, (
                f"classified as a keepalive: {content!r} — anything this "
                "cannot positively identify as all-keepalive must count as an "
                "answer, or the drain stops waiting on a live reply")

    def case_the_response_head_is_movement_but_not_an_answer(self, certdir):
        """THE HEAD GOES THROUGH THE SAME WRITER, and counting it as content
        would make every response look answered from its first byte — a rule
        that ships, reads like a fix, and never fires.

        It must still STAMP: a head reaching the client is the connection
        moving, and the stall window is what reads that.
        """
        import cswap_pin.proxy as pp

        seen = []
        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        try:
            def _upstream():
                try:
                    up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Type: text/event-stream\r\n\r\n")
                    time.sleep(0.15)
                    up_b.sendall(b"event: ping\ndata: {}\n\n")
                    time.sleep(0.05)
                    up_b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            threading.Thread(target=_upstream, daemon=True).start()
            pp._relay_response(up_a, cl_a, 0,
                               on_headers=lambda n, c: seen.append(c))
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try:
                    s_.close()
                except OSError:
                    pass

        assert seen, "nothing was stamped at all; the case proves nothing"
        assert seen[0] is False, (
            "the response HEAD was reported as content, so every reply looks "
            "answered from its first byte and nothing can ever be classified "
            "as a stopped one")
        assert all(c is False for c in seen), (
            f"a keepalive-only body was reported as content: {seen}")

    def case_content_before_the_drain_does_not_make_a_reply_live(
        self, certdir, monkeypatch
    ):
        """SINCE THE DRAIN BEGAN, NOT SINCE THE REQUEST BEGAN.

        Measured on host-a 2026-08-18: the twelve that mattered delivered real
        content in the FIRST 20 SECONDS of their drain and nothing but
        keepalives for the thirty minutes after. A counter that starts at the
        request would call every one of them live, and the reaper would then
        protect a process holding twelve stopped replies over one still
        writing.

        Drives `await_inflight`, not `live_replies` directly: the snapshot is
        taken inside the drain and that wiring is the part that can be lost.
        """
        import cswap_pin.proxy as pp

        monkeypatch.setattr(pp, "_DRAIN_STALL_SECONDS", 0.2)
        seen = []
        real_beat = pp.beat_draining
        monkeypatch.setattr(
            pp, "beat_draining",
            lambda cd, pid=None, owed=None, live=None, quiet=None, **k: (
                seen.append((owed, live)),
                real_beat(cd, pid, owed, live, quiet, **k))[1])

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)
            # AN ANSWER, DELIVERED BEFORE ANY OF THIS — then silence but for a
            # keepalive, which is what the drain will actually see.
            proxy._note_response_started(a, 4000, True)
            proxy._note_response_started(a, 39, False)

            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(1.0)
        finally:
            for s_ in (a, b):
                try:
                    s_.close()
                except OSError:
                    pass

        assert seen, "the drain never beat, so nothing published a count"
        owed, live = seen[0]
        assert owed == 1, f"precondition: one reply is owed, got {owed}"
        assert live == 0, (
            "a reply whose only content predates the drain was counted as "
            "still being written, so the reaper will protect a predecessor "
            f"holding nothing but stopped replies. live={live}")

    def case_the_reaper_prefers_the_predecessor_with_no_live_answers(
        self, certdir
    ):
        """TWELVE CORPSES OUTWEIGHED TWO LIVE REPLIES.

        The sort keyed on replies OWED, and a connection that stopped half an
        hour ago is owed exactly as much as one still streaming — so at the
        limit the reaper preferred to kill the process still doing real work.
        Measured on host-a 2026-08-18: `12 mid-response` over twelve
        connections carrying nothing but a fixed frame.
        """
        import cswap_pin.proxy as pp

        killed = []
        real_kill, real_pids = pp._kill_daemon, pp._pin_daemon_pids
        pp._kill_daemon = lambda pid: killed.append(pid)
        pids = _fake_pids(7000, pp._MAX_DRAINING_PREDECESSORS + 1)
        pp._pin_daemon_pids = lambda certdir: list(pids)
        try:
            for pid in pids:
                pp.announce_draining(certdir, pid)
                # pids[0] holds the MOST replies and none is being written;
                # every other one holds fewer and all of theirs are live.
                if pid == pids[0]:
                    pp.beat_draining(certdir, pid, owed=12, live=0)
                else:
                    pp.beat_draining(certdir, pid, owed=2, live=2)

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert killed == [pids[0]], (
                "the reaper took a predecessor that was still writing answers "
                "while one holding twelve stopped ones survived — owed counts "
                f"debts, not answers. killed={killed}")
        finally:
            pp._kill_daemon, pp._pin_daemon_pids = real_kill, real_pids

    def case_a_reply_that_has_gone_quiet_is_timed_not_guessed(self, certdir):
        """THE NUMBER `await_inflight` SAYS THE DECISION IS WAITING ON.

        That comment names its own unblocking condition — "it becomes decidable
        the day somebody measures the longest content-free interval a live
        reply produces" — and nothing was measuring it. A peer tried, from
        `/proc/<pid>/io` deltas with a burst detector, and could not: that rate
        is process-wide, so its gap means "no burst on ANY of twelve replies"
        while the rule needs "no content on ONE". Twelve replies staggered ten
        seconds apart produce a burst every ten seconds while each one is
        content-free for two minutes, so the aggregate reads small and safe and
        a threshold chosen from it cuts live work.

        `_StampingWriter` is the only thing that sees bytes attributed to one
        connection, and `_is_only_keepalive` already separates content from a
        ping BY NAME. So the interval is exact here and a heuristic anywhere
        else.

        AND IT GOES IN THE MARKER, not only the exit line. The daemon this
        question exists for is the one that NEVER exits — measured on host-a
        2026-08-18, pid 609285, twelve live sessions, keepalive-only for 45
        minutes and still draining. A number printed on the way out is a
        number that case never produces.

        AN INSTRUMENT ONLY. Nothing decides on it yet; see `_owed_still_moving`
        for why a content-based stall stays refused until this has run.
        """
        import os
        import re

        import cswap_pin.proxy as pp

        class _Clock:
            t = 1000.0

            def monotonic(self):
                return self.t

            def time(self):
                return 1787000000.0 + self.t

            def sleep(self, _s):
                pass

        clock = _Clock()
        real_time = pp.time
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        e, f = socket.socketpair()
        err = io.StringIO()
        # BOUND BEFORE THE `try`, or a failure earlier in the body makes the
        # `finally` raise NameError and hide it.
        _depth_before = dict(pp._DRAINING_DEPTH)
        try:
            pp.time = clock
            # `e` IS OWED AND NEVER WRITTEN TO — a request on the wire whose
            # upstream has said nothing. It is the SILENTEST thing here, and
            # timing it from its first content byte would report the silentest
            # reply on the box as the busiest: there is no first byte, so the
            # clock would start now and read 0 s. It is timed from the debt.
            for sock in (a, c, e):
                with proxy._live_lock:
                    proxy._open_conns.add(sock)
                proxy._owe_answer(sock, True)
            proxy._note_response_started(a, 500, True)
            proxy._note_response_started(c, 500, True)

            # `a` GOES QUIET AND KEEPS PINGING; `c` KEEPS ANSWERING. Both stay
            # owed, both keep moving bytes, both look identical to
            # `_owed_still_moving` — which is exactly the pair a byte rate
            # cannot separate and this line has to.
            clock.t = 1300.0
            proxy._note_response_started(a, 39, False)
            clock.t = 1305.0
            proxy._note_response_started(c, 500, True)

            clock.t = 1310.0
            # THE NEVER-WRITTEN REPLY SCORES ITS FULL SILENCE, same as the one
            # that went quiet 310s ago. Read before the drain, because
            # `await_inflight` closes the connections this counts over.
            assert proxy.content_free_intervals() == [5.0, 310.0, 310.0], (
                "a reply that has sent nothing did not report the silence it "
                "has actually been sitting in — timed from its first content "
                "byte it has none, so the worst case on the box reads as the "
                f"best: {proxy.content_free_intervals()}")

            with contextlib.redirect_stderr(err):
                proxy.await_inflight(0.0)
            line = err.getvalue()

            # MIN AND MAX, not the median: with three samples the middle is
            # still a formatter detail. The fact is that the quiet replies and
            # the busy one land at opposite ends of the same line.
            assert "content-free 5/" in line and "/310 s min/med/max" in line, (
                "the drain line does not say how long each reply has gone "
                "without content, so the interval a stall threshold would "
                "have to clear is still unmeasured: " + line)

            # AND READABLE ON A DAEMON THAT HAS NOT FINISHED. The exit line is
            # written by a drain that ended; this marker is what a stuck one
            # publishes every beat.
            pid = os.getpid()
            # SAVED AND RESTORED. The depth map is a module global keyed by
            # marker basename, and `this_process_is_draining()` matches on it,
            # so an announcement left standing here makes every later case in
            # this worker take the draining branch — `Connection: close` on
            # every response and `handed_over=True` in the teardown budget.
            # Only definition order kept the sibling case's precondition green.
            pp.announce_draining(certdir, pid)
            pp.beat_draining(certdir, pid, owed=2, live=2, quiet=310.0)
            assert pp.draining_quiet(certdir, pid) == 310.0, (
                "the beat marker does not carry the quiet interval, so the "
                "one daemon this question is about — the one that never "
                "exits — publishes no answer to it")
            # A MARKER FROM A VERSION THAT DID NOT RECORD IT MUST NOT READ AS
            # ZERO. Zero means "answering right now", the safest possible
            # reading, and this fleet runs mixed versions through every
            # upgrade.
            pp.draining_marker_path(certdir, pid).write_text("1787000000\n2\n2")
            assert pp.draining_quiet(certdir, pid) is None, (
                "a marker with no quiet line answered a number, so an older "
                "daemon would be reported as freshly answering")

            # AND THE CLEAN BRANCH, which is the one the number is FOR and the
            # one where a snapshot of the live set is 0 by construction:
            # `drained clean` means nothing is owed. Only a reply that went
            # quiet and then FINISHED can raise a ceiling, so that is what the
            # line has to carry.
            #
            # DRIVEN IN THE ORDER `_mitm` PRODUCES, which the first version of
            # this case did not. It called `_note_reply_finished` at a clock
            # 400s past the last content write — a state the relay cannot
            # reach, because that call sits at the top of the next loop
            # iteration, immediately after the last `sendall` refreshed the
            # stamp. So the assertion was green about behaviour that never
            # happens, and the field it certified banked the TRAILING gap
            # (~0 for every streaming reply) instead of the longest one.
            #
            # `c` is the shape that matters: quiet from t=1305 to t=1395, then
            # DELIVERS, then completes one tick later. The peak has to be the
            # 90s it survived, not the ~0s between its last token and its end.
            clock.t = 1395.0
            proxy._note_response_started(c, 500, True)
            # THE MID-STREAM GAP, ASSERTED PER CONNECTION, because the fleet
            # maximum cannot isolate it: `a` and `e` end after long TRAILING
            # silences that legitimately dominate. `c` delivered at t=1000,
            # 1305 and 1395, so its longest quiet-then-delivered interval is
            # 305s — a number the old code could not produce at all, since it
            # only ever read the gap after the LAST content byte.
            assert proxy._gap[c] == 305.0, (
                "the longest interval between content writes was not banked, "
                "so a reply that pings through a long think and then delivers "
                f"scores nothing: {proxy._gap.get(c)}")
            clock.t = 1395.5
            # `c` FINISHES ALONE FIRST, so the peak it produces can only have
            # come from its MID-STREAM gap. Finished alongside `a` and `e` — as
            # the first version did — their 395s TRAILING silences dominate the
            # process-wide maximum, and dropping `_gap` from the peak entirely
            # changes nothing observable. That mutation survived until this
            # ordering existed.
            proxy._note_reply_finished(c)
            proxy._owe_answer(c, False)
            assert proxy._quiet_peak == 305.0, (
                "the peak did not come from the longest gap BETWEEN content "
                "writes; this reply's trailing silence was 0.5s and its "
                f"mid-stream quiet was 305s: {proxy._quiet_peak}")
            for sock in (a, e):
                proxy._note_reply_finished(sock)
                proxy._owe_answer(sock, False)
            # AND THE DEBT BOUNDARY CLEARS IT, like every other per-debt
            # counter — or the next request on a keep-alive starts already
            # holding the last one's silence.
            assert c not in proxy._gap, (
                "the gap survived the debt it belongs to; the next reply on "
                "this connection would inherit it")
            clock.t = 1400.0
            clean = io.StringIO()
            with contextlib.redirect_stderr(clean):
                proxy.await_inflight(0.0)
            got = clean.getvalue()
            assert "drained clean" in got, (
                "the second drain still had debts, so this proves nothing "
                "about the clean branch: " + got)
            assert "content-free wait a completed reply survived 396s" in got, (
                "the clean drain reported no content-free interval, or "
                "reported it from the live set — which is empty on every "
                "clean drain, so the field could never be anything but "
                "zero: " + got)

            # THE PHRASES OTHER PEOPLE MATCH ON, checked against the rendered
            # lines rather than against my memory of them. Two peer readers on
            # this fleet grep these UNANCHORED, so the component tag added to
            # `_log_lifecycle` had to go ahead of `pid=` and leave both tokens
            # in place. Asserting it here, where the real lines exist, is the
            # only place that can tell a safe insertion from a rename.
            for pat, where in ((r"cut \d+ in-flight", line),
                               (r"drained clean", got)):
                assert re.search(pat, where), (
                    f"the format change broke `{pat}`, which peer tooling "
                    f"greps unanchored: {where}")
            # NAME AND VERSION. The name alone was not enough: 0.1.113-0.1.115
            # printed a `content-free` value measuring the wrong quantity and
            # 0.1.116 fixed it, and both spell the line identically — so every
            # reader had to know when each machine was upgraded to tell a
            # usable number from a worthless one.
            assert re.search(PIN_STAMP, line), (
                "the drain line does not name the component AND VERSION that "
                f"wrote it, so its numbers carry no provenance: {line}")
        finally:
            pp.time = real_time
            with pp._DRAINING_LOCK:
                pp._DRAINING_DEPTH.clear()
                pp._DRAINING_DEPTH.update(_depth_before)
            try:
                pp.draining_marker_path(certdir, os.getpid()).unlink()
            except OSError:
                pass
            for s_ in (a, b, c, d, e, f):
                try: s_.close()
                except OSError: pass

    def case_an_unwritable_marker_does_not_shorten_our_own_drain(self, certdir):
        """FAILING OPEN FOR THE SWEEP, NOT FOR US.

        `announce_draining` promises in its own docstring that this file "may
        only ever REMOVE a kill, never cause one" — the marker is advice to
        OTHER processes, so a certdir that cannot be written just leaves the
        sweep as blind as it was before markers existed.

        Then `teardown_drain_budget(handed_over=this_process_is_draining())`
        started reading the same state, and the rollback broke the promise: an
        ENOSPC or a read-only certdir made a daemon mid-handover report
        `handed_over=False`, take the 30s held ceiling instead of the uncapped
        one, and cut exactly the live mid-response replies that ceiling was
        removed to save.

        The DEPTH is in-process knowledge and is true whether or not the file
        landed. Only the file is advice, and only the file may fail.
        """
        import os

        import cswap_pin.proxy as pp

        before = dict(pp._DRAINING_DEPTH)
        real_write = pathlib.Path.write_text
        try:
            def _boom(self, *a, **kw):
                if self.name.startswith(pp._DRAINING_PREFIX):
                    raise OSError(28, "No space left on device")
                return real_write(self, *a, **kw)

            pathlib.Path.write_text = _boom
            # ASSERTED ON THIS CASE'S OWN KEY, not on the process-wide
            # predicate. `this_process_is_draining()` matches ANY entry whose
            # marker basename is `.draining-<our pid>`, across every certdir in
            # the map — so a sibling case in the same xdist worker that
            # announced for this pid makes both directions vacuous. It passed
            # on linux and failed on macOS purely on which cases shared the
            # worker, which is a scheduling detail, not a fact about the fix.
            key = str(pp.draining_marker_path(certdir, os.getpid()))
            done = pp.announce_draining(certdir, os.getpid())
            assert pp._DRAINING_DEPTH.get(key, 0) == 1, (
                "a marker that could not be written made this daemon forget "
                "it is draining, so its next teardown takes the short ceiling "
                f"and cuts the replies the uncapped one exists to finish: "
                f"{pp._DRAINING_DEPTH.get(key)}")
            assert pp.this_process_is_draining(), (
                "the depth is set but the predicate production reads does not "
                "see it")
            done()
            assert key not in pp._DRAINING_DEPTH, (
                "the releaser handed back nothing, so the state it set on the "
                "failed-write path leaks for the life of the process")
        finally:
            pathlib.Path.write_text = real_write
            with pp._DRAINING_LOCK:
                pp._DRAINING_DEPTH.clear()
                pp._DRAINING_DEPTH.update(before)

    def case_the_opt_in_trace_files_are_capped_like_the_daemon_log(self, tmp_path):
        """THE CAP WAS ON THE FILE NOBODY ENABLES.

        `daemon.log` is bounded — 64 KiB, rotated through `.1` and `.2`, so a
        machine can hold ~192 KiB of it however long the daemon runs. That care
        was taken for the log that is always on and always small.

        `CSWAP_PIN_DEBUG` and `CSWAP_PIN_SHAPE` open in append mode and write
        one line PER REQUEST through a path `_LOG_MAX_BYTES` never touched. Off
        by default, so a fresh install is safe — but a human turns them on
        precisely when something is going wrong, which is also when they stop
        watching the disk. The careful bound was on the file that could not
        grow and absent from the two that can.

        Asserted by WRITING PAST THE CAP rather than by reading the source: the
        question is what a downstream user's disk does, and only bytes answer
        it.
        """
        import os

        import cswap_pin.proxy as pp

        # UNDER PYTEST'S OWN TREE, not a bare mkdtemp: pytest reaps this on
        # every exit path, and a plain /tmp dir outlives the run. A peer
        # counted 297 of ours left on this box.
        d = str(tmp_path / "cap-probe")
        os.makedirs(d, exist_ok=True)
        for env, writer in (
            ("CSWAP_PIN_DEBUG", "debug"),
            ("CSWAP_PIN_SHAPE", "shape"),
        ):
            target = os.path.join(d, f"{writer}.log")
            line = "x" * 512 + "\n"
            # FIVE TIMES THE CAP, so the rotation runs several times. At one
            # overflow an unbounded-generations bug leaves a single extra file
            # and hides under any sane threshold; it only becomes visible once
            # the policy has been applied repeatedly.
            need = 5 * (pp._LOG_MAX_BYTES // len(line))
            fh = None
            try:
                for _ in range(need):
                    fh = pp._append_capped(target, line, fh)
            finally:
                if fh is not None:
                    try:
                        fh.close()
                    except OSError:
                        pass
            live = os.path.getsize(target)
            assert live <= pp._LOG_MAX_BYTES, (
                f"{env} grew to {live} B with no cap; a trace left on after an "
                "incident fills the disk of somebody who installed this")
            # AND THE ROTATIONS ARE BOUNDED TOO, or the cap just moves the
            # growth one filename over.
            #
            # GLOBBED, NOT A SUFFIX LIST. The first version summed `""`, `.1`
            # and `.2`, so a rotation that minted a fresh name per pass — the
            # unbounded-generations mutation — produced files it never looked
            # at and passed. A check whose input is a hardcoded list goes stale
            # the first time the thing it watches grows a new shape, which is
            # the defect being tested one level up.
            siblings = [
                f for f in os.listdir(os.path.dirname(target))
                if f.startswith(os.path.basename(target))
            ]
            total = sum(
                os.path.getsize(os.path.join(os.path.dirname(target), f))
                for f in siblings
            )
            assert len(siblings) <= 3, (
                f"{env} left {len(siblings)} generations behind ({siblings}); "
                "the rotation keeps two plus the live file, or the ceiling is "
                "per file and the directory is unbounded")
            assert total <= 3 * pp._LOG_MAX_BYTES, (
                f"{env} plus its rotations reached {total} B; the ceiling has "
                "to hold across generations, not per file")
            # CONTROL: it must still be WRITING. A cap that works by dropping
            # everything passes both asserts above and records nothing.
            assert live > 0, f"{env} is capped because it writes nothing"

    def case_the_cut_line_says_how_much_each_reply_delivered(self, certdir):
        """`mid-response` CANNOT TELL A LIVE STREAM FROM A CORPSE.

        It means headers went out and nothing finished. A keepalive is bytes,
        so `_owed_still_moving` counts it as movement and the connection stays
        `mid-response` forever. Measured on host-a 2026-08-18: twelve logged as
        `12 mid-response` had delivered nothing but a fixed 39-byte frame for
        thirty minutes, and the reaper's "cheapest to lose" sort weighed those
        twelve corpses exactly as heavily as twelve live replies.

        PER CONNECTION, which is why this cannot come from `/proc/<pid>/io`:
        that is a process-wide rate and nobody could say how many connections
        the content was flowing on. `_StampingWriter` sees bytes attributed to
        one connection, so the count comes from there.

        AN INSTRUMENT ONLY. Nothing decides on this number yet; it exists so
        the population a threshold would be chosen from arrives in a log line
        rather than from somebody sampling at the right moment.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        err = io.StringIO()
        try:
            for sock in (a, c):
                with proxy._live_lock:
                    proxy._open_conns.add(sock)
                proxy._owe_answer(sock, True)
            # ONE CORPSE AND ONE LIVE REPLY, told apart only by volume: both
            # are owed, both are mid-response, both have moved recently.
            for _ in range(3):
                proxy._note_response_started(a, 39)
            proxy._note_response_started(c, 5000)

            with contextlib.redirect_stderr(err):
                proxy.await_inflight(0.0)
            line = err.getvalue()

            # MIN AND MAX, not the median: with two samples the middle is a
            # tie-break convention and asserting it would pin the formatter
            # rather than the fact. The fact is that the corpse and the live
            # reply land at opposite ends of the same line.
            # AND IT BELONGS TO THE DEBT. A keep-alive socket that has paid
            # and is waiting for its next request starts the next one at zero,
            # or a long-lived connection looks busier the longer it lives and
            # outranks a genuinely streaming one forever.
            proxy._owe_answer(a, False)
            proxy._owe_answer(a, True)
            with proxy._live_lock:
                carried = proxy._delivered.get(a, 0)
            assert carried == 0, (
                f"{carried} bytes carried across the debt boundary — the next "
                "request on this connection starts already looking busy")

            assert "delivered 117/" in line and "/5000 B min/med/max" in line, (
                "the cut line does not carry per-connection byte counts, so a "
                "reply that stopped thirty minutes ago is indistinguishable "
                "from one still streaming: " + line)
        finally:
            for s_ in (a, b, c, d):
                try: s_.close()
                except OSError: pass

    def case_the_accept_debt_survives_until_the_first_answer(self, certdir):
        """THE ACCEPT-TIME OWE WAS UNDONE ONE FRAME LATER.

        `accept` marks a connection OWED because a client that has connected
        is waiting on us whether or not its request bytes have arrived — added
        after `case_a_planned_restart_under_a_holder_loses_nothing` failed with
        "1 requests connected and were never answered".

        `_mitm`'s loop then cleared the debt at the TOP of every iteration,
        including the first, which runs after CONNECT and the TLS handshake
        and BEFORE `_read_line`. So for every MITM'd connection the accept-time
        debt was gone while the request was on the wire, and
        `inflight_requests()` reported zero for a client that was mid-request.

        BETWEEN requests it must still clear — that is the third unreachable
        zero, a keep-alive socket nobody waits on holding a drain — so this
        checks the boundary rather than the release.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        seen = []

        class _Ctx:
            def wrap_socket(self, sock, server_side=False):
                return sock

        def _one_request(tls, conn=None):
            seen.append(proxy.inflight_requests())
            return len(seen) < 2          # one served, then end the loop

        proxy._server_ctx = _Ctx()
        proxy._handle_one_request = _one_request
        try:
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)     # what `accept` does
            proxy._mitm(a)
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

        assert seen, "the loop never ran; the case proves nothing"
        assert seen[0] == 1, (
            "the accept-time debt was cleared before the first request line "
            "was even read, so a recycle drops a client whose request is on "
            f"the wire — inflight_requests() was {seen[0]}")
        assert len(seen) > 1 and seen[1] == 0, (
            "the debt was not released BETWEEN requests, so a keep-alive "
            f"socket nobody is waiting on holds the drain: {seen}")

    def case_the_relay_stamps_every_write_not_only_the_head(self, certdir):
        """THE WIRING, for the fourth time — and the first three were misses.

        `_blind_tunnel` never cleared its drain debt, the relay never marked a
        reply started, and `await_inflight` never announced it was draining.
        Each was a correct function nothing called, and each passed a suite
        that tested the function directly.

        Here the question is whether BODY bytes stamp, not just the head. A
        version that notifies once — which is exactly what `on_headers` did
        before this change — keeps every long reply looking frozen after its
        first chunk, so the stall window cuts it. That is the 600s bug back in
        a smaller window.
        """
        from cswap_pin.proxy import _relay_response

        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        stamps = []
        try:
            # PACED, because writing it all at once is not the case under test.
            # The first version of this sent the head and both events before
            # the relay read anything, so one `recv` took the lot and the whole
            # response went out in a single write — the assertion failed on a
            # premise, not on the code. A stream the drain has to survive
            # arrives in separate reads, so the upstream has to produce it that
            # way.
            def _upstream():
                up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                             b"Content-Type: text/event-stream\r\n\r\n")
                time.sleep(0.15)
                up_b.sendall(b"event: a\n\n")
                time.sleep(0.15)
                up_b.sendall(b"event: b\n\n")
                time.sleep(0.05)
                up_b.shutdown(socket.SHUT_WR)

            threading.Thread(target=_upstream, daemon=True).start()
            _relay_response(up_a, cl_a, 0,
                            on_headers=lambda n, c: stamps.append((time.monotonic(), n, c)))

            # AND THE SIZE IS REAL, not merely non-zero. The count is what
            # separates a live reply from one delivering a keepalive, so a
            # writer that reports every write as 0 bytes is the same defect as
            # one that does not report at all — and the sibling case that
            # drives `_note_response_started` directly cannot see it.
            sizes = [n for _, n, _c in stamps]
            assert all(n > 0 for n in sizes), (
                f"a write was reported as {min(sizes)} bytes: {sizes}")
            assert sum(sizes) >= len(b"event: a\n\n") + len(b"event: b\n\n"), (
                f"reported {sum(sizes)} bytes total, less than the body the "
                f"client actually received: {sizes}")

            assert len(stamps) >= 3, (
                f"the relay reported {len(stamps)} write(s). The head plus two "
                "body chunks is three: a relay that notifies only on the head "
                "leaves a streaming reply looking frozen from its second chunk "
                "onward, and the stall window then cuts it")
            # AND THE CLIENT REALLY GOT THE BODY, or a wrapper that notifies
            # and swallows would pass.
            cl_a.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                chunk = cl_b.recv(4096)
                if not chunk:
                    break
                got += chunk
            assert b"event: a" in got and b"event: b" in got, got[:120]
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

        # --- AND ONE WRAPPER PER RESPONSE, not one per interim head.
        # `client` is rebound to the `_StampingWriter` before the 1xx branch,
        # and that branch recursed with the wrapper AND the callback — so a
        # response preceded by two 103 Early Hints was written through three
        # nested writers, each stamping on the way down. The count is what
        # `_owed_still_moving` reads, and a stamp is also a lock acquisition.
        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        stamps = []
        try:
            def _with_interim():
                # Tolerant of the teardown race: the assertions below finish
                # first and the fixture closes these, which is not a failure.
                try:
                    up_b.sendall(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                    time.sleep(0.1)
                    up_b.sendall(b"HTTP/1.1 103 Early Hints\r\n\r\n")
                    time.sleep(0.1)
                    up_b.sendall(b"HTTP/1.1 200 OK\r\n"
                                 b"Content-Length: 5\r\n\r\nhello")
                    time.sleep(0.05)
                    up_b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            threading.Thread(target=_with_interim, daemon=True).start()
            _relay_response(up_a, cl_a, 0,
                            on_headers=lambda n, c: stamps.append(n))

            cl_a.shutdown(socket.SHUT_WR)
            got = b""
            while True:
                chunk = cl_b.recv(4096)
                if not chunk:
                    break
                got += chunk
            writes = got.count(b"HTTP/1.1")
            assert b"hello" in got, got[:160]
            assert len(stamps) <= writes + 1, (
                f"{len(stamps)} stamps for {writes} response head(s) plus a "
                "body — the interim recursion is nesting a writer per 1xx, so "
                "every byte of the real answer is stamped once per layer")
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

    def case_the_orphan_sweep_spares_a_daemon_that_is_draining(self, certdir):
        """THE FIFTH CAUSE, and it is two of my own fixes in direct opposition.

        `_spawn_daemon` runs `_sweep_orphan_daemons(keep_pid=<successor>)` the
        moment the successor is serving and recorded. A predecessor that handed
        the port on and is patiently finishing its replies is, to that filter,
        exactly "a pin daemon for this certdir that is not keep_pid".

        Measured on host-a 2026-08-18, the 0.1.100 rollout — one second between
        the two lines:

            08:21:19Z  pid=616877  serving on port 36301
            08:21:19Z  pid=2932386 stopping (signal SIGTERM)
            08:21:49Z  pid=2932386 cut 13 (13 mid-response, 0 before headers)

        AND THE HANDOVER CEILING IS WHAT MADE IT BITE. Before 0.1.99 the
        predecessor exited inside thirty seconds and the sweep usually found
        nothing; widening the wait twentyfold widened the window to be killed
        in. Each fix was right alone. Nothing in either said the other existed.

        THE POPULATIONS ARE GENUINELY DIFFERENT and the sweep's own docstring
        says so — it targets daemons that "hold ports and never idle-teardown".
        A drainer accepts nothing and exits by itself. So the fix is in the
        sweep, not in the drain, and NOT in making the drainer ignore SIGTERM:
        that would defeat a real supervisor and buy a SIGKILL at 32s, which
        cuts harder than the drain it was meant to protect.
        """
        import cswap_pin.proxy as pp

        killed = []
        real_kill = pp._kill_daemon
        real_pids = pp._pin_daemon_pids
        pp._kill_daemon = lambda pid: killed.append(pid)
        # A PREDECESSOR AND A REAL ORPHAN, so the case cannot pass by sparing
        # everything — which is the failure mode of a guard that only ever
        # removes a kill.
        pp._pin_daemon_pids = lambda certdir: [4242, 7777]
        try:
            pp.announce_draining(certdir, 4242)
            assert pp.is_draining(certdir, 4242) is True, "precondition"
            assert pp.is_draining(certdir, 7777) is False, "precondition"

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert 4242 not in killed, (
                "the sweep TERMed a daemon that had announced it was draining. "
                "That is the 08:21:19Z line: a handover that cut nothing, "
                "followed one second later by a signal that cut 13 replies")
            assert killed == [7777], (
                "a real orphan must still be killed — a sweep that spares "
                "everything is not a fix, it is a disabled sweep. "
                f"killed={killed}")

            # --- AND A PILE OF THEM IS A LEAK, which is the bound that
            # replaces the wall clock. ONE predecessor lingering three hours
            # on a box serving a three-hour reply is CORRECT behaviour, and a
            # per-process clock cannot tell it from a leak. A count can. The
            # quantity moved because the old one answered the wrong question,
            # not because the number was too small.
            killed.clear()
            pids = _fake_pids(5000, pp._MAX_DRAINING_PREDECESSORS + 2)
            pp._pin_daemon_pids = lambda certdir: list(pids)
            for i, pid in enumerate(pids):
                pp.announce_draining(certdir, pid)
                # OLDEST LAST, against the order they are enumerated in. Ages
                # ascending with the pid would make "take the first two" and
                # "take the two oldest" the same answer, and the ordering —
                # the only judgement this bound makes — would go untested.
                pp.draining_marker_path(certdir, pid).write_text(
                    str(time.time() - 1000 - i))

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert sorted(killed) == pids[-2:], (
                "with no ceiling on a drain, nothing else bounds a drainer "
                "that never finishes. Over the limit the sweep must take the "
                "ones draining LONGEST, and only the excess. "
                f"killed={killed}, oldest two are {pids[-2:]}")

            # --- AND AGE IS THE TIEBREAK, NOT THE RULE. Measured on host-a
            # 2026-08-18: a draining predecessor's connections carry a fixed
            # 39-byte frame at ~1/s (GCD exact across 17 samples), so EVERY
            # predecessor stays "moving" and age stops tracking doneness — it
            # tracks how long a reply has been RUNNING. Reaping longest-first
            # then takes the stream with the most work already sunk. Reap the
            # one with the FEWEST replies to lose.
            killed.clear()
            owed = {pids[0]: 9, pids[1]: 0, pids[2]: 1}
            for i, pid in enumerate(pids):
                # Oldest FIRST this time, so age alone would pick pids[0..1]
                # and only the owed counts can produce the expected answer.
                pp.announce_draining(certdir, pid)
                pp.beat_draining(certdir, pid, owed=owed.get(pid, 5))
                path = pp.draining_marker_path(certdir, pid)
                body = path.read_text().split("\n")
                body[0] = str(time.time() - 1000 + i)
                # ONE MARKER THAT DOES NOT SAY, and it is the OLDEST — written
                # by a version that recorded no count, or caught between the
                # announce and the first beat. Unknown must sort EXPENSIVE:
                # this orders what to kill, and a file we cannot read is not
                # permission to take the one that may be holding the most.
                if pid == pids[3]:
                    body = [str(time.time() - 2000)]
                path.write_text("\n".join(body))

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert sorted(killed) == sorted([pids[1], pids[2]]), (
                "the sweep reaped by age while every predecessor was equally "
                "alive. The cheapest one to lose is the one owing the fewest "
                f"replies. killed={killed}, owed={owed}")
            assert pids[3] not in killed, (
                "the sweep took the one marker that does not say what it "
                "would cost, and it was the oldest — an unknown count sorted "
                "as if it were cheap")

            # --- AND THE DEAD ONES' MARKERS ARE COLLECTED. A drainer that is
            # SIGKILLed cannot unlink its own, and every reap above produces
            # one. `is_draining` already stops honouring it past the TTL, so
            # this is litter rather than a safety hole — but it is litter in
            # the one directory a human reads while debugging a handover, and
            # the sweep already walks this exact set.
            import os as _os
            ghost = pp.draining_marker_path(certdir, 6001)
            ghost.write_text(str(time.time() - 9999))
            stale = time.time() - pp._DRAINING_MARKER_TTL - 1
            _os.utime(ghost, (stale, stale))
            live = pp.draining_marker_path(certdir, pids[0])
            pp._pin_daemon_pids = lambda certdir: [pids[0]]

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert not ghost.exists(), (
                "a marker whose writer is long gone survived the sweep. One "
                "per hard-killed daemon accumulates forever in the directory "
                "somebody opens to find out what a handover did")
            assert live.exists(), (
                "the sweep collected a marker that is still being beaten — "
                "that is a live drainer losing its protection mid-reply")

            # --- AND A PREDECESSOR CARRYING A BRIDGE IS NOT PART OF THE PILE.
            # It has zero live replies — its remaining job is a held-open
            # subscription, not an answer — so every rule above scored it as
            # the CHEAPEST thing on the box and it was always the one taken.
            # That is the one cut a session cannot recover from by itself:
            # claude.ai pushes through that stream, and the client does not
            # get it back without reconnecting.
            killed.clear()
            pids = _fake_pids(8000, pp._MAX_DRAINING_PREDECESSORS + 2)
            pp._pin_daemon_pids = lambda certdir: list(pids)
            for i, pid in enumerate(pids):
                pp.announce_draining(certdir, pid)
                # EVERY ONE CHEAP BY THE OLD RULES, so only the subscription
                # count can produce the expected answer. The two WITHOUT one
                # are the youngest, so age cannot pick them either.
                pp.beat_draining(certdir, pid, owed=0, live=0, quiet=0.0,
                                 streams=0 if i >= len(pids) - 2 else 3)
                path = pp.draining_marker_path(certdir, pid)
                body = path.read_text().split("\n")
                body[0] = str(time.time() - 1000 - i)
                path.write_text("\n".join(body))

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert sorted(killed) == sorted(pids[-2:]), (
                "the sweep took a predecessor still delivering a held-open "
                "subscription while stream-less ones were available. Every "
                "other cost here can be retried; that one cannot be reopened "
                f"by the session that lost it. killed={killed}")

            # AND WHEN THERE IS NOTHING CHEAP TO TAKE, IT TAKES NOTHING. A
            # reaper with no safe choice must say so, not pick the least-bad
            # session to cut.
            killed.clear()
            for pid in pids:
                pp.beat_draining(certdir, pid, owed=0, live=0, quiet=0.0,
                                 streams=2)

            pp._sweep_orphan_daemons(certdir, keep_pid=999)

            assert killed == [], (
                "over the limit with every predecessor carrying a bridge, the "
                f"sweep still cut one. killed={killed}")
        finally:
            pp._kill_daemon = real_kill
            pp._pin_daemon_pids = real_pids

    def case_two_teardowns_at_once_do_not_unprotect_each_other(self, certdir):
        """MEASURED, SAME PID, SAME SECOND — both terminators fired.

            08:41:19Z pid=616877 stopping (refcount)
            08:41:19Z pid=616877 stopping (signal SIGTERM)
            08:41:49Z pid=616877 cut 14 (14 mid-response, 0 before headers)

        Two teardowns in one process means two `stop()` calls, two drains, and
        two announcements. They take DIFFERENT ceilings by design — refcount
        600s, signal 30s — so the short one finishes first, and the first
        version of the marker had it unlink the file out from under the drain
        still waiting. That hands the sweep exactly the process the marker
        exists to protect, at the moment it is most exposed.

        The bug was one hour old and its evidence was already in the log that
        motivated the marker. Counted rather than flagged: the LAST release
        removes it.
        """
        import cswap_pin.proxy as pp

        first = pp.announce_draining(certdir, 4242)   # the long, still waiting
        second = pp.announce_draining(certdir, 4242)  # the short, about to end
        assert pp.is_draining(certdir, 4242) is True, "precondition"

        second()
        assert pp.is_draining(certdir, 4242) is True, (
            "the short drain's release unprotected the long one that is still "
            "running — the sweep can now TERM a daemon mid-reply, which is the "
            "whole fault this marker was added for")

        first()
        assert pp.is_draining(certdir, 4242) is False, (
            "the marker outlived every drain that announced it, so a genuine "
            "orphan on this pid is spared until the TTL expires")

        # A CALLER THAT RELEASES TWICE MUST NOT SPEND SOMEBODY ELSE'S COUNT.
        # The first version of this assertion released twice AFTER everything
        # had already released, where `dict.get(key, 1) - 1` lands on zero
        # either way — so the mutation that removes the idempotence guard
        # SURVIVED it. Tested where it can fail: a second drain is still
        # running, and the double release must not take the count to zero
        # under it.
        long_drain = pp.announce_draining(certdir, 4242)
        short_drain = pp.announce_draining(certdir, 4242)
        short_drain()
        short_drain()      # the same caller, twice
        assert pp.is_draining(certdir, 4242) is True, (
            "one caller's double release spent the OTHER drain's count and "
            "unlinked the marker while it was still waiting — the sweep can "
            "now TERM it mid-reply")
        long_drain()
        assert pp.is_draining(certdir, 4242) is False

    def case_the_handover_announces_before_the_successor_can_exist(self, certdir):
        """ANNOUNCING WHEN THE DRAIN STARTS IS ONE STEP TOO LATE.

        `await_inflight` announces, and at the fd-handdown site it runs AFTER
        `_spawn_daemon` returns. The successor publishes `proxy.json` the
        instant it serves, so from that publish until the predecessor reaches
        the drain, `read_daemon_state` names the successor as keep_pid while
        the predecessor has written no marker. Any concurrent `ensure_proxy`
        sweeps in that window and TERMs a daemon that is about to finish its
        replies — the 08:21:19Z race through a door one frame higher.

        Same shape at the ask-the-holder site: the holder spawns the successor
        while we are still sleeping out `_ASK_SETTLE_SECONDS`.

        READ OUT OF THE SOURCE because the property is an ORDERING, and the
        window is a few hundred milliseconds wide on a machine that has to be
        recycling and launching at the same moment to show it.
        """
        import inspect
        import cswap_pin.proxy as pp

        src = inspect.getsource(pp._watch_own_code)
        ask = src.find("_REPLACE_ME_SIGNAL")
        spawn = src.find("_spawn_daemon(")
        assert -1 not in (ask, spawn) and ask < spawn, (
            "the scan is broken: it assumes the ask-the-holder site precedes "
            f"the fd-handdown site in this function. ask={ask} spawn={spawn}")

        # ONE PER SITE, and the case must fail if EITHER is removed — a single
        # "an announce exists somewhere above" check passes with the second
        # site unprotected, because the first site's call is above both.
        before_ask = src.rfind("announce_draining", 0, ask)
        assert before_ask != -1, (
            "nothing announces before the holder is asked to replace us. The "
            "holder spawns the successor on that signal, and the successor's "
            "publish is what makes this daemon sweepable")
        between = src.rfind("announce_draining", ask, spawn)
        assert between != -1, (
            "nothing announces between the ask and `_spawn_daemon`, so the "
            "fd-handdown site is protected only from inside `await_inflight` "
            "— which runs after the spawn has already published a successor")

    def case_the_drain_is_what_announces_itself(self, certdir):
        """THE WIRING, and it is the third time tonight the guard was orphaned.

        The sibling cases call `announce_draining` themselves, so removing the
        call from `await_inflight` leaves them green — a correct function that
        nothing invokes, which is the exact shape of `_blind_tunnel` never
        clearing its debt and of the relay never marking a reply started.

        ANNOUNCED INSIDE `await_inflight` ON PURPOSE. There are four exit paths
        that drain and tonight's whole bug list is fixes that landed on some
        paths and not the one that mattered, so the announcement lives in the
        one function all four go through. This case is what makes that claim
        checkable rather than aspirational.
        """
        import cswap_pin.proxy as pp

        calls, released = [], []
        real = pp.announce_draining

        def _spy(certdir_arg, pid=None):
            calls.append(Path(certdir_arg))
            done = real(certdir_arg, pid)
            return lambda: (released.append(True), done())[1]

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        pp.announce_draining = _spy
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(0.0)
        finally:
            pp.announce_draining = real

        assert calls, (
            "the drain did not announce itself, so the orphan sweep will TERM "
            "this daemon while it is finishing replies — the 08:21:19Z line")
        assert calls[0] == Path(certdir), (
            f"announced against the wrong certdir: {calls[0]} != {certdir}. A "
            "marker under another daemon's directory protects nobody")
        assert released, (
            "the marker was never removed. It expires on a TTL, so this is not "
            "a leak that lasts — but until it does, a genuinely orphaned pin "
            "daemon on that pid is spared by a sweep that should have taken it")

    def case_a_draining_marker_does_not_outlive_its_writer(self, certdir):
        """A SIGKILLED DRAINER CANNOT CLEAN UP AFTER ITSELF, and pids are reused.

        The marker's only power is to spare a process, so a stale one is a
        pin daemon that never gets swept — the orphan this sweep exists for,
        wearing a dead process's badge. Past the TTL the answer goes back to
        what it was before any of this existed, which is the safe direction.
        """
        import cswap_pin.proxy as pp

        import os

        pp.announce_draining(certdir, 4242)
        assert pp.is_draining(certdir, 4242) is True

        # STALE MEANS UNTOUCHED, NOT OLD, and that distinction is the change.
        # A handover drain has no ceiling any more, so age cannot mean
        # abandoned — a drain that has run three hours because a reply has run
        # three hours is healthy. Only silence separates them.
        path = pp.draining_marker_path(certdir, 4242)
        old_t = time.time() - pp._DRAINING_MARKER_TTL - 1
        os.utime(path, (old_t, old_t))
        assert pp.is_draining(certdir, 4242) is False, (
            "a marker nothing has touched since before the TTL still protected "
            "a pid — an orphan inheriting that number would never be swept")

        # AND A BEAT BRINGS IT BACK. This is what lets a drain outlive its own
        # marker TTL: an hour-long reply keeps its protection by SAYING SO
        # every few seconds, not by having been handed a big enough number in
        # advance. Every number handed out in advance tonight was wrong.
        pp.beat_draining(certdir, 4242)
        assert pp.is_draining(certdir, 4242) is True, (
            "a beat did not refresh the marker, so a long drain loses its "
            "protection mid-reply and the sweep TERMs it — the 08:21:19Z line "
            "again, with the clock moved from the drain into the marker")

        # AND AN UNWRITABLE MARKER MUST NOT BREAK THE DRAIN. Failing open here
        # means the outcome is exactly what it was before this existed; failing
        # closed would mean a drain that cannot start.
        done = pp.announce_draining(Path("/nonexistent-dir-for-a-marker"), 1)
        done()

    def case_a_refcount_shutdown_is_not_a_recycle_and_not_a_signal(self, certdir):
        """THE FOURTH EXIT PATH, found by fixing the other three.

        Measured on host-a, the 0.1.99 rollout, in this order:

            08:04:18Z  handover — NO drain line at all. The departing daemon
                       handed the port on and kept living, which is what
                       `_HANDOVER_DRAIN_SECONDS` is for. Nothing cut.
            08:08:18Z  `stopping (refcount)` on that same lingering daemon,
                       cut 13 (13 mid-response, 0 before headers), 30s budget.

        So the handover stopped costing anything and a shutdown four minutes
        later cost the same as before. The cost was MOVED, not removed — which
        is only visible because the other three were fixed first.

        WHAT EACH ARM IS REALLY ASKING is who is waiting for this process to be
        gone, and the three answers are genuinely different:

          held      the holder cannot put the successor on the socket until we
                    exit, so waiting is unserved port time
          signal    a supervisor is counting `_DRAIN_SECONDS + 2` and then
                    SIGKILLs. Waiting past that does not save a reply, it
                    guarantees a harder kill partway through one
          refcount  nobody is waiting at all: no successor, no supervisor, and
                    the listener is already released so a fresh daemon could
                    bind now

        THE SIGNAL ROW IS THE ONE THAT MATTERS MOST, because "a shutdown is a
        shutdown" would give it the long ceiling and make things WORSE than
        before — a SIGKILL at 32 seconds cuts harder than an orderly drain.
        """
        from cswap_pin.proxy import (
            teardown_drain_budget,
            _DRAIN_SECONDS,
            _HANDOVER_DRAIN_SECONDS,
            _HELD_DRAIN_SECONDS,
        )

        assert teardown_drain_budget("refcount", False) == _HANDOVER_DRAIN_SECONDS, (
            "a refcount shutdown cut 13 mid-response replies on the short "
            "ceiling. Nobody is waiting for this process — no successor, no "
            "supervisor — so the only cost of waiting is finishing what it owes")

        assert teardown_drain_budget("signal TERM", False) == _DRAIN_SECONDS, (
            "a signalled shutdown took the long ceiling. The supervisor "
            "SIGKILLs at _DRAIN_SECONDS + 2, so draining past it cuts a reply "
            "harder than an orderly drain would have")
        assert teardown_drain_budget("signal INT", False) == _DRAIN_SECONDS

        # HELD WINS OVER EVERY REASON, including refcount: the holder is
        # blocked on our exit whatever brought us here.
        assert teardown_drain_budget("refcount", True) == _HELD_DRAIN_SECONDS, (
            "a held shutdown took a ceiling other than the held one — that is "
            "unserved port time, however the shutdown started")
        assert teardown_drain_budget("signal TERM", True) == _HELD_DRAIN_SECONDS

        # ...UNLESS THE SUCCESSOR IS ALREADY SERVING, and that is the whole
        # premise of the held arm rather than a corner of it. Its reasoning is
        # "the holder cannot put the successor on the socket until we are
        # gone", which was true before the replace-ask existed and is FALSE
        # for a daemon that has already handed over: `_watch_own_code` asks,
        # verifies the holder survived, and the successor is serving on the
        # same socket while this process drains.
        #
        # MEASURED ON host-b 2026-08-18, and this is what it cost:
        #   20:01:32Z pid=96075 code on disk changed — asked the holder to
        #             replace us while we keep serving      (uncapped drain)
        #   20:01:32Z pid=25445 serving on port 53749       (successor is UP)
        #   20:02:01Z pid=96075 stopping (refcount)         (second drain)
        #   20:02:31Z pid=96075 cut 4 in-flight request(s) after 30.1s of a
        #             30s budget (4 mid-response, content-free 0/2/9 s)
        # Four replies, every one still delivering — the content-free field is
        # what proves that; `4 mid-response` alone cannot tell a live stream
        # from one that stopped. The uncapped handover ceiling was overridden
        # by a second drain that re-armed a clock the first had removed.
        assert teardown_drain_budget(
            "refcount", True, handed_over=True) == _HANDOVER_DRAIN_SECONDS, (
            "a daemon that had already handed over took the held ceiling. "
            "Its successor is on the socket, so there is no unserved port "
            "time to buy, and the 30s bought instead cut four live replies")
        # THE SIGNAL ROW DOES NOT MOVE. A supervisor still SIGKILLs at
        # _DRAIN_SECONDS + 2 whether or not we handed over, so a long ceiling
        # here still buys a harder kill partway through a reply.
        #
        # ASSERTED AGAINST THE UNCAPPED CEILING, not against `_DRAIN_SECONDS`.
        # `_HELD_DRAIN_SECONDS IS _DRAIN_SECONDS` (both 30.0), so `== _DRAIN_
        # SECONDS` passes with the handed-over guard, without it, and with it
        # inverted — a verdict it can never produce. What can actually go wrong
        # here is the row going UNCAPPED, so that is what is pinned.
        assert teardown_drain_budget(
            "signal TERM", True, handed_over=True) != _HANDOVER_DRAIN_SECONDS, (
            "a signalled shutdown took the uncapped ceiling; the supervisor "
            "SIGKILLs at _DRAIN_SECONDS + 2, so waiting past it buys a harder "
            "kill partway through a reply rather than a finished one")
        assert teardown_drain_budget(
            "signal TERM", True, handed_over=True) == _DRAIN_SECONDS

    def case_a_pin_names_itself_in_the_live_config(self, certdir, tmp_path,
                                                   monkeypatch):
        """A pin that does not SPLICE does nothing until the next switch.

        `apply_pin` saved the record, wired the proxy env and started the
        daemon, and never wrote `oauthAccount` — the field Claude Code reads to
        decide who OWNS a bridge. The only writer was cswap's switch, so a pin
        set while another account was active left the config naming THAT
        account, and every bridge minted afterwards belonged to it.

        MEASURED on a live machine before this: pin=slot 1,
        `~/.claude.json`=slot 4, and cswap's own bridge-owner check reporting
        "all 13 live bridge pointers match the current login" — the current
        login, not the pin. Re-running `cswap pin` did not move it.

        THE RULE IS HERE, THE LOOKUP IS NOT. Which identity to write means
        reading cswap's backup store, whose layout this package must not know,
        so it arrives as an argument.
        """
        import json

        import cswap_pin.proxy as pp

        cfg = tmp_path / "claude.json"
        cfg.write_text(json.dumps({
            "oauthAccount": {"emailAddress": "active@example.com",
                             "organizationUuid": "org-ACTIVE"},
            "env": {"HTTPS_PROXY": "http://127.0.0.1:1"},
        }))
        # PATCH THE SEAM, not a name this module does not own: the path is
        # fetched through `require("paths")` at call time.
        import types
        monkeypatch.setattr(
            pp, "require",
            lambda name, _r=pp.require: (
                types.SimpleNamespace(get_global_config_path=lambda: cfg)
                if name == "paths" else _r(name)))

        want = {"emailAddress": "pinned@example.com",
                "organizationUuid": "org-PIN", "accountUuid": "uuid-PIN"}
        assert pp.splice_config_identity(want) is True, (
            "setting a pin did not name it in the live config, so Claude Code "
            "keeps minting bridges under the ACTIVE account and the pin is "
            "inert until the next switch")
        after = json.loads(cfg.read_text())
        assert after["oauthAccount"] == want
        assert after["env"] == {"HTTPS_PROXY": "http://127.0.0.1:1"}, (
            "the splice rewrote a field that belongs to Claude Code; only "
            "oauthAccount is ours to touch")

        # IDEMPOTENT. Every live session watches this file, so a rewrite that
        # changes nothing is a wake-up for all of them.
        assert pp.splice_config_identity(want) is False

        # NOTHING TO WRITE IS NOT AN ERROR — no pin, or a lookup that failed.
        assert pp.splice_config_identity(None) is False

        # AND A CONFIG WE CANNOT PARSE IS LEFT FOR ITS OWNER.
        for bad in ("[]", "null", '"a string"', "{torn"):
            cfg.write_text(bad)
            assert pp.splice_config_identity(want) is False, (
                f"a {bad!r} config was rewritten; a file we do not understand "
                "is one we must not touch")
            assert cfg.read_text() == bad

        # AND apply_pin IS THE PATH THAT CARRIES IT. Reaching a real apply_pin
        # needs a switcher and a daemon, so read the wiring out of the source.
        import inspect

        src = inspect.getsource(pp.apply_pin)
        assert "splice_config_identity(identity)" in src, (
            "apply_pin does not name the pin in the config, so the rule exists "
            "and nothing calls it")
        assert "identity" in inspect.signature(pp.apply_pin).parameters, (
            "apply_pin cannot be handed an identity, so cswap has no way to "
            "pass the one it looked up")

    def case_the_armed_trace_can_see_the_tunnel(self, certdir):
        """An armed trace was blind to the one path that fails.

        `trace-to` arms `self._debug`, which only the MITM request path wrote.
        `_blind_tunnel` wrote to `_TRACE`, a module global opened once at
        import from `CSWAP_PIN_DEBUG` and unreachable afterwards. So a trace
        armed on a running daemon recorded every route Claude Code SENDS and
        nothing about the channel it RECEIVES on — which is the outage the
        comment at that very site describes.

        MEASURED WITH A CONTROL before the fix: a real CONNECT driven through
        a live pin produced ZERO lines in an armed trace. The zero was the
        instrument.
        """
        import cswap_pin.proxy as pp

        out = certdir / "armed-trace.log"
        (certdir / pp._TRACE_SWITCH_FILE).write_text(str(out))
        pp._TRACE_CACHE.clear()

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        proxy._tunnel_trace("CONNECT example:443 tunnelled")
        assert out.exists() and "CONNECT example:443" in out.read_text(), (
            "the tunnel path does not write to the armable trace, so an "
            "incident can only be traced by restarting the daemon — which "
            "ends the very connections being investigated")

        # AND ALL THREE TUNNEL SITES GO THROUGH IT, not just the one above.
        # Reaching them needs a real chain, so read it out of the source.
        import inspect

        src = inspect.getsource(pp.PinProxy._blind_tunnel)
        assert "_TRACE.write" not in src, (
            "a tunnel line still writes straight to the import-time global, "
            "so that line is invisible to a trace armed during an incident")
        assert src.count("self._tunnel_trace(") >= 3, (
            f"only {src.count('self._tunnel_trace(')} tunnel site(s) use the "
            "shared writer; the others are blind to an armed trace")

    def case_every_beat_keeps_the_channel_count(self, certdir):
        """The beat REWRITES the marker, so a beat that omits the channel
        count erases the reap protection.

        The first beat wrote the fifth line and the periodic one, 15 seconds
        later, wrote a four-line marker over it — so a daemon carrying a bridge
        looked like a daemon carrying nothing to the sweep that decides what to
        kill. The protection lasted one interval.

        MEASURED ON A LIVE MARKER while this was shipped: pid draining with 13
        replies owed, 13 live, and no fifth line.
        """
        import cswap_pin.proxy as pp

        pid = 918273
        pp.announce_draining(certdir, pid)
        pp.beat_draining(certdir, pid, owed=3, live=3, quiet=1.0, streams=7)
        assert pp.draining_streams(certdir, pid) == 7, (
            "the marker does not carry the channel count at all")

        # THE SECOND BEAT IS THE ONE THAT USED TO ERASE IT.
        pp.beat_draining(certdir, pid, owed=3, live=2, quiet=2.0, streams=7)
        assert pp.draining_streams(certdir, pid) == 7, (
            "a later beat dropped the channel count, so the reaper reads zero "
            "and takes the daemon carrying the bridge — the protection lasts "
            "one beat interval")

        # AND THE DRAIN'S OWN PERIODIC BEAT MUST PASS IT. Reaching that line
        # needs a live daemon mid-drain, so read it out of the source, which is
        # the convention this file uses for the exit paths.
        import inspect

        src = inspect.getsource(pp.PinProxy.await_inflight)
        beats = src.count("beat_draining(")
        passes = src.count("streams=")
        assert beats > 0 and passes == beats, (
            f"{beats} beat(s) in the drain but {passes} pass the channel "
            "count; the ones that do not erase it on their next write")

    def case_the_pump_can_say_what_the_process_is_carrying(self, certdir):
        """The reaper needs the PROCESS's tunnel count, and only the marker
        can carry it — the sweep runs somewhere else.

        A daemon whose only remaining job is a bridge WebSocket owes no reply,
        so every cost the reaper weighs scored it as the cheapest thing on the
        box and it was always the one taken. That is the reap no session can
        recover from by itself.

        THE COUNT IS PROCESS-WIDE, THE PROXY'S IS NOT. `_PUMP` drives every
        tunnel in the process; folding it into `live_stream_count` made one
        proxy report another's, measured on a single-process runner as 2 where
        1 was expected. The proxy counts its own subscriptions; the marker adds
        the pump's pairs, because the marker describes the process.
        """
        import socket

        import cswap_pin.proxy as pp
        from cswap_pin.proxy import _PUMP, PinProxy

        a, b = socket.socketpair()
        try:
            before = _PUMP.live_pairs()
            _PUMP.add(a, b)
            assert _PUMP.live_pairs() == before + 1, (
                "the pump cannot say how many tunnels it drives, so the "
                "marker cannot tell the reaper this daemon is carrying one")
        finally:
            for s_ in (a, b):
                try:
                    s_.close()
                except OSError:
                    pass

        # AND THE PROXY'S OWN COUNT STAYS ITS OWN.
        proxy = PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                         upstream=("127.0.0.1", 1))
        c, d = socket.socketpair()
        try:
            _PUMP.add(c, d)
            assert proxy.live_stream_count() == 0, (
                "a proxy with no subscriptions of its own reported the "
                "process's tunnels, so one proxy speaks for another")
        finally:
            for s_ in (c, d):
                try:
                    s_.close()
                except OSError:
                    pass

        # AND THE DRAIN MUST WAIT FOR THEM. A daemon whose tunnels are its
        # only remaining work owes nothing — `_mitm` hands a tunnel's debt back
        # at the 101 — so without this it leaves at once and the tunnels die
        # with the process. Measured on the fleet: pid 423760 owed nothing,
        # drained "clean" in 0.0s and took four open connections with it, while
        # pid 1452400 owed a stream, stayed, and kept fourteen channels.
        #
        # AND IT MUST END. `live_pairs()` alone has no exit — a wedged peer
        # keeps its entry for ever — so it is bounded on SILENCE, the same
        # discriminator the reply wait uses.
        import inspect

        src = inspect.getsource(pp.PinProxy.await_inflight)
        assert "while (_PUMP.live_pairs()" in src, (
            "the drain does not wait for live tunnels, so a recycle drops "
            "every Remote Control channel this daemon is pumping")
        i = src.index("while (_PUMP.live_pairs()")
        assert "_PUMP.quiet_for() <= _DRAINING_MARKER_TTL" in src[i:i + 200], (
            "the tunnel wait has no exit: a tunnel whose peer wedged holds "
            "this process open for ever, which is the never-ending drain the "
            "removed wall clock used to bound")
        assert 'budget == float("inf")' in src[:i], (
            "the tunnel wait is not confined to the uncapped arm. The signal "
            "arm has a supervisor counting to `_DRAIN_SECONDS + 2`, so waiting "
            "past it buys a harder kill; the held arm holds the port dark")

        # AND THE PUMP CAN BE ISOLATED, or this suite measures leftovers. The
        # macOS runner is single-process, so without a per-case reset one
        # case's tunnels are counted by the next one's proxy.
        assert hasattr(_PUMP, "reset_for_tests"), (
            "nothing can clear the shared pump between cases, so a leftover "
            "tunnel makes one case fail about another case's state")
    def case_a_drain_does_not_cut_the_subscription(self, certdir):
        """The channel a session cannot reopen for itself must survive a recycle.

        A drain used to close every held-open `/worker/events/stream` on the
        grounds that it never completes, so waiting for it waits for ever. The
        premise behind the harm — that holding one stamps `Connection: close`
        on enough other replies to matter — did not survive measurement: the
        banner was observed with NOTHING draining, and a departing daemon has
        released its listener, so the only replies left are on keep-alives that
        migrate after one each.

        What the cut did buy was a hard disconnect of the bridge's inbound
        stream. A DRAINING DAEMON STILL SERVES WHAT IT ALREADY HOLDS — it gave
        up the listener, not its connections — so leaving the stream alone
        keeps the session working on the departing process for as long as it
        lasts. That is what shipped before 0.1.125 and it is what this guards.

        The cost is a process that lingers. That is the session still working,
        not a leak, and `live_stream_count` is how the drain line says so.
        """
        import socket
        import threading

        from cswap_pin.proxy import PinProxy, _EVENT_STREAM

        assert _EVENT_STREAM.search(
            "GET /v1/code/sessions/cse_x/worker/events/stream HTTP/1.1"), (
            "the one request that never completes is not recognised, so the "
            "drain line cannot say what is holding it")
        assert not _EVENT_STREAM.search(
            "POST /v1/code/sessions/cse_x/worker/events HTTP/1.1"), (
            "the ordinary event POST was taken for a subscription")

        proxy = PinProxy.__new__(PinProxy)
        proxy._live_lock = threading.Lock()
        proxy._stream_conns, proxy._open_conns = set(), set()
        a, b = socket.socketpair()
        c, d = socket.socketpair()
        try:
            # A SUBSCRIPTION THAT ALREADY FINISHED, still remembered. Its
            # descriptor is gone and the NUMBER has been handed to something
            # else, so counting it names a connection that is not ours.
            c.close()
            d.close()
            proxy._stream_conns.add(c)
            proxy._stream_conns.add(a)
            proxy._open_conns.add(a)
            assert proxy.live_stream_count() == 1, (
                "the count is taken from the stream set alone, so it reports a "
                "connection whose descriptor has been reused")

            # AND THE PEER MUST NOT SEE EOF WHEN A REAL DRAIN RUNS. Asserting
            # on names — no `release_subscriptions`, no `_end_connection` —
            # only holds until somebody writes the cut under a third name.
            # This asks the property instead: run the drain, then read the far
            # end. A cut gives EOF; an intact stream gives a timeout.
            real = PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
            # THE FINAL CATCH-ALL IS A NO-OP IN PRODUCTION, so it is one here.
            # `_close_open_connections` shuts down every open connection as
            # the drain's last act, and for a MITM'd connection it reaches the
            # RAW socket that `wrap_socket` detached — `fileno()` is -1 and
            # the close does nothing. That no-op is load-bearing and its own
            # guard covers it. A plain socketpair is NOT detached, so leaving
            # the call in makes this case measure a cut that cannot happen on
            # the real object. The question here is the DELIBERATE cut.
            real._close_open_connections = lambda: None
            e, f = socket.socketpair()
            with real._live_lock:
                real._open_conns.add(e)
                real._stream_conns.add(e)
            try:
                real.await_inflight(0.0)
                f.settimeout(1.0)
                try:
                    got = f.recv(1)
                except (TimeoutError, OSError):
                    got = None            # still open — nothing cut it
                assert got is None, (
                    "the drain closed a held-open subscription. That is the "
                    "channel claude.ai pushes through, and the session cannot "
                    "reopen it for itself")
            finally:
                for s_ in (e, f):
                    try:
                        s_.close()
                    except OSError:
                        pass

            # AND NOTHING CLOSES IT. Reaching a real drain needs a live daemon,
            # so read it out of the source — the convention this file already
            # uses for the exit paths.
            import ast
            import inspect

            import cswap_pin.proxy as pp

            src = inspect.getsource(pp)
            assert "_end_connection" not in src, (
                "the apparatus that made the cut real is back. Closing the "
                "TLS object really does end the connection, and the one it "
                "ends is the bridge's inbound stream")
            tree = ast.parse(src)
            drains = [n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef)
                      and n.name == "await_inflight"]
            assert drains, "await_inflight moved; this guard is blind"
            closers = {c_.func.attr for d_ in drains for c_ in ast.walk(d_)
                       if isinstance(c_, ast.Call)
                       and isinstance(c_.func, ast.Attribute)}
            assert "release_subscriptions" not in closers, (
                "the drain cuts subscriptions again, so every recycle drops "
                "the channel claude.ai pushes through and the session stops "
                "receiving until it reconnects")

            # AND THE MARK IS FORGOTTEN WHEN THE REPLY THAT SET IT ENDS,
            # or the set grows for the life of the daemon and fills with
            # sockets whose descriptors have been reused.
            paid = src.find("self._note_reply_finished(conn)")
            assert paid != -1, "the debt boundary moved; this guard is blind"
            assert "self._stream_conns.discard(conn)" in src[paid:paid + 700], (
                "the subscription mark outlives the reply that set it")
        finally:
            for s_ in (a, b, c, d):
                try:
                    s_.close()
                except OSError:
                    pass
    def case_a_successor_on_the_port_means_nobody_waits_for_us(self, certdir):
        """`handed_over` asks "did I hand over"; the budget needs "is anyone
        waiting for me to be gone". Those differ for a daemon superseded from
        OUTSIDE, and that daemon is the one that pays.

        Measured: a holder took the replace signal and spawned a successor,
        which served the same port from 01:44:13Z. The predecessor had
        announced no drain of its own, so `this_process_is_draining()` was
        False, the held arm fired, and its refcount teardown at 01:47:19Z cut
        13 mid-response replies on a 30s ceiling while the successor was three
        minutes into serving. The uncapped refcount arm below it is
        unreachable for a held daemon, so nothing else could have caught this.
        """
        import os
        import subprocess

        from cswap_pin.proxy import _superseded_on_the_port, write_daemon_state

        assert _superseded_on_the_port(certdir) is False, (
            "no record at all read as a successor")

        write_daemon_state(certdir, 40404, os.getpid(), "fp")
        assert _superseded_on_the_port(certdir) is False, (
            "the record naming US read as a successor — every teardown would "
            "take the uncapped ceiling with nothing behind the port")

        live = subprocess.Popen(["sleep", "30"])
        try:
            write_daemon_state(certdir, 40404, live.pid, "fp")
            assert _superseded_on_the_port(certdir) is True, (
                "a live successor on the record read as absent — the held arm "
                "fires and cuts whatever this daemon still owes")
        finally:
            live.kill()
            live.wait()

        write_daemon_state(certdir, 40404, live.pid, "fp")
        assert _superseded_on_the_port(certdir) is False, (
            "a reaped pid on the record read as a live successor — that is an "
            "uncapped drain with nothing serving the port")

        # AND THE TEARDOWN MUST ACTUALLY ASK IT. The predicate above is right
        # in isolation whether or not anything calls it, so the assertions so
        # far cannot fail on the bug they describe. Read out of the source
        # because `_teardown` is a closure inside `daemon_main` and reaching it
        # needs a live daemon, its sockets and its state file — a harness that
        # reconstructs those can be wrong in its own right.
        import ast
        import inspect

        import cswap_pin.proxy as pp

        asked = None
        for node in ast.walk(ast.parse(inspect.getsource(pp))):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "teardown_drain_budget"):
                for kw in node.keywords:
                    if kw.arg == "handed_over":
                        asked = {n.func.id for n in ast.walk(kw.value)
                                 if isinstance(n, ast.Call)
                                 and isinstance(n.func, ast.Name)}
        assert asked == {"this_process_is_draining", "_superseded_on_the_port"}, (
            "the teardown no longer asks both ways a daemon can owe nothing. "
            "Its own marker covers the handover it announced; a successor the "
            "holder started leaves nothing announced here at all, and the "
            "held arm then cuts every reply still in flight. Got: " + str(asked)
        )

    def case_each_exit_path_drains_on_the_ceiling_that_fits_it(self, certdir):
        """THREE DRAINS, TWO SITUATIONS — and they were collapsed into one number.

        Measured 2026-08-18, all three hosts, with the phase split live:

            host-a  cut 16   (16 mid-response, 0 before headers)
            wmac   cut  3   ( 3 mid-response, 0 before headers)
            pmac   drained clean

        Zero "before headers" anywhere, so those are replies that had already
        begun streaming to a user and did not finish inside thirty seconds. The
        drain was working; the ceiling was wrong.

        THE TWO SITUATIONS ARE NOT INTERCHANGEABLE:

          successor already serving  the holder spawned it, or we handed the
                                     listening socket down by fd. This process
                                     accepts nothing and nobody is waiting on
                                     it, so waiting costs one idle process and
                                     nothing else -> `_HANDOVER_DRAIN_SECONDS`.

          holder respawns after us   the holder cannot start the successor
                                     until we are gone, so every second here is
                                     a second with nothing serving the port.
                                     Cutting is the lesser evil
                                     -> `_HELD_DRAIN_SECONDS`.

        AND `_DRAIN_SECONDS` COULD NOT SIMPLY BE RAISED, which is why this is a
        third constant rather than a bigger one: it is also the supervisor's
        patience (`proc.wait(timeout=_DRAIN_SECONDS + 2)`, the SIGKILL
        escalation, the stop poll). Raising it makes every teardown wait ten
        minutes for a process that is not coming back.

        Read out of the source because the property IS the wiring. A behavioural
        test would have to run for ten minutes to tell 600 from 30, and the
        regression this guards is somebody tidying three constants into one.
        """
        import ast
        import inspect
        import cswap_pin.proxy as pp

        tree = ast.parse(inspect.getsource(pp))
        named = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "await_inflight"
                    and node.args
                    and isinstance(node.args[0], ast.Name)
                    # CONSTANTS ONLY. `stop()` forwards its own `drain`
                    # parameter through here, and a parameter says nothing
                    # about which ceiling an exit path chose.
                    and node.args[0].id.isupper()):
                named.append(node.args[0].id)

        assert named, (
            "no `await_inflight(<CONSTANT>)` call found at all — the scan is "
            "broken, and a broken scan passes every assertion below it")
        assert sorted(named) == [
            "_HANDOVER_DRAIN_SECONDS", "_HANDOVER_DRAIN_SECONDS",
            "_HELD_DRAIN_SECONDS",
        ], (
            "the exit paths no longer drain on the ceilings that fit them. Two "
            "hand over to a successor that is already serving (free to wait) "
            "and one exits so a holder can start the successor (every second "
            "is an unserved port). Got: " + ", ".join(sorted(named))
        )

        # AND THE NUMBERS THEMSELVES, or the names above are decoration.
        #
        # THE HANDOVER CEILING IS NOT A NUMBER ANY MORE, and no number can be
        # right: 1800 cuts a 31-minute reply, 3600 cuts a 61-minute one, and
        # this box runs subagent replies past an hour. Nothing waits on this
        # process — the successor is already serving — so a clock buys nothing
        # here and spends a reply every time it is wrong.
        assert pp._HANDOVER_DRAIN_SECONDS == float("inf"), (
            "the handover drain is capped by a clock again. A clock cannot "
            "tell a slow reply from a wedged one; `_owed_still_moving` can, "
            f"and it is what ends a healthy drain. Got "
            f"{pp._HANDOVER_DRAIN_SECONDS}")
        assert pp._HELD_DRAIN_SECONDS <= pp._DRAIN_SECONDS, (
            "the held ceiling holds the port dark, and the supervisor SIGKILLs "
            "at `_DRAIN_SECONDS + 2` — raising it past that trades a logged "
            "cut for an unlogged one")

        # AND THE MARKER TTL MUST NOT FOLLOW THE CEILING. It was
        # `_HANDOVER_DRAIN_SECONDS + 60`, which is now infinite — a marker
        # that never expires spares whatever pid inherits the number, forever.
        # Freshness comes from a beat instead, so this stays small.
        assert pp._DRAINING_MARKER_TTL < 600.0, (
            "the draining marker outlives its writer by "
            f"{pp._DRAINING_MARKER_TTL}s. A SIGKILLed drainer cannot unlink "
            "it, and pids are reused — that window is a real orphan wearing a "
            "dead process's badge")
        assert pp._DRAINING_BEAT_SECONDS * 3 < pp._DRAINING_MARKER_TTL, (
            "the beat is too slow for the TTL it refreshes: a drain that is "
            "alive and working would look abandoned between two beats")

    def case_the_blind_tunnel_gives_its_debt_back(self, certdir):
        """THE FOURTH UNREACHABLE ZERO, and it is the same connection as the first.

        `_blind_tunnel` never called `_owe_answer(conn, False)`. The accept path
        marks every connection OWED, so a blind tunnel stayed owed for its
        entire life and `inflight_requests()` could not reach zero on any
        machine that had ever connected Remote Control. Every drain then paid
        its full ceiling — exactly the behaviour the `_owed` set was introduced
        to end.

        AND THIS IS THE RC PATH. `_blind_tunnel`'s own docstring: "Remote
        Control receives over a WebSocket to the ingress host the /bridge
        response names — NOT api.anthropic.com — so it lands here, not in the
        MITM." The fix went to `_mitm`'s 101 handover, which is the path RC
        does not take.

        Measured on host-a 2026-08-18, three versions, one signature:
            0.1.93 departing  cut 14 / cut 16  after 30s
            0.1.94 departing  cut 14           after 30s
            0.1.96 departing  cut 16           after 30s

        DRIVEN THROUGH THE REAL FUNCTION, not by arranging the state it should
        produce. The sibling cases above model "a tunnel owes nothing" by simply
        not adding it to `_owed` — which asserts the conclusion and can never
        catch a path that fails to reach it. This one dials a real listener,
        lets `_blind_tunnel` send its own 200, and then asks the counter.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(128)
        target = "127.0.0.1:%d" % srv.getsockname()[1]
        client, conn = socket.socketpair()
        accepted = []
        try:
            # THE ACCEPT PATH'S OWN MARKING, reproduced exactly: open, and owed
            # from the moment it is accepted.
            with proxy._live_lock:
                proxy._open_conns.add(conn)
            proxy._owe_answer(conn, True)
            assert proxy.inflight_requests() == 1, "precondition: owed at accept"

            proxy._local.conn = conn
            proxy._local.release = lambda: None
            proxy._blind_tunnel(target, conn)
            accepted.append(srv.accept()[0])

            assert proxy.inflight_requests() == 0, (
                "the tunnel still owes an answer. Nobody is waiting on it — it "
                "is two sockets being copied into each other — so it holds "
                "every drain to its full ceiling, and this is the path Remote "
                "Control's WebSocket takes")
            assert proxy.live_client_count() == 1, (
                "and it is still an OPEN connection, which teardown must close")

            # AND THE DRAIN MUST SAY SO. This is the one state where the two
            # counters disagree — one socket open, nothing owed — so it is the
            # only place that can catch a message reporting open sockets as
            # cut requests. That conflation is what put "cut 14 in-flight
            # request(s)" in the log for fourteen sockets nobody was waiting on.
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                assert proxy.await_inflight(0.0) == 0, (
                    "a tunnel owes nobody an answer, so cutting it costs "
                    "nothing and must not be reported as a cut request")
            assert "cut" not in err.getvalue(), err.getvalue()
            assert "closed 1 idle connection(s)" in err.getvalue(), (
                "the tunnel WAS closed and the line must account for it, or "
                "the two counters go back to being one number: "
                + err.getvalue())
        finally:
            for s_ in accepted + [client, conn, srv]:
                try: s_.close()
                except OSError: pass

    def case_the_drain_line_measures_instead_of_quoting_its_budget(self, certdir):
        """"after 30s" was the ARGUMENT, printed whether or not it was spent.

            f"cut {cut} in-flight request(s) after {budget:.0f}s"

        `budget` is the ceiling passed in. A drain that broke out in 20ms
        printed the same "after 30s" as one that burned the whole thing, so the
        one field that says whether the wait was real could not be read — and a
        peer session correctly refused to conclude anything from it.

        Here the drain returns at once (nothing is owed) on a large budget, and
        the line must not claim the budget was spent.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        err = io.StringIO()
        try:
            # OPEN, OWING NOTHING, ON A LARGE BUDGET. The elapsed and the
            # budget must DIFFER or the assertion cannot tell them apart —
            # this case first drove `await_inflight(0.0)`, where `0.0` and
            # `0.0` are the same string, and the mutation that put the budget
            # back into the field passed it. A test whose two candidate values
            # are equal is not a test.
            with proxy._live_lock:
                proxy._open_conns.add(a)
            assert proxy.inflight_requests() == 0, "precondition: nothing owed"
            with contextlib.redirect_stderr(err):
                proxy.await_inflight(20.0)
            line = err.getvalue()
            assert "drained clean" in line, (
                "a departure that cost nothing must still say so — silence "
                "reads the same as a daemon that never drained: " + line)
            assert "in 0.0s" in line, (
                "the line quotes its budget rather than what it waited: " + line)
            assert "20s budget" in line, (
                "and it must still name the ceiling it did not need: " + line)

            # AND WITH NO CEILING AT ALL it must say that, not print a float.
            # "of a infs budget" reads as a number nobody can act on, and this
            # is the one line a later session reads to decide whether a pin
            # departure cost somebody a reply.
            err2 = io.StringIO()
            with contextlib.redirect_stderr(err2):
                proxy.await_inflight(pp._HANDOVER_DRAIN_SECONDS)
            line2 = err2.getvalue()
            assert "inf" not in line2, (
                "the drain line printed a raw infinity: " + line2)
            assert "no wall-clock cap" in line2, (
                "an uncapped drain must name that it is uncapped — otherwise "
                "the log cannot tell it from one that had a budget and did "
                "not spend it: " + line2)
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_the_cut_says_whether_the_reply_had_started(self, certdir):
        """A CUT BEFORE HEADERS IS A RETRY; A CUT MID-RESPONSE IS A LOSS.

        The line said "a reply may have ended mid-stream" over both, so the
        number could not be used for the one thing it exists for: telling the
        user whether a recycle cost them an answer. A request cut before its
        headers went out has sent the client nothing — the SDK retries and it
        costs a round trip. One cut after has delivered part of an answer, and
        no retry repairs that.

        Measured on the sibling CCF proxy the same night, which already splits
        them: `cut 4 in-flight request(s) after 5s (4 mid-response, 0 before
        headers)`. Its counts were the only ones defensible as user-visible
        while ours reported sockets and hedged about the phase.

        BOTH DIRECTIONS IN ONE CASE, because either alone passes on a version
        that hardcodes the other: a constant "0 mid-response" survives the
        before-headers half, and a constant "0 before headers" survives the
        mid-response half.
        """
        import cswap_pin.proxy as pp

        for started, want in ((False, "0 mid-response, 1 before headers"),
                              (True, "1 mid-response, 0 before headers")):
            proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                                upstream=("127.0.0.1", 1))
            a, b = socket.socketpair()
            err = io.StringIO()
            try:
                with proxy._live_lock:
                    proxy._open_conns.add(a)
                proxy._owe_answer(a, True)
                if started:
                    proxy._note_response_started(a)
                assert proxy.inflight_requests() == 1, "precondition: owed"
                assert proxy.inflight_mid_response() == (1 if started else 0)
                with contextlib.redirect_stderr(err):
                    proxy.await_inflight(0.0)
                assert want in err.getvalue(), (
                    f"started={started}: the line does not say which kind of "
                    f"cut this was: {err.getvalue()}")
            finally:
                for s_ in (a, b):
                    try: s_.close()
                    except OSError: pass

    def case_the_relay_is_what_says_the_reply_started(self, certdir):
        """THE WIRING, not the method — and the mutation that proved it missing.

        The two cases around this one call `_note_response_started` themselves,
        so deleting the `on_headers()` call from the relay left them both GREEN.
        Measured: mutation "the relay never says the reply started" SURVIVED,
        which means nothing connected the marker to the only event that can set
        it. That is the same hole as a drain fix landing on the path Remote
        Control does not take — a correct function nobody calls.

        So this drives the real `_relay_response` over a real socket pair with
        a canned upstream response, and asks whether the callback fired.
        """
        from cswap_pin.proxy import _relay_response

        up_a, up_b = socket.socketpair()
        cl_a, cl_b = socket.socketpair()
        fired = []
        try:
            up_b.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
            up_b.shutdown(socket.SHUT_WR)
            _relay_response(up_a, cl_a, 0,
                            on_headers=lambda n, c: fired.append(n))
            assert fired, (
                "the relay wrote the response head to the client without "
                "saying so, so every cut is reported as retryable no matter "
                "how much of the answer had already been delivered")
            # AND THE CLIENT REALLY GOT IT — otherwise a relay that fires the
            # callback and sends nothing would pass.
            cl_a.shutdown(socket.SHUT_WR)
            got = cl_b.recv(4096)
            assert got.startswith(b"HTTP/1.1 200"), got[:60]
            assert got.endswith(b"hi"), got[-20:]
        finally:
            for s_ in (up_a, up_b, cl_a, cl_b):
                try: s_.close()
                except OSError: pass

    def case_marking_a_response_started_cannot_rewind(self, certdir):
        """RE-OWING MUST NOT UNDO IT, and `_owe_answer` is called again mid-request.

        The accept path marks a connection owed, and `_handle_one_request`
        marks it owed AGAIN when the request line arrives — so a plain
        `self._owed[conn] = False` would reset a response already in flight to
        "before headers" and under-report exactly the cuts that matter.
        `setdefault` is what makes that impossible, and this is the case that
        says so.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            proxy._owe_answer(a, True)
            proxy._note_response_started(a)
            proxy._owe_answer(a, True)          # the second marking
            assert proxy.inflight_mid_response() == 1, (
                "re-marking an owed connection rewound a reply that had "
                "already started, so a real mid-response cut would be counted "
                "as a retryable one")
            # And paying the debt really does clear it, or the rewind guard
            # would be a leak instead.
            proxy._owe_answer(a, False)
            assert proxy.inflight_requests() == 0
            assert proxy.inflight_mid_response() == 0
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass

    def case_a_request_in_flight_holds_the_drain(self, certdir):
        """THE OTHER HALF, and the one that must never regress to "fast".

        Counting requests is only right if a request actually holds the drain.
        Without this case, `await_inflight` could return immediately always and
        the case above would still pass — which is the same "verified where it
        cannot fail" shape as the drain line that reported a constant 0.
        """
        import cswap_pin.proxy as pp

        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: "T",
                            upstream=("127.0.0.1", 1))
        a, b = socket.socketpair()
        try:
            # OWED AN ANSWER — what the accept path marks, and what a
            # streaming `/v1/messages` stays marked as for every second it
            # streams. This is the state a recycle must never walk away from.
            with proxy._live_lock:
                proxy._open_conns.add(a)
            proxy._owe_answer(a, True)
            assert proxy.inflight_requests() == 1
            started = time.monotonic()
            with contextlib.redirect_stderr(io.StringIO()):
                proxy.await_inflight(1.0)
            waited = time.monotonic() - started
            assert waited >= 0.9, (
                f"returned after {waited:.2f}s with a request in flight — a "
                "streaming reply would be cut mid-response")
        finally:
            for s_ in (a, b):
                try: s_.close()
                except OSError: pass


class TestTunnelIsOpen:
    """`_tunnel_is_open` on its own, with nothing racing.

    The integration case above proves the FALLBACK happens; this proves the
    DETECTOR that is supposed to trigger it, and it can do so without a
    scheduler in the loop — a socket whose peer has already closed is EOF now,
    not in 0.35 s.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_a_peer_that_closed_reads_as_EOF(self):
        import cswap_pin.proxy as pp
        a, b = socket.socketpair()
        b.close()
        try:
            assert pp.PinProxy._tunnel_is_open(a) is None, (
                "a closed peer must read as EOF — this is the whole detector")
        finally:
            a.close()

    def case_a_live_idle_socket_reads_as_OPEN(self):
        """THE CONTROL. Without it, "closed reads as EOF" also passes on a
        detector that answers None for everything — which would send every
        healthy tunnel down the direct-dial path."""
        import cswap_pin.proxy as pp
        a, b = socket.socketpair()
        try:
            assert pp.PinProxy._tunnel_is_open(a) is a, (
                "an idle tunnel has nothing to read and that means OPEN")
        finally:
            a.close(); b.close()

    def case_a_byte_already_waiting_is_pushed_back(self):
        """It READS to test, so the byte it consumed has to reappear or the
        caller's stream is corrupted — the reason it returns a socket rather
        than a bool."""
        import cswap_pin.proxy as pp
        a, b = socket.socketpair()
        try:
            b.sendall(b"XY")
            out = pp.PinProxy._tunnel_is_open(a)
            assert out is not None and out is not a, "expected the wrapper"
            # READ UNTIL SATISFIED, not one recv. `_Prefixed` hands back the
            # single probed byte first and the socket's own data after it, so
            # a `recv(2) == b"XY"` expectation is the TEST being wrong about
            # stream semantics, not the wrapper losing anything. What the
            # contract actually promises is that no byte disappears.
            got = b""
            while len(got) < 2:
                chunk = out.recv(2 - len(got))
                assert chunk, "the stream ended early — a byte was swallowed"
                got += chunk
            assert got == b"XY", got
        finally:
            a.close(); b.close()


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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_falls_back_when_the_200_tunnel_is_already_eof(self, certdir, tmp_path):
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
        # THE CONTRACT, NOT THE BRANCH THAT DELIVERED IT. This used to assert
        # `"already EOF" in log`, which names one internal path. Measured on
        # macOS CI 2026-08-18: the two behavioural assertions above BOTH passed
        # — the host was dialled directly and answered PONG, so the dead chain
        # was correctly not used — while the log read
        # `CONNECT … tunnelled (no pin: bearer never seen)`. The chain closes
        # immediately after its 200, so whether the proxy observes a FIN inside
        # `_tunnel_is_open`'s 0.35 s select or an RST earlier is a scheduling
        # question, and both answers are right.
        #
        # The detector itself is pinned deterministically instead, with no
        # sockets in flight, by `TestTunnelIsOpen` below. Asserting a log line
        # here bought nothing that case does not, and cost a red CI on a
        # correct build — which blocked a release.
        assert log.read_text().strip(), "the connection was not traced at all"


class TestTheTrustFileActuallyVerifies:
    """Every other check on the CA-trust contract inspects file CONTENT — does
    the bundle contain our CA, are its BEGIN/END markers balanced. Both are
    necessary and neither is evidence: they are pre-flight guards, and only a
    completed handshake proves the file yields a working trust path to the
    proxy. Measured on host-a against the live daemon: with the merged bundle,
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_named_trust_file_verifies_the_proxy(self, certdir, tmp_path, monkeypatch):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_certdir_must_be_the_last_argv_token(self, tmp_path, monkeypatch):
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

    def case_a_different_certdir_is_never_matched(self, tmp_path, monkeypatch):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

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

    def case_a_deferred_refresh_does_not_condemn_the_daemon(self, tmp_path):
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

    def case_a_real_unreadable_credential_IS_still_a_failure(self, tmp_path):
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

    def case_warns_when_the_token_cannot_be_minted(self, certdir, monkeypatch):
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        self._proxy(certdir, lambda: None)._warn_unpinnable()
        err = buf.getvalue()
        assert "UNPINNED" in err
        assert "cswap pin" in err, "the message must name the fix"

    def case_the_spawned_daemon_has_somewhere_to_warn(self, certdir, monkeypatch):
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

    def case_the_warning_lands_in_that_log(self, certdir):
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

    def case_the_cap_rotates_rather_than_deleting(self, certdir):
        """THE INSTRUMENT MUST NOT BE DESTROYED BY THE EVENT IT DESCRIBES.

        `_open_daemon_log` runs at DAEMON START, and past the size cap it used
        to `unlink` the file. Daemon start is the instant a handover completes,
        so the INCOMING daemon was deleting the OUTGOING daemon's teardown
        record — the "drained, N" and "cut N in-flight request(s)" lines that
        exist to say whether a recycle cost anyone their reply.

        Measured 2026-08-18: three sessions took "API Error: Connection lost
        mid-response" during a two-stage recycle, and the log covering it had
        been unlinked 8 seconds in. A second question riding the same window —
        who emptied `.claude.json`'s env block — could not be settled either,
        by anyone, ever.

        An empty log reads as "the daemon had nothing to say", which is why
        this is worse than having no log at all.
        """
        from cswap_pin import proxy as pp

        log = pp.daemon_log_path(certdir)
        log.parent.mkdir(parents=True, exist_ok=True)
        marker = "THE-DEPARTING-DAEMONS-LAST-WORDS"
        log.write_text(marker + "x" * (pp._LOG_MAX_BYTES + 1), encoding="utf-8")

        handle = pp._open_daemon_log(certdir)
        try:
            assert log.stat().st_size < pp._LOG_MAX_BYTES, (
                "the cap has to hold, or the log grows without bound")
            kept = log.with_suffix(log.suffix + ".1")
            assert kept.is_file(), (
                "the previous generation was deleted, not rotated — the next "
                "recycle's evidence dies with it")
            assert marker in kept.read_text(encoding="utf-8", errors="replace"), (
                "the rotated file does not carry what the old daemon wrote")
        finally:
            handle.close()

        # A SECOND ROTATION IN THE SAME RECYCLE MUST NOT EAT THE FIRST. A
        # recycle is two-stage — measured 70 s apart — and each stage opens
        # the log. One generation meant stage two overwrote stage one's
        # teardown record, which is the very line the rotation exists to keep.
        log.write_text("STAGE-TWO" + "x" * (pp._LOG_MAX_BYTES + 1),
                       encoding="utf-8")
        handle = pp._open_daemon_log(certdir)
        try:
            older = log.with_suffix(log.suffix + ".2")
            assert older.is_file(), (
                "a second rotation kept only one generation, so the departing "
                "daemon's last words were overwritten by the next stage of "
                "the same recycle")
            assert marker in older.read_text(encoding="utf-8", errors="replace"), (
                "the older generation is not the one that carried the "
                "teardown record")
        finally:
            handle.close()

    def case_warns_only_once_per_daemon(self, certdir, monkeypatch):
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

    def case_health_reports_whether_the_pin_can_apply(self, certdir):
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

    def case_a_noop_pin_does_not_warn(self, certdir, monkeypatch):
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

    def case_an_unreadable_store_still_warns(self, certdir, monkeypatch):
        """The quieting must not swallow the case the warning exists for."""
        import io
        import sys as _sys

        buf = io.StringIO()
        monkeypatch.setattr(_sys, "stderr", buf)
        # No pin_is_noop hook: "cannot read" is the default reading of None.
        p = self._proxy(certdir, lambda: None)
        assert self._drive_pinned_request(p) is None
        assert "UNPINNED" in buf.getvalue(), "went silent on a real fail-open"

    def case_a_noop_pin_reports_can_pin_on_health(self, certdir):
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

    def case_a_raising_provider_reports_cannot_pin(self, certdir):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

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

    def case_an_unauthenticated_connect_is_served_but_never_pinned(self, certdir):
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

    def case_a_wrong_credential_is_served_but_never_pinned(self, certdir):
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

    def case_the_real_credential_is_accepted(self, certdir):
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

    def case_a_blind_tunnel_is_not_gated(self, certdir):
        """It used to be, on "otherwise we are an open forward proxy". That
        assumes the port is reachable; it binds 127.0.0.1 only, so the
        population it could refuse is the same-user processes that can read
        the 0600 secret anyway.

        What it cost is the reason it is gone. EVERY host that is not
        api.anthropic.com takes this branch — git, pip, npm, the auto-updater
        — so with the pin on, a session wired before the credential existed
        got 200 for Claude and 407 for the entire rest of the internet.
        Measured on host-a: github.com, pypi.org and registry.npmjs.org all
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

    def case_absolute_form_also_needs_the_credential(self, certdir):
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

    def case_health_stays_open(self, certdir):
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

    def case_a_daemon_without_a_secret_still_serves(self, certdir):
        """A pin that starts refusing traffic after an upgrade is worse than
        the exposure it closes. No secret on disk => no auth required."""
        p = self._proxy(certdir)  # nothing minted
        p.start()
        try:
            assert "407" not in self._connect(p.port)
        finally:
            p.stop()

    def case_the_secret_is_not_world_readable(self, certdir):
        import stat
        from cswap_pin.proxy import ensure_proxy_secret, proxy_secret_path
        ensure_proxy_secret(certdir)
        mode = proxy_secret_path(certdir).stat().st_mode
        assert not (mode & (stat.S_IRGRP | stat.S_IROTH)), (
            "the credential is readable by other users — it protects nothing"
        )

    def case_the_secret_is_stable_across_respawns(self, certdir):
        """A new secret each spawn would strand every live session: their
        HTTPS_PROXY is fixed at exec time and would carry the old one."""
        from cswap_pin.proxy import ensure_proxy_secret
        assert ensure_proxy_secret(certdir) == ensure_proxy_secret(certdir)

    def case_the_wiring_hands_clients_the_credential(self, certdir):
        """Measured: the real Claude Code client sends Proxy-Authorization on
        CONNECT only when HTTPS_PROXY carries user:pass. If the wiring does
        not embed it, enforcing auth cuts off every session."""
        from cswap_pin.proxy import ensure_proxy_secret, wire_env
        secret = ensure_proxy_secret(certdir)
        env = wire_env({}, 9955, certdir / "ca.pem", open_refcount=False)
        assert secret in env["HTTPS_PROXY"]
        assert "@127.0.0.1:9955" in env["HTTPS_PROXY"]

    def case_the_credential_is_not_forwarded_upstream(self, certdir):
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

    def case_a_secret_written_under_a_running_daemon_takes_effect(self, certdir):
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

    def case_a_respawn_does_not_arm_the_gate(self, certdir, monkeypatch):
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

    def case_apply_pin_mints_the_credential(self, certdir, monkeypatch):
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

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_rc_swaps_and_inference_does_not_for_an_uncredentialed_session(
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

    def case_clearing_returns_rc_to_the_active_account(self, certdir):
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

    def case_no_407_in_either_direction(self, certdir):
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
    def test_all(self, request, tmp_path_factory):
        run_cases(
            self,
            request,
            tmp_path_factory,
            # this class wants the CA one level down, in `pin-proxy/`
            extra={"certdir": lambda t: _make_certdir(_mkdir(t / "pin-proxy"))},
        )

    def case_a_403_on_a_swapped_route_is_retried_unswapped(self, certdir):
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
                TestStreamingRelay(),
                TestChunkedRequestBodiesReachUpstream(),
                TestTheChainsCredentialIsSent(),
                TestLoopbackChainTrust(),
                TestLongPollSurvives(),
                TestAbsoluteFormPassthrough(),
                TestHealthEndpoint(),
                TestKeepAlive(),
                TestWebSocketUpgrade(),
                TestBlindTunnelIsTraced(),
                TestBlindTunnelFallsBackWhenChainRefuses(),
                TestOptimisticConnectIsDetected(),
                TestTheTrustFileActuallyVerifies(),
                TestTheKillGateIdentifiesItsTarget(),
                ],
            request,
            tmp_path_factory,
        )
