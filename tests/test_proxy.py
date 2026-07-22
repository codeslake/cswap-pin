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
