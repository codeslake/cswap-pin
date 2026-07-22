"""Tests for the account-pin proxy's request classification.

The proxy MITMs api.anthropic.com and swaps the Authorization bearer to a
pinned account's token, but ONLY on the Remote-Control and Artifact routes;
inference (/v1/messages) and everything else must pass through untouched.
"""

from __future__ import annotations

from claude_swap.pin_proxy import is_pinned_route, swap_authorization


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
