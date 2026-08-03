"""No test may touch the real machine's Claude config. Enforced, not asked.

MEASURED BREAKAGE, and it was live rather than theoretical. Running this suite
on a developer's own box rewired that box's `~/.claude.json` to port 52000 — a
value that exists only as a fixture in `test_recycles_stale_fingerprint`:

    monkeypatch.setattr(pin_proxy, "_spawn_daemon", lambda *a, **k: 52000)
    got, ca = pin_proxy.ensure_proxy(self._Sw(tmp_path))

That test patched `_spawn_daemon` and `_kill_daemon` but not the config PATH,
and `ensure_proxy` ends in `wire_global_config(port, ca)`, which resolves the
path from `claude_swap.paths` — the real `~/.claude.json`. So every run pointed
the machine's sessions at a port nothing had ever served. Measured afterwards:
`CSWAP_PIN_PORT = 52000`, connect refused, while the actual daemon served
36301. Any session started in that window could not reach the API at all.

WHY A CONFTEST AND NOT A FIX IN THAT TEST. This is the third instance in one
evening of a test reaching outside its fixture — a `GIT_DIR` inherited into a
hook fixture that rewrote the real repository's `main`, port-36301 literals
that described a LIVE daemon while claiming a dead one, and now this. Patching
each one as it is found leaves the next one to be discovered by damage. The
class of bug is "a test forgot to redirect something", so the guard belongs
where forgetting is impossible.

`autouse` means a test cannot opt out by omission. A test that genuinely wants
to exercise config writing gets a real file — under `tmp_path`, where pytest
throws it away.
"""

import json

import pytest


@pytest.fixture(autouse=True)
def _never_touch_the_real_claude_config(tmp_path, monkeypatch):
    """Point every config-path lookup at this test's own tmp_path."""
    cfg = tmp_path / "conftest-claude.json"
    if not cfg.exists():
        cfg.write_text(json.dumps({}), encoding="utf-8")

    try:
        import claude_swap.paths as paths
    except Exception:  # noqa: BLE001
        # The host is not importable here (packaging tests block it on
        # purpose). Nothing can resolve a real path either, so there is
        # nothing to redirect.
        return

    for name in ("get_global_config_path", "get_default_global_config_path"):
        if hasattr(paths, name):
            monkeypatch.setattr(paths, name, lambda cfg=cfg: cfg)

    # AND THE CONFIG HOME, which is a different question with the same answer.
    # The first version of this guard redirected only the two config-PATH
    # lookups, and `publish_ca` uses `get_claude_config_home` — so the suite
    # went on writing a test-generated CA into the real
    # `~/.claude/ca-trust.d/cswap-pin.pem`, replacing the one the live daemon
    # actually signs with. Caught by the shared ca-trust suite ("every
    # published component CA is in the bundle: missing cswap-pin.pem"), not by
    # anything here — which is the argument for redirecting the whole home
    # rather than enumerating the accessors someone might add next.
    home = tmp_path / "claude-home"
    home.mkdir(exist_ok=True)
    if hasattr(paths, "get_claude_config_home"):
        monkeypatch.setattr(paths, "get_claude_config_home", lambda home=home: home)

    # AND THROUGH THE ENVIRONMENT, because a monkeypatched attribute does not
    # cross a process boundary. `get_claude_config_home` reads CLAUDE_CONFIG_DIR
    # first, so setting it redirects the CHILDREN this suite spawns — the
    # daemons, the packaging probes, the oracle's node — none of which inherit
    # a patched module object.
    #
    # That gap was not theoretical. After the in-process redirect was added and
    # the real `~/.claude/ca-trust.d/cswap-pin.pem` restored, the file was
    # overwritten AGAIN by a test-minted CA — and the published CA then could
    # not verify the leaf the live daemon serves:
    #
    #     openssl verify -CAfile ca-trust.d/cswap-pin.pem  pin-proxy/leaf.pem
    #       error 20: unable to get local issuer certificate
    #     openssl verify -CAfile pin-proxy/ca.pem          pin-proxy/leaf.pem
    #       OK
    #
    # Every session on the box was handed a bundle carrying a CA that signs
    # nothing it talks to. An env var is the only redirect a child obeys.
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(home))

    # The seam re-imports these INSIDE functions (`from claude_swap.paths
    # import ...`), which reads the attribute at call time — so patching the
    # module attribute above is enough for those. But any module that bound
    # the name at import time keeps its own reference, and patching the source
    # module would not reach it. Catch those too.
    import sys

    for mod in list(sys.modules.values()):
        if mod is None or mod is paths:
            continue
        origin = getattr(mod, "__name__", "")
        if not (origin.startswith("claude_swap") or origin.startswith("cswap_pin")):
            continue
        for name in ("get_global_config_path", "get_default_global_config_path"):
            if hasattr(mod, name):
                monkeypatch.setattr(mod, name, lambda cfg=cfg: cfg, raising=False)
        if hasattr(mod, "get_claude_config_home"):
            monkeypatch.setattr(
                mod, "get_claude_config_home", lambda home=home: home, raising=False
            )
