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
import pathlib
import sys

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

    # AND THE ACCOUNT STORE, which is a THIRD question the config redirects
    # above do not answer. Everything so far points at the CONFIG
    # (`.claude.json`, `~/.claude/`). The credentials and the roster live
    # somewhere else entirely — `~/.local/share/claude-swap/` — reached
    # through `get_backup_root`, and nothing here redirected it.
    #
    # This was found during a live incident on host-a: the real
    # `sequence.json` was overwritten with test fixture accounts
    # (`a@example.com`, `b@example.com`) plus matching 88-byte `.creds-*.enc`
    # files. That damage was NOT traced to this suite — no test here builds a
    # real switcher, so nothing reaches `switcher.backup_dir` today. But that
    # is a property of the tests, not a guard, and it is exactly the shape
    # every other hole in this file had before it fired. The roster syncs by
    # WHOLE-FILE COPY with newest-wins, so a store corrupted on one machine is
    # one sync away from overwriting both Macs.
    #
    # Three redirects because `get_backup_root` can be reached three ways:
    # the function itself (in-process callers), `XDG_DATA_HOME` (the children
    # this suite spawns, which do not inherit a patched module object), and
    # `Path.home()` (its fallback when XDG is unset, and anything that
    # computes the path itself).
    store = tmp_path / "data-home"
    store.mkdir(exist_ok=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(store))
    monkeypatch.setattr(pathlib.Path, "home", lambda: tmp_path / "fake-home")
    (tmp_path / "fake-home").mkdir(exist_ok=True)
    if hasattr(paths, "get_backup_root"):
        monkeypatch.setattr(
            paths, "get_backup_root", lambda store=store: store / "claude-swap"
        )

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
        if hasattr(mod, "get_backup_root"):
            monkeypatch.setattr(
                mod,
                "get_backup_root",
                lambda store=store: store / "claude-swap",
                raising=False,
            )


# --- one CA for the whole session -------------------------------------------
# `ensure_ca` generates an RSA key pair, which costs ~90 ms. Measured: 158 of
# the suite's tests call it, so the suite spent ~14 s — 18% of its runtime —
# re-deriving a key whose VALUE no test asserts on. The tests that care about
# CA CONTENT (the consistency checks, the trust-bundle merge) build their own
# and are unaffected; everything else just needs A valid CA to exist.
#
# So: build one, and have `ensure_ca` copy it when the target has none. The
# copy is what keeps the function's contract intact — callers still get four
# files in their own directory, and the idempotent-reuse path is untouched.
@pytest.fixture(autouse=True)
def _shared_ca(monkeypatch, tmp_path_factory):
    """Serve one pre-built CA to the FIRST cert dir each test asks for.

    `ensure_ca` mints two RSA-2048 keys — ~70 ms — and the suite calls it in
    most of its tests. Nothing asserts on a key's VALUE; what matters is that
    a CA signs its leaf, which a copy satisfies.

    THE FIRST DIR ONLY, per test. A test that builds a SECOND cert dir is
    almost always constructing a DIFFERENT CA on purpose ("a leaf signed by
    another CA of the same name", "a bundle without ours"), and handing those
    the same files makes the assertion vacuous. Measured: serving every dir
    broke three such tests.

    Only for the default host, too: a test naming another host needs a leaf
    with that SAN.
    """
    import shutil

    from cswap_pin import proxy as _p

    cache = tmp_path_factory.getbasetemp() / "_ca-cache"
    real = _p.ensure_ca
    if not (cache / "ca.pem").exists():
        cache.mkdir(parents=True, exist_ok=True)
        real(cache, "api.anthropic.com")

    served: list = []

    def fast_ensure_ca(ca_dir, host):
        d = pathlib.Path(ca_dir)
        if (
            host == "api.anthropic.com"
            and not served
            and not (d / "ca.pem").exists()
        ):
            served.append(str(d))
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            for f in ("ca.pem", "ca.key", "leaf.pem", "leaf.key"):
                shutil.copy2(cache / f, d / f)
        return real(d, host)

    monkeypatch.setattr(_p, "ensure_ca", fast_ensure_ca)
    # AND EVERY MODULE THAT IMPORTED THE NAME. `from cswap_pin.proxy import
    # ensure_ca` binds it into that module's namespace, so patching only the
    # source leaves those call sites on the real one.
    for mod in list(sys.modules.values()):
        if mod is None or mod is _p:
            continue
        if getattr(mod, "__name__", "").startswith(("test_", "tests.")):
            if getattr(mod, "ensure_ca", None) is real:
                monkeypatch.setattr(mod, "ensure_ca", fast_ensure_ca, raising=False)


@pytest.fixture(scope="session")
def _session_ca(tmp_path_factory):
    """ONE CA for the whole run, built once and copied by everything that
    only needs *a* valid CA. Two RSA-2048 keys cost ~70 ms and the suite asked
    for one in most of its tests."""
    from cswap_pin import proxy as _p

    d = tmp_path_factory.mktemp("session-ca")
    _p.ensure_ca(d, "api.anthropic.com")
    return d
