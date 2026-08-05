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
    _redirect_everything_to(tmp_path, monkeypatch)


def _redirect_everything_to(tmp_path, monkeypatch):
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
    # This was found during a live incident on lmd42: the real
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
    # AND THE PIN'S OWN ENV, which a pinned developer's session inherits at
    # BOOT. Claude Code applies `.claude.json`'s env block into process.env,
    # so every test run from inside a pinned session started with
    # `CSWAP_PIN_PORT` naming the LIVE daemon's port. Nothing read it until
    # the daemon started honouring a configured port — and then four unrelated
    # tests went red, each trying to bind the developer's real 36301 and
    # logging "configured port 36301 is not available". The suite was reading
    # a value from outside its own fixture, exactly like the config paths
    # above; it just had no consumer yet.
    for name in ("CSWAP_PIN_PORT", "CSWAP_PIN_WIRED", "CSWAP_PIN_FIFO",
                 "CSWAP_PIN_REFCOUNT_FD"):
        monkeypatch.delenv(name, raising=False)

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
        # A SECOND cert dir gets the cache too, UNLESS its path says the test
        # wants a distinct CA. Restricting it to the first dir left 88 calls
        # generating (5.5 s); the tests that genuinely need two DIFFERENT CAs
        # name them, and `_other_ca` has its own cache.
        wants_distinct = any(
            w in str(d).lower()
            for w in ("other", "corp", "foreign", "sibling", "another", "second")
        )
        if (
            host == "api.anthropic.com"
            and not wants_distinct
            and not (d / "ca.pem").exists()
        ):
            served.append(str(d))
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            for f in ("ca.pem", "ca.key", "leaf.pem", "leaf.key"):
                shutil.copy2(cache / f, d / f)
            # AND SKIP THE RE-VERIFICATION. `ensure_ca` re-parses all four
            # files and checks the CA actually signed the leaf — 50 ms, and
            # correct for a real run. These four were verified once when the
            # cache was built and copied byte-for-byte, so re-deriving that
            # per test was 6.3 s of the suite. Tests that CARE about
            # consistency build their own pair and are unaffected.
            return _p.CertBundle(
                ca_path=d / "ca.pem",
                leaf_path=d / "leaf.pem",
                leaf_key_path=d / "leaf.key",
            )
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


@pytest.fixture(autouse=True)
def _short_hop_budgets(monkeypatch):
    """Shrink the egress-hop budgets for tests.

    A hop that accepts and never answers costs `_HOP_REPLY_BUDGET_S` (6 s) per
    dial, and several tests point the walk at exactly that shape on purpose.
    The PRODUCT budget has to be generous — it covers a real proxy's outbound
    round trip — but a test dialling 127.0.0.1 needs none of it, and the
    budget was the runtime rather than the thing under test.
    """
    from cswap_pin import proxy as _p

    monkeypatch.setattr(_p, "_HOP_CONNECT_BUDGET_S", 0.3, raising=False)
    monkeypatch.setattr(_p, "_HOP_REPLY_BUDGET_S", 0.3, raising=False)
    # AND THE HEAL GRACE. The production value waits out a hop that is
    # restarting (~1s, measured); a test whose hop is deliberately dead pays it
    # in full for nothing. Measured: the suite went 5s -> 96s the moment the
    # grace landed. Shrunk rather than zeroed, so the retry LOOP still runs —
    # a zero would skip the behaviour instead of shortening it.
    monkeypatch.setattr(_p, "_CHAIN_HEAL_GRACE_S", 0.3, raising=False)
    monkeypatch.setattr(_p, "_CHAIN_HEAL_POLL_S", 0.05, raising=False)


def _reap_pin_processes(certdir, timeout: float = 20.0) -> None:
    """Kill every pin process serving ``certdir``, PARENTS FIRST, and WAIT.

    Two things make this less obvious than it looks, both measured here:

      - PARENTS FIRST. A holder's whole job is to replace a daemon that dies,
        so killing children first MULTIPLIES them. A handover test that TERM'd
        only the recorded daemon pid accumulated 7 orphans across a few suite
        runs; a peer session stalled its machine with 53.
      - WAIT, and re-sweep. A holder answering SIGTERM drains its daemon
        first, so the child is still alive when this returns — and a test that
        returns before its processes are gone leaves them for the next run to
        find. Re-sending until the set is empty also catches a daemon the
        holder respawned in the window before it saw the signal.

    Matched on the certdir being the LAST argv token, which is how the product
    identifies its own daemons — so a test certdir can never select the live
    pin, whose certdir is the real backup dir.
    """
    import os
    import subprocess
    import time

    target = str(pathlib.Path(certdir).resolve())

    def _mine():
        try:
            out = subprocess.run(["ps", "-eo", "pid=,command="],
                                 capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return [], []
        holders, daemons = [], []
        for line in out.splitlines():
            pid_s, _, cmd = line.strip().partition(" ")
            if "cswap_pin.proxy" not in cmd:
                continue
            if not cmd.rstrip().endswith(" " + target):
                continue
            try:
                pid = int(pid_s)
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            (holders if "--hold-port" in cmd else daemons).append(pid)
        return holders, daemons

    deadline = time.monotonic() + timeout
    while True:
        holders, daemons = _mine()
        if not holders and not daemons:
            return
        for pid in holders + daemons:
            try:
                os.kill(pid, 15)
            except OSError:
                pass
        if time.monotonic() >= deadline:
            for pid in holders + daemons:  # last resort, still parents first
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
            return
        time.sleep(0.2)


# --- one pytest test per class, N cases inside -------------------------------
# The suite's cases are cheap (54 ms each, measured) and its per-case pytest
# overhead is not the cost — but 332 collected items is more surface than the
# behaviour warrants, and each one re-pays the autouse fixtures. `run_cases`
# runs every `case_*` method of a class inside ONE pytest test, giving each its
# own tmp_path and its own monkeypatch so a case cannot leak into the next.
#
# WHAT THIS MUST NOT LOSE, and does not:
#  - INDEPENDENCE. Each case gets a fresh MonkeyPatch (undone in a finally) and
#    a fresh tmp_path subdir, so state a case installs dies with it. That is
#    the property pytest's own per-test teardown was providing.
#  - EVERY FAILURE, not the first. A raising case is recorded and the run
#    continues; the driver fails at the end naming ALL of them. Stopping at the
#    first would hide the rest behind one fix — strictly worse than what the
#    separate tests reported.
#  - THE FAILING CASE'S NAME AND TRACEBACK. Both are in the message, so a
#    failure still points at one method in one file.
def run_cases(instance, request, tmp_path_factory, extra=None):
    """Run every `case_*` method of `instance`, isolated, reporting all failures.

    `instance` may be a LIST of holders — several small classes sharing one
    pytest test. They are run separately (own instance, own helpers) rather
    than merged by inheritance, because three of this suite's classes define a
    `_ca` / `_cfg` / `_ours` helper with DIFFERENT meanings and a shared MRO
    would have handed every case just one of them.

    A case takes the fixtures it names in its signature, resolved from `extra`
    plus the per-case `tmp_path` / `monkeypatch` this builds. Anything else it
    asks for is fetched from pytest itself via `request.getfixturevalue`.
    """
    import traceback

    from _pytest.monkeypatch import MonkeyPatch

    holders = instance if isinstance(instance, (list, tuple)) else [instance]
    work = []
    for holder in holders:
        cls = type(holder)
        for n in sorted(dir(cls)):
            if n.startswith("case_") and callable(getattr(holder, n)):
                work.append((holder, f"{cls.__name__}::{n}", getattr(holder, n)))
    module_factories = getattr(
        sys.modules[type(holders[0]).__module__], "case_fixtures", {}
    )
    failures = []
    for i, (instance, name, method) in enumerate(work):
        wants = [
            a
            for a in method.__code__.co_varnames[: method.__code__.co_argcount]
            if a != "self"
        ]
        mp = MonkeyPatch()
        # A per-case dir, not the shared one: two cases writing `pin-proxy/`
        # under one tmp_path would see each other's files.
        case_tmp = tmp_path_factory.mktemp(f"c{i}")
        try:
            # The autouse guards ran once for the DRIVER's tmp_path. Re-point
            # them at this case's dir, or a case's config writes land in the
            # dir a sibling case is asserting about.
            _redirect_everything_to(case_tmp, mp)
            pool = {"tmp_path": case_tmp, "monkeypatch": mp}
            # A FIXTURE A CASE CAN WRITE INTO IS BUILT PER CASE, not once for
            # the driver. Measured: sharing one `certdir` across a class let a
            # case's `upstream.json` be read by the next one, which then
            # asserted about a chain it had never recorded. A test module names
            # those in `case_fixtures`; everything else still comes from pytest,
            # where a read-only or session-scoped value is correct to share.
            for fname, factory in {**module_factories, **(extra or {})}.items():
                pool[fname] = factory(case_tmp) if callable(factory) else factory
            args = [
                pool[a] if a in pool else request.getfixturevalue(a) for a in wants
            ]
            method(*args)
        except Exception:  # noqa: BLE001 — collect, do not stop the run
            failures.append(f"--- {name} ---\n{traceback.format_exc()}")
        finally:
            mp.undo()
    if failures:
        raise AssertionError(
            f"{len(failures)} of {len(work)} cases failed:\n\n" + "\n".join(failures)
        )



def test_every_case_has_a_driver():
    """A `case_*` method with no `test_all` NEVER RUNS, and nothing says so.

    MEASURED: 82 cases across 57 classes had been silently dead — including
    TestKillDaemon, TestOrphanSweep, TestDaemonSignalTeardown and
    TestEnsureProxyLifecycle, i.e. the paths that strand sessions. The suite
    reported `60 passed` the whole time, and a test written for a REAL defect
    (the mtime fingerprint) passed while the defect was still there, because
    its class had no driver either.

    That is worse than having no test: a green run is read as evidence. This
    guard is the one thing that cannot itself go quiet, because it is a plain
    pytest function with no driver of its own.
    """
    import pathlib
    import re

    dead = []
    for path in sorted(pathlib.Path(__file__).parent.glob("test_*.py")):
        cls = None
        has_driver = False
        cases = []
        for line in path.read_text().splitlines():
            if line.startswith("class "):
                if cls and cases and not has_driver:
                    dead.append((path.name, cls, len(cases)))
                cls = line.split(":")[0].split("(")[0].replace("class ", "").strip()
                has_driver = False
                cases = []
            elif re.match(r"    def test_all\b", line):
                has_driver = True
            elif re.match(r"    def case_", line):
                cases.append(line.strip())
        if cls and cases and not has_driver:
            dead.append((path.name, cls, len(cases)))

    assert not dead, (
        f"{sum(n for _, _, n in dead)} case(s) in {len(dead)} class(es) never "
        f"run — they have `case_*` methods and no `test_all` driver:\n"
        + "\n".join(f"  {f}::{c} ({n} cases)" for f, c, n in dead)
        + "\n\nAdd to each class:\n"
        "    def test_all(self, request, tmp_path_factory):\n"
        "        run_cases(self, request, tmp_path_factory)"
    )


def test_no_blocking_socket_call_is_unbounded():
    """A SOCKET CALL WITH NO TIMEOUT CAN HANG THE WHOLE SUITE.

    pytest has no default per-test timeout, so one `recv` on a peer that
    accepts and never answers does not fail the case — it stops the run, and
    the job idles to whatever outer cap exists with nothing reported. A peer
    session measured exactly that on its own runner: one job past 43 minutes
    while its siblings finished in 39 seconds, and NO check anywhere said
    "failed".

    A global timeout is the wrong fix and is deliberately not used here: a
    value large enough for a slow machine cannot catch a hang, and one small
    enough to catch it turns a slow machine red. This reads source instead —
    it cannot make a slow runner fail, only an unbounded call.

    WHY A GUARD RATHER THAN CARE. The same peer swept its suite BY HAND three
    times and missed the same shape three times; my own sweep of this suite
    was by hand too. Judgement does not scale to a file that keeps growing.

    Scoped to `connect`/`recv`/`accept` on a bare socket — the calls that
    block forever by default. `create_connection` is covered because its
    timeout argument is what a caller forgets.
    """
    import pathlib
    import re

    # `recv` on a socket whose timeout was set earlier is fine, so this looks
    # for the two shapes that CANNOT have one: a connection built with no
    # timeout=, and a bare `socket.socket()` used without `settimeout`.
    unbounded = []
    for path in sorted(pathlib.Path(__file__).parent.glob("test_*.py")):
        lines = path.read_text().splitlines()
        for n, line in enumerate(lines, 1):
            if "# noqa: unbounded" in line:
                continue  # deliberate, and it has to say so
            if "socket.create_connection(" not in line:
                continue
            # PROSE IS NOT A CALL. A guard that flags the sentence describing
            # it reads as a finding and trains the reader to ignore it — a
            # peer's first version of this same guard did exactly that.
            if re.match(r"\s*[#*]|\s*`|\s*\"\"\"", line) or "`" in line:
                continue
            # THE ARGUMENTS MAY WRAP: `create_connection(\n  addr,\n
            # timeout=5)` is bounded and looks unbounded on line 1 alone. So
            # read to the paren that CLOSES the call — the first `)` is the
            # address tuple's, and stopping there flagged every bounded call
            # in the suite while looking correct.
            call = "\n".join(lines[n - 1:n + 4])
            call = call[call.index("create_connection("):]
            depth, end = 0, len(call)
            for i, ch in enumerate(call):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if "timeout" in call[:end]:
                continue
            unbounded.append(f"{path.name}:{n}: {line.strip()}")

    assert not unbounded, (
        "socket call(s) with no timeout — one of these can hang the entire "
        "run with nothing reported, because pytest has no default per-test "
        "deadline:\n" + "\n".join(f"  {u}" for u in unbounded)
        + "\n\nPass timeout=, or mark the line `# noqa: unbounded` if the "
        "block is the point of the test."
    )
