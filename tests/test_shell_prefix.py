"""The opt-in `CLAUDE_CODE_SHELL_PREFIX` script: the file, and what it does.

The pin never sets that variable. A user who wants the programs a pinned Claude
Code starts (Bash tool, hooks, stdio MCP servers, status line) off the pin sets
it themselves, to a file this package writes on request. Those programs get the
proxy the user had before the pin wired itself in, or none: the pin writes that
value to a file beside the script, and the script hands it over.

Two halves, kept apart. The first is the writer: exact text, mode 0755, atomic,
compare-before-write, refreshed by `heal` only once it exists. The second runs
the REAL written file under /bin/sh with the three spawn shapes Claude Code
2.1.296 uses, each built from an environment made from scratch (never a copy of
this process's own, which may itself carry a pin's proxy variables).

The wiring guard at the end pins the other half of the owner's order: nothing
here ever writes the variable, and the env block keeps exactly its five keys.
"""

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SIX = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")
SIX_SET = "".join("${%s+S}" % v for v in SIX)  # shell: one S per proxy variable that is set
NO_PROXY = "localhost,example.test"


def _proxy():
    import cswap_pin.proxy as pin_proxy

    return pin_proxy


@pytest.fixture
def state(tmp_path):
    return tmp_path / "state" / "pin-proxy"


@pytest.fixture
def prefix(state):
    return _proxy().write_shell_prefix(state)


def _env(tmp_path, **extra):
    """An environment built from scratch: the six proxies set, NO_PROXY set."""
    env = {"HOME": str(tmp_path), "PATH": os.environ["PATH"],
           "NO_PROXY": NO_PROXY, "no_proxy": NO_PROXY}
    env.update({v: "http://127.0.0.1:1" for v in SIX})
    env.update(extra)
    return env


def _run(prefix, cmd, env, cwd=None):
    return subprocess.run([str(prefix), cmd], env=env, cwd=cwd, text=True,
                          capture_output=True, timeout=30)


# -- the writer ----------------------------------------------------------------


def test_writes_the_exact_text_at_mode_0755_under_the_state_dir(state):
    pin_proxy = _proxy()
    old = os.umask(0o077)  # a restrictive umask must not take the exec bit away
    try:
        path = pin_proxy.write_shell_prefix(state)
    finally:
        os.umask(old)
    assert path == state.absolute() / "shell-prefix" and path.is_absolute()
    assert path.read_text(encoding="utf-8") == pin_proxy.SHELL_PREFIX_SH
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    # VERBATIM, against a digest of the text as reviewed (T2171), not computed from this code.
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "3874db683982711eac73f40702be82b7da2b9679990e3e11dfbece75ce6126b8")


def test_an_unchanged_file_is_not_rewritten(state):
    pin_proxy = _proxy()
    path = pin_proxy.write_shell_prefix(state)
    os.utime(path, ns=(10**9, 10**9))
    before = path.stat()
    assert pin_proxy.write_shell_prefix(state) == path
    after = path.stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


@pytest.mark.parametrize("content,mode", [
    (b"#!/bin/sh\necho old\n", 0o755),  # stale text
    (b"\xff\xfe\x00", 0o755),            # not text at all
    (None, 0o644),                        # the current text, but not executable
], ids=["stale", "not-text", "not-executable"])
def test_a_file_that_is_not_current_text_at_an_executable_mode_is_replaced(state, content, mode):
    pin_proxy = _proxy()
    state.mkdir(parents=True)
    path = state / "shell-prefix"
    path.write_bytes(pin_proxy.SHELL_PREFIX_SH.encode() if content is None else content)
    path.chmod(mode)
    pin_proxy.write_shell_prefix(state)
    assert path.read_text(encoding="utf-8") == pin_proxy.SHELL_PREFIX_SH
    assert stat.S_IMODE(path.stat().st_mode) == 0o755


def test_a_failed_write_leaves_no_partial_file_and_no_temp(state, monkeypatch):
    pin_proxy = _proxy()

    def boom(*a, **k):
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            pin_proxy.write_shell_prefix(state)
    assert list(state.iterdir()) == [], "a failed first write left something behind"

    (state / "shell-prefix").write_text("#!/bin/sh\necho old\n")
    with monkeypatch.context() as m:
        m.setattr(os, "replace", boom)
        with pytest.raises(OSError):
            pin_proxy.write_shell_prefix(state)
    assert (state / "shell-prefix").read_text() == "#!/bin/sh\necho old\n"
    assert [p.name for p in state.iterdir()] == ["shell-prefix"]


def test_the_command_prints_the_bare_path_or_one_line_on_stderr(state, capsys, monkeypatch):
    pin_proxy = _proxy()
    assert pin_proxy.shell_prefix_main() == 0
    out, err = capsys.readouterr()
    path = Path(out.rstrip("\n"))
    assert out == f"{path}\n" and err == ""
    assert path.is_absolute() and path.name == "shell-prefix" and path.parent.name == "pin-proxy"
    assert path.read_text(encoding="utf-8") == pin_proxy.SHELL_PREFIX_SH

    def boom(_):
        raise PermissionError("denied")

    monkeypatch.setattr(pin_proxy, "write_shell_prefix", boom)
    assert pin_proxy.shell_prefix_main() == 1
    out, err = capsys.readouterr()
    assert out == "" and err.count("\n") == 1 and "denied" in err


def _run_dash_m(tmp_path, *args):
    root = Path(__file__).resolve().parent.parent
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "data"),
           "PATH": os.environ["PATH"], "PYTHONPATH": str(root / "src")}
    return subprocess.run([sys.executable, "-m", "cswap_pin", *args], env=env,
                          text=True, capture_output=True, timeout=60)


def test_python_dash_m_cswap_pin_print_shell_prefix_path_runs_without_a_cswap_change(tmp_path):
    r = _run_dash_m(tmp_path, "print-shell-prefix-path")
    assert r.returncode == 0, r.stderr
    path = Path(r.stdout.rstrip("\n"))
    assert path.is_absolute() and tmp_path in path.parents
    assert path.name == "shell-prefix" and path.parent.name == "pin-proxy"
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert path.read_text(encoding="utf-8") == _proxy().SHELL_PREFIX_SH
    bad = _run_dash_m(tmp_path, "nonsense")
    assert bad.returncode == 2 and bad.stdout == "" and bad.stderr.count("\n") == 1


def test_the_old_name_shell_prefix_is_a_hidden_alias_printing_the_same_path(tmp_path):
    new = _run_dash_m(tmp_path, "print-shell-prefix-path")
    old = _run_dash_m(tmp_path, "shell-prefix")
    assert new.returncode == old.returncode == 0, old.stderr
    assert old.stdout == new.stdout and Path(old.stdout.rstrip("\n")).is_absolute()
    assert old.stderr == ""


def test_the_usage_line_names_only_print_shell_prefix_path(tmp_path):
    r = _run_dash_m(tmp_path)
    assert r.returncode == 2 and r.stdout == ""
    tokens = r.stderr.split()  # whole tokens: the new name contains the old one as a substring
    assert "print-shell-prefix-path" in tokens and "shell-prefix" not in tokens


# -- the `--ensure` path: refresh only a file that is already there -------------


def _pinned_root(tmp_path, monkeypatch):
    """What `heal` needs to get past its early returns, as test_proxy's heal cases build it."""
    import claude_swap.paths as paths
    from cswap_pin.proxy import save_pin

    root = tmp_path / "backup"
    (root / "pin-proxy").mkdir(parents=True)
    save_pin(root, "a@example.com", "org-1")
    (root / "sequence.json").write_text(json.dumps({"accounts": {"1": {"email": "a@example.com"}}}))
    cfg = tmp_path / ".claude.json"
    cfg.write_text("{}")
    monkeypatch.setattr(paths, "get_global_config_path", lambda: cfg)
    monkeypatch.setattr(_proxy(), "_spawn_daemon", lambda *a: 1)
    return root


def test_ensure_refreshes_a_stale_file_and_creates_none(tmp_path, monkeypatch):
    pin_proxy = _proxy()
    root = _pinned_root(tmp_path, monkeypatch)
    path = root / "pin-proxy" / "shell-prefix"

    pin_proxy.heal(root)
    assert not path.exists(), "a user who never opted in got a file"

    path.write_text("#!/bin/sh\necho stale\n")
    path.chmod(0o755)
    pin_proxy.heal(root)
    assert path.read_text(encoding="utf-8") == pin_proxy.SHELL_PREFIX_SH


def test_ensure_never_raises_when_the_file_cannot_be_written(tmp_path, monkeypatch):
    pin_proxy = _proxy()
    root = _pinned_root(tmp_path, monkeypatch)
    path = root / "pin-proxy" / "shell-prefix"
    path.write_text("#!/bin/sh\necho stale\n")
    called = []

    def boom(certdir):
        called.append(certdir)
        raise PermissionError("read-only")

    monkeypatch.setattr(pin_proxy, "write_shell_prefix", boom)
    pin_proxy.heal(root)
    assert called, "the refresh never ran, so the guard around it was not exercised"
    assert path.read_text() == "#!/bin/sh\necho stale\n"


# -- the script, run for real under /bin/sh -------------------------------------


def _shells():
    return [pytest.param(name, marks=pytest.mark.skipif(
        shutil.which(name) is None, reason=f"no {name} here")) for name in ("bash", "zsh")]


BASH_CMD = "\n".join([
    f'echo "six=[{SIX_SET}]"',
    'echo "np=$NO_PROXY,$no_proxy"',
    "printf '%s\\n' 'a \"b\" $HOME'",
    'echo "mark=$SHELL_PREFIX_CLAUDE_PID"',
    'echo "shell=${BASH_VERSION:+bash}${ZSH_VERSION:+zsh}"',
    "exit 7",
])


@pytest.mark.parametrize("shell", _shells())
def test_bash_tool_shape_runs_in_the_chosen_shell_with_the_six_unset(prefix, tmp_path, shell):
    env = _env(tmp_path, SHELL=shutil.which(shell), CLAUDE_PID="4242")
    r = _run(prefix, BASH_CMD, env)
    assert r.stdout.splitlines() == [
        "six=[]", f"np={NO_PROXY},{NO_PROXY}", 'a "b" $HOME', "mark=4242", f"shell={shell}"
    ], r.stderr
    assert r.returncode == 7


@pytest.mark.parametrize("shell", _shells())
def test_a_startup_file_that_re_exports_a_proxy_does_not_win(prefix, tmp_path, shell):
    """The unset runs again INSIDE the chosen shell, after its startup files."""
    rc = tmp_path / "re-export"
    rc.write_text("export HTTPS_PROXY=http://zenv.test https_proxy=http://zenv.test\n")
    (tmp_path / ".zshenv").write_text(rc.read_text())
    env = _env(tmp_path, SHELL=shutil.which(shell), CLAUDE_PID="4242", BASH_ENV=str(rc))
    r = _run(prefix, f'echo "six=[{SIX_SET}]"', env)
    assert r.stdout == "six=[]\n", r.stderr


@pytest.mark.parametrize("shell", _shells())
def test_hook_shape_runs_under_bin_sh_like_a_hook_without_a_prefix(prefix, tmp_path, shell):
    cmd = 'echo /nonexistent-T2134/*.zz "z=${ZSH_VERSION+Z}"; echo "e\\tx"; echo "six=[%s]"' % SIX_SET
    env = _env(tmp_path, SHELL=shutil.which(shell), CLAUDE_PROJECT_DIR="/p", CLAUDE_PID="4242")
    control = subprocess.run(["/bin/sh", "-c", cmd], text=True, capture_output=True,
                             env={k: v for k, v in env.items() if k not in SIX})
    got = _run(prefix, cmd, env)
    assert (got.stdout, got.returncode) == (control.stdout, control.returncode)
    assert got.stdout.splitlines()[0].endswith(" z="), "the hook did not run under /bin/sh"
    assert "six=[]" in got.stdout


MCP_SERVER = (
    "import json, os, sys\n"
    "print(json.dumps({'argv': sys.argv[1:], 'pid': os.getpid(), 'ppid': os.getppid(),\n"
    "  'six': [k for k in %r if k in os.environ], 'np': [os.environ.get('NO_PROXY'),\n"
    "  os.environ.get('no_proxy')]}))\n" % (SIX,)
)
MCP_ARGS = ["a b", 'c"d', "$HOME", ";x", "\\y", "-z", "it's"]


def _mcp(prefix, tmp_path, **extra):
    server = tmp_path / "server.py"
    server.write_text(MCP_SERVER)
    cmd = " ".join(shlex.quote(a) for a in [sys.executable, str(server), *MCP_ARGS])
    proc = subprocess.Popen([str(prefix), cmd], env=_env(tmp_path, CLAUDE_PROJECT_DIR="/p", **extra),
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 0, err
    return proc.pid, json.loads(out)


def test_mcp_shape_becomes_the_server_with_exact_argv(prefix, tmp_path):
    spawned, got = _mcp(prefix, tmp_path)
    assert got["argv"] == MCP_ARGS
    assert got["pid"] == spawned and got["ppid"] == os.getpid(), "a wrapper process was left in front"
    assert got["six"] == [] and got["np"] == [NO_PROXY, NO_PROXY]


def test_a_nested_claudes_mcp_server_is_told_from_a_hook_by_the_marker(prefix, tmp_path):
    spawned, got = _mcp(prefix, tmp_path, CLAUDE_PID="1234", SHELL_PREFIX_CLAUDE_PID="1234")
    assert got["pid"] == spawned and got["argv"] == MCP_ARGS
    # The same CLAUDE_PID against a DIFFERENT marker is a hook: /bin/sh runs both statements.
    # (An MCP-branch `exec` would stop after the first.)
    env = _env(tmp_path, CLAUDE_PROJECT_DIR="/p", CLAUDE_PID="1234", SHELL_PREFIX_CLAUDE_PID="999")
    assert _run(prefix, "echo a; echo b", env).stdout == "a\nb\n"
    env["SHELL_PREFIX_CLAUDE_PID"] = "1234"
    assert _run(prefix, "echo a; echo b", env).stdout == "a\n"


PREV = """#!/bin/sh
{ printf 'argc=%s\\n' "$#"; printf 'arg=%s\\n' "$1"
  printf 'six=[%s]\\n' "@SIX@"; printf 'prevvar=[%s]\\n' "${CSWAP_PIN_PREV_SHELL_PREFIX+S}"; } >> "$LOG"
exec /bin/sh -c "$1"
""".replace("@SIX@", SIX_SET)


def _chain_env(tmp_path, prev, shell="bash"):
    return _env(tmp_path, SHELL=shutil.which(shell) or "/bin/sh", CLAUDE_PID="4242",
                CSWAP_PIN_PREV_SHELL_PREFIX=str(prev), LOG=str(tmp_path / "log"),
                OUT=str(tmp_path / "out"))


def test_an_absolute_prev_prefix_runs_once_with_the_one_argument_and_the_six_unset(prefix, tmp_path):
    prev = tmp_path / "prev.sh"
    prev.write_text(PREV)
    prev.chmod(0o755)
    cmd = 'echo ran >> "$OUT"; echo "six=[%s]"' % SIX_SET
    r = _run(prefix, cmd, _chain_env(tmp_path, prev))
    assert r.returncode == 0, r.stderr
    assert r.stdout == "six=[]\n"
    assert (tmp_path / "log").read_text().splitlines() == [
        "argc=1", f"arg={cmd}", "six=[]", "prevvar=[]"], "prev must run once, with the one argument"
    assert (tmp_path / "out").read_text() == "ran\n"


@pytest.mark.parametrize("kind", ["relative", "missing", "not-executable", "self-loop"])
def test_a_prev_prefix_that_cannot_chain_is_skipped_and_the_command_still_runs(prefix, tmp_path, kind):
    prev = tmp_path / "prev.sh"
    prev.write_text(PREV)
    prev.chmod(0o755)
    chosen = {"relative": "prev.sh", "missing": str(tmp_path / "nope.sh"),
              "not-executable": str(tmp_path / "plain.sh"), "self-loop": str(prefix)}[kind]
    (tmp_path / "plain.sh").write_text(PREV)
    (tmp_path / "plain.sh").chmod(0o644)
    r = _run(prefix, 'echo ran >> "$OUT"', _chain_env(tmp_path, chosen), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "out").read_text() == "ran\n", "the command did not run exactly once"
    assert not (tmp_path / "log").exists(), "a prefix that cannot chain was run"


# -- the proxy the children get: what the pin writes, and what the script does with it ----

SIDECAR = "shell-prefix.proxy"
BEFORE = "http://user:pw@proxy.example:3128"  # the proxy the user had before the pin, credentialed
OTHER = "http://other.example:8080"
TRICKY = "http://us$er:p'w\"d`x@proxy.example:3128/?a=b&c;d"  # every character a shell would act on
VALUES = " ".join('"$%s"' % v for v in SIX)


@pytest.fixture
def certdir(state, monkeypatch):
    """The pin's directory as a launch leaves it, with no probe memory from another test."""
    pin_proxy = _proxy()
    monkeypatch.setattr(pin_proxy, "_ASKED_NOHEALTH", set())
    monkeypatch.setattr(pin_proxy, "_ANSWERED_HEALTH", set())
    state.mkdir(parents=True)
    return state


class _Health:
    """A local proxy answering /health with `answer`, or with 400 when `answer` is None."""

    def __init__(self, answer):
        import http.server
        import threading

        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(outer.answer).encode()
                self.send_response(200 if outer.answer is not None else 400)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.answer = answer
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def _launch(certdir, proxy, **kw):
    """What `ensure_proxy` does with a hop: ask it, then record what it said."""
    pin_proxy = _proxy()
    pin_proxy.write_upstream_hint(certdir, proxy, next_hop=pin_proxy._probe_next_hop(proxy, timeout=10), **kw)


def _child_proxy(certdir):
    return (certdir / SIDECAR).read_text()


# The four cases the children's proxy comes from.
def test_pin_only_the_children_get_the_proxy_the_user_had(certdir):
    _launch(certdir, BEFORE)
    assert _child_proxy(certdir) == BEFORE + "\n", "a credentialed proxy is kept as recorded"


def test_pin_only_a_local_proxy_that_is_not_a_cache_proxy_is_the_proxy_the_user_had(certdir):
    with _Health(None) as hop:  # answers every /health with a 400
        _launch(certdir, hop.url)
        assert _child_proxy(certdir) == hop.url + "\n"
    with _Health({"status": "ok"}) as down:
        gone = down.url
    _launch(certdir, gone)  # and one that gives no answer at all
    assert _child_proxy(certdir) == gone + "\n"


def test_pin_and_a_cache_proxy_the_children_get_the_hop_behind_it(certdir):
    with _Health({"https_proxy": BEFORE}) as cache:
        _launch(certdir, cache.url)
    assert _child_proxy(certdir) == BEFORE + "\n"


def test_pin_and_a_cache_proxy_that_names_no_upstream_the_children_get_none(certdir):
    with _Health({"status": "ok"}) as cache:
        _launch(certdir, cache.url)
        assert json.loads((certdir / "upstream.json").read_text())["cache"] == cache.url.removeprefix("http://")
    assert _child_proxy(certdir) == "", "the cache proxy's own address reached the children"


@pytest.mark.parametrize("record", ["proxy.json", "port.hint"])
def test_a_hop_behind_the_cache_proxy_that_names_the_pin_itself_is_not_handed_over(certdir, record):
    """A first daemon has `proxy.json` and no `port.hint`; the hint is only left by a teardown."""
    pin_proxy = _proxy()
    if record == "proxy.json":
        pin_proxy.write_daemon_state(certdir, 40123, os.getpid(), "FP")
    else:
        pin_proxy._write_port_hint(certdir, 40123)
    with _Health({"https_proxy": "http://127.0.0.1:40123"}) as cache:  # started from a pinned shell
        _launch(certdir, cache.url)
    assert json.loads((certdir / "upstream.json").read_text())["next"] == "http://127.0.0.1:40123", "the control"
    assert _child_proxy(certdir) == ""


def test_a_cache_proxy_that_names_the_pin_to_the_daemon_is_recorded_as_one_and_the_children_get_none(certdir):
    """The daemon's timer refuses to record the pin as a next hop, but it still learned
    that the hop is a cache proxy: the children must not get the cache proxy's own address."""
    import functools

    pin_proxy = _proxy()
    with _Health({"https_proxy": "http://127.0.0.1:40123"}) as cache:
        pin_proxy.write_upstream_hint(certdir, cache.url)
        assert _child_proxy(certdir) == cache.url + "\n", "the control: nothing has asked the hop yet"
        daemon = pin_proxy.PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                                    upstream=("127.0.0.1", 1), rediscover_chain=True)
        daemon.port = 40123
        with pytest.MonkeyPatch.context() as m:
            m.setattr(pin_proxy, "_probe_next_hop", functools.partial(pin_proxy._probe_next_hop, timeout=10))
            daemon.learn_next_hop()
    record = json.loads((certdir / "upstream.json").read_text())
    assert (record["next"], record["cache"]) == ("", cache.url.removeprefix("http://")), record
    assert _child_proxy(certdir) == ""


def test_a_stale_next_is_not_handed_over_once_the_first_hop_is_not_a_local_proxy(certdir):
    """`write_upstream_hint` keeps an earlier `next` when the first hop changes. Only a loopback
    first hop is ever asked, so only there can `next` be what stands behind it."""
    with _Health({"https_proxy": BEFORE}) as cache:
        _launch(certdir, cache.url)
    _proxy().write_upstream_hint(certdir, OTHER)  # a re-pin from a shell exporting a corporate proxy
    record = json.loads((certdir / "upstream.json").read_text())
    assert (record["proxy"], record["next"]) == (OTHER, BEFORE), "the control"
    assert _child_proxy(certdir) == OTHER + "\n"


def test_no_proxy_at_all_the_children_get_none(certdir):
    _launch(certdir, None)
    assert _child_proxy(certdir) == ""


# What a launch that cannot ask does with what an earlier one learned.
def test_a_launch_that_cannot_ask_keeps_that_the_hop_is_a_cache_proxy(certdir):
    pin_proxy = _proxy()
    with _Health({"status": "ok"}) as cache:
        _launch(certdir, cache.url)
        pin_proxy._ANSWERED_HEALTH.clear()  # a new process: it never asked this hop
        pin_proxy.write_upstream_hint(certdir, cache.url)
        pin_proxy.write_upstream_hint(certdir, None)  # and one from a shell that sees no proxy
    assert _child_proxy(certdir) == ""


def test_a_hop_that_now_answers_a_4xx_is_not_kept_as_a_cache_proxy(certdir):
    pin_proxy = _proxy()
    with _Health({"status": "ok"}) as cache:
        _launch(certdir, cache.url)
        cache.answer = None  # something else holds the port now
        pin_proxy._ANSWERED_HEALTH.clear()
        _launch(certdir, cache.url)
    assert _child_proxy(certdir) == cache.url + "\n"
    assert "cache" not in json.loads((certdir / "upstream.json").read_text())


def test_a_hop_answering_a_4xx_after_a_200_in_the_same_process_is_not_a_cache_proxy(certdir):
    pin_proxy = _proxy()
    with _Health({"status": "ok"}) as hop:
        _launch(certdir, hop.url)
        hop.answer = None
        pin_proxy._probe_next_hop(hop.url, timeout=10)
        pin_proxy.write_upstream_hint(certdir, hop.url)
    assert _child_proxy(certdir) == hop.url + "\n"


def test_a_different_hop_does_not_inherit_the_cache_proxy_record(certdir):
    pin_proxy = _proxy()
    with _Health({"status": "ok"}) as cache:
        _launch(certdir, cache.url)
    pin_proxy._ANSWERED_HEALTH.clear()
    pin_proxy.write_upstream_hint(certdir, OTHER)
    assert _child_proxy(certdir) == OTHER + "\n"


def test_a_launch_that_cannot_ask_keeps_the_hop_behind_the_cache_proxy(certdir):
    with _Health({"https_proxy": BEFORE}) as cache:
        _launch(certdir, cache.url)
        _proxy().write_upstream_hint(certdir, None)
    assert _child_proxy(certdir) == BEFORE + "\n"


def test_the_child_proxy_file_has_the_mode_of_upstream_json_and_leaves_no_temp(certdir):
    old = os.umask(0o027)
    try:
        _proxy().write_upstream_hint(certdir, BEFORE)
    finally:
        os.umask(old)
    assert stat.S_IMODE((certdir / SIDECAR).stat().st_mode) == stat.S_IMODE((certdir / "upstream.json").stat().st_mode)
    assert sorted(p.name for p in certdir.iterdir()) == [SIDECAR, "upstream.json"]


@pytest.mark.parametrize("answer,expected", [({"https_proxy": BEFORE}, BEFORE + "\n"), ({"status": "ok"}, "")],
                         ids=["names-an-upstream", "names-none"])
def test_the_daemon_asking_a_cache_proxy_refreshes_the_file(certdir, answer, expected):
    """`learn_next_hop` is the other writer. The launch that recorded the hop did not ask it,
    the way a launch from the shell that runs the hop does not (`own_proxy`)."""
    import functools

    pin_proxy = _proxy()
    with _Health(answer) as cache:
        pin_proxy.write_upstream_hint(certdir, cache.url)
        assert _child_proxy(certdir) == cache.url + "\n", "the control: nothing has asked the hop yet"
        daemon = pin_proxy.PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                                    upstream=("127.0.0.1", 1), rediscover_chain=True)
        with pytest.MonkeyPatch.context() as m:
            m.setattr(pin_proxy, "_probe_next_hop", functools.partial(pin_proxy._probe_next_hop, timeout=10))
            daemon.learn_next_hop()
    assert _child_proxy(certdir) == expected


def _ensure_proxy(tmp_path, monkeypatch):
    """`ensure_proxy`, the writer every launch goes through, with all but the record stubbed.

    Returns the pin's directory under `tmp_path / "backup"`."""
    pin_proxy = _proxy()

    class Switcher:
        backup_dir = tmp_path / "backup"

        def resolve_account(self, email):
            return "1", email, None

    monkeypatch.setattr(pin_proxy, "load_pin", lambda _b: ("a@example.com", ""))
    monkeypatch.setattr(pin_proxy, "_carry_history_pointers", lambda _c: None)
    monkeypatch.setattr(pin_proxy, "daemon_fingerprint", lambda *_a: "FP")
    monkeypatch.setattr(pin_proxy, "ensure_ca", lambda *_a: None)
    monkeypatch.setattr(pin_proxy, "publish_ca", lambda _p: None)
    monkeypatch.setattr(pin_proxy, "wire_global_config", lambda *_a: None)
    monkeypatch.setattr(pin_proxy, "_read_alive_port", lambda *_a, **_k: 1234)
    monkeypatch.setattr(pin_proxy, "_move_into_this_lineage", lambda _c, _n, _e, port: port)
    assert pin_proxy.ensure_proxy(Switcher()) is not None
    return Switcher.backup_dir / "pin-proxy"


def test_a_launch_writes_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(_proxy(), "_ambient_chain", lambda **_k: (BEFORE, None))
    assert _child_proxy(_ensure_proxy(tmp_path, monkeypatch)) == BEFORE + "\n"


@pytest.mark.parametrize("script", ["stale", "current"])
def test_ensure_leaves_the_file_on_a_host_whose_record_is_already_stable(tmp_path, monkeypatch, script):
    """An upgraded host: `upstream.json` is settled, so no launch or timer will write the file."""
    pin_proxy = _proxy()
    root = _pinned_root(tmp_path, monkeypatch)
    certdir = root / "pin-proxy"
    (certdir / "upstream.json").write_text(json.dumps({"proxy": BEFORE, "ca": "", "next": ""}))
    if script == "current":
        pin_proxy.write_shell_prefix(certdir)
    else:
        (certdir / "shell-prefix").write_text("#!/bin/sh\necho stale\n")
    assert not (certdir / SIDECAR).exists(), "the control"
    pin_proxy.heal(root)
    assert _child_proxy(certdir) == BEFORE + "\n"


def test_the_command_leaves_the_file_beside_the_script_on_a_host_whose_record_is_already_stable(capsys):
    pin_proxy = _proxy()
    assert pin_proxy.shell_prefix_main() == 0
    certdir = Path(capsys.readouterr().out.rstrip("\n")).parent
    (certdir / SIDECAR).unlink(missing_ok=True)
    (certdir / "upstream.json").write_text(json.dumps({"proxy": BEFORE, "ca": "", "next": ""}))
    assert pin_proxy.shell_prefix_main() == 0  # the script is current: only the file is owed
    assert _child_proxy(certdir) == BEFORE + "\n"


def _launch_from(tmp_path, monkeypatch, shell_proxy, pin_port):
    """A `cswap pin` run from a shell exporting `shell_proxy`, over a record whose first hop is
    down and whose second is BEFORE. Returns the pin's directory."""
    certdir = tmp_path / "backup" / "pin-proxy"
    certdir.mkdir(parents=True)
    with _Health({"status": "ok"}) as down:
        gone = down.url
    _proxy().write_upstream_hint(certdir, gone, next_hop=BEFORE)
    for k in (*SIX, "CSWAP_PIN_PORT", "NODE_EXTRA_CA_CERTS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", shell_proxy)
    if pin_port:
        monkeypatch.setenv("CSWAP_PIN_PORT", pin_port)
    assert _ensure_proxy(tmp_path, monkeypatch) == certdir
    return certdir, gone


@pytest.mark.parametrize("pin_port", [None, "51000"], ids=["pin-port-unset", "pin-port-set"])
def test_a_pin_run_from_a_child_keeps_the_hop_in_front_while_it_is_down(tmp_path, monkeypatch, pin_port):
    """A child carries the hop behind the recorded one. Adopted as the FIRST hop while the recorded
    one is down, it drops that hop for good (28dad1d, 7acfec1: the same pollution by the pin's own URL)."""
    certdir, gone = _launch_from(tmp_path, monkeypatch, BEFORE, pin_port)
    record = json.loads((certdir / "upstream.json").read_text())
    assert (record["proxy"], record["next"]) == (gone, BEFORE), record
    assert _child_proxy(certdir) == BEFORE + "\n"


def test_a_pin_run_from_a_shell_with_another_proxy_still_records_it(tmp_path, monkeypatch):
    """The control: only the hop behind the recorded one is refused, any other proxy is a choice."""
    certdir, _ = _launch_from(tmp_path, monkeypatch, OTHER, "51000")
    record = json.loads((certdir / "upstream.json").read_text())
    assert (record["proxy"], record["next"]) == (OTHER, BEFORE), record


def test_a_degraded_holder_still_relays_through_the_hop_it_inherited_when_that_is_the_recorded_next(
        certdir, monkeypatch):
    """The holder's blind relay is the only thing holding the machine up. An ssh shell exports the
    machine egress, which the record also holds as `next`; the recorded first hop is down."""
    import socket
    import threading

    pin_proxy = _proxy()
    hop = socket.create_server(("127.0.0.1", 0))
    hop.settimeout(10)
    asked = []

    def serve():
        conn, _ = hop.accept()
        asked.append(conn.recv(4096))
        conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    egress = f"http://127.0.0.1:{hop.getsockname()[1]}"
    with _Health({"status": "ok"}) as down:
        gone = down.url
    pin_proxy.write_upstream_hint(certdir, gone, next_hop=egress)
    for k in (*SIX, "CSWAP_PIN_PORT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", egress)
    holder = pin_proxy.PortHolder.__new__(pin_proxy.PortHolder)
    holder._certdir = certdir
    client, conn = socket.socketpair()
    client.settimeout(10)
    relay = threading.Thread(target=holder._relay_one, args=(conn,), daemon=True)
    relay.start()
    client.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
    reply = client.recv(64)
    client.close()
    relay.join(10)
    hop.close()
    assert asked and asked[0].startswith(b"CONNECT example.test:443"), "the relay never reached the inherited hop"
    assert reply.startswith(b"HTTP/1.1 200"), reply


def _put(prefix, value):
    (prefix.parent / SIDECAR).write_text("" if value is None else value + "\n")


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize("value", [BEFORE, TRICKY], ids=["credentialed", "every-shell-character"])
def test_the_bash_tool_gets_the_recorded_proxy_in_all_six_and_not_the_holder(prefix, tmp_path, shell, value):
    _put(prefix, value)
    cmd = f"printf '%s\\n' {VALUES}; echo \"holder=${{CSWAP_PIN_CHILD_PROXY+S}}\"; echo \"np=$NO_PROXY\""
    r = _run(prefix, cmd, _env(tmp_path, SHELL=shutil.which(shell), CLAUDE_PID="4242"))
    assert r.stdout.splitlines() == [value] * 6 + ["holder=", f"np={NO_PROXY}"], r.stderr


@pytest.mark.parametrize("shell", _shells())
def test_a_startup_file_that_exports_another_proxy_does_not_win_over_the_recorded_one(prefix, tmp_path, shell):
    _put(prefix, BEFORE)
    rc = tmp_path / "re-export"
    rc.write_text("export HTTPS_PROXY=http://zenv.test https_proxy=http://zenv.test\n")
    (tmp_path / ".zshenv").write_text(rc.read_text())
    env = _env(tmp_path, SHELL=shutil.which(shell), CLAUDE_PID="4242", BASH_ENV=str(rc))
    r = _run(prefix, f"printf '%s\\n' {VALUES}", env)
    assert r.stdout.splitlines() == [BEFORE] * 6, r.stderr


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize("kind", ["empty-file", "no-file"])
def test_an_empty_or_missing_file_unsets_the_six_as_before(prefix, tmp_path, kind, shell):
    if kind == "empty-file":
        _put(prefix, None)
    r = _run(prefix, f'echo "six=[{SIX_SET}] holder=[${{CSWAP_PIN_CHILD_PROXY+S}}]"',
             _env(tmp_path, SHELL=shutil.which(shell), CLAUDE_PID="4242", CSWAP_PIN_CHILD_PROXY="inherited"))
    assert r.stdout == "six=[] holder=[]\n", r.stderr


def test_the_hook_shape_gets_the_recorded_proxy(prefix, tmp_path):
    _put(prefix, BEFORE)
    env = _env(tmp_path, CLAUDE_PROJECT_DIR="/p", CLAUDE_PID="4242")
    r = _run(prefix, f"printf '%s\\n' {VALUES}; echo \"holder=${{CSWAP_PIN_CHILD_PROXY+S}}\"", env)
    assert r.stdout.splitlines() == [BEFORE] * 6 + ["holder="], r.stderr


def test_an_mcp_server_is_started_with_the_recorded_proxy_and_without_the_holder(prefix, tmp_path):
    _put(prefix, BEFORE)
    server = tmp_path / "server.py"
    server.write_text("import json, os\nprint(json.dumps({k: os.environ.get(k) for k in "
                      "%r + ('CSWAP_PIN_CHILD_PROXY',)}))\n" % (SIX,))
    r = _run(prefix, f"{shlex.quote(sys.executable)} {shlex.quote(str(server))}",
             _env(tmp_path, CLAUDE_PROJECT_DIR="/p"))
    got = json.loads(r.stdout)
    assert [got[v] for v in SIX] == [BEFORE] * 6 and got["CSWAP_PIN_CHILD_PROXY"] is None, r.stderr


def test_a_chained_prefix_is_run_with_the_recorded_proxy_and_without_the_holder(prefix, tmp_path):
    _put(prefix, BEFORE)
    prev = tmp_path / "prev.sh"
    prev.write_text("#!/bin/sh\nprintf '%s\\n' " + VALUES + ' "holder=${CSWAP_PIN_CHILD_PROXY+S}" >> "$LOG"\n'
                    'exec /bin/sh -c "$1"\n')
    prev.chmod(0o755)
    r = _run(prefix, "true", _chain_env(tmp_path, prev))
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "log").read_text().splitlines() == [BEFORE] * 6 + ["holder="]


# -- the owner's order: the wiring is untouched ----------------------------------

ENV_KEYS = {"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "NODE_EXTRA_CA_CERTS", "CSWAP_PIN_PORT"}


def test_the_wiring_writes_the_same_five_keys_and_never_the_prefix(tmp_path, monkeypatch, state):
    from cryptography.hazmat.primitives import serialization

    pin_proxy = _proxy()
    cfg = tmp_path / "claude.json"
    users = "/home/me/their-own-prefix"
    cfg.write_text(json.dumps({"env": {"CLAUDE_CODE_SHELL_PREFIX": users}}))
    monkeypatch.setattr("claude_swap.paths.get_global_config_path", lambda: cfg)
    ca = tmp_path / "ca.pem"
    ca.write_bytes(pin_proxy._make_ca()[0].public_bytes(serialization.Encoding.PEM))

    pin_proxy.write_shell_prefix(state)  # the opt-in file existing changes nothing below
    assert pin_proxy.wire_global_config(9955, ca) is True
    env = json.loads(cfg.read_text())["env"]
    assert set(env) - {"CLAUDE_CODE_SHELL_PREFIX"} == ENV_KEYS
    assert env["CLAUDE_CODE_SHELL_PREFIX"] == users, "the user's own prefix was touched"
    receipts = list((Path(pin_proxy.require("paths").get_backup_root()) / "pin-wiring").glob("*.json"))
    assert receipts and all("CLAUDE_CODE_SHELL_PREFIX" not in p.read_text() for p in receipts)

    assert pin_proxy.wire_global_config(None, None) is True
    assert json.loads(cfg.read_text())["env"] == {"CLAUDE_CODE_SHELL_PREFIX": users}


def test_the_readme_states_the_version_pair_once_and_not_ahead_of_the_package():
    """ONE PLACE. The README named the pair twice and let it age 27 releases.

    Not ahead of the package: a pair naming a release that does not exist is a
    typo. NOT EQUAL to it, deliberately: the release tool bumps `pyproject.toml`
    alone, so an equality check would turn the publish gate red on every bump.
    """
    import re

    root = Path(__file__).resolve().parent.parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M).group(1)
    named = re.findall(r"cswap-pin==([0-9][^\s`\"']*)", readme)
    as_tuple = lambda v: tuple(int(n) for n in v.split("."))  # noqa: E731
    assert len(named) == 1 and as_tuple(named[0]) <= as_tuple(version), (named, version)


def test_the_readme_carries_the_script_it_ships():
    root = Path(__file__).resolve().parent.parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert _proxy().SHELL_PREFIX_SH.rstrip("\n") in readme
