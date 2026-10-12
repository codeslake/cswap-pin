"""The opt-in `CLAUDE_CODE_SHELL_PREFIX` script: the file, and what it does.

The pin never sets that variable. A user who wants the programs a pinned Claude
Code starts (Bash tool, hooks, stdio MCP servers, status line) off the pin sets
it themselves, to a file this package writes on request.

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
    # VERBATIM, against a digest taken from the file the analysis measured, not from this code.
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "338b45a83a0f530c65e84a16d38151f803eedf0c2d5ba08bbd93eaecd5d05bf0")


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


def test_python_dash_m_cswap_pin_shell_prefix_runs_without_a_cswap_change(tmp_path):
    root = Path(__file__).resolve().parent.parent
    env = {"HOME": str(tmp_path), "XDG_DATA_HOME": str(tmp_path / "data"),
           "PATH": os.environ["PATH"], "PYTHONPATH": str(root / "src")}
    r = subprocess.run([sys.executable, "-m", "cswap_pin", "shell-prefix"], env=env,
                       text=True, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    path = Path(r.stdout.rstrip("\n"))
    assert path.is_absolute() and tmp_path in path.parents
    assert path.name == "shell-prefix" and path.parent.name == "pin-proxy"
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    assert path.read_text(encoding="utf-8") == _proxy().SHELL_PREFIX_SH
    bad = subprocess.run([sys.executable, "-m", "cswap_pin", "nonsense"], env=env,
                         text=True, capture_output=True, timeout=60)
    assert bad.returncode == 2 and bad.stdout == "" and bad.stderr.count("\n") == 1


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
