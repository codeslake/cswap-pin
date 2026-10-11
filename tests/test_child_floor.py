"""Children of a pinned Claude Code session ride the floor, not the pin (T2134).

`wire_global_config` writes HTTPS_PROXY, https_proxy and ALL_PROXY (the pin's
port) into the `env` block of `.claude.json`. Claude Code applies that block to
itself, and every process it starts inherits it: aws, git, curl, pip, hooks,
stdio MCP servers and the status line then ride pin -> CCF too. Only Claude
Code's own traffic should. So the pin also writes CLAUDE_CODE_SHELL_PREFIX, a
script Claude Code puts in front of every Bash command, command hook and stdio
MCP server, and the script points those children at the FLOOR: the proxy below
the pin (what the recorded cache proxy publishes as its own floor, or the
recorded hop itself when that is not a cache proxy), or nothing when the pin
dials direct. The floor is published where any local proxy can publish its own:
`${CLAUDE_CONFIG_DIR:-$HOME/.claude}/proxy-floor/<port>`.

The script is the user's last line of defence against a broken shell prefix, so
every case that runs it runs the real file under a real `sh`, `bash` and `zsh`.
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import shlex
import shutil
import socket
import stat
import subprocess
import threading
from pathlib import Path

import pytest

from conftest import run_cases

PIN = 9955
KEY = "CLAUDE_CODE_SHELL_PREFIX"
SIX = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
       "ALL_PROXY", "all_proxy")
FLOOR_URL = "http://127.0.0.1:8118"


def _pin_url(port=PIN):
    return f"http://127.0.0.1:{port}"


def _floor_file(port=PIN):
    """Where the proxy on `port` publishes its floor: `proxy-floor/<port>` in the
    Claude config home the suite redirected."""
    from claude_swap.paths import get_claude_config_home
    return get_claude_config_home() / "proxy-floor" / str(port)


def _own_home(tmp_path, monkeypatch):
    """A config home of this case's own, so two daemons in one case do not share
    a floor directory."""
    home = Path(tmp_path) / "claude-home"
    monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
    return home


def _serve_health(answer):
    """A /health server that answers `answer` (a dict) with a 200. Change what it
    says through `srv.RequestHandlerClass.answer`."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(self.answer).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    H.answer = answer
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _vanish_after_test(tmp_path, suffix):
    """The env that makes bash's `[ -r FILE ]` delete FILE (a path ending in
    `suffix`) as it answers: the file the script just found is gone when it
    opens it. Run the script with bash as its interpreter."""
    hook = Path(tmp_path) / "vanish.bash"
    hook.write_text('[() {\n  builtin "[" "$@"; local rc=$?\n'
                    '  case "$1:$2" in -r:*"$VANISH") command rm -f -- "$2" ;; esac\n'
                    '  return $rc\n}\n')
    return {"BASH_ENV": str(hook), "VANISH": suffix}


class _Rig:
    """The real script in a scratch wiring dir, and a way to run it."""

    def __init__(self, tmp_path, user_prefix=None):
        from cswap_pin import proxy as pp

        self.dir = Path(tmp_path) / "rig"
        self.script = pp._write_child_floor_script(self.dir)
        if user_prefix:
            (self.dir / "child-prefix").write_text(user_prefix + "\n")
        self.tmp = Path(tmp_path)

    def floor(self, text, config=None, port=PIN):
        """None removes the floor file (UNKNOWN); "" is DIRECT. `config` is the
        Claude config dir the script will resolve (default `$HOME/.claude`)."""
        path = Path(config or self.tmp / ".claude") / "proxy-floor" / str(port)
        if text is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def env(self, shell, **extra):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp), "SHELL": shell,
               "CSWAP_PIN_PORT": str(PIN),
               # What the env block gives every child of a pinned session.
               "HTTPS_PROXY": _pin_url(), "https_proxy": _pin_url(),
               "ALL_PROXY": _pin_url()}
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def run(self, command, env, interp=None, timeout=30):
        argv = ([interp] if interp else []) + [str(self.script), command]
        return subprocess.run(argv, env=env, capture_output=True, text=True,
                              timeout=timeout)

    def bash_tool(self, command, snapshot="zsh"):
        """The string Claude Code 2.1.296 hands the prefix for a Bash-tool
        command: it sources a snapshot written for the shell it picked (the file
        name says which; no `snapshot` is a snapshot that failed), evals the
        command, and reads the cwd back."""
        source = (f"source '{self.tmp}/shell-snapshots/snapshot-{snapshot}-"
                  "1700000000000-ab12cd.sh' 2>/dev/null || true && "
                  if snapshot else "")
        return (f"{source}{{ shopt -u extglob || setopt NO_EXTENDED_GLOB "
                "NO_BARE_GLOB_QUAL; } >/dev/null 2>&1 || true && "
                "{ \\builtin unalias -- 'unsetenv'; } >/dev/null 2>&1 || true && "
                f"eval {shlex.quote(command)} && pwd -P >| '{self.tmp}/cwd'")

    def seen(self, shell, interp=None, **extra):
        """The proxy variables a command run through the script sees."""
        report = ('for n in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy '
                  'ALL_PROXY all_proxy NO_PROXY; do '
                  'eval "v=\\${$n-UNSET}"; echo "$n=$v"; done')
        done = self.run(report, self.env(shell, **extra), interp)
        assert done.returncode == 0, done
        return dict(line.split("=", 1) for line in done.stdout.splitlines())


def _shells():
    """The shells Claude Code picks (bash or zsh) that exist here."""
    return [s for s in (shutil.which("bash"), shutil.which("zsh")) if s]


class TestChildFloorWiring:
    """The env block names the script, the receipt owns the key, and an
    unwire takes the key out and leaves the script where it is."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _config(self, tmp_path, monkeypatch, initial):
        path = Path(tmp_path) / ".claude.json"
        path.write_text(json.dumps(initial), encoding="utf-8")
        monkeypatch.setattr("claude_swap.paths.get_global_config_path",
                            lambda: path)
        return path

    def _dir(self):
        """Where the script and the chained prefix live: beside the receipts."""
        from claude_swap.paths import get_backup_root
        return Path(get_backup_root()) / "pin-wiring"

    def case_wire_writes_the_prefix_key_and_an_executable_script(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy as pp

        cfg = self._config(tmp_path, monkeypatch, {})
        assert pp.wire_global_config(9955, Path(tmp_path) / "ca.pem") is True
        env = json.loads(cfg.read_text())["env"]
        script = Path(env[KEY])
        assert script.is_absolute() and script.is_file(), env
        assert os.access(script, os.X_OK), (
            "a prefix that is not executable fails every command in every "
            "new session")
        assert script.read_text().startswith("#!/bin/sh\n")
        assert script.parent == self._dir()
        led = pp._read_ledger(cfg, {})
        assert KEY in led[pp._WIRE_MARK], (
            "the receipt does not list the key, so an unwire could not "
            f"remove it: {led}")

    def case_unwire_removes_the_key_and_keeps_the_script(
        self, tmp_path, monkeypatch
    ):
        """A session already running holds the key in its process env from
        its boot: deleting the script would fail every command it runs."""
        from cswap_pin import proxy as pp

        cfg = self._config(tmp_path, monkeypatch, {"env": {"KEEP": "1"}})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        script = Path(json.loads(cfg.read_text())["env"][KEY])
        assert pp.wire_global_config(None, None) is True
        assert json.loads(cfg.read_text())["env"] == {"KEEP": "1"}
        assert script.is_file() and os.access(script, os.X_OK)

    def case_unwire_removes_the_pins_floor_file_and_no_other(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy as pp

        cfg = self._config(tmp_path, monkeypatch, {})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        for port, who in ((9955, "pin"), (9901, "another proxy")):
            _floor_file(port).parent.mkdir(parents=True, exist_ok=True)
            _floor_file(port).write_text(f"{who}\n")
        assert pp.wire_global_config(None, None) is True
        assert not _floor_file(9955).exists(), "the pin left its floor behind"
        assert _floor_file(9901).read_text() == "another proxy\n"
        # CONTROL: a block this pin never wrote (no receipt) is not its file.
        self._config(tmp_path, monkeypatch, {"env": {"CSWAP_PIN_PORT": "9955"}})
        _floor_file(9955).write_text("not ours\n")
        pp.wire_global_config(None, None)
        assert _floor_file(9955).read_text() == "not ours\n"

    def case_an_unwire_leaves_a_prefix_another_product_wired_since(
        self, tmp_path, monkeypatch
    ):
        """The receipt owns the key only while the block still holds OUR script.
        Another product's prefix written over it later is theirs, and the
        user's displaced one (receipt) is not handed back over it."""
        from cswap_pin import proxy as pp

        mine = Path(tmp_path) / "my-prefix.sh"
        cfg = self._config(tmp_path, monkeypatch, {"env": {KEY: str(mine)}})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        raw = json.loads(cfg.read_text())
        theirs = Path(tmp_path) / "their-prefix.sh"
        raw["env"][KEY] = str(theirs)
        cfg.write_text(json.dumps(raw))
        assert pp.wire_global_config(None, None) is True
        env = json.loads(cfg.read_text())["env"]
        assert env == {KEY: str(theirs)}, env

    def case_a_users_own_prefix_is_restored_and_chained(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy as pp

        mine = Path(tmp_path) / "my-prefix.sh"
        mine.write_text('#!/bin/sh\nexec "$SHELL" -c "$1"\n')
        mine.chmod(0o755)
        cfg = self._config(tmp_path, monkeypatch, {"env": {KEY: str(mine)}})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        env = json.loads(cfg.read_text())["env"]
        assert env[KEY] != str(mine)
        assert (self._dir() / "child-prefix").read_text().strip() == str(mine), (
            "the user's own prefix was displaced and not chained to")
        pp.wire_global_config(None, None)
        assert json.loads(cfg.read_text())["env"] == {KEY: str(mine)}, (
            "an unwire did not hand the user's prefix back")

    def case_a_prefix_from_the_wiring_process_env_is_chained(
        self, tmp_path, monkeypatch
    ):
        from cswap_pin import proxy as pp

        mine = Path(tmp_path) / "audit.sh"
        monkeypatch.setenv(KEY, str(mine))
        self._config(tmp_path, monkeypatch, {})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        assert (self._dir() / "child-prefix").read_text().strip() == str(mine)

    def case_our_own_script_in_the_process_env_is_not_a_users_prefix(
        self, tmp_path, monkeypatch
    ):
        """A `cswap pin` run from a Bash child of a pinned session inherits
        our script as CLAUDE_CODE_SHELL_PREFIX. Chaining to it would loop."""
        from cswap_pin import proxy as pp

        cfg = self._config(tmp_path, monkeypatch, {})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        ours = json.loads(cfg.read_text())["env"][KEY]
        monkeypatch.setenv(KEY, ours)
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        assert not (self._dir() / "child-prefix").exists()

    def case_a_script_that_cannot_be_written_leaves_the_key_out(
        self, tmp_path, monkeypatch
    ):
        """A prefix key naming a missing file would fail every command."""
        from cswap_pin import proxy as pp

        def refuse(*a, **k):
            raise PermissionError("read-only")

        cfg = self._config(tmp_path, monkeypatch, {})
        monkeypatch.setattr(pp, "_write_child_floor_script", refuse)
        assert pp.wire_global_config(9955, Path(tmp_path) / "ca.pem") is True
        env = json.loads(cfg.read_text())["env"]
        assert KEY not in env, env
        assert env["HTTPS_PROXY"], "the pin itself must still be wired"

    def case_a_rewire_restores_a_lost_exec_bit(self, tmp_path, monkeypatch):
        """An atomic replace by something else drops the exec bit."""
        from cswap_pin import proxy as pp

        cfg = self._config(tmp_path, monkeypatch, {})
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        script = Path(json.loads(cfg.read_text())["env"][KEY])
        script.chmod(0o644)
        pp.wire_global_config(9955, Path(tmp_path) / "ca.pem")
        assert os.access(script, os.X_OK)
        assert not list(script.parent.glob("*.cswap-tmp"))


class TestChildFloorScript:
    """The script, run for real. `seen` is what a child of the command sees."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_unknown_floor_changes_nothing(self, tmp_path):
        rig = _Rig(tmp_path)
        rig.floor(None)
        for shell in _shells():
            seen = rig.seen(shell)
            assert seen["HTTPS_PROXY"] == _pin_url()
            assert seen["HTTP_PROXY"] == "UNSET"

    def case_a_directory_where_the_floor_file_would_be_is_unknown(self, tmp_path):
        """`[ -r dir ]` is true, and reading a directory gives an empty line,
        which is DIRECT. Only a regular file is a floor."""
        rig = _Rig(tmp_path)
        (tmp_path / ".claude" / "proxy-floor" / str(PIN)).mkdir(parents=True)
        for shell in _shells():
            seen = rig.seen(shell)
            assert seen["HTTPS_PROXY"] == _pin_url(), seen
            assert seen["HTTP_PROXY"] == "UNSET", seen

    def case_direct_floor_sets_all_six_to_empty_never_unset(self, tmp_path):
        rig = _Rig(tmp_path)
        rig.floor("")
        for shell in _shells():
            seen = rig.seen(shell)
            for name in SIX:
                assert seen[name] == "", (name, seen)

    def case_a_url_floor_sets_all_six_to_it_and_leaves_no_proxy(self, tmp_path):
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        for shell in _shells():
            seen = rig.seen(shell, NO_PROXY="localhost,example.test")
            for name in SIX:
                assert seen[name] == FLOOR_URL, (name, seen)
            assert seen["NO_PROXY"] == "localhost,example.test"

    def case_an_env_that_names_no_published_port_is_left_alone(self, tmp_path):
        """A proxy that publishes nothing (a launcher's, a corporate one), a
        port that only looks like a published one, a published port on another
        host: not floored."""
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        shell = _shells()[0]
        for other in (_pin_url(9901), _pin_url(PIN // 10),
                      _pin_url(int(f"{PIN}1")), f"http://proxy.corp:{PIN}",
                      f"http://127.0.0.1:{PIN}x", "http://127.0.0.1:../x",
                      "http://127.0.0.1", ""):
            seen = rig.seen(shell, HTTPS_PROXY=other, https_proxy=other,
                            ALL_PROXY=other)
            assert seen["HTTPS_PROXY"] == other, (other, seen)
            assert seen["HTTP_PROXY"] == "UNSET", (other, seen)

    def case_any_loopback_port_with_a_floor_file_is_floored(self, tmp_path):
        """The contract is the directory's, not the pin's: whichever proxy's
        port the variables name, and whoever published it. This is what makes
        either product's prefix script right when a settings file chose the
        other product's proxy."""
        rig = _Rig(tmp_path)
        shell = _shells()[0]
        rig.floor("http://127.0.0.1:3128\n", port=9901)
        other = _pin_url(9901)
        seen = rig.seen(shell, HTTPS_PROXY=other, https_proxy=other,
                        ALL_PROXY=other, CSWAP_PIN_PORT=None)
        assert all(seen[n] == "http://127.0.0.1:3128" for n in SIX), seen
        # The first of the six that names a published port decides.
        rig.floor(FLOOR_URL + "\n")
        seen = rig.seen(shell, HTTPS_PROXY=_pin_url(9902), https_proxy=other,
                        ALL_PROXY=_pin_url())
        assert all(seen[n] == "http://127.0.0.1:3128" for n in SIX), seen
        # CONTROL: the same variables with that file gone fall to the next key.
        rig.floor(None, port=9901)
        seen = rig.seen(shell, HTTPS_PROXY=_pin_url(9902), https_proxy=other,
                        ALL_PROXY=_pin_url())
        assert all(seen[n] == FLOOR_URL for n in SIX), seen

    def case_any_one_key_naming_the_pin_is_enough(self, tmp_path):
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        shell = _shells()[0]
        seen = rig.seen(shell, HTTPS_PROXY=None, https_proxy=None,
                        ALL_PROXY=None, http_proxy=_pin_url())
        assert all(seen[n] == FLOOR_URL for n in SIX), seen
        gated = f"http://cswap:s3cret@127.0.0.1:{PIN}"
        seen = rig.seen(shell, HTTPS_PROXY=gated, https_proxy=gated,
                        ALL_PROXY=gated)
        assert all(seen[n] == FLOOR_URL for n in SIX), (
            "the gated userinfo form of the pin's URL was not recognised", seen)

    def case_a_file_for_a_port_the_variables_do_not_name_is_ignored(self, tmp_path):
        """The directory is shared: a file for a port none of the six names is
        another proxy's business."""
        rig = _Rig(tmp_path)
        shell = _shells()[0]
        rig.floor(FLOOR_URL + "\n", port=9901)
        seen = rig.seen(shell)
        assert seen["HTTPS_PROXY"] == _pin_url() and seen["HTTP_PROXY"] == "UNSET", seen
        # CONTROL: the file of the port the variables do name is read.
        rig.floor("", port=PIN)
        assert all(rig.seen(shell)[n] == "" for n in SIX)

    def case_the_floor_is_read_from_the_sessions_config_dir(self, tmp_path):
        """Resolved when the script RUNS, from the session's own env: one script
        file serves every config, so a path baked in at wire time would be the
        last wiring process's."""
        rig = _Rig(tmp_path)
        shell = _shells()[0]
        mine = Path(tmp_path) / "profile"
        rig.floor(FLOOR_URL + "\n", config=mine)
        rig.floor("http://127.0.0.1:8119\n")
        seen = rig.seen(shell, CLAUDE_CONFIG_DIR=str(mine))
        assert all(seen[n] == FLOOR_URL for n in SIX), seen
        for unset in (None, ""):
            seen = rig.seen(shell, CLAUDE_CONFIG_DIR=unset)
            assert all(seen[n] == "http://127.0.0.1:8119" for n in SIX), (
                unset, seen)
        # The pin's file in the other directory is not consulted.
        rig.floor(None)
        assert rig.seen(shell)["HTTPS_PROXY"] == _pin_url()
        seen = rig.seen(shell, CLAUDE_CONFIG_DIR=str(mine))
        assert all(seen[n] == FLOOR_URL for n in SIX), seen

    def case_a_session_with_a_config_dir_falls_back_to_the_default_one(self, tmp_path):
        """CCF's script (bin/child-proxy-floor.sh) tries the session's config dir
        and then `$HOME/.claude`; so does this one, so both products resolve the
        one file the same way."""
        rig = _Rig(tmp_path)
        shell = _shells()[0]
        mine = Path(tmp_path) / "profile"
        mine.mkdir()
        rig.floor(FLOOR_URL + "\n")
        seen = rig.seen(shell, CLAUDE_CONFIG_DIR=str(mine))
        assert all(seen[n] == FLOOR_URL for n in SIX), seen
        # CONTROL: the session's own dir wins when it has the file.
        rig.floor("http://127.0.0.1:8119\n", config=mine)
        seen = rig.seen(shell, CLAUDE_CONFIG_DIR=str(mine))
        assert all(seen[n] == "http://127.0.0.1:8119" for n in SIX), seen
        # CONTROL: neither has it.
        rig.floor(None)
        rig.floor(None, config=mine)
        assert rig.seen(shell, CLAUDE_CONFIG_DIR=str(mine))["HTTPS_PROXY"] == _pin_url()

    def case_the_opt_out_changes_nothing(self, tmp_path):
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        seen = rig.seen(_shells()[0], CSWAP_PIN_CHILD_FLOOR="off")
        assert seen["HTTPS_PROXY"] == _pin_url()
        assert seen["HTTP_PROXY"] == "UNSET"
        # CONTROL: any other value is not the opt-out.
        seen = rig.seen(_shells()[0], CSWAP_PIN_CHILD_FLOOR="on")
        assert seen["HTTPS_PROXY"] == FLOOR_URL

    def case_the_command_is_run_unchanged(self, tmp_path):
        """Exit code, both streams and the quoting survive the wrapper: a hook
        as `/bin/sh -c` would have run it, a Bash-tool string as its shell."""
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        command = ("printf '%s\\n' \"a b\" 'c$d' | tr a-z A-Z; "
                   "echo \"line1\nline2\" >&2; echo $((6*7)) '$HOME'; exit 7")
        for interp in (None, "bash"):
            if interp and not shutil.which(interp):
                continue
            direct = subprocess.run(["/bin/sh", "-c", command],
                                    capture_output=True, text=True,
                                    env=rig.env("/bin/sh"))
            wrapped = rig.run(command, rig.env("/bin/sh"), interp)
            assert wrapped.returncode == direct.returncode == 7
            assert (wrapped.stdout, wrapped.stderr) == (direct.stdout, direct.stderr)
        for shell in _shells():
            string = rig.bash_tool(command, os.path.basename(shell))
            direct = subprocess.run([shell, "-c", string], capture_output=True,
                                    text=True, env=rig.env(shell))
            wrapped = rig.run(string, rig.env(shell))
            assert wrapped.returncode == direct.returncode == 7
            assert (wrapped.stdout, wrapped.stderr) == (direct.stdout, direct.stderr)

    def case_a_hook_keeps_bin_sh_whatever_shell_the_user_has(self, tmp_path):
        """A hook is spawned `/bin/sh -c "'prefix' 'cmd'"`: zsh would turn an
        unmatched glob into an error and stop splitting an unquoted variable."""
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        hooks = ("echo *.no-such-file-here; echo after",
                 'v="a b"; set -- $v; echo $#',
                 'echo "${BASH_VERSION:+bash}${ZSH_VERSION:+zsh}"')
        for shell in _shells():
            for hook in hooks:
                direct = subprocess.run(["/bin/sh", "-c", hook], capture_output=True,
                                        text=True, env=rig.env(shell))
                for env in (rig.env(shell), rig.env(shell, CLAUDE_CODE_SHELL=shell)):
                    wrapped = rig.run(hook, env)
                    assert (wrapped.returncode, wrapped.stdout, wrapped.stderr) == (
                        direct.returncode, direct.stdout, direct.stderr), (
                        shell, hook, wrapped, direct)

    def case_a_stdio_mcp_command_line_is_run_as_it_was_quoted(self, tmp_path):
        """A stdio MCP server arrives as the prefix plus ONE quoted string."""
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        for shell in _shells():
            done = rig.run("'printf' '%s|%s\\n' 'a b' '$HOME'", rig.env(shell))
            assert (done.returncode, done.stdout) == (0, "a b|$HOME\n"), done
            done = rig.run("'sh' '-c' 'exit 3'", rig.env(shell))
            assert done.returncode == 3, done

    def case_a_user_prefix_is_invoked_with_the_command(self, tmp_path):
        log = Path(tmp_path) / "log"
        mine = Path(tmp_path) / "audit.sh"
        mine.write_text(f'#!/bin/sh\nprintf "%s|%s|%s\\n" "$#" "$1" '
                        f'"$HTTPS_PROXY" >> {log}\nexec "$SHELL" -c "$1"\n')
        mine.chmod(0o755)
        rig = _Rig(tmp_path, str(mine))
        rig.floor(FLOOR_URL + "\n")
        shell = _shells()[0]
        done = rig.run("echo ran-$((1+1))", rig.env(shell))
        assert done.stdout.strip() == "ran-2", done
        assert log.read_text().strip() == f"1|echo ran-$((1+1))|{FLOOR_URL}", (
            "the user's prefix must get the command as its one argument, "
            "after the floor was applied")

    def case_a_user_prefix_with_flags_is_split_like_claude_code_splits_it(
        self, tmp_path
    ):
        log = Path(tmp_path) / "log"
        mine = Path(tmp_path) / "audit.sh"
        mine.write_text(f'#!/bin/sh\necho "$# $1 $2" >> {log}\n'
                        'shift; exec "$SHELL" -c "$1"\n')
        mine.chmod(0o755)
        rig = _Rig(tmp_path, f"{mine} -v")
        done = rig.run("echo hi", rig.env(_shells()[0]))
        assert done.stdout.strip() == "hi", done
        assert log.read_text().strip() == "2 -v echo hi"

    def case_a_user_prefix_that_is_gone_falls_through_to_the_shell(
        self, tmp_path
    ):
        rig = _Rig(tmp_path, str(Path(tmp_path) / "deleted.sh"))
        done = rig.run("echo still-runs", rig.env(_shells()[0]))
        assert (done.returncode, done.stdout.strip()) == (0, "still-runs"), done

    def case_a_user_prefix_that_is_a_command_name_is_found_on_the_path(
        self, tmp_path
    ):
        """Claude Code runs the prefix through a shell, so a bare name resolves
        through PATH. `[ -x name ]` looks in the cwd and skipped it."""
        log = Path(tmp_path) / "log"
        bindir = Path(tmp_path) / "bin"
        bindir.mkdir()
        mine = bindir / "audit-prefix"
        mine.write_text(f'#!/bin/sh\necho "$#|$1" >> {log}\nexec "$SHELL" -c "$1"\n')
        mine.chmod(0o755)
        rig = _Rig(tmp_path, "audit-prefix")
        shell = _shells()[0]
        env = rig.env(shell, PATH=f"{bindir}:{os.getenv('PATH')}")
        done = rig.run("echo ran", env)
        assert (done.returncode, done.stdout.strip()) == (0, "ran"), done
        assert log.read_text().strip() == "1|echo ran", (
            "a prefix named by a bare command was not called")
        # CONTROL: a name nothing on PATH answers to falls through to the shell.
        rig = _Rig(tmp_path / "b", "no-such-prefix-anywhere")
        done = rig.run("echo ran", rig.env(shell))
        assert (done.returncode, done.stdout.strip()) == (0, "ran"), done

    def case_two_floor_scripts_naming_each_other_do_not_loop(self, tmp_path):
        """A prefix that is a floor script (ours from another wiring dir, or a
        copy) is never chained to: A -> B -> A would exec for ever."""
        a = _Rig(tmp_path / "a")
        b = _Rig(tmp_path / "b")
        (a.dir / "child-prefix").write_text(f"{b.script}\n")
        (b.dir / "child-prefix").write_text(f"{a.script}\n")
        done = a.run("echo ran", a.env(_shells()[0]), timeout=5)
        assert (done.returncode, done.stdout.strip()) == (0, "ran"), done

    def case_a_floor_file_that_vanishes_after_the_test_is_unknown(self, tmp_path):
        """The file is there for `[ -f ]` and gone for the `read`. That is not
        an empty file (DIRECT): the children stay as they are, and the command
        says nothing about it."""
        bash = shutil.which("bash")
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        report = 'echo "$HTTPS_PROXY|${HTTP_PROXY-UNSET}|${all_proxy-UNSET}"'
        env = rig.env(bash, **_vanish_after_test(tmp_path, f"/proxy-floor/{PIN}"))
        done = rig.run(report, env, interp=bash)
        assert (done.returncode, done.stdout.strip(), done.stderr) == (
            0, f"{_pin_url()}|UNSET|UNSET", ""), done
        assert not (rig.tmp / ".claude" / "proxy-floor" / str(PIN)).exists(), (
            "the injection did not fire")
        # CONTROL: the same run with the file left alone is floored.
        rig.floor(FLOOR_URL + "\n")
        done = rig.run(report, rig.env(bash), interp=bash)
        assert done.stdout.strip() == f"{FLOOR_URL}|{FLOOR_URL}|{FLOOR_URL}", done

    def case_only_the_first_line_of_a_floor_file_is_read(self, tmp_path):
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\nhttp://127.0.0.1:1\n")
        for shell in _shells():
            assert all(rig.seen(shell)[n] == FLOOR_URL for n in SIX)

    def case_an_inherited_pp_is_not_the_users_prefix(self, tmp_path):
        """`_pp` is the script's own variable: when the read fails it must not
        be whatever the environment happened to hold."""
        bash = shutil.which("bash")
        log = Path(tmp_path) / "log"
        evil = Path(tmp_path) / "evil.sh"
        evil.write_text(f'#!/bin/sh\necho ran >> {log}\nexec "$SHELL" -c "$1"\n')
        evil.chmod(0o755)
        rig = _Rig(tmp_path, "unused")
        env = rig.env(bash, _pp=str(evil),
                      **_vanish_after_test(tmp_path, "/child-prefix"))
        done = rig.run("echo ok", env, interp=bash)
        assert (done.returncode, done.stdout.strip(), done.stderr) == (0, "ok", ""), done
        assert not (rig.dir / "child-prefix").exists(), "the injection did not fire"
        assert not log.exists(), "the environment's _pp was run as the prefix"

    def case_the_shell_is_the_one_claude_code_picked(self, tmp_path):
        """`h0s` in the 2.1.296 binary: CLAUDE_CODE_SHELL if it names bash or
        zsh and runs, else SHELL if it names bash or zsh, else a search that
        tries zsh first (bash first when SHELL names bash). Used for a Bash-tool
        string whose snapshot names no shell Claude Code uses (`sh`) or that has
        no snapshot at all."""
        rig = _Rig(tmp_path)
        bash = shutil.which("bash")
        probe = 'echo "${BASH_VERSION:+bash}${ZSH_VERSION:+zsh}"'
        for snapshot in ("sh", None):
            string = rig.bash_tool(probe, snapshot)
            env = rig.env("/bin/sh", CLAUDE_CODE_SHELL=bash)
            assert rig.run(string, env).stdout.strip() == "bash", snapshot
            # SHELL naming neither shell, and nothing set: still a shell that runs.
            for shell in ("/usr/bin/fish", "/nonexistent/zsh", None):
                done = rig.run(rig.bash_tool("echo ok", snapshot), rig.env(shell))
                assert (done.returncode, done.stdout.strip()) == (0, "ok"), (
                    shell, done)
            # SHELL names bash but is not there: the search tries bash first.
            done = rig.run(string, rig.env("/nonexistent/bash"))
            assert done.stdout.strip() == "bash", done
            done = rig.run(string, rig.env(bash))
            assert done.stdout.strip() == "bash"

    def case_a_command_that_mentions_a_snapshot_does_not_choose_the_shell(
        self, tmp_path
    ):
        rig = _Rig(tmp_path)
        shells = {os.path.basename(s): s for s in _shells()}
        if len(shells) < 2:
            pytest.skip("needs both bash and zsh")
        probe = ('echo "${BASH_VERSION:+bash}${ZSH_VERSION:+zsh}" '
                 '# /shell-snapshots/snapshot-zsh-1-x.sh 2>/dev/null')
        done = rig.run(rig.bash_tool(probe, "bash"), rig.env(shells["zsh"]))
        assert done.stdout.strip() == "bash", done

    def case_a_bash_tool_string_runs_under_the_shell_its_snapshot_names(
        self, tmp_path
    ):
        """The snapshot is written for one shell and sourced by that shell
        only. SHELL says the other one, so the picker alone would be wrong."""
        rig = _Rig(tmp_path)
        probe = 'echo "${BASH_VERSION:+bash}${ZSH_VERSION:+zsh}"'
        shells = {os.path.basename(s): s for s in _shells()}
        for name, path in shells.items():
            others = [p for n, p in shells.items() if n != name] or ["/usr/bin/fish"]
            done = rig.run(rig.bash_tool(probe, name), rig.env(others[0]))
            assert done.stdout.strip() == name, (name, others, done)
            assert (tmp_path / "cwd").is_file(), "the cwd read-back did not run"
            (tmp_path / "cwd").unlink()

    def case_it_runs_under_zsh(self, tmp_path):
        zsh = shutil.which("zsh")
        if zsh is None:
            pytest.skip("zsh is not installed here: the zsh arm did not run")
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        seen = rig.seen(zsh)
        assert all(seen[n] == FLOOR_URL for n in SIX), seen
        done = rig.run(rig.bash_tool('echo "${ZSH_VERSION:+zsh}"'), rig.env(zsh))
        assert done.stdout.strip() == "zsh", done
        rig.floor("")
        assert all(rig.seen(zsh)[n] == "" for n in SIX)

    def case_it_runs_under_bash_as_the_interpreter(self, tmp_path):
        """/bin/sh is bash on macOS: the script must not lean on dash."""
        bash = shutil.which("bash")
        rig = _Rig(tmp_path)
        rig.floor(FLOOR_URL + "\n")
        seen = rig.seen(bash, interp=bash)
        assert all(seen[n] == FLOOR_URL for n in SIX), seen
        rig.floor("")
        assert all(rig.seen(bash, interp=bash)[n] == "" for n in SIX)


class TestTheFloorTheDaemonRecords:
    """`proxy-floor/<the pin's port>` in the Claude config home: absent is
    UNKNOWN, empty is DIRECT, a URL is the proxy below the pin. Written by the daemon's timer, after
    `learn_next_hop` has classified the recorded hop."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _floor(self, tmp_path, monkeypatch, proxy=None, next_hop=None, raw=None,
               nohealth=(), hop_floor=None):
        """What the daemon records for this `upstream.json`. `hop_floor` is what
        the recorded proxy itself publishes in `proxy-floor/<its port>`."""
        import cswap_pin.proxy as pp

        certdir = Path(tmp_path) / "pin-proxy"
        certdir.mkdir(parents=True, exist_ok=True)
        home = _own_home(tmp_path, monkeypatch)
        if hop_floor is not None:
            theirs = home / "proxy-floor" / str(pp.parse_upstream_proxy(proxy).port)
            theirs.parent.mkdir(parents=True, exist_ok=True)
            theirs.write_text(hop_floor)
        if raw is not None:
            (certdir / "upstream.json").write_text(raw)
        elif proxy is not None or next_hop is not None:
            pp.write_upstream_hint(certdir, proxy, next_hop=next_hop or "")
        monkeypatch.setattr(pp, "_ASKED_NOHEALTH", set(nohealth))
        proxy_ = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                             upstream=("127.0.0.1", 1), rediscover_chain=True)
        proxy_.port = PIN
        proxy_.record_child_floor()
        path = _floor_file()
        return path.read_text() if path.exists() else None

    def case_the_hops_own_published_floor_is_the_floor(self, tmp_path, monkeypatch):
        """The hop below the pin says what is below it, in its own file. What
        its /health reports (`next`) is credential-stripped, so the pin never
        publishes that: it publishes the hop's line, credentials and all."""
        theirs = "http://user:secret@127.0.0.1:3128\n"
        assert self._floor(tmp_path, monkeypatch, "http://127.0.0.1:9901", FLOOR_URL,
                           hop_floor=theirs) == theirs

    def case_a_hop_that_publishes_an_empty_floor_is_direct(self, tmp_path, monkeypatch):
        """A cache proxy with no chain configured publishes an empty file."""
        assert self._floor(tmp_path, monkeypatch, "http://127.0.0.1:9901",
                           hop_floor="") == ""

    def case_a_hop_that_publishes_nothing_is_unknown_even_with_next_learned(
        self, tmp_path, monkeypatch
    ):
        """Absent is the hop saying "I do not know" (a chain with credentials, an
        unreachable one, a value it could not parse). Not a guess from `next`,
        and the pin's own file goes when the hop's does."""
        hop = "http://127.0.0.1:9901"
        assert self._floor(tmp_path, monkeypatch, hop, FLOOR_URL,
                           hop_floor=FLOOR_URL + "\n") == FLOOR_URL + "\n"
        (tmp_path / "claude-home" / "proxy-floor" / "9901").unlink()
        assert self._floor(tmp_path, monkeypatch, hop, FLOOR_URL) is None
        assert not _floor_file().exists()

    def case_a_directory_where_the_hops_file_would_be_is_unknown(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "claude-home" / "proxy-floor" / "9901").mkdir(parents=True)
        assert self._floor(tmp_path, monkeypatch, "http://127.0.0.1:9901",
                           FLOOR_URL) is None

    def case_without_ccf_the_users_own_proxy_is_the_floor(self, tmp_path, monkeypatch):
        """A remote proxy, a TLS one, and a loopback one that answered /health
        with a 4xx (privoxy) are not CCF: the floor is the proxy itself, and a
        file at that port is not asked."""
        corp = "http://proxy.corp.example:3128"
        assert self._floor(tmp_path / "a", monkeypatch, corp) == corp + "\n"
        tls = "https://proxy.corp.example:3129"
        assert self._floor(tmp_path / "b", monkeypatch, tls) == tls + "\n"
        assert self._floor(tmp_path / "c", monkeypatch, FLOOR_URL,
                           nohealth={"127.0.0.1:8118"},
                           hop_floor="http://127.0.0.1:3128\n") == FLOOR_URL + "\n"

    def case_an_unlearned_next_is_unknown_never_direct(self, tmp_path, monkeypatch):
        """A loopback proxy nobody has classified, that publishes nothing, may be
        CCF with its own upstream not known yet. Direct there is the corporate
        403 (dotfiles b28af221), so the children stay on the pin."""
        assert self._floor(tmp_path / "a", monkeypatch, "http://127.0.0.1:9901") is None
        # ...and the file goes when the answer goes: a stale floor is a hop
        # nobody chose any more.
        floor = tmp_path / "a" / "claude-home" / "proxy-floor" / str(PIN)
        floor.parent.mkdir(parents=True, exist_ok=True)
        floor.write_text(FLOOR_URL + "\n")
        assert self._floor(tmp_path / "a", monkeypatch) is None
        assert not floor.exists()

    def case_no_record_or_an_unreadable_one_is_unknown(self, tmp_path, monkeypatch):
        assert self._floor(tmp_path / "a", monkeypatch) is None
        assert self._floor(tmp_path / "b", monkeypatch, raw="{not json") is None
        assert self._floor(tmp_path / "c", monkeypatch, raw="[]") is None

    def case_a_pin_with_no_hop_at_all_says_direct(self, tmp_path, monkeypatch):
        """The one positive statement: it dials direct itself, so a child
        dialling direct takes the same road."""
        assert self._floor(tmp_path / "a", monkeypatch, raw='{"proxy": "", "next": ""}') == ""
        # CONTROL: the same record with a hop in it is not DIRECT.
        assert self._floor(tmp_path / "b", monkeypatch, raw='{"proxy": "http://127.0.0.1:9901"}'
                           ) is None

    def case_a_hop_that_names_the_pin_is_not_a_floor(self, tmp_path, monkeypatch):
        assert self._floor(tmp_path / "a", monkeypatch, raw=json.dumps(
            {"proxy": "http://127.0.0.1:9901",
             "next": _pin_url()})) is None
        # ...and the hop the pin does dial is the next one the record names.
        corp = "http://proxy.corp.example:3128"
        assert self._floor(tmp_path / "b", monkeypatch, raw=json.dumps(
            {"proxy": _pin_url(), "next": corp})) == corp + "\n"

    def case_a_hop_that_4xxs_health_is_classified_by_the_daemons_own_tick(
        self, tmp_path, monkeypatch
    ):
        """privoxy answers /health with a 400. The daemon learns that on its
        timer, and the floor follows without a launch."""
        import cswap_pin.proxy as pp

        class _Privoxy(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(400)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), _Privoxy)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            hop = f"http://127.0.0.1:{srv.server_address[1]}"
            certdir = Path(tmp_path) / "pin-proxy"
            certdir.mkdir()
            _own_home(tmp_path, monkeypatch)
            monkeypatch.setattr(pp, "_ASKED_NOHEALTH", set())
            monkeypatch.setattr(pp, "_probe_next_hop", functools.partial(
                pp._probe_next_hop, timeout=10))
            pp.write_upstream_hint(certdir, hop)
            proxy = pp.PinProxy(certdir=certdir,
                                pin_token_provider=lambda: None,
                                upstream=("127.0.0.1", 1),
                                rediscover_chain=True)
            proxy.port = PIN
            proxy.record_child_floor()
            assert not _floor_file().exists(), "unclassified yet"
            proxy.learn_next_hop()
            proxy.record_child_floor()
            assert _floor_file().read_text() == hop + "\n"
        finally:
            srv.shutdown()

    def _ticks(self, tmp_path, monkeypatch, hop):
        """The daemon's timer against `hop` as the recorded proxy: a callable
        that asks it, records the floor, and returns what the file says."""
        import cswap_pin.proxy as pp

        certdir = Path(tmp_path) / "pin-proxy"
        certdir.mkdir(parents=True)
        _own_home(tmp_path, monkeypatch)
        monkeypatch.setattr(pp, "_ASKED_NOHEALTH", set())
        monkeypatch.setattr(pp, "_probe_next_hop", functools.partial(
            pp._probe_next_hop, timeout=10))
        pp.write_upstream_hint(certdir, hop)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                            upstream=("127.0.0.1", 1), rediscover_chain=True)
        proxy.port = PIN

        def tick():
            proxy.learn_next_hop()
            proxy.record_child_floor()
            path = _floor_file()
            return path.read_text() if path.exists() else None
        return tick

    def case_the_floor_follows_the_hops_file_on_each_tick(self, tmp_path, monkeypatch):
        """Through the real `learn_next_hop`: the hop's /health reports a
        credential-stripped upstream, and the pin still publishes only what the
        hop's own file says, as that file changes and goes."""
        srv = _serve_health({"https_proxy": FLOOR_URL})
        try:
            tick = self._ticks(tmp_path, monkeypatch,
                               f"http://127.0.0.1:{srv.server_address[1]}")
            theirs = _floor_file(srv.server_address[1])
            assert tick() is None, "the hop publishes nothing yet"
            theirs.parent.mkdir(parents=True, exist_ok=True)
            theirs.write_text("http://user:secret@127.0.0.1:8118\n")
            assert tick() == "http://user:secret@127.0.0.1:8118\n"
            theirs.write_text("")
            assert tick() == ""
            theirs.unlink()
            assert tick() is None
        finally:
            srv.shutdown()

    def case_the_file_is_replaced_atomically_and_only_on_a_change(
        self, tmp_path, monkeypatch
    ):
        hop = "http://127.0.0.1:9901"
        self._floor(tmp_path, monkeypatch, hop, hop_floor=FLOOR_URL + "\n")
        path = _floor_file()
        before = path.stat().st_ino
        self._floor(tmp_path, monkeypatch, hop, hop_floor=FLOOR_URL + "\n")
        assert path.stat().st_ino == before, "an unchanged floor was rewritten"
        self._floor(tmp_path, monkeypatch, hop, hop_floor="http://127.0.0.1:8119\n")
        assert path.read_text() == "http://127.0.0.1:8119\n"
        assert not list(path.parent.glob("*.cswap-tmp"))
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def case_the_floor_is_the_daemons_one_file_in_the_shared_directory(
        self, tmp_path, monkeypatch
    ):
        """One file, named by the listen port, beside the files other local
        proxies publish. Another port's file is never read, rewritten or
        removed, whatever this daemon concludes."""
        other = tmp_path / "claude-home" / "proxy-floor" / "9902"
        other.parent.mkdir(parents=True)
        other.write_text("http://127.0.0.1:3128\n")
        assert self._floor(tmp_path, monkeypatch, "http://127.0.0.1:9901", FLOOR_URL,
                           hop_floor=FLOOR_URL + "\n")
        assert sorted(p.name for p in other.parent.iterdir()) == [
            "9901", "9902", str(PIN)]
        assert not (tmp_path / "pin-proxy" / "child-floor").exists(), (
            "the old file in the cert dir is not written any more")
        assert self._floor(tmp_path, monkeypatch, raw="{not json") is None
        assert other.read_text() == "http://127.0.0.1:3128\n"
        assert sorted(p.name for p in other.parent.iterdir()) == ["9901", "9902"]

    def case_claude_config_dir_chooses_the_directory(self, tmp_path, monkeypatch):
        """Through the host's own resolver, which is the one the pin already
        wires `.claude.json` with."""
        import importlib.util

        import claude_swap.paths as paths
        import cswap_pin.proxy as pp

        spec = importlib.util.spec_from_file_location("_host_paths", paths.__file__)
        real = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(real)
        monkeypatch.setattr(paths, "get_claude_config_home",
                            real.get_claude_config_home)
        certdir = Path(tmp_path) / "pin-proxy"
        certdir.mkdir()
        corp = "http://proxy.corp.example:3128"
        pp.write_upstream_hint(certdir, corp)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                            upstream=("127.0.0.1", 1), rediscover_chain=True)
        proxy.port = PIN
        mine = Path(tmp_path) / "profile"
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(mine))
        proxy.record_child_floor()
        assert (mine / "proxy-floor" / str(PIN)).read_text() == corp + "\n"
        monkeypatch.delenv("CLAUDE_CONFIG_DIR")
        proxy.record_child_floor()
        default = Path.home() / ".claude" / "proxy-floor" / str(PIN)
        assert default.read_text() == corp + "\n"

    def _wire(self, tmp_path, monkeypatch, name, port=PIN, wire=True):
        """Be a session whose config is `<name>/.claude.json` and whose config
        home is `<name>` (a CLAUDE_CONFIG_DIR), and wire it on `port`."""
        import cswap_pin.proxy as pp

        home = Path(tmp_path) / name
        home.mkdir(parents=True, exist_ok=True)
        cfg = home / ".claude.json"
        if not cfg.exists():
            cfg.write_text("{}")
        monkeypatch.setattr("claude_swap.paths.get_global_config_path", lambda: cfg)
        monkeypatch.setattr("claude_swap.paths.get_claude_config_home", lambda: home)
        if wire:
            assert pp.wire_global_config(port, Path(tmp_path) / "ca.pem")
        return home

    def case_every_config_home_the_pin_wired_on_this_port_gets_the_floor(
        self, tmp_path, monkeypatch
    ):
        """A box wires two configs (`~/.claude.json` and a CLAUDE_CONFIG_DIR one)
        on the one pin port, and a child reads the floor from ITS session's
        config dir: publishing into the daemon's own env's home alone leaves the
        other config's children with no floor."""
        import cswap_pin.proxy as pp

        corp = "http://proxy.corp.example:3128"
        a = self._wire(tmp_path, monkeypatch, "a")
        b = self._wire(tmp_path, monkeypatch, "b")
        elsewhere = self._wire(tmp_path, monkeypatch, "elsewhere", port=PIN + 1)
        gone = self._wire(tmp_path, monkeypatch, "gone")
        assert pp.wire_global_config(None, None)
        ghost = self._wire(tmp_path, monkeypatch, "ghost")
        shutil.rmtree(ghost)
        mine = tmp_path / "claude-home"      # the daemon's own env's home
        assert self._floor(tmp_path, monkeypatch, corp) == corp + "\n"
        for home in (a, b, mine):
            assert (home / "proxy-floor" / str(PIN)).read_text() == corp + "\n", home
        # Another port's wiring, and an unwired one, are not this daemon's homes.
        assert not (elsewhere / "proxy-floor").exists()
        assert not (gone / "proxy-floor").exists()
        assert not ghost.exists(), "a deleted profile's directory was recreated"
        # UNKNOWN removes every file the daemon published, and only those.
        other = b / "proxy-floor" / "9902"
        other.write_text("http://127.0.0.1:3128\n")
        assert self._floor(tmp_path, monkeypatch, raw="{not json") is None
        for home in (a, b, mine):
            assert not (home / "proxy-floor" / str(PIN)).exists(), home
        assert other.read_text() == "http://127.0.0.1:3128\n"
        # Unwiring one config takes its file and no other config's.
        assert self._floor(tmp_path, monkeypatch, corp) == corp + "\n"
        self._wire(tmp_path, monkeypatch, "a", wire=False)
        assert pp.wire_global_config(None, None)
        assert not (a / "proxy-floor" / str(PIN)).exists()
        assert (b / "proxy-floor" / str(PIN)).read_text() == corp + "\n"
        # ...and the daemon's next tick no longer writes there.
        assert self._floor(tmp_path, monkeypatch, corp) == corp + "\n"
        assert not (a / "proxy-floor" / str(PIN)).exists()
        assert (b / "proxy-floor" / str(PIN)).read_text() == corp + "\n"

    def case_the_hops_file_in_another_wired_home_is_still_the_hops_floor(
        self, tmp_path, monkeypatch
    ):
        """The hop (CCF) publishes into ITS config home, which follows its own
        CLAUDE_CONFIG_DIR: it may be a wired home other than the daemon's. The
        first home that has the file decides; none is UNKNOWN."""
        hop, theirs = "http://127.0.0.1:9901", "http://user:secret@127.0.0.1:3128\n"
        a = self._wire(tmp_path, monkeypatch, "a")
        b = self._wire(tmp_path, monkeypatch, "b")
        mine = tmp_path / "claude-home"
        (b / "proxy-floor").mkdir()
        (b / "proxy-floor" / "9901").write_text(theirs)
        assert self._floor(tmp_path, monkeypatch, hop, FLOOR_URL) == theirs
        for home in (a, b, mine):
            assert (home / "proxy-floor" / str(PIN)).read_text() == theirs, home
        # The daemon's own home is asked first.
        (mine / "proxy-floor" / "9901").write_text("http://127.0.0.1:3129\n")
        assert self._floor(tmp_path, monkeypatch, hop, FLOOR_URL
                           ) == "http://127.0.0.1:3129\n"
        # CONTROL: in no home at all is UNKNOWN, everywhere.
        (b / "proxy-floor" / "9901").unlink()
        (mine / "proxy-floor" / "9901").unlink()
        assert self._floor(tmp_path, monkeypatch, hop, FLOOR_URL) is None
        for home in (a, b, mine):
            assert not (home / "proxy-floor" / str(PIN)).exists(), home

    def case_the_daemons_timer_records_it(self):
        """The call that matters is the one the daemon makes: `_watch_own_code`
        asks `learn_next_hop` and then records the floor."""
        import inspect

        import cswap_pin.proxy as pp

        src = inspect.getsource(pp._watch_own_code)
        assert src.index("server.learn_next_hop()") < src.index(
            "server.record_child_floor()"), (
            "the floor is recorded before the hop is classified")


class TestAFlooredEnvKeepsTheChain:
    """History 28dad1d, b037cee and 7acfec1: a `cswap pin` run from a Bash
    child of a pinned session must not record the child's proxy as the chain.
    Children used to carry the pin's own URL (recognised by CSWAP_PIN_PORT);
    now they carry the floor, which is a real proxy to a launch."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _ensure(self, tmp_path, monkeypatch, env):
        import cswap_pin.proxy as pp

        class _Sw:
            backup_dir = tmp_path
            @staticmethod
            def resolve_account(identifier):
                return "1", "pinned@example.com", "org"

        for k in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
                  "HTTP_PROXY", "http_proxy", "CSWAP_PIN_PORT",
                  "NODE_EXTRA_CA_CERTS"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.setattr(pp, "load_pin", lambda d: ("pinned@example.com", "org"))
        monkeypatch.setattr(pp, "_read_alive_port", lambda d, fingerprint=None: 51000)
        monkeypatch.setattr(pp, "wire_global_config", lambda *a, **k: True)
        pp.ensure_proxy(_Sw())
        return json.loads((tmp_path / "pin-proxy" / "upstream.json").read_text())

    def case_a_launch_with_the_floor_in_its_env_keeps_a_serving_ccf(
        self, tmp_path, monkeypatch
    ):
        import cswap_pin.proxy as pp

        ccf = _serve_health({"https_proxy": FLOOR_URL})
        try:
            ccf_url = f"http://127.0.0.1:{ccf.server_address[1]}"
            certdir = tmp_path / "pin-proxy"
            certdir.mkdir()
            pp.write_upstream_hint(certdir, ccf_url, next_hop=FLOOR_URL)
            record = self._ensure(tmp_path, monkeypatch, {
                "HTTPS_PROXY": FLOOR_URL, "https_proxy": FLOOR_URL,
                "ALL_PROXY": FLOOR_URL, "CSWAP_PIN_PORT": "51000"})
            assert record["proxy"] == ccf_url, (
                "a pin run from a floored child replaced CCF with the floor "
                f"and the chain lost its first hop: {record}")
            assert record["next"] == FLOOR_URL
        finally:
            ccf.shutdown()

    def case_the_same_launch_when_the_ccf_hop_is_down_keeps_it_too(
        self, tmp_path, monkeypatch
    ):
        """CCF restarting is the moment a nested `cswap pin` is most likely
        to be misread, and nothing re-adds a hop once it is dropped."""
        import cswap_pin.proxy as pp

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        ccf_url = f"http://127.0.0.1:{dead.getsockname()[1]}"
        dead.close()
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pp.write_upstream_hint(certdir, ccf_url, next_hop=FLOOR_URL)
        record = self._ensure(tmp_path, monkeypatch, {
            "HTTPS_PROXY": FLOOR_URL, "https_proxy": FLOOR_URL,
            "ALL_PROXY": FLOOR_URL, "CSWAP_PIN_PORT": "51000"})
        assert record["proxy"] == ccf_url, record
        assert record["next"] == FLOOR_URL, record

    def case_a_floor_with_userinfo_is_still_the_floor_when_ccf_is_down(
        self, tmp_path, monkeypatch
    ):
        """The hop's published floor carries its credentials; the recorded
        `next` is the stripped form of the same address. Compared as strings
        they differ, and the child's floor is recorded as the chain."""
        import cswap_pin.proxy as pp

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        ccf_url = f"http://127.0.0.1:{dead.getsockname()[1]}"
        dead.close()
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pp.write_upstream_hint(certdir, ccf_url, next_hop=FLOOR_URL)
        gated = "http://user:secret@127.0.0.1:8118"
        record = self._ensure(tmp_path, monkeypatch, {
            "HTTPS_PROXY": gated, "https_proxy": gated, "ALL_PROXY": gated,
            "CSWAP_PIN_PORT": "51000"})
        assert record["proxy"] == ccf_url, record
        assert record["next"] == FLOOR_URL, record
        # CONTROL: another proxy on the same host is a launch that chooses.
        other = "http://user:secret@127.0.0.1:8119"
        record = self._ensure(tmp_path, monkeypatch, {
            "HTTPS_PROXY": other, "CSWAP_PIN_PORT": "51000"})
        assert record["proxy"] == other, record

    def case_an_unparseable_next_in_the_record_matches_nothing(
        self, tmp_path, monkeypatch
    ):
        """The record is a file on disk. A `next` whose port is not a number must
        not stop the launch: it names no address, so it is not the floor."""
        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        (certdir / "upstream.json").write_text(json.dumps(
            {"proxy": "http://127.0.0.1:9", "next": "http://127.0.0.1:notaport"}))
        record = self._ensure(tmp_path, monkeypatch, {
            "HTTPS_PROXY": FLOOR_URL, "https_proxy": FLOOR_URL,
            "ALL_PROXY": FLOOR_URL, "CSWAP_PIN_PORT": "51000"})
        assert record["proxy"] == FLOOR_URL, record

    def case_a_plain_shell_exporting_the_floor_is_still_a_launch_that_chooses(
        self, tmp_path, monkeypatch
    ):
        """CONTROL: the guard is for a pinned session's child. An ssh shell
        that exports the machine's proxy and never ran a pinned claude still
        records it (no CSWAP_PIN_PORT)."""
        import cswap_pin.proxy as pp

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir()
        pp.write_upstream_hint(certdir, "http://127.0.0.1:9", next_hop=FLOOR_URL)
        record = self._ensure(tmp_path, monkeypatch, {
            "HTTPS_PROXY": "http://127.0.0.1:8200"})
        assert record["proxy"] == "http://127.0.0.1:8200", record


class _Hop:
    """A CONNECT-accepting stand-in that records the line it was asked for."""

    def __init__(self, answer=b"HTTP/1.1 200 Connection Established\r\n\r\n"):
        self.answer = answer
        self.seen = []
        self.held = []
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            self.held.append(conn)
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                self.seen.append(buf.split(b"\r\n", 1)[0].decode("latin1"))
                conn.sendall(self.answer)
            except OSError:
                pass

    def stop(self):
        for s in [self.srv, *self.held]:
            try:
                s.close()
            except OSError:
                pass


class TestTheBackstopDialsTheFloorFirst:
    """A CONNECT to a host the pin does not serve is some child's, and it goes
    to the floor hop first. CCF is the fallback. Hosts the pin serves keep the
    order they always had."""

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _tunnel(self, tmp_path, target, ccf, nxt):
        import cswap_pin.proxy as pp

        certdir = tmp_path / "pin-proxy"
        certdir.mkdir(exist_ok=True)
        pp.write_upstream_hint(certdir, ccf, next_hop=nxt)
        proxy = pp.PinProxy(certdir=certdir, pin_token_provider=lambda: None,
                            upstream=("127.0.0.1", 1), rediscover_chain=True)
        client, conn = socket.socketpair()
        try:
            proxy._local.conn = conn
            proxy._local.release = lambda: None
            proxy._capped_tunnel(target, conn)
            client.settimeout(5)
            return client.recv(4096)
        finally:
            pp._PUMP.release_pairs()
            for s in (client, conn):
                s.close()

    def case_a_bulk_connect_goes_to_the_floor_hop(self, tmp_path):
        ccf, floor = _Hop(), _Hop()
        try:
            got = self._tunnel(tmp_path, "bulk.example.test:443",
                               ccf.url, floor.url)
            assert b" 200 " in got, got
            assert floor.seen == ["CONNECT bulk.example.test:443 HTTP/1.1"], (
                floor.seen, ccf.seen)
            assert ccf.seen == [], (
                "a child's CONNECT still rode CCF before the floor")
        finally:
            ccf.stop()
            floor.stop()

    def case_without_a_learned_next_it_is_ccf_as_before(self, tmp_path):
        ccf = _Hop()
        try:
            got = self._tunnel(tmp_path, "bulk.example.test:443", ccf.url, "")
            assert b" 200 " in got, got
            assert ccf.seen == ["CONNECT bulk.example.test:443 HTTP/1.1"]
        finally:
            ccf.stop()

    def case_a_floor_hop_that_refuses_falls_back_to_ccf(self, tmp_path):
        ccf = _Hop()
        floor = _Hop(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        try:
            got = self._tunnel(tmp_path, "bulk.example.test:443",
                               ccf.url, floor.url)
            assert b" 200 " in got, got
            assert floor.seen and ccf.seen == [
                "CONNECT bulk.example.test:443 HTTP/1.1"], (floor.seen, ccf.seen)
        finally:
            ccf.stop()
            floor.stop()

    def case_a_floor_hop_that_is_down_falls_back_to_ccf(self, tmp_path):
        ccf = _Hop()
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_url = f"http://127.0.0.1:{dead.getsockname()[1]}"
        dead.close()
        try:
            got = self._tunnel(tmp_path, "bulk.example.test:443",
                               ccf.url, dead_url)
            assert b" 200 " in got, got
            assert ccf.seen == ["CONNECT bulk.example.test:443 HTTP/1.1"]
        finally:
            ccf.stop()

    def case_a_host_the_pin_serves_keeps_its_order(self, tmp_path):
        """Remote Control's ingress and the API are Claude Code's own."""
        ccf, floor = _Hop(), _Hop()
        try:
            got = self._tunnel(tmp_path, "claude.ai:443", ccf.url, floor.url)
            assert b" 200 " in got, got
            assert ccf.seen == ["CONNECT claude.ai:443 HTTP/1.1"], (
                ccf.seen, floor.seen)
            assert floor.seen == []
        finally:
            ccf.stop()
            floor.stop()
