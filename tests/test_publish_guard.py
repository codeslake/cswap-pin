"""The suite must not be able to write the real machine's trust store.

A monkeypatched module attribute does not cross a process boundary, and
this package spawns children constantly: daemons, packaging probes, the
CA oracle's node. Each one resolves `get_claude_config_home` afresh.
"""

def test_a_child_cannot_publish_into_the_real_config_home(tmp_path, capsys):
    """The guard must cross a PROCESS boundary, not just a module attribute.

    `publish_ca` resolves its target through `get_claude_config_home`, which
    reads CLAUDE_CONFIG_DIR from the ENVIRONMENT. A monkeypatched module
    attribute does not survive a spawn, so every daemon, packaging probe and
    oracle child this suite starts resolved the REAL ~/.claude — and one of
    them overwrote the published pin CA with a test-minted one. The published
    CA then could not verify the leaf the live daemon serves.
    """
    import os, pathlib, subprocess, sys

    real = pathlib.Path.home() / ".claude" / "ca-trust.d" / "cswap-pin.pem"
    before = real.read_bytes() if real.exists() else None

    # A child doing exactly what ensure_proxy does on every launch.
    prog = (
        "import sys; sys.path.insert(0, %r); sys.path.insert(0, %r)\n"
        "from cswap_pin.proxy import ensure_ca, publish_ca\n"
        "import pathlib\n"
        "d = pathlib.Path(%r)\n"
        "ensure_ca(d, 'api.anthropic.com')\n"
        "print(publish_ca(d / 'ca.pem'))\n"
    ) % ("src", str(pathlib.Path(__file__).parent.parent / "src"), str(tmp_path / "cd"))
    r = subprocess.run([sys.executable, "-c", prog], capture_output=True,
                       text=True, cwd=str(pathlib.Path(__file__).parent.parent))
    with capsys.disabled():
        print()
        print("  CLAUDE_CONFIG_DIR :", os.environ.get("CLAUDE_CONFIG_DIR"))
        print("  child published to:", (r.stdout.strip() or r.stderr.strip()[-90:]))
    after = real.read_bytes() if real.exists() else None
    assert after == before, "a child process overwrote the REAL published CA"
    if r.stdout.strip():
        assert str(pathlib.Path.home() / ".claude") not in r.stdout, (
            "a child resolved the REAL config home"
        )


import os
import pathlib

from conftest import run_cases


class TestTheGuardCoversTheACCOUNTSTORE:
    """The autouse guard redirected the CONFIG but not the ACCOUNT STORE.

    Found during a live incident on host-a: the real
    `~/.local/share/claude-swap/sequence.json` was overwritten with test
    fixture accounts (`a@example.com`, `b@example.com`) and matching 88-byte
    `.creds-*.enc` files. That damage was not traced to this suite — this
    suite constructs no real switcher, so nothing here reaches
    `switcher.backup_dir` today. But "no test happens to do it" is luck, not a
    guard, and the roster syncs by WHOLE-FILE COPY with newest-wins, so a
    corrupt store on one machine is one sync away from both Macs.

    `tests/conftest.py` redirected `get_global_config_path`,
    `get_default_global_config_path`, `get_claude_config_home` and
    `CLAUDE_CONFIG_DIR` — every CONFIG accessor and none of the STORE ones.
    `get_backup_root` resolves the credential store, and it reads
    `XDG_DATA_HOME` then falls back to `Path.home()`, so all three need
    redirecting: the function for in-process callers, the env var for the
    children this suite spawns, and `Path.home` for anything that computes the
    path itself.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_the_backup_root_is_not_the_real_one(self, tmp_path):
        """The store a test would write to must be under tmp, never $HOME."""
        from claude_swap.paths import get_backup_root

        real = pathlib.Path.home() / ".local/share/claude-swap"
        got = pathlib.Path(get_backup_root())
        assert real not in got.parents and got != real, (
            f"get_backup_root() resolves to the REAL account store ({got}) — a "
            "test that builds a switcher would overwrite the machine's own "
            "credentials and roster"
        )

    def case_the_env_the_children_inherit_does_not_name_the_real_store(self):
        """A monkeypatched attribute does not cross a process boundary; the
        daemons and probes this suite spawns obey XDG_DATA_HOME."""
        xdg = os.environ.get("XDG_DATA_HOME")
        assert xdg, "XDG_DATA_HOME is unset — a spawned child falls back to $HOME"
        assert pathlib.Path.home() not in pathlib.Path(xdg).parents, (
            f"XDG_DATA_HOME points inside the real home ({xdg})"
        )

    def case_path_home_is_redirected(self):
        """`get_backup_root`'s fallback computes the path from Path.home()."""
        assert pathlib.Path.home() != pathlib.Path(os.path.expanduser("~")), (
            "Path.home() returns the REAL home, so any code computing the "
            "store path itself lands on the machine's own credentials"
        )
