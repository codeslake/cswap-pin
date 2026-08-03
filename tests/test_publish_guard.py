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
