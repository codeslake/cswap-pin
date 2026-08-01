"""The package must be importable and diagnosable without claude-swap present.

cswap-pin is installed as `claude-swap[pin]`, so the host is normally there.
But `pip install cswap-pin` alone is a thing people will do, and a tool that
answers with a traceback from line 43 of proxy.py has told them nothing.
"""

import subprocess
import sys
import textwrap


def _in_clean_python(code: str, pkg_src: str):
    """Run code with cswap_pin importable and claude_swap NOT."""
    prog = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {pkg_src!r})
        # make claude_swap unimportable no matter what is installed
        import builtins
        _real = builtins.__import__
        def _fake(name, g=None, l=None, fromlist=(), level=0):
            if name == "claude_swap" or name.startswith("claude_swap."):
                raise ImportError("No module named 'claude_swap'")
            return _real(name, g, l, fromlist, level)
        builtins.__import__ = _fake
        """
    ) + textwrap.dedent(code)
    return subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True)


def _src():
    from pathlib import Path

    return str(Path(__file__).resolve().parent.parent / "src")


class TestImportableWithoutTheHost:
    def test_importing_the_package_does_not_explode(self):
        """`import cswap_pin` must succeed even with claude-swap absent.

        The package re-exported proxy symbols at module scope, so the import
        chain reached `require("oauth")` at proxy.py:43 and raised HostMissing
        during `import cswap_pin` itself — before any caller could catch it,
        and from a line that names neither package.
        """
        r = _in_clean_python("import cswap_pin; print(cswap_pin.__version__)", _src())
        assert r.returncode == 0, (
            "importing the package requires claude-swap:\n" + r.stderr[-900:]
        )

    def test_it_can_say_the_host_is_missing(self):
        """The diagnosis must be reachable, which needs the import to work."""
        r = _in_clean_python(
            "from cswap_pin import host_available; print('AVAILABLE', host_available())",
            _src(),
        )
        assert r.returncode == 0, r.stderr[-900:]
        assert "AVAILABLE False" in r.stdout

    def test_using_it_without_the_host_names_the_fix(self):
        """Touching real functionality fails with the install line, not a
        traceback about `oauth`."""
        r = _in_clean_python(
            "from cswap_pin.proxy import ensure_proxy", _src()
        )
        assert r.returncode != 0
        assert "claude-swap[pin]" in r.stderr, (
            "the failure does not name the fix:\n" + r.stderr[-900:]
        )
