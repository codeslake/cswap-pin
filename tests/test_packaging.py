"""The package must be importable and diagnosable without claude-swap present.

cswap-pin is installed as `claude-swap[pin]`, so the host is normally there.
But `pip install cswap-pin` alone is a thing people will do, and a tool that
answers with a traceback from line 43 of proxy.py has told them nothing.
"""

import subprocess
import sys
import textwrap

from conftest import run_cases


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
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_importing_the_package_does_not_explode(self):
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

    def case_it_can_say_the_host_is_missing(self):
        """The diagnosis must be reachable, which needs the import to work."""
        r = _in_clean_python(
            "from cswap_pin import host_available; print('AVAILABLE', host_available())",
            _src(),
        )
        assert r.returncode == 0, r.stderr[-900:]
        assert "AVAILABLE False" in r.stdout

    def case_using_it_without_the_host_names_the_fix(self):
        """Touching real functionality fails with the install line, not a
        traceback about `oauth`."""
        r = _in_clean_python(
            "from cswap_pin.proxy import ensure_proxy", _src()
        )
        assert r.returncode != 0
        assert "claude-swap[pin]" in r.stderr, (
            "the failure does not name the fix:\n" + r.stderr[-900:]
        )


class TestConcatenationCannotFuseBlocks:
    """A byte concatenation must not weld one block's END onto the next BEGIN.

    `_trust_file` joined two PEM files with no separator. If the first does not
    end in a newline the result is:

        -----END CERTIFICATE----------BEGIN CERTIFICATE-----

    openssl rejects that block and node then loads ZERO CAs — the session
    silently loses all trust, which is the same outcome as a torn write and
    just as invisible.

    Raised by the CCF session, whose read-side guard was accepting it until
    e28abd0 (their END matcher used indexOf, so trailing content passed). It is
    reachable from here in a way their base64/label classes are not, because
    this writer concatenates whatever the ambient CA store holds.

    Today all three live inputs happen to end in a newline. That is a property
    of the inputs, not a guarantee of this code.
    """

    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def _blocks_are_clean(self, body: bytes) -> bool:
        return all(
            line.strip() in ("", "-----END CERTIFICATE-----")
            for line in body.decode().splitlines()
            if "-----END" in line
        )

    def case_a_file_without_a_trailing_newline_does_not_fuse(self, tmp_path):
        from cswap_pin.proxy import _join_pem

        ours = tmp_path / "ca.pem"
        ours.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
        other = tmp_path / "other.pem"
        other.write_bytes(b"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")

        body = _join_pem(ours.read_bytes(), other.read_bytes())
        assert self._blocks_are_clean(body), (
            f"welded a terminator onto the next block: {body!r}"
        )

    def case_a_file_that_already_ends_cleanly_is_not_padded(self, tmp_path):
        """Do not add blank lines to inputs that were already fine — the file
        is compared against the ambient store by cert count elsewhere."""
        from cswap_pin.proxy import _join_pem

        a = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        b = b"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"
        assert _join_pem(a, b) == a + b
def test_the_runtime_version_is_not_a_hand_maintained_constant():
    """`cswap_pin.__version__` must be DERIVED, not typed a second time.

    THE SOURCE-FILE COMPARISON ABOVE IS NECESSARY AND WAS NOT SUFFICIENT. It
    caught the drift and 0.1.9 shipped anyway, because a check only fails when
    someone runs it and the release run did not include this file. The
    published wheel:

        dist metadata          0.1.9
        cswap_pin.__version__  0.1.8

    A PyPI version cannot be re-uploaded, so that wheel is wrong forever.

    An upgraded machine that reports the old number looks un-upgraded to
    anything asking the package itself — the same class as an install floor
    comparing a stale value and skipping the upgrade it exists to force.

    WHY THIS ASSERTS ON THE MECHANISM RATHER THAN THE VALUE. The obvious test
    is "__version__ == importlib.metadata.version(...)", and it SKIPS in this
    worktree, which runs from PYTHONPATH=src with no distribution installed —
    silent in exactly the tree where the release is cut. Two hand-maintained
    constants will drift again; one derived from the distribution cannot. So
    the requirement is that there is only ONE source, and a literal in
    __init__.py is a second one.
    """
    import ast
    from pathlib import Path

    init = Path(__file__).resolve().parent.parent / "src" / "cswap_pin" / "__init__.py"
    tree = ast.parse(init.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            continue
        assert not isinstance(node.value, ast.Constant), (
            "__version__ is a literal, so it is a SECOND place the version is "
            "written by hand — it drifted from pyproject.toml in 0.1.9 and "
            "that wheel can never be corrected. Derive it from the installed "
            "distribution instead."
        )
        return
    raise AssertionError("__version__ is not assigned at module level in __init__.py")


def test_every_environment_variable_the_pin_reads_is_named_in_the_readme():
    """A knob nobody documented is a knob nobody can turn — or turn OFF.

    `CSWAP_PIN_EXIT_WITH_PARENT` was added without a README line, and it is
    the one that most needed one: set by accident, a holder loses its port
    within seconds of every launch. Two trace switches had been undocumented
    for longer, and the two hand-down variables appear in a daemon's
    environment where a reader will meet them and has no way to learn they
    are not settings.

    BEING NAMED IS THE WHOLE ASSERTION. What the README says about a variable
    is prose no test can judge; that it says anything at all is decidable, and
    it is the part that was missing.

    NOT IN conftest.py, which is where I wrote it first. `pytest tests/`
    collects `test_*.py` and does NOT collect `conftest.py` — measured, 0
    tests gathered from it — so the guard would have run nowhere. The two
    checks already living there have the same problem; that is theirs to fix,
    but it is why this one is here.

    Reads only: a name the module WRITES into a child's environment is not
    something anybody sets at it. Two shapes, because the module uses both —
    the literal, and a module constant holding it.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    src = (root / "src" / "cswap_pin" / "proxy.py").read_text(encoding="utf-8")

    consts = dict(re.findall(r'^(\w+_ENV) = "(CSWAP_PIN_\w+)"', src, re.M))
    read = set(re.findall(r'environ\.get\(\s*"(CSWAP_PIN_\w+)"', src))
    for const, value in consts.items():
        if re.search(rf"environ\.get\(\s*{const}\b", src):
            read.add(value)
    assert read, "found no environment reads at all — the pattern has drifted"

    readme = (root / "README.md").read_text(encoding="utf-8")
    missing = sorted(name for name in read if name not in readme)
    assert not missing, (
        f"the pin reads {missing} from the environment and the README never "
        f"names it — including, for an internal one, to say it is not a setting"
    )
