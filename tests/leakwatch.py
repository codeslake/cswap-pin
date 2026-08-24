"""Name every thread a test leaves running. OPT-IN, and never fails a run.

    uv run ... pytest tests/ -p tests.leakwatch

WHY IT EXISTS. The suite kills xdist workers with no traceback, and the case
blamed MOVES between runs -- four different classes in one evening, each
passing alone. That is the signature of a leaked daemon thread reaching the
REAL `os._exit` after the case that stubbed it was torn down: the process
exits instantly, so there is nothing to print. Fixing leaks one at a time
moved the crash rather than ending it, which is how the scale became clear.

BASELINE WHEN THIS LANDED: about 31 tests leaking about 100 threads,
single-process. The count moves a little between runs because some threads
exit while the check is being taken -- read it as a magnitude, not a
fingerprint. `-n 0` in CI is what keeps that from being a red build; this is
what makes the number go down.

NOT AN AUTOUSE FAILURE, deliberately. Turning 32 tests red at once buys
nothing and hides the next real regression. Run it, fix a class, watch the
count drop, and only make it fail once the count is zero.
"""
import re
import threading

import pytest

_LEAKS = []


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    before = {t.ident for t in threading.enumerate()}
    yield
    after = [t for t in threading.enumerate() if t.ident not in before]
    if after:
        _LEAKS.append((item.nodeid, [t.name for t in after]))


def _target(name):
    """`Thread-5 (_accept_loop)` -> `_accept_loop`; a named thread keeps its name.

    THE GROUPING KEY, AND WHY IT IS NOT `name`. CPython numbers anonymous
    threads, so the same leak reads as a different string every run and every
    test -- 108 unique names, no two alike, which is a list nobody can act on.
    The parenthesised target is what identifies the CODE that leaked.
    """
    m = re.fullmatch(r"Thread-\d+ \((.+)\)", name)
    return m.group(1) if m else name


def pytest_sessionfinish(session, exitstatus):
    print("\n\n=== threads left alive ===")
    if not _LEAKS:
        print("  none")
        return
    # BY TARGET FIRST, BECAUSE THAT IS THE TARGET LIST. The per-test list below
    # says how wide the problem is; this says how FEW places have to change.
    by_target = {}
    for nodeid, names in _LEAKS:
        for n in names:
            t = by_target.setdefault(_target(n), set())
            t.add(nodeid)
    print("\n  by target — threads, and the test(s) they leak from:")
    for target, tests in sorted(
            by_target.items(), key=lambda kv: -len(kv[1])):
        print(f"    {len(tests):2d} test(s)  {target}")
    print("\n  per test:")
    for nodeid, names in _LEAKS:
        print(f"    {len(names):2d}  {nodeid}")
    print(f"\n  {len(_LEAKS)} test(s) leaked, "
          f"{sum(len(n) for _, n in _LEAKS)} thread(s) total, "
          f"{len(by_target)} distinct target(s)")
