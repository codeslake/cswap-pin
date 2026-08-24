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


def pytest_sessionfinish(session, exitstatus):
    print("\n\n=== threads left alive, per test ===")
    if not _LEAKS:
        print("  none")
        return
    for nodeid, names in _LEAKS:
        print(f"  {len(names):2d}  {nodeid}")
    print(f"\n  {len(_LEAKS)} test(s) leaked, "
          f"{sum(len(n) for _, n in _LEAKS)} thread(s) total")
