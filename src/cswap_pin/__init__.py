"""Keep Claude Code's Remote Control and Artifacts on one account.

cswap swaps the on-disk credential, so everything follows the swap — including
two things that are not inference and usually should not move: Remote Control
(a session's owner is fixed at creation by the bearer that created it) and
Artifacts (owned by the publishing bearer). This package keeps those on one
account while inference keeps following ``cswap switch`` / ``cswap auto``.

Companion to claude-swap. Installed as ``claude-swap[pin]``; see
https://github.com/realiti4/claude-swap/issues/198 for why it lives apart.

**Nothing is imported from :mod:`cswap_pin.proxy` here.** That module reaches
into claude-swap at import time, so re-exporting its symbols made
``import cswap_pin`` itself raise ``HostMissing`` when the host was absent —
from proxy.py line 43, naming neither package, and before any caller could
catch it. Importing a package must never require the thing the package is
meant to report on. Reach for ``cswap_pin.proxy`` directly; use
:func:`host_available` first if you want to check rather than catch.
"""

from __future__ import annotations

def _derive_version() -> str:
    """The version of the INSTALLED distribution, never a second literal.

    This was `__version__ = "0.1.8"`, a constant kept in sync with
    pyproject.toml by hand. 0.1.9 shipped with the two disagreeing:

        dist metadata          0.1.9
        cswap_pin.__version__  0.1.8

    A test for exactly that drift existed and was in the released tree; it
    simply was not run before the tag, and a PyPI version cannot be
    re-uploaded, so that wheel is wrong forever. An upgraded machine reporting
    the old number looks un-upgraded to anything asking the package itself.

    Reading the metadata removes the second source rather than adding a third
    check on it. The fallback is for a source checkout with no distribution
    installed (this repo's own test run, `PYTHONPATH=src`), where there is no
    metadata to disagree with.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("cswap-pin")
    except PackageNotFoundError:
        return "0+unknown"


__version__ = _derive_version()

__all__ = ["__version__", "host_available"]


def host_available() -> bool:
    """Whether claude-swap is importable, i.e. whether the pin can do anything.

    Safe to call with the host missing — that is the case it exists for.
    """
    from cswap_pin._host import available

    return available()
