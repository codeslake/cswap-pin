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

__version__ = "0.1.5"

__all__ = ["__version__", "host_available"]


def host_available() -> bool:
    """Whether claude-swap is importable, i.e. whether the pin can do anything.

    Safe to call with the host missing — that is the case it exists for.
    """
    from cswap_pin._host import available

    return available()
