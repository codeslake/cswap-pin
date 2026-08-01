"""Keep Claude Code's Remote Control and Artifacts on one account.

cswap swaps the on-disk credential, so everything follows the swap — including
two things that are not inference and usually should not move: Remote Control
(a session's owner is fixed at creation by the bearer that created it) and
Artifacts (owned by the publishing bearer). This package keeps those on one
account while inference keeps following ``cswap switch`` / ``cswap auto``.

Companion to claude-swap. Installed as ``claude-swap[pin]``; see
https://github.com/realiti4/claude-swap/issues/198 for why it lives apart.
"""

from cswap_pin.proxy import (  # noqa: F401
    apply_pin,
    ensure_proxy,
    heal,
    load_pin,
    save_pin,
    unwire_if_dead,
    wire_env,
    wire_global_config,
)

__version__ = "0.1.0"
