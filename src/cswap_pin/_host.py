"""Everything cswap-pin borrows from claude-swap, in one place.

The pin runs INSIDE claude-swap: it is loaded by `claude-swap[pin]`, reads the
account store cswap owns, and rewrites the config file cswap already rewrites.
So it needs part of cswap's internals — but "needs part of" is exactly the
coupling that made splitting the two hard in the first place, and an import
scattered across 2800 lines is a dependency nobody can see the shape of.

This module IS that shape. Seven symbols, six modules, listed once:

    paths.get_global_config_path      where the env block lives
    paths.get_claude_config_home      the config dir root
    settings                          read/write the pin record
    exceptions.AccountNotFoundError   pin resolution failures
    exceptions.ConfigError            ...
    switcher.ClaudeAccountSwitcher    the account store
    oauth                             token extraction and refresh
    claude_locks.claude_config_lock   serialize config rewrites

Two rules follow from putting it here:

1. **Nothing else in cswap_pin imports claude_swap directly.** A new import
   elsewhere grows the contract silently; a new name in this file is a
   deliberate change to it, visible in one diff.
2. **claude-swap is a PEER, not a dependency.** It is not in our
   ``dependencies``: cswap-pin is loaded by claude-swap, so declaring it here
   would make the pair circular and pull the whole switcher into anyone who
   installs cswap-pin alone. The import therefore has to be able to fail, and
   ``require()`` is where that failure gets a readable message instead of a
   traceback from line 2000 of the proxy.
"""

from __future__ import annotations

from types import ModuleType

_HINT = (
    "cswap-pin runs inside claude-swap and cannot find it. "
    "Install the pair together: pip install 'claude-swap[pin]'"
)


class HostMissing(RuntimeError):
    """claude-swap is not importable, so the pin has nothing to pin."""


def require(name: str) -> ModuleType:
    """Import a claude_swap submodule, or fail with something readable.

    ``name`` is the part after ``claude_swap.`` — ``require("paths")`` gets
    ``claude_swap.paths``.
    """
    import importlib

    try:
        return importlib.import_module(f"claude_swap.{name}")
    except ImportError as exc:  # noqa: TRY003 — the message IS the point
        raise HostMissing(_HINT) from exc


def available() -> bool:
    """Whether the host is importable at all. For callers that want to check
    rather than catch."""
    try:
        require("paths")
    except HostMissing:
        return False
    return True
