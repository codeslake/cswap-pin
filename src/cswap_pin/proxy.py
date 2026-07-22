"""Account-pin proxy.

A local MITM forward proxy that swaps the ``Authorization`` bearer to a pinned
account's token on the Remote-Control and Artifact routes, so those operations
stay on one account while inference follows whatever cswap has swapped onto
disk. Everything else (inference at ``/v1/messages``, OAuth, telemetry, …) is
relayed untouched, and non-anthropic hosts are blind-tunnelled.
"""

from __future__ import annotations


def is_pinned_route(path: str) -> bool:
    """Whether a request path's bearer must be swapped to the pinned account.

    True for the routes whose server-side ownership is set by the bearer and
    that we want pinned — Remote-Control code sessions and Artifact ("frame")
    deploys. False for everything else, most importantly ``/v1/messages`` (which
    must keep billing the currently-swapped inference account).
    """
    return path.startswith("/v1/code/sessions") or path.startswith("/api/frame/")


def swap_authorization(headers: dict[str, str], pin_token: str) -> dict[str, str]:
    """Return ``headers`` with the ``Authorization`` bearer replaced by the pin.

    Only the Authorization value changes; every other header is preserved.
    """
    out = dict(headers)
    for name in out:
        if name.lower() == "authorization":
            out[name] = f"Bearer {pin_token}"
    return out
