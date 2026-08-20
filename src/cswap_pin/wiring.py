"""Which config files name the pin proxy, and how that block is written.

MOVED OUT OF THE HOST. This lived in `claude_swap/pin.py`, where it was 817 of
that file's 2198 lines — the largest thing there that was not a bond. The host
module's job is to answer when this package is ABSENT, to say where the host
keeps its own files, and to carry the host's UI policy. Deciding which configs
name the proxy, writing and clearing that block, and keeping the ledger of what
was overwritten are none of those: they are what the pin DOES, and the package
already writes the same file through `wire_global_config`.

TWO VALUES ARRIVE AS ARGUMENTS rather than being read off a switcher, because
they are the host's layout and not ours:

    backup_root   where the host keeps its per-account store
    write_json    the host's own atomic writer for its config

Everything else the subsystem needs — `paths`, `claude_locks`, `update_check` —
comes through `cswap_pin._host.require`, which is the declared seam. Nothing
here imports `claude_swap` directly; see that module's rule 1.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from pathlib import Path

from cswap_pin._host import require

_logger = logging.getLogger(__name__)

# The marker written beside the env block, naming the keys the pin added, so a
# later clear removes exactly those and nothing a user set by hand.
_WIRE_MARK = "_cswapPinWiredKeys"

# A launch must never stall on this. Both are well under the launch budget: a
# black-holed port must not turn a launch-path guard into the stall it exists
# to avoid.
_LAUNCH_PROBE_S = 0.35
_LAUNCH_LOCK_BUDGET_S = 0.5


def _certdir(backup_root):
    """Where the pin keeps its own files. One definition, so a layout change
    is one edit rather than a grep.

    THIS DOCSTRING HAS BEEN FALSE TWICE. It first said "all three go through
    it now" while two sites still spelled `backup_dir / "pin-proxy"`
    themselves; those were routed here, and the SAME diff then grew two more —
    `pin_is_applying` and `--get_certdir`, the command whose entire purpose is
    being the single authority on this path. A prose claim about a grep is a
    claim nothing checks, so it drifts every time somebody needs the path in a
    hurry.

    `test_the_certdir_literal_appears_exactly_once` is what makes it true now.
    Adding a third spelling fails the suite instead of aging into another
    aspirational sentence."""
    from pathlib import Path

    return Path(backup_root) / "pin-proxy"


def _clear_ledger(config_path) -> bool:
    """Record "not wired" in the sidecar. Never raises; SAYS whether it wrote.

    THE RETURN IS LOAD-BEARING, and discarding it made `--clear` permanently
    non-converging. The config write could succeed while this one failed (an
    unwritable pin-wiring dir, a full disk, a root-owned parent) and
    `_clear_wiring_locked` still returned True. The sidecar then kept a
    non-empty marker over a config that was already clean, so `_wiring_present`
    stayed true forever: every re-run re-injected the recorded values, failed
    the same way, and answered "re-run once it frees up" — advice that could
    never come true. The TUI kept showing a phantom cloud-account row on top.

    WRITES AN EMPTY MARKER rather than deleting the file. `_wire_mark_of`
    treats a sidecar that says "not wired" as the answer FOR THE SIDECAR and
    stops there when the config carries no marker of its own; a DELETED
    sidecar is a miss, so unlinking would let an old config key that a failed
    earlier write left behind resurrect a wiring this call just removed.

    It does NOT silence a marker in the config: that is a receipt this clear
    never saw, and reading the empty sidecar as an answer for BOTH locations
    made an older cswap-pin's wiring invisible to every recovery path.
    """
    path = None
    try:
        path = _ledger_path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps({_WIRE_MARK: []}), encoding="utf-8")
        # 0600 BEFORE the rename, like every other writer in this store. The
        # ambient umask put this file at 0644 next to the package's 0600 ones
        # in the same directory. The contents are key NAMES, not secrets, so
        # this is consistency rather than exposure — but a store where the
        # mode depends on which component wrote last is one someone will
        # eventually read the wrong way.
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except Exception:  # noqa: BLE001 — the config write is what matters
        if path is not None:
            try:
                path.with_name(f"{path.name}.{os.getpid()}.tmp").unlink()
            except OSError:
                pass
        return False


def _clear_wiring_locked(switcher, path, *, write_json=None) -> bool:
    """The read-modify-write of :func:`clear_wiring`, under its lock."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(raw, dict):
        return False

    ours = _wire_mark_of(raw, path)
    if ours is None:
        return False  # nothing of ours in there

    env = raw.get("env")
    env = dict(env) if isinstance(env, dict) else {}
    saved = _saved_of(raw, path)
    for key in ours:
        env.pop(key, None)
    env.update(saved)

    # BOTH LOCATIONS, always. The receipt may live in either (see
    # `_wire_mark_of`), and clearing only the one we read from leaves the other
    # claiming a wiring whose proxy vars are already gone — which every
    # "is it wired" caller then believes.
    raw.pop(_WIRE_MARK, None)
    raw.pop(f"{_WIRE_MARK}Saved", None)
    if env:
        raw["env"] = env
    else:
        raw.pop("env", None)

    try:
        # The switcher's own writer, not a second one: it already validates the
        # JSON it produced and chmods the TEMP file so the rename is the atomic
        # commit. This file can hold ``primaryApiKey`` and inline MCP
        # credentials, so a hand-rolled write here would be a second place for
        # that 0600 to drift out of agreement with switcher.py.
        write_json(path, raw)
    except (OSError, ConfigError):
        return False
    # AFTER the config write, never before. This is the receipt for what the
    # config still holds; dropping it first and then failing to write the
    # config would leave the proxy vars in place with nothing recording that
    # they are ours — unremovable except by hand, the exact failure
    # `clear_wiring` exists to prevent.
    # GATED ON THE SIDECAR, not only the config. Both receipts have to go, or
    # `_wiring_present` reads the survivor and the caller is told to re-run a
    # command that cannot converge.
    return _clear_ledger(path)


def _config_lock_is_free(budget: float) -> bool:
    """Can the config lock be taken within ``budget`` seconds?

    A probe, not a hold — the caller re-locks immediately after. That race is
    deliberate: losing it costs one skipped unwire (the next launch heals it),
    while the alternative is the launch itself waiting on the package's own
    5-second lock timeout, which it has no way to shorten.

    BOTH CONFIGS, because the operation this gates acts on both. It probed
    `get_global_config_path()` alone, and `clear_wiring` says why that is not
    the same question: with `CLAUDE_CONFIG_DIR` set the two paths diverge, so
    a free session config and a HELD `~/.claude.json` — a Claude Code
    credential refresh, say — passed the probe. `unwire_if_dead` then blocked
    on the package's own `claude_config_lock(timeout=5)`: a 5.3 s launch
    stall, ten times the `_LAUNCH_LOCK_BUDGET_S` this guard exists to enforce,
    reached THROUGH the guard.

    The budget is per config rather than shared. Two configs is the maximum,
    they are the same path whenever `CLAUDE_CONFIG_DIR` is unset (so the
    common case pays once), and splitting a sub-second budget in half makes
    each probe more likely to lose a race it would otherwise have won.
    """
    proper_lockfile = require("claude_locks").proper_lockfile

    for path in _each_config():
        try:
            with proper_lockfile(
                    path.parent / (path.name + ".lock"), timeout=budget):
                continue
        except Exception:  # noqa: BLE001
            return False
    return True


def _dead_wired_configs(_switcher, connect_timeout: float = 2.0, *,
                        backup_root=None) -> list:
    """Every wired config whose OWN port is not answering — and no more.

    THE VERDICT IS MACHINE-WIDE; THE ACT MUST NOT BE. `_wired_port_is_serving`
    is AND over every wired config on purpose, so one dead config makes the
    whole machine "not serving" — correct, because a live session config must
    not mask a dead default config. But `clear_wiring` is unconditional over
    every wired config, and composing the two unwired the OTHER config's live,
    correctly-routed pin:

        session cfg -> 42967 (LIVE)   default cfg -> 39967 (DEAD)
        stale verdict : True      ->  clear_wiring strips BOTH

    which is this file's own rule broken by its own code path — see the
    capitals at the top of :func:`heal`. The per-config answer was already
    computed by `_port_of_config`; it just was not used to decide WHICH.

    THIS LIST IS ALSO THE STALENESS VERDICT, one bool wide: "should any wiring
    be removed" is exactly "is any wired config's own port dead". A separate
    ``_wiring_is_stale`` predicate held that answer until every call site moved
    here, and it was deleted rather than kept as a one-line shim — one decision
    with two implementations is how the two drift apart, which this module's
    header warns about and which its `clear_wiring` call sites had already
    demonstrated.

    "Is any of this cswap's to condemn at all" is asked by
    :func:`_port_of_config`, once per config, and not again here — see the
    comment below for what that replaced.
    """
    # BOTH GUARDS THAT STOOD HERE ARE ENFORCED ONE SCOPE DOWN, and asking
    # them again was a leftover from before they moved. `_port_of_config`
    # runs `_wire_mark_of` itself and range-checks the port, so a config
    # without cswap's marker and a config whose port cannot be read BOTH
    # yield None and are skipped by the comprehension below — which is also
    # what made `_wired_ports()` (the same comprehension over the same
    # reader) unable to change this answer.
    #
    # Measured: deleting the line cost 0 of 2013 tests, and it was costing
    # two extra passes over `.claude.json` on the launch path — a file that
    # is megabytes on a real machine.
    #
    # THE TWO FACTS IT WAS KEEPING ARE STILL TRUE, and both are documented
    # where they are now enforced (`_port_of_config`):
    #
    #   A foreign `CSWAP_PIN_PORT` with no marker — a future `cswap-pin`
    #   that stops writing it, or an unrelated var of the same name — must
    #   not make this list non-empty, or `heal` reports "Removed a cloud pin
    #   wiring…" over a byte-for-byte unchanged config. Nothing is ever
    #   mutated (`_clear_wiring_locked` refuses a markerless file); the
    #   damage is entirely in the VERDICT.
    #
    #   "I CANNOT TELL" IS NOT "IT IS DEAD". A config carrying the marker
    #   with no readable port satisfies "wired" and "not serving" at once,
    #   and the launch path tore it down against a proxy that may be
    #   perfectly live. Per-config, that read sees None and the config is
    #   skipped rather than cleared — which is what makes the ACT per-config
    #   while the verdict stays machine-wide.
    return [
        path
        for path in _each_config()
        if (port := _port_of_config(path)) and not _port_answers(port, connect_timeout)
    ]


def _each_config(level: int = logging.DEBUG):
    """Both global configs, in read order, de-duplicated, guards applied.

    THE GETTER ITSELF CAN RAISE, and that is why this exists as one function
    rather than three loops. ``get_default_global_config_path`` calls
    ``Path.home()``, which raises ``RuntimeError`` when HOME is unset and the
    uid has no ``/etc/passwd`` entry (the standard rootless-container shape).
    ``heal``'s docstring promises "never raises" because the status line calls
    it on a timer, and ``_wired_ports`` sits on the path from ``heal`` through
    ``_wired_port_is_serving`` with no guard above it — an unguarded raise
    there reaches the status line's caller directly, so ``pin.heal(sw)``
    raises ``RuntimeError`` instead of returning ``(False, 'Could not heal…')``.

    A config this cannot even LOCATE has no opinion — a fact about ONE config,
    never a reason to abandon the other, which is why it continues rather than
    propagating.

    ``level`` is the caller's, and only ``clear_wiring`` raises it to WARNING;
    see the comment at that call site for why that one is allowed to be loud
    and the two ``heal`` calls unconditionally are not.

    De-duplicated because the two getters return the SAME path whenever
    ``CLAUDE_CONFIG_DIR`` is unset, and every caller would otherwise do its
    work on that config twice.
    """
    get_default_global_config_path = require("paths").get_default_global_config_path
    get_global_config_path = require("paths").get_global_config_path

    seen = set()
    for get in (get_global_config_path, get_default_global_config_path):
        try:
            path = get()
        except Exception as exc:  # noqa: BLE001 — unresolvable: no opinion
            _log_unresolvable(get, exc, level)
            continue
        if path in seen:
            continue
        seen.add(path)
        yield path


def _install_hint() -> str:
    """How to install the extra, in a form that reaches THIS install.

    Not a constant, because `pip install` is wrong for the install method most
    users have. Under a uv tool install, pip puts a second copy in whatever pip
    is on PATH and the extra never reaches the tool's environment — the user
    follows the instruction, it succeeds, and the pin is still missing.
    `cswap upgrade` already solves this; reuse its detector rather than
    re-deriving it.

    THE ONE PLACE THAT DECIDES THE COMMAND, which is why the mapping is inline
    rather than in a helper of its own: a second hardcoded `uv tool install`
    once survived beside the derived hint and diverged from it on a pipx
    machine — one screen apart, both wrong for someone.
    `test_one_place_decides_the_install_command` enforces that by name.
    """
    _detect_install_method = require("update_check")._detect_install_method

    how = {
        "uv": "uv tool install 'claude-swap[pin]'",
        "pipx": "pipx install 'claude-swap[pin]'",
    }.get(_detect_install_method() or "", "pip install 'claude-swap[pin]'")
    return f"The cloud pin requires 'cswap-pin'. Install with: {how}"


def _ledger_path(config_path):
    """The sidecar receipt for ``config_path``, under the account store.

    KEYED BY CONFIG PATH, because there are two configs. `cswap run` from a
    normal terminal wires `~/.claude.json`; from inside a session terminal it
    wires that session's `CLAUDE_CONFIG_DIR` copy. One sidecar for both would
    have the second wiring's receipt overwrite the first's, and unwiring would
    then restore the wrong displaced values into the wrong file — worse than
    the config key it replaces, which at least travelled WITH its config.
    """
    import hashlib

    get_backup_root = require("paths").get_backup_root

    key = hashlib.sha256(str(config_path).encode("utf-8")).hexdigest()[:16]
    return get_backup_root() / "pin-wiring" / f"{key}.json"


def _log_unresolvable(get, exc: BaseException, level: int = logging.DEBUG) -> None:
    """Record a path getter's raise, every time it happens. DEBUG by default.

    THE LEVEL IS THE CALLER'S, and only `clear_wiring` passes WARNING. No cap.

    A once-per-PROCESS cap cannot suppress anything here: `heal` runs as a
    fresh short-lived process per tick, so the cap's lifetime IS one tick.

    DEBUG is the default because `heal` calls `_wiring_present` and
    `_wired_ports` on EVERY tick regardless of wiring state; warning from
    there costs ~4.2MB/day and overwrites the whole 4MB rotating history in
    under a day. DEBUG keeps the record without paying for it every tick.

    `clear_wiring` overrides to WARNING because it is gated by
    `_dead_wired_configs`, and because a config that could not be LOCATED is the
    one fact its return value cannot carry: the bool is a claim about every
    path it REACHED. Why a wiring could not be REMOVED is a different record —
    the lock WARNING at the bottom of `clear_wiring`.
    """
    # `stacklevel=3` ATTRIBUTES THE RECORD TO THE CONSUMER. Without it all
    # three call sites' records are identical in origin — same `funcName`,
    # same `pathname`, same `lineno` — so nothing downstream can tell the
    # per-tick getters from the gated one, and a guard on this split can only
    # key on LEVEL. With it, `record.funcName` is `_wiring_present` /
    # `_wired_ports` / `clear_wiring`.
    #
    # THREE, NOT TWO, because the traversal is now one shared generator
    # (`_each_config`) rather than three copies of the loop: 2 would name
    # `_each_config` for all of them, which is precisely the collapse this
    # argument exists to prevent. Verified against a generator AND a
    # comprehension consumer — a comprehension reports its ENCLOSING function
    # (inlined since 3.12; this project's floor), not a `<listcomp>` frame.
    #
    # Production output is UNCHANGED: `logging_config` formats
    # "%(asctime)s - %(levelname)s - %(message)s" and never renders funcName,
    # filename or lineno.
    _logger.log(level, "%s could not be resolved: %s", get.__name__, exc, stacklevel=3)


def _port_answers(port: int, connect_timeout: float) -> bool:
    """Does a loopback connect to ``port`` succeed? The one probe, once.

    Extracted because two callers need it and they need DIFFERENT shapes of
    the answer: :func:`_wired_port_is_serving` wants the machine-wide AND,
    :func:`_dead_wired_configs` wants it per config. Two copies of the probe
    would be two places for a timeout or an exception class to drift.
    """
    import socket

    # INSIDE THE TRY, both of them. `socket.socket()` raises `OSError` on fd
    # exhaustion (EMFILE/ENFILE) and it sat OUTSIDE — so on a starved box the
    # probe raised through `_wired_port_is_serving`, which `heal` calls twice
    # with no guard, out of the function whose docstring promises "never
    # raises: this is called from the status line every few seconds". Nothing
    # about "can I reach this port" should be able to end the command that
    # answers it.
    # AND `sock` IS BOUND FIRST, or the fix moves the raise instead of
    # removing it: with the construction inside the `try`, a failing
    # `socket()` leaves the name unbound and `finally` raises
    # `UnboundLocalError` — not an `OSError`, so it escapes the handler that
    # was just widened to catch it.
    sock = None
    try:
        sock = socket.socket()
        sock.settimeout(connect_timeout)
        sock.connect(("127.0.0.1", port))
    except OSError:
        return False
    finally:
        if sock is not None:
            sock.close()
    return True


def _port_of_config(path) -> int | None:
    """The pin port ONE config file names, or None when it names none, is
    unreadable, or malformed. The single-file read :func:`_wired_ports`
    builds on, so a config's own answer is asked once.

    RANGE-CHECKED HERE, at the read, not at the probe. A value outside
    0-65535 is not a port at all — `int()` accepts it happily, but
    `socket.connect` raises `OverflowError` for it, a type
    `_wired_port_is_serving` never catches (it only catches `OSError`), and
    both its call sites inside `heal` sit OUTSIDE its bottom `try`. That
    turned a malformed `CSWAP_PIN_PORT` (any hand-edit or future writer bug,
    e.g. 99999, 70000, -1, 4294967296) into a traceback out of `cswap pin
    --heal` — called from the status line on a timer, where `heal`
    documents "never raises". Treating it as "no opinion" here, at the
    source, means every downstream consumer inherits the fix for free.
    """

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        # ONLY A PORT THIS TOOL WIRED. The marker is the receipt; a
        # ``CSWAP_PIN_PORT`` without one was put there by something else, and
        # its liveness says nothing about ours. Reading it anyway let a foreign
        # dead port make the staleness verdict True while OUR wiring was marked
        # and serving — and ``heal`` then tore down the healthy one. The
        # marker check lived only in ``_wiring_present``, one scope up, so
        # every port-level consumer inherited the gap.
        #
        # THROUGH ``_wire_mark_of``, not a fresh isinstance. That helper exists
        # because two readers of this same marker disagreed once and `--clear`
        # never converged; a third reader written here would be a fourth
        # opinion on one fact. It is the stricter test — a marker must be a
        # NON-EMPTY list — and asking it here is what makes "names a port" and
        # "is wired" the same question everywhere.
        if _wire_mark_of(raw, path) is None:
            return None
        env = raw.get("env") or {}
        port = int(env.get("CSWAP_PIN_PORT") or 0)
    except Exception:  # noqa: BLE001 — unreadable/unwired: no opinion
        return None
    return port if 0 < port <= 65535 else None


def _read_ledger(config_path) -> dict:
    """The sidecar receipt, or an empty one when there is none to read.

    ``{}`` rather than ``None``: ABSENT and UNREADABLE answer every question a
    caller asks the same way an empty dict does — ``_WIRE_MARK in {}`` is
    False and ``{}.get()`` is None — so both readers were re-testing for a
    distinction neither of them made. Verified equivalent across all 56
    sidecar/config pairs before the change.

    What still differs, and must, is ``{_WIRE_MARK: []}``: that is `--clear`'s
    receipt, it answers FOR THE SIDECAR, and it carries what that clear
    displaced. Absence carries nothing.
    """
    # RESOLVING THE PATH IS ITSELF A RAISING CALL — `_ledger_path` goes through
    # `get_backup_root()`, which raises with no HOME. It used to sit inside the
    # try below, where the bare `except` swallowed it; hoisting it to name the
    # file in the warning took it OUT of every guard, and three tests that run
    # without HOME turned into RuntimeErrors. A receipt whose PATH cannot be
    # resolved is a machine with no backup root, i.e. no pin — genuinely
    # absent, so it answers like absent, at debug rather than in silence.
    try:
        path = _ledger_path(config_path)
    except Exception as exc:  # noqa: BLE001 — no backup root means no pin
        _logger.debug("no pin receipt path for %s: %r", config_path, exc)
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        # THE ORDINARY STATE. Every machine that was never pinned lands here,
        # so it must stay silent or the warning below is noise on every launch
        # and the next reader deletes it.
        return {}
    except Exception as exc:  # noqa: BLE001 — see below
        # PRESENT AND UNREADABLE IS NOT ABSENT, even though both answer the two
        # readers with `{}` — which is true, verified across all 56
        # sidecar/config pairs, and only half the story.
        #
        # Current cswap-pin writes the receipt ONLY here; the config carries no
        # marker. So a root-owned parent, a read-only mount or a truncated file
        # makes a LIVE wiring invisible to every recovery path at once:
        # `_wiring_present` False, `heal` -> "Nothing to heal", `--ensure` a
        # no-op, and `purge` printing "Removed: Cloud pin wiring" — while
        # `.claude.json` still names a dead HTTPS_PROXY that every hand-launched
        # `claude` dials.
        #
        # The RETURN stays `{}` so that equivalence is untouched. What changes
        # is that the operator hears about it, and it is said HERE because this
        # is the single read point every caller already goes through — the
        # property `_wire_mark_of`'s docstring claims for the read-both rule.
        _logger.warning(
            "%s exists but could not be read (%s), so it is treated as no pin "
            "receipt. If a pin IS wired, heal/purge/--ensure will all report "
            "nothing to do while the env block still names its proxy.",
            path, exc)
        return {}
    return raw if isinstance(raw, dict) else {}


def _saved_of(raw: object, config_path=None) -> dict:
    """What the wiring displaced, from wherever the receipt lives.

    Same read-both rule as :func:`_wire_mark_of`, and it must stay paired with
    it: reading the marker from the sidecar and the displaced values from the
    config would restore one wiring's values over another's keys.
    """
    if config_path is not None:
        side = _read_ledger(config_path)
        if _WIRE_MARK in side:
            # PAIRED WITH THE MARKER, not merely with the sidecar's existence.
            # `_wire_mark_of` falls through to the config when the sidecar is
            # EMPTY and the config carries a marker of its own; reading the
            # displaced values from the sidecar in that case would restore one
            # wiring's values over another wiring's keys — which is worse than
            # restoring nothing, because it writes a proxy address that was
            # never there.
            side_mark = side.get(_WIRE_MARK)
            if isinstance(side_mark, list) and side_mark:
                saved = side.get(f"{_WIRE_MARK}Saved")
                return dict(saved) if isinstance(saved, dict) else {}
            if not (
                isinstance(raw, dict)
                and isinstance(raw.get(_WIRE_MARK), list)
                and raw.get(_WIRE_MARK)
            ):
                saved = side.get(f"{_WIRE_MARK}Saved")
                return dict(saved) if isinstance(saved, dict) else {}
    if not isinstance(raw, dict):
        return {}
    saved = raw.get(f"{_WIRE_MARK}Saved")
    return dict(saved) if isinstance(saved, dict) else {}


def _wire_mark_of(raw: object, config_path=None) -> list | None:
    """The marker THIS module wrote, or None. The single reader.

    ``_wiring_present`` and ``_clear_wiring_locked`` both answer "is it
    wired", and they disagreed: one accepted any truthy marker, the other
    required a non-empty list. A malformed marker (a hand-edit, a format
    change in a future cswap-pin) therefore satisfied the first and not the
    second, so `--clear` reported "could not remove the wiring — re-run once
    it frees up" forever: nothing was contended and nothing ever converged.

    That single-reader property is what makes the sidecar safe to add: the
    "read both locations" rule is written HERE, once, so every caller gets it
    without knowing the receipt moved.
    """
    if config_path is not None:
        side = _read_ledger(config_path)
        ours = side.get(_WIRE_MARK)
        if isinstance(ours, list) and ours:
            return ours
        # AN EMPTY SIDECAR ANSWERS FOR THE SIDECAR, NOT FOR THE CONFIG.
        #
        # `--clear` empties it, and treating that as the final answer made
        # a wiring written by an OLDER cswap-pin — which writes the config
        # key and no sidecar, the compat promise stated above — invisible
        # to every recovery path at once:
        #
        #     _wiring_present  False    _wired_ports  []
        #     _dead_wired_configs []     clear_wiring  False
        #     heal             (False, 'Nothing to heal')
        #
        # while `.claude.json` still named a proxy port. Every probe that
        # could have caught the stranding reported healthy. The population
        # is not exotic: the extra carries no floor, so an already-present
        # `cswap-pin` is never upgraded, and anyone who installed the pin
        # before the sidecar existed lands here on their first clear.
        #
        # What the empty sidecar DOES rule out is resurrecting a receipt
        # the clear emptied — but only the one it emptied. A marker in the
        # config is a receipt the clear never saw.
        if _WIRE_MARK in side and not (
            isinstance(raw, dict)
            and isinstance(raw.get(_WIRE_MARK), list)
            and raw.get(_WIRE_MARK)
        ):
            return None
    if not isinstance(raw, dict):
        return None
    ours = raw.get(_WIRE_MARK)
    return ours if isinstance(ours, list) and ours else None


def clear_wiring(switcher, timeout: float | None = None, only=None, *,
                 backup_root=None, write_json=None) -> bool:
    """Remove a pin wiring from the global config. True when it removed one.

    ``only`` narrows it to the given config paths. The default — every wired
    config — is what ``cswap pin --clear`` means and must not change: the user
    asked to be unpinned, and leaving one config wired is the stranding this
    function exists to prevent. ``heal`` is the caller that needs less than
    that, because its trigger is per-config (see :func:`_dead_wired_configs`)
    while its remedy was not.

    The pin writes its proxy address into ``.claude.json``'s env block and
    records which keys it wrote in ``_cswapPinWiredKeys``; this reads that
    marker and puts the file back. It touches no proxy, no daemon and no
    credential — only a record cswap left.

    It has to be here rather than in the optional package because the failure
    it prevents is caused by that package being GONE. Claude Code applies the
    env block at boot, so a wiring naming a port nothing listens on makes
    every hand-launched ``claude`` dial a dead proxy and retry forever. If the
    only code able to remove it shipped in the pin package, uninstalling the
    pin — the very thing an optional extra invites — would strand the wiring
    permanently, with hand-editing ``.claude.json`` the sole cure.

    Only keys the pin recorded are touched, and anything it displaced is
    restored, so a proxy the user or their launcher set beforehand comes back
    rather than being lost with ours.
    """
    proper_lockfile = require("claude_locks").proper_lockfile
    get_default_global_config_path = require("paths").get_default_global_config_path
    get_global_config_path = require("paths").get_global_config_path

    # BOTH configs, because the writing side resolves the same way this does:
    # `CLAUDE_CONFIG_DIR` is set in the *child's* env dict, not the process's,
    # so a `cswap run` from a normal terminal wires ~/.claude.json while one
    # from inside a session terminal wires that session's copy. Clearing only
    # the resolved path leaves the other wired, and `cswap pin --clear` then
    # prints "No cloud account pinned" over a config that still names a dead
    # port — the exact stranding this function exists to prevent. The two
    # paths diverge as soon as CLAUDE_CONFIG_DIR is set.
    #
    # EACH GETTER CAN RAISE (see the same guard on `_wired_ports` and
    # `_wiring_present`): `get_default_global_config_path` calls `Path.home()`,
    # which raises `RuntimeError` with no HOME and no `/etc/passwd` entry. A
    # config this call cannot even locate has nothing to clear there — that
    # is a fact about ONE config, not a reason to abandon the other.
    #
    # LOGGED, not just skipped: a config that could not be RESOLVED and one
    # that resolved with nothing wired both leave this loop silently short a
    # path, and `clear_wiring`'s bool is a claim about every path it reached
    # — not a claim that every path was reachable. Without a record, "the
    # default profile was never attempted because HOME could not be found"
    # and "the default profile was attempted and had nothing wired" are the
    # same silence from the outside.
    # WARNING HERE ONLY, which is the whole reason this passes a level. `heal`
    # reaches `clear_wiring` through `_dead_wired_configs`, which goes empty
    # ONCE THE REMOVAL SUCCEEDS, so this logs once and goes quiet. The two getters
    # `heal` calls UNCONDITIONALLY stay at DEBUG (see `_log_unresolvable`).
    #
    # THIS RECORD DOES NOT EXPLAIN AN UNREMOVABLE WIRING, and must not be read
    # as if it did. On the flagship shape — read-only config dir, HOME
    # resolvable — nothing raises here and it never fires; what fires is
    # `heal`'s own "the config is locked" message. Make `Path.home()` raise
    # too and this names `get_default_global_config_path` while the STUCK
    # config is the one the other getter resolved fine. Put the wiring in the
    # raising getter's config and `_wiring_present` cannot see it either, so
    # `heal` answers "Nothing to heal" and never reaches this function.
    #
    # What names an unremovable wiring is the lock-failure WARNING at the
    # bottom of this function. This record's job is the narrower one it can
    # do: a config that could not be LOCATED is missing from `paths`, and
    # `clear_wiring`'s bool is a claim about every path it REACHED.
    paths = list(_each_config(logging.WARNING))
    if only is not None:
        # BY RESOLVED PATH, not by identity: the caller got its list from
        # `_each_config` too, but a getter that resolves through a symlink or
        # a different Path flavour would silently filter everything out — and
        # an empty `paths` here is a clear that removes nothing while
        # reporting the same False as "there was nothing to remove".
        wanted = {str(p) for p in only}
        paths = [p for p in paths if str(p) in wanted]

    # ONE LOCK PER PATH. The shared config lock derives its directory from
    # get_global_config_path(), so a single lock around the loop guards one
    # file and leaves the other rewritten unprotected — racing `cswap switch`
    # and Claude Code, the whole-file clobber the lock exists to prevent.
    #
    # ``timeout`` is a TOTAL, not a per-file allowance. Passing it to each
    # acquisition makes the worst case a multiple of the number of configs, so
    # the launch path's sub-second cap silently becomes ~2x that (1.37-1.64s
    # against a documented 0.5s).
    import time as _time

    # An UNTIMED call still gets a total. Leaving `None` lets each config
    # independently wait the lock's own default, so `cswap pin --clear` with
    # both locks held freezes for 2x that (18.18s against a 9s default) — the
    # same multiple-of-the-configs shape, on the branch with no timeout.
    if timeout is None:
        DEFAULT_TIMEOUT_S = require("claude_locks").DEFAULT_TIMEOUT_S

        timeout = DEFAULT_TIMEOUT_S
    deadline = _time.monotonic() + timeout
    changed = False
    for i, path in enumerate(paths):
        # EVERY PATH IS ATTEMPTED, even with the budget gone. `if left <= 0:
        # continue` was here, and it is the same starvation the fair share
        # below was introduced to fix, one runner-speed away: path 1 only has
        # to OVERSHOOT its share for path 2 to be skipped without a single
        # attempt. Measured on this branch's Windows CI 2026-08-18 —
        # `test_a_contended_first_path_does_not_starve_a_free_second` red with
        # `attempted` holding the session lock alone — while twenty local runs
        # on Linux were green, because the overshoot needs a slow machine.
        #
        # A zero share is not a skip: `proper_lockfile` tries `os.mkdir`
        # BEFORE it checks its deadline, so a FREE lock is taken instantly and
        # a contended one fails at once. The cost of the change is a few
        # syscalls past the budget; the cost of the skip was `cswap pin
        # --clear` returning with the second config still wired.
        left = max(0.0, deadline - _time.monotonic())
        # FAIR SHARE of what remains, not "however much is left". Handing the
        # first path the whole remaining budget let a config that stayed
        # contended for the entire call consume it all, so a SECOND path
        # whose lock was completely free was skipped by the `left <= 0` check
        # above without ever being tried: with the session lock held for the
        # full 0.5s budget, `clear_wiring` returns False with BOTH configs
        # still wired.
        #
        # Dividing by how many paths are still untried gives each one at
        # least an equal slice of whatever time remains when its turn comes,
        # while the running total can still never exceed `timeout` — each
        # share is carved out of `left`, never added to it.
        share = left / (len(paths) - i)
        try:
            with proper_lockfile(
                path.parent / (path.name + ".lock"), timeout=share
            ):
                if _clear_wiring_locked(switcher, path, write_json=write_json):
                    changed = True
        except Exception as exc:  # noqa: BLE001
            # A lock we cannot take is a reason to skip THIS file, not to
            # abandon the other one — and on the launch path (sub-second
            # budget) a contended config must not fail the clear outright.
            #
            # BUT SAY WHICH FILE AND WHY. This is the ONLY record naming which
            # config could not be unwired and what stopped it. Skipping
            # silently leaves the flagship failure — a read-only config dir,
            # HOME resolvable — telling the user "could not be removed (the
            # config is locked)" every tick with zero records at any level.
            # The getter WARNING above does not fire on that shape.
            #
            # KEPT AT WARNING FOR BOTH REACHABLE KINDS. `PermissionError` and
            # `ClaudeCodeLockTimeout` both land here, and the type does not
            # separate transient from permanent: a live Claude Code credential
            # refresh raises the timeout, and so does an orphaned lock dir
            # inside a directory this process cannot write, which never
            # resolves. Splitting on type would silence the stuck machine this
            # WARNING exists for.
            #
            # The lock dir's mtime age WOULD separate them (`proper_lockfile`
            # already reads it against `CONFIG_STALENESS_S`), but the transient
            # case is self-limiting — the competitor lets go and the next free
            # tick unwires — so it costs ~2 lines once, against a permanent
            # case that repeats forever. Not worth the arithmetic.
            _logger.warning("%s could not be unwired: %s", path, exc)
            continue
    return changed


def wire_launch_env(switcher, env: dict[str, str], *, backup_root=None,
                    write_json=None) -> dict[str, str]:
    """Route a child Claude Code through the pin proxy, if one is pinned.

    Returns ``env`` unchanged when there is no pin, when the extra is not
    installed, or when the proxy cannot be started: an optional feature must
    never be able to block a launch.
    """
    # ONE guard around everything, including _impl(). A split try leaves the
    # resolution step uncovered, so anything raised there — a broken
    # cryptography, a corrupt install — kills the launch instead of starting
    # it unpinned.
    try:
        pin = _impl()
    except Exception:  # noqa: BLE001 — never block the launch
        # No pin this launch, whatever the reason: not installed, or installed
        # and broken. A wiring a previous install left behind would otherwise
        # outlive it and point every session at a dead port — see clear_wiring.
        #
        # ASK FIRST, LOCK ONLY IF THERE IS WORK. The budget is per PATH and
        # clear_wiring takes one lock per config, so a user who never installed
        # the pin — the case this budget exists for — would pay it twice
        # (1.37-1.64s with Claude Code holding the lock, against a 0.5s cap).
        # `_wiring_present` is lock-free, answers in ~1.5ms, and for that user
        # the answer is always "nothing to remove".
        #
        # AND NOT SERVING. `_impl()` raising says nothing about the daemon: a
        # broken cryptography, a half-finished reinstall, an import error in a
        # new release all land here while the proxy on the port keeps answering
        # every session already wired to it. Unwiring on presence alone strips
        # the env block from a healthy pin.
        #
        # The probe is bounded well under the launch budget rather than given
        # the default 2s: a black-holed port must not turn a launch-path guard
        # into the stall it was written to avoid.
        #
        # `clear_wiring` logs at most twice per LAUNCH here (its getter WARNING
        # and its lock WARNING), because the gate goes false only when the
        # removal succeeds. At human launch cadence that is negligible, which
        # is why the churn arithmetic lives at the statusline call site.
        #
        # THE DEAD CONFIGS, NOT "THE WIRING" — the correction `heal` carries,
        # on the third of its three call sites. All three ask a MACHINE-WIDE
        # verdict, and answering it with a machine-wide ACT strips a live
        # session config wired to a serving port because the OTHER config
        # names a dead one. `_dead_wired_configs` keeps the verdict identical
        # (the list IS the staleness verdict, one bool wide) and narrows
        # only what gets removed.
        try:
            dead = _dead_wired_configs(switcher, connect_timeout=_LAUNCH_PROBE_S,
                                        backup_root=backup_root)
            if dead:
                clear_wiring(switcher, timeout=_LAUNCH_LOCK_BUDGET_S, only=dead,
                             backup_root=backup_root, write_json=write_json)
        except Exception:  # noqa: BLE001
            pass
        return env
    try:
        pinned = pin.ensure_proxy(switcher)
        if pinned:
            port, ca_path = pinned
            # A COPY, so the peer can only scribble on a throwaway. The
            # validation below covers what `wire_env` RETURNS; a version that
            # also WRITES would leave a half-wired env in the object the
            # caller keeps — `session.py` passes the dict it goes on to use —
            # and in the one this function falls back to returning, which
            # reaches `os.execvpe` OUTSIDE the launch's try. There a wrong
            # shape is not a caught exception, it is the launch.
            #
            # Today's 0.1.68 opens with `out = dict(env)` and does not write.
            # But this module's stated threat model is a peer on an
            # independent release schedule: `heal` already refuses to trust
            # its return value, and trusting it not to WRITE while validating
            # what it returns was the missing half. One `dict()` here covers
            # the caller's object and the fallback path together.
            wired = pin.wire_env(dict(env), port, ca_path)
            # VALIDATED, NOT TRUSTED. This is the one value from the peer that
            # reaches `os.execvpe`, and execvpe sits OUTSIDE the launch's try —
            # so a wrong shape here is not a caught exception, it is the
            # launch. Both failure modes were measured:
            #
            #   None            execvpe(argv, None) does NOT fail. It hands the
            #                   child the PARENT's environ, dropping
            #                   CLAUDE_CONFIG_DIR — so the session launches
            #                   against the default login instead of the
            #                   selected account, silently. An account-isolation
            #                   break with no error anywhere.
            #   {"K": 41234}    execvpe raises TypeError out of the launch.
            #
            # The module's standing rule is that the peer may be wrong: `heal`
            # re-reads state rather than believing a return value. Same rule
            # here — anything that is not a str->str mapping degrades to an
            # UNPINNED launch, which is the failure mode the rest of this file
            # is built to tolerate.
            if isinstance(wired, dict) and all(
                isinstance(k, str) and isinstance(v, str) for k, v in wired.items()
            ):
                return wired
    except Exception:  # noqa: BLE001 — never block the launch
        pass
    # No proxy this launch, whether ensure_proxy said so or died saying it.
    # .claude.json's env block is applied at boot, so a wiring a previous
    # launch left behind would send this child at a port nothing answers.
    # ONE tail, not one per branch: duplicating it runs the unwire twice when
    # the None path's own unwire raises.
    #
    # BOUNDED, like the no-package branch above. `unwire_if_dead` takes no
    # timeout and uses the package's own claude_config_lock(timeout=5), so a
    # held .claude.json.lock costs every `cswap run` 5.3s before it returns the
    # env unchanged — and Claude Code holds that lock routinely while
    # refreshing credentials.
    #
    # If the lock is not free right now, SKIP: the wiring is stale but the next
    # launch heals it, and a launch that blocks is worse than a launch that is
    # briefly unpinned — the whole reason this path fails open.
    try:
        if _config_lock_is_free(_LAUNCH_LOCK_BUDGET_S):
            pin.unwire_if_dead(_certdir(backup_root))
    except Exception:  # noqa: BLE001
        pass
    return env
