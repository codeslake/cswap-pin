"""Guards on the suite itself, rather than on the proxy.

THEY LIVED IN `conftest.py` AND NEVER RAN. pytest imports a conftest for its
fixtures and hooks and does not collect test functions from it, so these six
were never executed once — including `test_every_case_has_a_driver`, whose
docstring calls itself the one guard that cannot go quiet. It had gone quiet,
and four of the six were red by the time anyone looked.

They live here because this file IS collected. `conftest.py` is still a normal
module, so what they need comes from it by import.
"""
from conftest import run_cases  # noqa: F401  — used by the driver guard


def test_a_case_cannot_leave_the_process_marked_draining(request, tmp_path_factory):
    """A drain one case announces must not answer yes for the next one.

    `_DRAINING_DEPTH` is a module global, so `mp.undo()` does not reach it, and
    `this_process_is_draining` matches the marker BASENAME — the pid — which is
    exactly right for a daemon that owns one certdir and wrong for a worker
    that runs dozens. The relay reads it and puts `Connection: close` on every
    keep-alive reply it writes, so an unrelated later case sees a closed
    connection and a second request that was never served.

    Measured on HEAD: `TestResponseFramingIsParseable` failing 2 of 8 cases in
    roughly one full-suite run in four, always those two.
    """
    import cswap_pin.proxy as pin_proxy

    class Holder:
        def case_a_announces_and_never_releases(self, tmp_path):
            pin_proxy.announce_draining(tmp_path)

        def case_b_must_not_inherit_it(self, tmp_path):
            assert not pin_proxy.this_process_is_draining(), (
                "a previous case's drain marks this one's replies "
                "`Connection: close`")

    try:
        run_cases(Holder(), request, tmp_path_factory)
    finally:
        with pin_proxy._DRAINING_LOCK:
            pin_proxy._DRAINING_DEPTH.clear()


def test_every_case_has_a_driver():
    """A `case_*` method with no `test_all` NEVER RUNS, and nothing says so.

    MEASURED: 82 cases across 57 classes had been silently dead — including
    TestKillDaemon, TestOrphanSweep, TestDaemonSignalTeardown and
    TestEnsureProxyLifecycle, i.e. the paths that strand sessions. The suite
    reported `60 passed` the whole time, and a test written for a REAL defect
    (the mtime fingerprint) passed while the defect was still there, because
    its class had no driver either.

    That is worse than having no test: a green run is read as evidence. This
    guard is the one thing that cannot itself go quiet, because it is a plain
    pytest function with no driver of its own.
    """
    import pathlib
    import re

    dead = []
    for path in sorted(pathlib.Path(__file__).parent.glob("test_*.py")):
        cls = None
        has_driver = False
        cases = []
        for line in path.read_text().splitlines():
            if line.startswith("class "):
                if cls and cases and not has_driver:
                    dead.append((path.name, cls, len(cases)))
                cls = line.split(":")[0].split("(")[0].replace("class ", "").strip()
                has_driver = False
                cases = []
            elif re.match(r"    def test_all\b", line):
                has_driver = True
            elif re.match(r"    def case_", line):
                cases.append(line.strip())
        if cls and cases and not has_driver:
            dead.append((path.name, cls, len(cases)))

    assert not dead, (
        f"{sum(n for _, _, n in dead)} case(s) in {len(dead)} class(es) never "
        f"run — they have `case_*` methods and no `test_all` driver:\n"
        + "\n".join(f"  {f}::{c} ({n} cases)" for f, c, n in dead)
        + "\n\nAdd to each class:\n"
        "    def test_all(self, request, tmp_path_factory):\n"
        "        run_cases(self, request, tmp_path_factory)"
    )


def test_the_holder_has_no_accept_loop():
    """THE HOLDER MUST NEVER ACCEPT, and every measured property rests on it.

    Two processes hold one listening socket, and the kernel gives each arrival
    to exactly ONE of them. A holder that accepts therefore eats a share of
    STEADY-STATE traffic and hangs it, because nothing in the holder answers a
    request.

    A peer session measured that on its runtime: 200 concurrent requests,
    hung=36 acceptedByHolder=36, EXACTLY 1:1, ~18% of all traffic. Its holder
    cannot avoid it — node's `net.Server` has no `pause()`, and
    `maxConnections=0` accepts then RSTs (19 of 20 measured) — so it must
    CLOSE the socket while a child runs and win it back after. That close is
    what gives its port a refusal window a crash can land in.

    Mine has no window because it never closes, and it can stay open only
    because it never accepts: a bare socket object with nothing calling
    `accept()` on it does not accept, so the kernel has one candidate.
    Measured against this shape, 200 concurrent, no kills:
    `ok=200 hung=0 refused=0`, peak accepted holder 0 / daemon 7.

    ASSERTED ON THE SOURCE, deliberately. The runtime version of this test was
    written first and DELETED: it passed, and then failed to fail when the
    holder was given a real accept loop — an unfalsifiable green test is worse
    than none, because it reads as coverage. This asks the one question that
    is decidable: does `PortHolder` contain an accept call at all.
    """
    import pathlib
    import re

    src = (
        pathlib.Path(__file__).parent.parent / "src/cswap_pin/proxy.py"
    ).read_text()
    # THE CLASS BODY, not everything after it. Splitting on "\nclass " runs
    # past the end of the class into the module-level functions below, which
    # DO accept — `_handed_down_listener`'s one-shot non-blocking probe asks
    # a socket whether it is listening, and immediately closes what it gets.
    # Reading those as PortHolder's made this fail on correct code, which
    # teaches a reader to ignore it.
    body = src.split("class PortHolder")[1]
    body = body[: body.index("\ndef ")] if "\ndef " in body else body
    # Comments and docstrings discuss accepting at length — that is the point
    # of the class. Only executable calls matter.
    code = "\n".join(
        line for line in body.splitlines()
        if not line.lstrip().startswith("#")
    )
    # EXCEPT IN THE DEGRADED PATH, which did not exist when this was written.
    # There the holder serves the port ITSELF because no successor could start,
    # so there is no daemon to steal a connection from — the premise below is
    # about a holder accepting BESIDE a live daemon, and that is still banned.
    # Cut the degraded method out and scan what is left.
    if "def _accept_degraded" in code:
        head, _, rest = code.partition("    def _accept_degraded")
        _, _, after = rest.partition("\n    def ")
        code = head + ("\n    def " + after if after else "")
    accepts = re.findall(r"\.accept\(\)", code)
    assert not accepts, (
        f"PortHolder calls accept() {len(accepts)} time(s). Two processes "
        f"share one listening socket, so every connection it takes is one the "
        f"daemon never sees — and nothing in the holder answers, so it hangs. "
        f"A peer measured exactly 1:1, 36 of 200 requests, ~18% of ALL "
        f"traffic. If the holder must accept, it must also close between "
        f"children, and the port gains a refusal window a crash can land in."
    )


def test_the_reaper_kills_holders_before_the_daemons_they_replace():
    """A REAPER THAT KILLS CHILDREN FIRST CANNOT CONVERGE.

    A holder's whole job is to replace a daemon that dies, so killing the
    daemon first hands the holder its cue: the sweep races a supervisor that
    is actively undoing it. `_reap_pin_processes` therefore kills PARENTS
    first, and this pins that ordering against a later edit that looks
    harmless.

    MEASURED HERE, before that ordering existed: a handover test that TERM'd
    only the recorded daemon pid accumulated 7 orphans across a few suite
    runs. A peer session hit the same wall from further along and its numbers
    are the clearer ones — four reaping strategies in a row failed, and the
    last two failed EVEN WITH A 20-SECOND WATCH, because the survivors it
    found were 37 s and 17 s old: born DURING the sweep, and again AFTER it.
    Its conclusion is the same rule: "killing the listener loses to a holder
    that just starts another".

    That leak cost it a CI hang, because a leftover on the runner held the
    job's stdout pipe — the job stopped updating rather than failing.

    THE OTHER HALF is that the sweep matches on the CERTDIR in argv rather
    than on process ancestry. A holder's replacement is spawned DETACHED, so
    its ppid is 1 and `pgrep -P` cannot see it at all; the peer's reaper was
    blind to exactly the process it needed to kill.
    """
    import pathlib
    import re

    # THE FILE WITH THE REAPER, NAMED. `__file__` was conftest.py while this
    # guard lived there; from here it finds no reaper and the scan comes back
    # empty, which reads as "the shape changed" rather than "I looked in the
    # wrong place".
    src = (pathlib.Path(__file__).parent / "conftest.py").read_text()
    body = src.split("def _reap_pin_processes")[1].split("\ndef ")[0]

    kills = re.findall(r"for pid in ([\w +]+):", body)
    assert kills, "the reaper no longer loops over a list of pids"
    # STANDBYS ARE NEITHER, and they did not exist when this was written. A
    # standby holds the port for its holder and respawns nothing, so killing it
    # first cannot multiply the set — the hazard here is a PARENT outliving the
    # children it replaces. Judge only the two that stand in that relation.
    seen_pair = False
    for order in kills:
        parts = [p.strip() for p in order.split("+")]
        ranked = [p for p in parts if p.startswith(("holder", "daemon"))]
        if not ({"holders", "daemons"} <= set(ranked)):
            continue
        seen_pair = True
        assert ranked.index("holders") < ranked.index("daemons"), (
            f"the reaper kills `{order.strip()}` — daemons before holders, and "
            f"a holder left alive replaces every daemon the sweep kills, so it "
            f"cannot converge"
        )
    assert seen_pair, (
        "no loop kills holders and daemons together any more, so the ordering "
        "this guards is not being asserted at all — read the reaper before "
        "deleting this"
    )
    # AND NOT BY ANCESTRY: a holder's replacement is detached (ppid 1).
    assert "pgrep -P" not in body and "ppid" not in body, (
        "the reaper is selecting by process ancestry — a detached replacement "
        "has ppid 1 and is invisible to it"
    )


def test_the_developers_environment_cannot_change_what_the_suite_measures(
    tmp_path, monkeypatch
):
    """EVERY VARIABLE THE PIN READS MUST BE SCRUBBED BEFORE A CASE RUNS.

    The suite runs inside a pinned session, which inherits the pin's own env
    at boot, and a developer debugging the daemon exports more of it by hand.
    Both directions have bitten:

      - `CSWAP_PIN_PORT` made four unrelated cases fail, each trying to bind
        the developer's real 36301. Loud, so it was fixed the day it appeared.
      - `CSWAP_PIN_SELF_HEAL=off` disables the holder's respawn and the code
        watchdog, so it turned every test of those paths GREEN without running
        them. Silent, so nothing surfaced it. A peer session hit the same
        class from the loud side and said it plainly: "they passed because the
        bug existed".

    So this asserts the scrub COVERS what the module reads, rather than
    trusting a list somebody remembers to extend. It reads the source for
    `CSWAP_PIN_*` names and checks each one is either scrubbed or is a name
    the pin WRITES rather than reads.

    AND THAT THE SCRUB RUNS FIRST. A peer put its equivalent scrub AFTER the
    fixture set its own values and deleted what the fixture had just set —
    "the edit applied cleanly and looked right". Here the scrub is at the top
    of `_redirect_everything_to`, and this pins that: a fixture-set value must
    survive into the case.
    """
    import os
    import pathlib
    import re

    # THE FILE WITH THE SCRUB LIST, NAMED. This read `__file__` while the
    # guard lived in conftest.py; moving it here made that the wrong file
    # and the set came back EMPTY, so every variable read as unscrubbed.
    src = (pathlib.Path(__file__).parent / "conftest.py").read_text()
    scrubbed = set(re.findall(r'"(CSWAP_PIN_\w+)"', src.split("store =")[0]))

    proxy_src = (
        pathlib.Path(__file__).parent.parent / "src/cswap_pin/proxy.py"
    ).read_text()
    # What the module READS from the environment — a name it only WRITES (into
    # a child's env, or into `.claude.json`) cannot pollute a case.
    #
    # Two shapes, because the module uses both: the literal, and a module
    # constant holding it. Resolving the constants first makes the second
    # shape the same question as the first.
    consts = dict(re.findall(r'^(\w+_ENV) = "(CSWAP_PIN_\w+)"', proxy_src, re.M))
    read = set(re.findall(r'environ\.get\(\s*"(CSWAP_PIN_\w+)"', proxy_src))
    for const, value in consts.items():
        if re.search(rf"environ\.get\(\s*{const}\b", proxy_src):
            read.add(value)

    missing = sorted(read - scrubbed)
    assert not missing, (
        f"the pin reads {missing} from the environment and the conftest does "
        f"not scrub it — a developer who exports it changes what this suite "
        f"measures, silently if the value makes a path a no-op"
    )

    # AND THE ORDER: THE SCRUB MUST RUN BEFORE THE FIXTURE SETS ANYTHING.
    #
    # A peer put its equivalent scrub AFTER its fixture's own assignments and
    # deleted what the fixture had just set — "the edit applied cleanly and
    # looked right", caught only by reading the surrounding lines.
    #
    # ASSERTED ON THE SOURCE, not by setting a variable here and reading it
    # back. That was the first version and it was worthless: it runs inside
    # THIS test, where the fixture's own assignments are not in play, so it
    # passed with the scrub moved to the end of the fixture — verified by
    # mutation, which is the only reason it is not still here.
    # THE RULE IS NARROWER THAN "SCRUB FIRST": what must not happen is the
    # scrub deleting a name the fixture ITSELF sets. Unrelated writes may come
    # before it — `CLAUDE_CONFIG_DIR` does, and correctly, because the scrub
    # never touches that name.
    #
    # Two earlier versions of this check were wrong ON CORRECT CODE, which is
    # how a guard teaches people to ignore it: one compared against
    # `setattr` (not an env write at all), the next against the first `setenv`
    # of any name. Both found by running it, not by reading it.
    body = src.split("def _redirect_everything_to")[1].split("\ndef ")[0]
    scrub_at = body.index("delenv(name, raising=False)")
    clobbered = [
        n for n in scrubbed
        if f'setenv("{n}"' in body and body.index(f'setenv("{n}"') < scrub_at
    ]
    assert not clobbered, (
        f"the scrub deletes {clobbered}, which this fixture sets ABOVE it — "
        f"scrub the BASE, then apply, or the fixture's own value is thrown "
        f"away before any case sees it"
    )


def test_no_blocking_socket_call_is_unbounded():
    """A SOCKET CALL WITH NO TIMEOUT CAN HANG THE WHOLE SUITE.

    pytest has no default per-test timeout, so one `recv` on a peer that
    accepts and never answers does not fail the case — it stops the run, and
    the job idles to whatever outer cap exists with nothing reported. A peer
    session measured exactly that on its own runner: one job past 43 minutes
    while its siblings finished in 39 seconds, and NO check anywhere said
    "failed".

    A global timeout is the wrong fix and is deliberately not used here: a
    value large enough for a slow machine cannot catch a hang, and one small
    enough to catch it turns a slow machine red. This reads source instead —
    it cannot make a slow runner fail, only an unbounded call.

    WHY A GUARD RATHER THAN CARE. The same peer swept its suite BY HAND three
    times and missed the same shape three times; my own sweep of this suite
    was by hand too. Judgement does not scale to a file that keeps growing.

    Scoped to `connect`/`recv`/`accept` on a bare socket — the calls that
    block forever by default. `create_connection` is covered because its
    timeout argument is what a caller forgets.
    """
    import pathlib
    import re

    # `recv` on a socket whose timeout was set earlier is fine, so this looks
    # for the two shapes that CANNOT have one: a connection built with no
    # timeout=, and a bare `socket.socket()` used without `settimeout`.
    unbounded = []
    for path in sorted(pathlib.Path(__file__).parent.glob("test_*.py")):
        lines = path.read_text().splitlines()
        for n, line in enumerate(lines, 1):
            if "# noqa: unbounded" in line:
                continue  # deliberate, and it has to say so
            if "socket.create_connection(" not in line:  # noqa: unbounded
                continue
            # PROSE IS NOT A CALL. A guard that flags the sentence describing
            # it reads as a finding and trains the reader to ignore it — a
            # peer's first version of this same guard did exactly that.
            if re.match(r"\s*[#*]|\s*`|\s*\"\"\"", line) or "`" in line:
                continue
            # THE ARGUMENTS MAY WRAP: `create_connection(\n  addr,\n
            # timeout=5)` is bounded and looks unbounded on line 1 alone. So
            # read to the paren that CLOSES the call — the first `)` is the
            # address tuple's, and stopping there flagged every bounded call
            # in the suite while looking correct.
            call = "\n".join(lines[n - 1:n + 4])
            call = call[call.index("create_connection("):]
            depth, end = 0, len(call)
            for i, ch in enumerate(call):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i + 1
                        break
            if "timeout" in call[:end]:
                continue
            unbounded.append(f"{path.name}:{n}: {line.strip()}")

    assert not unbounded, (
        "socket call(s) with no timeout — one of these can hang the entire "
        "run with nothing reported, because pytest has no default per-test "
        "deadline:\n" + "\n".join(f"  {u}" for u in unbounded)
        + "\n\nPass timeout=, or mark the line `# noqa: unbounded` if the "
        "block is the point of the test."
    )
