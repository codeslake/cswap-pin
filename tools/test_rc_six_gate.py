"""The gate's slow-request count must be EVENTS, not lines.

The pin rate-limits its slow-request report to one line a minute and folds
the rest into "; N more in the last minute". So a line count is bounded at
60/hour no matter how bad the hour is, and it falls whenever the reporter is
quiet for reasons unrelated to the stall.

Measured 2026-08-20: a hand-rolled count of the same log read 85 lines before
a change and 6 after, which looked exactly like a fix. The events were 134
and 22. This is the single implementation the whole fleet reads, so the fix
belongs here rather than in another script beside it.

A peer put the general form best the same night: if this is resumed, the unit
is events with timestamps, not events per hour. A rate needs a stationary
process and this one swings two orders of magnitude inside an hour.
"""
import json
import pathlib
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import rc_six_gate as g  # noqa: E402

TAIL = " — a live view times out on stalls like this"


def line(stamp, ms, suppressed=0):
    more = f"; {suppressed} more in the last minute" if suppressed else ""
    return (f"[{stamp}Z] cswap-pin/0.1.159 pid=1 a POST to /x took {ms}ms "
            f"(0ms of it inside the pin; {ms}ms waiting for the answer, "
            f"0ms getting it out{more}){TAIL}")


@pytest.fixture
def log(tmp_path, monkeypatch):
    """A store whose daemon.log we control, resolved the way the gate does."""
    d = tmp_path / "pin-proxy"
    d.mkdir(parents=True)
    (tmp_path / "sequence.json").write_text("{}")
    monkeypatch.setattr(g, "store", lambda: tmp_path)
    return d / "daemon.log"


def stamps(*offsets_s):
    """UTC stamps at now-offset, so every fixture line is inside the window."""
    return [time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - o))
            for o in offsets_s]


def test_a_suppressed_count_is_folded_in(log):
    """THE BUG. One line carrying seven suppressed siblings is eight events."""
    a, b = stamps(120, 60)
    log.write_text(line(a, 1600, suppressed=7) + "\n" + line(b, 1700) + "\n")
    ev = g.pin_slow_events()
    assert sum(e.events for e in ev) == 9, ev
    assert len(ev) == 2, "still two records; only the COUNT differs"


def test_a_line_count_would_have_said_two(log):
    """The control that names the defect. Without it this test could pass
    against an implementation that returns the right total by luck."""
    a, b = stamps(120, 60)
    log.write_text(line(a, 1600, suppressed=7) + "\n" + line(b, 1700) + "\n")
    assert len(g.pin_slow_lines()) == 2
    assert sum(e.events for e in g.pin_slow_events()) == 9


def test_the_worst_carries_its_timestamp(log):
    """A number without a timestamp cannot be checked against anything else --
    a peer's probe window, a deploy, an outage. Events with timestamps is the
    unit; a bare count is what produced two retractions."""
    a, b = stamps(180, 90)
    log.write_text(line(a, 1600) + "\n" + line(b, 6473) + "\n")
    worst = max(g.pin_slow_events(), key=lambda e: e.ms)
    assert worst.ms == 6473.0
    assert worst.stamp == b


def test_a_log_with_no_slow_records_is_empty_not_an_error(log):
    log.write_text("[2026-08-20T23:00:00Z] cswap-pin/0.1.159 pid=1 started\n")
    assert g.pin_slow_events() == []


def test_records_outside_the_window_are_dropped(log):
    """The window is the one thing this file already got wrong once: a
    mktime/time.timezone pair read a UTC stamp as local and reported zero
    during an hour with an event every ninety seconds."""
    old, new = stamps(7200, 30)
    log.write_text(line(old, 9999) + "\n" + line(new, 1600) + "\n")
    ev = g.pin_slow_events()
    assert [e.stamp for e in ev] == [new], "the 2h-old record must not appear"


def test_an_unreadable_log_is_not_a_quiet_one(tmp_path, monkeypatch):
    """Absent and quiet are different facts and the caller must not read the
    empty list as 'nothing happened' -- the docstring says so, and this pins
    that the function does not invent records to fill the gap."""
    (tmp_path / "sequence.json").write_text("{}")
    monkeypatch.setattr(g, "store", lambda: tmp_path)
    assert g.pin_slow_events() == []


def test_a_transcript_is_read_by_its_TAIL_not_whole(tmp_path):
    """THE GATE MUST NOT ALLOCATE A TRANSCRIPT.

    `check_attachment` scanned the 12 newest transcripts with
    `open(t).read()`. Measured on this box: 4 of those 12 are over 50MB and
    the largest is 394MB, so every run of a ten-minute cron read ~400MB into
    memory to find one regex.

    The tail is also the CORRECT window — an attachment referenced only in the
    first megabyte of a 394MB transcript is months old and not what
    requirement 4 asks about.
    """
    big = tmp_path / "big.jsonl"
    big.write_bytes(b"x" * 3_000_000 + b"\nMARKER\n")
    got = g._transcript_tail(str(big), limit=100_000)
    assert "MARKER" in got, "the tail must still contain the end of the file"
    assert len(got) <= 200_000, f"read {len(got)} bytes, expected a tail"


def test_a_small_transcript_is_read_whole(tmp_path):
    """THE CONTROL. A tail reader that truncated everything would pass the
    test above and silently halve the gate's reach on ordinary files."""
    small = tmp_path / "small.jsonl"
    small.write_text("HEAD\n" + "y" * 500 + "\nTAIL\n")
    got = g._transcript_tail(str(small), limit=100_000)
    assert "HEAD" in got and "TAIL" in got


class TestReconnect:
    """Requirement 3 reported PASS on a string that is always present.

    The static half greps the binary for `[SessionsV2Client] Force reconnect`.
    That string is there whether or not reconnect WORKS, so a PASS resting on
    it alone is a verdict the check can never fail to produce.

    The live half was already read — rc_watch's `.back` files — but only to
    decorate the PASS. So the one state that matters was invisible: sessions
    torn off Remote Control and NONE of them coming back still printed PASS.
    """

    def _wire(self, monkeypatch, tmp_path, backs, discos, binary=True):
        d = tmp_path / ".rc_watch"
        d.mkdir(parents=True, exist_ok=True)
        (d / "h.back").write_text("\n".join(f"b{i}" for i in range(backs)))
        (d / "h.disco").write_text("\n".join(f"d{i}" for i in range(discos)))
        monkeypatch.setattr(g, "_rc_watch_dir", lambda: d)
        b = tmp_path / "2.1.238"
        b.write_bytes(b"[SessionsV2Client] Force reconnect exhaustedBudget"
                      if binary else b"nothing")
        return b

    def _verdict(self, monkeypatch, tmp_path, backs, discos, binary=True):
        b = self._wire(monkeypatch, tmp_path, backs, discos, binary)
        g.ROWS.clear()
        g.check_reconnect_possible(b)
        return g.ROWS[-1][1], g.ROWS[-1][2]

    def test_torn_off_and_none_came_back_is_not_a_PASS(self, monkeypatch,
                                                       tmp_path):
        """THE STATE THAT MATTERS. Four sessions lost Remote Control and not
        one recovered — the exact failure requirement 3 names — and the old
        check said PASS because a string was in the binary."""
        v, detail = self._verdict(monkeypatch, tmp_path, backs=0, discos=4)
        assert v != "PASS", detail
        assert "4" in detail, detail

    def test_an_observed_reconnect_is_a_PASS(self, monkeypatch, tmp_path):
        """THE CONTROL. A check that never says PASS is as useless as one that
        always does."""
        v, detail = self._verdict(monkeypatch, tmp_path, backs=2, discos=3)
        assert v == "PASS", detail
        assert "2" in detail, detail

    def test_nothing_to_recover_from_is_UNPROVEN_not_PASS(self, monkeypatch,
                                                          tmp_path):
        """No disconnect, so no reconnect COULD have happened. The mechanism
        is present and the event is unobserved — that is UNPROVEN, and the
        cron rule grants its exemption for exactly this shape. Saying PASS
        spends the exemption on a claim the check did not make."""
        v, detail = self._verdict(monkeypatch, tmp_path, backs=0, discos=0)
        assert v == "UNPROVEN", detail

    def test_a_build_missing_the_reset_path_still_FAILs(self, monkeypatch,
                                                        tmp_path):
        """Unchanged behaviour, pinned so the rework cannot drop it."""
        v, _ = self._verdict(monkeypatch, tmp_path, 0, 0, binary=False)
        assert v == "FAIL"


class TestBidirectionalFreshness:
    """Requirement 5 trusted a verdict of any age.

    It scans the daemon log in reverse and takes the first inbound verdict it
    meets, with NO time bound. Measured live: the line it was reporting as
    current was 99.5 minutes old, written by a daemon generation that had
    since been replaced twice. The gate said PASS on it every ten minutes.

    The daemon's own cadence, from 15 verdict lines over ~7h in that log:
    median gap 34 min, max 73.8 min. So 99.5 min is already past anything
    normal operation produces -- the reporter had stopped, and the check could
    not tell.
    """

    def _log(self, tmp_path, monkeypatch, line):
        d = tmp_path / "pin-proxy"
        d.mkdir(parents=True, exist_ok=True)
        (tmp_path / "sequence.json").write_text("{}")
        (d / "daemon.log").write_text(line + "\n")
        monkeypatch.setattr(g, "store", lambda: tmp_path)
        monkeypatch.setattr(g, "api", lambda *a, **k: (200, ""))

    def _verdict(self, tmp_path, monkeypatch, age_min, text=None):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S",
                              time.gmtime(time.time() - age_min * 60))
        body = text or "every posting bridge holds an inbound stream (3 posting)"
        self._log(tmp_path, monkeypatch, f"[{stamp}Z] cswap-pin/0 pid=1 {body}")
        g.ROWS.clear()
        g.check_bidirectional(36301)
        return g.ROWS[-1][1], g.ROWS[-1][2]

    def test_a_fresh_verdict_still_PASSes(self, tmp_path, monkeypatch):
        """THE CONTROL. A freshness rule that rejected everything would pass
        the staleness test below while making the check useless."""
        v, detail = self._verdict(tmp_path, monkeypatch, age_min=2)
        assert v == "PASS", detail

    def test_the_age_is_always_stated(self, tmp_path, monkeypatch):
        """A verdict with no age cannot be judged by the reader, which is how
        a 99-minute-old line was read as the current state."""
        _, detail = self._verdict(tmp_path, monkeypatch, age_min=2)
        assert "min" in detail and ("ago" in detail or "old" in detail), detail

    # THE TWO STALENESS TESTS THAT STOOD HERE ARE DELETED, not moved.
    #
    # They asserted that a verdict older than two hours is UNPROVEN, and that
    # model is wrong: `_report_deaf_bridges` reports TRANSITIONS, so silence
    # means the set has not changed. Keeping them would have forced the wrong
    # behaviour back in — a test that pins a mistake is worse than no test,
    # because it makes the mistake look deliberate.
    #
    # What replaced them is `TestInboundVerdictIsTransitionOnly`, which keys
    # staleness on the DAEMON having been replaced rather than on the clock.
    # The two tests above still stand: a fresh verdict passes, and the age is
    # always printed, because the reader still needs to see how old the
    # observation is even when it is valid.


class TestArrearsKeyNames:
    """The arrears probe read the TRANSCRIPT with the JOB store's key names.

    Two stores hold a bridge owner under DIFFERENT spellings:

        transcript bridge-session record   ownerAccountUuid
        job state.json                     bridgeOwnerAccountUuid

    `_ARREARS_SRC` asked the transcript record for `bridgeOwnerAccountUuid`,
    which it never has, so that branch always yielded None and fell through to
    the job record. A session whose pointer lives ONLY in the transcript
    therefore read as owner=None and was filtered out of `owed` entirely --
    silently exempting it from the one branch of requirement 1 that can FAIL.

    Latent rather than active: `_carry_candidates()` only yields ENDED
    sessions and every session on this box is alive, so the count is 0 today.
    It bites exactly when the check finally has something to check.

    Source-level, because the probe runs in a subprocess under the pin's own
    interpreter. That is weaker than exercising it, and it is what catches the
    spelling going back.
    """

    def test_the_transcript_is_read_with_the_TRANSCRIPT_spelling(self):
        src = g._ARREARS_SRC
        head = src.split("if owner is None and job")[0]
        assert "ownerAccountUuid" in head, (
            "the transcript branch must ask for ownerAccountUuid; asking for "
            "bridgeOwnerAccountUuid there is always None")

    def test_the_job_record_keeps_its_own_spelling(self):
        """THE CONTROL. Fixing one spelling by breaking the other would pass
        the test above and lose the job-record owner instead."""
        src = g._ARREARS_SRC
        tail = src.split("if owner is None and job")[-1]
        assert "bridgeOwnerAccountUuid" in tail, (
            "the job-record branch must keep bridgeOwnerAccountUuid")


class TestNamesMatchOwnBridge:
    """Requirement 2 matched a session name against ANY bridge title.

    The loop scanned every title in the account listing and passed on the
    first equal one, rather than looking at the session's OWN bridge. This
    account carries 72 bridges of which 37 are stale (rc-inbound reports it
    every run), so a bridge left over from an earlier run under the same name
    satisfies the check while the session's CURRENT bridge wears an invented
    title — the exact failure requirement 2 exists to catch.

    Not hypothetical, and the check's own comment records it happening: "The
    third escaped only because a bridge from an earlier run still carried its
    title on the server." The FAIL side was scoped to sessions with a pointer;
    the MATCH side was left alone.
    """

    def _wire(self, monkeypatch, live, ids, titles):
        monkeypatch.setattr(g, "live_sessions", lambda: live)
        monkeypatch.setattr(g, "bridge_pointers",
                            lambda: [(n, "acct") for n in live.values()])
        monkeypatch.setattr(g, "live_bridge_ids", lambda: ids)
        body = json.dumps({"data": [{"id": b, "title": t}
                                    for b, t in titles.items()]})
        monkeypatch.setattr(g, "api", lambda *a, **k: (200, body))
        g.ROWS.clear()
        g.check_names_restored(36301)
        return g.ROWS[-1][1], g.ROWS[-1][2]

    def test_a_stale_bridge_under_the_same_name_does_not_rescue_it(
            self, monkeypatch):
        """THE BUG. The session's own bridge has a server-invented title; an
        OLD bridge still carries its name. Matching any title calls that a
        pass."""
        v, detail = self._wire(
            monkeypatch,
            live={"s1": "rewake"},
            ids={"rewake": "cse_NEW"},
            # A server-invented title. Shaped like the real ones
            # (<host>-<adj>-<noun>) without naming a machine: this repo is
            # public and a hostname in a fixture is still a hostname.
            titles={"cse_NEW": "somehost-cozy-badger",
                    "cse_OLD": "rewake"})
        assert v == "FAIL", detail
        assert "rewake" in detail, detail

    def test_the_session_s_own_bridge_wearing_its_name_PASSes(self, monkeypatch):
        """THE CONTROL. A check that never passes is as useless as one that
        always does."""
        v, detail = self._wire(
            monkeypatch,
            live={"s1": "rewake"},
            ids={"rewake": "cse_NEW"},
            titles={"cse_NEW": "rewake", "cse_OLD": "something-else"})
        assert v == "PASS", detail

    def test_a_session_whose_bridge_id_is_unknown_is_SKIPPED_not_failed(
            self, monkeypatch):
        """Unresolvable is not wrong. Reporting it as a naming failure is the
        same conflation the FAIL side was already scoped to avoid."""
        v, detail = self._wire(
            monkeypatch,
            live={"s1": "rewake"},
            ids={},
            titles={"cse_OLD": "rewake"})
        assert v == "UNPROVEN", detail


class TestOwnBridgeComesFromTheRegistry:
    """THREE stores hold a session's bridge id, and only one is current.

        ~/.claude/sessions/<pid>.json   bridgeSessionId   <- the pin uses this
        ~/.claude/jobs/<job>/state.json bridgeSessionId
        transcript bridge-session entry bridgeSessionId

    Measured: for `ai-inter-session-peer1` the registry said
    `session_01DLpX38...` and the transcript's newest entry said
    `cse_013sfbS8...`. The server listing contained the first and not the
    second, so the registry is the live one and the transcript was stale.

    Reading the transcript first made requirement 2 FAIL on a session that was
    fine -- a wrong join reported as a fleet fault, and reported to the user
    before it was checked against the pin's own answer.

    THE PREFIXES DIFFER TOO. The registry writes `session_<rest>`, the listing
    and the transcript write `cse_<rest>`. Joining without normalising them
    would break every session at once, which is the failure mode that looks
    like a fleet outage.
    """

    def test_the_registry_id_wins_over_the_transcript(self, tmp_path,
                                                      monkeypatch):
        monkeypatch.setattr(g, "HOME", tmp_path)
        s = tmp_path / ".claude/sessions"
        s.mkdir(parents=True)
        (s / "1.json").write_text(json.dumps(
            {"sessionId": "sid1", "pid": 1, "name": "peer1",
             "bridgeSessionId": "session_RIGHT"}))
        monkeypatch.setattr(g, "live_sessions", lambda: {"sid1": "peer1"})
        got = g.live_bridge_ids()
        assert got.get("peer1") == "cse_RIGHT", got

    def test_a_session_prefix_is_normalised_to_the_listing_spelling(
            self, tmp_path, monkeypatch):
        """THE CONTROL, and it is the one that would have broken everything.
        The listing spells ids `cse_`; the registry spells them `session_`."""
        monkeypatch.setattr(g, "HOME", tmp_path)
        s = tmp_path / ".claude/sessions"
        s.mkdir(parents=True)
        (s / "1.json").write_text(json.dumps(
            {"sessionId": "sid1", "pid": 1, "name": "a",
             "bridgeSessionId": "session_ABC"}))
        (s / "2.json").write_text(json.dumps(
            {"sessionId": "sid2", "pid": 1, "name": "b",
             "bridgeSessionId": "cse_DEF"}))
        monkeypatch.setattr(g, "live_sessions",
                            lambda: {"sid1": "a", "sid2": "b"})
        got = g.live_bridge_ids()
        assert got == {"a": "cse_ABC", "b": "cse_DEF"}, got


class TestInboundVerdictIsTransitionOnly:
    """The freshness bound added earlier tonight was WRONG, and this pins why.

    `_report_deaf_bridges` says in its own docstring: "Say which bridges post
    but hold no inbound stream, on CHANGE ... Transitions only -- a line per
    sweep would bury it, and the event is the set changing." It returns early
    when the set is unchanged:

        if not self.deaf_bridges():
            if [] == getattr(self, "_last_deaf", None):
                return

    So SILENCE MEANS UNCHANGED, and an old verdict from a daemon that is still
    running means nothing has gone deaf since. Ageing it out reports a healthy
    fleet as UNPROVEN -- which the gate did, at 129 minutes, every ten
    minutes.

    The "cadence" that justified the bound (median 34 min, max 74) was not a
    cadence either. Those were intervals between CHANGES; a long gap is
    stability, not a stopped reporter.

    What CAN make the verdict stale is the daemon that wrote it being gone:
    a successor has its own `_last_deaf` and has not yet spoken.
    """

    def _wire(self, tmp_path, monkeypatch, age_min, pid, live_pid):
        d = tmp_path / "pin-proxy"
        d.mkdir(parents=True, exist_ok=True)
        (tmp_path / "sequence.json").write_text("{}")
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S",
                              time.gmtime(time.time() - age_min * 60))
        (d / "daemon.log").write_text(
            f"[{stamp}Z] cswap-pin/0 pid={pid} every posting bridge holds an "
            f"inbound stream (3 posting)\n")
        (d / "proxy.json").write_text(json.dumps({"pid": live_pid,
                                                  "port": 36301}))
        monkeypatch.setattr(g, "store", lambda: tmp_path)
        monkeypatch.setattr(g, "api", lambda *a, **k: (200, ""))
        g.ROWS.clear()
        g.check_bidirectional(36301)
        return g.ROWS[-1][1], g.ROWS[-1][2]

    def test_an_old_verdict_from_the_LIVE_daemon_still_PASSes(self, tmp_path,
                                                              monkeypatch):
        """THE BUG THIS REPLACES. 129 minutes of silence from the daemon that
        is still running means nothing went deaf in 129 minutes."""
        v, detail = self._wire(tmp_path, monkeypatch, age_min=129,
                               pid=1166010, live_pid=1166010)
        assert v == "PASS", detail

    def test_a_verdict_from_a_REPLACED_daemon_is_UNPROVEN(self, tmp_path,
                                                          monkeypatch):
        """THE CONTROL, and the real staleness: a successor has its own
        `_last_deaf` and has not spoken yet, so its silence says nothing."""
        v, detail = self._wire(tmp_path, monkeypatch, age_min=5,
                               pid=111, live_pid=222)
        assert v == "UNPROVEN", detail
        assert "111" in detail or "replaced" in detail.lower(), detail


class TestArrearsReportsItsDenominator:
    """`owed == []` meant two different things and said one.

    `carry_arrears` returns the sessions the carry still owes a restamp. An
    empty list covers BOTH "there were candidates and none was owed" -- a real
    check -- and "there were no candidates at all", which examines nothing.
    Requirement 1 printed "no ended session is owed one" for both.

    Measured tonight: it is the second. `_carry_candidates()` yields only
    ENDED sessions and every session on this host is alive, so the probe
    returns `[]` and the claim rests on an empty set. Same shape as
    requirement 3's old PASS-on-a-string, in the one requirement whose verdict
    text had not been read this pass.

    The probe already has both numbers -- its `out` list IS the candidates --
    and simply discarded the total.
    """

    def _fake_pin(self, tmp_path, monkeypatch, rows, rc=0):
        py = tmp_path / "python"
        py.write_text("#!/bin/sh\necho '%s'\nexit %d\n" % (rows, rc))
        py.chmod(0o755)
        monkeypatch.setattr(g, "_PIN_PY", py)

    def test_it_reports_how_many_candidates_it_saw(self, tmp_path,
                                                   monkeypatch):
        """Two candidates, neither owed: an examined zero."""
        self._fake_pin(tmp_path, monkeypatch,
                       '[["aaaa1111","LOGIN"],["bbbb2222","LOGIN"]]')
        owed, why, total = g.carry_arrears("LOGIN")
        assert owed == [] and total == 2, (owed, why, total)

    def test_no_candidates_is_a_distinct_total(self, tmp_path, monkeypatch):
        """THE CASE THAT WAS INVISIBLE. Nothing ended, so nothing was
        checked -- and the caller can now say so instead of implying it
        looked."""
        self._fake_pin(tmp_path, monkeypatch, "[]")
        owed, why, total = g.carry_arrears("LOGIN")
        assert owed == [] and total == 0, (owed, why, total)

    def test_an_owed_session_still_comes_back(self, tmp_path, monkeypatch):
        """THE CONTROL. Adding a denominator must not lose the numerator."""
        self._fake_pin(tmp_path, monkeypatch,
                       '[["aaaa1111","OTHER"],["bbbb2222","LOGIN"]]')
        owed, why, total = g.carry_arrears("LOGIN")
        assert owed == ["aaaa1111"] and total == 2, (owed, why, total)


class TestSlowReporterMustBeArmed:
    """Requirement 6 read a DISARMED reporter as a quiet fleet.

    `slow_report_ms()` says it in its own docstring: "OFF UNTIL SOMEONE ASKS."
    The pin writes no slow-request line at all unless
    `remoteControl.debugSlowMs` is set (or `CSWAP_PIN_SLOW_MS` in the
    environment). On a machine where it is not set the log is empty, the gate
    finds no events, and the row reads exactly like a machine with no stalls.

    That matters beyond theory: the setting is armed on the linux host and is
    NOT in the committed dotfiles, so both Macs are in precisely that state
    right now. Requirement 6 -- whose entire subject is an intermittent tail
    -- would report them as clean.

    Absent switch and quiet fleet are different facts, and this is the last
    place in the file where they were reported the same.
    """

    def _wire(self, tmp_path, monkeypatch, armed, lines=""):
        d = tmp_path / "pin-proxy"
        d.mkdir(parents=True, exist_ok=True)
        (tmp_path / "sequence.json").write_text("{}")
        (tmp_path / "settings.json").write_text(json.dumps(
            {"remoteControl": {"debugSlowMs": 1500}} if armed
            else {"remoteControl": {}}))
        (d / "daemon.log").write_text(lines)
        monkeypatch.setattr(g, "store", lambda: tmp_path)
        monkeypatch.delenv("CSWAP_PIN_SLOW_MS", raising=False)

    def test_a_disarmed_reporter_is_reported_as_such(self, tmp_path,
                                                     monkeypatch):
        self._wire(tmp_path, monkeypatch, armed=False)
        assert g.slow_reporter_armed() is False

    def test_an_armed_one_is_too(self, tmp_path, monkeypatch):
        """THE CONTROL. A predicate that always says False would satisfy the
        test above while making the row permanently useless."""
        self._wire(tmp_path, monkeypatch, armed=True)
        assert g.slow_reporter_armed() is True

    def test_the_env_override_counts_as_armed(self, tmp_path, monkeypatch):
        """`CSWAP_PIN_SLOW_MS` arms it without touching settings, so reading
        settings alone would call an armed reporter disarmed."""
        self._wire(tmp_path, monkeypatch, armed=False)
        monkeypatch.setenv("CSWAP_PIN_SLOW_MS", "1500")
        assert g.slow_reporter_armed() is True


class TestTheRotatedLogIsStillTheRecord:
    """The pin rotates `daemon.log` through `.1` and `.2` ON SIZE.

    So a busy hour is exactly what moves the evidence out of the live file,
    and reading only that file reported "no slow request in the last hour"
    with the record one filename away. Measured: live 0, `.1` 168, 18 of them
    inside the window, verdict PASS.
    """

    def test_a_record_in_the_rotated_file_is_counted(self, log):
        a, b = stamps(300, 60)
        log.with_name(log.name + ".1").write_text(line(a, 1600) + "\n")
        log.write_text(line(b, 1700) + "\n")
        ev = g.pin_slow_events()
        assert len(ev) == 2, ev
        assert [e.stamp for e in ev] == [a, b], "oldest first, .1 before live"

    def test_two_deep_is_read_too(self, log):
        a, b, c = stamps(600, 300, 60)
        log.with_name(log.name + ".2").write_text(line(a, 1600) + "\n")
        log.with_name(log.name + ".1").write_text(line(b, 1700) + "\n")
        log.write_text(line(c, 1800) + "\n")
        assert [e.stamp for e in g.pin_slow_events()] == [a, b, c]

    def test_the_window_still_applies_to_a_rotated_record(self, log):
        old, = stamps(7200)
        recent, = stamps(60)
        log.with_name(log.name + ".1").write_text(line(old, 9000) + "\n")
        log.write_text(line(recent, 1600) + "\n")
        ev = g.pin_slow_events()
        assert [e.stamp for e in ev] == [recent], (
            "reading the sibling must not widen the hour")

    def test_a_sibling_that_is_not_a_rotation_is_ignored(self, log):
        a, b = stamps(300, 60)
        # Someone's copy, not the producer's rotation. Keyed on the numeric
        # suffix, so a prefix match alone must not pull it in.
        log.with_name(log.name + ".bak").write_text(line(a, 9000) + "\n")
        log.write_text(line(b, 1600) + "\n")
        assert [e.stamp for e in g.pin_slow_events()] == [b]

    def test_CONTROL_a_live_only_log_is_unchanged(self, log):
        """No rotation present at all: the original behaviour, so a failure
        above is the rotation handling and not the reader in general."""
        a, b = stamps(120, 60)
        log.write_text(line(a, 1600) + "\n" + line(b, 1700) + "\n")
        assert [e.stamp for e in g.pin_slow_events()] == [a, b]

    def test_CONTROL_no_log_at_all_is_still_silence(self, log):
        """`[]` here means "nothing to read", which the caller must not read
        as "quiet" — the contract the docstring names, unchanged."""
        assert g.pin_slow_events() == []


class TestAnOwnerWithNoBridgeIdIsNotComparable:
    """Requirement 1 counted every job record whose owner differs as risk.

    Measured on this host, 13 live records: the 9 that name another account
    carry NO `bridgeSessionId`, and CC's veto runs on a pointer it hydrated —
    with no id there is nothing to hydrate, so that owner is not comparable.
    The correlation is exact and is neither recency nor version (one
    cliVersion across all 13, creation dates interleaved). Those 9 sessions'
    TRANSCRIPT pointers name the live login with a real `cse_` id, which is
    the half `_carry_pointer` can write — it refuses any record without a
    bridge id, so the job half has never been restamped.
    """

    LOGIN = "acct-live"

    def _wire(self, tmp_path, monkeypatch, stores, ptrs=None):
        (tmp_path / ".claude.json").write_text(json.dumps(
            {"oauthAccount": {"accountUuid": self.LOGIN,
                              "emailAddress": "x@y.z"}}))
        d = tmp_path / "store"
        d.mkdir(exist_ok=True)
        (d / "settings.json").write_text("{}")
        monkeypatch.setattr(g, "HOME", tmp_path)
        monkeypatch.setattr(g, "store", lambda: d)
        if ptrs is None:
            ptrs = [(r[0], r[1]) for r in stores]
        monkeypatch.setattr(g, "bridge_pointers", lambda: ptrs)
        monkeypatch.setattr(g, "carry_arrears", lambda u: ([], None, 0))
        # The real one returns `(rows, reason)`; a stub that returns the bare
        # list passes a shape the caller never sees in production.
        monkeypatch.setattr(
            g, "pointer_stores",
            (lambda: stores) if isinstance(stores, tuple)
            else (lambda: (stores, None)))
        g.ROWS.clear()
        g.check_rc_survives()
        return g.ROWS[-1][1], g.ROWS[-1][2]

    # [name, job_owner, job_has_id, transcript_owner, transcript_has_id]
    def test_a_stale_owner_WITH_a_bridge_id_is_still_a_WARN(
            self, tmp_path, monkeypatch):
        """The one case that can actually fail: the owner is comparable, so
        CC can veto the reattach."""
        v, detail = self._wire(tmp_path, monkeypatch, [
            ["risky", "acct-old", True, "acct-old", True],
            ["ok", self.LOGIN, True, self.LOGIN, True],
        ])
        assert v == "WARN", (v, detail)
        assert "risky" in detail and "WITH a bridge id" in detail

    def test_stale_owners_with_no_id_and_a_current_transcript_are_a_PASS(
            self, tmp_path, monkeypatch):
        """THE MEASURED FLEET STATE. Nothing here can be vetoed: the job
        owner has no bridge beside it, and the pointer that does have one
        names this login."""
        v, detail = self._wire(tmp_path, monkeypatch, [
            ["a", "acct-old", False, self.LOGIN, True],
            ["b", "acct-old", False, self.LOGIN, True],
            ["c", self.LOGIN, True, self.LOGIN, True],
        ])
        assert v == "PASS", (v, detail)
        assert "NO bridge id" in detail

    def test_no_id_and_no_transcript_pointer_is_a_WARN(
            self, tmp_path, monkeypatch):
        """Neither store would reattach it — that is not the benign case and
        must not ride out on the same PASS."""
        v, detail = self._wire(tmp_path, monkeypatch, [
            ["orphan", "acct-old", False, None, False],
            ["c", self.LOGIN, True, self.LOGIN, True],
        ])
        assert v == "WARN", (v, detail)
        assert "orphan" in detail and "nothing on disk" in detail.lower()

    def test_a_transcript_naming_ANOTHER_account_is_not_coverage(
            self, tmp_path, monkeypatch):
        """Coverage means the transcript names THIS login. A transcript with
        a bridge id but the wrong owner would be vetoed exactly like a job
        record, so it must not count as covered."""
        v, detail = self._wire(tmp_path, monkeypatch, [
            ["wrong", "acct-old", False, "acct-other", True],
        ])
        assert v == "WARN", (v, detail)
        assert "wrong" in detail

    def test_CONTROL_all_matching_is_still_a_PASS(self, tmp_path, monkeypatch):
        """The pre-existing green path, so a failure above is the split and
        not the check as a whole."""
        v, detail = self._wire(tmp_path, monkeypatch, [
            ["a", self.LOGIN, True, self.LOGIN, True],
        ])
        assert v == "PASS", (v, detail)

    def test_CONTROL_an_unreadable_split_is_a_WARN_not_a_PASS(
            self, tmp_path, monkeypatch):
        """If the two stores cannot be read, the old single-store number is
        all there is — report it as unresolved, never as clean."""
        monkeypatch.setattr(g, "pointer_stores", lambda: (None, "boom"))
        v, detail = self._wire(
            tmp_path, monkeypatch, (None, "boom"),
            ptrs=[("a", "acct-old"), ("b", self.LOGIN)])
        assert v == "WARN", (v, detail)
        assert "boom" in detail


class TestABridgedAttachmentIsNotAnImageBlock:
    """Requirement 4 looked for image blocks in `message.content`.

    A claude.ai attachment does not land there. It arrives as its own record,
    `type=attachment` / `attachment.type=queued_command`, with the bytes
    inline under `attachment.prompt`. The old census was scoped to a record
    type that cannot hold one, and then named `entrypoint` as the field to
    key on — which is session-level and read 'cli' on all 201,208 records of
    a session that had just received an attachment.
    """

    def _tx(self, tmp_path, monkeypatch, *records):
        d = tmp_path / ".claude" / "projects" / "p"
        d.mkdir(parents=True, exist_ok=True)
        (d / "s.jsonl").write_text(
            "\n".join(json.dumps(r) for r in records) + "\n")
        monkeypatch.setattr(g, "HOME", tmp_path)
        return g.bridged_attachments()

    def _attach(self, text, media="image/webp", stamp="2026-01-01T00:00:00Z"):
        return {"type": "attachment", "timestamp": stamp,
                "entrypoint": "cli", "sessionKind": "bg",
                "attachment": {"type": "queued_command",
                               "origin": {"kind": "human"},
                               "prompt": [
                                   {"type": "image",
                                    "source": {"type": "base64",
                                               "media_type": media,
                                               "data": "AAAA"}},
                                   {"type": "text", "text": text}]}}

    def test_a_tagged_attachment_is_found(self, tmp_path, monkeypatch):
        got = self._tx(tmp_path, monkeypatch, self._attach(g._BRIDGE_TAG))
        assert got == [("2026-01-01T00:00:00Z", "image/webp")], got

    def test_an_untagged_attachment_is_not_claimed(self, tmp_path, monkeypatch):
        """The tag is the only handle. Claiming an untagged one would report a
        local paste as a claude.ai attachment."""
        got = self._tx(tmp_path, monkeypatch, self._attach("here you go"))
        assert got == [], got

    def test_an_image_block_in_a_message_is_not_an_attachment(
            self, tmp_path, monkeypatch):
        """THE OLD SHAPE. A local `Read` of a PNG, or a pasted image, puts an
        image block in message.content — carrying the tag in a sibling text
        block must still not count, because that record is not an arrival."""
        got = self._tx(tmp_path, monkeypatch, {
            "type": "user", "timestamp": "2026-01-01T00:00:00Z",
            "entrypoint": "cli",
            "message": {"role": "user", "content": [
                {"type": "image", "source": {"type": "base64",
                                             "media_type": "image/png",
                                             "data": "AAAA"}},
                {"type": "text", "text": g._BRIDGE_TAG}]}})
        assert got == [], got

    def test_CONTROL_a_transcript_with_neither_is_empty(
            self, tmp_path, monkeypatch):
        """So a zero above is the corpus and not a reader that always
        returns nothing."""
        got = self._tx(tmp_path, monkeypatch,
                       {"type": "user", "message": {"role": "user",
                                                    "content": "hello"}})
        assert got == []

    def test_CONTROL_two_tagged_attachments_are_both_found(
            self, tmp_path, monkeypatch):
        """And the reader can count past one, so `len(seen)` in the row means
        something."""
        got = self._tx(tmp_path, monkeypatch,
                       self._attach(g._BRIDGE_TAG, stamp="2026-01-01T00:00:00Z"),
                       self._attach(g._BRIDGE_TAG, media="image/png",
                                    stamp="2026-01-02T00:00:00Z"))
        assert len(got) == 2, got
        assert got[-1] == ("2026-01-02T00:00:00Z", "image/png")


class TestThePopupFollowsALostEarNotASlowRequest:
    """Requirement 6 was driven by round-trip latency over 1500ms.

    That metric is falsified for this purpose: across a ten-hour window in
    which the pin logged slow round trips at 60-260 an hour, the person
    watching claude.ai reported no disconnect popup at all, and the pin's own
    record showed no bridge had lost its inbound stream since the previous
    afternoon. Latency was crying wolf on a fleet that was healthy by the
    requirement's own subject.

    The verdict is now the lost ear -- a bridge that posts and holds no
    inbound stream, which is the state a live view has nothing to receive on.
    Latency stays in the line as context.
    """

    def _wire(self, log, monkeypatch, lines, lat_ms=300.0):
        log.write_text("\n".join(lines) + ("\n" if lines else ""))
        monkeypatch.setattr(g, "api", lambda *a, **k: (200, "{}"))
        monkeypatch.setattr(g, "slow_reporter_armed", lambda: True)
        monkeypatch.setattr(g, "time", g.time)
        # A fixed latency so the probe loop cannot decide the verdict.
        seq = iter([lat_ms / 1000.0] * (g._STALL_PROBES * 4))
        base = [0.0]

        def _perf():
            base[0] += next(seq)
            return base[0]
        monkeypatch.setattr(g.time, "perf_counter", _perf)
        g.ROWS.clear()
        g.check_no_stall(36301)
        return g.ROWS[-1][1], g.ROWS[-1][2]

    def _verdict_line(self, stamp, kind):
        return f"[{stamp}Z] cswap-pin/0.1.160 pid=1 {kind}"

    def test_a_lost_ear_in_the_window_is_a_FAIL(self, log, monkeypatch):
        """THE STATE THAT MATTERS. A bridge that posts and cannot listen is
        exactly what the popup follows."""
        now, = stamps(300)
        v, detail = self._wire(log, monkeypatch, [
            self._verdict_line(now, "3 of 12 bridge(s) " + g.DEAF_PHRASE)])
        assert v == "FAIL", (v, detail)
        assert "lost their inbound stream" in detail

    def test_an_old_lost_ear_with_a_clean_hour_is_a_PASS(self, log,
                                                         monkeypatch):
        """THE STATE THE USER ASKED TO KEEP. It names the date it last
        happened, so 'still good' is a claim with a span behind it."""
        old, recent = stamps(36000, 120)
        v, detail = self._wire(log, monkeypatch, [
            self._verdict_line(old, "3 of 12 bridge(s) " + g.DEAF_PHRASE),
            self._verdict_line(recent, g.CLEAR_PHRASE + " (12 posting)")])
        assert v == "PASS", (v, detail)
        assert f"none since {old}" in detail

    def test_CONTROL_heavy_latency_alone_does_not_move_the_verdict(
            self, log, monkeypatch):
        """THE REGRESSION THIS CHANGE EXISTS TO PREVENT. Slow round trips are
        context; on their own they must not report the popup as present."""
        recent, = stamps(120)
        slow = [line(s, 9000) for s in stamps(300, 240, 180)]
        v, detail = self._wire(log, monkeypatch, [
            self._verdict_line(recent, g.CLEAR_PHRASE + " (12 posting)"),
            *slow], lat_ms=9000.0)
        assert v == "PASS", (v, detail)
        assert "context, not the verdict" in detail
        assert "slow round trip" in detail, "the latency must still be shown"

    def test_an_empty_record_is_UNPROVEN_not_a_quiet_fleet(self, log,
                                                          monkeypatch):
        """No verdict on record means nothing was evaluated. Reporting that as
        PASS is the same silent-absence failure the deaf report itself was
        built to avoid."""
        v, detail = self._wire(log, monkeypatch, [])
        assert v == "UNPROVEN", (v, detail)
        assert "not a" in detail and "quiet fleet" in detail

    def test_CONTROL_the_phrases_parse_out_of_a_real_shaped_line(self, log,
                                                                monkeypatch):
        """If `deaf_transitions` could not recognise its own phrases, every
        test above would pass by returning nothing."""
        a, b = stamps(600, 300)
        log.write_text("\n".join([
            self._verdict_line(a, "3 of 12 bridge(s) " + g.DEAF_PHRASE),
            self._verdict_line(b, g.CLEAR_PHRASE + " (12 posting)")]) + "\n")
        got = g.deaf_transitions()
        assert [k for _, k in got] == [g.DEAF_PHRASE, g.CLEAR_PHRASE], got
        assert [s for s, _ in got] == [a, b]
