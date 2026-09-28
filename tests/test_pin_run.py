"""`cswap pin`'s set, show and re-pin arms, which live in THIS package.

The half of `cswap pin` that only works WITH cswap-pin (setting a pin, showing
it, re-pinning) is `set_pin`, `repin_current`, `_warn_if_bridges_disagree` and
`pin_run` here; clear, heal, `--ensure` and the wiring removal stay in cswap
because they must work when this package is what is broken. These cases were
written against cswap's own copies and are ported with them: the behaviours
they defend (the rollback verdict is re-read, the pin names its account in the
live config, a note never fails the action) moved with the code.

THE HOST'S `pin` IS FAKED. CI installs the released claude-swap, which has no
`claude_swap.pin`, so the identity readers this code asks the host for
(`identity_for_config`, `_slot_for`, `_live_login_for_config`,
`_pinned_email_now`, `_config_address`, `_safe`) are stand-ins here, each a few
lines of what the host does. The host's `printer` is a stand-in too, tagging
each styling call so a case sees WHICH styler an arm used.

THE FAKE HOST `pin` CARRIES THE FOUR ENTRY POINTS THAT MUST NEVER BE CALLED BACK
(`set_pin`, `run`, `repin_current`, `_warn_if_bridges_disagree`): once cswap's
copies delegate to this package, a call from here into them is an infinite
recursion. They record the call before raising, and the fixture asserts none
was recorded at teardown for EVERY case in this file, because a raise alone is
swallowed by the very `except Exception` guards these arms are full of.
"""

import json
import re
import types

import pytest

import cswap_pin.proxy as pin_proxy

FORBIDDEN = ("set_pin", "run", "repin_current", "_warn_if_bridges_disagree")


def _record(backup):
    """The pin record as cswap's own settings file has it, or None."""
    try:
        rc = json.loads((backup / "settings.json").read_text()).get("remoteControl")
    except (OSError, ValueError):
        return None
    if not isinstance(rc, dict) or not isinstance(rc.get("pinnedEmail"), str) \
            or not rc["pinnedEmail"]:
        return None
    return rc["pinnedEmail"], rc.get("pinnedOrganizationUuid") or ""


def _write_record(backup, email, org):
    raw = {"remoteControl": {"pinnedEmail": email,
                             "pinnedOrganizationUuid": org or ""}} if email else {}
    (backup / "settings.json").write_text(json.dumps(raw))


@pytest.fixture
def host(monkeypatch):
    """The fake host `pin` and `printer`, and the recursion guard."""
    calls = []

    def _forbidden(name):
        def _call(*a, **k):
            calls.append(name)
            raise RuntimeError(f"cswap_pin called back into the host's pin.{name}")
        return _call

    pin = types.SimpleNamespace(
        calls=calls,
        _pinned_email_now=lambda sw: _record(sw.backup_dir),
        _safe=lambda exc: re.sub(r"(?<=://)[^/\s@]+@", "***@", str(exc)),
        _config_address=lambda oauth: (
            oauth["emailAddress"].casefold()
            if isinstance(oauth.get("emailAddress"), str) else ""),
        identity_for_config=lambda sw, email=None, num=None: None,
        _slot_for=lambda sw, email, org: None,
        _live_login_for_config=lambda sw: None,
        **{name: _forbidden(name) for name in FORBIDDEN},
    )
    printer = types.SimpleNamespace(
        accent=lambda t: f"[accent:{t}]",
        dimmed=lambda t: f"[dim:{t}]",
        warning=lambda msg, *, file=None: print(f"[warn:{msg}]"),
    )
    real = pin_proxy.require
    fakes = {"pin": pin, "printer": printer}
    monkeypatch.setattr(pin_proxy, "require",
                        lambda name: fakes.get(name) or real(name))
    yield pin
    assert not calls, f"cswap_pin called back into the host: {calls}"


def _sw(tmp_path, *, account=("2", "user2@example.com", None), kind="oauth"):
    backup = tmp_path / "b"
    backup.mkdir()
    (backup / "settings.json").write_text("{}")
    return types.SimpleNamespace(
        backup_dir=backup,
        resolve_account=lambda a: account,
        _account_kind=lambda n: kind,
    )


def _apply_recording(sw, *, returns=True, raises=None, seen=None):
    """`apply_pin` as the package has it: the record is written FIRST."""
    def apply_pin(switcher, email=None, org_uuid=None, identity=None):
        if seen is not None:
            seen.append({"email": email, "org": org_uuid, "identity": identity})
        _write_record(switcher.backup_dir, email, org_uuid)
        if raises:
            raise raises
        return returns
    return apply_pin


class TestNothingCallsBackIntoTheHost:
    def test_every_arm_stays_inside_the_package(self, host, tmp_path, monkeypatch,
                                                capsys):
        sw = _sw(tmp_path)
        sw._get_current_account = lambda: ("me@example.com", "org-login")
        _write_record(sw.backup_dir, "old@example.com", "org-old")
        monkeypatch.setattr(pin_proxy, "load_pin", lambda b: _record(b))
        monkeypatch.setattr(pin_proxy, "observed_bridge_owners",
                            lambda: {"cse_a": "org-stranger"})
        monkeypatch.setattr(pin_proxy, "live_remote_control_sessions", lambda: [])

        assert pin_proxy.pin_run(sw, None) == 0            # show + bridge warning
        assert "do not belong to it" in capsys.readouterr().out
        monkeypatch.setattr(pin_proxy, "apply_pin", _apply_recording(sw))
        assert pin_proxy.pin_run(sw, "2") == 0             # set
        monkeypatch.setattr(pin_proxy, "apply_pin",
                            _apply_recording(sw, returns=False))
        assert pin_proxy.pin_run(sw, "2") == 1             # failed set + rollback
        assert pin_proxy.repin_current(sw) is False        # apply_pin says no

    def test_control_the_guard_would_have_seen_a_callback(self, host):
        """A guard nothing has tripped is not yet a guard."""
        for name in FORBIDDEN:
            with pytest.raises(RuntimeError):
                getattr(host, name)()
        assert host.calls == list(FORBIDDEN)
        host.calls.clear()


class TestSetPinRefusesWhatItCannotPin:
    """The refusals are IN set_pin, not at its call sites.

    The TUI's row filter is a courtesy: an open submenu is never rebuilt, so a
    row that was OAuth when drawn can pin an API-key account when selected.
    """

    def test_refuses_an_api_key_account(self, host, tmp_path):
        sw = _sw(tmp_path, kind="api_key")
        ok, msg = pin_proxy.set_pin(sw, "key@example.com", "org")
        assert not ok, msg
        assert "API-key account" in msg, msg

    def test_a_duplicate_email_cannot_bypass_the_api_key_refusal(
            self, host, tmp_path, monkeypatch):
        """The slot is PASSED, not re-derived from the email.

        One address in two slots (cswap's own personal+org pattern) makes
        `resolve_account(email)` raise, and swallowing that skipped
        `_account_kind` entirely, accepting the account the refusal rejects.
        """
        applied = []
        sw = _sw(tmp_path, kind="api_key")

        def _resolve(a):
            raise RuntimeError("multiple accounts match dup@example.com")

        sw.resolve_account = _resolve
        monkeypatch.setattr(pin_proxy, "apply_pin",
                            lambda *a, **k: applied.append(a) or True)
        ok, msg = pin_proxy.set_pin(sw, "dup@example.com", "org", num="2")
        assert not ok, "a duplicate email got past the API-key refusal"
        # "API-key account" alone is in BOTH this refusal and the
        # resolve-failure message, so match the refusal's own words.
        assert "which the cloud pin cannot use" in msg, msg
        assert applied == [], "apply_pin ran for an API-key account"

    def test_an_unreadable_kind_refuses_rather_than_proceeding(
            self, host, tmp_path, monkeypatch):
        applied = []
        sw = _sw(tmp_path)

        def _boom(n):
            raise OSError("sequence.json is unreadable")

        sw._account_kind = _boom
        monkeypatch.setattr(pin_proxy, "apply_pin",
                            lambda *a, **k: applied.append(a) or True)
        ok, msg = pin_proxy.set_pin(sw, "who@example.com", "org", num="2")
        assert not ok, "pinned an account whose kind could not be read"
        assert "will not guess" in msg, msg
        assert applied == [], "apply_pin ran without knowing the kind"

    def test_pin_run_goes_through_set_pin_and_never_apply_pin(self):
        """The verdict has ONE implementation: the CLI arm delegates to
        `set_pin`, exactly as the TUI does, and does not re-derive it."""
        import ast
        import inspect
        import textwrap

        run = ast.parse(textwrap.dedent(inspect.getsource(pin_proxy.pin_run)))
        called = {n.func.id for n in ast.walk(run)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        attrs = {n.func.attr for n in ast.walk(run)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        assert "set_pin" in called, sorted(called)
        assert "apply_pin" not in called | attrs, (
            "pin_run calls apply_pin directly: the verdict is back in two places")


class TestTheRollbackVerdictIsNotFooledByShape:
    """The seam's reader and the package's writer must agree on shape.

    The host's reader returned the org uuid raw (None when the key is absent)
    while `save_pin` always writes `org_uuid or ""`, so a SUCCESSFUL rollback
    of a record with no org key compared unequal and reported itself a failure.
    """

    def test_a_record_with_no_org_key_rolls_back_cleanly(self, host, tmp_path,
                                                         monkeypatch):
        sw = _sw(tmp_path)
        # No org key at all: what an older writer or a hand-edit leaves.
        (sw.backup_dir / "settings.json").write_text(
            json.dumps({"remoteControl": {"pinnedEmail": "old@e.com"}}))
        n = [0]

        def apply_pin(switcher, email=None, org_uuid=None, identity=None):
            n[0] += 1
            _write_record(switcher.backup_dir, email, org_uuid)
            if n[0] == 1:                      # the set writes, then the proxy dies
                raise RuntimeError("pin-proxy")
            return True                        # the rollback lands

        monkeypatch.setattr(pin_proxy, "apply_pin", apply_pin)
        ok, msg = pin_proxy.set_pin(sw, "new@e.com", "org", num="2")

        assert not ok
        assert _record(sw.backup_dir)[0] == "old@e.com", "the rollback failed"
        assert "may still name" not in msg, (
            "a successful rollback was reported as a failure: the reader and "
            f"the writer disagree on shape: {msg}")
        assert "the previous pin is unchanged" in msg, msg

    def test_a_rollback_that_does_not_land_says_so(self, host, tmp_path,
                                                   monkeypatch):
        """The verdict comes from re-reading the file, not from having made
        the call: mutating `_restore_pin`'s last line to `return True` claims
        the old pin survived while the record still names the new one."""
        sw = _sw(tmp_path)
        _write_record(sw.backup_dir, "old@e.com", "org")
        n = [0]

        def apply_pin(switcher, email=None, org_uuid=None, identity=None):
            n[0] += 1
            if n[0] == 1:
                _write_record(switcher.backup_dir, email, org_uuid)
                raise RuntimeError("proxy exploded")
            raise RuntimeError("rollback could not reach the proxy either")

        monkeypatch.setattr(pin_proxy, "apply_pin", apply_pin)
        ok, msg = pin_proxy.set_pin(sw, "new@e.com", "org", num="2")

        assert not ok
        assert _record(sw.backup_dir)[0] == "new@e.com", (
            "fixture invalid: the rollback attempt actually wrote the file")
        assert "the previous pin is unchanged" not in msg, msg
        assert "may still name new@e.com" in msg, msg

    def test_the_failure_message_is_scrubbed_through_the_hosts_safe(
            self, host, tmp_path, monkeypatch):
        """Userinfo in a proxy URL must not reach the screen."""
        sw = _sw(tmp_path)
        monkeypatch.setattr(pin_proxy, "apply_pin", _apply_recording(
            sw, raises=RuntimeError("GET http://svc:s3cr3t@127.0.0.1:9901/x failed")))
        ok, msg = pin_proxy.set_pin(sw, "new@e.com", "org", num="2")
        assert not ok and msg.startswith("Could not pin the cloud account: "), msg
        assert "s3cr3t" not in msg and "***@127.0.0.1" in msg, msg


class TestConfigAlreadyNames:
    """`_config_already_names` reads `emailAddress` with the same casefold.

    It is on the SET path, and its raise is swallowed by `_restore_pin`'s
    blanket `except`, which is the harm: `_restore_pin` returns False and the
    rollback tail sends the user to check a record the code just cleared.
    """

    def _config(self, oauth):
        cfg = pin_proxy.require("paths").get_global_config_path()
        cfg.write_text(json.dumps({"oauthAccount": oauth}))

    def test_neither_side_of_the_compare_raises(self, host):
        for bad in (42, ["a@example.com"], {"x": 1}, True):
            self._config({"emailAddress": bad, "organizationUuid": ""})
            assert pin_proxy._config_already_names(
                {"emailAddress": "me@example.com", "organizationUuid": ""}) is False, (
                f"config emailAddress={bad!r} raised in the rollback verdict")
            self._config({"emailAddress": "me@example.com", "organizationUuid": ""})
            assert pin_proxy._config_already_names(
                {"emailAddress": bad, "organizationUuid": ""}) is False, (
                f"identity emailAddress={bad!r} raised")

    def test_the_accountuuid_decides_before_the_blanked_composite(self, host):
        """`identity_for_config` returns a stored config VERBATIM, so the
        identity can carry a non-string address; the composite then blanks and
        declines about a config carrying that identity byte for byte."""
        self._config({"emailAddress": 42, "accountUuid": "UUID-9",
                      "organizationUuid": "org-A"})
        assert pin_proxy._config_already_names(
            {"emailAddress": 42, "accountUuid": "UUID-9",
             "organizationUuid": "org-A"}) is True

    @pytest.mark.parametrize("oauth", [
        {"emailAddress": "cloud@example.com", "accountUuid": "",
         "organizationUuid": ""},
        {"emailAddress": "cloud@example.com", "organizationUuid": ""},
    ])
    def test_a_config_with_no_accountuuid_falls_back_to_the_composite(
            self, host, oauth):
        """The strong key decides only when the CONFIG has one too: `cswap add
        --token` writes a stored config with a blank `accountUuid`."""
        self._config(oauth)
        assert pin_proxy._config_already_names(
            {"emailAddress": "cloud@example.com", "organizationUuid": "",
             "accountUuid": "acct-U"}) is True

    def test_an_identity_with_no_uuid_lets_the_composite_decide(self, host):
        self._config({"emailAddress": "cloud@example.com",
                      "accountUuid": "UUID-LIVE", "organizationUuid": "org-A"})
        assert pin_proxy._config_already_names(
            {"emailAddress": "cloud@example.com",
             "organizationUuid": "org-A"}) is True

    def test_control_a_different_accountuuid_is_still_refused(self, host):
        """Without this, `return True` whenever a uuid is present kills no test."""
        self._config({"emailAddress": "me@example.com",
                      "accountUuid": "UUID-OTHER"})
        assert pin_proxy._config_already_names(
            {"emailAddress": "me@example.com", "accountUuid": "UUID-9"}) is False

    def test_control_a_matching_pair_still_answers_true(self, host):
        """Without this, a constant False satisfies every case above."""
        self._config({"emailAddress": "Me@Example.com",
                      "organizationUuid": "org-A"})
        assert pin_proxy._config_already_names(
            {"emailAddress": "me@example.com", "organizationUuid": "org-A"}) is True

    def test_a_blank_identity_address_cannot_exempt(self, host):
        """Two unreadable addresses are not a match. A NON-BLANK org on both
        sides, so a guard written on the org cannot satisfy this."""
        self._config({"emailAddress": 42, "organizationUuid": "org-A"})
        assert pin_proxy._config_already_names(
            {"emailAddress": 42, "organizationUuid": "org-A"}) is False


class TestASetThatFailsIsNotReportedAsSuccess:
    """`cswap pin NUM` must not report a pin that is not in effect.

    apply_pin writes the record BEFORE it starts the proxy, so both failures
    leave a pin that `cswap pin` and the TUI badge would report as live while
    nothing serves it.
    """

    def test_a_raising_apply_pin_is_not_a_traceback(self, host, tmp_path,
                                                    monkeypatch, capsys):
        sw = _sw(tmp_path)
        monkeypatch.setattr(pin_proxy, "apply_pin", _apply_recording(
            sw, raises=FileExistsError("pin-proxy")))
        rc = pin_proxy.pin_run(sw, "2")
        out = capsys.readouterr().out
        assert "Pinned" not in out, "reported a pin that did not happen"
        assert "Could not pin" in out, out
        assert rc == 1

    def test_no_proxy_serving_is_not_unqualified_success(self, host, tmp_path,
                                                         monkeypatch, capsys):
        sw = _sw(tmp_path)
        monkeypatch.setattr(pin_proxy, "apply_pin",
                            _apply_recording(sw, returns=False))
        rc = pin_proxy.pin_run(sw, "2")
        out = capsys.readouterr().out
        assert "nothing is pinned yet" in out, out
        assert "the daemon log says why: <backup>/pin-proxy/daemon.log" in out, out
        assert rc == 1, "a pin nothing serves must not exit 0"

    def test_no_proxy_serving_ROLLS_BACK_the_record(self, host, tmp_path,
                                                    monkeypatch):
        """`started == False` must undo the record, like the raise path does.

        Leaving it made `cswap pin 2` say "nothing is pinned yet" and exit 1
        while `cswap pin` then printed the address and exited 0. The stub
        writes the record for real: one that only returns False cannot show it.
        """
        sw = _sw(tmp_path)
        monkeypatch.setattr(pin_proxy, "apply_pin",
                            _apply_recording(sw, returns=False))
        assert pin_proxy.pin_run(sw, "2") == 1
        assert _record(sw.backup_dir) is None, (
            "the failed pin left a record the badge and `cswap pin` both read "
            "as live")


class TestSetPinNamesTheAccountItIsPinning:
    """`set_pin` handed `apply_pin` the identity of the PREVIOUS pin.

    `identity_for_config(switcher)` with no email resolves what the RECORD
    says, and Python evaluates that argument before `apply_pin` writes it:
    first pin ever gave None (no splice at all), a re-pin A -> B gave A's.
    The stand-in answers exactly that way when it is NOT told the email.
    """

    def _wire(self, host, monkeypatch, tmp_path, record):
        sw = _sw(tmp_path)
        seen = []

        def identity_for_config(switcher, email=None, num=None):
            who = email or (host._pinned_email_now(switcher) or (None,))[0]
            return {"emailAddress": who, "accountUuid": f"UUID-{who}"} if who else None

        host.identity_for_config = identity_for_config
        if record:
            _write_record(sw.backup_dir, *record)
        monkeypatch.setattr(pin_proxy, "apply_pin",
                            _apply_recording(sw, seen=seen))
        return sw, seen

    def test_the_first_pin_ever_still_names_itself(self, host, tmp_path,
                                                   monkeypatch):
        sw, seen = self._wire(host, monkeypatch, tmp_path, None)
        ok, _msg = pin_proxy.set_pin(sw, "a@example.com", "org-A", num="1")
        assert ok
        assert seen[0]["identity"] == {"emailAddress": "a@example.com",
                                       "accountUuid": "UUID-a@example.com"}, (
            "the first pin handed identity=None, so nothing spliced")

    def test_a_re_pin_names_the_new_account_not_the_old(self, host, tmp_path,
                                                        monkeypatch):
        sw, seen = self._wire(host, monkeypatch, tmp_path,
                              ("a@example.com", "org-A"))
        ok, _msg = pin_proxy.set_pin(sw, "b@example.com", "org-B", num="2")
        assert ok
        assert seen[-1]["identity"] == {"emailAddress": "b@example.com",
                                        "accountUuid": "UUID-b@example.com"}, (
            "re-pinning to B wrote A into the config")


class TestARolledBackPinDoesNotLeaveItsNameBehind:
    """A FAILED pin had already rewritten the live config.

    `apply_pin` splices `~/.claude.json` and THEN starts the proxy, so by the
    time it returns False the new account is already named there, and
    `_restore_pin` put the RECORD back and left the config alone.
    """

    def _impl(self, monkeypatch, tmp_path, spliced, *, splice_raises=None):
        sw = _sw(tmp_path)

        def apply_pin(switcher, email=None, org_uuid=None, identity=None):
            _write_record(switcher.backup_dir, email, org_uuid)
            return True

        def splice(identity):
            spliced.append(identity)
            if splice_raises:
                raise splice_raises
            return True

        monkeypatch.setattr(pin_proxy, "apply_pin", apply_pin)
        monkeypatch.setattr(pin_proxy, "splice_config_identity", splice)
        return sw

    def test_the_config_goes_back_to_the_pin_that_is_restored(
            self, host, tmp_path, monkeypatch):
        spliced = []
        sw = self._impl(monkeypatch, tmp_path, spliced)
        host.identity_for_config = lambda s, email=None, num=None: {
            "emailAddress": email, "accountUuid": "OLD-UUID"}

        assert pin_proxy._restore_pin(sw, ("old@example.com", "org-OLD"))
        assert spliced == [{"emailAddress": "old@example.com",
                            "accountUuid": "OLD-UUID"}], (
            "the rollback restored the record and left `~/.claude.json` "
            "naming the account whose pin had just failed")

    def test_a_splice_that_fails_does_not_change_the_verdict(
            self, host, tmp_path, monkeypatch):
        """The verdict is the RECORD re-read. Naming the pin in the config is
        best-effort: a config that cannot be written is a worse pin, not a
        failed one."""
        spliced = []
        sw = self._impl(monkeypatch, tmp_path, spliced,
                        splice_raises=OSError("read-only home"))
        host.identity_for_config = lambda s, email=None, num=None: {
            "emailAddress": "x"}

        assert pin_proxy._restore_pin(sw, ("old@example.com", "org-OLD"))
        assert spliced, "the splice was never reached"


class TestARollbackWithNothingToRestoreStillClearsTheName:
    """The FIRST pin on a machine, failing, was the case with no owner.

    `apply_pin(None, None)` CLEARS the record, and a lookup made afterwards has
    nothing to un-splice against, so it answers the account whose pin just
    failed. `_restore_pin` must ask for the live login BEFORE that call. The
    stand-in answers wrongly once the record is gone, as the host's does.
    """

    def _wire(self, host, monkeypatch, tmp_path, *, live):
        sw = _sw(tmp_path)
        _write_record(sw.backup_dir, "failed@example.com", "org-F")
        spliced = []

        def apply_pin(switcher, email=None, org_uuid=None, identity=None):
            _write_record(switcher.backup_dir, email, org_uuid)
            return True

        def live_login(switcher):
            if _record(switcher.backup_dir) is None:
                return {"emailAddress": "failed@example.com"}    # the wrong answer
            return live

        host._live_login_for_config = live_login
        monkeypatch.setattr(pin_proxy, "apply_pin", apply_pin)
        monkeypatch.setattr(pin_proxy, "splice_config_identity",
                            lambda identity: spliced.append(identity) or True)
        return sw, spliced

    def test_a_failed_first_pin_hands_the_config_to_the_live_login(
            self, host, tmp_path, monkeypatch):
        serving = {"emailAddress": "serving@example.com", "accountUuid": "UUID-3"}
        sw, spliced = self._wire(host, monkeypatch, tmp_path, live=serving)

        assert pin_proxy._restore_pin(sw, None) is True
        assert spliced == [serving], (
            "the rollback left `~/.claude.json` naming the account whose pin "
            f"just failed: {spliced!r}")

    def test_no_live_login_leaves_the_field_alone(self, host, tmp_path,
                                                  monkeypatch):
        """None is not an erasure: with nothing logged in there is no correct
        owner to write, and a blank one is worse than a stale one."""
        sw, spliced = self._wire(host, monkeypatch, tmp_path, live=None)

        assert pin_proxy._restore_pin(sw, None) is True
        assert spliced == [None]


class TestTheRepairPinsTheIDENTITYToo:
    """`repin_current` is the ONLY re-pin that runs without a person, and it
    was the only one that did not name the pin in the live config: without
    `identity=` the splice returns early, so the repair restored a serving
    daemon while `~/.claude.json` named whichever account was active."""

    def _wire(self, monkeypatch, calls, pin=("pinned@example.com", "org-1")):
        monkeypatch.setattr(pin_proxy, "load_pin", lambda backup: pin)
        monkeypatch.setattr(
            pin_proxy, "apply_pin",
            lambda sw, email, org, identity=None: calls.append(
                {"email": email, "org": org, "identity": identity}) or True)

    def test_the_repair_carries_the_identity(self, host, monkeypatch):
        calls = []
        self._wire(monkeypatch, calls)
        ident = {"accountUuid": "PIN-UUID", "emailAddress": "pinned@example.com"}
        host.identity_for_config = lambda s, **_k: ident

        assert pin_proxy.repin_current(types.SimpleNamespace(backup_dir="/x")) is True
        assert calls, "apply_pin was never reached: the test proves nothing"
        assert calls[0]["identity"] == ident, (
            "the unattended repair re-pinned without naming the pin in "
            "`~/.claude.json`")

    def test_an_unresolvable_identity_still_repairs(self, host, monkeypatch):
        """None is not a reason to refuse: a serving daemon beats a stopped
        one, and `set_pin` takes the same direction."""
        calls = []
        self._wire(monkeypatch, calls)
        host.identity_for_config = lambda s, **_k: None

        assert pin_proxy.repin_current(types.SimpleNamespace(backup_dir="/x")) is True
        assert calls[0]["identity"] is None

    def test_a_lookup_that_raises_does_not_take_the_repair_down(
            self, host, monkeypatch):
        """`repin_current` promises False, never an exception: its callers are
        a menu render and a background watcher."""
        calls = []
        self._wire(monkeypatch, calls)

        def _boom(_s, **_k):
            raise RuntimeError("the backup store is unreadable")

        host.identity_for_config = _boom
        assert pin_proxy.repin_current(types.SimpleNamespace(backup_dir="/x")) is False

    def test_nothing_pinned_is_nothing_to_repair(self, host, monkeypatch):
        calls = []
        self._wire(monkeypatch, calls, pin=None)
        assert pin_proxy.repin_current(types.SimpleNamespace(backup_dir="/x")) is False
        assert calls == []

    @pytest.mark.parametrize("org, slot", [("org-A", "1"), ("org-B", "2")])
    def test_the_org_picks_between_two_slots_at_one_address(
            self, host, monkeypatch, org, slot):
        """One address in two slots (personal + org): the repair hands the
        lookup the SLOT for the composite, never the bare address, which the
        host cannot resolve and answers None for -- so the splice silently did
        nothing on exactly the roster the composite exists for."""
        calls = []
        self._wire(monkeypatch, calls, pin=("shared@example.com", org))
        slots = {("shared@example.com", "org-A"): "1",
                 ("shared@example.com", "org-B"): "2"}
        host._slot_for = lambda s, email, o: slots.get((email, o))
        host.identity_for_config = lambda s, email=None, num=None: (
            {"accountUuid": f"UUID-{num}"} if num else None)

        assert pin_proxy.repin_current(types.SimpleNamespace(backup_dir="/x")) is True
        assert calls[0]["identity"] == {"accountUuid": f"UUID-{slot}"}, calls


class TestANoteMustNotFailTheAction:
    """`cswap pin`'s show and set arms end in advice, after the pin was applied
    and "Pinned..." printed. A raise from a peer on its own release schedule
    turned a SUCCEEDED pin into an error telling the user to run `--clear`."""

    def _wire(self, monkeypatch, sw, *, sessions=(), owners=None, load_raises=False):
        def load_pin(backup):
            if load_raises:
                raise ValueError("settings.json is not valid JSON")
            return _record(backup)

        def live_sessions():
            if isinstance(sessions, Exception):
                raise sessions
            return list(sessions)

        monkeypatch.setattr(pin_proxy, "load_pin", load_pin)
        monkeypatch.setattr(pin_proxy, "apply_pin", _apply_recording(sw))
        monkeypatch.setattr(pin_proxy, "live_remote_control_sessions", live_sessions)
        monkeypatch.setattr(pin_proxy, "observed_bridge_owners",
                            owners or (lambda: {}))

    def test_a_note_that_raises_does_not_fail_a_pin_that_worked(
            self, host, tmp_path, monkeypatch, capsys):
        sw = _sw(tmp_path)
        self._wire(monkeypatch, sw, sessions=RuntimeError(
            "GET http://svc:s3cr3t@127.0.0.1:9901/sessions failed"))
        rc = pin_proxy.pin_run(sw, "2")
        out = capsys.readouterr().out
        assert rc == 0, f"a pin that succeeded returned a failure code: {out}"
        assert "[accent:Pinned] the cloud account (RC/artifacts) to " \
               "Account-2 (user2@example.com)" in out, out
        assert _record(sw.backup_dir) == ("user2@example.com", ""), (
            "the pin is on disk: reporting failure invites --clear")

    def test_open_remote_control_sessions_are_named(self, host, tmp_path,
                                                    monkeypatch, capsys):
        sw = _sw(tmp_path)
        self._wire(monkeypatch, sw, sessions=["a", "b", "c", "d", "e"])
        assert pin_proxy.pin_run(sw, "2") == 0
        assert ("[dim:Remote Control is open on: a, b, c, +2 more. Those stay on "
                "the previous account until you reconnect them "
                "(/rc -> Disconnect this session -> /rc).]"
                ) in capsys.readouterr().out

    def test_a_pin_with_no_open_session_says_new_sessions_pick_it_up(
            self, host, tmp_path, monkeypatch, capsys):
        sw = _sw(tmp_path)
        self._wire(monkeypatch, sw)
        assert pin_proxy.pin_run(sw, "2") == 0
        assert "[dim:New sessions pick this up.]" in capsys.readouterr().out

    def test_an_unreadable_pin_file_is_no_pin_not_a_broken_package(
            self, host, tmp_path, monkeypatch, capsys):
        """The read-only arm. The TUI badge answers None in this exact state."""
        sw = _sw(tmp_path)
        self._wire(monkeypatch, sw, load_raises=True)
        rc = pin_proxy.pin_run(sw, None)
        assert rc == 0, "a malformed pin file made a read-only command fail"
        assert "[dim:No cloud account pinned]" in capsys.readouterr().out

    def test_a_reader_that_raises_still_reports(self, host, tmp_path,
                                                monkeypatch, capsys):
        """The exact shape that once turned a working pin into `Error: ... not
        usable`: the bridge reader is a peer feature on its own release
        schedule, and losing its line must not lose the command."""
        sw = _sw(tmp_path)
        _write_record(sw.backup_dir, "pinned@example.com", "org-1")

        def _boom():
            raise AttributeError("no observed_bridge_owners in this release")

        self._wire(monkeypatch, sw, owners=_boom)
        rc = pin_proxy.pin_run(sw, None)
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "Cloud account (RC/artifacts): pinned@example.com" in out, out


class TestTheStatusLineNamesABridgeThePinDoesNotOwn:
    """REPORTING THE PIN IS NOT REPORTING THE STATE.

    `Cloud account (RC/artifacts): ...` prints what this code WROTE. Measured
    with three accounts at once: 13 live bridges, none on the pinned org, and
    the line said "pinned" throughout, until the server answered
    `API Error: 500` on a reattach. The comparison is against the LITERAL
    config identity, which is what Claude Code compares a recorded owner to.
    """

    def _show(self, tmp_path, monkeypatch, capsys, *, owners, login, roster=None):
        sw = _sw(tmp_path)
        _write_record(sw.backup_dir, "pinned@example.com", "org-pin")
        sw._get_current_account = lambda: login
        if roster:
            sw.current_account_number = lambda: "2"
            sw._get_sequence_data_migrated = lambda: {"accounts": {"2": roster}}
        monkeypatch.setattr(pin_proxy, "load_pin", lambda b: _record(b))
        monkeypatch.setattr(pin_proxy, "observed_bridge_owners", lambda: owners)
        assert pin_proxy.pin_run(sw, None) == 0
        return capsys.readouterr().out

    def test_the_status_line_names_a_bridge_the_pin_does_not_own(
            self, host, tmp_path, monkeypatch, capsys):
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": "org-2"},
                         login=("pinned@example.com", "org-pin"))
        assert "Cloud account (RC/artifacts): pinned@example.com" in out, out
        assert "[warn:the live Remote Control bridges do not belong to it: " \
               "1 other organization(s) — org-2." in out, out

    def test_the_status_line_stays_quiet_when_the_bridges_agree(
            self, host, tmp_path, monkeypatch, capsys):
        """THE CONTROL: without it, "warns on a mismatch" also passes on a
        version that warns unconditionally. Asserted on the warning's own
        words, since with nothing to disagree with it would render "0 other
        organization(s)" and carry no org id at all."""
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": "org-pin"},
                         login=("pinned@example.com", "org-pin"))
        assert "Cloud account (RC/artifacts): pinned@example.com" in out, out
        assert "do not belong to it" not in out, out

    def test_a_carried_pointer_is_not_reported_as_foreign_ownership(
            self, host, tmp_path, monkeypatch, capsys):
        """`bridgeOwnerAccountUuid` HAS TWO WRITERS THAT MEAN OPPOSITE THINGS:
        Claude Code writes the true owner, and the live carry writes the
        account now signed in so CC REATTACHES instead of minting. CC compares
        the pointer to the LOGIN, never to the pin, so a recorded owner that
        agrees with the login while the pin differs is nothing to warn about."""
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": "org-login"},
                         login=("login@example.com", "org-login"))
        assert "do not belong to it" not in out, out

    def test_a_pointer_that_disagrees_with_the_LOGIN_is_still_reported(
            self, host, tmp_path, monkeypatch, capsys):
        """CONTROL for the case above: a bridge whose owner differs from the
        LOGIN is one CC mints over, and the session loses its history."""
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": "org-stranger"},
                         login=("login@example.com", "org-login"))
        assert "do not belong to it" in out, out

    ROSTER = {"email": "login@example.com", "organizationUuid": "org-login"}

    def test_the_pin_phase_does_not_manufacture_a_disagreement(
            self, host, tmp_path, monkeypatch, capsys):
        """`oauthAccount` swings between the pin and the active login, so a
        sentence decided by its phase is decided by WHEN the command ran. In
        the PIN phase, bridges owned by the roster's ACTIVE slot (the steady
        state under a working carry) are not a disagreement."""
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": "org-login"},
                         login=("pinned@example.com", "org-pin"),
                         roster=self.ROSTER)
        assert "do not belong to it" not in out, out

    def test_CONTROL_a_stranger_org_still_warns_in_that_same_phase(
            self, host, tmp_path, monkeypatch, capsys):
        """The measured incident: bridges on an org that is NEITHER the pin nor
        the active login. Widening past this point would make the row unable
        to fail."""
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": "org-stranger"},
                         login=("pinned@example.com", "org-pin"),
                         roster=self.ROSTER)
        assert "do not belong to it" in out, out

    def test_an_unrecorded_owner_is_unknown_not_a_disagreement(
            self, host, tmp_path, monkeypatch, capsys):
        out = self._show(tmp_path, monkeypatch, capsys,
                         owners={"cse_a": None},
                         login=("login@example.com", "org-login"))
        assert "do not belong to it" not in out, out
