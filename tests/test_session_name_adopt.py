"""A rename reaches the transcript and the server, never the session record.

`adopt_renamed_sessions` carries it the last hop. The record is what every
local reader uses — the peer list, `@`-completion, and the proxy's own title
restore — so a name left at its launch value is a name nobody uses.
"""

from __future__ import annotations

import json
import os

from conftest import run_cases


def _title(t, sid="s"):
    return json.dumps({"type": "custom-title", "customTitle": t, "sessionId": sid})


def _plant(home, *, source, name="proj-a3", titles=(), sid="s", pad=0):
    """A LIVE record, and the transcript its `sessionId` names.

    `pid` is this process because the adopt filters on a live pid: a record
    without one is invisible, and a case would pass for the wrong reason.
    """
    d = home / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    rec = {"pid": os.getpid(), "sessionId": sid, "name": name}
    if source is not None:
        rec["nameSource"] = source
    path = d / f"{os.getpid()}.json"
    path.write_text(json.dumps(rec), encoding="utf-8")

    p = home / "projects" / "-a-project"
    p.mkdir(parents=True, exist_ok=True)
    lines = []
    for i, t in enumerate(titles):
        lines.append(_title(t, sid))
        if pad and i == 0:
            lines.append(json.dumps({"type": "user", "pad": "x" * pad}))
    (p / f"{sid}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class TestAdoptRenamedSessions:
    def test_all(self, request, tmp_path_factory):
        run_cases(self, request, tmp_path_factory)

    def case_an_invented_name_takes_the_transcripts_title(self, tmp_path):
        from cswap_pin.proxy import adopt_renamed_sessions

        home = tmp_path / "claude-home"
        path = _plant(home, source="derived", titles=("a-name-somebody-typed",))
        assert adopt_renamed_sessions() == 1
        rec = json.loads(path.read_text())
        assert rec["name"] == "a-name-somebody-typed"
        # `user`, or the pin's own restore keeps refusing to push it up and
        # the next launch-time derivation overwrites it again.
        assert rec["nameSource"] == "user"

    def case_CONTROL_a_typed_name_is_left_alone(self, tmp_path):
        from cswap_pin.proxy import adopt_renamed_sessions

        home = tmp_path / "claude-home"
        path = _plant(home, source="user", titles=("something-else",))
        assert adopt_renamed_sessions() == 0
        assert json.loads(path.read_text())["name"] == "proj-a3"

    def case_CONTROL_an_absent_source_is_left_alone(self, tmp_path):
        """Absent counts as chosen, the same reading `invented_bridge_names`
        takes — most live records carry no source at all."""
        from cswap_pin.proxy import adopt_renamed_sessions

        home = tmp_path / "claude-home"
        path = _plant(home, source=None, titles=("something-else",))
        assert adopt_renamed_sessions() == 0
        assert json.loads(path.read_text())["name"] == "proj-a3"

    def case_CONTROL_no_rename_leaves_the_record_untouched(self, tmp_path):
        """THE DENOMINATOR. Without it the first case passes for a function
        that writes whatever it finds, rename or not."""
        from cswap_pin.proxy import adopt_renamed_sessions

        home = tmp_path / "claude-home"
        path = _plant(home, source="derived", titles=())
        before = path.read_text()
        assert adopt_renamed_sessions() == 0
        assert path.read_text() == before

    def case_the_NEWEST_title_wins_inside_ONE_chunk(self, tmp_path):
        """Two renames in the same 64 KiB read, so the walk's DIRECTION inside
        a chunk is what decides. With them in different chunks the case passes
        either way round — measured: a forward walk survived that version.
        """
        from cswap_pin.proxy import _last_custom_title

        tx = tmp_path / "t.jsonl"
        tx.write_text("\n".join([
            json.dumps({"type": "user", "pad": "x" * 200_000}),
            _title("older"), _title("newest")]) + "\n", encoding="utf-8")
        assert _last_custom_title(tx) == "newest"

    def case_a_title_STRADDLING_a_chunk_edge_is_still_read(self, tmp_path):
        """The partial first line of a chunk is carried into the next read.
        Dropping it instead loses exactly the rename that happens to sit on
        the boundary."""
        from cswap_pin.proxy import _last_custom_title

        tx = tmp_path / "t.jsonl"
        title = _title("a-name-somebody-typed")
        # The 64 KiB boundary from EOF falls INSIDE the title line: it needs
        # both reads to be parsed at all.
        trail = json.dumps({"type": "user", "pad": "y" * ((1 << 16) - 40)})
        tx.write_text("\n".join([
            json.dumps({"type": "user", "pad": "x" * 200_000}),
            title, trail]) + "\n", encoding="utf-8")
        assert len(trail) + 1 < (1 << 16) < len(trail) + 1 + len(title)
        assert _last_custom_title(tx) == "a-name-somebody-typed"

    def case_a_title_MANY_chunks_back_is_still_found(self, tmp_path):
        """The walk must reach the START. A rename early in a long session is
        the measured case — line 17 of a file that kept growing."""
        from cswap_pin.proxy import _last_custom_title

        home = tmp_path / "claude-home"
        _plant(home, source="derived", titles=("a-name-somebody-typed",), pad=400_000)
        tx = home / "projects" / "-a-project" / "s.jsonl"
        assert tx.stat().st_size > 6 * (1 << 16)
        assert _last_custom_title(tx) == "a-name-somebody-typed"
