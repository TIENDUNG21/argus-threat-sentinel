import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from argus.ingest.tail import Follower


class Script:
    """Runs one scripted file change per poll, then asks the follower to stop."""

    def __init__(self, *actions: Callable[[], None]) -> None:
        self.actions = list(actions)
        self.done = False
        self.polls = 0

    def sleep(self, _seconds: float) -> None:
        self.polls += 1
        if self.actions:
            self.actions.pop(0)()
        else:
            self.done = True

    def stop(self) -> bool:
        return self.done


def append(path: Path, text: str) -> Callable[[], None]:
    def run() -> None:
        with path.open("ab") as handle:
            handle.write(text.encode())

    return run


def collect(follower: Follower, script: Script) -> list[str]:
    return [text for text, _ in follower.lines(script.stop)]


def test_starts_at_end_and_yields_appended_lines(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_bytes(b"old line\n")
    script = Script(append(log, "a\n"), append(log, "b\r\nc\n"))
    assert collect(Follower(log, sleep=script.sleep), script) == ["a", "b", "c"]


def test_from_start_reads_existing_content(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_bytes(b"one\ntwo\n")
    script = Script()
    assert collect(Follower(log, from_start=True, sleep=script.sleep), script) == ["one", "two"]


def test_partial_line_is_buffered_until_newline(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_bytes(b"")
    script = Script(append(log, "par"), append(log, "tial\nnext"), append(log, "\n"))
    assert collect(Follower(log, sleep=script.sleep), script) == ["partial", "next"]


def test_truncation_restarts_from_the_beginning(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_bytes(b"x\n" * 5)

    def truncate() -> None:
        log.write_bytes(b"new\n")

    script = Script(truncate)
    lines = collect(Follower(log, from_start=True, sleep=script.sleep), script)
    assert lines == ["x"] * 5 + ["new"]


def test_waits_for_missing_file(tmp_path: Path) -> None:
    log = tmp_path / "later.log"

    def create() -> None:
        log.write_bytes(b"hello\n")

    script = Script(lambda: None, create)
    assert collect(Follower(log, sleep=script.sleep), script) == ["hello"]


def test_overlong_line_is_flagged(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_bytes(b"")
    script = Script(append(log, "A" * 5000 + "\nok\n"))
    result = list(Follower(log, sleep=script.sleep, max_line=1000).lines(script.stop))
    assert [flag for _, flag in result] == [True, False]
    assert result[1][0] == "ok"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows cannot rename an open file")
def test_follows_rotation_and_drains_the_old_file(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_bytes(b"")
    rotated = tmp_path / "access.log.1"

    def rotate() -> None:
        log.rename(rotated)
        append(rotated, "late\n")()
        log.write_bytes(b"fresh\n")

    script = Script(append(log, "before\n"), rotate)
    assert collect(Follower(log, sleep=script.sleep), script) == ["before", "late", "fresh"]
