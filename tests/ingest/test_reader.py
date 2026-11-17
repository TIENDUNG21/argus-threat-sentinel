import gzip
from pathlib import Path

import pytest

from argus.ingest.reader import detect_format, make_line_parser, read_events

GOOD = (
    '198.18.0.{n} - - [02/Mar/2026:10:00:0{n} +0000] "GET /p{n} HTTP/1.1" 200 12 "-" "Mozilla/5.0"'
)
AUTH = (
    "2026-03-02T10:00:0{n}+00:00 web01 sshd[1]: Failed password for root from 198.18.1.{n} port 22"
)


def write(path: Path, lines: list[str], newline: str = "\n") -> Path:
    path.write_bytes(newline.join(lines).encode() + newline.encode())
    return path


def test_counts_parsed_ignored_and_malformed(tmp_path: Path) -> None:
    lines = [
        GOOD.format(n=1),
        "",
        "total garbage",
        GOOD.format(n=2),
        "1.2.3.4 - - [x] y",
        GOOD.format(n=3),
    ]
    events, stats = read_events(write(tmp_path / "access.log", lines))
    assert [e.path for e in events] == ["/p1", "/p2", "/p3"]
    assert [e.line for e in events] == [1, 4, 6]
    assert (stats.total_lines, stats.parsed, stats.ignored, stats.malformed) == (6, 3, 1, 2)
    assert stats.reasons == {"not combined log format": 2}
    assert [(s.line, s.reason) for s in stats.samples] == [
        (3, "not combined log format"),
        (5, "not combined log format"),
    ]
    assert stats.samples[0].file.endswith("access.log")


def test_auth_log_cron_lines_are_ignored(tmp_path: Path) -> None:
    cron = "2026-03-02T10:17:01+00:00 web01 CRON[9]: pam_unix(cron:session): session opened"
    events, stats = read_events(write(tmp_path / "auth.log", [AUTH.format(n=1), cron]))
    assert len(events) == 1
    assert events[0].action == "failed_password"
    assert (stats.parsed, stats.ignored, stats.malformed) == (1, 1, 0)


def test_overlong_line_is_counted_and_skipped(tmp_path: Path) -> None:
    lines = [GOOD.format(n=1), "A" * 1_000_000, GOOD.format(n=2)]
    events, stats = read_events(write(tmp_path / "a.log", lines), max_line=4096)
    assert [e.line for e in events] == [1, 3]
    assert stats.reasons == {"line too long": 1}
    assert stats.samples[0].snippet.startswith("AAAA")
    assert len(stats.samples[0].snippet) <= 200


def test_crlf_line_endings(tmp_path: Path) -> None:
    events, stats = read_events(write(tmp_path / "a.log", [GOOD.format(n=1)] * 3, "\r\n"))
    assert len(events) == 3
    assert events[0].user_agent == "Mozilla/5.0"
    assert stats.malformed == 0


def test_nul_bytes_and_invalid_utf8_never_crash(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    good = GOOD.format(n=1).encode()
    path.write_bytes(
        b"\x00\x00\x00\n" + good.replace(b"Mozilla/5.0", b"Moz\xff\xfe") + b"\n" + good + b"\n"
    )
    events, stats = read_events(path)
    assert len(events) == 2
    assert "�" in events[0].user_agent
    assert stats.malformed == 1


def test_empty_file_has_no_events_and_no_error(tmp_path: Path) -> None:
    path = tmp_path / "empty.log"
    path.write_bytes(b"")
    events, stats = read_events(path)
    assert events == []
    assert stats.errors == []


def test_undetectable_format_is_reported_not_raised(tmp_path: Path) -> None:
    events, stats = read_events(write(tmp_path / "x.log", ["hello", "world"]))
    assert events == []
    assert stats.errors and "could not detect" in stats.errors[0]


def test_missing_file_is_reported(tmp_path: Path) -> None:
    events, stats = read_events(tmp_path / "nope.log")
    assert events == []
    assert stats.errors == [f"{tmp_path / 'nope.log'}: file not found"]


def test_gzip_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    path.write_bytes(gzip.compress(("\n".join(GOOD.format(n=i) for i in range(5)) + "\n").encode()))
    events, stats = read_events(path)
    assert len(events) == 5
    assert stats.errors == []


def test_truncated_gzip_keeps_events_and_records_error(tmp_path: Path) -> None:
    body = "\n".join(GOOD.format(n=i % 10) + f" #{i}" for i in range(3000)) + "\n"
    blob = gzip.compress(body.encode())
    path = tmp_path / "access.log.gz"
    path.write_bytes(blob[: len(blob) // 2])
    events, stats = read_events(path)
    assert 0 < len(events) < 3000
    assert len(stats.errors) == 1


def test_forced_wrong_format_marks_lines_malformed(tmp_path: Path) -> None:
    events, stats = read_events(write(tmp_path / "a.log", [GOOD.format(n=1)]), fmt="sshd")
    assert events == []
    assert stats.malformed == 1


def test_detect_format(tmp_path: Path) -> None:
    assert detect_format(write(tmp_path / "w.log", [GOOD.format(n=1)])) == "combined"
    assert detect_format(write(tmp_path / "s.log", [AUTH.format(n=1)])) == "sshd"
    assert detect_format(write(tmp_path / "x.log", ["nope"])) is None


def test_unknown_format_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown log format"):
        make_line_parser("json")


def test_stats_merge(tmp_path: Path) -> None:
    _, a = read_events(write(tmp_path / "a.log", [GOOD.format(n=1), "bad"]))
    _, b = read_events(write(tmp_path / "b.log", [GOOD.format(n=2), "bad", "bad"]))
    a.merge(b)
    assert (a.total_lines, a.parsed, a.malformed) == (5, 2, 3)
    assert a.reasons["not combined log format"] == 3
