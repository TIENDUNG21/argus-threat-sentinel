"""Read log files into events while accounting for every line.

Each line ends up in exactly one bucket: parsed (produced events), ignored
(blank, or well-formed but not something we model) or malformed (counted by
reason, with the first samples kept for the report). I/O problems such as a
missing file or a truncated gzip stream are recorded as errors; events read
before the problem are kept.
"""

from __future__ import annotations

import gzip
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, cast

from argus.events import Event
from argus.ingest.combined import parse_combined
from argus.ingest.errors import MalformedLineError
from argus.ingest.sshd import SyslogClock, parse_auth

FORMATS = ("combined", "sshd")
MAX_SAMPLES = 20
SNIPPET_CHARS = 160
DEFAULT_MAX_LINE = 65536

LineParser = Callable[[str, str, int], list[Event]]
"""``parser(text, file, line_no)`` returns events or raises MalformedLineError."""


@dataclass(frozen=True, slots=True)
class MalformedSample:
    file: str
    line: int
    reason: str
    snippet: str


@dataclass
class IngestStats:
    total_lines: int = 0
    parsed: int = 0
    events: int = 0
    ignored: int = 0
    malformed: int = 0
    reasons: Counter[str] = field(default_factory=Counter)
    samples: list[MalformedSample] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_malformed(self, file: str, line: int, reason: str, text: str) -> None:
        self.malformed += 1
        self.reasons[reason] += 1
        if len(self.samples) < MAX_SAMPLES:
            self.samples.append(MalformedSample(file, line, reason, text[:SNIPPET_CHARS]))

    def merge(self, other: IngestStats) -> None:
        self.total_lines += other.total_lines
        self.parsed += other.parsed
        self.events += other.events
        self.ignored += other.ignored
        self.malformed += other.malformed
        self.reasons.update(other.reasons)
        room = max(MAX_SAMPLES - len(self.samples), 0)
        self.samples.extend(other.samples[:room])
        self.errors.extend(other.errors)


def make_line_parser(fmt: str, *, year: int | None = None) -> LineParser:
    """Return a parser for ``fmt`` (``combined`` or ``sshd``)."""
    if fmt == "combined":

        def parse_web(text: str, file: str, line_no: int) -> list[Event]:
            return [parse_combined(text, file=file, line_no=line_no)]

        return parse_web
    if fmt == "sshd":
        clock = SyslogClock(year=year)

        def parse_ssh(text: str, file: str, line_no: int) -> list[Event]:
            return parse_auth(text, clock, file=file, line_no=line_no)

        return parse_ssh
    raise ValueError(f"unknown log format {fmt!r}; expected one of {', '.join(FORMATS)}")


def open_log(path: Path) -> BinaryIO:
    """Open a plain or gzip-compressed log (detected by magic bytes)."""
    handle = path.open("rb")
    magic = handle.read(2)
    handle.seek(0)
    if magic == b"\x1f\x8b":
        return cast(BinaryIO, gzip.GzipFile(fileobj=handle, mode="rb"))
    return handle


def iter_lines(handle: BinaryIO, *, max_line: int = DEFAULT_MAX_LINE) -> Iterator[tuple[str, bool]]:
    """Yield ``(text, too_long)`` per line, without the line ending.

    An overlong line is consumed in bounded chunks so a single huge line cannot
    exhaust memory; only its first characters are returned, with ``too_long`` set.
    """
    while True:
        chunk = handle.readline(max_line + 1)
        if not chunk:
            return
        if len(chunk) > max_line and not chunk.endswith(b"\n"):
            head = chunk[:SNIPPET_CHARS].decode("utf-8", "replace")
            while chunk and not chunk.endswith(b"\n"):
                chunk = handle.readline(max_line)
            yield head, True
            continue
        yield chunk.rstrip(b"\r\n").decode("utf-8", "replace"), False


def detect_format(path: Path, *, sniff_lines: int = 50, year: int | None = None) -> str | None:
    """Guess the format from the first non-blank lines; ``None`` if nothing matches."""
    scores = dict.fromkeys(FORMATS, 0)
    parsers = {fmt: make_line_parser(fmt, year=year) for fmt in FORMATS}
    seen = 0
    with open_log(path) as handle:
        for text, too_long in iter_lines(handle):
            if too_long or not text.strip():
                continue
            seen += 1
            for fmt, parser in parsers.items():
                try:
                    parser(text, "", 0)
                except MalformedLineError:
                    continue
                scores[fmt] += 1
            if seen >= sniff_lines:
                break
    best = max(scores, key=lambda fmt: scores[fmt])
    return best if scores[best] > 0 else None


def read_events(
    path: Path,
    fmt: str = "auto",
    *,
    year: int | None = None,
    max_line: int = DEFAULT_MAX_LINE,
) -> tuple[list[Event], IngestStats]:
    """Parse every line of ``path``. Never raises for bad content or I/O errors."""
    stats = IngestStats()
    events: list[Event] = []
    name = str(path)
    try:
        if fmt == "auto":
            if path.stat().st_size == 0:
                return events, stats
            detected = detect_format(path, year=year)
            if detected is None:
                stats.errors.append(f"{name}: could not detect log format; pass --format")
                return events, stats
            fmt = detected
        parser = make_line_parser(fmt, year=year)
        with open_log(path) as handle:
            for line_no, (text, too_long) in enumerate(iter_lines(handle, max_line=max_line), 1):
                stats.total_lines += 1
                if too_long:
                    stats.add_malformed(name, line_no, "line too long", text)
                else:
                    consume_line(parser, text, name, line_no, stats, events)
    except FileNotFoundError:
        stats.errors.append(f"{name}: file not found")
    except (OSError, EOFError) as exc:
        stats.errors.append(f"{name}: {exc}")
    return events, stats


def consume_line(
    parser: LineParser,
    text: str,
    name: str,
    line_no: int,
    stats: IngestStats,
    events: list[Event],
) -> None:
    """Parse one line and file it under parsed, ignored or malformed."""
    if not text.strip():
        stats.ignored += 1
        return
    try:
        found = parser(text, name, line_no)
    except MalformedLineError as exc:
        stats.add_malformed(name, line_no, exc.reason, text)
        return
    if found:
        stats.parsed += 1
        stats.events += len(found)
        events.extend(found)
    else:
        stats.ignored += 1
