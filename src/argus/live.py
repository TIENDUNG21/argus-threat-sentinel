"""``argus tail``: stream a growing log through the rule engine.

Only the rules run live. The anomaly model needs the whole population of actors
to say what is unusual, so it stays a batch feature of ``argus scan``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from argus.events import Event
from argus.ingest.reader import IngestStats, consume_line, make_line_parser
from argus.ingest.tail import Follower
from argus.report.terminal import format_alert
from argus.rules.engine import Engine
from argus.rules.model import Rule


def follow(
    path: Path,
    fmt: str,
    rules: Sequence[Rule],
    out: TextIO,
    *,
    year: int | None = None,
    from_start: bool = False,
    poll: float = 0.5,
    color: bool = False,
    stop: Callable[[], bool] = lambda: False,
    sleep: Callable[[float], None] = time.sleep,
) -> IngestStats:
    """Print each alert as it fires; return line accounting when ``stop()`` is true."""
    parser = make_line_parser(fmt, year=year)
    engine = Engine(rules)
    stats = IngestStats()
    name = str(path)
    follower = Follower(path, from_start=from_start, poll=poll, sleep=sleep)
    for line_no, (text, too_long) in enumerate(follower.lines(stop), 1):
        stats.total_lines += 1
        if too_long:
            stats.add_malformed(name, line_no, "line too long", text)
            continue
        events: list[Event] = []
        consume_line(parser, text, name, line_no, stats, events)
        for event in events:
            for alert in engine.process(event):
                out.write(format_alert(alert, color=color) + "\n")
                out.flush()
    return stats
