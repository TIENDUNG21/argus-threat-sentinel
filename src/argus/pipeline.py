"""The batch scan: ingest -> rules -> anomaly model -> incidents."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from operator import attrgetter
from pathlib import Path

from argus.alerts import Alert
from argus.correlate import DEFAULT_GAP, Incident, correlate
from argus.events import SSH, WEB, Event
from argus.ingest.reader import IngestStats, detect_format, read_events
from argus.ml.detector import Anomaly, AnomalyConfig, ModelSummary, detect_anomalies
from argus.rules.engine import Engine
from argus.rules.errors import RuleError
from argus.rules.loader import builtin_rules, load_rules
from argus.rules.model import Rule

HOURLY_LIMIT = timedelta(days=7)


@dataclass(frozen=True)
class ScanOptions:
    fmt: str = "auto"
    year: int | None = None
    rule_paths: tuple[Path, ...] = ()
    builtin: bool = True
    ml: bool = True
    anomaly: AnomalyConfig = field(default_factory=AnomalyConfig)
    gap: timedelta = DEFAULT_GAP


@dataclass(frozen=True)
class InputSummary:
    path: str
    format: str
    lines: int
    events: int
    ignored: int
    malformed: int
    errors: tuple[str, ...]


@dataclass(frozen=True)
class Activity:
    """Event counts per source in fixed buckets (hourly up to 7 days, else daily)."""

    start: datetime
    bucket: timedelta
    counts: dict[str, list[int]]

    def index(self, ts: datetime) -> int:
        return int((ts - self.start) / self.bucket)


@dataclass
class ScanResult:
    inputs: list[InputSummary]
    stats: IngestStats
    events: int
    window: tuple[datetime, datetime] | None
    activity: Activity
    rules: list[Rule]
    alerts: list[Alert]
    anomalies: list[Anomaly]
    models: list[ModelSummary]
    incidents: list[Incident]


def load_rule_set(options: ScanOptions) -> list[Rule]:
    """Built-in rules (unless disabled) plus custom files; ids must stay unique."""
    rules = builtin_rules() if options.builtin else []
    custom = load_rules(options.rule_paths)
    known = {rule.id: rule.origin for rule in rules}
    for rule in custom:
        if rule.id in known:
            raise RuleError(
                f"{rule.origin}: duplicate rule id '{rule.id}' (also in {known[rule.id]})"
            )
    return rules + custom


def _activity(events: Sequence[Event], window: tuple[datetime, datetime] | None) -> Activity:
    if window is None:
        return Activity(datetime(1970, 1, 1, tzinfo=UTC), timedelta(hours=1), {WEB: [], SSH: []})
    first, last = window
    bucket = timedelta(hours=1) if last - first <= HOURLY_LIMIT else timedelta(days=1)
    if bucket == timedelta(hours=1):
        start = first.replace(minute=0, second=0, microsecond=0)
    else:
        start = first.replace(hour=0, minute=0, second=0, microsecond=0)
    size = int((last - start) / bucket) + 1
    counts = {WEB: [0] * size, SSH: [0] * size}
    for event in events:
        counts[event.source][int((event.ts - start) / bucket)] += 1
    return Activity(start, bucket, counts)


def read_inputs(
    paths: Sequence[Path], options: ScanOptions
) -> tuple[list[Event], IngestStats, list[InputSummary]]:
    """Read every input; problems are recorded in the stats, never raised."""
    stats = IngestStats()
    summaries: list[InputSummary] = []
    events: list[Event] = []
    for path in paths:
        fmt = options.fmt
        if fmt == "auto":
            try:
                fmt = detect_format(path, year=options.year) or "auto"
            except OSError:
                fmt = "auto"
        found, file_stats = read_events(path, fmt, year=options.year)
        summaries.append(
            InputSummary(
                path=str(path),
                format=fmt if fmt != "auto" else "unknown",
                lines=file_stats.total_lines,
                events=file_stats.events,
                ignored=file_stats.ignored,
                malformed=file_stats.malformed,
                errors=tuple(file_stats.errors),
            )
        )
        stats.merge(file_stats)
        events.extend(found)
    events.sort(key=attrgetter("ts"))
    return events, stats, summaries


def scan(paths: Sequence[Path], options: ScanOptions | None = None) -> ScanResult:
    """Run the whole analysis over ``paths``. Raises only for invalid rule files."""
    options = options or ScanOptions()
    rules = load_rule_set(options)
    events, stats, summaries = read_inputs(paths, options)
    window = (events[0].ts, events[-1].ts) if events else None
    alerts = Engine(rules).run(events)
    anomalies: list[Anomaly] = []
    models: list[ModelSummary] = []
    if options.ml:
        anomalies, models = detect_anomalies(events, options.anomaly)
    return ScanResult(
        inputs=summaries,
        stats=stats,
        events=len(events),
        window=window,
        activity=_activity(events, window),
        rules=rules,
        alerts=alerts,
        anomalies=anomalies,
        models=models,
        incidents=correlate(alerts, anomalies, gap=options.gap),
    )
