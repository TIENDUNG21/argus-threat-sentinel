"""Group alerts and anomalies into incidents.

Two alerts belong to the same incident when they share an actor and the
second starts no later than ``gap`` after the actor's activity so far ended.
Alerts with several actors (credential stuffing from 40 addresses) link those
actors together, so grouping is a union-find over alerts. Anomalies join the
incident of their actor when their time span is within ``gap``; otherwise they
become anomaly-only incidents.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from argus.alerts import Alert, Severity
from argus.attack import tactic_rank
from argus.correlate.scoring import score_incident
from argus.ml.detector import Anomaly

DEFAULT_GAP = timedelta(hours=2)
ANOMALY_TACTIC = "anomaly"


@dataclass(frozen=True)
class TimelineEntry:
    ts: datetime
    end: datetime
    tactic: str
    """ATT&CK tactic, or ``anomaly`` for model findings."""
    label: str
    rule_id: str | None = None
    technique: str | None = None
    severity: Severity | None = None
    count: int = 1


@dataclass
class Incident:
    id: str
    actors: list[str]
    start: datetime
    end: datetime
    alerts: list[Alert] = field(default_factory=list)
    anomalies: list[Anomaly] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    score: int = 0
    level: Severity = Severity.LOW

    @property
    def title(self) -> str:
        if not self.alerts:
            sources = sorted({anomaly.source for anomaly in self.anomalies})
            return f"Anomalous {' and '.join(sources)} behaviour"
        top = max(self.alerts, key=lambda alert: (alert.severity, -alert.first_ts.timestamp()))
        others = len({alert.rule.id for alert in self.alerts}) - 1
        return top.rule.title + (f" and {others} more" if others else "")

    @property
    def techniques(self) -> list[str]:
        return sorted({alert.rule.technique for alert in self.alerts})


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[max(root_a, root_b)] = min(root_a, root_b)


def _group_alerts(alerts: Sequence[Alert], gap: timedelta) -> list[list[Alert]]:
    sets = _UnionFind(len(alerts))
    by_actor: dict[str, list[int]] = defaultdict(list)
    for index, alert in enumerate(alerts):
        for actor in alert.actors:
            by_actor[actor].append(index)
    for indexes in by_actor.values():
        indexes.sort(key=lambda i: alerts[i].first_ts)
        previous = indexes[0]
        horizon = alerts[previous].last_ts
        for index in indexes[1:]:
            if alerts[index].first_ts - horizon <= gap:
                sets.union(previous, index)
                horizon = max(horizon, alerts[index].last_ts)
            else:
                horizon = alerts[index].last_ts
            previous = index
    groups: dict[int, list[Alert]] = defaultdict(list)
    for index, alert in enumerate(alerts):
        groups[sets.find(index)].append(alert)
    return list(groups.values())


def _timeline(alerts: list[Alert], anomalies: list[Anomaly]) -> list[TimelineEntry]:
    entries = [
        TimelineEntry(
            ts=alert.first_ts,
            end=alert.last_ts,
            tactic=alert.rule.tactic,
            label=alert.rule.title,
            rule_id=alert.rule.id,
            technique=alert.rule.technique,
            severity=alert.severity,
            count=alert.count,
        )
        for alert in alerts
    ]
    entries.extend(
        TimelineEntry(
            ts=anomaly.first_ts,
            end=anomaly.last_ts,
            tactic=ANOMALY_TACTIC,
            label=f"Anomalous {anomaly.source} behaviour (score {anomaly.score:.2f})",
            count=anomaly.events,
        )
        for anomaly in anomalies
    )
    entries.sort(key=lambda entry: (entry.ts, tactic_rank(entry.tactic), entry.label))
    return entries


def _build(alerts: list[Alert], anomalies: list[Anomaly]) -> Incident:
    actors = {actor for alert in alerts for actor in alert.actors}
    actors.update(anomaly.actor for anomaly in anomalies)
    starts = [a.first_ts for a in alerts] + [a.first_ts for a in anomalies]
    ends = [a.last_ts for a in alerts] + [a.last_ts for a in anomalies]
    score, level = score_incident(alerts, anomalies)
    return Incident(
        id="",
        actors=sorted(actors),
        start=min(starts),
        end=max(ends),
        alerts=sorted(alerts, key=lambda alert: (alert.first_ts, alert.rule.id)),
        anomalies=sorted(anomalies, key=lambda anomaly: (anomaly.first_ts, anomaly.actor)),
        tactics=sorted({alert.rule.tactic for alert in alerts}, key=tactic_rank),
        timeline=_timeline(alerts, anomalies),
        score=score,
        level=level,
    )


def correlate(
    alerts: Sequence[Alert], anomalies: Sequence[Anomaly], *, gap: timedelta = DEFAULT_GAP
) -> list[Incident]:
    """Build incidents ordered by start time with ids ``INC-0001``, ``INC-0002``, ..."""
    groups = _group_alerts(alerts, gap) if alerts else []
    attached: list[list[Anomaly]] = [[] for _ in groups]
    by_actor: dict[str, list[int]] = defaultdict(list)
    for position, group in enumerate(groups):
        for alert in group:
            for actor in alert.actors:
                by_actor[actor].append(position)
    loose: dict[str, list[Anomaly]] = defaultdict(list)
    for anomaly in anomalies:
        target = next(
            (
                position
                for position in by_actor.get(anomaly.actor, [])
                if any(
                    alert.first_ts - gap <= anomaly.last_ts
                    and anomaly.first_ts <= alert.last_ts + gap
                    for alert in groups[position]
                )
            ),
            None,
        )
        if target is None:
            loose[anomaly.actor].append(anomaly)
        else:
            attached[target].append(anomaly)

    incidents = [_build(group, extra) for group, extra in zip(groups, attached, strict=True)]
    incidents.extend(_build([], found) for found in loose.values())
    incidents.sort(key=lambda incident: (incident.start, -incident.score, incident.actors))
    for number, incident in enumerate(incidents, 1):
        incident.id = f"INC-{number:04d}"
    return incidents
