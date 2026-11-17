"""Per-rule state machines. Each detector sees only events that already passed
its rule's ``source`` filter and ``when`` condition."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from argus.alerts import Alert
from argus.events import Event
from argus.rules.model import Rule, Threshold

GroupKey = tuple[str, ...]


class Detector(Protocol):
    rule: Rule

    def process(self, event: Event) -> Alert | None:
        """Consume a matching event; return an alert if one fired."""
        ...

    def sweep(self, now: datetime) -> None:
        """Forget per-group state that can no longer contribute to an alert."""
        ...

    def tracked_groups(self) -> int: ...


class AlertFactory:
    """Issues alerts with ids that are unique per rule (``rule-id#n``)."""

    def __init__(self) -> None:
        self.issued: Counter[str] = Counter()

    def open(self, rule: Rule, key: GroupKey, now: datetime) -> Alert:
        self.issued[rule.id] += 1
        return Alert(
            id=f"{rule.id}#{self.issued[rule.id]}",
            rule=rule,
            group=tuple(zip(rule.group_by, key, strict=True)),
            first_ts=now,
            fired_ts=now,
            last_ts=now,
        )


def group_key(rule: Rule, event: Event) -> GroupKey:
    return tuple(str(getattr(event, name)) for name in rule.group_by)


@dataclass
class _ThresholdGroup:
    window: deque[tuple[Event, str | None]] = field(default_factory=deque)
    values: Counter[str] = field(default_factory=Counter)
    alert: Alert | None = None
    last_ts: datetime | None = None


class ThresholdDetector:
    """Sliding-window counter per group with episode semantics.

    An alert fires when the window ``[now - window, now]`` holds ``count``
    events (or ``count`` distinct values). The episode then stays open, absorbing
    further matching events, until a gap longer than ``window`` closes it.
    """

    def __init__(self, rule: Rule, kind: Threshold, factory: AlertFactory) -> None:
        self.rule = rule
        self.kind = kind
        self.factory = factory
        self.groups: dict[GroupKey, _ThresholdGroup] = {}

    def process(self, event: Event) -> Alert | None:
        key = group_key(self.rule, event)
        group = self.groups.get(key)
        if group is None:
            group = self.groups[key] = _ThresholdGroup()
        window = self.kind.window
        value = str(getattr(event, self.kind.distinct)) if self.kind.distinct else None
        group.last_ts = event.ts
        if group.alert is not None:
            if event.ts - group.alert.last_ts <= window:
                group.alert.add(event, value)
                return None
            group.alert = None
        group.window.append((event, value))
        horizon = event.ts - window
        while group.window[0][0].ts < horizon:
            _, old_value = group.window.popleft()
            if old_value is not None:
                group.values[old_value] -= 1
                if not group.values[old_value]:
                    del group.values[old_value]
        if value is not None:
            group.values[value] += 1
            reached = len(group.values) >= self.kind.count
        else:
            reached = len(group.window) >= self.kind.count
        if not reached:
            return None
        alert = self.factory.open(self.rule, key, group.window[0][0].ts)
        for queued, queued_value in group.window:
            alert.add(queued, queued_value)
        alert.fired_ts = event.ts
        group.window.clear()
        group.values.clear()
        group.alert = alert
        return alert

    def sweep(self, now: datetime) -> None:
        horizon = now - self.kind.window
        stale = [
            key
            for key, group in self.groups.items()
            if group.last_ts is not None and group.last_ts < horizon
        ]
        for key in stale:
            del self.groups[key]

    def tracked_groups(self) -> int:
        return len(self.groups)
