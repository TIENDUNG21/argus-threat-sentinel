"""Per-rule state machines. Each detector sees only events that already passed
its rule's ``source`` filter and ``when`` condition."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from argus.alerts import Alert
from argus.events import Event
from argus.rules.model import NewValue, Rule, Sequence, Threshold

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


@dataclass
class _SequenceGroup:
    first_step: deque[Event] = field(default_factory=deque)
    later: list[Event] = field(default_factory=list)
    step: int = 0
    count: int = 0
    started: datetime | None = None
    alert: Alert | None = None
    last_ts: datetime | None = None


class SequenceDetector:
    """Ordered steps per group within ``within``.

    Step 1 is tracked with a sliding window, so a long brute force that finally
    succeeds is still linked to the success: when later steps expire, the state
    falls back to whatever step-1 events are still inside the window.
    """

    def __init__(self, rule: Rule, kind: Sequence, factory: AlertFactory) -> None:
        self.rule = rule
        self.kind = kind
        self.factory = factory
        self.groups: dict[GroupKey, _SequenceGroup] = {}

    def process(self, event: Event) -> Alert | None:
        key = group_key(self.rule, event)
        group = self.groups.get(key)
        if group is None:
            group = self.groups[key] = _SequenceGroup()
        group.last_ts = event.ts
        steps = self.kind.steps
        within = self.kind.within
        matched_first = steps[0].when(event)
        if matched_first:
            group.first_step.append(event)
        while group.first_step and group.first_step[0].ts < event.ts - within:
            group.first_step.popleft()
        if group.step > 0 and group.started is not None and event.ts - group.started > within:
            group.step, group.count, group.later = 0, 0, []
        if group.step == 0 and len(group.first_step) >= steps[0].count:
            group.step, group.count, group.later = 1, 0, []
            group.started = group.first_step[0].ts
        if matched_first or group.step == 0:
            return None
        step = steps[group.step]
        if not step.when(event):
            return None
        group.later.append(event)
        group.count += 1
        if group.count < step.count:
            return None
        group.step += 1
        group.count = 0
        if group.step < len(steps):
            return None
        return self._complete(group, key, event)

    def _complete(self, group: _SequenceGroup, key: GroupKey, event: Event) -> Alert | None:
        events = [*group.first_step, *group.later]
        group.first_step.clear()
        group.step, group.count, group.later, group.started = 0, 0, [], None
        if group.alert is not None and event.ts - group.alert.last_ts <= self.kind.within:
            for item in events:
                group.alert.add(item)
            return None
        alert = self.factory.open(self.rule, key, events[0].ts)
        for item in events:
            alert.add(item)
        alert.fired_ts = event.ts
        group.alert = alert
        return alert

    def sweep(self, now: datetime) -> None:
        horizon = now - self.kind.within
        stale = [k for k, g in self.groups.items() if g.last_ts is not None and g.last_ts < horizon]
        for key in stale:
            del self.groups[key]

    def tracked_groups(self) -> int:
        return len(self.groups)


class NewValueDetector:
    """Learns the values of ``field`` per group, then alerts on unseen ones.

    The learning period starts at the first event the rule sees. Known values
    are kept for the whole run (memory grows with distinct group/value pairs).
    """

    def __init__(self, rule: Rule, kind: NewValue, factory: AlertFactory) -> None:
        self.rule = rule
        self.kind = kind
        self.factory = factory
        self.first_ts: datetime | None = None
        self.seen: dict[GroupKey, set[str]] = {}

    def process(self, event: Event) -> Alert | None:
        if self.first_ts is None:
            self.first_ts = event.ts
        key = group_key(self.rule, event)
        known = self.seen.setdefault(key, set())
        value = str(getattr(event, self.kind.field))
        learning = event.ts < self.first_ts + self.kind.learn
        if learning or value in known:
            known.add(value)
            return None
        known.add(value)
        alert = self.factory.open(self.rule, key, event.ts)
        alert.add(event, value)
        return alert

    def sweep(self, now: datetime) -> None:
        """Known values are the baseline; they are never forgotten."""

    def tracked_groups(self) -> int:
        return len(self.seen)
