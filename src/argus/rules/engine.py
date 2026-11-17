"""The detection engine: routes events to every rule's detector.

The engine is streaming: ``process`` handles one event and returns the alerts
that fired on it, so the same code serves batch scans and ``argus tail``.
Events are expected in time order (batch scans sort them first).
"""

from __future__ import annotations

from collections.abc import Iterable

from argus.alerts import Alert
from argus.events import Event
from argus.rules.detectors import (
    AlertFactory,
    Detector,
    NewValueDetector,
    SequenceDetector,
    ThresholdDetector,
)
from argus.rules.model import NewValue, Rule, Sequence, Threshold


def make_detector(rule: Rule, factory: AlertFactory) -> Detector:
    kind = rule.kind
    if isinstance(kind, Threshold):
        return ThresholdDetector(rule, kind, factory)
    if isinstance(kind, Sequence):
        return SequenceDetector(rule, kind, factory)
    if isinstance(kind, NewValue):
        return NewValueDetector(rule, kind, factory)
    raise TypeError(f"unsupported rule kind {type(kind).__name__}")


class Engine:
    """Runs rules over a time-ordered stream of events."""

    def __init__(self, rules: Iterable[Rule], *, sweep_every: int = 10_000) -> None:
        self.rules = list(rules)
        factory = AlertFactory()
        self._detectors = [make_detector(rule, factory) for rule in self.rules]
        self._by_source: dict[str, list[Detector]] = {}
        self._alerts: list[Alert] = []
        self._processed = 0
        self._sweep_every = sweep_every

    def _for_source(self, source: str) -> list[Detector]:
        detectors = self._by_source.get(source)
        if detectors is None:
            detectors = [d for d in self._detectors if d.rule.source in (None, source)]
            self._by_source[source] = detectors
        return detectors

    def process(self, event: Event) -> list[Alert]:
        """Feed one event; return the alerts that fired because of it."""
        fired: list[Alert] = []
        for detector in self._for_source(event.source):
            if detector.rule.when(event):
                alert = detector.process(event)
                if alert is not None:
                    fired.append(alert)
        self._alerts.extend(fired)
        self._processed += 1
        if self._processed % self._sweep_every == 0:
            for detector in self._detectors:
                detector.sweep(event.ts)
        return fired

    def run(self, events: Iterable[Event]) -> list[Alert]:
        """Process every event and return all alerts raised so far."""
        for event in events:
            self.process(event)
        return self.alerts

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    def tracked_groups(self) -> int:
        """Number of per-group states held in memory (for tests and diagnostics)."""
        return sum(detector.tracked_groups() for detector in self._detectors)
