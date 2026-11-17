"""Score a scan against simulator labels.

Everything is counted per actor (client address):

* precision of a rule = alerted actors that are malicious / all alerted actors
  (an alert on any attacker is a useful alert, even if another rule was the
  intended one);
* recall of a rule = actors whose scenario expects the rule and that the rule
  alerted / actors whose scenario expects the rule.

The anomaly model is scored the same way per source, plus ROC-AUC over all
scored actors.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import numpy as np

from argus.pipeline import ScanResult
from argus.simulate.labels import Labels


def roc_auc(scores: Sequence[float], positive: Sequence[bool]) -> float | None:
    """Area under the ROC curve via the Mann-Whitney U statistic (ties averaged).

    ``None`` when only one class is present.
    """
    values = np.asarray(scores, dtype=np.float64)
    is_positive = np.asarray(positive, dtype=bool)
    n_pos = int(is_positive.sum())
    n_neg = len(values) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=np.float64)
    sorted_values = values[order]
    start = 0
    while start < len(values):
        stop = start
        while stop + 1 < len(values) and sorted_values[stop + 1] == sorted_values[start]:
            stop += 1
        ranks[order[start : stop + 1]] = (start + stop) / 2 + 1
        start = stop + 1
    u = ranks[is_positive].sum() - n_pos * (n_pos + 1) / 2
    return float(u / (n_pos * n_neg))


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


@dataclass(frozen=True)
class DetectionMetrics:
    rule_id: str
    expected: int
    alerted: int
    true_positives: int
    malicious_alerted: int
    benign_alerted: int

    @property
    def precision(self) -> float | None:
        return _ratio(self.malicious_alerted, self.alerted)

    @property
    def recall(self) -> float | None:
        return _ratio(self.true_positives, self.expected)

    def merged(self, other: DetectionMetrics) -> DetectionMetrics:
        return DetectionMetrics(
            self.rule_id,
            self.expected + other.expected,
            self.alerted + other.alerted,
            self.true_positives + other.true_positives,
            self.malicious_alerted + other.malicious_alerted,
            self.benign_alerted + other.benign_alerted,
        )


@dataclass(frozen=True)
class ModelMetrics:
    source: str
    actors: int
    malicious: int
    flagged: int
    flagged_malicious: int
    scored: tuple[tuple[float, bool], ...]

    @classmethod
    def from_scores(
        cls, source: str, scores: Mapping[str, float], malicious: set[str], threshold: float
    ) -> ModelMetrics:
        pairs = tuple((scores[actor], actor in malicious) for actor in sorted(scores))
        flagged = [bad for score, bad in pairs if score >= threshold]
        return cls(
            source=source,
            actors=len(pairs),
            malicious=sum(bad for _, bad in pairs),
            flagged=len(flagged),
            flagged_malicious=sum(flagged),
            scored=pairs,
        )

    @property
    def precision(self) -> float | None:
        return _ratio(self.flagged_malicious, self.flagged)

    @property
    def recall(self) -> float | None:
        return _ratio(self.flagged_malicious, self.malicious)

    @property
    def auc(self) -> float | None:
        return roc_auc([score for score, _ in self.scored], [bad for _, bad in self.scored])

    def merged(self, other: ModelMetrics) -> ModelMetrics:
        return ModelMetrics(
            self.source,
            self.actors + other.actors,
            self.malicious + other.malicious,
            self.flagged + other.flagged,
            self.flagged_malicious + other.flagged_malicious,
            self.scored + other.scored,
        )


@dataclass(frozen=True)
class SeedSummary:
    seed: int
    access_lines: int
    auth_lines: int
    events: int
    malformed_injected: int
    malformed_counted: int
    benign_actors: int
    malicious_actors: int
    alerts: int
    incidents: int


@dataclass
class EvalReport:
    detections: dict[str, DetectionMetrics] = field(default_factory=dict)
    models: dict[str, ModelMetrics] = field(default_factory=dict)
    misses: Counter[tuple[str, str]] = field(default_factory=Counter)
    """(scenario, rule) -> expected actors the rule did not alert."""
    false_alarms: Counter[tuple[str, str]] = field(default_factory=Counter)
    """(benign scenario, rule) -> benign actors the rule alerted."""
    seeds: list[SeedSummary] = field(default_factory=list)

    def merge(self, other: EvalReport) -> None:
        for rule_id, metrics in other.detections.items():
            current = self.detections.get(rule_id)
            self.detections[rule_id] = metrics if current is None else current.merged(metrics)
        for source, model in other.models.items():
            current_model = self.models.get(source)
            self.models[source] = model if current_model is None else current_model.merged(model)
        self.misses.update(other.misses)
        self.false_alarms.update(other.false_alarms)
        self.seeds.extend(other.seeds)

    def total(self) -> DetectionMetrics:
        """Micro-average over all rules."""
        total = DetectionMetrics("all", 0, 0, 0, 0, 0)
        for metrics in self.detections.values():
            total = total.merged(metrics)
        return total


def evaluate(result: ScanResult, labels: Labels) -> EvalReport:
    alerted: dict[str, set[str]] = {rule.id: set() for rule in result.rules}
    for alert in result.alerts:
        alerted[alert.rule.id].update(alert.actors)
    malicious = {ip for ip, label in labels.actors.items() if label.malicious}
    report = EvalReport()
    for rule_id, actors in alerted.items():
        expected = {ip for ip, label in labels.actors.items() if rule_id in label.expected}
        report.detections[rule_id] = DetectionMetrics(
            rule_id=rule_id,
            expected=len(expected),
            alerted=len(actors),
            true_positives=len(actors & expected),
            malicious_alerted=len(actors & malicious),
            benign_alerted=len(actors - malicious),
        )
        for ip in expected - actors:
            report.misses[(labels.get(ip).scenario, rule_id)] += 1
        for ip in actors - malicious:
            report.false_alarms[(labels.get(ip).scenario, rule_id)] += 1
    for model in result.models:
        if model.scores:
            report.models[model.source] = ModelMetrics.from_scores(
                model.source, model.scores, malicious, model.threshold
            )
    actor_labels = list(labels.actors.values())
    report.seeds.append(
        SeedSummary(
            seed=labels.seed,
            access_lines=next((i.lines for i in result.inputs if i.path.endswith("access.log")), 0),
            auth_lines=next((i.lines for i in result.inputs if i.path.endswith("auth.log")), 0),
            events=result.events,
            malformed_injected=sum(labels.malformed.values()),
            malformed_counted=result.stats.malformed,
            benign_actors=sum(not label.malicious for label in actor_labels),
            malicious_actors=sum(label.malicious for label in actor_labels),
            alerts=len(result.alerts),
            incidents=len(result.incidents),
        )
    )
    return report
