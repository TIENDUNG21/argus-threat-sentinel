"""Incident severity score (0-100) and level.

    alerts present:  points(max severity)            low 15, medium 35, high 60, critical 85
                     + 8 per additional ATT&CK tactic (progress along the kill chain)
                     + 4 * log2(number of alerts)    (breadth, with diminishing returns)
                     + 10 if the anomaly model also flagged an actor
    anomalies only:  50 * highest anomaly score      (0.6 -> 30, at most 50: never above medium)

The total is capped at 100 and mapped to a level: >= 80 critical, >= 55 high,
>= 30 medium, otherwise low.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

from argus.alerts import Alert, Severity
from argus.ml.detector import Anomaly

SEVERITY_POINTS = {
    Severity.LOW: 15,
    Severity.MEDIUM: 35,
    Severity.HIGH: 60,
    Severity.CRITICAL: 85,
}
TACTIC_BONUS = 8
BREADTH_FACTOR = 4
ANOMALY_BONUS = 10
ANOMALY_ONLY_FACTOR = 50
LEVELS = ((80, Severity.CRITICAL), (55, Severity.HIGH), (30, Severity.MEDIUM))


def level_for(score: int) -> Severity:
    for floor, level in LEVELS:
        if score >= floor:
            return level
    return Severity.LOW


def score_incident(alerts: Sequence[Alert], anomalies: Sequence[Anomaly]) -> tuple[int, Severity]:
    if alerts:
        total = float(max(SEVERITY_POINTS[alert.severity] for alert in alerts))
        tactics = {alert.rule.tactic for alert in alerts}
        total += TACTIC_BONUS * (len(tactics) - 1)
        total += BREADTH_FACTOR * math.log2(len(alerts))
        if anomalies:
            total += ANOMALY_BONUS
    elif anomalies:
        total = ANOMALY_ONLY_FACTOR * max(anomaly.score for anomaly in anomalies)
    else:
        total = 0.0
    score = min(100, round(total))
    return score, level_for(score)
