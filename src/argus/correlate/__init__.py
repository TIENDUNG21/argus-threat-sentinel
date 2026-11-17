"""Correlation of alerts and anomalies into scored incidents."""

from argus.correlate.incidents import DEFAULT_GAP, Incident, TimelineEntry, correlate
from argus.correlate.scoring import level_for, score_incident

__all__ = [
    "DEFAULT_GAP",
    "Incident",
    "TimelineEntry",
    "correlate",
    "level_for",
    "score_incident",
]
