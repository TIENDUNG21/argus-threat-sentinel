"""Helpers shared by the report writers."""

from __future__ import annotations

import os
from collections.abc import Sequence
from datetime import UTC, datetime

from argus.alerts import Severity
from argus.correlate import Incident

LEVELS = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def generated_at() -> datetime:
    """Report timestamp. ``SOURCE_DATE_EPOCH`` pins it so builds are reproducible."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), UTC)
    return datetime.now(UTC).replace(microsecond=0)


def iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat().replace("+00:00", "Z")


def level_counts(incidents: Sequence[Incident]) -> dict[str, int]:
    counts = {level.label: 0 for level in LEVELS}
    for incident in incidents:
        counts[incident.level.label] += 1
    return counts


def by_priority(incidents: Sequence[Incident]) -> list[Incident]:
    """Highest score first; ties by start time."""
    return sorted(incidents, key=lambda incident: (-incident.score, incident.start, incident.id))
