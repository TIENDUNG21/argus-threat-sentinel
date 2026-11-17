"""Machine-readable scan output (schema version 1).

Incidents reference alerts by id so the document has no duplicated data; actor
lists and distinct values are sorted so two runs over the same input produce
the same file (apart from ``generated_at``, which ``SOURCE_DATE_EPOCH`` pins).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from argus import __version__
from argus.alerts import Alert
from argus.attack import technique_url
from argus.correlate import Incident
from argus.ml.detector import Anomaly
from argus.pipeline import ScanResult
from argus.report.common import generated_at, iso, level_counts

SCHEMA_VERSION = 1
MAX_DISTINCT_VALUES = 50


def _alert(alert: Alert) -> dict[str, Any]:
    rule = alert.rule
    return {
        "id": alert.id,
        "rule": rule.id,
        "title": rule.title,
        "severity": alert.severity.label,
        "technique": rule.technique,
        "technique_name": rule.technique_name,
        "technique_url": technique_url(rule.technique),
        "tactic": rule.tactic,
        "group": dict(alert.group),
        "actors": sorted(alert.actors),
        "first_seen": iso(alert.first_ts),
        "fired_at": iso(alert.fired_ts),
        "last_seen": iso(alert.last_ts),
        "count": alert.count,
        "distinct_values": sorted(alert.distinct_values)[:MAX_DISTINCT_VALUES],
        "evidence": [
            {"file": e.file, "line": e.line, "ts": iso(e.ts), "text": e.text}
            for e in alert.evidence
        ],
    }


def _anomaly(anomaly: Anomaly) -> dict[str, Any]:
    return {
        "actor": anomaly.actor,
        "source": anomaly.source,
        "score": round(anomaly.score, 4),
        "events": anomaly.events,
        "first_seen": iso(anomaly.first_ts),
        "last_seen": iso(anomaly.last_ts),
        "features": [
            {
                "name": f.name,
                "value": round(f.value, 4),
                "typical": round(f.typical, 4),
                "share": round(f.share, 4),
            }
            for f in anomaly.features
        ],
    }


def _incident(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "level": incident.level.label,
        "score": incident.score,
        "title": incident.title,
        "actors": incident.actors,
        "start": iso(incident.start),
        "end": iso(incident.end),
        "tactics": incident.tactics,
        "techniques": incident.techniques,
        "alerts": [alert.id for alert in incident.alerts],
        "anomalies": [
            {"actor": a.actor, "source": a.source, "score": round(a.score, 4)}
            for a in incident.anomalies
        ],
        "timeline": [
            {
                "start": iso(entry.ts),
                "end": iso(entry.end),
                "tactic": entry.tactic,
                "label": entry.label,
                "rule": entry.rule_id,
                "technique": entry.technique,
                "severity": entry.severity.label if entry.severity else None,
                "count": entry.count,
            }
            for entry in incident.timeline
        ],
    }


def build_json(result: ScanResult, *, label: str | None = None) -> dict[str, Any]:
    stats = result.stats
    return {
        "tool": "argus",
        "version": __version__,
        "schema": SCHEMA_VERSION,
        "generated_at": iso(generated_at()),
        "label": label,
        "window": (
            {"start": iso(result.window[0]), "end": iso(result.window[1])}
            if result.window
            else None
        ),
        "inputs": [
            {
                "path": i.path,
                "format": i.format,
                "lines": i.lines,
                "events": i.events,
                "ignored": i.ignored,
                "malformed": i.malformed,
                "errors": list(i.errors),
            }
            for i in result.inputs
        ],
        "ingest": {
            "total_lines": stats.total_lines,
            "parsed_lines": stats.parsed,
            "events": stats.events,
            "ignored": stats.ignored,
            "malformed": stats.malformed,
            "malformed_reasons": dict(sorted(stats.reasons.items())),
            "malformed_samples": [
                {"file": s.file, "line": s.line, "reason": s.reason, "snippet": s.snippet}
                for s in stats.samples
            ],
            "errors": list(stats.errors),
        },
        "rules": {"loaded": len(result.rules)},
        "models": [
            {
                "source": m.source,
                "actors": m.actors,
                "skipped": m.skipped,
                "threshold": m.threshold,
                "fitted": bool(m.scores),
            }
            for m in result.models
        ],
        "summary": {
            "events": result.events,
            "alerts": len(result.alerts),
            "anomalies": len(result.anomalies),
            "incidents": len(result.incidents),
            "incidents_by_level": level_counts(result.incidents),
        },
        "incidents": [_incident(incident) for incident in result.incidents],
        "alerts": [_alert(alert) for alert in result.alerts],
        "anomalies": [_anomaly(anomaly) for anomaly in result.anomalies],
    }


def write_json(result: ScanResult, path: Path, *, label: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(build_json(result, label=label), indent=2, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8", newline="\n")
