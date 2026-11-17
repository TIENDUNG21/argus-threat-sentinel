"""Plain-text scan summary for the terminal."""

from __future__ import annotations

from argus import __version__
from argus.alerts import Alert, Severity
from argus.pipeline import ScanResult
from argus.report.common import LEVELS, by_priority, iso, level_counts

_COLORS = {
    Severity.CRITICAL: "\x1b[1;31m",
    Severity.HIGH: "\x1b[38;5;209m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[2m",
}
_RESET = "\x1b[0m"


def _level(level: Severity, *, color: bool) -> str:
    text = f"{level.label:<8}"
    return f"{_COLORS[level]}{text}{_RESET}" if color else text


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 3] + "..."


def render_summary(result: ScanResult, *, color: bool = False, top: int = 15) -> str:
    stats = result.stats
    lines = [
        f"argus {__version__}: {len(result.inputs)} input(s), {stats.total_lines:,} lines, "
        f"{result.events:,} events, {stats.malformed:,} malformed, {stats.ignored:,} ignored",
    ]
    if result.window:
        lines.append(f"window: {iso(result.window[0])} to {iso(result.window[1])}")
    lines.append(f"rules: {len(result.rules)} loaded, {len(result.alerts):,} alerts")
    for model in result.models:
        if model.scores:
            flagged = sum(1 for a in result.anomalies if a.source == model.source)
            lines.append(
                f"anomaly model ({model.source}): {model.actors:,} actors scored, "
                f"{flagged} flagged at {model.threshold:.2f}"
            )
        else:
            lines.append(f"anomaly model ({model.source}): {model.actors} actors, too few to fit")
    lines.extend(f"error: {error}" for error in stats.errors)

    counts = level_counts(result.incidents)
    breakdown = ", ".join(f"{counts[level.label]} {level.label}" for level in LEVELS)
    lines += ["", f"{len(result.incidents)} incidents ({breakdown})"]
    ordered = by_priority(result.incidents)
    if ordered:
        lines.append("")
        lines.append(
            f"{'ID':<9} {'LEVEL':<8} {'SCORE':>5}  {'START (UTC)':<11}  {'ACTORS':<22}  TITLE"
        )
        for incident in ordered[:top]:
            actors = incident.actors[0] + (
                f" +{len(incident.actors) - 1}" if len(incident.actors) > 1 else ""
            )
            lines.append(
                f"{incident.id:<9} {_level(incident.level, color=color)} {incident.score:>5}  "
                f"{incident.start:%m-%d %H:%M}  {_clip(actors, 22):<22}  "
                f"{_clip(incident.title, 70)}"
            )
        if len(ordered) > top:
            lines.append(f"... {len(ordered) - top} more in the HTML and JSON reports")
    if stats.malformed:
        reasons = ", ".join(f"{reason} {n:,}" for reason, n in sorted(stats.reasons.items()))
        lines += ["", f"malformed lines (skipped): {reasons}"]
    return "\n".join(lines) + "\n"


def format_alert(alert: Alert, *, color: bool = False) -> str:
    """One line per alert, for ``argus tail``."""
    actors = sorted(alert.actors)
    who = actors[0] + (f" +{len(actors) - 1}" if len(actors) > 1 else "")
    return (
        f"{iso(alert.fired_ts)}  {_level(alert.severity, color=color)}  {alert.rule.id}  "
        f"{who}  {alert.rule.title} ({alert.count:,} events, {alert.rule.technique})"
    )
