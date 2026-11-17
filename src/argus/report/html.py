"""Self-contained HTML report: inline CSS, inline SVG, no JavaScript.

Log lines are attacker-controlled, so every value goes through ``html.escape``
and the page carries a Content-Security-Policy that forbids scripts and remote
resources. A report opened from disk therefore cannot run anything an attacker
smuggled into a User-Agent or a URL.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta
from html import escape
from pathlib import Path

from argus import __version__
from argus.alerts import Alert, Severity
from argus.attack import TACTIC_NAMES, technique_url
from argus.correlate import Incident
from argus.events import SSH, WEB
from argus.ml.detector import Anomaly, FeatureContribution
from argus.pipeline import ScanResult
from argus.report import svg
from argus.report.common import LEVELS, by_priority, generated_at, level_counts
from argus.report.theme import CSS, LOGO_SVG

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)
MAX_INCIDENTS = 200
OPEN_INCIDENTS = 3


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _basename(path: str) -> str:
    """File name for display; inputs may use either path separator."""
    return re.split(r"[\\/]", path)[-1]


def _num(value: float) -> str:
    """Readable feature values: 26,402 / 87.5 / 0.895 rather than 2.64e+04."""
    magnitude = abs(value)
    if magnitude >= 1000:
        return f"{value:,.0f}"
    if magnitude >= 10:
        return f"{value:.1f}".removesuffix(".0")
    return f"{value:.3g}"


def _ts(value: datetime) -> str:
    return f"{value:%Y-%m-%d %H:%M:%S}"


def _span(start: datetime, end: datetime) -> str:
    return f"{start:%m-%d %H:%M} to {end:%m-%d %H:%M} UTC"


def _chip(level: Severity) -> str:
    return f'<span class="chip"><span class="dot sev-{level.label}"></span>{level.label}</span>'


def _actors(actors: Sequence[str], limit: int = 3) -> str:
    shown = ", ".join(actors[:limit])
    extra = len(actors) - limit
    return _e(shown + (f" and {extra} more" if extra > 0 else ""))


def _features(features: Sequence[FeatureContribution], *, with_share: bool) -> str:
    items = []
    for f in features:
        share = f", {f.share:.0%} of the isolation" if with_share else ""
        items.append(
            f'<li><span class="fname mono">{_e(f.name)}</span>{svg.share_bar(f.share)}'
            f"<span>{_num(f.value)} (typical {_num(f.typical)}){share}</span></li>"
        )
    return '<ul class="features">' + "".join(items) + "</ul>"


def _tiles(result: ScanResult) -> str:
    counts = level_counts(result.incidents)
    breakdown = " ".join(
        f'<span class="chip"><span class="dot sev-{level.label}"></span>'
        f"{counts[level.label]} {level.label}</span>"
        for level in LEVELS
    )
    stats = result.stats
    tiles = [
        ("Events parsed", f"{result.events:,}", f"{stats.total_lines:,} lines read"),
        ("Malformed lines", f"{stats.malformed:,}", f"{stats.ignored:,} ignored as irrelevant"),
        ("Rule alerts", f"{len(result.alerts):,}", f"{len(result.rules)} rules loaded"),
        ("Anomalous actors", f"{len(result.anomalies):,}", "Isolation Forest"),
    ]
    html = [
        f'<div class="tile"><div class="label">{_e(label)}</div>'
        f'<div class="value">{value}</div><div class="sub">{_e(sub)}</div></div>'
        for label, value, sub in tiles
    ]
    html.insert(
        0,
        '<div class="tile" style="grid-column: span 2"><div class="label">Incidents</div>'
        f'<div class="value">{len(result.incidents):,}</div>'
        f'<div class="sub">{breakdown}</div></div>',
    )
    return '<section class="tiles">' + "".join(html) + "</section>"


def _activity(result: ScanResult) -> str:
    activity = result.activity
    if result.window is None:
        return '<p class="muted">No events were parsed.</p>'
    hourly = activity.bucket == timedelta(hours=1)
    unit = "hour" if hourly else "day"
    size = len(activity.counts[WEB])
    every = 6 if hourly else max(1, size // 10)
    ticks = {}
    for index in range(0, size, every):
        moment = activity.start + activity.bucket * index
        ticks[index] = f"{moment:%m-%d %H:%M}" if hourly else f"{moment:%m-%d}"
    markers = [
        (
            activity.index(incident.start),
            incident.level,
            f"{incident.id} {incident.level.label}: {incident.title}",
        )
        for incident in result.incidents
        if incident.level >= Severity.HIGH
    ]
    parts = []
    for source, name in ((WEB, "Web requests"), (SSH, "SSH auth events")):
        values = activity.counts[source]
        if not any(values):
            continue
        tooltips = [
            f"{activity.start + activity.bucket * i:%Y-%m-%d %H:%M} UTC: {v:,} events"
            for i, v in enumerate(values)
        ]
        title = f"{name} per {unit} (UTC)"
        chart = svg.column_chart(
            values, title=title, tick_labels=ticks, tooltips=tooltips, markers=markers
        )
        parts.append(
            f'<p class="caption">{_e(title)}. Triangles mark high and critical incidents.</p>'
            f'<div class="chart">{chart}</div>'
        )
    return '<div class="card">' + "".join(parts) + "</div>"


def _evidence(alert: Alert) -> str:
    lines = "\n".join(f"{_basename(e.file)}:{e.line}  {e.text}" for e in alert.evidence)
    shown = len(alert.evidence)
    note = f"first {shown} of {alert.count:,}" if alert.count > shown else f"{shown}"
    return (
        f'<details class="evidence"><summary>Evidence ({note} lines)</summary>'
        f"<pre>{_e(lines)}</pre></details>"
    )


def _alert_rows(alerts: Sequence[Alert]) -> str:
    rows = []
    for alert in alerts:
        rule = alert.rule
        rows.append(
            "<tr>"
            f'<td class="mono">{_ts(alert.first_ts)}</td>'
            f'<td>{_e(rule.title)}<br><span class="muted mono">{_e(rule.id)}</span>'
            f"{_evidence(alert)}</td>"
            f'<td><a href="{_e(technique_url(rule.technique))}">{_e(rule.technique)}</a>'
            f'<br><span class="muted">{_e(rule.technique_name)}</span></td>'
            f"<td>{_chip(alert.severity)}</td>"
            f'<td class="num">{alert.count:,}</td>'
            f"<td>{_actors(sorted(alert.actors))}</td>"
            "</tr>"
        )
    return (
        '<div class="scroll"><table><thead><tr><th>First seen (UTC)</th><th>Detection</th>'
        '<th>ATT&amp;CK</th><th>Severity</th><th class="num">Events</th><th>Actors</th></tr>'
        "</thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _anomaly_block(anomaly: Anomaly) -> str:
    return (
        f"<p>{_e(anomaly.actor)} ({_e(anomaly.source)}): score {anomaly.score:.2f} over "
        f"{anomaly.events:,} events, {_span(anomaly.first_ts, anomaly.last_ts)}.</p>"
        + _features(anomaly.features, with_share=True)
    )


def _incident(incident: Incident, *, open_: bool) -> str:
    chain = '<span class="sep">&gt;</span>'.join(
        _e(TACTIC_NAMES.get(t, t)) for t in incident.tactics
    )
    findings = f", {len(incident.anomalies)} anomaly findings" if incident.anomalies else ""
    parts = [
        f'<details class="incident" id="{_e(incident.id)}"{" open" if open_ else ""}>',
        "<summary>",
        _chip(incident.level),
        f'<span class="score">{incident.score}</span>',
        f'<span class="inc-id">{_e(incident.id)}</span>',
        f'<span class="inc-title">{_e(incident.title)}</span>',
        f'<span class="inc-meta">{_actors(incident.actors)} · '
        f"{_span(incident.start, incident.end)} · {len(incident.alerts)} alerts{findings}</span>",
        '</summary><div class="body">',
    ]
    if chain:
        parts.append(f'<p class="chain">ATT&amp;CK tactics: {chain}</p>')
    parts.append(
        f'<div class="chart">{svg.timeline(incident.timeline, incident.start, incident.end)}</div>'
    )
    if incident.alerts:
        parts.append(_alert_rows(incident.alerts))
    if incident.anomalies:
        parts.append("<h3>Anomaly model</h3>")
        parts.extend(_anomaly_block(anomaly) for anomaly in incident.anomalies)
    parts.append("</div></details>")
    return "".join(parts)


def _incidents(result: ScanResult) -> str:
    if not result.incidents:
        return '<p class="muted">No incidents. No rule fired and no actor was anomalous.</p>'
    ordered = by_priority(result.incidents)
    shown = ordered[:MAX_INCIDENTS]
    html = [
        _incident(incident, open_=index < OPEN_INCIDENTS) for index, incident in enumerate(shown)
    ]
    if len(ordered) > len(shown):
        html.append(
            f'<p class="muted">{len(ordered) - len(shown):,} lower-scored incidents are omitted '
            "here; the JSON report lists all of them.</p>"
        )
    return "".join(html)


def _detections(result: ScanResult) -> str:
    alerts_per_rule: Counter[str] = Counter(alert.rule.id for alert in result.alerts)
    actors_per_rule: dict[str, set[str]] = {}
    for alert in result.alerts:
        actors_per_rule.setdefault(alert.rule.id, set()).update(alert.actors)
    if not alerts_per_rule:
        return f'<p class="muted">None of the {len(result.rules)} rules fired.</p>'
    rules = {rule.id: rule for rule in result.rules}
    ranked = sorted(alerts_per_rule, key=lambda rid: (-len(actors_per_rule[rid]), rid))
    chart = svg.bar_list(
        [
            (
                rid,
                len(actors_per_rule[rid]),
                f"{rules[rid].title}: {len(actors_per_rule[rid]):,} actors in "
                f"{alerts_per_rule[rid]:,} alerts",
            )
            for rid in ranked
        ],
        title="Distinct actors per detection",
    )
    rows = "".join(
        "<tr>"
        f'<td class="mono">{_e(rid)}</td><td>{_e(rules[rid].title)}</td>'
        f'<td><a href="{_e(technique_url(rules[rid].technique))}">'
        f"{_e(rules[rid].technique)}</a></td>"
        f"<td>{_chip(rules[rid].severity)}</td>"
        f'<td class="num">{alerts_per_rule[rid]:,}</td>'
        f'<td class="num">{len(actors_per_rule[rid]):,}</td>'
        "</tr>"
        for rid in ranked
    )
    silent = len(result.rules) - len(alerts_per_rule)
    return (
        '<div class="card"><p class="caption">Distinct actors per detection</p>'
        f'<div class="chart">{chart}</div>'
        '<div class="scroll"><table><thead><tr><th>Rule</th><th>Title</th><th>ATT&amp;CK</th>'
        '<th>Severity</th><th class="num">Alerts</th><th class="num">Actors</th></tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
        f'<p class="caption" style="margin-top:10px">{silent} of {len(result.rules)} loaded '
        "rules did not fire.</p></div>"
    )


def _anomalies(result: ScanResult) -> str:
    fitted = [m for m in result.models if m.scores]
    notes = "; ".join(
        f"{m.source}: {m.actors:,} actors scored, {m.skipped:,} with too few events skipped"
        if m.scores
        else f"{m.source}: {m.actors:,} actors, too few to fit a model"
        for m in result.models
    )
    if not result.anomalies:
        detail = notes or "the model was not run"
        return f'<p class="muted">No anomalous actors ({_e(detail)}).</p>'
    rows = "".join(
        "<tr>"
        f'<td class="mono">{_e(a.actor)}</td><td>{_e(a.source)}</td>'
        f'<td class="num">{a.score:.2f}</td><td class="num">{a.events:,}</td>'
        f"<td>{_features(a.features, with_share=False)}</td></tr>"
        for a in result.anomalies
    )
    threshold = fitted[0].threshold if fitted else 0.0
    return (
        f'<p class="caption">{_e(notes)}. Flag threshold {threshold:.2f}. Bars show each '
        "feature's share of the isolation (bits of node-size reduction across the forest).</p>"
        '<div class="card scroll"><table><thead><tr><th>Actor</th><th>Source</th>'
        '<th class="num">Score</th><th class="num">Events</th><th>What isolated it</th>'
        f"</tr></thead><tbody>{rows}</tbody></table></div>"
    )


def _ingest(result: ScanResult) -> str:
    stats = result.stats
    rows = "".join(
        "<tr>"
        f'<td class="mono">{_e(i.path)}</td><td>{_e(i.format)}</td>'
        f'<td class="num">{i.lines:,}</td><td class="num">{i.events:,}</td>'
        f'<td class="num">{i.ignored:,}</td><td class="num">{i.malformed:,}</td>'
        f"<td>{_e('; '.join(i.errors))}</td>"
        "</tr>"
        for i in result.inputs
    )
    parts = [
        '<div class="card scroll"><table><thead><tr><th>Input</th><th>Format</th>'
        '<th class="num">Lines</th><th class="num">Events</th><th class="num">Ignored</th>'
        f'<th class="num">Malformed</th><th>Errors</th></tr></thead><tbody>{rows}</tbody>'
        "</table></div>"
    ]
    if stats.malformed:
        reasons = ", ".join(f"{_e(r)} ({n:,})" for r, n in sorted(stats.reasons.items()))
        samples = "\n".join(
            f"{_basename(s.file)}:{s.line} [{s.reason}] {s.snippet!r}" for s in stats.samples
        )
        parts.append(
            f"<p>Malformed lines were counted and skipped: {reasons}.</p>"
            f'<details class="evidence"><summary>First {len(stats.samples)} samples</summary>'
            f"<pre>{_e(samples)}</pre></details>"
        )
    return "".join(parts)


def render_html(result: ScanResult, *, label: str | None = None) -> str:
    window = (
        f"{_ts(result.window[0])} to {_ts(result.window[1])} UTC" if result.window else "no events"
    )
    banner = f'<p class="banner">{_e(label)}</p>' if label else ""
    body = [
        '<div class="page">',
        '<header class="top"><div class="brand">',
        LOGO_SVG,
        "<h1>Argus scan report</h1></div>",
        f'<div class="meta">{_e(window)}</div></header>',
        banner,
        _tiles(result),
        "<h2>Activity</h2>",
        _activity(result),
        "<h2>Incidents, highest score first</h2>",
        _incidents(result),
        "<h2>Detections</h2>",
        _detections(result),
        "<h2>Anomalous actors</h2>",
        _anomalies(result),
        "<h2>Input</h2>",
        _ingest(result),
        "<footer>",
        f"Generated by Argus {_e(__version__)} on {_ts(generated_at())} UTC. ",
        "This page is self-contained: no scripts, no external requests. "
        "Links to attack.mitre.org open only when followed.",
        "</footer></div>",
    ]
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
        '<meta name="referrer" content="no-referrer">'
        "<title>Argus scan report</title>"
        f"<style>{CSS}</style></head><body>" + "".join(body) + "</body></html>\n"
    )


def write_html(result: ScanResult, path: Path, *, label: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(result, label=label), encoding="utf-8", newline="\n")
