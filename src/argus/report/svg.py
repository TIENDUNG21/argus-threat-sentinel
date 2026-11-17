"""Inline SVG charts for the HTML report.

Pure functions returning SVG markup. Colors come from CSS classes defined in
:mod:`argus.report.theme` (``bar``, ``sev-*``, ``axis``, ...), so a chart never
hard-codes a color. Hover details use native ``<title>`` tooltips, which work
without JavaScript. Every piece of text is escaped: log content is attacker
controlled.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from html import escape

from argus.alerts import Severity
from argus.attack import TACTIC_NAMES, tactic_rank
from argus.correlate import TimelineEntry

SVG_NS = 'xmlns="http://www.w3.org/2000/svg"'


def _e(text: object) -> str:
    return escape(str(text), quote=True)


def _open(width: float, height: float, title: str) -> str:
    return (
        f'<svg {SVG_NS} viewBox="0 0 {width:.0f} {height:.0f}" role="img" '
        f'aria-label="{_e(title)}" preserveAspectRatio="xMinYMin meet">'
        f"<title>{_e(title)}</title>"
    )


def _rounded_top(x: float, y: float, w: float, h: float, r: float = 2.0) -> str:
    """Path for a column with rounded data end and a square baseline."""
    r = min(r, w / 2, h)
    return (
        f"M{x:.1f},{y + h:.1f} V{y + r:.1f} Q{x:.1f},{y:.1f} {x + r:.1f},{y:.1f} "
        f"H{x + w - r:.1f} Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h:.1f} Z"
    )


def _nice_max(value: int) -> int:
    if value <= 0:
        return 1
    magnitude = 10 ** (len(str(value)) - 1)
    for step in (1, 2, 2.5, 5, 10):
        top = int(step * magnitude)
        if top >= value:
            return top
    return value


def _compact(value: int) -> str:
    return f"{value / 1000:g}K" if value >= 10_000 else f"{value:,}"


def column_chart(
    values: Sequence[int],
    *,
    title: str,
    tick_labels: Mapping[int, str] | None = None,
    tooltips: Sequence[str] | None = None,
    markers: Sequence[tuple[int, Severity, str]] = (),
    width: int = 960,
    height: int = 170,
) -> str:
    """Columns over time with a recessive axis; ``markers`` are small severity
    triangles under the axis (for example where incidents start)."""
    left, right, top, bottom = 44.0, 8.0, 10.0, 40.0
    plot_w = width - left - right
    plot_h = height - top - bottom
    peak = _nice_max(max(values, default=0))
    slot = plot_w / max(len(values), 1)
    bar_w = max(1.0, min(24.0, slot - 2.0))
    base_y = top + plot_h
    parts = [_open(width, height, title)]
    for fraction in (0.5, 1.0):
        y = base_y - plot_h * fraction
        parts.append(
            f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="tick" x="{left - 6}" y="{y + 4:.1f}" text-anchor="end">'
            f"{_e(_compact(int(peak * fraction)))}</text>"
        )
    parts.append(
        f'<line class="axis" x1="{left}" x2="{width - right}" y1="{base_y}" y2="{base_y}"/>'
    )
    parts.append(
        f'<text class="tick" x="{left - 6}" y="{base_y + 4:.1f}" text-anchor="end">0</text>'
    )
    for index, value in enumerate(values):
        if value <= 0:
            continue
        h = max(1.0, plot_h * value / peak)
        x = left + index * slot + (slot - bar_w) / 2
        tip = tooltips[index] if tooltips else f"{value:,}"
        parts.append(
            f'<g class="col"><title>{_e(tip)}</title>'
            f'<rect class="hit" x="{left + index * slot:.1f}" y="{top}" '
            f'width="{slot:.1f}" height="{plot_h:.1f}"/>'
            f'<path class="bar" d="{_rounded_top(x, base_y - h, bar_w, h)}"/></g>'
        )
    for index, label in (tick_labels or {}).items():
        x = left + index * slot + slot / 2
        parts.append(
            f'<line class="axis" x1="{x:.1f}" x2="{x:.1f}" y1="{base_y}" y2="{base_y + 4}"/>'
        )
        parts.append(
            f'<text class="tick" x="{x:.1f}" y="{base_y + 16:.1f}" text-anchor="middle">'
            f"{_e(label)}</text>"
        )
    for index, level, tip in markers:
        x = left + index * slot + slot / 2
        y = base_y + 22
        parts.append(
            f'<path class="marker sev-{level.label}" d="M{x:.1f},{y:.1f} l5,9 h-10 Z">'
            f"<title>{_e(tip)}</title></path>"
        )
    parts.append("</svg>")
    return "".join(parts)


def bar_list(
    rows: Sequence[tuple[str, int, str]], *, title: str, width: int = 960, label_width: int = 250
) -> str:
    """Horizontal bars, one per (label, value, tooltip), value printed at the tip."""
    row_h = 26.0
    height = max(row_h * len(rows) + 8, 30)
    plot_w = width - label_width - 60
    peak = max((value for _, value, _ in rows), default=0) or 1
    parts = [_open(width, height, title)]
    for index, (label, value, tip) in enumerate(rows):
        y = 4 + index * row_h
        w = plot_w * value / peak
        parts.append(f"<g><title>{_e(tip)}</title>")
        parts.append(
            f'<text class="label" x="{label_width - 10}" y="{y + 15:.1f}" text-anchor="end">'
            f"{_e(label)}</text>"
        )
        parts.append(
            f'<rect class="bar" x="{label_width}" y="{y + 4:.1f}" width="{w:.1f}" '
            'height="14" rx="2"/>'
        )
        parts.append(
            f'<text class="value" x="{label_width + w + 6:.1f}" y="{y + 15:.1f}">{value:,}</text>'
        )
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


def share_bar(share: float, *, width: int = 80) -> str:
    """A thin 6px bar showing a 0-1 share (used for feature attributions)."""
    filled = max(0.0, min(1.0, share)) * width
    return (
        f'<svg {SVG_NS} class="share" viewBox="0 0 {width} 6" width="{width}" height="6" '
        f'aria-hidden="true"><rect class="track" width="{width}" height="6" rx="3"/>'
        f'<rect class="bar" width="{filled:.1f}" height="6" rx="3"/></svg>'
    )


def _row_label(tactic: str) -> str:
    if tactic == "anomaly":
        return "Anomaly model"
    return TACTIC_NAMES.get(tactic, tactic.replace("-", " ").title())


def timeline(
    entries: Sequence[TimelineEntry], start: datetime, end: datetime, *, width: int = 960
) -> str:
    """Kill-chain timeline: one row per tactic (in ATT&CK order), time on x."""
    tactics = sorted(
        {entry.tactic for entry in entries}, key=lambda t: (t == "anomaly", tactic_rank(t))
    )
    label_w, right, row_h = 150.0, 12.0, 24.0
    height = row_h * len(tactics) + 30
    plot_w = width - label_w - right
    span = max((end - start).total_seconds(), 1.0)
    parts = [_open(width, height, "Incident timeline by ATT&CK tactic")]
    for row, tactic in enumerate(tactics):
        y = row * row_h
        parts.append(
            f'<line class="grid" x1="{label_w}" x2="{width - right}" '
            f'y1="{y + row_h:.1f}" y2="{y + row_h:.1f}"/>'
        )
        parts.append(
            f'<text class="row-label" x="{label_w - 10}" y="{y + 16:.1f}" text-anchor="end">'
            f"{_e(_row_label(tactic))}</text>"
        )
        for entry in (e for e in entries if e.tactic == tactic):
            x0 = label_w + plot_w * (entry.ts - start).total_seconds() / span
            x1 = label_w + plot_w * (entry.end - start).total_seconds() / span
            w = max(6.0, x1 - x0)
            css = "anomaly" if entry.severity is None else f"sev-{entry.severity.label}"
            tip = f"{entry.label} - {entry.ts:%Y-%m-%d %H:%M:%S} UTC, {entry.count:,} events"
            if entry.technique:
                tip += f", {entry.technique}"
            parts.append(
                f'<rect class="span {css}" x="{min(x0, width - right - w):.1f}" y="{y + 6:.1f}" '
                f'width="{w:.1f}" height="12" rx="3"><title>{_e(tip)}</title></rect>'
            )
    axis_y = row_h * len(tactics)
    parts.append(
        f'<line class="axis" x1="{label_w}" x2="{width - right}" y1="{axis_y}" y2="{axis_y}"/>'
    )
    parts.append(f'<text class="tick" x="{label_w}" y="{axis_y + 18}">{start:%m-%d %H:%M}</text>')
    parts.append(
        f'<text class="tick" x="{width - right}" y="{axis_y + 18}" text-anchor="end">'
        f"{end:%m-%d %H:%M} UTC</text>"
    )
    parts.append("</svg>")
    return "".join(parts)
