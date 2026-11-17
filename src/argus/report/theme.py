"""Visual identity of the HTML report: one inline stylesheet and the logo mark.

Severity uses the four status colors and is always printed next to its label,
so color never carries meaning alone. Magnitude charts use a single blue that
is not a status color, so a bar never reads as "high severity".
"""

from __future__ import annotations

ACCENT = "#ff7b54"

LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="28" height="28" '
    'aria-hidden="true"><path d="M2.5 16C8 6.5 24 6.5 29.5 16C24 25.5 8 25.5 2.5 16Z" '
    f'fill="none" stroke="{ACCENT}" stroke-width="2.6" stroke-linejoin="round"/>'
    f'<circle cx="16" cy="16" r="5.2" fill="{ACCENT}"/></svg>'
)

CSS = """
:root {
  color-scheme: dark;
  --bg: #0a0a0a;
  --surface: #121212;
  --surface-2: #1a1a1a;
  --border: #262626;
  --text: #ededed;
  --text-2: #b9b8b2;
  --muted: #8f8e88;
  --accent: #ff7b54;
  --series: #3987e5;
  --series-hover: #66a3ee;
  --grid: #24241f;
  --axis: #3a3a36;
  --low: #8f8e88;
  --medium: #fab219;
  --high: #ec835a;
  --critical: #d03b3b;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 var(--sans); -webkit-font-smoothing: antialiased;
}
.page { max-width: 1120px; margin: 0 auto; padding: 32px 24px 56px; }
a { color: var(--text); text-decoration: underline; text-decoration-color: var(--accent);
    text-underline-offset: 2px; }
a:hover { color: var(--accent); }
h1, h2, h3 { font-weight: 600; letter-spacing: -0.01em; margin: 0; }
h1 { font-size: 22px; }
h2 { font-size: 17px; margin: 40px 0 12px; }
h3 { font-size: 14px; margin: 18px 0 8px; color: var(--text-2); }
p { margin: 0 0 10px; }
code, pre, .mono { font-family: var(--mono); font-size: 12.5px; }
header.top { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
header.top .brand { display: flex; align-items: center; gap: 10px; }
header.top .meta { color: var(--muted); font-size: 13px; margin-left: auto; }
.banner {
  margin: 18px 0 0; padding: 10px 14px; border: 1px solid var(--border);
  border-left: 3px solid var(--accent); background: var(--surface); color: var(--text-2);
}
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px;
         margin-top: 24px; }
.tile { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
        padding: 14px 16px; }
.tile .label { color: var(--muted); font-size: 12.5px; }
.tile .value { font-size: 26px; font-weight: 600; font-variant-numeric: tabular-nums; }
.tile .sub { color: var(--text-2); font-size: 12.5px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
        padding: 16px; }
.chart { margin: 4px 0 16px; }
.chart svg { width: 100%; height: auto; display: block; }
.caption { color: var(--muted); font-size: 12.5px; margin: 0 0 6px; }
.chip { display: inline-flex; align-items: center; gap: 6px; color: var(--text);
        font-size: 12.5px; white-space: nowrap; }
.dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }
.dot.sev-low { background: var(--low); }
.dot.sev-medium { background: var(--medium); }
.dot.sev-high { background: var(--high); }
.dot.sev-critical { background: var(--critical); }
details.incident { background: var(--surface); border: 1px solid var(--border);
                   border-radius: 8px; margin: 8px 0; }
details.incident > summary {
  list-style: none; cursor: pointer; padding: 12px 16px; display: grid;
  grid-template-columns: 92px 44px 82px 1fr; gap: 4px 12px; align-items: baseline;
}
details.incident > summary::-webkit-details-marker { display: none; }
details.incident > summary:hover { background: var(--surface-2); }
details.incident[open] > summary { border-bottom: 1px solid var(--border); }
.score { font-variant-numeric: tabular-nums; font-weight: 600; text-align: right; }
.inc-id { color: var(--muted); font-family: var(--mono); font-size: 12.5px; }
.inc-title { font-weight: 500; }
.inc-meta { grid-column: 4; color: var(--muted); font-size: 12.5px; }
.incident .body { padding: 12px 16px 16px; }
.chain { color: var(--text-2); font-size: 13px; }
.chain .sep { color: var(--muted); padding: 0 6px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 500; font-size: 12px;
     border-bottom: 1px solid var(--border); padding: 6px 8px; }
td { border-bottom: 1px solid var(--border); padding: 6px 8px; vertical-align: top; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
details.evidence > summary { cursor: pointer; color: var(--text-2); font-size: 12.5px; }
pre { background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
      padding: 10px 12px; overflow-x: auto; margin: 6px 0; color: var(--text-2);
      white-space: pre; }
.features { margin: 4px 0 0; padding: 0; list-style: none; }
.features li { display: flex; align-items: center; gap: 10px; font-size: 12.5px;
               color: var(--text-2); }
.features .fname { width: 120px; color: var(--text); }
.muted { color: var(--muted); }
footer { margin-top: 48px; color: var(--muted); font-size: 12.5px;
         border-top: 1px solid var(--border); padding-top: 16px; }
svg .bar { fill: var(--series); }
svg .col:hover .bar { fill: var(--series-hover); }
svg .hit { fill: transparent; }
svg .track { fill: var(--surface-2); }
svg .grid { stroke: var(--grid); stroke-width: 1; }
svg .axis { stroke: var(--axis); stroke-width: 1; }
svg .tick { fill: var(--muted); font: 11px var(--sans); }
svg .label, svg .row-label { fill: var(--text-2); font: 12px var(--sans); }
svg .rule-label { fill: var(--muted); font: 11.5px var(--mono); }
svg .value { fill: var(--text-2); font: 12px var(--mono); }
svg .sev-low { fill: var(--low); }
svg .sev-medium { fill: var(--medium); }
svg .sev-high { fill: var(--high); }
svg .sev-critical { fill: var(--critical); }
svg .anomaly { fill: var(--series); }
svg .span { stroke: var(--surface); stroke-width: 2; }
@media (max-width: 640px) {
  .page { padding: 20px 16px 40px; }
  header.top .meta { margin-left: 0; width: 100%; }
  details.incident > summary { grid-template-columns: 84px 36px 1fr; }
  .inc-id { display: none; }
  .inc-meta { grid-column: 1 / -1; }
  .inc-title { grid-column: 3; }
}
@media print {
  details.incident > .body { display: block; }
}
"""
