# Changelog

All notable changes are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## 1.0.0 - 2026-11-17

First release.

### Ingest
- nginx/Apache combined and common access logs, including Apache's escaped
  quotes, IPv6 clients, trailing custom fields and repeated percent-encoding.
- OpenSSH messages from syslog auth logs, both BSD timestamps (year inferred,
  New Year rollover handled) and RFC 3339 timestamps.
- Format detection per file, transparent gzip, and accounting of every line as
  parsed, ignored or malformed (by reason, with samples). Malformed input is
  counted, never raised.

### Detection
- Rule language: TOML files with typed conditions, threshold (count or
  distinct values in a sliding window), sequence and new-value kinds, episode
  alerts, load-time errors naming file, rule and column.
- 25 built-in detections mapped to MITRE ATT&CK, each with a positive and a
  near-miss test.
- Isolation Forest written with NumPy, per-actor features for web and SSH
  actors, per-feature attributions of each score. Web actors are modelled by
  default; SSH is opt-in (`--ml-sources`).
- Correlation of alerts and anomalies into incidents (union-find over shared
  actors, 2-hour gap) with a 0-100 score and kill-chain ordering.

### Output
- Self-contained HTML report (inline CSS and SVG, no JavaScript, CSP), JSON
  report (schema 1, reproducible with `SOURCE_DATE_EPOCH`), terminal summary.
- `argus tail` follows a growing log through the rules and survives rotation
  and truncation.
- `argus scan --fail-on LEVEL` for use in scheduled jobs; exit codes 0, 1, 2.

### Evaluation
- Seeded simulator of labelled nginx and OpenSSH logs, `argus simulate`.
- `scripts/evaluate.py` writes `docs/EVALUATION.md` (per-rule precision and
  recall, anomaly ROC-AUC, misses by scenario); CI checks it is reproducible.
- `scripts/bench.py` writes `docs/BENCHMARKS.md`.
- Sample report generated from seed 7, published on GitHub Pages.
