"""Build the sample report published on GitHub Pages.

    python scripts/build_site.py                 # seed 7 into ./site
    python scripts/build_site.py --seed 3 --out /tmp/site

Simulates two days of labelled traffic, scans it with the default options and
writes ``index.html`` (the HTML report) and ``report.json``. Every link in the
output is relative or absolute to another host, so the site works under the
``/argus-threat-sentinel/`` sub-path. Set ``SOURCE_DATE_EPOCH`` to pin the
"generated" timestamp.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from argus.pipeline import scan
from argus.report.html import write_html
from argus.report.json_report import write_json
from argus.simulate import ACCESS_LOG, AUTH_LOG, simulate, write_simulation

ROOT = Path(__file__).resolve().parents[1]


def build(out: Path, *, seed: int, visitors: int) -> list[Path]:
    label = (
        f"Sample report generated from synthetic logs (seed {seed}). "
        "No real traffic: the addresses come from 198.18.0.0/15 and 2001:db8::/32, "
        "ranges reserved for benchmarks and documentation."
    )
    simulation = simulate(seed, visitors_per_day=visitors)
    with tempfile.TemporaryDirectory(prefix="argus-site-") as folder:
        files = write_simulation(simulation, Path(folder))
        result = scan([files[ACCESS_LOG], files[AUTH_LOG]])
    out.mkdir(parents=True, exist_ok=True)
    page, data = out / "index.html", out / "report.json"
    write_html(result, page, label=label)
    write_json(result, data, label=label)
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return [page, data]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--visitors", type=int, default=300, help="visitors per simulated day")
    parser.add_argument("--out", type=Path, default=ROOT / "site")
    args = parser.parse_args(argv)
    for path in build(args.out, seed=args.seed, visitors=args.visitors):
        print(f"wrote {path} ({path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
