import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_site.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_site", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("site")
    assert _load().main(["--seed", "3", "--visitors", "40", "--out", str(out)]) == 0
    return out


def test_site_contains_labelled_report(site: Path) -> None:
    assert {p.name for p in site.iterdir()} == {"index.html", "report.json", ".nojekyll"}
    page = (site / "index.html").read_text(encoding="utf-8")
    assert "Sample report generated from synthetic logs (seed 3)" in page
    document = json.loads((site / "report.json").read_text(encoding="utf-8"))
    assert document["label"].startswith("Sample report")


def test_site_has_no_root_relative_links(site: Path) -> None:
    """Pages serves the site under /argus-threat-sentinel/, so "/x" would 404."""
    page = (site / "index.html").read_text(encoding="utf-8")
    targets = re.findall(r'(?:href|src|action)\s*=\s*"([^"]*)"', page)
    assert targets, "expected ATT&CK links in the sample report"
    for target in targets:
        assert not target.startswith("/"), target
        assert target.startswith(("https://", "#")), target
