import re
from html.parser import HTMLParser
from pathlib import Path

from argus.pipeline import ScanOptions, ScanResult, scan
from argus.report.html import CSP, render_html, write_html


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)


def collect(html: str) -> _Collector:
    parser = _Collector()
    parser.feed(html)
    return parser


def test_html_escapes_attacker_content(scan_result: ScanResult) -> None:
    html = render_html(scan_result)
    assert "<script" not in html.lower()
    assert "%3Cscript%3E" in html
    assert "&lt;b&gt;not escaped?&lt;/b&gt;" in html
    parsed = collect(html)
    assert "script" not in parsed.tags
    assert "b" not in parsed.tags
    assert not any(name.startswith("on") for name, _ in parsed.attributes)


def test_page_is_self_contained(scan_result: ScanResult) -> None:
    html = render_html(scan_result)
    assert f'content="{CSP}"' in html
    assert "default-src 'none'" in CSP
    parsed = collect(html)
    assert "link" not in parsed.tags
    assert "img" not in parsed.tags
    sources = [value for name, value in parsed.attributes if name in ("src", "href")]
    assert all(value and value.startswith("https://attack.mitre.org/") for value in sources)
    assert html.count("<details") == html.count("</details>")
    assert html.rstrip().endswith("</html>")


def test_sections_and_incidents_are_present(scan_result: ScanResult) -> None:
    html = render_html(scan_result, label="Sample report from synthetic logs")
    assert '<p class="banner">Sample report from synthetic logs</p>' in html
    for heading in ("Activity", "Incidents, highest score first", "Detections", "Input"):
        assert f"<h2>{heading}</h2>" in html
    for incident in scan_result.incidents:
        assert f'id="{incident.id}"' in html
    assert "web-scanner-user-agent" in html
    assert "not combined log format (1)" in html
    assert len(re.findall(r"<details class=\"incident\"[^>]* open>", html)) == min(
        3, len(scan_result.incidents)
    )


def test_empty_scan_renders(tmp_path: Path) -> None:
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    html = render_html(scan([empty], ScanOptions()))
    assert "No incidents" in html
    assert "No events were parsed" in html


def test_write_html(scan_result: ScanResult, tmp_path: Path) -> None:
    path = tmp_path / "nested" / "report.html"
    write_html(scan_result, path)
    assert path.read_text(encoding="utf-8").startswith("<!doctype html>")
