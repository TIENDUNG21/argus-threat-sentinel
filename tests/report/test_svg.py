import re
import xml.etree.ElementTree as ET
from datetime import timedelta

from argus.alerts import Severity
from argus.correlate import TimelineEntry
from argus.report.svg import bar_list, column_chart, share_bar, timeline
from tests.helpers import at


def parse(svg: str) -> ET.Element:
    return ET.fromstring(svg)


def test_column_chart_draws_one_bar_per_nonzero_bucket_with_tooltips() -> None:
    svg = column_chart(
        [0, 5, 10, 0, 2],
        title="Web events per hour",
        tick_labels={0: "00:00", 4: "04:00"},
        tooltips=["00:00 0", "01:00 5", "02:00 10", "03:00 0", "04:00 2"],
    )
    root = parse(svg)
    bars = [el for el in root.iter("{http://www.w3.org/2000/svg}path") if el.get("class") == "bar"]
    assert len(bars) == 3
    assert "02:00 10" in svg
    assert 'role="img"' in svg
    assert "Web events per hour" in svg
    tops = sorted(float(bar.get("d", "").split(" V")[1].split()[0]) for bar in bars)
    assert tops[0] < tops[-1]


def test_column_chart_markers_carry_level_class_and_title() -> None:
    svg = column_chart([1, 1, 1], title="x", markers=[(1, Severity.CRITICAL, "INC-0001 critical")])
    assert 'class="marker sev-critical"' in svg
    assert "<title>INC-0001 critical</title>" in svg


def test_column_chart_with_no_data_still_renders() -> None:
    parse(column_chart([], title="Empty"))
    parse(column_chart([0, 0], title="Zero"))


def test_text_is_escaped() -> None:
    svg = bar_list([("<script>alert(1)</script>", 3, "x & y")], title="t")
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg
    assert "x &amp; y" in svg
    parse(svg)


def test_bar_list_scales_to_the_largest_value_and_labels_values() -> None:
    svg = bar_list([("a", 10, "a"), ("b", 5, "b")], title="Alerts per rule")
    widths = [float(w) for w in re.findall(r'class="bar"[^>]*width="([\d.]+)"', svg)]
    assert widths[0] == 2 * widths[1]
    assert ">10<" in svg and ">5<" in svg


def test_timeline_has_a_row_per_tactic_in_kill_chain_order() -> None:
    entries = [
        TimelineEntry(
            at(600), at(900), "credential-access", "Brute", "r1", "T1110", Severity.MEDIUM
        ),
        TimelineEntry(at(0), at(60), "reconnaissance", "Scan", "r2", "T1595", Severity.LOW),
        TimelineEntry(at(950), at(950), "anomaly", "Anomalous web behaviour", None, None, None),
    ]
    svg = timeline(entries, at(0), at(0) + timedelta(seconds=1000))
    parse(svg)
    rows = re.findall(r'class="row-label"[^>]*>([^<]+)<', svg)
    assert rows == ["Reconnaissance", "Credential Access", "Anomaly model"]
    assert "sev-medium" in svg and "sev-low" in svg and "anomaly" in svg


def test_share_bar_width_tracks_share() -> None:
    assert 'width="40.0"' in share_bar(0.5, width=80)
    assert 'width="0.0"' in share_bar(0.0, width=80)
