from argus import __version__
from argus.pipeline import ScanResult
from argus.report.terminal import format_alert, render_summary


def test_summary_lists_counts_and_top_incidents(scan_result: ScanResult) -> None:
    text = render_summary(scan_result)
    assert text.startswith(f"argus {__version__}: 2 input(s)")
    assert "1 malformed" in text
    assert f"{len(scan_result.incidents)} incidents (" in text
    assert "ID        LEVEL" in text
    for incident in scan_result.incidents[:3]:
        assert incident.id in text
    assert "malformed lines (skipped): not combined log format 1" in text
    assert "\x1b[" not in text


def test_summary_truncates_to_top(scan_result: ScanResult) -> None:
    text = render_summary(scan_result, top=1)
    if len(scan_result.incidents) > 1:
        assert f"... {len(scan_result.incidents) - 1} more" in text


def test_color_adds_ansi_codes(scan_result: ScanResult) -> None:
    assert "\x1b[" in render_summary(scan_result, color=True)


def test_format_alert(scan_result: ScanResult) -> None:
    alert = scan_result.alerts[0]
    line = format_alert(alert)
    assert alert.rule.id in line
    assert alert.rule.technique in line
    assert line.startswith(f"{alert.fired_ts:%Y-%m-%dT%H:%M:%S}Z  ")
    assert f"({alert.count:,} event" in line
