import json
from pathlib import Path

import pytest

from argus import __version__
from argus.pipeline import ScanResult
from argus.report.json_report import SCHEMA_VERSION, build_json, write_json


def test_document_shape(scan_result: ScanResult) -> None:
    document = build_json(scan_result, label="Sample")
    assert document["tool"] == "argus"
    assert document["version"] == __version__
    assert document["schema"] == SCHEMA_VERSION
    assert document["label"] == "Sample"
    assert document["ingest"]["malformed"] == 1
    assert document["ingest"]["malformed_reasons"] == {"not combined log format": 1}
    assert document["ingest"]["malformed_samples"][0]["line"] == 264
    assert document["rules"]["loaded"] == 25
    assert document["summary"]["alerts"] == len(scan_result.alerts)
    assert set(document["summary"]["incidents_by_level"]) == {"critical", "high", "medium", "low"}
    assert document["window"]["start"].endswith("Z")


def test_incidents_reference_alerts_by_id(scan_result: ScanResult) -> None:
    document = build_json(scan_result)
    alert_ids = {alert["id"] for alert in document["alerts"]}
    referenced = {aid for incident in document["incidents"] for aid in incident["alerts"]}
    assert referenced == alert_ids
    attacker = next(i for i in document["incidents"] if "198.18.81.2" in i["actors"])
    assert {"reconnaissance", "credential-access"} <= set(attacker["tactics"])
    assert attacker["timeline"][0]["start"] <= attacker["timeline"][-1]["start"]


def test_alert_fields(scan_result: ScanResult) -> None:
    document = build_json(scan_result)
    xss = next(a for a in document["alerts"] if a["rule"] == "web-xss-probe")
    assert xss["technique"] == "T1190"
    assert xss["technique_url"] == "https://attack.mitre.org/techniques/T1190/"
    assert xss["actors"] == ["198.18.81.1"]
    assert xss["group"] == {"ip": "198.18.81.1"}
    assert xss["evidence"][0]["text"].startswith("198.18.81.1")


def test_source_date_epoch_fixes_the_timestamp(
    scan_result: ScanResult, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1772409600")
    assert build_json(scan_result)["generated_at"] == "2026-03-02T00:00:00Z"


def test_write_json_round_trips(scan_result: ScanResult, tmp_path: Path) -> None:
    path = tmp_path / "out" / "report.json"
    write_json(scan_result, path)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["summary"]["incidents"] == len(scan_result.incidents)
    assert loaded["anomalies"] == build_json(scan_result)["anomalies"]


def test_two_scans_of_the_same_input_give_identical_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.pipeline import scan
    from argus.simulate import ACCESS_LOG, AUTH_LOG, simulate, write_simulation

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1772409600")
    files = write_simulation(simulate(5, visitors_per_day=40), tmp_path / "logs")
    outputs = []
    for run in range(2):
        out = tmp_path / f"run{run}.json"
        write_json(scan([files[ACCESS_LOG], files[AUTH_LOG]]), out)
        outputs.append(out.read_bytes())
    assert outputs[0] == outputs[1]
