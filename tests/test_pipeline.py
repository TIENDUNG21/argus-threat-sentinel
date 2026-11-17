from datetime import timedelta
from pathlib import Path

import pytest

from argus.ml.detector import AnomalyConfig
from argus.pipeline import ScanOptions, load_rule_set, scan
from argus.rules.errors import RuleError

UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"


def access_line(ip: str, minute: int, second: int, target: str, status: int = 200) -> str:
    return (
        f'{ip} - - [02/Mar/2026:10:{minute:02d}:{second:02d} +0000] "GET {target} HTTP/1.1" '
        f'{status} 512 "-" "{UA}"'
    )


def auth_line(minute: int, second: int, message: str) -> str:
    return f"2026-03-02T10:{minute:02d}:{second:02d}+00:00 web01 sshd[100]: {message}"


@pytest.fixture
def logs(tmp_path: Path) -> tuple[Path, Path]:
    access = [
        access_line("198.18.60.1", 1, s, f"/products?id={s}'%20OR%20'1'='1", 500) for s in range(5)
    ]
    access += [access_line(f"198.18.61.{i}", 2, i, "/") for i in range(20)]
    access += ["this is not a log line", ""]
    auth = [
        auth_line(5, s, "Failed password for root from 198.18.60.1 port 4000 ssh2")
        for s in range(0, 40, 2)
    ]
    auth.append("2026-03-02T10:06:00+00:00 web01 CRON[5]: pam_unix(cron:session): session opened")
    access_path = tmp_path / "access.log"
    auth_path = tmp_path / "auth.log"
    access_path.write_text("\n".join(access) + "\n", encoding="utf-8")
    auth_path.write_text("\n".join(auth) + "\n", encoding="utf-8")
    return access_path, auth_path


def test_scan_combines_sources_into_one_incident(logs: tuple[Path, Path]) -> None:
    result = scan(list(logs), ScanOptions(ml=False))
    assert [(i.path.endswith("access.log"), i.format) for i in result.inputs] == [
        (True, "combined"),
        (False, "sshd"),
    ]
    assert result.stats.malformed == 1
    assert result.stats.ignored == 2
    assert result.events == 45
    rule_ids = {alert.rule.id for alert in result.alerts}
    assert {"web-sqli-probe", "ssh-brute-force"} <= rule_ids
    attacker = [i for i in result.incidents if "198.18.60.1" in i.actors]
    assert len(attacker) == 1
    assert {"web-sqli-probe", "ssh-brute-force"} <= {a.rule.id for a in attacker[0].alerts}
    assert result.window is not None
    assert result.window[1] - result.window[0] < timedelta(minutes=10)
    assert result.anomalies == []
    assert result.models == []


def test_activity_histogram_counts_events_per_source(logs: tuple[Path, Path]) -> None:
    result = scan(list(logs), ScanOptions(ml=False))
    assert result.activity.bucket == timedelta(hours=1)
    assert sum(result.activity.counts["web"]) == 25
    assert sum(result.activity.counts["ssh"]) == 20


def test_ml_runs_when_enough_actors(logs: tuple[Path, Path]) -> None:
    result = scan([logs[0]], ScanOptions(anomaly=AnomalyConfig(min_events=1, min_actors=5)))
    assert [model.source for model in result.models] == ["web"]
    assert result.models[0].actors == 21


def test_missing_input_is_reported_not_raised(tmp_path: Path) -> None:
    result = scan([tmp_path / "missing.log"], ScanOptions(ml=False))
    assert result.stats.errors == [f"{tmp_path / 'missing.log'}: file not found"]
    assert result.incidents == []
    assert result.window is None


def test_custom_rules_are_added_and_checked(tmp_path: Path, logs: tuple[Path, Path]) -> None:
    custom = tmp_path / "custom.toml"
    custom.write_text(
        "[[rule]]\nid = 'home-page'\ntitle = 'Home page'\nseverity = 'low'\n"
        "technique = 'T1595'\nsource = 'web'\nwhen = 'path == \"/\"'\n",
        encoding="utf-8",
    )
    result = scan([logs[0]], ScanOptions(ml=False, builtin=False, rule_paths=(custom,)))
    assert [rule.id for rule in result.rules] == ["home-page"]
    assert {alert.rule.id for alert in result.alerts} == {"home-page"}
    clash = tmp_path / "clash.toml"
    clash.write_text(custom.read_text(encoding="utf-8").replace("home-page", "ssh-brute-force"))
    with pytest.raises(RuleError, match="duplicate rule id 'ssh-brute-force'"):
        load_rule_set(ScanOptions(rule_paths=(clash,)))
