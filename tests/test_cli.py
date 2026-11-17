import json
from pathlib import Path

import pytest

from argus import __version__
from argus.cli import main

BAD_RULE = """
[[rule]]
id = "typo"
title = "Typo"
severity = "low"
technique = "T1190"
when = 'stauts == 500'
"""


@pytest.fixture(scope="module")
def logs(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("sim")
    assert main(["simulate", "--out", str(folder), "--seed", "3", "--visitors", "40"]) == 0
    return folder


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert f"argus {__version__}" in capsys.readouterr().out


def test_no_command_prints_help_and_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "usage: argus" in capsys.readouterr().err


def test_simulate_writes_logs_and_labels(logs: Path) -> None:
    assert {p.name for p in logs.iterdir()} == {"access.log", "auth.log", "labels.json"}


def test_scan_writes_reports_and_summary(
    logs: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    html, report = tmp_path / "report.html", tmp_path / "report.json"
    code = main(
        [
            "scan",
            str(logs / "access.log"),
            str(logs / "auth.log"),
            "--html",
            str(html),
            "--json",
            str(report),
            "--label",
            "Synthetic sample",
            "--color",
            "never",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"argus {__version__}: 2 input(s)")
    assert "incidents (" in out
    assert "Synthetic sample" in html.read_text(encoding="utf-8")
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["label"] == "Synthetic sample"
    assert document["summary"]["incidents"] > 0


def test_fail_on_returns_1_when_threshold_is_reached(logs: Path) -> None:
    assert main(["scan", str(logs / "auth.log"), "--quiet", "--fail-on", "high"]) == 1
    assert (
        main(
            [
                "scan",
                str(logs / "auth.log"),
                "--quiet",
                "--no-builtin",
                "--no-ml",
                "--fail-on",
                "low",
            ]
        )
        == 0
    )


def test_unreadable_input_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path / "missing.log"), "--quiet"]) == 2
    assert "file not found" in capsys.readouterr().err


def test_bad_rule_file_exits_2_with_location(
    tmp_path: Path, logs: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text(BAD_RULE, encoding="utf-8")
    assert main(["rules", "check", str(bad)]) == 2
    err = capsys.readouterr().err
    assert "rule 'typo'" in err
    assert "did you mean 'status'" in err
    assert main(["scan", str(logs / "auth.log"), "--rules", str(bad), "--quiet"]) == 2


def test_rules_list_and_check(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["rules", "list"]) == 0
    out = capsys.readouterr().out
    assert "ssh-brute-force" in out and "T1110.001" in out
    assert len(out.strip().splitlines()) == 26
    good = tmp_path / "good.toml"
    good.write_text(BAD_RULE.replace("stauts", "status"), encoding="utf-8")
    assert main(["rules", "check", str(good)]) == 0
    assert "1 rules OK" in capsys.readouterr().out


def test_ml_sources_validation() -> None:
    with pytest.raises(SystemExit):
        main(["scan", "x.log", "--ml-sources", "ftp"])


def test_tail_needs_a_format_for_an_empty_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "new.log"
    empty.write_text("", encoding="utf-8")
    assert main(["tail", str(empty)]) == 2
    assert "pass --format" in capsys.readouterr().err
