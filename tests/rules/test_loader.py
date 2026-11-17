from datetime import timedelta
from pathlib import Path

import pytest

from argus.alerts import Severity
from argus.attack import TACTIC_ORDER, TECHNIQUES, technique_url
from argus.rules.errors import RuleError
from argus.rules.loader import load_rules, load_rules_text
from argus.rules.model import NewValue, Sequence, Threshold

MINIMAL = """
[[rule]]
id = "demo"
title = "Demo"
severity = "low"
technique = "T1190"
when = 'status == 500'
"""


def test_minimal_rule_gets_defaults() -> None:
    (rule,) = load_rules_text(MINIMAL, "demo.toml")
    assert rule.id == "demo"
    assert rule.severity is Severity.LOW
    assert rule.tactic == "initial-access"
    assert rule.technique_name == "Exploit Public-Facing Application"
    assert rule.source is None
    assert rule.group_by == ("ip",)
    assert rule.kind == Threshold(window=timedelta(minutes=10), count=1, distinct=None)
    assert rule.origin == "demo.toml"


def test_threshold_rule() -> None:
    text = """
[[rule]]
id = "spray"
title = "Spray"
severity = "medium"
technique = "T1110.003"
source = "ssh"
when = 'action == "failed_password"'
group_by = ["ip"]
[rule.threshold]
count = 6
window = "15m"
distinct = "user"
"""
    (rule,) = load_rules_text(text, "x.toml")
    assert rule.kind == Threshold(window=timedelta(minutes=15), count=6, distinct="user")
    assert rule.source == "ssh"


def test_sequence_rule() -> None:
    text = """
[[rule]]
id = "seq"
title = "Seq"
severity = "critical"
technique = "T1110.001"
source = "ssh"
[rule.sequence]
within = "30m"
steps = [
  { when = 'action == "failed_password"', count = 5 },
  { when = 'action startswith "accepted"' },
]
"""
    (rule,) = load_rules_text(text, "x.toml")
    assert isinstance(rule.kind, Sequence)
    assert rule.kind.within == timedelta(minutes=30)
    assert [step.count for step in rule.kind.steps] == [5, 1]
    assert rule.when_text == ""


def test_new_value_rule() -> None:
    text = """
[[rule]]
id = "new"
title = "New"
severity = "medium"
technique = "T1078"
source = "ssh"
when = 'action startswith "accepted"'
group_by = ["user"]
new_value = { field = "ip", learn = "24h" }
"""
    (rule,) = load_rules_text(text, "x.toml")
    assert rule.kind == NewValue(field="ip", learn=timedelta(hours=24))


def test_custom_technique_needs_tactic() -> None:
    text = MINIMAL.replace('"T1190"', '"T1046"') + 'tactic = "discovery"\n'
    (rule,) = load_rules_text(text, "x.toml")
    assert rule.tactic == "discovery"


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    [
        (lambda t: t + 'colour = "red"\n', "unknown key 'colour'"),
        (lambda t: t.replace('"low"', '"severe"'), "severity must be one of"),
        (lambda t: t.replace('"T1190"', '"1190"'), "technique must look like"),
        (lambda t: t.replace('"T1190"', '"T9999"'), "not in the built-in catalog"),
        (lambda t: t.replace("status == 500", "stauts == 500"), "did you mean 'status'"),
        (lambda t: t.replace("status == 500", 'status ~ "("'), "column"),
        (lambda t: t + '[rule.threshold]\nwindow = "5 minutes"\n', "invalid duration"),
        (lambda t: t + "[rule.threshold]\ncount = 0\n", "count must be an integer >= 1"),
        (lambda t: t + "[rule.threshold]\nlimit = 3\n", "unknown key 'limit'"),
        (lambda t: t + 'group_by = ["nope"]\n', "unknown field 'nope'"),
        (lambda t: t + 'source = "ftp"\n', "source must be"),
        (lambda t: t.replace('id = "demo"', 'id = "Bad Id"'), "id must be"),
        (lambda t: t.replace('title = "Demo"\n', ""), "missing required key 'title'"),
        (
            lambda t: t + 'new_value = { field = "ip", learn = "1h" }\n[rule.threshold]\n',
            "at most one of",
        ),
        (
            lambda t: t + "[rule.sequence]\nwithin = \"5m\"\nsteps = [{ when = 'status == 1' }]\n",
            "at least two steps",
        ),
        (lambda t: t + "]]]", "invalid TOML"),
        (lambda t: t + MINIMAL, "duplicate rule id 'demo'"),
    ],
)
def test_invalid_rules_raise_rule_error(mutation: object, fragment: str) -> None:
    assert callable(mutation)
    with pytest.raises(RuleError) as exc:
        load_rules_text(mutation(MINIMAL), "custom.toml")
    assert fragment in str(exc.value)
    assert "custom.toml" in str(exc.value)


def test_error_names_the_rule_id() -> None:
    with pytest.raises(RuleError, match="rule 'demo'"):
        load_rules_text(MINIMAL.replace('"low"', '"severe"'), "custom.toml")


def test_top_level_keys_other_than_rule_are_rejected() -> None:
    with pytest.raises(RuleError, match="unknown top-level key 'rules'"):
        load_rules_text("[[rules]]\nid = 'x'\n", "custom.toml")


def test_load_rules_from_files_rejects_duplicates_across_files(tmp_path: Path) -> None:
    first = tmp_path / "a.toml"
    second = tmp_path / "b.toml"
    first.write_text(MINIMAL, encoding="utf-8")
    second.write_text(MINIMAL, encoding="utf-8")
    assert len(load_rules([first])) == 1
    with pytest.raises(RuleError, match="duplicate rule id 'demo'"):
        load_rules([first, second])


def test_missing_rule_file_is_a_rule_error(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="cannot read"):
        load_rules([tmp_path / "missing.toml"])


def test_catalog_is_consistent() -> None:
    for technique_id, technique in TECHNIQUES.items():
        assert technique.id == technique_id
        assert technique.tactic in TACTIC_ORDER
    assert technique_url("T1110.001") == "https://attack.mitre.org/techniques/T1110/001/"
    assert technique_url("T1190") == "https://attack.mitre.org/techniques/T1190/"


def test_severity_parse_and_order() -> None:
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert Severity.MEDIUM.label == "medium"
    with pytest.raises(ValueError, match="severity"):
        Severity.parse("urgent")
