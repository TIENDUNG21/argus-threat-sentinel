from pathlib import Path

from argus.attack import TECHNIQUES
from argus.rules.loader import builtin_rules
from tests.detections import (
    test_ssh_detections,
    test_web_access_detections,
    test_web_exploit_detections,
    test_web_recon_detections,
)

ROOT = Path(__file__).resolve().parents[2]

EXPECTED_TECHNIQUES = {
    "ssh-brute-force": "T1110.001",
    "ssh-password-spray": "T1110.003",
    "ssh-brute-force-success": "T1110.001",
    "ssh-root-login": "T1078.003",
    "ssh-new-source-for-user": "T1078",
    "ssh-banner-scan": "T1595.001",
    "ssh-max-auth-exceeded": "T1110.001",
    "web-scanner-user-agent": "T1595.002",
    "web-wordlist-scan": "T1595.003",
    "web-sensitive-file-probe": "T1595.003",
    "web-sensitive-file-exposed": "T1552.001",
    "web-user-enumeration": "T1589",
    "web-sqli-probe": "T1190",
    "web-xss-probe": "T1190",
    "web-path-traversal": "T1190",
    "web-command-injection": "T1190",
    "web-ssti-probe": "T1190",
    "web-log4shell-probe": "T1190",
    "web-shellshock-probe": "T1190",
    "web-cloud-metadata-ssrf": "T1552.005",
    "web-shell-known-name": "T1505.003",
    "web-shell-upload-exec": "T1505.003",
    "web-login-brute-force": "T1110",
    "web-credential-stuffing": "T1110.004",
    "web-request-flood": "T1499.002",
}

ALL_CASES = {
    **test_ssh_detections.CASES,
    **test_web_recon_detections.CASES,
    **test_web_exploit_detections.CASES,
    **test_web_access_detections.CASES,
}


def test_builtin_rules_and_techniques_are_pinned() -> None:
    assert {rule.id: rule.technique for rule in builtin_rules()} == EXPECTED_TECHNIQUES


def test_every_builtin_rule_has_positive_and_negative_cases() -> None:
    for rule in builtin_rules():
        case = ALL_CASES.get(rule.id)
        assert case is not None, f"no test cases registered for {rule.id}"
        assert case.positives, f"{rule.id} has no positive case"
        assert case.negatives, f"{rule.id} has no negative case"
    assert set(ALL_CASES) == set(EXPECTED_TECHNIQUES)


def test_every_technique_is_in_the_catalog_with_its_tactic() -> None:
    for rule in builtin_rules():
        technique = TECHNIQUES[rule.technique]
        assert rule.tactic == technique.tactic
        assert rule.title
        assert len(rule.description) > 40
        assert rule.source in ("web", "ssh")


def test_rules_reference_lists_every_rule_with_its_technique() -> None:
    lines = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8").splitlines()
    for rule in builtin_rules():
        rows = [line for line in lines if f"`{rule.id}`" in line]
        assert rows, f"docs/RULES.md does not list {rule.id}"
        assert rule.technique in rows[0], f"docs/RULES.md shows the wrong technique for {rule.id}"
