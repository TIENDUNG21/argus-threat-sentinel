import pytest

from argus.events import Event
from tests.detections.support import Case, fire, variants
from tests.helpers import ssh

ATTACKER = "198.18.7.7"


def failures(n: int, *, every: float = 10, user: str = "root", start: float = 0) -> list[Event]:
    return [ssh("failed_password", t=start + i * every, ip=ATTACKER, user=user) for i in range(n)]


def baseline(user: str, ip: str, *, start: float = 0) -> list[Event]:
    """Daily logins that teach the new-source rule the user's usual address."""
    return [ssh("accepted_publickey", t=start + i * 3600, ip=ip, user=user) for i in range(3)]


DAY = 86400

CASES: dict[str, Case] = {
    "ssh-brute-force": Case(
        positives=[
            failures(10, every=25),
            failures(200, every=1),
            [
                ssh("failed_password", t=i * 5, ip="2001:db8::66", user=f"u{i % 3}")
                for i in range(12)
            ],
        ],
        negatives=[
            failures(9, every=25),
            failures(30, every=40),
            [ssh("accepted_publickey", t=i, ip=ATTACKER) for i in range(50)],
        ],
    ),
    "ssh-password-spray": Case(
        positives=[
            [
                ssh("failed_password", t=i * 60, ip=ATTACKER, user=name)
                for i, name in enumerate(["admin", "test", "oracle", "ubuntu", "git", "pi"])
            ],
        ],
        negatives=[
            failures(40, every=5, user="root"),
            [ssh("failed_password", t=i * 400, ip=ATTACKER, user=f"user{i}") for i in range(6)],
        ],
    ),
    "ssh-brute-force-success": Case(
        positives=[
            [*failures(5), ssh("accepted_password", t=100, ip=ATTACKER, user="deploy")],
            [*failures(400, every=6), ssh("accepted_password", t=2500, ip=ATTACKER)],
        ],
        negatives=[
            [*failures(2), ssh("accepted_password", t=60, ip=ATTACKER, user="root")],
            [*failures(8), ssh("accepted_publickey", t=60, ip="198.18.9.9", user="root")],
            [*failures(8), ssh("accepted_password", t=3 * 3600, ip=ATTACKER)],
        ],
    ),
    "ssh-root-login": Case(
        positives=[[ssh("accepted_publickey", ip=ATTACKER, user="root")]],
        negatives=[
            [ssh("accepted_publickey", ip=ATTACKER, user="rootkit-admin")],
            [ssh("failed_password", ip=ATTACKER, user="root")],
        ],
    ),
    "ssh-new-source-for-user": Case(
        positives=[
            [
                *baseline("alice", "198.18.5.1"),
                ssh("accepted_publickey", t=DAY + 600, ip=ATTACKER, user="alice"),
            ],
        ],
        negatives=[
            [
                *baseline("alice", "198.18.5.1"),
                ssh("accepted_publickey", t=DAY + 600, ip="198.18.5.1", user="alice"),
            ],
            [
                *baseline("alice", "198.18.5.1"),
                ssh("accepted_publickey", t=7200 + 600, ip=ATTACKER, user="alice"),
            ],
            [
                *baseline("alice", "198.18.5.1"),
                ssh("failed_password", t=DAY + 600, ip=ATTACKER, user="alice"),
            ],
        ],
    ),
    "ssh-banner-scan": Case(
        positives=[
            [ssh("no_ident", t=i * 30, ip=ATTACKER, user="") for i in range(3)],
            [ssh("bad_banner", t=i, ip=ATTACKER, user="") for i in range(5)],
        ],
        negatives=[
            [ssh("no_ident", t=i * 300, ip="198.18.5.9", user="") for i in range(20)],
        ],
    ),
    "ssh-max-auth-exceeded": Case(
        positives=[[ssh("max_auth_exceeded", ip=ATTACKER)]],
        negatives=[failures(6)],
    ),
}


@pytest.mark.parametrize(("rule_id", "index"), variants(CASES, positive=True))
def test_positive_cases_fire(rule_id: str, index: int) -> None:
    alerts = fire(rule_id, CASES[rule_id].positives[index])
    assert alerts, f"{rule_id} did not fire on positive case {index}"
    assert all(alert.rule.id == rule_id for alert in alerts)


@pytest.mark.parametrize(("rule_id", "index"), variants(CASES, positive=False))
def test_negative_cases_stay_quiet(rule_id: str, index: int) -> None:
    assert fire(rule_id, CASES[rule_id].negatives[index]) == []


def test_brute_force_alert_names_the_attacker() -> None:
    (alert,) = fire("ssh-brute-force", failures(30, every=2))
    assert alert.actors == {ATTACKER}
    assert alert.count == 30


def test_spray_alert_lists_targeted_users() -> None:
    names = ["admin", "test", "oracle", "ubuntu", "git", "pi", "postgres"]
    events = [ssh("failed_password", t=i * 30, ip=ATTACKER, user=n) for i, n in enumerate(names)]
    (alert,) = fire("ssh-password-spray", events)
    assert alert.distinct_values == set(names)
