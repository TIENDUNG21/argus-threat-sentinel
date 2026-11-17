from argus.events import Event
from argus.rules.engine import Engine
from argus.rules.loader import load_rules_text
from argus.rules.model import Rule
from tests.helpers import at, ssh

SEQUENCE = """
[[rule]]
id = "brute-then-success"
title = "Brute force followed by a successful login"
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

NEW_VALUE = """
[[rule]]
id = "new-source"
title = "Login from a new address"
severity = "medium"
technique = "T1078"
source = "ssh"
when = 'action startswith "accepted"'
group_by = ["user"]
new_value = { field = "ip", learn = "1h" }
"""


def load(text: str) -> Rule:
    (rule,) = load_rules_text(text, "test.toml")
    return rule


def fails(n: int, start: float = 0, step: float = 10, ip: str = "198.18.1.10") -> list[Event]:
    return [ssh("failed_password", t=start + i * step, ip=ip) for i in range(n)]


def test_five_failures_then_success_fires() -> None:
    events = [*fails(5), ssh("accepted_password", t=60)]
    (alert,) = Engine([load(SEQUENCE)]).run(events)
    assert alert.count == 6
    assert alert.first_ts == at(0)
    assert alert.fired_ts == at(60)


def test_four_failures_then_success_does_not_fire() -> None:
    events = [*fails(4), ssh("accepted_password", t=60)]
    assert Engine([load(SEQUENCE)]).run(events) == []


def test_success_after_the_window_does_not_fire() -> None:
    events = [*fails(5), ssh("accepted_password", t=40 * 60)]
    assert Engine([load(SEQUENCE)]).run(events) == []


def test_order_matters() -> None:
    events = [ssh("accepted_password", t=0), *fails(5, start=10)]
    assert Engine([load(SEQUENCE)]).run(events) == []


def test_long_brute_force_still_links_to_the_final_success() -> None:
    events = [*fails(300, step=10), ssh("accepted_password", t=3001)]
    (alert,) = Engine([load(SEQUENCE)]).run(events)
    assert alert.fired_ts == at(3001)
    assert alert.first_ts >= at(3001 - 30 * 60)


def test_sequence_is_per_group() -> None:
    events = [*fails(5, ip="198.18.1.1"), ssh("accepted_password", t=60, ip="198.18.1.2")]
    assert Engine([load(SEQUENCE)]).run(events) == []


def test_repeated_success_extends_the_same_alert() -> None:
    events = [*fails(5), ssh("accepted_password", t=60), *fails(5, start=70)]
    events.append(ssh("accepted_password", t=200))
    (alert,) = Engine([load(SEQUENCE)]).run(events)
    assert alert.last_ts == at(200)


def test_new_value_learns_then_alerts_on_unseen_value() -> None:
    rule = load(NEW_VALUE)
    events = [
        ssh("accepted_publickey", t=0, user="alice", ip="198.18.5.1"),
        ssh("accepted_publickey", t=1800, user="bob", ip="198.18.5.2"),
        ssh("accepted_publickey", t=7200, user="alice", ip="198.18.5.1"),
        ssh("accepted_publickey", t=7300, user="alice", ip="198.18.9.9"),
        ssh("accepted_publickey", t=7400, user="alice", ip="198.18.9.9"),
        ssh("accepted_publickey", t=7500, user="bob", ip="198.18.5.1"),
    ]
    alerts = Engine([rule]).run(events)
    assert [(a.group, a.actors) for a in alerts] == [
        ((("user", "alice"),), {"198.18.9.9"}),
        ((("user", "bob"),), {"198.18.5.1"}),
    ]
    assert alerts[0].distinct_values == {"198.18.9.9"}


def test_new_value_is_silent_during_learning() -> None:
    rule = load(NEW_VALUE)
    events = [ssh("accepted_publickey", t=i * 60, user="u", ip=f"198.18.6.{i}") for i in range(30)]
    assert Engine([rule]).run(events) == []
