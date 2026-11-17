from datetime import timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from argus.rules.engine import Engine
from argus.rules.loader import load_rules_text
from argus.rules.model import Rule
from tests.helpers import at, ssh, web


def rule(body: str, *, when: str = 'action == "failed_password"', extra: str = "") -> Rule:
    text = f"""
[[rule]]
id = "test-rule"
title = "Test rule"
severity = "medium"
technique = "T1110.001"
when = '{when}'
{extra}
{body}
"""
    (loaded,) = load_rules_text(text, "test.toml")
    return loaded


BRUTE = rule('[rule.threshold]\ncount = 10\nwindow = "5m"')


def test_threshold_fires_on_the_tenth_event_not_the_ninth() -> None:
    engine = Engine([BRUTE])
    fired = [engine.process(ssh("failed_password", t=i * 10)) for i in range(10)]
    assert all(not batch for batch in fired[:9])
    (alert,) = fired[9]
    assert alert.count == 10
    assert alert.first_ts == at(0)
    assert alert.fired_ts == at(90)
    assert alert.actors == {"198.18.1.10"}
    assert alert.group == (("ip", "198.18.1.10"),)
    assert alert.rule is BRUTE


def test_events_outside_the_window_do_not_count() -> None:
    engine = Engine([BRUTE])
    alerts = engine.run(ssh("failed_password", t=i * 40) for i in range(20))
    assert alerts == []


def test_non_matching_events_are_ignored() -> None:
    engine = Engine([BRUTE])
    assert engine.run(ssh("accepted_password", t=i) for i in range(50)) == []


def test_episode_extends_while_activity_continues() -> None:
    engine = Engine([BRUTE])
    (alert,) = engine.run(ssh("failed_password", t=i * 10) for i in range(100))
    assert alert.count == 100
    assert alert.last_ts == at(990)
    assert len(alert.evidence) == 10


def test_quiet_gap_longer_than_window_starts_a_new_episode() -> None:
    engine = Engine([BRUTE])
    first = [ssh("failed_password", t=i) for i in range(10)]
    second = [ssh("failed_password", t=3600 + i) for i in range(10)]
    alerts = engine.run(first + second)
    assert [a.count for a in alerts] == [10, 10]
    assert alerts[0].id != alerts[1].id


def test_groups_are_independent() -> None:
    engine = Engine([BRUTE])
    events = [ssh("failed_password", t=i, ip=f"198.18.1.{i % 2}") for i in range(18)]
    assert engine.run(events) == []


def test_distinct_counts_unique_values() -> None:
    spray = rule('[rule.threshold]\ncount = 3\nwindow = "10m"\ndistinct = "user"')
    engine = Engine([spray])
    same_user = [ssh("failed_password", t=i, user="root") for i in range(10)]
    assert engine.run(same_user) == []
    (alert,) = Engine([spray]).run(
        ssh("failed_password", t=i, user=name) for i, name in enumerate(["a", "b", "a", "c"])
    )
    assert alert.distinct_values == {"a", "b", "c"}


def test_group_by_other_field_collects_all_actors() -> None:
    stuffing = rule(
        '[rule.threshold]\ncount = 3\nwindow = "10m"\ndistinct = "ip"',
        when="status == 401",
        extra='group_by = ["user_agent"]',
    )
    events = [web("/login", t=i, ip=f"198.18.2.{i}", status=401, ua="bot/1") for i in range(4)]
    (alert,) = Engine([stuffing]).run(events)
    assert alert.actors == {"198.18.2.0", "198.18.2.1", "198.18.2.2", "198.18.2.3"}
    assert alert.group == (("user_agent", "bot/1"),)


def test_source_filter_skips_other_sources() -> None:
    web_only = rule("", when="status >= 0", extra='source = "web"')
    alerts = Engine([web_only]).run([ssh("failed_password"), web("/")])
    assert [a.rule.id for a in alerts] == ["test-rule"]
    assert alerts[0].actors == {"198.18.0.10"}


def test_idle_groups_are_evicted() -> None:
    engine = Engine([BRUTE], sweep_every=100)
    engine.run(ssh("failed_password", t=i, ip=f"198.18.3.{i}") for i in range(50))
    assert engine.tracked_groups() == 50
    engine.run(ssh("failed_password", t=7200 + i, ip="198.18.4.1") for i in range(200))
    assert engine.tracked_groups() == 1


def oracle_episodes(times: list[float], count: int, window: float) -> int:
    """Independent O(n^2) statement of the episode semantics."""
    alerts = 0
    open_last: float | None = None
    for index, now in enumerate(times):
        if open_last is not None and now - open_last > window:
            open_last = None
        if open_last is not None:
            open_last = now
            continue
        in_window = sum(1 for earlier in times[: index + 1] if earlier >= now - window)
        if in_window >= count:
            alerts += 1
            open_last = now
    return alerts


@settings(max_examples=150, deadline=None)
@given(
    gaps=st.lists(st.integers(min_value=0, max_value=400), min_size=1, max_size=80),
    count=st.integers(min_value=1, max_value=8),
    window=st.integers(min_value=1, max_value=600),
)
def test_threshold_matches_oracle(gaps: list[int], count: int, window: int) -> None:
    times: list[float] = []
    now = 0
    for gap in gaps:
        now += gap
        times.append(float(now))
    under_test = rule(f'[rule.threshold]\ncount = {count}\nwindow = "{window}s"')
    alerts = Engine([under_test]).run(ssh("failed_password", t=t) for t in times)
    assert len(alerts) == oracle_episodes(times, count, window)
    assert sum(alert.count for alert in alerts) <= len(times)
    assert timedelta(seconds=window) == under_test.kind.window  # type: ignore[union-attr]
