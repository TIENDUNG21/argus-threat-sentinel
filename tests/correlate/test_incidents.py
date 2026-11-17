from datetime import timedelta

import pytest

from argus.alerts import Alert, Severity
from argus.correlate import correlate, score_incident
from argus.ml.detector import Anomaly, FeatureContribution
from argus.rules.loader import builtin_rules
from tests.helpers import at

RULES = {rule.id: rule for rule in builtin_rules()}
A, B, C = "198.18.50.1", "198.18.50.2", "198.18.50.3"


def alert(rule_id: str, actors: set[str], start: float, end: float | None = None) -> Alert:
    return Alert(
        id=f"{rule_id}#{int(start)}",
        rule=RULES[rule_id],
        group=(("ip", sorted(actors)[0]),),
        first_ts=at(start),
        fired_ts=at(start),
        last_ts=at(end if end is not None else start),
        count=1,
        actors=set(actors),
    )


def anomaly(actor: str, start: float, end: float, score: float = 0.7) -> Anomaly:
    return Anomaly(
        actor=actor,
        source="web",
        score=score,
        events=500,
        first_ts=at(start),
        last_ts=at(end),
        features=(FeatureContribution("rate_per_min", 120.0, 1.5, 0.6),),
    )


HOUR = 3600


def test_alerts_of_one_actor_close_in_time_form_one_incident() -> None:
    (incident,) = correlate(
        [alert("web-scanner-user-agent", {A}, 0, 600), alert("web-sqli-probe", {A}, 1800)], []
    )
    assert incident.actors == [A]
    assert incident.start == at(0)
    assert incident.end == at(1800)
    assert [a.rule.id for a in incident.alerts] == ["web-scanner-user-agent", "web-sqli-probe"]


def test_long_quiet_gap_splits_incidents() -> None:
    incidents = correlate(
        [alert("web-sqli-probe", {A}, 0), alert("web-xss-probe", {A}, 5 * HOUR)], []
    )
    assert [i.id for i in incidents] == ["INC-0001", "INC-0002"]
    assert [i.start for i in incidents] == [at(0), at(5 * HOUR)]


def test_multi_actor_alert_links_actors_transitively() -> None:
    incidents = correlate(
        [
            alert("web-login-brute-force", {A}, 0),
            alert("web-credential-stuffing", {A, B}, 600),
            alert("web-sqli-probe", {B}, 1200),
            alert("web-sqli-probe", {C}, 1300),
        ],
        [],
    )
    assert sorted(len(i.actors) for i in incidents) == [1, 2]
    linked = next(i for i in incidents if len(i.actors) == 2)
    assert linked.actors == [A, B]
    assert len(linked.alerts) == 3


def test_anomaly_attaches_to_the_matching_incident_or_stands_alone() -> None:
    incidents = correlate(
        [alert("web-wordlist-scan", {A}, 0, 300)],
        [anomaly(A, 0, 400), anomaly(B, 10 * HOUR, 11 * HOUR, score=0.8)],
    )
    with_alerts = next(i for i in incidents if i.alerts)
    alone = next(i for i in incidents if not i.alerts)
    assert [x.actor for x in with_alerts.anomalies] == [A]
    assert alone.actors == [B]
    assert alone.level is Severity.MEDIUM
    assert alone.tactics == []
    assert "Anomalous" in alone.title


def test_timeline_is_chronological_and_tactics_follow_the_kill_chain() -> None:
    (incident,) = correlate(
        [
            alert("ssh-brute-force-success", {A}, 900),
            alert("ssh-brute-force", {A}, 0, 800),
            alert("ssh-banner-scan", {A}, -600),
            alert("ssh-new-source-for-user", {A}, 905),
        ],
        [],
    )
    assert [entry.ts for entry in incident.timeline] == sorted(e.ts for e in incident.timeline)
    assert incident.timeline[0].rule_id == "ssh-banner-scan"
    assert incident.tactics == ["reconnaissance", "initial-access", "credential-access"]
    assert incident.level is Severity.CRITICAL
    assert incident.title.startswith("SSH login succeeded after repeated failures")


@pytest.mark.parametrize(
    ("rule_ids", "with_anomaly", "score", "level"),
    [
        (["web-user-enumeration"], False, 15, Severity.LOW),
        (["web-sqli-probe"], False, 35, Severity.MEDIUM),
        (["web-sensitive-file-exposed"], False, 60, Severity.HIGH),
        (["ssh-brute-force-success"], False, 85, Severity.CRITICAL),
        (["web-sqli-probe", "web-xss-probe"], False, 39, Severity.MEDIUM),
        (
            ["web-scanner-user-agent", "web-sqli-probe", "web-login-brute-force"],
            False,
            57,
            Severity.HIGH,
        ),
        (["web-sqli-probe"], True, 45, Severity.MEDIUM),
    ],
)
def test_scoring(rule_ids: list[str], with_anomaly: bool, score: int, level: Severity) -> None:
    alerts = [alert(rule_id, {A}, i * 60) for i, rule_id in enumerate(rule_ids)]
    anomalies = [anomaly(A, 0, 60)] if with_anomaly else []
    assert score_incident(alerts, anomalies) == (score, level)


def test_score_is_capped_at_100() -> None:
    alerts = [alert(rule.id, {A}, i) for i, rule in enumerate(RULES.values())]
    assert score_incident(alerts, [anomaly(A, 0, 10)]) == (100, Severity.CRITICAL)


def test_anomaly_only_score_scales_with_model_score() -> None:
    assert score_incident([], [anomaly(A, 0, 1, score=0.6)])[0] == 30
    assert score_incident([], [anomaly(A, 0, 1, score=0.9)])[0] == 45


def test_custom_gap() -> None:
    alerts = [alert("web-sqli-probe", {A}, 0), alert("web-xss-probe", {A}, 3 * HOUR)]
    assert len(correlate(alerts, [], gap=timedelta(hours=4))) == 1
    assert correlate([], []) == []
