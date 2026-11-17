import numpy as np
import pytest

from argus.events import Event
from argus.ml.detector import AnomalyConfig, detect_anomalies
from argus.ml.explain import attributions
from argus.ml.iforest import IsolationForest
from tests.helpers import ssh, web


def test_attribution_points_at_the_feature_that_isolates() -> None:
    rng = np.random.default_rng(5)
    data = rng.normal(0.0, 1.0, size=(300, 4))
    data[0, 2] = 12.0
    forest = IsolationForest(n_trees=150, seed=2).fit(data)
    shares = attributions(forest, data)
    assert shares.shape == (300, 4)
    assert np.allclose(shares.sum(axis=1), 1.0)
    assert int(np.argmax(shares[0])) == 2
    assert shares[0, 2] > 0.5


def test_attributions_for_unsplittable_data_are_zero() -> None:
    data = np.ones((10, 2))
    forest = IsolationForest(n_trees=5, seed=0).fit(data)
    assert np.array_equal(attributions(forest, data), np.zeros((10, 2)))


def visitors(count: int) -> list[Event]:
    """Ordinary browsing: a few pages each, spread over an afternoon."""
    rng = np.random.default_rng(9)
    events: list[Event] = []
    for index in range(count):
        ip = f"198.18.40.{index}"
        start = float(rng.uniform(0, 4 * 3600))
        events.extend(
            web(
                f"/blog/post-{int(rng.integers(0, 30))}",
                t=start + page * float(rng.uniform(20, 90)),
                ip=ip,
                size=int(rng.integers(3000, 9000)),
            )
            for page in range(int(rng.integers(6, 15)))
        )
    return events


def flood(ip: str = "198.18.66.66") -> list[Event]:
    return [web(f"/x{i}", t=1000 + i * 0.05, ip=ip, status=404, size=150) for i in range(1200)]


def test_flood_actor_is_flagged_with_explanation() -> None:
    anomalies, summaries = detect_anomalies(visitors(60) + flood(), AnomalyConfig(seed=1))
    flagged = {anomaly.actor: anomaly for anomaly in anomalies}
    assert "198.18.66.66" in flagged
    anomaly = flagged["198.18.66.66"]
    assert anomaly.source == "web"
    assert anomaly.events == 1200
    assert anomaly.score >= 0.6
    assert len(anomaly.features) == 3
    names = [feature.name for feature in anomaly.features]
    assert {"requests", "rate_per_min", "distinct_paths", "error_ratio", "mean_bytes"} & set(names)
    assert anomaly.features[0].share >= anomaly.features[1].share
    (summary,) = summaries
    assert summary.source == "web"
    assert summary.actors == 61
    assert summary.scores["198.18.66.66"] == pytest.approx(anomaly.score)
    assert len(anomalies) <= 6


def test_anomalies_are_reproducible_for_a_seed() -> None:
    events = visitors(40) + flood()
    first, _ = detect_anomalies(events, AnomalyConfig(seed=4))
    second, _ = detect_anomalies(events, AnomalyConfig(seed=4))
    assert [(a.actor, a.score) for a in first] == [(a.actor, a.score) for a in second]


def test_too_few_actors_means_no_model() -> None:
    anomalies, summaries = detect_anomalies(visitors(5) + flood(), AnomalyConfig(min_actors=8))
    assert anomalies == []
    assert summaries[0].actors == 6
    assert summaries[0].scores == {}


def test_no_events() -> None:
    assert detect_anomalies([], AnomalyConfig()) == ([], [])


def ssh_actors(count: int) -> list[Event]:
    return [
        ssh("failed_password", t=i * 7 + n, ip=f"198.18.70.{i}", user=f"u{n}")
        for i in range(count)
        for n in range(6)
    ]


def test_ssh_model_is_opt_in() -> None:
    events = ssh_actors(20)
    assert detect_anomalies(events, AnomalyConfig()) == ([], [])
    _, summaries = detect_anomalies(events, AnomalyConfig(sources=("web", "ssh")))
    assert [summary.source for summary in summaries] == ["ssh"]
    assert len(summaries[0].scores) == 20


def test_unknown_source_is_rejected() -> None:
    with pytest.raises(ValueError, match="sources"):
        AnomalyConfig(sources=("ftp",))
