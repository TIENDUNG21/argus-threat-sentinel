from datetime import UTC, datetime
from pathlib import Path

import pytest

from argus.evaluation import DetectionMetrics, ModelMetrics, evaluate, roc_auc
from argus.pipeline import ScanOptions, scan
from argus.simulate import Labels, simulate, write_simulation


def test_roc_auc_extremes_and_ties() -> None:
    assert roc_auc([0.1, 0.2, 0.8, 0.9], [False, False, True, True]) == 1.0
    assert roc_auc([0.9, 0.8, 0.2, 0.1], [False, False, True, True]) == 0.0
    assert roc_auc([0.5, 0.5, 0.5, 0.5], [False, True, False, True]) == 0.5
    assert roc_auc([0.1, 0.4, 0.35, 0.8], [False, False, True, True]) == pytest.approx(0.75)
    assert roc_auc([0.3, 0.4], [True, True]) is None


def test_detection_metrics_properties_and_merge() -> None:
    first = DetectionMetrics(
        "r", expected=4, alerted=5, true_positives=3, malicious_alerted=4, benign_alerted=1
    )
    assert first.precision == pytest.approx(0.8)
    assert first.recall == pytest.approx(0.75)
    empty = DetectionMetrics(
        "r", expected=0, alerted=0, true_positives=0, malicious_alerted=0, benign_alerted=0
    )
    assert empty.precision is None
    assert empty.recall is None
    merged = first.merged(first)
    assert (merged.expected, merged.alerted, merged.true_positives) == (8, 10, 6)


def test_model_metrics() -> None:
    metrics = ModelMetrics.from_scores(
        "web", {"a": 0.9, "b": 0.7, "c": 0.3, "d": 0.2}, {"a", "c"}, threshold=0.6
    )
    assert (metrics.actors, metrics.malicious, metrics.flagged, metrics.flagged_malicious) == (
        4,
        2,
        2,
        1,
    )
    assert metrics.precision == pytest.approx(0.5)
    assert metrics.recall == pytest.approx(0.5)
    assert metrics.auc == pytest.approx(0.75)


def test_evaluate_scores_alerts_against_labels(tmp_path: Path) -> None:
    sim = simulate(11, visitors_per_day=40)
    files = write_simulation(sim, tmp_path)
    result = scan([files["access.log"], files["auth.log"]], ScanOptions())
    report = evaluate(result, sim.labels)
    assert set(report.detections) == {rule.id for rule in result.rules}
    for metrics in report.detections.values():
        assert metrics.true_positives <= min(metrics.expected, metrics.alerted)
        assert metrics.malicious_alerted + metrics.benign_alerted == metrics.alerted
    total = report.total()
    assert total.recall is not None and total.recall > 0.5
    assert total.precision is not None and total.precision > 0.5
    assert report.seeds[0].malformed_injected == report.seeds[0].malformed_counted
    assert {m.source for m in report.models.values()} <= {"web", "ssh"}


def test_unlabelled_actor_counts_as_benign() -> None:
    labels = Labels(seed=0, start=datetime(2026, 3, 2, tzinfo=UTC), hours=48)
    assert labels.get("198.18.0.1").malicious is False
