import math

import numpy as np
import pytest

from argus.ml.features import SSH_FEATURES, WEB_FEATURES, build_features
from tests.helpers import ssh, web


def column(matrix_names: tuple[str, ...], name: str) -> int:
    return matrix_names.index(name)


def test_web_features_for_one_actor() -> None:
    events = [
        web("/a", t=0, status=200, size=100),
        web("/b", t=60, status=404, size=300),
        web("/c", t=120, status=200, size=200, method="POST"),
        web("/d", t=180, status=500, size=400),
    ]
    matrices = build_features(events, min_events=1)
    web_matrix = matrices["web"]
    assert web_matrix.names == WEB_FEATURES
    assert web_matrix.actors == ["198.18.0.10"]
    raw = dict(zip(web_matrix.names, web_matrix.raw[0], strict=True))
    assert raw["requests"] == 4
    assert raw["distinct_paths"] == 4
    assert raw["path_entropy"] == pytest.approx(2.0)
    assert raw["error_ratio"] == pytest.approx(0.5)
    assert raw["mean_bytes"] == pytest.approx(250)
    assert raw["post_ratio"] == pytest.approx(0.25)
    assert raw["rate_per_min"] == pytest.approx(4 / 3)
    assert raw["night_share"] == 0.0


def test_model_input_log_scales_heavy_tailed_counts() -> None:
    events = [web(f"/p{i}", t=i) for i in range(9)]
    matrix = build_features(events, min_events=1)["web"]
    requests = column(matrix.names, "requests")
    entropy = column(matrix.names, "path_entropy")
    assert matrix.X[0, requests] == pytest.approx(math.log1p(9))
    assert matrix.X[0, entropy] == pytest.approx(matrix.raw[0, entropy])


def test_entropy_is_zero_for_a_single_path() -> None:
    matrix = build_features([web("/same", t=i) for i in range(10)], min_events=1)["web"]
    assert matrix.raw[0, column(matrix.names, "path_entropy")] == 0.0


def test_actors_below_min_events_are_skipped_and_counted() -> None:
    events = [web("/", t=i, ip="198.18.0.1") for i in range(5)]
    events += [web("/", t=i, ip="198.18.0.2") for i in range(2)]
    matrix = build_features(events, min_events=5)["web"]
    assert matrix.actors == ["198.18.0.1"]
    assert matrix.skipped == 1


def test_ssh_features() -> None:
    events = [
        ssh("failed_password", t=0, user="root"),
        ssh("failed_password", t=30, user="admin", invalid=True),
        ssh("invalid_user", t=31, user="admin", invalid=True),
        ssh("accepted_publickey", t=60, user="root"),
    ]
    matrix = build_features(events, min_events=1)["ssh"]
    assert matrix.names == SSH_FEATURES
    raw = dict(zip(matrix.names, matrix.raw[0], strict=True))
    assert raw["attempts"] == 4
    assert raw["fail_ratio"] == pytest.approx(0.75)
    assert raw["distinct_users"] == 2
    assert raw["invalid_user_ratio"] == pytest.approx(0.5)


def test_night_share_uses_utc_hours_0_to_5() -> None:
    events = [web("/", t=h * 3600 + 12 * 3600) for h in range(24)]
    matrix = build_features(events, min_events=1)["web"]
    assert matrix.raw[0, column(matrix.names, "night_share")] == pytest.approx(6 / 24)


def test_actor_order_is_deterministic_and_spans_are_kept() -> None:
    events = [web("/", t=10, ip="198.18.0.9"), web("/", t=0, ip="198.18.0.1")]
    matrix = build_features(events, min_events=1)["web"]
    assert matrix.actors == ["198.18.0.1", "198.18.0.9"]
    assert matrix.counts.tolist() == [1, 1]
    assert matrix.spans[1][0] < matrix.spans[1][1] or matrix.spans[1][0] == matrix.spans[1][1]
    assert np.isfinite(matrix.X).all()


def test_no_events_gives_no_matrices() -> None:
    assert build_features([]) == {}
