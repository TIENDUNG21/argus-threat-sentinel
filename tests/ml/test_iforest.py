import math

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays

from argus.ml.iforest import IsolationForest, average_path_length


def synthetic(seed: int = 7) -> tuple[np.ndarray, np.ndarray]:
    """500 Gaussian inliers plus 10 injected outliers far from the bulk."""
    rng = np.random.default_rng(seed)
    inliers = rng.normal(0.0, 1.0, size=(500, 2))
    outliers = rng.uniform(6.0, 9.0, size=(10, 2)) * rng.choice([-1.0, 1.0], size=(10, 2))
    return inliers, outliers


def test_average_path_length_matches_definition() -> None:
    assert average_path_length(1) == 0.0
    assert average_path_length(2) == 1.0
    expected = 2 * (math.log(255) + 0.5772156649015329) - 2 * 255 / 256
    assert average_path_length(256) == pytest.approx(expected)
    assert average_path_length(np.array([0, 1, 2])).tolist() == [0.0, 0.0, 1.0]


def test_injected_outliers_score_higher_than_inliers() -> None:
    inliers, outliers = synthetic()
    data = np.vstack([inliers, outliers])
    scores = IsolationForest(n_trees=200, sample_size=256, seed=1).fit(data).score(data)
    inlier_scores, outlier_scores = scores[:500], scores[500:]
    assert float(np.min(outlier_scores)) > float(np.percentile(inlier_scores, 95))
    assert outlier_scores.mean() > 0.65
    assert inlier_scores.mean() < 0.5


def test_outliers_have_shorter_paths() -> None:
    inliers, outliers = synthetic()
    data = np.vstack([inliers, outliers])
    paths = IsolationForest(seed=3).fit(data).path_lengths(data)
    assert paths[500:].mean() < paths[:500].mean() - 2


def test_same_seed_is_reproducible_and_different_seed_differs() -> None:
    inliers, outliers = synthetic()
    data = np.vstack([inliers, outliers])
    first = IsolationForest(n_trees=50, seed=11).fit(data).score(data)
    second = IsolationForest(n_trees=50, seed=11).fit(data).score(data)
    other = IsolationForest(n_trees=50, seed=12).fit(data).score(data)
    assert np.array_equal(first, second)
    assert not np.array_equal(first, other)


def test_constant_feature_and_small_samples() -> None:
    data = np.column_stack([np.zeros(20), np.arange(20, dtype=float)])
    forest = IsolationForest(n_trees=20, sample_size=256, seed=0).fit(data)
    assert forest.sample_size_ == 20
    scores = forest.score(data)
    assert np.all((scores > 0) & (scores <= 1))


def test_all_identical_rows_score_one_half_or_less() -> None:
    data = np.ones((30, 3))
    scores = IsolationForest(n_trees=10, seed=0).fit(data).score(data)
    assert np.allclose(scores, scores[0])
    assert scores[0] <= 0.5 + 1e-9


def test_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="2-D"):
        IsolationForest().fit(np.zeros(5))
    with pytest.raises(ValueError, match="finite"):
        IsolationForest().fit(np.array([[1.0], [np.nan]]))
    with pytest.raises(ValueError, match="at least 2"):
        IsolationForest().fit(np.zeros((1, 2)))
    with pytest.raises(RuntimeError, match="fit"):
        IsolationForest().score(np.zeros((2, 2)))
    forest = IsolationForest(n_trees=5).fit(np.random.default_rng(0).normal(size=(10, 2)))
    with pytest.raises(ValueError, match="features"):
        forest.score(np.zeros((2, 3)))


@settings(max_examples=40, deadline=None)
@given(
    arrays(
        np.float64,
        st.tuples(st.integers(2, 40), st.integers(1, 4)),
        elements=st.floats(-1e6, 1e6, allow_nan=False),
    )
)
def test_scores_are_always_in_unit_interval(data: np.ndarray) -> None:
    scores = IsolationForest(n_trees=10, sample_size=16, seed=0).fit(data).score(data)
    assert scores.shape == (data.shape[0],)
    assert np.all((scores > 0) & (scores <= 1))
