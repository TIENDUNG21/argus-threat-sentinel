"""Isolation Forest (Liu, Ting and Zhou, 2008) written with NumPy only.

Idea: anomalies are few and different, so random axis-aligned splits isolate
them in fewer steps than normal points. Each tree is grown on a random
subsample of ``sample_size`` rows: pick a feature that varies in the node, pick
a split uniformly between its min and max, recurse until a node holds one row
or the height limit ``ceil(log2(sample_size))`` is reached.

The anomaly score of a point is ``2 ** (-E[h(x)] / c(n))`` where ``h(x)`` is
its path length in a tree (plus ``c(size)`` for the unbuilt subtree at the
leaf) and ``c(n)`` is the average path length of an unsuccessful search in a
binary search tree of ``n`` nodes. Scores near 1 mean "easy to isolate".

Trees are stored as flat arrays so scoring walks all points down a tree at
once, one level per NumPy step.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Self, overload

import numpy as np
from numpy.typing import NDArray

EULER_GAMMA = 0.5772156649015329
FloatArray = NDArray[np.float64]
IntArray = NDArray[np.int64]


@overload
def average_path_length(n: int) -> float: ...


@overload
def average_path_length(n: IntArray) -> FloatArray: ...


def average_path_length(n: int | IntArray) -> float | FloatArray:
    """``c(n) = 2 H(n-1) - 2 (n-1) / n`` with ``c(2) = 1`` and ``c(n<=1) = 0``."""
    sizes = np.asarray(n, dtype=np.float64)
    result = np.zeros_like(sizes)
    big = sizes > 2
    m = sizes[big]
    result[big] = 2.0 * (np.log(m - 1.0) + EULER_GAMMA) - 2.0 * (m - 1.0) / m
    result[sizes == 2] = 1.0
    if np.ndim(n) == 0:
        return float(result)
    return result


@dataclass(frozen=True)
class Tree:
    """One isolation tree as parallel arrays; ``left == -1`` marks a leaf."""

    feature: IntArray
    threshold: FloatArray
    left: IntArray
    right: IntArray
    size: IntArray

    @property
    def is_leaf(self) -> NDArray[np.bool_]:
        return self.left < 0


def _grow(sample: FloatArray, rng: np.random.Generator, height_limit: int) -> Tree:
    feature: list[int] = []
    threshold: list[float] = []
    left: list[int] = []
    right: list[int] = []
    size: list[int] = []

    def new_node(count: int) -> int:
        feature.append(-1)
        threshold.append(0.0)
        left.append(-1)
        right.append(-1)
        size.append(count)
        return len(size) - 1

    root = new_node(len(sample))
    stack: list[tuple[int, NDArray[np.intp], int]] = [(root, np.arange(len(sample)), 0)]
    while stack:
        node, rows, depth = stack.pop()
        if depth >= height_limit or len(rows) <= 1:
            continue
        values = sample[rows]
        lows = values.min(axis=0)
        highs = values.max(axis=0)
        varying = np.flatnonzero(highs > lows)
        if varying.size == 0:
            continue
        split_feature = int(rng.choice(varying))
        split = float(rng.uniform(lows[split_feature], highs[split_feature]))
        goes_left = values[:, split_feature] < split
        left_rows, right_rows = rows[goes_left], rows[~goes_left]
        feature[node] = split_feature
        threshold[node] = split
        left[node] = new_node(len(left_rows))
        right[node] = new_node(len(right_rows))
        stack.append((left[node], left_rows, depth + 1))
        stack.append((right[node], right_rows, depth + 1))

    return Tree(
        feature=np.asarray(feature, dtype=np.int64),
        threshold=np.asarray(threshold, dtype=np.float64),
        left=np.asarray(left, dtype=np.int64),
        right=np.asarray(right, dtype=np.int64),
        size=np.asarray(size, dtype=np.int64),
    )


def _check(data: object) -> FloatArray:
    array = np.asarray(data, dtype=np.float64)
    if array.ndim != 2:
        raise ValueError("expected a 2-D array of shape (samples, features)")
    if not np.isfinite(array).all():
        raise ValueError("input must be finite (no NaN or infinity)")
    return array


class IsolationForest:
    def __init__(self, n_trees: int = 200, sample_size: int = 256, seed: int = 0) -> None:
        if n_trees < 1 or sample_size < 2:
            raise ValueError("n_trees must be >= 1 and sample_size >= 2")
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees: list[Tree] = []
        self.sample_size_ = 0
        self.n_features_ = 0

    def fit(self, data: object) -> Self:
        X = _check(data)
        if X.shape[0] < 2:
            raise ValueError("need at least 2 samples to fit")
        rng = np.random.default_rng(self.seed)
        self.sample_size_ = min(self.sample_size, X.shape[0])
        self.n_features_ = X.shape[1]
        height_limit = math.ceil(math.log2(self.sample_size_))
        self.trees = []
        for _ in range(self.n_trees):
            rows = rng.choice(X.shape[0], size=self.sample_size_, replace=False)
            self.trees.append(_grow(X[rows], rng, height_limit))
        return self

    def _ready(self, data: object) -> FloatArray:
        if not self.trees:
            raise RuntimeError("call fit() before scoring")
        X = _check(data)
        if X.shape[1] != self.n_features_:
            raise ValueError(f"expected {self.n_features_} features, got {X.shape[1]}")
        return X

    def leaves(self, tree: Tree, X: FloatArray) -> tuple[IntArray, IntArray]:
        """Walk every row of ``X`` down ``tree``; return (leaf node, depth) per row."""
        node = np.zeros(X.shape[0], dtype=np.int64)
        depth = np.zeros(X.shape[0], dtype=np.int64)
        active = np.flatnonzero(~tree.is_leaf[node])
        while active.size:
            current = node[active]
            goes_left = X[active, tree.feature[current]] < tree.threshold[current]
            node[active] = np.where(goes_left, tree.left[current], tree.right[current])
            depth[active] += 1
            active = active[~tree.is_leaf[node[active]]]
        return node, depth

    def path_lengths(self, data: object) -> FloatArray:
        """Mean adjusted path length ``E[h(x)]`` over all trees."""
        X = self._ready(data)
        total = np.zeros(X.shape[0], dtype=np.float64)
        for tree in self.trees:
            leaf, depth = self.leaves(tree, X)
            total += depth + average_path_length(tree.size[leaf])
        return total / len(self.trees)

    def score(self, data: object) -> FloatArray:
        """Anomaly score in (0, 1]; higher means more anomalous."""
        normaliser = average_path_length(self.sample_size_)
        scores: FloatArray = np.power(2.0, -self.path_lengths(data) / normaliser)
        return scores
