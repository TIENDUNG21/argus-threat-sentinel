"""Feature-level explanations for Isolation Forest scores.

Every split on a point's path shrinks the set of training rows that share its
node. A split that takes the point from 256 rows to 1 did most of the
isolating; one that halves the node did little. Each split therefore credits
its feature with ``log2(size_parent / size_child)`` bits, summed over all trees
and normalised so a point's credits add up to 1. The result reads as "share of
the isolation explained by each feature".
"""

from __future__ import annotations

import numpy as np

from argus.ml.iforest import FloatArray, IsolationForest


def attributions(forest: IsolationForest, data: object) -> FloatArray:
    """Per-row feature shares of shape (rows, features); rows never split are 0."""
    X = np.asarray(data, dtype=np.float64)
    credit = np.zeros(X.shape, dtype=np.float64)
    for tree in forest.trees:
        node = np.zeros(X.shape[0], dtype=np.int64)
        active = np.flatnonzero(~tree.is_leaf[node])
        while active.size:
            current = node[active]
            features = tree.feature[current]
            goes_left = X[active, features] < tree.threshold[current]
            child = np.where(goes_left, tree.left[current], tree.right[current])
            parent_size = tree.size[current].astype(np.float64)
            child_size = np.maximum(tree.size[child], 1).astype(np.float64)
            credit[active, features] += np.log2(parent_size / child_size)
            node[active] = child
            active = active[~tree.is_leaf[child]]
    totals = credit.sum(axis=1, keepdims=True)
    shares: FloatArray = np.divide(credit, totals, out=np.zeros_like(credit), where=totals > 0)
    return shares
