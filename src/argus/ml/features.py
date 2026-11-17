"""Per-actor behaviour features for the anomaly model.

An actor is a client address. Web and SSH activity live in different feature
spaces, so each source gets its own matrix (and later its own model).

``raw`` holds human-readable values (counts, ratios) for explanations; ``X``
is the model input, with heavy-tailed counts compressed by ``log1p``.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from numpy.typing import NDArray

from argus.events import SSH, WEB, Event

WEB_FEATURES: tuple[str, ...] = (
    "requests",
    "rate_per_min",
    "distinct_paths",
    "path_entropy",
    "error_ratio",
    "mean_bytes",
    "night_share",
    "post_ratio",
)
SSH_FEATURES: tuple[str, ...] = (
    "attempts",
    "rate_per_min",
    "fail_ratio",
    "distinct_users",
    "invalid_user_ratio",
    "night_share",
)
LOG_SCALED = frozenset(
    {"requests", "rate_per_min", "distinct_paths", "mean_bytes", "attempts", "distinct_users"}
)
NIGHT_HOURS = range(6)
_SSH_FAILURES = frozenset(
    {"failed_password", "failed_publickey", "failed_other", "invalid_user", "max_auth_exceeded"}
)


@dataclass(frozen=True)
class FeatureMatrix:
    source: str
    actors: list[str]
    names: tuple[str, ...]
    raw: NDArray[np.float64]
    X: NDArray[np.float64]
    counts: NDArray[np.int64]
    spans: list[tuple[datetime, datetime]]
    skipped: int = 0


@dataclass
class _Actor:
    first: datetime
    last: datetime
    count: int = 0
    night: int = 0
    paths: Counter[str] = field(default_factory=Counter)
    errors: int = 0
    bytes: int = 0
    posts: int = 0
    failures: int = 0
    invalid: int = 0
    users: set[str] = field(default_factory=set)

    def add(self, event: Event) -> None:
        self.count += 1
        self.first = min(self.first, event.ts)
        self.last = max(self.last, event.ts)
        if event.ts.hour in NIGHT_HOURS:
            self.night += 1
        if event.source == WEB:
            self.paths[event.path or event.target] += 1
            self.errors += event.status >= 400
            self.bytes += event.bytes
            self.posts += event.method == "POST"
        else:
            self.failures += event.action in _SSH_FAILURES
            self.invalid += event.invalid_user
            if event.user:
                self.users.add(event.user)

    def rate_per_min(self) -> float:
        minutes = (self.last - self.first).total_seconds() / 60
        return self.count / max(minutes, 1.0)

    def web_row(self) -> list[float]:
        return [
            self.count,
            self.rate_per_min(),
            len(self.paths),
            _entropy(self.paths, self.count),
            self.errors / self.count,
            self.bytes / self.count,
            self.night / self.count,
            self.posts / self.count,
        ]

    def ssh_row(self) -> list[float]:
        return [
            self.count,
            self.rate_per_min(),
            self.failures / self.count,
            len(self.users),
            self.invalid / self.count,
            self.night / self.count,
        ]


def _entropy(counts: Counter[str], total: int) -> float:
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def build_features(events: Iterable[Event], *, min_events: int = 5) -> dict[str, FeatureMatrix]:
    """Aggregate events per (source, actor) into feature matrices."""
    actors: dict[str, dict[str, _Actor]] = {WEB: {}, SSH: {}}
    for event in events:
        per_source = actors.get(event.source)
        if per_source is None:
            continue
        actor = per_source.get(event.ip)
        if actor is None:
            actor = per_source[event.ip] = _Actor(first=event.ts, last=event.ts)
        actor.add(event)

    matrices: dict[str, FeatureMatrix] = {}
    for source, names in ((WEB, WEB_FEATURES), (SSH, SSH_FEATURES)):
        kept = sorted(
            (ip, actor) for ip, actor in actors[source].items() if actor.count >= min_events
        )
        skipped = len(actors[source]) - len(kept)
        if not kept:
            continue
        rows = [actor.web_row() if source == WEB else actor.ssh_row() for _, actor in kept]
        raw = np.asarray(rows, dtype=np.float64)
        model_input = raw.copy()
        for index, name in enumerate(names):
            if name in LOG_SCALED:
                model_input[:, index] = np.log1p(raw[:, index])
        matrices[source] = FeatureMatrix(
            source=source,
            actors=[ip for ip, _ in kept],
            names=names,
            raw=raw,
            X=model_input,
            counts=np.asarray([actor.count for _, actor in kept], dtype=np.int64),
            spans=[(actor.first, actor.last) for _, actor in kept],
            skipped=skipped,
        )
    return matrices
