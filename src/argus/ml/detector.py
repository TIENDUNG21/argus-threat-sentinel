"""Flag actors whose behaviour the Isolation Forest finds easy to isolate."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np

from argus.events import Event
from argus.ml.explain import attributions
from argus.ml.features import build_features
from argus.ml.iforest import IsolationForest


@dataclass(frozen=True)
class AnomalyConfig:
    threshold: float = 0.6
    seed: int = 0
    n_trees: int = 200
    sample_size: int = 256
    min_events: int = 5
    min_actors: int = 8
    top_features: int = 3


@dataclass(frozen=True)
class FeatureContribution:
    name: str
    value: float
    typical: float
    """Median of the feature over all scored actors of the same source."""
    share: float


@dataclass(frozen=True)
class Anomaly:
    actor: str
    source: str
    score: float
    events: int
    first_ts: datetime
    last_ts: datetime
    features: tuple[FeatureContribution, ...]

    def explanation(self) -> str:
        return ", ".join(
            f"{f.name} {f.value:.3g} (typical {f.typical:.3g}, {f.share:.0%})"
            for f in self.features
        )


@dataclass(frozen=True)
class ModelSummary:
    source: str
    actors: int
    skipped: int
    threshold: float
    scores: dict[str, float] = field(default_factory=dict)
    """Score per actor; empty when there were too few actors to fit a model."""


def detect_anomalies(
    events: Iterable[Event], config: AnomalyConfig | None = None
) -> tuple[list[Anomaly], list[ModelSummary]]:
    """Fit one forest per source and return anomalies (highest score first)."""
    config = config or AnomalyConfig()
    anomalies: list[Anomaly] = []
    summaries: list[ModelSummary] = []
    for source, matrix in sorted(build_features(events, min_events=config.min_events).items()):
        actors = len(matrix.actors)
        if actors < config.min_actors:
            summaries.append(ModelSummary(source, actors, matrix.skipped, config.threshold))
            continue
        forest = IsolationForest(config.n_trees, config.sample_size, config.seed).fit(matrix.X)
        scores = forest.score(matrix.X)
        shares = attributions(forest, matrix.X)
        typical = np.median(matrix.raw, axis=0)
        summaries.append(
            ModelSummary(
                source,
                actors,
                matrix.skipped,
                config.threshold,
                {actor: float(score) for actor, score in zip(matrix.actors, scores, strict=True)},
            )
        )
        for row in np.flatnonzero(scores >= config.threshold):
            order = np.argsort(-shares[row], kind="stable")[: config.top_features]
            first, last = matrix.spans[row]
            anomalies.append(
                Anomaly(
                    actor=matrix.actors[row],
                    source=source,
                    score=float(scores[row]),
                    events=int(matrix.counts[row]),
                    first_ts=first,
                    last_ts=last,
                    features=tuple(
                        FeatureContribution(
                            name=matrix.names[col],
                            value=float(matrix.raw[row, col]),
                            typical=float(typical[col]),
                            share=float(shares[row, col]),
                        )
                        for col in order
                    ),
                )
            )
    anomalies.sort(key=lambda anomaly: (-anomaly.score, anomaly.actor))
    return anomalies, summaries
