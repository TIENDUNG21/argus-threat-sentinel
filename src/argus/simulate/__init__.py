"""Seeded generator of labelled synthetic logs (nginx access log + OpenSSH auth log).

The same seed always produces byte-identical files. The data is synthetic: it
exists to test and evaluate the detectors, not to describe any real network.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime
from operator import attrgetter
from pathlib import Path

from argus.simulate import benign
from argus.simulate.attacks import SCENARIOS, background_noise
from argus.simulate.labels import ActorLabel, Labels
from argus.simulate.render import inject_malformed, render_auth, render_web
from argus.simulate.world import IpPool, World

DEFAULT_START = datetime(2026, 3, 2, tzinfo=UTC)
MIN_HOURS = 36
ACCESS_LOG = "access.log"
AUTH_LOG = "auth.log"
LABELS = "labels.json"


@dataclass(frozen=True)
class Simulation:
    access_lines: list[str]
    auth_lines: list[str]
    labels: Labels


def simulate(
    seed: int,
    *,
    start: datetime = DEFAULT_START,
    hours: int = 48,
    visitors_per_day: int = 300,
    malformed_rate: float = 0.0005,
) -> Simulation:
    """Generate ``hours`` of traffic. SSH scenarios need a learned baseline, so at
    least 36 hours are required."""
    if hours < MIN_HOURS:
        raise ValueError(f"hours must be at least {MIN_HOURS}")
    if visitors_per_day < 1:
        raise ValueError("visitors_per_day must be at least 1")
    rng = random.Random(seed)
    labels = Labels(seed=seed, start=start, hours=hours)
    world = World(
        rng=rng,
        start=start,
        hours=hours,
        ips=IpPool(rng),
        labels=labels,
        git_exposed=rng.random() < 0.35,
    )
    benign.visitors(world, visitors_per_day)
    benign.office(world)
    benign.crawlers(world)
    benign.monitor(world)
    benign.api_client(world)
    benign.ssh_users(world)
    for name, scenario, (low, high) in SCENARIOS:
        runs = rng.randint(low, high)
        labels.scenarios[name] = runs
        for _ in range(runs):
            scenario(world)
    background_noise(world)

    access = [render_web(hit) for hit in sorted(world.traffic.web, key=attrgetter("ts"))]
    auth = [render_auth(line) for line in sorted(world.traffic.auth, key=attrgetter("ts"))]
    labels.malformed[ACCESS_LOG] = inject_malformed(rng, access, "web", malformed_rate)
    labels.malformed[AUTH_LOG] = inject_malformed(rng, auth, "ssh", malformed_rate)
    return Simulation(access, auth, labels)


def write_simulation(simulation: Simulation, out_dir: Path) -> dict[str, Path]:
    """Write ``access.log``, ``auth.log`` and ``labels.json`` into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        ACCESS_LOG: "\n".join(simulation.access_lines) + "\n",
        AUTH_LOG: "\n".join(simulation.auth_lines) + "\n",
        LABELS: simulation.labels.to_json(),
    }
    written: dict[str, Path] = {}
    for name, text in files.items():
        path = out_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written[name] = path
    return written


__all__ = [
    "ACCESS_LOG",
    "AUTH_LOG",
    "DEFAULT_START",
    "LABELS",
    "ActorLabel",
    "Labels",
    "Simulation",
    "simulate",
    "write_simulation",
]
