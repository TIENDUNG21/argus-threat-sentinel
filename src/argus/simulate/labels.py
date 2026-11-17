"""Ground truth written next to the simulated logs (``labels.json``)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class ActorLabel:
    scenario: str
    malicious: bool
    expected: tuple[str, ...] = ()
    """Built-in rules that should fire for this actor."""


BENIGN = ActorLabel("unknown", malicious=False)


@dataclass
class Labels:
    seed: int
    start: datetime
    hours: int
    actors: dict[str, ActorLabel] = field(default_factory=dict)
    malformed: dict[str, int] = field(default_factory=dict)
    scenarios: dict[str, int] = field(default_factory=dict)
    """Number of runs per scenario name."""

    def add(
        self, ip: str, scenario: str, *, malicious: bool, expected: tuple[str, ...] = ()
    ) -> None:
        """Label ``ip``. A malicious label always wins over a benign one, and the
        expectations of several malicious scenarios on one address are merged."""
        current = self.actors.get(ip)
        if current is None or (malicious and not current.malicious):
            self.actors[ip] = ActorLabel(scenario, malicious, tuple(sorted(set(expected))))
        elif malicious and current.malicious:
            merged = tuple(sorted(set(current.expected) | set(expected)))
            self.actors[ip] = ActorLabel(current.scenario, True, merged)

    def get(self, ip: str) -> ActorLabel:
        return self.actors.get(ip, BENIGN)

    def to_json(self) -> str:
        document = {
            "seed": self.seed,
            "start": self.start.isoformat(),
            "hours": self.hours,
            "malformed": dict(sorted(self.malformed.items())),
            "scenarios": dict(sorted(self.scenarios.items())),
            "actors": {
                ip: {
                    "scenario": label.scenario,
                    "malicious": label.malicious,
                    "expected": list(label.expected),
                }
                for ip, label in sorted(self.actors.items())
            },
        }
        return json.dumps(document, indent=1) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Labels:
        data = json.loads(text)
        labels = cls(
            seed=int(data["seed"]),
            start=datetime.fromisoformat(data["start"]),
            hours=int(data["hours"]),
            malformed={str(k): int(v) for k, v in data["malformed"].items()},
            scenarios={str(k): int(v) for k, v in data["scenarios"].items()},
        )
        for ip, item in data["actors"].items():
            labels.actors[ip] = ActorLabel(
                str(item["scenario"]), bool(item["malicious"]), tuple(item["expected"])
            )
        return labels
