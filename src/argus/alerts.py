"""Severity levels and the alerts rules produce."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus.events import Event
    from argus.rules.model import Rule

MAX_EVIDENCE = 10
MAX_DISTINCT = 200


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError:
            choices = ", ".join(member.label for member in cls)
            raise ValueError(f"severity must be one of {choices}, got {text!r}") from None


@dataclass(frozen=True, slots=True)
class Evidence:
    """A log line that contributed to an alert."""

    file: str
    line: int
    ts: datetime
    text: str


@dataclass(eq=False)
class Alert:
    """One detection episode: a rule firing for one group.

    While matching events keep arriving within the rule's window the episode
    stays open and grows (``count``, ``last_ts``, ``actors``) instead of
    producing a new alert per event.
    """

    id: str
    rule: Rule
    group: tuple[tuple[str, str], ...]
    first_ts: datetime
    fired_ts: datetime
    last_ts: datetime
    count: int = 0
    actors: set[str] = field(default_factory=set)
    distinct_values: set[str] = field(default_factory=set)
    evidence: list[Evidence] = field(default_factory=list)

    def add(self, event: Event, distinct_value: str | None = None) -> None:
        self.count += 1
        self.actors.add(event.ip)
        self.first_ts = min(self.first_ts, event.ts)
        self.last_ts = max(self.last_ts, event.ts)
        if distinct_value is not None and len(self.distinct_values) < MAX_DISTINCT:
            self.distinct_values.add(distinct_value)
        if len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(Evidence(event.file, event.line, event.ts, event.raw))

    @property
    def severity(self) -> Severity:
        return self.rule.severity
