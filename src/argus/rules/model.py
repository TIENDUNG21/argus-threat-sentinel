"""Loaded, validated rules."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import timedelta

from argus.alerts import Severity
from argus.attack import TECHNIQUES
from argus.rules.compiler import Predicate


def match_all(_event: object) -> bool:
    return True


@dataclass(frozen=True, slots=True)
class Threshold:
    """Fire when ``count`` matching events (or distinct values of ``distinct``)
    fall inside a sliding ``window`` for one group."""

    window: timedelta
    count: int = 1
    distinct: str | None = None


@dataclass(frozen=True, slots=True)
class Step:
    when_text: str
    when: Predicate = dataclasses.field(compare=False)
    count: int = 1


@dataclass(frozen=True, slots=True)
class Sequence:
    """Fire when the steps happen in order, for one group, within ``within``."""

    within: timedelta
    steps: tuple[Step, ...]


@dataclass(frozen=True, slots=True)
class NewValue:
    """After a ``learn`` period, fire when a group shows a value of ``field`` it
    has never shown before (for example a user logging in from a new address)."""

    field: str
    learn: timedelta


Kind = Threshold | Sequence | NewValue


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    description: str
    severity: Severity
    technique: str
    tactic: str
    source: str | None
    when_text: str
    when: Predicate = dataclasses.field(compare=False, repr=False)
    kind: Kind = Threshold(window=timedelta(minutes=10))
    group_by: tuple[str, ...] = ("ip",)
    origin: str = ""

    @property
    def technique_name(self) -> str:
        technique = TECHNIQUES.get(self.technique)
        return technique.name if technique else self.technique
