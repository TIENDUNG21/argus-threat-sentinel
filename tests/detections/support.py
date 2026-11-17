"""Shared machinery for the per-detection tests.

Every built-in rule registers at least one positive case (log activity that
must fire it) and one negative case (a near miss that must not).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache

from argus.alerts import Alert
from argus.events import Event
from argus.rules.engine import Engine
from argus.rules.loader import builtin_rules
from argus.rules.model import Rule


@dataclass(frozen=True)
class Case:
    positives: list[list[Event]] = field(default_factory=list)
    negatives: list[list[Event]] = field(default_factory=list)


@cache
def rules_by_id() -> dict[str, Rule]:
    return {rule.id: rule for rule in builtin_rules()}


def fire(rule_id: str, events: list[Event]) -> list[Alert]:
    engine = Engine([rules_by_id()[rule_id]])
    return engine.run(sorted(events, key=lambda event: event.ts))


def variants(cases: dict[str, Case], *, positive: bool) -> list[tuple[str, int]]:
    return [
        (rule_id, index)
        for rule_id, case in sorted(cases.items())
        for index in range(len(case.positives if positive else case.negatives))
    ]
