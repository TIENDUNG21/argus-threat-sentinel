"""Severity levels shared by rules, alerts and incidents."""

from __future__ import annotations

from enum import IntEnum


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
