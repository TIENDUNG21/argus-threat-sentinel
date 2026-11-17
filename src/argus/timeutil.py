"""Duration parsing and formatting for rule files and the CLI."""

from __future__ import annotations

import re
from datetime import timedelta

_UNITS = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_DURATION = re.compile(r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?")


def parse_duration(text: str) -> timedelta:
    """Parse ``"30s"``, ``"5m"``, ``"2h"``, ``"1d"`` or combinations like ``"1h30m"``."""
    cleaned = text.strip()
    match = _DURATION.fullmatch(cleaned)
    if not cleaned or match is None:
        raise ValueError(f"invalid duration {text!r}: use forms like 30s, 5m, 2h, 1d or 1h30m")
    seconds = sum(
        int(value) * factor
        for value, factor in zip(match.groups(), _UNITS.values(), strict=True)
        if value is not None
    )
    if seconds <= 0:
        raise ValueError(f"invalid duration {text!r}: must be greater than zero")
    return timedelta(seconds=seconds)


def format_duration(delta: timedelta) -> str:
    """Inverse of :func:`parse_duration` for whole seconds."""
    remaining = int(delta.total_seconds())
    parts: list[str] = []
    for unit, factor in _UNITS.items():
        value, remaining = divmod(remaining, factor)
        if value:
            parts.append(f"{value}{unit}")
    return "".join(parts) or "0s"
