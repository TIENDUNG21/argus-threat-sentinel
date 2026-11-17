from datetime import timedelta

import pytest

from argus.timeutil import format_duration, parse_duration


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("5m", timedelta(minutes=5)),
        ("2h", timedelta(hours=2)),
        ("1d", timedelta(days=1)),
        ("1h30m", timedelta(minutes=90)),
        (" 10m ", timedelta(minutes=10)),
    ],
)
def test_parse_duration_accepts_units(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "5", "5x", "-5m", "m", "0s", "1h 30m", "5m5"])
def test_parse_duration_rejects_garbage(text: str) -> None:
    with pytest.raises(ValueError, match="duration"):
        parse_duration(text)


def test_format_duration_round_trips() -> None:
    assert format_duration(timedelta(minutes=90)) == "1h30m"
    assert format_duration(timedelta(seconds=45)) == "45s"
    assert format_duration(timedelta(days=1)) == "1d"
