from datetime import UTC, datetime

from argus.events import FIELD_TYPES, Event


def make(**kwargs: object) -> Event:
    base: dict[str, object] = {
        "source": "web",
        "ts": datetime(2026, 3, 2, 14, 5, tzinfo=UTC),
        "ip": "198.18.0.1",
    }
    base.update(kwargs)
    return Event(**base)  # type: ignore[arg-type]


def test_hour_is_utc_hour() -> None:
    assert make().hour == 14


def test_ext_is_lowercase_extension_of_last_segment() -> None:
    assert make(path="/uploads/a.b/shell.PHP").ext == "php"
    assert make(path="/static/").ext == ""
    assert make(path="/.env").ext == ""
    assert make(path="/archive.tar.gz").ext == "gz"


def test_field_types_cover_rule_visible_fields() -> None:
    assert FIELD_TYPES["status"] is int
    assert FIELD_TYPES["user_agent"] is str
    assert FIELD_TYPES["invalid_user"] is bool
    assert FIELD_TYPES["hour"] is int
    assert "raw" not in FIELD_TYPES
    assert "ts" not in FIELD_TYPES
