import contextlib
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.events import SSH
from argus.ingest.errors import MalformedLineError
from argus.ingest.sshd import SyslogClock, parse_auth

PREFIX = "Mar  2 10:00:01 web01 sshd[4242]: "


def one(message: str, clock: SyslogClock | None = None) -> dict[str, object]:
    events = parse_auth(PREFIX + message, clock or SyslogClock(year=2026))
    assert len(events) == 1
    event = events[0]
    assert event.source == SSH
    assert event.host == "web01"
    return {
        "action": event.action,
        "user": event.user,
        "ip": event.ip,
        "port": event.port,
        "invalid_user": event.invalid_user,
        "auth_method": event.auth_method,
    }


def test_failed_password_for_valid_user() -> None:
    assert one("Failed password for root from 198.18.0.9 port 51234 ssh2") == {
        "action": "failed_password",
        "user": "root",
        "ip": "198.18.0.9",
        "port": 51234,
        "invalid_user": False,
        "auth_method": "password",
    }


def test_failed_password_for_invalid_user_over_ipv6() -> None:
    fields = one("Failed password for invalid user admin from 2001:db8::5 port 2222 ssh2")
    assert fields["user"] == "admin"
    assert fields["invalid_user"] is True
    assert fields["ip"] == "2001:db8::5"


def test_failed_publickey_and_keyboard_interactive() -> None:
    assert one("Failed publickey for git from 198.18.0.1 port 1 ssh2")["action"] == (
        "failed_publickey"
    )
    kbd = one("Failed keyboard-interactive/pam for bob from 198.18.0.1 port 1 ssh2")
    assert kbd["action"] == "failed_password"
    assert kbd["auth_method"] == "keyboard-interactive/pam"


def test_accepted_publickey_and_password() -> None:
    key = one("Accepted publickey for alice from 198.18.0.2 port 50000 ssh2: ED25519 SHA256:abc")
    assert key["action"] == "accepted_publickey"
    assert key["user"] == "alice"
    assert one("Accepted password for deploy from 198.18.0.2 port 1 ssh2")["action"] == (
        "accepted_password"
    )


def test_invalid_user_line() -> None:
    fields = one("Invalid user oracle from 198.18.0.3 port 40000")
    assert fields["action"] == "invalid_user"
    assert fields["user"] == "oracle"
    assert fields["invalid_user"] is True


def test_max_auth_attempts_exceeded() -> None:
    fields = one(
        "error: maximum authentication attempts exceeded for root from 198.18.0.4 port 3 ssh2 "
        "[preauth]"
    )
    assert fields["action"] == "max_auth_exceeded"
    assert fields["user"] == "root"


def test_scanner_banner_messages() -> None:
    assert one("Did not receive identification string from 198.18.0.5 port 999")["action"] == (
        "no_ident"
    )
    bad = one("banner exchange: Connection from 198.18.0.6 port 4000: invalid format")
    assert bad["action"] == "bad_banner"
    assert bad["ip"] == "198.18.0.6"


def test_preauth_close() -> None:
    fields = one("Connection closed by authenticating user root 198.18.0.7 port 22 [preauth]")
    assert fields["action"] == "preauth_close"
    assert fields["user"] == "root"


def test_message_repeated_expands_to_n_events() -> None:
    line = (
        "Mar  2 10:00:01 web01 sshd[1]: message repeated 3 times: "
        "[ Failed password for root from 198.18.0.8 port 22 ssh2]"
    )
    events = parse_auth(line, SyslogClock(year=2026))
    assert [e.action for e in events] == ["failed_password"] * 3


def test_newer_sshd_session_program_name() -> None:
    line = "Mar  2 10:00:01 web01 sshd-session[7]: Failed password for root from 198.18.0.1 port 2"
    assert parse_auth(line, SyslogClock(year=2026))[0].action == "failed_password"


def test_other_programs_and_unmodelled_messages_are_ignored() -> None:
    clock = SyslogClock(year=2026)
    cron = "Mar  2 10:17:01 web01 CRON[99]: pam_unix(cron:session): session opened for user root"
    assert parse_auth(cron, clock) == []
    assert parse_auth(PREFIX + "Server listening on 0.0.0.0 port 22.", clock) == []


def test_traditional_timestamp_uses_clock_year_and_utc() -> None:
    event = parse_auth(PREFIX + "Invalid user x from 198.18.0.1", SyslogClock(year=2026))[0]
    assert event.ts == datetime(2026, 3, 2, 10, 0, 1, tzinfo=UTC)


def test_year_rolls_over_from_december_to_january() -> None:
    clock = SyslogClock(year=2025)
    dec = parse_auth("Dec 31 23:59:59 h sshd[1]: Invalid user a from 198.18.0.1", clock)[0]
    jan = parse_auth("Jan  1 00:00:01 h sshd[1]: Invalid user b from 198.18.0.1", clock)[0]
    assert dec.ts.year == 2025
    assert jan.ts == datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)


def test_default_year_steps_back_when_date_would_be_in_the_future() -> None:
    clock = SyslogClock(now=datetime(2026, 1, 3, tzinfo=UTC))
    event = parse_auth("Dec 30 08:00:00 h sshd[1]: Invalid user a from 198.18.0.1", clock)[0]
    assert event.ts.year == 2025


def test_rfc3339_timestamp_with_offset() -> None:
    line = (
        "2026-03-02T17:00:01.123456+07:00 web01 sshd[5]: "
        "Accepted publickey for alice from 198.18.0.2 port 1 ssh2"
    )
    event = parse_auth(line, SyslogClock(year=1999))[0]
    assert event.ts == datetime(2026, 3, 2, 10, 0, 1, 123456, tzinfo=UTC)


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("", "not syslog format"),
        ("complete garbage \x00\x01", "not syslog format"),
        ("Feb 30 10:00:00 h sshd[1]: Invalid user a from 198.18.0.1", "bad timestamp"),
        ("2026-13-02T10:00:00+00:00 h sshd[1]: Invalid user a from 1.2.3.4", "bad timestamp"),
    ],
)
def test_malformed_lines(line: str, reason: str) -> None:
    with pytest.raises(MalformedLineError) as exc:
        parse_auth(line, SyslogClock(year=2026))
    assert exc.value.reason == reason


@given(st.text(max_size=300))
def test_arbitrary_text_never_raises_anything_else(text: str) -> None:
    with contextlib.suppress(MalformedLineError):
        parse_auth(text, SyslogClock(year=2026))
