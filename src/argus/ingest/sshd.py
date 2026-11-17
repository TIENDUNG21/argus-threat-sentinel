"""Parser for OpenSSH messages in syslog auth logs (``/var/log/auth.log``, ``secure``).

Two header styles are supported:

* traditional BSD syslog: ``Mar  2 10:00:01 host sshd[123]: message`` (no year,
  no zone; :class:`SyslogClock` supplies both), and
* RFC 3339 as written by modern rsyslog/journald:
  ``2026-03-02T10:00:01.123456+00:00 host sshd[123]: message``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo
from typing import NamedTuple

from argus.events import SSH, Event
from argus.ingest.errors import MalformedLineError

_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
_TRADITIONAL = re.compile(
    r"([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^\s\[:]+)(?:\[\d+\])?: (.*)"
)
_RFC3339 = re.compile(
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})) "
    r"(\S+) ([^\s\[:]+)(?:\[\d+\])?: (.*)"
)
_REPEATED = re.compile(r"message repeated (\d+) times: \[ ?(.*?)\]?$")
_MAX_REPEAT = 1000

_FAILED = re.compile(r"Failed (\S+) for (invalid user )?(.*?) from (\S+) port (\d+)")
_ACCEPTED = re.compile(r"Accepted (\S+) for (.*?) from (\S+) port (\d+)")
_INVALID = re.compile(r"Invalid user (.*?) from (\S+)(?: port (\d+))?")
_MAX_AUTH = re.compile(
    r"error: maximum authentication attempts exceeded for (invalid user )?(.*?) "
    r"from (\S+) port (\d+)"
)
_NO_IDENT = re.compile(r"Did not receive identification string from (\S+)(?: port (\d+))?")
_BAD_BANNER = re.compile(
    r"(?:error: )?(?:kex_exchange_identification|banner exchange): "
    r"Connection from (\S+) port (\d+): (?:invalid format|could not read protocol version)"
)
_PREAUTH = re.compile(
    r"(?:Connection closed by|Disconnected from) (?:(?:authenticating|invalid) user (.*?) )?"
    r"(\S+) port (\d+) \[preauth\]"
)
_PASSWORD_METHODS = frozenset({"password", "keyboard-interactive/pam", "keyboard-interactive"})


@dataclass
class SyslogClock:
    """Turns year-less syslog timestamps into aware UTC datetimes.

    ``year`` defaults to the current year; if the first timestamp would then lie
    more than two days in the future, the previous year is used (reading last
    December's log in January). A month that jumps backwards by more than six
    (December to January) advances the year.
    """

    year: int | None = None
    tz: tzinfo = UTC
    now: datetime | None = None
    _last_month: int | None = field(default=None, init=False, repr=False)

    def resolve(self, month: int, day: int, hour: int, minute: int, second: int) -> datetime:
        if self.year is None:
            now = self.now or datetime.now(UTC)
            self.year = now.year
            candidate = _safe_datetime(self.year, month, day, hour, minute, second, self.tz)
            if candidate - now > timedelta(days=2):
                self.year -= 1
        elif self._last_month is not None and month < self._last_month - 6:
            self.year += 1
        self._last_month = month
        return _safe_datetime(self.year, month, day, hour, minute, second, self.tz).astimezone(UTC)


def _safe_datetime(
    year: int, month: int, day: int, hour: int, minute: int, second: int, tz: tzinfo
) -> datetime:
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except ValueError:
        raise MalformedLineError("bad timestamp") from None


def _parse_header(line: str, clock: SyslogClock) -> tuple[datetime, str, str, str]:
    match = _RFC3339.match(line)
    if match is not None:
        stamp, host, program, message = match.groups()
        try:
            ts = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            raise MalformedLineError("bad timestamp") from None
        return ts.astimezone(UTC), host, program, message
    match = _TRADITIONAL.match(line)
    if match is None:
        raise MalformedLineError("not syslog format")
    mon, day, hh, mm, ss, host, program, message = match.groups()
    month = _MONTHS.get(mon)
    if month is None:
        raise MalformedLineError("bad timestamp")
    ts = clock.resolve(month, int(day), int(hh), int(mm), int(ss))
    return ts, host, program, message


def parse_auth(line: str, clock: SyslogClock, *, file: str = "", line_no: int = 0) -> list[Event]:
    """Parse one auth-log line.

    Returns the sshd events on the line (usually one; ``message repeated N times``
    expands to N), an empty list for well-formed lines that carry nothing we model
    (CRON, PAM session lines, ...), and raises :class:`MalformedLineError` when the
    syslog header itself does not parse.
    """
    ts, host, program, message = _parse_header(line, clock)
    if not program.startswith("sshd"):
        return []
    repeat = 1
    repeated = _REPEATED.match(message)
    if repeated is not None:
        repeat = min(int(repeated.group(1)), _MAX_REPEAT)
        message = repeated.group(2)
    found = _classify(message)
    if found is None:
        return []
    event = Event(
        source=SSH,
        ts=ts,
        ip=found.ip,
        file=file,
        line=line_no,
        raw=line,
        host=host,
        user=found.user,
        action=found.action,
        invalid_user=found.invalid,
        auth_method=found.method,
        port=int(found.port) if found.port else 0,
    )
    return [event] * repeat


class _Found(NamedTuple):
    action: str
    ip: str
    user: str
    port: str | None
    invalid: bool = False
    method: str = ""


def _classify(message: str) -> _Found | None:
    if (m := _FAILED.match(message)) is not None:
        method, invalid, user, ip, port = m.groups()
        if method in _PASSWORD_METHODS:
            action = "failed_password"
        elif method == "publickey":
            action = "failed_publickey"
        else:
            action = "failed_other"
        return _Found(action, ip, user, port, bool(invalid), method)
    if (m := _ACCEPTED.match(message)) is not None:
        method, user, ip, port = m.groups()
        if method in _PASSWORD_METHODS:
            action = "accepted_password"
        elif method == "publickey":
            action = "accepted_publickey"
        else:
            action = "accepted_other"
        return _Found(action, ip, user, port, False, method)
    if (m := _INVALID.match(message)) is not None:
        user, ip, port = m.groups()
        return _Found("invalid_user", ip, user, port, True)
    if (m := _MAX_AUTH.match(message)) is not None:
        invalid, user, ip, port = m.groups()
        return _Found("max_auth_exceeded", ip, user, port, bool(invalid))
    if (m := _NO_IDENT.match(message)) is not None:
        ip, port = m.groups()
        return _Found("no_ident", ip, "", port)
    if (m := _BAD_BANNER.match(message)) is not None:
        ip, port = m.groups()
        return _Found("bad_banner", ip, "", port)
    if (m := _PREAUTH.match(message)) is not None:
        user, ip, port = m.groups()
        return _Found("preauth_close", ip, user or "", port)
    return None
