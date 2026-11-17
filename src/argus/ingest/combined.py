"""Parser for the nginx/Apache "combined" (and "common") access log format.

%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta, timezone
from functools import lru_cache

from argus.events import WEB, Event
from argus.ingest.decode import build_uri, unescape_log_field
from argus.ingest.errors import MalformedLineError

_QUOTED = r'"((?:[^"\\]|\\.)*)"'
_LINE = re.compile(
    r"(\S+) \S+ (\S+) \[([^\]]*)\] "
    + _QUOTED
    + r" (\S+) (\S+)(?: "
    + _QUOTED
    + " "
    + _QUOTED
    + ")?"
)
_TIME = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
_HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_METHOD = re.compile(r"[A-Z]{3,10}")
_MONTHS = {
    name: index
    for index, name in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1
    )
}


@lru_cache(maxsize=64)
def _offset(sign: str, hours: int, minutes: int) -> timezone:
    delta = timedelta(hours=hours, minutes=minutes)
    return timezone(-delta if sign == "-" else delta)


@lru_cache(maxsize=65536)
def _valid_client(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return _HOSTNAME.fullmatch(token) is not None
    return True


def parse_clf_time(text: str) -> datetime:
    """Parse ``10/Oct/2000:13:55:36 -0700`` into an aware UTC datetime."""
    match = _TIME.fullmatch(text)
    if match is None:
        raise MalformedLineError("bad timestamp")
    day, mon, year, hh, mm, ss, sign, oh, om = match.groups()
    month = _MONTHS.get(mon.lower())
    if month is None:
        raise MalformedLineError("bad timestamp")
    try:
        local = datetime(
            int(year),
            month,
            int(day),
            int(hh),
            int(mm),
            int(ss),
            tzinfo=_offset(sign, int(oh), int(om)),
        )
    except ValueError:
        raise MalformedLineError("bad timestamp") from None
    return local.astimezone(UTC)


def parse_combined(line: str, *, file: str = "", line_no: int = 0) -> Event:
    """Parse one access-log line or raise :class:`MalformedLineError`."""
    match = _LINE.match(line)
    if match is None:
        raise MalformedLineError("not combined log format")
    ip, user, time_text, request, status_text, bytes_text, referrer, agent = match.groups()
    rest = line[match.end() :]
    if rest and (agent is None or not rest.startswith(" ")):
        raise MalformedLineError("not combined log format")
    if not _valid_client(ip):
        raise MalformedLineError("bad client address")
    ts = parse_clf_time(time_text)
    if len(status_text) != 3 or not status_text.isdigit() or not 100 <= int(status_text) <= 599:
        raise MalformedLineError("bad status")
    if bytes_text == "-":
        size = 0
    elif bytes_text.isdigit():
        size = int(bytes_text)
    else:
        raise MalformedLineError("bad byte count")

    request = unescape_log_field(request)
    method = protocol = path = query = ""
    target = request
    parts = request.split(" ")
    if 2 <= len(parts) <= 3 and _METHOD.fullmatch(parts[0]):
        method, target = parts[0], parts[1]
        protocol = parts[2] if len(parts) == 3 else ""
        path, _, query = target.partition("?")
        uri = build_uri(path, query)
    else:
        uri = build_uri(request, "")

    return Event(
        source=WEB,
        ts=ts,
        ip=ip,
        file=file,
        line=line_no,
        raw=line,
        user="" if user == "-" else user,
        method=method,
        target=target,
        path=path,
        query=query,
        uri=uri,
        protocol=protocol,
        status=int(status_text),
        bytes=size,
        referrer=_dash_to_empty(unescape_log_field(referrer or "")),
        user_agent=_dash_to_empty(unescape_log_field(agent or "")),
    )


def _dash_to_empty(value: str) -> str:
    return "" if value == "-" else value
