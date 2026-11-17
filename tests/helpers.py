"""Event builders shared by the tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from argus.events import SSH, WEB, Event
from argus.ingest.decode import build_uri

BASE = datetime(2026, 3, 2, 12, 0, tzinfo=UTC)
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


def at(seconds: float) -> datetime:
    return BASE + timedelta(seconds=seconds)


def web(
    target: str = "/",
    *,
    t: float = 0,
    ip: str = "198.18.0.10",
    method: str = "GET",
    status: int = 200,
    size: int = 1024,
    ua: str = BROWSER,
    referrer: str = "",
) -> Event:
    path, _, query = target.partition("?")
    return Event(
        source=WEB,
        ts=at(t),
        ip=ip,
        raw=f'{ip} "{method} {target}" {status}',
        method=method,
        target=target,
        path=path,
        query=query,
        uri=build_uri(path, query),
        protocol="HTTP/1.1",
        status=status,
        bytes=size,
        referrer=referrer,
        user_agent=ua,
    )


def ssh(
    action: str,
    *,
    t: float = 0,
    ip: str = "198.18.1.10",
    user: str = "root",
    invalid: bool = False,
) -> Event:
    return Event(
        source=SSH,
        ts=at(t),
        ip=ip,
        raw=f"sshd {action} {user} from {ip}",
        host="web01",
        user=user,
        action=action,
        invalid_user=invalid,
        auth_method="password" if "password" in action else "",
        port=50000,
    )
