"""Turn simulated records into log lines, and break a few lines on purpose."""

from __future__ import annotations

import random
import re
import string
import zlib

from argus.simulate.world import HOST, AuthLine, WebHit

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_GARBAGE = string.ascii_letters + string.digits + "!@#$%^&*()[]{};:<>?/|~ \x00\x01\x7f"


def escape_field(value: str) -> str:
    """Escape like nginx: quote, backslash and non-printable bytes become ``\\xHH``."""
    out: list[str] = []
    for byte in value.encode("utf-8"):
        if byte in (0x22, 0x5C) or byte < 0x20 or byte >= 0x7F:
            out.append(f"\\x{byte:02X}")
        else:
            out.append(chr(byte))
    return "".join(out)


def render_web(hit: WebHit) -> str:
    ts = hit.ts
    stamp = f"{ts.day:02d}/{_MONTHS[ts.month - 1]}/{ts.year}:{ts:%H:%M:%S} +0000"
    request = escape_field(f"{hit.method} {hit.target} HTTP/1.1")
    referrer = escape_field(hit.referrer) or "-"
    agent = escape_field(hit.user_agent) or "-"
    return f'{hit.ip} - - [{stamp}] "{request}" {hit.status} {hit.size} "{referrer}" "{agent}"'


def render_auth(line: AuthLine) -> str:
    pid = 1000 + zlib.crc32(line.message.encode("utf-8")) % 30000
    stamp = line.ts.isoformat(timespec="microseconds")
    return f"{stamp} {HOST} {line.program}[{pid}]: {line.message}"


def _broken_web(rng: random.Random, source: str) -> str:
    kind = rng.randrange(3)
    if kind == 0:
        cut = source.index('"') + rng.randint(1, 8)
        return source[:cut]
    if kind == 1:
        return re.sub(r"/[A-Z][a-z]{2}/", "/Foo/", source, count=1)
    return "\x16\x03\x01" + "".join(rng.choice(_GARBAGE) for _ in range(rng.randint(5, 80)))


def _broken_auth(rng: random.Random, source: str) -> str:
    kind = rng.randrange(3)
    if kind == 0:
        return source[: rng.randint(5, 25)]
    if kind == 1:
        return source[:5] + "13" + source[7:]
    return "#" + "".join(rng.choice(_GARBAGE) for _ in range(rng.randint(5, 80)))


def inject_malformed(rng: random.Random, lines: list[str], kind: str, rate: float) -> int:
    """Insert ``round(len(lines) * rate)`` (at least one) broken lines; return how many."""
    if not lines or rate <= 0:
        return 0
    originals = list(lines)
    count = max(1, round(len(lines) * rate))
    for _ in range(count):
        source = rng.choice(originals)
        broken = _broken_web(rng, source) if kind == "web" else _broken_auth(rng, source)
        lines.insert(rng.randrange(len(lines) + 1), broken)
    return count
