"""The normalized event every parser produces and every detector consumes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

WEB = "web"
SSH = "ssh"


@dataclass(frozen=True, slots=True)
class Event:
    """One parsed log line.

    Web fields stay empty for SSH events and the other way round, so rules can
    reference any field without checking the source first.
    """

    source: str
    ts: datetime
    ip: str
    file: str = ""
    line: int = 0
    raw: str = ""
    host: str = ""
    user: str = ""
    # Web (combined log format)
    method: str = ""
    target: str = ""
    path: str = ""
    query: str = ""
    uri: str = ""
    protocol: str = ""
    status: int = 0
    bytes: int = 0
    referrer: str = ""
    user_agent: str = ""
    # SSH (OpenSSH auth log)
    action: str = ""
    invalid_user: bool = False
    auth_method: str = ""
    port: int = 0

    @property
    def hour(self) -> int:
        """Hour of day in UTC (0-23)."""
        return self.ts.hour

    @property
    def ext(self) -> str:
        """Lower-case extension of the last path segment, without the dot."""
        name = self.path.rsplit("/", 1)[-1]
        stem, dot, suffix = name.rpartition(".")
        if not dot or not stem:
            return ""
        return suffix.lower()


FIELD_TYPES: Mapping[str, type] = MappingProxyType(
    {
        "source": str,
        "ip": str,
        "host": str,
        "user": str,
        "method": str,
        "target": str,
        "path": str,
        "query": str,
        "uri": str,
        "protocol": str,
        "status": int,
        "bytes": int,
        "referrer": str,
        "user_agent": str,
        "action": str,
        "invalid_user": bool,
        "auth_method": str,
        "port": int,
        "hour": int,
        "ext": str,
    }
)
"""Fields a rule may reference, with their types (used by the rule compiler)."""
