"""Errors raised by line parsers."""

from __future__ import annotations


class MalformedLineError(ValueError):
    """A line that does not match the expected log format.

    The reader catches this, counts the line under ``reason`` and keeps going:
    a malformed line must never stop a scan.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
