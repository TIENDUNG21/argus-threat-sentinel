"""Errors raised while loading rules."""

from __future__ import annotations


class RuleSyntaxError(ValueError):
    """A problem inside a condition expression, with a 1-based column."""

    def __init__(self, message: str, column: int) -> None:
        super().__init__(f"column {column}: {message}")
        self.message = message
        self.column = column


class RuleError(ValueError):
    """A rule file that cannot be loaded. The message names the file and rule id."""
