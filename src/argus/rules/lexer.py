"""Tokenizer for the rule condition language.

String literals are *raw*: a backslash only escapes the surrounding quote
character (and ``\\`` is kept as two characters), so regular expressions can be
written without double escaping, e.g. ``path ~ "\\.php$"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from argus.rules.errors import RuleSyntaxError

KEYWORDS = frozenset(
    {"and", "or", "not", "in", "contains", "icontains", "startswith", "endswith", "true", "false"}
)
_OPERATORS = ("==", "!=", "<=", ">=", "!~", "<", ">", "~")
_PUNCTUATION = {"(": "lparen", ")": "rparen", "[": "lbracket", "]": "rbracket", ",": "comma"}
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    """One of ident, keyword, string, number, op, lparen, rparen, lbracket, rbracket, comma, eof."""
    value: str
    pos: int
    """Zero-based offset in the source text."""


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    length = len(text)
    while pos < length:
        char = text[pos]
        if char.isspace():
            pos += 1
            continue
        if char in "\"'":
            value, pos_after = _read_string(text, pos)
            tokens.append(Token("string", value, pos))
            pos = pos_after
            continue
        if char in _PUNCTUATION:
            tokens.append(Token(_PUNCTUATION[char], char, pos))
            pos += 1
            continue
        operator = next((op for op in _OPERATORS if text.startswith(op, pos)), None)
        if operator is not None:
            tokens.append(Token("op", operator, pos))
            pos += len(operator)
            continue
        if (match := _NUMBER.match(text, pos)) is not None:
            tokens.append(Token("number", match.group(), pos))
            pos = match.end()
            continue
        if (match := _IDENT.match(text, pos)) is not None:
            word = match.group()
            tokens.append(Token("keyword" if word in KEYWORDS else "ident", word, pos))
            pos = match.end()
            continue
        raise RuleSyntaxError(f"unexpected character {char!r}", pos + 1)
    tokens.append(Token("eof", "", length))
    return tokens


def _read_string(text: str, start: int) -> tuple[str, int]:
    quote = text[start]
    out: list[str] = []
    pos = start + 1
    while pos < len(text):
        char = text[pos]
        if char == "\\" and pos + 1 < len(text):
            following = text[pos + 1]
            if following == quote:
                out.append(quote)
                pos += 2
                continue
            if following == "\\":
                out.append("\\\\")
                pos += 2
                continue
        if char == quote:
            return "".join(out), pos + 1
        out.append(char)
        pos += 1
    raise RuleSyntaxError("unterminated string", start + 1)
