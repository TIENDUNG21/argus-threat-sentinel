"""Decoding helpers for values that attackers like to obfuscate."""

from __future__ import annotations

import re
from urllib.parse import unquote, unquote_plus

_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{2}|.)", re.DOTALL)
_SIMPLE_ESCAPES = {"b": "\b", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def decode_component(text: str, *, plus: bool = False, rounds: int = 3) -> str:
    """Percent-decode repeatedly so double-encoded payloads (``%252e``) show up.

    Stops early once a round changes nothing. ``plus`` turns ``+`` into a space,
    which is correct for query strings only.
    """
    decode = unquote_plus if plus else unquote
    current = text
    for _ in range(rounds):
        decoded = decode(current, errors="replace")
        if decoded == current:
            break
        current = decoded
    return current


def build_uri(path: str, query: str) -> str:
    """Decoded ``path?query`` used by detections."""
    decoded = decode_component(path)
    if query:
        return f"{decoded}?{decode_component(query, plus=True)}"
    return decoded


def unescape_log_field(text: str) -> str:
    r"""Undo the escaping nginx and Apache apply inside quoted log fields.

    Handles ``\"``, ``\\``, ``\xHH`` (raw bytes, decoded as UTF-8) and the
    usual single-letter escapes such as ``\n``.
    """
    if "\\" not in text:
        return text
    out = bytearray()
    pos = 0
    for match in _ESCAPE.finditer(text):
        out += text[pos : match.start()].encode("utf-8", "surrogatepass")
        token = match.group(1)
        if len(token) == 3 and token[0] == "x":
            out.append(int(token[1:], 16))
        else:
            out += _SIMPLE_ESCAPES.get(token, token).encode("utf-8", "surrogatepass")
        pos = match.end()
    out += text[pos:].encode("utf-8", "surrogatepass")
    return out.decode("utf-8", "replace")
