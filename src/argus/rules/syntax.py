"""Syntax tree of a condition expression."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

Literal = str | int | float | bool
Value = Literal | tuple[Literal, ...]


@dataclass(frozen=True, slots=True)
class Compare:
    """``field op value``; ``pos`` is the zero-based offset of the field name."""

    field: str
    op: str
    value: Value
    pos: int
    value_pos: int = dataclasses.field(default=0, compare=False)


@dataclass(frozen=True, slots=True)
class Truthy:
    """A bare boolean field such as ``invalid_user``."""

    field: str
    pos: int


@dataclass(frozen=True, slots=True)
class Not:
    item: Node


@dataclass(frozen=True, slots=True)
class And:
    items: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Or:
    items: tuple[Node, ...]


Node = Compare | Truthy | Not | And | Or
