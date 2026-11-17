"""Compile condition syntax trees into fast, type-checked predicates.

Type errors are caught when a rule file is loaded, not when the first event
arrives: unknown fields (with a suggestion), ordering operators on text,
regular expressions on numbers, invalid regular expressions and literals of
the wrong type all raise :class:`RuleSyntaxError` with a column.
"""

from __future__ import annotations

import difflib
import operator
import re
from collections.abc import Callable
from typing import cast

from argus.events import FIELD_TYPES, Event
from argus.rules.errors import RuleSyntaxError
from argus.rules.parser import parse_expression
from argus.rules.syntax import And, Compare, Literal, Node, Not, Truthy

Predicate = Callable[[Event], bool]

_ORDERING: dict[str, Callable[[float, float], bool]] = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
}
_TEXT_ONLY = frozenset({"~", "!~", "contains", "icontains", "startswith", "endswith"})


def compile_expression(text: str) -> Predicate:
    """Parse and compile ``text``; raise :class:`RuleSyntaxError` on any problem."""
    return compile_node(parse_expression(text))


def compile_node(node: Node) -> Predicate:
    if isinstance(node, Compare):
        return _compile_compare(node)
    if isinstance(node, Truthy):
        if _field_type(node.field, node.pos) is not bool:
            raise RuleSyntaxError(
                f"field '{node.field}' is not a true/false field; compare it with a value",
                node.pos + 1,
            )
        return cast(Predicate, operator.attrgetter(node.field))
    if isinstance(node, Not):
        inner = compile_node(node.item)
        return lambda event: not inner(event)
    predicates = tuple(compile_node(item) for item in node.items)
    return _all_of(predicates) if isinstance(node, And) else _any_of(predicates)


def _all_of(predicates: tuple[Predicate, ...]) -> Predicate:
    def run(event: Event) -> bool:
        return all(predicate(event) for predicate in predicates)

    return run


def _any_of(predicates: tuple[Predicate, ...]) -> Predicate:
    def run(event: Event) -> bool:
        return any(predicate(event) for predicate in predicates)

    return run


def _field_type(name: str, pos: int) -> type:
    field_type = FIELD_TYPES.get(name)
    if field_type is None:
        close = difflib.get_close_matches(name, list(FIELD_TYPES), n=1)
        hint = f" (did you mean '{close[0]}'?)" if close else ""
        known = ", ".join(sorted(FIELD_TYPES))
        raise RuleSyntaxError(f"unknown field '{name}'{hint}; known fields: {known}", pos + 1)
    return field_type


def _check_literal(field: str, field_type: type, value: Literal, column: int) -> None:
    if field_type is bool:
        if not isinstance(value, bool):
            raise RuleSyntaxError(f"field '{field}' expects true or false", column)
    elif field_type is int:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise RuleSyntaxError(f"field '{field}' expects a number", column)
    elif not isinstance(value, str):
        raise RuleSyntaxError(f"field '{field}' expects a string", column)


def _compile_compare(node: Compare) -> Predicate:
    field_type = _field_type(node.field, node.pos)
    op = node.op
    if op in _ORDERING and field_type is not int:
        raise RuleSyntaxError(
            f"operator '{op}' needs a numeric field, '{node.field}' is text", node.pos + 1
        )
    if op in _TEXT_ONLY and field_type is not str:
        raise RuleSyntaxError(
            f"operator '{op}' needs a text field, '{node.field}' is not text", node.pos + 1
        )
    values = node.value if isinstance(node.value, tuple) else (node.value,)
    for value in values:
        _check_literal(node.field, field_type, value, node.value_pos + 1)

    get = cast(Callable[[Event], object], operator.attrgetter(node.field))
    if op == "in":
        members = frozenset(values)
        return lambda event: get(event) in members
    if op == "not in":
        excluded = frozenset(values)
        return lambda event: get(event) not in excluded
    if op == "==":
        return lambda event: get(event) == values[0]
    if op == "!=":
        return lambda event: get(event) != values[0]
    if op in _ORDERING:
        compare = _ORDERING[op]
        number = float(cast(float, values[0]))
        get_number = cast(Callable[[Event], int], get)
        return lambda event: compare(get_number(event), number)
    return _text_operator(op, cast(Callable[[Event], str], get), str(values[0]), node)


def _text_operator(op: str, get: Callable[[Event], str], value: str, node: Compare) -> Predicate:
    if op in ("~", "!~"):
        try:
            search = re.compile(value).search
        except re.error as exc:
            raise RuleSyntaxError(
                f"invalid regular expression: {exc}", node.value_pos + 1
            ) from None
        if op == "~":
            return lambda event: search(get(event)) is not None
        return lambda event: search(get(event)) is None
    if op == "contains":
        return lambda event: value in get(event)
    if op == "icontains":
        lowered = value.lower()
        return lambda event: lowered in get(event).lower()
    if op == "startswith":
        return lambda event: get(event).startswith(value)
    return lambda event: get(event).endswith(value)
