"""Load and validate TOML rule files.

A rule file is a list of ``[[rule]]`` tables. Every problem is reported as a
:class:`RuleError` whose message names the file, the rule and the problem, so a
typo in a custom rule never turns into a silent miss.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Mapping
from datetime import timedelta
from importlib import resources
from pathlib import Path
from typing import Any

from argus.alerts import Severity
from argus.attack import TACTIC_ORDER, TECHNIQUES
from argus.events import FIELD_TYPES, SSH, WEB
from argus.rules.compiler import Predicate, compile_expression
from argus.rules.errors import RuleError, RuleSyntaxError
from argus.rules.model import Kind, NewValue, Rule, Sequence, Step, Threshold, match_all
from argus.timeutil import parse_duration

_RULE_KEYS = frozenset(
    {
        "id",
        "title",
        "description",
        "severity",
        "technique",
        "tactic",
        "source",
        "when",
        "group_by",
        "threshold",
        "sequence",
        "new_value",
    }
)
_KIND_KEYS = ("threshold", "sequence", "new_value")
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")
_DEFAULT_WINDOW = timedelta(minutes=10)


class _Context:
    def __init__(self, origin: str, label: str) -> None:
        self.origin = origin
        self.label = label

    def error(self, message: str) -> RuleError:
        return RuleError(f"{self.origin}: {self.label}: {message}")


def builtin_rules() -> list[Rule]:
    """The detections shipped with Argus (``argus/rules/builtin/*.toml``)."""
    folder = resources.files("argus").joinpath("rules", "builtin")
    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in sorted(folder.iterdir(), key=lambda item: item.name):
        if entry.name.endswith(".toml"):
            loaded = load_rules_text(entry.read_text(encoding="utf-8"), f"builtin/{entry.name}")
            _check_duplicates(loaded, seen, f"builtin/{entry.name}")
            rules.extend(loaded)
    return rules


def load_rules(paths: Iterable[Path]) -> list[Rule]:
    """Load rule files; rule ids must be unique across all of them."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuleError(f"{path}: cannot read rule file ({exc.strerror or exc})") from None
        loaded = load_rules_text(text, str(path))
        _check_duplicates(loaded, seen, str(path))
        rules.extend(loaded)
    return rules


def _check_duplicates(rules: list[Rule], seen: set[str], origin: str) -> None:
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"{origin}: duplicate rule id '{rule.id}'")
        seen.add(rule.id)


def load_rules_text(text: str, origin: str) -> list[Rule]:
    """Parse one rule file's text. ``origin`` is used in error messages."""
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"{origin}: invalid TOML: {exc}") from None
    for key in document:
        if key != "rule":
            raise RuleError(f"{origin}: unknown top-level key '{key}'; expected [[rule]] tables")
    tables = document.get("rule", [])
    if not isinstance(tables, list):
        raise RuleError(f"{origin}: 'rule' must be an array of tables ([[rule]])")
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, table in enumerate(tables, 1):
        rule = _build_rule(table, _Context(origin, f"rule #{index}"))
        if rule.id in seen:
            raise RuleError(f"{origin}: duplicate rule id '{rule.id}'")
        seen.add(rule.id)
        rules.append(rule)
    return rules


def _build_rule(table: Mapping[str, Any], ctx: _Context) -> Rule:
    rule_id = _require_str(table, "id", ctx)
    if not _ID.fullmatch(rule_id):
        raise ctx.error("id must be lower-case letters, digits and dashes (max 64)")
    ctx.label = f"rule '{rule_id}'"
    _reject_unknown(table, _RULE_KEYS, ctx)

    title = _require_str(table, "title", ctx)
    description = _optional_str(table, "description", ctx) or ""
    try:
        severity = Severity.parse(_require_str(table, "severity", ctx))
    except ValueError as exc:
        raise ctx.error(str(exc)) from None
    technique, tactic = _technique(table, ctx)
    source = _optional_str(table, "source", ctx)
    if source not in (None, WEB, SSH):
        raise ctx.error(f"source must be '{WEB}' or '{SSH}', got {source!r}")
    when_text = _optional_str(table, "when", ctx) or ""
    when = _compile(when_text, "when", ctx) if when_text else match_all
    group_by = _group_by(table, ctx)
    kind = _kind(table, ctx)
    return Rule(
        id=rule_id,
        title=title,
        description=description.strip(),
        severity=severity,
        technique=technique,
        tactic=tactic,
        source=source,
        when_text=when_text,
        when=when,
        kind=kind,
        group_by=group_by,
        origin=ctx.origin,
    )


def _technique(table: Mapping[str, Any], ctx: _Context) -> tuple[str, str]:
    technique = _require_str(table, "technique", ctx)
    if not _TECHNIQUE.fullmatch(technique):
        raise ctx.error(f"technique must look like T1234 or T1234.001, got {technique!r}")
    tactic = _optional_str(table, "tactic", ctx)
    if tactic is not None and tactic not in TACTIC_ORDER:
        raise ctx.error(f"tactic must be one of {', '.join(TACTIC_ORDER)}, got {tactic!r}")
    known = TECHNIQUES.get(technique)
    if tactic is None:
        if known is None:
            raise ctx.error(
                f"technique {technique} is not in the built-in catalog; add a 'tactic' key"
            )
        tactic = known.tactic
    return technique, tactic


def _group_by(table: Mapping[str, Any], ctx: _Context) -> tuple[str, ...]:
    value = table.get("group_by", ["ip"])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ctx.error("group_by must be a list of field names")
    for name in value:
        _check_field(name, "group_by", ctx)
    return tuple(value)


def _kind(table: Mapping[str, Any], ctx: _Context) -> Kind:
    present = [key for key in _KIND_KEYS if key in table]
    if len(present) > 1:
        raise ctx.error(f"use at most one of {', '.join(_KIND_KEYS)} (found {', '.join(present)})")
    if not present:
        return Threshold(window=_DEFAULT_WINDOW)
    key = present[0]
    body = table[key]
    if not isinstance(body, dict):
        raise ctx.error(f"'{key}' must be a table")
    if key == "threshold":
        _reject_unknown(body, frozenset({"count", "window", "distinct"}), ctx, key)
        distinct = _optional_str(body, "distinct", ctx)
        if distinct is not None:
            _check_field(distinct, "threshold.distinct", ctx)
        return Threshold(
            window=_duration(body.get("window", "10m"), f"{key}.window", ctx),
            count=_count(body.get("count", 1), f"{key}.count", ctx),
            distinct=distinct,
        )
    if key == "sequence":
        _reject_unknown(body, frozenset({"within", "steps"}), ctx, key)
        if "within" not in body:
            raise ctx.error("missing required key 'sequence.within'")
        steps = body.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            raise ctx.error("sequence needs at least two steps")
        return Sequence(
            within=_duration(body["within"], "sequence.within", ctx),
            steps=tuple(_step(step, number, ctx) for number, step in enumerate(steps, 1)),
        )
    _reject_unknown(body, frozenset({"field", "learn"}), ctx, key)
    field = _require_str(body, "field", ctx)
    _check_field(field, "new_value.field", ctx)
    if "learn" not in body:
        raise ctx.error("missing required key 'new_value.learn'")
    return NewValue(field=field, learn=_duration(body["learn"], "new_value.learn", ctx))


def _step(step: object, number: int, ctx: _Context) -> Step:
    if not isinstance(step, dict):
        raise ctx.error(f"sequence step {number} must be a table")
    _reject_unknown(step, frozenset({"when", "count"}), ctx, f"sequence step {number}")
    when_text = _require_str(step, "when", ctx)
    return Step(
        when_text=when_text,
        when=_compile(when_text, f"sequence step {number}", ctx),
        count=_count(step.get("count", 1), f"sequence step {number} count", ctx),
    )


def _compile(text: str, where: str, ctx: _Context) -> Predicate:
    try:
        return compile_expression(text)
    except RuleSyntaxError as exc:
        raise ctx.error(f"{where}: {exc}") from None


def _check_field(name: str, where: str, ctx: _Context) -> None:
    if name not in FIELD_TYPES:
        raise ctx.error(f"{where}: unknown field '{name}'")


def _duration(value: object, where: str, ctx: _Context) -> timedelta:
    if not isinstance(value, str):
        raise ctx.error(f'{where} must be a duration string such as "5m"')
    try:
        return parse_duration(value)
    except ValueError as exc:
        raise ctx.error(f"{where}: {exc}") from None


def _count(value: object, where: str, ctx: _Context) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ctx.error(f"{where}: count must be an integer >= 1")
    return value


def _reject_unknown(
    table: Mapping[str, Any], allowed: frozenset[str], ctx: _Context, where: str = ""
) -> None:
    for key in table:
        if key not in allowed:
            prefix = f"{where}: " if where else ""
            raise ctx.error(f"{prefix}unknown key '{key}'")


def _require_str(table: Mapping[str, Any], key: str, ctx: _Context) -> str:
    if key not in table:
        raise ctx.error(f"missing required key '{key}'")
    value = table[key]
    if not isinstance(value, str) or not value.strip():
        raise ctx.error(f"'{key}' must be a non-empty string")
    return value


def _optional_str(table: Mapping[str, Any], key: str, ctx: _Context) -> str | None:
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, str):
        raise ctx.error(f"'{key}' must be a string")
    return value
