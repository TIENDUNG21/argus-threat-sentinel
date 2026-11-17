import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.rules.errors import RuleSyntaxError
from argus.rules.lexer import tokenize
from argus.rules.parser import parse_expression
from argus.rules.syntax import And, Compare, Not, Or, Truthy


def test_tokenize_positions_and_kinds() -> None:
    tokens = tokenize('status >= 400 and path ~ "^/a"')
    assert [(t.kind, t.value, t.pos) for t in tokens] == [
        ("ident", "status", 0),
        ("op", ">=", 7),
        ("number", "400", 10),
        ("keyword", "and", 14),
        ("ident", "path", 18),
        ("op", "~", 23),
        ("string", "^/a", 25),
        ("eof", "", 30),
    ]


def test_strings_are_raw_except_for_escaped_quotes() -> None:
    assert tokenize(r'"\d+\.\d+"')[0].value == r"\d+\.\d+"
    assert tokenize(r'"say \"hi\""')[0].value == 'say "hi"'
    assert tokenize(r"'it\'s'")[0].value == "it's"
    assert tokenize(r'"C:\\"')[0].value == "C:\\\\"


def test_precedence_not_binds_tighter_than_and_than_or() -> None:
    tree = parse_expression("a == 1 or b == 2 and not c")
    assert tree == Or(
        (
            Compare("a", "==", 1, 0),
            And((Compare("b", "==", 2, 10), Not(Truthy("c", 25)))),
        )
    )


def test_parentheses_override_precedence() -> None:
    tree = parse_expression("(a == 1 or b == 2) and c")
    assert isinstance(tree, And)
    assert isinstance(tree.items[0], Or)


def test_list_operators_and_not_in() -> None:
    assert parse_expression('action in ["a", "b"]') == Compare("action", "in", ("a", "b"), 0)
    assert parse_expression("status not in [404, 410]") == Compare(
        "status", "not in", (404, 410), 0
    )


def test_word_operators_and_literals() -> None:
    assert parse_expression('ua icontains "Bot"') == Compare("ua", "icontains", "Bot", 0)
    assert parse_expression("invalid_user == true") == Compare("invalid_user", "==", True, 0)
    assert parse_expression("bytes > 1.5") == Compare("bytes", ">", 1.5, 0)
    assert parse_expression("port != -1") == Compare("port", "!=", -1, 0)


@pytest.mark.parametrize(
    ("text", "column", "fragment"),
    [
        ('path ~ "unterminated', 8, "unterminated string"),
        ("a == 1 and", 11, "expected a field name"),
        ("a in []", 6, "empty list"),
        ("a == 1 $ b", 8, "unexpected character"),
        ("a == 1 b", 8, "unexpected"),
        ("(a == 1", 8, "expected ')'"),
        ("a ==", 5, "expected a value"),
        ("", 1, "expected a field name"),
        ("a in [1, ]", 10, "expected a value"),
    ],
)
def test_syntax_errors_report_column(text: str, column: int, fragment: str) -> None:
    with pytest.raises(RuleSyntaxError) as exc:
        parse_expression(text)
    assert exc.value.column == column
    assert fragment in str(exc.value)


def test_deep_nesting_is_an_error_not_a_crash() -> None:
    with pytest.raises(RuleSyntaxError, match="nested too deeply"):
        parse_expression("(" * 500 + "a" + ")" * 500)
    with pytest.raises(RuleSyntaxError, match="nested too deeply"):
        parse_expression("not " * 500 + "a")


@given(st.text(max_size=200))
def test_arbitrary_text_parses_or_raises_syntax_error(text: str) -> None:
    with contextlib.suppress(RuleSyntaxError):
        parse_expression(text)
