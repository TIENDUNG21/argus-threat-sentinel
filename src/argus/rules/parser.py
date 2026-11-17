"""Recursive-descent parser for the rule condition language.

Grammar (``not`` binds tighter than ``and``, which binds tighter than ``or``)::

    expr     := and_expr ("or" and_expr)*
    and_expr := unary ("and" unary)*
    unary    := "not" unary | primary
    primary  := "(" expr ")" | FIELD [operator operand]
    operator := == != < <= > >= ~ !~ in "not in" contains icontains startswith endswith
    operand  := literal | "[" literal ("," literal)* "]"
    literal  := STRING | NUMBER | true | false
"""

from __future__ import annotations

from argus.rules.errors import RuleSyntaxError
from argus.rules.lexer import Token, tokenize
from argus.rules.syntax import And, Compare, Literal, Node, Not, Or, Truthy, Value

MAX_DEPTH = 64
SYMBOL_OPERATORS = frozenset({"==", "!=", "<", "<=", ">", ">=", "~", "!~"})
WORD_OPERATORS = frozenset({"in", "contains", "icontains", "startswith", "endswith"})
LIST_OPERATORS = frozenset({"in", "not in"})


def parse_expression(text: str) -> Node:
    """Parse ``text`` into a syntax tree or raise :class:`RuleSyntaxError`."""
    return _Parser(tokenize(text)).parse()


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.index = 0
        self.depth = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.index]

    def advance(self) -> Token:
        token = self.tokens[self.index]
        if token.kind != "eof":
            self.index += 1
        return token

    def at_keyword(self, word: str, offset: int = 0) -> bool:
        index = min(self.index + offset, len(self.tokens) - 1)
        token = self.tokens[index]
        return token.kind == "keyword" and token.value == word

    def error(self, message: str, token: Token | None = None) -> RuleSyntaxError:
        return RuleSyntaxError(message, (token or self.current).pos + 1)

    def parse(self) -> Node:
        node = self.expr()
        if self.current.kind != "eof":
            raise self.error(f"unexpected {self.current.value!r}")
        return node

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise self.error("expression nested too deeply")

    def expr(self) -> Node:
        items = [self.and_expr()]
        while self.at_keyword("or"):
            self.advance()
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def and_expr(self) -> Node:
        items = [self.unary()]
        while self.at_keyword("and"):
            self.advance()
            items.append(self.unary())
        return items[0] if len(items) == 1 else And(tuple(items))

    def unary(self) -> Node:
        if self.at_keyword("not"):
            self.advance()
            self.enter()
            node = Not(self.unary())
            self.depth -= 1
            return node
        return self.primary()

    def primary(self) -> Node:
        token = self.current
        if token.kind == "lparen":
            self.advance()
            self.enter()
            node = self.expr()
            self.depth -= 1
            if self.current.kind != "rparen":
                raise self.error("expected ')'")
            self.advance()
            return node
        if token.kind != "ident":
            raise self.error("expected a field name or '('")
        self.advance()
        operator = self.operator()
        if operator is None:
            return Truthy(token.value, token.pos)
        value_token = self.current
        value: Value = self.list_literal() if operator in LIST_OPERATORS else self.literal()
        return Compare(token.value, operator, value, token.pos, value_token.pos)

    def operator(self) -> str | None:
        token = self.current
        if token.kind == "op" and token.value in SYMBOL_OPERATORS:
            self.advance()
            return token.value
        if token.kind == "keyword" and token.value in WORD_OPERATORS:
            self.advance()
            return token.value
        if self.at_keyword("not") and self.at_keyword("in", offset=1):
            self.advance()
            self.advance()
            return "not in"
        return None

    def literal(self) -> Literal:
        token = self.current
        if token.kind == "string":
            self.advance()
            return token.value
        if token.kind == "number":
            self.advance()
            return float(token.value) if "." in token.value else int(token.value)
        if token.kind == "keyword" and token.value in ("true", "false"):
            self.advance()
            return token.value == "true"
        raise self.error("expected a value (string, number, true or false)")

    def list_literal(self) -> tuple[Literal, ...]:
        start = self.current
        if start.kind != "lbracket":
            raise self.error("expected '[' to start a list")
        self.advance()
        if self.current.kind == "rbracket":
            raise self.error("empty list", start)
        items = [self.literal()]
        while self.current.kind == "comma":
            self.advance()
            items.append(self.literal())
        if self.current.kind != "rbracket":
            raise self.error("expected ',' or ']'")
        self.advance()
        return tuple(items)
