from datetime import UTC, datetime

import pytest

from argus.events import Event
from argus.rules.compiler import compile_expression
from argus.rules.errors import RuleSyntaxError

WEB = Event(
    source="web",
    ts=datetime(2026, 3, 2, 3, 0, tzinfo=UTC),
    ip="198.18.0.1",
    method="GET",
    path="/wp-login.php",
    uri="/wp-login.php?redirect=../../etc/passwd",
    status=404,
    bytes=512,
    user_agent="Mozilla/5.0 (compatible; Nikto/2.5)",
)
SSH = Event(
    source="ssh",
    ts=datetime(2026, 3, 2, 3, 0, tzinfo=UTC),
    ip="198.18.0.2",
    action="failed_password",
    user="root",
    invalid_user=True,
    port=22,
)


@pytest.mark.parametrize(
    ("expression", "web", "ssh"),
    [
        ('source == "web"', True, False),
        ('source != "web"', False, True),
        ("status >= 400", True, False),
        ("status < 400", False, True),
        ("bytes > 511.5", True, False),
        ("bytes <= 512", True, True),
        (r'uri ~ "\.\./"', True, False),
        (r'uri !~ "\.\./"', False, True),
        ('user_agent ~ "(?i)nikto"', True, False),
        ('user_agent contains "Nikto"', True, False),
        ('user_agent contains "nikto"', False, False),
        ('user_agent icontains "NIKTO"', True, False),
        ('path startswith "/wp-"', True, False),
        ('path endswith ".php"', True, False),
        ('ext == "php"', True, False),
        ("hour == 3", True, True),
        ('action in ["failed_password", "invalid_user"]', False, True),
        ("status not in [200, 404]", False, True),
        ("invalid_user", False, True),
        ("not invalid_user", True, False),
        ("invalid_user == true", False, True),
        ('status == 404 and method == "GET"', True, False),
        ('status == 404 or user == "root"', True, True),
        ('not (status == 404 or user == "root")', False, False),
    ],
)
def test_operators_evaluate(expression: str, web: bool, ssh: bool) -> None:
    predicate = compile_expression(expression)
    assert predicate(WEB) is web
    assert predicate(SSH) is ssh


@pytest.mark.parametrize(
    ("expression", "column", "fragment"),
    [
        ('pth == "/"', 1, "unknown field 'pth' (did you mean 'path'?)"),
        ('xyz == "/"', 1, "unknown field 'xyz'"),
        ("path > 3", 1, "needs a numeric field"),
        ('status == "404"', 11, "expects a number"),
        ("path == 3", 9, "expects a string"),
        ("invalid_user == 1", 17, "expects true or false"),
        ('status ~ "4.."', 1, "needs a text field"),
        ('path ~ "(unclosed"', 8, "invalid regular expression"),
        ("path", 1, "is not a true/false field"),
        ('status in [404, "x"]', 11, "expects a number"),
        ("status contains 4", 1, "needs a text field"),
        ("path contains 4", 15, "expects a string"),
    ],
)
def test_type_errors_name_the_problem(expression: str, column: int, fragment: str) -> None:
    with pytest.raises(RuleSyntaxError) as exc:
        compile_expression(expression)
    assert fragment in exc.value.message
    assert exc.value.column == column
