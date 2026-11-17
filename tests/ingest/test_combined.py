import contextlib
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.events import Event
from argus.ingest.combined import parse_combined
from argus.ingest.errors import MalformedLineError

NGINX = (
    '198.18.4.7 - - [02/Mar/2026:10:15:32 +0000] "GET /products?id=42&ref=home HTTP/1.1" '
    '200 5123 "https://shop.example/" "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"'
)


def test_parses_nginx_combined_line() -> None:
    event = parse_combined(NGINX, file="access.log", line_no=7)
    assert event == Event(
        source="web",
        ts=datetime(2026, 3, 2, 10, 15, 32, tzinfo=UTC),
        ip="198.18.4.7",
        file="access.log",
        line=7,
        raw=NGINX,
        method="GET",
        target="/products?id=42&ref=home",
        path="/products",
        query="id=42&ref=home",
        uri="/products?id=42&ref=home",
        protocol="HTTP/1.1",
        status=200,
        bytes=5123,
        referrer="https://shop.example/",
        user_agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
    )


def test_converts_timezone_offset_to_utc() -> None:
    line = '203.0.113.9 - frank [10/Oct/2026:13:55:36 -0700] "GET / HTTP/1.0" 200 2326 "-" "-"'
    event = parse_combined(line)
    assert event.ts == datetime(2026, 10, 10, 20, 55, 36, tzinfo=UTC)
    assert event.user == "frank"
    assert event.referrer == ""
    assert event.user_agent == ""


def test_apache_escaped_quotes_inside_user_agent() -> None:
    line = (
        '198.18.0.2 - - [02/Mar/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" '
        r'"() { :; }; echo \"probe\""'
    )
    assert parse_combined(line).user_agent == '() { :; }; echo "probe"'


def test_dash_bytes_and_common_format_without_agent() -> None:
    line = '198.18.0.3 - - [02/Mar/2026:10:00:00 +0000] "HEAD / HTTP/1.1" 304 -'
    event = parse_combined(line)
    assert event.bytes == 0
    assert event.user_agent == ""


def test_ipv6_client() -> None:
    line = '2001:db8::7 - - [02/Mar/2026:10:00:00 +0000] "GET / HTTP/2.0" 200 1 "-" "curl/8.5"'
    assert parse_combined(line).ip == "2001:db8::7"


def test_non_http_request_keeps_raw_request() -> None:
    line = r'198.18.0.4 - - [02/Mar/2026:10:00:00 +0000] "\x16\x03\x01\x00" 400 157 "-" "-"'
    event = parse_combined(line)
    assert event.method == ""
    assert event.status == 400
    assert event.uri == "\x16\x03\x01\x00"


def test_encoded_traversal_is_decoded_in_uri() -> None:
    line = (
        "198.18.0.5 - - [02/Mar/2026:10:00:00 +0000] "
        '"GET /download?file=%252e%252e%252fetc%252fpasswd HTTP/1.1" 400 0 "-" "-"'
    )
    event = parse_combined(line)
    assert event.query == "file=%252e%252e%252fetc%252fpasswd"
    assert event.uri == "/download?file=../etc/passwd"


def test_trailing_custom_fields_are_tolerated() -> None:
    assert parse_combined(NGINX + ' "198.51.100.1" rt=0.004').status == 200


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("", "not combined log format"),
        ("garbage line without structure", "not combined log format"),
        (NGINX[:60], "not combined log format"),
        (NGINX.replace("02/Mar/2026", "31/Feb/2026"), "bad timestamp"),
        (NGINX.replace("02/Mar/2026", "02/Foo/2026"), "bad timestamp"),
        (NGINX.replace(" 200 ", " 2x0 "), "bad status"),
        (NGINX.replace(" 200 ", " 999 "), "bad status"),
        (NGINX.replace(" 5123 ", " 12ab "), "bad byte count"),
        (NGINX.replace("198.18.4.7", "not/an/ip"), "bad client address"),
    ],
)
def test_malformed_lines_raise_with_reason(line: str, reason: str) -> None:
    with pytest.raises(MalformedLineError) as exc:
        parse_combined(line)
    assert exc.value.reason == reason


@given(st.text(max_size=300))
def test_arbitrary_text_never_raises_anything_else(text: str) -> None:
    with contextlib.suppress(MalformedLineError):
        parse_combined(text)
