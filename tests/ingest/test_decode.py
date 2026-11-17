from hypothesis import given
from hypothesis import strategies as st

from argus.ingest.decode import build_uri, decode_component, unescape_log_field


def test_decode_component_handles_double_encoding() -> None:
    assert decode_component("%252e%252e%252f") == "../"
    assert decode_component("%2e%2e/etc/passwd") == "../etc/passwd"


def test_decode_component_stops_when_stable() -> None:
    assert decode_component("100%") == "100%"
    assert decode_component("plain/path") == "plain/path"


def test_build_uri_decodes_plus_only_in_query() -> None:
    assert build_uri("/a+b/%3Cx%3E", "q=union+select") == "/a+b/<x>?q=union select"
    assert build_uri("/only", "") == "/only"


def test_unescape_log_field_handles_backslash_and_hex_escapes() -> None:
    assert unescape_log_field(r"say \"hi\"") == 'say "hi"'
    assert unescape_log_field(r"\x16\x03\x01") == "\x16\x03\x01"
    assert unescape_log_field(r"caf\xC3\xA9") == "café"
    assert unescape_log_field("no escapes") == "no escapes"


@given(st.text())
def test_decoders_never_raise(text: str) -> None:
    decode_component(text)
    unescape_log_field(text)
    build_uri(text, text)
