"""URL normalisation: decoding, authority parsing and obfuscation tracking."""

from __future__ import annotations

import pytest

from mlwsg.features.normalize import (
    candidate_destinations,
    extract_urls_from_text,
    iterative_unquote,
    looks_like_destination,
    normalize_url,
)


def test_plain_url_is_decomposed():
    result = normalize_url("https://cdn.example.com:8443/static/app.js?v=3#top")
    assert result.parse_ok
    assert (result.scheme, result.host, result.port) == ("https", "cdn.example.com", 8443)
    assert result.path == "/static/app.js"
    assert result.params == [("v", "3")]
    assert result.fragment == "top"


def test_percent_encoded_host_is_decoded():
    result = normalize_url("http://%31%32%37%2e%30%2e%30%2e%31/admin")
    assert result.host == "127.0.0.1"
    assert result.decode_rounds == 1


def test_double_encoding_is_counted():
    result = normalize_url("http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/")
    assert result.decode_rounds == 2
    assert result.host == "127.0.0.1"


def test_iterative_unquote_stops_when_stable():
    decoded, rounds = iterative_unquote("no-encoding-here")
    assert (decoded, rounds) == ("no-encoding-here", 0)


def test_userinfo_does_not_become_the_host():
    """http://trusted.example.com@127.0.0.1/ really goes to 127.0.0.1."""
    result = normalize_url("http://trusted.example.com@127.0.0.1:6379/admin")
    assert result.host == "127.0.0.1"
    assert result.userinfo == "trusted.example.com"
    assert result.userinfo_looks_like_host
    assert result.port == 6379


def test_backslashes_are_normalised_and_recorded():
    result = normalize_url("http:\\\\127.0.0.1\\admin")
    assert result.host == "127.0.0.1"
    assert result.had_backslash


def test_scheme_less_url_is_still_parsed():
    result = normalize_url("//10.0.0.5/internal")
    assert result.host == "10.0.0.5"
    assert not result.scheme_present


def test_dangerous_schemes_are_flagged():
    assert normalize_url("file:///etc/passwd").scheme_is_dangerous
    assert normalize_url("gopher://127.0.0.1:6379/_SET").scheme_is_dangerous
    assert not normalize_url("https://example.com/").scheme_is_dangerous


def test_uppercase_scheme_and_host_are_lowercased():
    result = normalize_url("HtTp://LOCALHOST./admin")
    assert result.scheme == "http"
    assert result.host == "localhost"
    assert result.had_trailing_dot


def test_ipv6_literal_keeps_its_address():
    result = normalize_url("http://[::1]:8080/x")
    assert result.host == "::1"
    assert result.port == 8080


def test_whitespace_and_control_characters_are_recorded():
    result = normalize_url("http://127.0.0.1%09/admin")
    assert result.had_control_chars
    assert result.host == "127.0.0.1"


def test_malformed_port_is_flagged_not_fatal():
    result = normalize_url("http://example.com:99999/")
    assert result.port_malformed
    assert result.port is None


def test_embedded_url_is_extracted_from_the_query():
    result = normalize_url("https://app.example.com/fetch?url=http%3A%2F%2F10.0.0.5%2Fadmin")
    assert "10.0.0.5" in candidate_destinations(result)


def test_candidate_destinations_lists_every_reachable_host():
    result = normalize_url("https://app.example.com/proxy?url=http://169.254.42.7/meta")
    destinations = candidate_destinations(result)
    assert destinations[0] == "app.example.com"
    assert "169.254.42.7" in destinations


@pytest.mark.parametrize(
    "value,expected",
    [
        ("http://10.0.0.5/", True),
        ("//127.0.0.1/", True),
        ("2130706433", True),      # plausible as a decimal IP literal
        ("0x7f000001", True),
        ("example.com", True),
        ("326", False),            # pagination, not 0.0.1.70
        ("50", False),
        ("newsletter", False),
        ("", False),
    ],
)
def test_looks_like_destination(value, expected):
    assert looks_like_destination(value) is expected


def test_numeric_parameters_are_not_treated_as_destinations():
    """Regression: ?page=326 once parsed as the IP 0.0.1.70 and looked internal."""
    result = normalize_url("https://api.example.com/v2/users?page=326&limit=50")
    assert result.destination_params == []
    assert candidate_destinations(result) == ["api.example.com"]


def test_urls_are_extracted_from_a_json_body():
    body = '{"callback_url":"http://192.168.1.10/admin","retries":3}'
    assert "http://192.168.1.10/admin" in extract_urls_from_text(body)


def test_urls_are_extracted_from_a_form_encoded_body():
    body = "description=see%20http%3A%2F%2F127.0.0.1%3A8080%2F&priority=low"
    urls = extract_urls_from_text(body)
    assert any("127.0.0.1" in url for url in urls)


def test_empty_and_whitespace_urls_do_not_raise():
    for value in ("", "   ", None):
        result = normalize_url(value)  # type: ignore[arg-type]
        assert result.host == ""
