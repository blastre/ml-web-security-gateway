"""Permissive IP parsing and destination classification."""

from __future__ import annotations

import pytest

from mlwsg.net.addresses import (
    CATEGORY_LINK_LOCAL,
    CATEGORY_LOOPBACK,
    CATEGORY_PRIVATE,
    CATEGORY_PUBLIC,
    CATEGORY_SHARED,
    CATEGORY_UNSPECIFIED,
    classify_host,
    classify_ip,
    embedded_ip_in_hostname,
    hostname_is_internal,
    normalize_host,
    parse_ip_literal,
)


@pytest.mark.parametrize(
    "host,expected_canonical,expected_notation",
    [
        ("127.0.0.1", "127.0.0.1", "dotted_quad"),
        ("2130706433", "127.0.0.1", "decimal"),
        ("0x7f000001", "127.0.0.1", "hex"),
        ("0x7f.0x0.0x0.0x1", "127.0.0.1", "hex"),
        ("0177.0000.0000.0001", "127.0.0.1", "octal"),
        ("0177.0.0.1", "127.0.0.1", "octal"),
        ("127.1", "127.0.0.1", "short"),
        ("10.1", "10.0.0.1", "short"),
        ("192.168.257", "192.168.1.1", "short"),
    ],
)
def test_every_ipv4_notation_resolves_to_the_same_address(host, expected_canonical, expected_notation):
    """All the inet_aton forms a HTTP client accepts must collapse together."""
    info = classify_host(host)
    assert info.is_ip_literal
    assert info.canonical == expected_canonical
    assert info.notation == expected_notation


@pytest.mark.parametrize(
    "host,category",
    [
        ("127.0.0.1", CATEGORY_LOOPBACK),
        ("10.4.5.6", CATEGORY_PRIVATE),
        ("172.16.0.1", CATEGORY_PRIVATE),
        ("172.32.0.1", CATEGORY_PUBLIC),  # just outside 172.16/12
        ("192.168.1.1", CATEGORY_PRIVATE),
        ("169.254.42.7", CATEGORY_LINK_LOCAL),
        ("100.64.1.1", CATEGORY_SHARED),
        ("0.0.0.0", CATEGORY_UNSPECIFIED),
        ("8.8.8.8", CATEGORY_PUBLIC),
        ("1.1.1.1", CATEGORY_PUBLIC),
    ],
)
def test_ipv4_classification(host, category):
    assert classify_host(host).category == category


@pytest.mark.parametrize(
    "host",
    ["[::1]", "::1", "0:0:0:0:0:0:0:1", "[::ffff:127.0.0.1]", "::ffff:7f00:1"],
)
def test_ipv6_loopback_forms_are_internal(host):
    info = classify_host(host)
    assert info.is_internal
    assert info.category == CATEGORY_LOOPBACK


def test_ipv4_mapped_ipv6_inherits_the_embedded_classification():
    info = classify_host("[::ffff:10.0.0.5]")
    assert info.notation == "ipv4_mapped_ipv6"
    assert info.category == CATEGORY_PRIVATE
    assert info.is_internal


def test_ipv6_unique_local_is_internal():
    assert classify_host("[fd00:1234::1]").is_internal


def test_public_ipv6_is_not_internal():
    assert not classify_host("[2606:4700:4700::1111]").is_internal


@pytest.mark.parametrize(
    "host", ["localhost", "LOCALHOST", "db.internal", "admin.intranet", "svc.cluster.local",
             "metadata.sim.local", "printer.home", "router.lan", "host.localdomain"],
)
def test_internal_hostnames_are_detected(host):
    assert hostname_is_internal(host)


@pytest.mark.parametrize("host", ["example.com", "cdn.example.org", "api.acmeworks.io",
                                  "shop.northwind.co.uk"])
def test_public_hostnames_are_not_internal(host):
    assert not hostname_is_internal(host)


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.0.0.1.rebind.test", "127.0.0.1"),
        ("10-0-0-1.wildcard.test", "10.0.0.1"),
        ("192.168.1.1.anyip.test", "192.168.1.1"),
    ],
)
def test_ip_embedded_in_a_dns_name_is_recovered(host, expected):
    """Wildcard-DNS bypasses carry the target address inside the hostname."""
    assert str(embedded_ip_in_hostname(host)) == expected
    assert classify_host(host).is_internal


def test_embedded_ip_ignores_ordinary_hostnames():
    assert embedded_ip_in_hostname("cdn.example.com") is None
    assert embedded_ip_in_hostname("v2.api.example.org") is None


def test_dns_names_are_not_mistaken_for_ip_literals():
    assert parse_ip_literal("example.com") is None
    assert parse_ip_literal("256.1.1.1") is None      # octet out of range
    assert parse_ip_literal("127.0.0.1.5") is None    # too many parts
    assert parse_ip_literal("09.0.0.1") is None       # invalid octal digit


def test_normalize_host_strips_brackets_case_and_trailing_dots():
    assert normalize_host("  [::1]  ") == "::1"
    assert normalize_host("EXAMPLE.COM.") == "example.com"


def test_normalize_host_converts_unicode_to_punycode():
    assert normalize_host("münchen.example.com").startswith("xn--")


def test_classify_ip_accepts_address_objects():
    import ipaddress

    assert classify_ip(ipaddress.IPv4Address("127.0.0.1")) == CATEGORY_LOOPBACK
    assert classify_ip(ipaddress.IPv6Address("::1")) == CATEGORY_LOOPBACK


def test_empty_host_is_handled():
    info = classify_host("")
    assert not info.is_ip_literal
    assert not info.is_internal
