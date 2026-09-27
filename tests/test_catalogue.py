import socket
from ipaddress import IPv6Address, ip_address
from urllib.parse import unquote, urlsplit

import pytest

from mlwsg.catalogue import LAYERS, VECTORS, load

CATALOGUE = load()
ATTACKS = CATALOGUE.attacks
INDIRECT = [a for a in ATTACKS if a.vector in ("dns", "redirect")]


def connect_address(url: str):
    """Address a libc-based HTTP client would connect to for a literal-host URL."""
    host = unquote(urlsplit(url).hostname)
    if ":" in host:
        ip = IPv6Address(host)
        return ip.ipv4_mapped or ip
    return ip_address(socket.inet_aton(host))


def by_id(attack):
    return attack.id


def test_ids_are_unique_and_sequential():
    assert [a.id for a in ATTACKS] == [f"A{i:02d}" for i in range(1, len(ATTACKS) + 1)]


@pytest.mark.parametrize("attack", ATTACKS, ids=by_id)
def test_fields_are_consistent(attack):
    assert attack.asset in CATALOGUE.assets
    assert attack.vector in VECTORS
    assert attack.layers and set(attack.layers) <= set(LAYERS)
    assert (attack.resolves_to is None) == (CATALOGUE.assets[attack.asset].networks == ())


@pytest.mark.parametrize("attack", [a for a in ATTACKS if a.resolves_to], ids=by_id)
def test_destination_is_inside_the_targeted_asset(attack):
    assert CATALOGUE.assets[attack.asset].contains(attack.resolves_to)


@pytest.mark.parametrize("attack", [a for a in ATTACKS if a.vector == "literal"], ids=by_id)
def test_literal_payload_reaches_declared_destination(attack):
    assert connect_address(attack.payload) == attack.resolves_to


@pytest.mark.parametrize("attack", [a for a in ATTACKS if a.vector == "parser"], ids=by_id)
def test_parser_payload_misleads_urllib(attack):
    assert urlsplit(attack.payload).hostname != str(attack.resolves_to)


@pytest.mark.parametrize("attack", INDIRECT, ids=by_id)
def test_indirect_payload_hides_destination(attack):
    assert str(attack.resolves_to) not in urlsplit(attack.payload).netloc


def test_indirect_attacks_require_egress_layer():
    assert all("egress" in a.layers for a in INDIRECT)
