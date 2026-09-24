"""IP-literal parsing and destination classification.

SSRF detection rests on a single awkward fact: ``127.0.0.1``, ``2130706433``,
``0x7f000001``, ``0177.0.0.1``, ``127.1`` and ``[::ffff:127.0.0.1]`` all name
the same host, and most HTTP clients happily accept every one of them.  A
detector that only understands dotted quads is trivially bypassed, so this
module reimplements the permissive ``inet_aton``-style parsing that libc (and
therefore the resolver behind most HTTP stacks) actually performs, and then
maps the result onto a security category.

The same primitives are reused by the Phase 2 egress guard, which classifies
the *resolved* destination rather than the requested one.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

CATEGORY_PUBLIC = "public"
CATEGORY_LOOPBACK = "loopback"
CATEGORY_PRIVATE = "private"
CATEGORY_LINK_LOCAL = "link_local"
CATEGORY_UNIQUE_LOCAL = "unique_local"
CATEGORY_SHARED = "shared"          # 100.64.0.0/10 (CGNAT)
CATEGORY_MULTICAST = "multicast"
CATEGORY_UNSPECIFIED = "unspecified"  # 0.0.0.0 / ::
CATEGORY_RESERVED = "reserved"
CATEGORY_UNKNOWN = "unknown"        # not an IP literal at all

#: Categories an outbound fetch must never reach.  Anything not listed here is
#: routable, public Internet space.
INTERNAL_CATEGORIES = frozenset(
    {
        CATEGORY_LOOPBACK,
        CATEGORY_PRIVATE,
        CATEGORY_LINK_LOCAL,
        CATEGORY_UNIQUE_LOCAL,
        CATEGORY_SHARED,
        CATEGORY_MULTICAST,
        CATEGORY_UNSPECIFIED,
        CATEGORY_RESERVED,
    }
)

# ---------------------------------------------------------------------------
# Hostname heuristics
# ---------------------------------------------------------------------------

#: Hostnames that resolve to the local machine without any DNS lookup.
LOCALHOST_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)

#: DNS suffixes that only ever appear inside a private network.  ``.sim`` and
#: ``.test`` are this project's simulated internal zones (``.test`` is reserved
#: by RFC 2606, so it can never collide with a real registered domain).
INTERNAL_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".intranet",
    ".corp",
    ".lan",
    ".home",
    ".private",
    ".svc",
    ".svc.cluster.local",
    ".cluster.local",
    ".sim",
    ".test",
)

#: Stand-ins for a cloud instance-metadata service.  The project deliberately
#: never references a real provider's metadata endpoint; these names are served
#: by the local simulated-internal-services app instead.
SIMULATED_METADATA_HOSTS = (
    "metadata.sim",
    "metadata.sim.local",
    "metadata.internal.sim",
    "instance-data.internal.sim",
)

#: Ports that carry internal-only services.  Seeing one of these in a
#: user-supplied URL is a strong SSRF / internal-port-scan signal.
SENSITIVE_INTERNAL_PORTS = frozenset(
    {
        22,     # ssh
        23,     # telnet
        25,     # smtp
        445,    # smb
        1433,   # mssql
        1521,   # oracle
        2375,   # docker api
        2379,   # etcd
        3306,   # mysql
        3389,   # rdp
        5432,   # postgres
        5672,   # amqp
        5984,   # couchdb
        6379,   # redis
        8500,   # consul
        9000,   # misc admin
        9200,   # elasticsearch
        11211,  # memcached
        15672,  # rabbitmq management
        27017,  # mongodb
    }
)

#: Ports normal web traffic uses.
STANDARD_WEB_PORTS = frozenset({80, 443, 8080, 8443})

_HEX_PART = re.compile(r"^0[xX][0-9a-fA-F]+$")
_OCTAL_PART = re.compile(r"^0[0-7]+$")
_DECIMAL_PART = re.compile(r"^\d+$")

#: ``10.0.0.1.rebind.test`` / ``10-0-0-1.wildcard.test`` style hostnames that
#: smuggle an IP literal through DNS.
_EMBEDDED_IP = re.compile(
    r"(?<![0-9a-zA-Z])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})(?![0-9a-zA-Z])"
)


@dataclass(frozen=True)
class AddressInfo:
    """Result of inspecting the host component of a URL."""

    host: str
    is_ip_literal: bool
    family: str = ""       # "ipv4" | "ipv6" | ""
    notation: str = ""     # dotted_quad | decimal | hex | octal | short | ipv6 | ipv4_mapped_ipv6
    canonical: str = ""    # canonical dotted-quad / compressed IPv6 form
    category: str = CATEGORY_UNKNOWN
    is_internal: bool = False
    #: True when the hostname is not a literal but is still internal-only
    #: (``localhost``, ``db.internal``, an embedded IP, ...).
    internal_by_name: bool = False
    embeds_ip: bool = False


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Lowercase, strip brackets/trailing dots, and IDNA-encode a hostname.

    Unicode hostnames are converted to their punycode form so that homoglyph
    tricks (``𝗅ocalhost``) collapse onto something comparable.
    """
    if not host:
        return ""
    host = host.strip().strip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.lower()
    if any(ord(ch) > 127 for ch in host):
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, UnicodeDecodeError):
            # Leave the raw value in place; the caller records it as unusual.
            pass
    return host


def _parse_ipv4_part(part: str) -> Optional[tuple[int, str]]:
    """Parse one ``inet_aton`` component, returning ``(value, notation)``."""
    if not part:
        return None
    if _HEX_PART.match(part):
        return int(part, 16), "hex"
    if _OCTAL_PART.match(part):
        return int(part, 8), "octal"
    if _DECIMAL_PART.match(part):
        if len(part) > 1 and part[0] == "0":
            # "00" style: libc reads it as octal, and "08"/"09" are invalid.
            try:
                return int(part, 8), "octal"
            except ValueError:
                return None
        return int(part), "decimal"
    return None


def _parse_ipv4_permissive(host: str) -> Optional[tuple[ipaddress.IPv4Address, str]]:
    """Parse the ``inet_aton`` IPv4 forms: a, a.b, a.b.c and a.b.c.d.

    Returns the address plus the notation that was used, or ``None`` when the
    string is not an IPv4 literal in any notation.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None

    values: list[int] = []
    notations: set[str] = set()
    for part in parts:
        parsed = _parse_ipv4_part(part)
        if parsed is None:
            return None
        value, notation = parsed
        values.append(value)
        notations.add(notation)

    # The final component absorbs all remaining low-order bytes.
    tail_bits = 8 * (4 - len(values) + 1)
    if values[-1] >= (1 << tail_bits):
        return None
    if any(value > 0xFF for value in values[:-1]):
        return None

    packed = 0
    for value in values[:-1]:
        packed = (packed << 8) | value
    packed = (packed << tail_bits) | values[-1]
    if packed > 0xFFFFFFFF:
        return None

    if "hex" in notations:
        notation = "hex"
    elif "octal" in notations:
        notation = "octal"
    elif len(parts) < 4:
        notation = "decimal" if len(parts) == 1 else "short"
    else:
        notation = "dotted_quad"
    return ipaddress.IPv4Address(packed), notation


def parse_ip_literal(host: str) -> Optional[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str]]:
    """Parse *host* as an IP literal in any notation a HTTP client accepts.

    Returns ``(address, notation)`` or ``None`` when *host* is a DNS name.
    """
    if not host:
        return None
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    candidate = candidate.strip()
    if not candidate:
        return None

    if ":" in candidate:
        # Strip an IPv6 zone index ("fe80::1%eth0") before parsing.
        zoneless = candidate.split("%", 1)[0]
        try:
            address = ipaddress.IPv6Address(zoneless)
        except ValueError:
            return None
        mapped = address.ipv4_mapped or _ipv4_compatible(address)
        if mapped is not None:
            return address, "ipv4_mapped_ipv6"
        return address, "ipv6"

    parsed = _parse_ipv4_permissive(candidate)
    if parsed is None:
        return None
    return parsed


def _ipv4_compatible(address: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Return the embedded IPv4 address of an ``::a.b.c.d`` literal."""
    packed = int(address)
    if packed >> 32 == 0 and packed > 1:
        return ipaddress.IPv4Address(packed & 0xFFFFFFFF)
    return None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """Map an address onto one of the ``CATEGORY_*`` constants."""
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or _ipv4_compatible(address)
        if embedded is not None:
            return classify_ip(embedded)

    if address.is_unspecified:
        return CATEGORY_UNSPECIFIED
    if address.is_loopback:
        return CATEGORY_LOOPBACK
    if address.is_link_local:
        return CATEGORY_LINK_LOCAL
    if address.is_multicast:
        return CATEGORY_MULTICAST

    if isinstance(address, ipaddress.IPv6Address):
        if address.is_site_local or int(address) >> 121 == 0b1111110:  # fc00::/7
            return CATEGORY_UNIQUE_LOCAL
        if address.is_reserved:
            return CATEGORY_RESERVED
        return CATEGORY_PUBLIC if address.is_global else CATEGORY_RESERVED

    if address in ipaddress.IPv4Network("100.64.0.0/10"):
        return CATEGORY_SHARED
    if address.is_private:
        return CATEGORY_PRIVATE
    if address.is_reserved:
        return CATEGORY_RESERVED
    return CATEGORY_PUBLIC


def hostname_is_internal(host: str) -> bool:
    """True when a DNS name can only refer to an internal destination."""
    name = normalize_host(host)
    if not name:
        return False
    if name in LOCALHOST_NAMES or name in SIMULATED_METADATA_HOSTS:
        return True
    return any(name == suffix.lstrip(".") or name.endswith(suffix) for suffix in INTERNAL_HOST_SUFFIXES)


def embedded_ip_in_hostname(host: str) -> Optional[ipaddress.IPv4Address]:
    """Extract an IPv4 literal smuggled inside a DNS name.

    ``127.0.0.1.rebind.test`` and ``10-0-0-1.wildcard.test`` are the classic
    wildcard-DNS SSRF bypasses; both carry the target address in plain sight.
    """
    name = normalize_host(host)
    if not name:
        return None
    for match in _EMBEDDED_IP.finditer(name):
        octets = match.groups()
        if all(int(octet) <= 255 for octet in octets):
            try:
                return ipaddress.IPv4Address(".".join(octets))
            except ValueError:
                continue
    return None


def classify_host(host: str) -> AddressInfo:
    """Inspect the host component of a URL and describe where it points."""
    normalized = normalize_host(host)
    if not normalized:
        return AddressInfo(host="", is_ip_literal=False)

    parsed = parse_ip_literal(normalized)
    if parsed is not None:
        address, notation = parsed
        category = classify_ip(address)
        family = "ipv6" if isinstance(address, ipaddress.IPv6Address) else "ipv4"
        return AddressInfo(
            host=normalized,
            is_ip_literal=True,
            family=family,
            notation=notation,
            canonical=str(address),
            category=category,
            is_internal=category in INTERNAL_CATEGORIES,
            embeds_ip=True,
        )

    embedded = embedded_ip_in_hostname(normalized)
    internal_by_name = hostname_is_internal(normalized)
    category = CATEGORY_UNKNOWN
    if embedded is not None:
        category = classify_ip(embedded)
    elif internal_by_name:
        category = CATEGORY_PRIVATE

    internal = internal_by_name or (embedded is not None and category in INTERNAL_CATEGORIES)
    return AddressInfo(
        host=normalized,
        is_ip_literal=False,
        family="",
        notation="",
        canonical=str(embedded) if embedded is not None else "",
        category=category,
        is_internal=internal,
        internal_by_name=internal_by_name,
        embeds_ip=embedded is not None,
    )
