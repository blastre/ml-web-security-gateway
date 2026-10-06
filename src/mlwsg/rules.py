"""Deterministic URL rules: the gateway's fast path and the agent's `url_rules` tool.

`inbound_reason` is the strict inbound policy. `technique_hints` names which catalogue
techniques a URL's *shape* resembles; it never resolves names or opens connections.
"""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

LAB_PUBLIC = {"public.lab", "redirect.attacker.lab"}
METADATA_HOSTS = {"metadata.google.internal"}
METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata (zero-day probe only)
}


def inbound_reason(url: str) -> str | None:
    if len(url) > 2048 or "\\" in url or any(ord(ch) < 32 for ch in url):
        return "ambiguous or oversized URL"
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "invalid URL"
    if parsed.scheme not in ("http", "https") or not host or port == 0:
        return "only absolute HTTP(S) URLs are supported"
    if parsed.username or parsed.password or "@" in parsed.netloc or "%" in parsed.netloc:
        return "ambiguous URL authority"
    host = unquote(host).rstrip(".").lower()
    if host in METADATA_HOSTS:
        return "metadata hostname"
    if host in LAB_PUBLIC:
        return None
    ip = literal_address(host)
    if ip is None:
        return None  # Names are checked against pinned DNS results by the egress guard.
    if not ip.is_global:
        return "non-public destination"
    return None


def literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Interpret a host the way C resolvers do (dword, hex, octal, short forms), or None."""
    host = unquote(host).strip("[]").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


@dataclass(frozen=True, slots=True)
class Hint:
    technique_id: str | None  # catalogue ID, or None for a signal with no catalogue match
    signal: str


def _numeric_form(host: str) -> str | None:
    """Classify an IPv4 literal's spelling; None for an ordinary name or dotted quad."""
    labels = host.split(".")
    if not all(label and (label.isdigit() or label.startswith("0x")) for label in labels):
        return None
    if len(labels) == 1:
        return "hex" if labels[0].startswith("0x") else "dword"
    kinds = {
        "hex"
        if label.startswith("0x")
        else "octal"
        if label[0] == "0" and len(label) > 1
        else "dec"
        for label in labels
    }
    if len(labels) < 4:
        return "short"
    if kinds == {"octal"}:
        return "octal"
    if len(kinds) > 1:
        return "mixed"
    return None


def embedded_urls(url: str) -> list[str]:
    """Absolute URLs carried in query parameters, decoded once (open-redirect payloads)."""
    try:
        query = urlsplit(url).query
    except ValueError:
        return []
    found = []
    for _, value in parse_qsl(query, keep_blank_values=False):
        for candidate in (value, unquote(value)):
            if "://" in candidate and candidate not in found:
                found.append(candidate)
                break
    return found


def technique_hints(url: str) -> list[Hint]:
    """Map URL shape to catalogue techniques (A01-A22). Destination checks live elsewhere."""
    hints: list[Hint] = []
    if "\\" in url:
        hints.append(Hint("A15", "backslash in authority: urllib and WHATWG parsers disagree"))
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return hints + [Hint(None, "URL does not parse")]
    scheme = parsed.scheme.lower()
    if scheme == "file":
        return hints + [Hint("A21", "file:// reads local files")]
    if scheme == "gopher":
        return hints + [Hint("A22", "gopher:// can speak raw TCP protocols such as Redis")]
    if scheme not in ("http", "https"):
        return hints + [Hint(None, f"non-HTTP scheme {scheme or '(none)'}")]
    if "@" in parsed.netloc and "\\" not in url:
        hints.append(Hint("A14", "userinfo before @ hides the real host"))
    if "%" in parsed.netloc:
        hints.append(Hint("A13", "percent-encoded characters in the host"))
    decoded = unquote(host).strip("[]")
    if decoded in METADATA_HOSTS:
        hints.append(Hint("A03", "cloud metadata hostname"))
    form = _numeric_form(decoded)
    if form:
        names = {
            "dword": ("A04", "IPv4 written as one decimal number"),
            "hex": ("A05", "IPv4 written in hexadecimal"),
            "octal": ("A06", "IPv4 written in octal"),
            "mixed": ("A07", "IPv4 mixing hex, octal and decimal parts"),
            "short": ("A08", "IPv4 with omitted octets"),
        }
        hints.append(Hint(*names[form]))
    ip = literal_address(decoded) if decoded else None
    if ip is not None:
        try:
            raw = ipaddress.ip_address(decoded)
        except ValueError:
            raw = None
        if isinstance(raw, ipaddress.IPv6Address) and raw.ipv4_mapped:
            hints.append(Hint("A11", "IPv4-mapped IPv6 literal"))
        if ip.is_unspecified:
            hints.append(Hint("A09", "unspecified address reaches local services"))
        elif ip.version == 6 and ip.is_loopback:
            hints.append(Hint("A10", "IPv6 loopback literal"))
        elif ip in METADATA_ADDRESSES and not form and "%" not in parsed.netloc:
            if ip.version == 6 and not hints:
                hints.append(Hint("A12", "metadata IPv6 literal"))
            elif "/latest/meta-data" in parsed.path:
                hints.append(Hint("A02", "AWS IMDSv1 credential path"))
            elif not hints:
                hints.append(Hint("A01", "metadata IPv4 literal"))
        elif not ip.is_global and not hints:
            hints.append(Hint("A16", "private or reserved IP literal"))
    for target in embedded_urls(url):
        hints.append(Hint(None, f"query parameter carries a URL (possible redirect) to {target}"))
    return hints
