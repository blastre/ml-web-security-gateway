"""Deterministic URL logic: host canonicalisation, destination lookup, technique hints,
the fast inbound rules and the egress guard."""

import ipaddress
import re
import socket
import tomllib
import unicodedata
from functools import cache
from urllib.parse import parse_qsl, unquote, urlsplit

from ssrf_agent.config import settings

IP = ipaddress.IPv4Address | ipaddress.IPv6Address
ALLOWED_SCHEMES = {"http", "https"}
METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}
METADATA_HOSTS = {"metadata.google.internal", "metadata", "metadata.internal", "instance-data"}
_NUMERIC_HOST = re.compile(r"^[0-9a-fx.]+$", re.IGNORECASE)
_AUTHORITY = re.compile(r"^([a-z][a-z0-9+.-]*:)?[/\\]{2}([^/?#\\]*)", re.IGNORECASE)
_FULL_STOPS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})


def normalise(url: str) -> str:
    """Map Unicode look-alikes in the authority to ASCII, as browsers do for hosts (UTS 46):
    circled and fullwidth characters (ⓕ -> f, ① -> 1, ⑯ -> 16) and ideographic full stops."""
    match = _AUTHORITY.match(url)
    if not match or match.group(2).isascii():
        return url
    authority = unicodedata.normalize("NFKC", match.group(2)).translate(_FULL_STOPS)
    return url[: match.start(2)] + authority + url[match.end(2) :]


def split(url: str):
    """urlsplit on the normalised URL. Raises ValueError when the URL cannot be parsed."""
    return urlsplit(normalise(url))


@cache
def _lab_dns() -> dict[str, list[str]]:
    with (settings.data_dir / "lab_dns.toml").open("rb") as handle:
        return tomllib.load(handle)["hosts"]


def parse_ip(host: str) -> IP | None:
    """Canonical address of an IP-literal host in any notation (hex, octal, dword, %-encoded)."""
    host = unquote(host).strip("[]").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if not _NUMERIC_HOST.match(host) or not any(c.isdigit() for c in host):
            return None
        try:  # inet_aton accepts the legacy forms browsers and libc still honour
            ip = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def asset(ip: IP) -> str:
    """Which protected range an address belongs to, or "public"."""
    if ip in METADATA_IPS:
        return "metadata"
    for name in ("loopback", "unspecified", "link_local", "private", "reserved", "multicast"):
        if getattr(ip, f"is_{name}"):
            return name
    return "public" if ip.is_global else "non-public"


def resolve(host: str) -> list[str]:
    """Lab DNS first, then system DNS. Returns every answer (all of them get checked)."""
    host = host.lower().rstrip(".")
    if ip := parse_ip(host):
        return [str(ip)]
    lab = _lab_dns()
    if host in lab:
        return lab[host]
    for key, answers in lab.items():
        if key.startswith("*.") and host.endswith(key[1:]):
            return answers
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (OSError, UnicodeError):
        return []


def embedded_urls(url: str) -> list[str]:
    """URLs carried in query parameters: what an open redirect would forward to."""
    query = split(url.replace("\\", "/")).query
    return [v for _, v in parse_qsl(query) if re.match(r"^[a-z][a-z0-9+.-]*://", v, re.I)]


def _hostname(url: str) -> str:
    try:
        return split(url).hostname or ""
    except ValueError:
        return ""


def destinations(url: str) -> list[dict]:
    """Every host the request could end up at: the URL itself, the WHATWG reading of a
    backslash URL, and open-redirect targets. Each with its addresses and asset class."""
    candidates = [("url", url)]
    if "\\" in url:
        candidates.append(("whatwg-parse", url.replace("\\", "/")))
    candidates += [("redirect", target) for target in embedded_urls(url)]
    result = []
    for role, target in candidates:
        host = _hostname(target)
        addresses = [{"ip": a, "asset": asset(ipaddress.ip_address(a))} for a in resolve(host)]
        result.append(
            {
                "role": role,
                "scheme": split(target).scheme.lower(),
                "host": host,
                "addresses": addresses,
                "public": bool(addresses) and all(a["asset"] == "public" for a in addresses),
            }
        )
    return result


def hints(url: str) -> list[dict]:
    """Catalogue techniques the URL's *shape* resembles (no DNS)."""
    found = []

    def add(technique_id: str, signal: str) -> None:
        found.append({"technique_id": technique_id, "signal": signal})

    parts = split(url)
    scheme, raw_host = parts.scheme.lower(), parts.netloc.rsplit("@", 1)[-1].rsplit(":", 1)[0]
    host = _hostname(url)
    if scheme == "file":
        add("A21", "file:// scheme")
    elif scheme == "gopher":
        add("A22", "gopher:// scheme")
    elif scheme and scheme not in ALLOWED_SCHEMES:
        add("unknown", f"{scheme}:// scheme")
    if "%" in raw_host:
        add("A13", "percent-encoded host")
    if host.isdigit():
        add("A04", "host is a single decimal number")
    if "0x" in host:
        add("A05" if "." not in host else "A07", "hexadecimal host")
    if re.search(r"(^|\.)0\d", host):
        add("A06", "octal host segment")
    if re.fullmatch(r"\d+\.\d+", host):
        add("A08", "shortened IPv4")
    if "::ffff:" in host:
        add("A11", "IPv4-mapped IPv6")
    if "@" in parts.netloc:
        add("A14", "userinfo before host")
    if normalise(url) != url:
        add("A32", "Unicode look-alike characters in host")
    if "\\" in url:
        add("A15", "backslash in authority")
    if host in METADATA_HOSTS:
        add("A03", "metadata hostname")
    if embedded_urls(url):
        add("A19", "URL embedded in query (open redirect)")
    return found


def inbound_block(url: str) -> str | None:
    """Obvious blocks, decided without the models: bad schemes, plain internal literals and
    metadata names. Obfuscated encodings are left for the models and the agent."""
    parts = split(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return f"scheme {parts.scheme or '(none)'}:// not allowed"
    host = _hostname(url)
    if host in METADATA_HOSTS:
        return "metadata hostname"
    try:
        ip = ipaddress.ip_address(host)  # plain notation only
    except ValueError:
        return None
    if asset(ip) != "public":
        return f"{asset(ip)} address {ip}"
    return None


def egress_block(url: str) -> str | None:
    """Always-on guard: what the connection would really reach. Fails closed."""
    for dest in destinations(url):
        if dest["scheme"] not in ALLOWED_SCHEMES:
            return f"{dest['role']}: scheme {dest['scheme']}:// not allowed"
        if not dest["addresses"]:
            return f"{dest['role']}: {dest['host'] or 'host'} does not resolve"
        for address in dest["addresses"]:
            if address["asset"] != "public":
                return f"{dest['role']}: {address['ip']} is {address['asset']}"
    return None
