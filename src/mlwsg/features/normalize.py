"""URL normalisation.

Attackers do not send ``http://127.0.0.1/``; they send
``http://%31%32%37%2e%30%2e%30%2e%31/``, ``http://trusted.example.com@127.0.0.1/``
or ``http:\\\\127.0.0.1\\``.  Every one of those reaches the same destination
once a HTTP client is done with it.

:func:`normalize_url` collapses those representations onto a single canonical
view *while remembering how much work that took* -- the number of decoding
rounds, whether userinfo was present, whether backslashes were used.  Those
observations are themselves strong features, so nothing is thrown away.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qsl, unquote, urlsplit

from mlwsg.net.addresses import normalize_host

#: Maximum percent-decoding passes.  Two rounds cover the common
#: double-encoding bypass; the third catches the rare triple encoding.
MAX_DECODE_ROUNDS = 3

#: Schemes a URL-fetching web feature has any legitimate reason to use.
SAFE_SCHEMES = frozenset({"http", "https"})

#: Schemes that turn a fetcher into a file reader or a raw-socket gadget.
DANGEROUS_SCHEMES = frozenset(
    {"file", "gopher", "dict", "ftp", "ftps", "ldap", "ldaps", "tftp", "jar", "netdoc", "php", "data"}
)

#: Query/body parameter names that carry a destination URL.  These are the
#: parameters SSRF and open-redirect bugs live in.
REDIRECT_PARAM_NAMES = frozenset(
    {
        "url", "uri", "u", "link", "src", "source", "target", "dest", "destination",
        "redirect", "redirect_to", "redirect_uri", "redirecturl", "return", "return_to",
        "returnurl", "next", "continue", "callback", "callback_url", "webhook",
        "webhook_url", "image", "image_url", "imageurl", "img", "photo", "avatar",
        "feed", "rss", "endpoint", "host", "domain", "site", "page", "path", "file",
        "load", "fetch", "proxy", "remote", "resource", "document", "data", "out", "to",
    }
)

#: Path fragments that mark a server-side fetch or redirect endpoint.
FETCH_PATH_MARKERS = (
    "/fetch", "/proxy", "/redirect", "/render", "/preview", "/thumbnail", "/import",
    "/webhook", "/callback", "/resolve", "/screenshot", "/pdf", "/convert", "/mirror",
)

_SCHEME_RE = re.compile(r"^\s*([a-zA-Z][a-zA-Z0-9+.\-]*)\s*:")
_URL_IN_TEXT_RE = re.compile(
    r"(?:https?|ftps?|gopher|dict|file|ldaps?|jar|netdoc)://[^\s\"'<>\\]+", re.IGNORECASE
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_PURE_INT_RE = re.compile(r"^\d+$")

#: Smallest integer that is plausible as a 32-bit-decimal IPv4 literal (1.0.0.0).
#: Below it, a bare number in a parameter is pagination, an id or a timestamp --
#: not ``?url=2130706433``.  Without this floor, ``?page=326`` would "resolve"
#: to 0.0.1.70 and be classified as an internal destination.
MIN_DECIMAL_IP = 1 << 24


@dataclass
class NormalizedURL:
    """A URL taken apart, plus the obfuscation observed while doing so."""

    raw: str
    decoded: str = ""
    decode_rounds: int = 0
    percent_sequences: int = 0
    parse_ok: bool = False

    scheme: str = ""
    scheme_present: bool = False
    userinfo: str = ""
    host_raw: str = ""
    host: str = ""
    port: Optional[int] = None
    port_raw: str = ""
    path: str = ""
    query: str = ""
    fragment: str = ""
    params: list[tuple[str, str]] = field(default_factory=list)

    had_backslash: bool = False
    had_whitespace: bool = False
    had_control_chars: bool = False
    had_unicode: bool = False
    had_trailing_dot: bool = False
    port_malformed: bool = False
    embedded_urls: list[str] = field(default_factory=list)

    @property
    def redirect_params(self) -> list[tuple[str, str]]:
        """Parameters whose *name* suggests they carry a destination URL."""
        return [(k, v) for k, v in self.params if k.lower() in REDIRECT_PARAM_NAMES]

    @property
    def destination_params(self) -> list[tuple[str, str]]:
        """Redirect parameters whose *value* also looks like a destination.

        ``?url=http://10.0.0.5/`` qualifies; ``?page=326`` does not.
        """
        return [(k, v) for k, v in self.redirect_params if looks_like_destination(v)]

    @property
    def scheme_is_dangerous(self) -> bool:
        return self.scheme in DANGEROUS_SCHEMES

    @property
    def userinfo_looks_like_host(self) -> bool:
        """``http://trusted.example.com@127.0.0.1/`` -- the credentials slot is
        being used to make the real host look legitimate."""
        return "." in self.userinfo and not self.userinfo.startswith(".")


def iterative_unquote(value: str, max_rounds: int = MAX_DECODE_ROUNDS) -> tuple[str, int]:
    """Percent-decode until the string stops changing.

    Returns the decoded string and the number of rounds that actually changed
    it -- ``2`` means the input was double-encoded.
    """
    current = value
    rounds = 0
    for _ in range(max_rounds):
        decoded = unquote(current)
        if decoded == current:
            break
        current = decoded
        rounds += 1
    return current, rounds


def _split_scheme(value: str) -> tuple[str, bool, str]:
    """Return ``(scheme, present, remainder_with_scheme)``."""
    match = _SCHEME_RE.match(value)
    if match:
        return match.group(1).lower(), True, value
    return "http", False, "http://" + value.lstrip("/\\ ")


def normalize_url(raw_url: str) -> NormalizedURL:
    """Decode and decompose *raw_url* into a :class:`NormalizedURL`."""
    raw = raw_url if isinstance(raw_url, str) else str(raw_url or "")
    result = NormalizedURL(raw=raw)
    if not raw.strip():
        return result

    result.percent_sequences = len(_PERCENT_RE.findall(raw))
    result.had_whitespace = bool(re.search(r"\s", raw))
    result.had_control_chars = bool(_CONTROL_RE.search(raw))
    result.had_unicode = any(ord(ch) > 127 for ch in raw)

    decoded, rounds = iterative_unquote(raw)
    result.decoded = decoded
    result.decode_rounds = rounds
    if not result.had_control_chars:
        result.had_control_chars = bool(_CONTROL_RE.search(decoded))

    # Browsers and several HTTP clients treat "\" as "/" in the authority.
    working = decoded.strip()
    result.had_backslash = "\\" in working
    working = working.replace("\\", "/")
    working = _CONTROL_RE.sub("", working)

    scheme, present, with_scheme = _split_scheme(working)
    result.scheme = scheme
    result.scheme_present = present

    try:
        parts = urlsplit(with_scheme)
        result.parse_ok = True
    except ValueError:
        return result

    netloc = parts.netloc
    if "@" in netloc:
        result.userinfo, _, netloc = netloc.rpartition("@")

    host_raw, port_raw = _split_host_port(netloc)
    result.host_raw = host_raw
    result.port_raw = port_raw
    result.had_trailing_dot = host_raw.endswith(".") and len(host_raw) > 1
    result.host = normalize_host(host_raw)

    if port_raw:
        try:
            port = int(port_raw)
        except ValueError:
            result.port_malformed = True
        else:
            if 0 <= port <= 65535:
                result.port = port
            else:
                result.port_malformed = True

    result.path = parts.path
    result.query = parts.query
    result.fragment = parts.fragment
    try:
        result.params = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        result.params = []

    # Any further URL hiding inside the query string, fragment or path.
    remainder = decoded[len(f"{scheme}://") :] if present else decoded
    result.embedded_urls = [
        match.group(0)
        for match in _URL_IN_TEXT_RE.finditer(remainder)
    ]
    return result


def _split_host_port(netloc: str) -> tuple[str, str]:
    """Split ``host:port`` while keeping bracketed IPv6 literals intact."""
    if not netloc:
        return "", ""
    if netloc.startswith("["):
        closing = netloc.find("]")
        if closing == -1:
            return netloc, ""
        host = netloc[: closing + 1]
        rest = netloc[closing + 1 :]
        port = rest[1:] if rest.startswith(":") else ""
        return host, port
    if netloc.count(":") == 1:
        host, _, port = netloc.partition(":")
        return host, port
    return netloc, ""


def looks_like_destination(value: str) -> bool:
    """Could this parameter value plausibly be a fetch destination?

    Parameter names alone are a poor filter: ``page``, ``path`` and ``data``
    carry URLs in some applications and ordinary scalars in most.  This is the
    value-side check that decides whether a value is worth classifying as a
    host at all.
    """
    if not value:
        return False
    decoded, _ = iterative_unquote(value.strip())
    decoded = decoded.strip()
    if not decoded:
        return False
    if _SCHEME_RE.match(decoded):
        return True
    if decoded.startswith("//") or decoded.startswith("\\\\"):
        return True
    if _PURE_INT_RE.match(decoded):
        return int(decoded) >= MIN_DECIMAL_IP
    lowered = decoded.lower()
    if lowered.startswith("0x"):
        return True
    return "." in decoded or ":" in decoded or "[" in decoded


def extract_urls_from_text(text: str) -> list[str]:
    """Find every absolute URL inside a free-text blob (a request body, a JSON
    payload, a form field).  The text is percent-decoded first, so a
    form-encoded body hides nothing.
    """
    if not text:
        return []
    decoded, _ = iterative_unquote(text)
    found: list[str] = []
    for candidate in (text, decoded):
        for match in _URL_IN_TEXT_RE.finditer(candidate):
            url = match.group(0).rstrip('",;)\'')
            if url not in found:
                found.append(url)
    return found


def candidate_destinations(normalized: NormalizedURL) -> list[str]:
    """Every host this request could plausibly reach.

    Includes the URL's own host, any host embedded in a redirect-style
    parameter, and any URL found elsewhere in the query.  Phase 2's egress
    guard resolves each of these before allowing the fetch.
    """
    hosts: list[str] = []
    if normalized.host:
        hosts.append(normalized.host)
    for candidate in normalized.embedded_urls:
        inner = normalize_url(candidate)
        if inner.host and inner.host not in hosts:
            hosts.append(inner.host)
    for _, value in normalized.destination_params:
        inner = normalize_url(value)
        if inner.host and inner.host not in hosts:
            hosts.append(inner.host)
    return hosts
