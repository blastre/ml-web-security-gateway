"""Reproducible synthetic SSRF dataset generator.

The dataset is organised as a set of *families*: each family is a small
generator that produces one recognisable attack technique or one realistic
benign traffic pattern.  Sampling from families rather than from a flat
distribution has two benefits:

* the evaluation report can break precision/recall down per technique, showing
  exactly which bypasses a model misses;
* benign families can be written as deliberate **hard negatives** -- public IP
  literals, percent-encoded search terms, non-standard ports on public hosts,
  documentation pages that merely *mention* ``127.0.0.1`` -- so the models
  cannot pass by latching onto a single surface cue.

Every sample is produced from a seeded :class:`random.Random`, so the same seed
always yields the same dataset.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence
from urllib.parse import quote

from mlwsg.config import (
    DATASET_METADATA_PATH,
    DATASET_PATH,
    LABEL_BENIGN,
    LABEL_SSRF,
    RANDOM_SEED,
    ensure_directories,
)
from mlwsg.dataset.vocab import (
    ADMIN_PORTS,
    BRANDS,
    DANGEROUS_SCHEME_TARGETS,
    DOC_SLUGS,
    FETCH_ENDPOINTS,
    INTERNAL_HOSTNAMES,
    INTERNAL_MENTION_PHRASES,
    INTERNAL_PATHS,
    METHODS_BENIGN,
    METHODS_SSRF,
    REDIRECT_PARAMS,
    SEARCH_PARAMS,
    SEARCH_PHRASES,
    SENSITIVE_PORTS,
    SIMULATED_METADATA_PATHS,
    TEXT_PARAMS,
    INTERNAL_URL_MENTIONS,
    USER_AGENT_HOSTS,
    public_host,
    public_path,
    query_string,
    random_cgnat_ipv4,
    random_link_local_ipv4,
    random_loopback_ipv4,
    random_private_ipv4,
    random_public_ipv4,
    random_unique_local_ipv6,
    to_decimal_notation,
    to_fullwidth,
    to_hex_notation,
    to_octal_notation,
    to_short_notation,
)
from mlwsg.schema import DATASET_COLUMNS, DatasetSample, RequestRecord

DATASET_VERSION = "1.0.0"


@dataclass(frozen=True)
class Draft:
    """A request produced by a family builder, before labelling."""

    url: str
    method: str = "GET"
    body: str = ""
    redirect_location: str = ""
    redirect_hops: int = 0
    notes: str = ""


@dataclass(frozen=True)
class Family:
    """A named traffic pattern the generator can draw from."""

    name: str
    label: str
    weight: float
    description: str
    builder: Callable[[random.Random], Draft]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _wrap_in_fetch_endpoint(rng: random.Random, target: str, encode_prob: float = 0.55) -> str:
    """Embed *target* in a URL-taking parameter of a public fetch endpoint.

    Models the realistic shape of an inbound request: the gateway sees
    ``https://app.example.com/fetch?url=<target>``, not the bare target.
    """
    host = public_host(rng)
    endpoint = rng.choice(FETCH_ENDPOINTS)
    param = rng.choice(REDIRECT_PARAMS)
    value = quote(target, safe="") if rng.random() < encode_prob else target
    extra = f"&{query_string(rng, 1)}" if rng.random() < 0.3 else ""
    return f"https://{host}{endpoint}?{param}={value}{extra}"


def _present(rng: random.Random, target: str, wrap_prob: float = 0.4) -> str:
    """Either the bare target URL or the same target wrapped in a fetch endpoint."""
    if rng.random() < wrap_prob:
        return _wrap_in_fetch_endpoint(rng, target)
    return target


def _internal_target(rng: random.Random, host: str, scheme: str = "http") -> str:
    """Compose an internal URL: host + optional port + an interesting path."""
    port = ""
    roll = rng.random()
    if roll < 0.3:
        port = f":{rng.choice(ADMIN_PORTS)}"
    elif roll < 0.4:
        port = f":{rng.choice(SENSITIVE_PORTS)}"
    path = rng.choice(INTERNAL_PATHS) if rng.random() < 0.8 else public_path(rng)
    return f"{scheme}://{host}{port}{path}"


def _bracket(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


# ---------------------------------------------------------------------------
# Benign families
# ---------------------------------------------------------------------------


def _benign_static_asset(rng: random.Random) -> Draft:
    host = public_host(rng)
    folder = rng.choice(("static", "assets", "dist", "public"))
    kind = rng.choice(("css", "js", "img", "fonts", "media"))
    from mlwsg.dataset.vocab import FILE_NAMES

    url = f"https://{host}/{folder}/{kind}/{rng.choice(FILE_NAMES)}"
    if rng.random() < 0.45:
        url += f"?v={rng.randint(1, 99999)}"
    return Draft(url=url, notes="CDN/static asset request")


def _benign_api_call(rng: random.Random) -> Draft:
    url = f"https://{public_host(rng)}{public_path(rng)}?{query_string(rng)}"
    return Draft(url=url, method=rng.choice(METHODS_BENIGN), notes="ordinary JSON API call")


def _benign_search(rng: random.Random) -> Draft:
    """Percent-encoded, sometimes non-ASCII search terms: encoding is not an attack."""
    param = rng.choice(SEARCH_PARAMS)
    phrase = rng.choice(SEARCH_PHRASES)
    url = f"https://{public_host(rng)}/search?{param}={quote(phrase)}"
    if rng.random() < 0.4:
        url += f"&{query_string(rng, 2)}"
    return Draft(url=url, notes="search query with percent-encoded text")


def _benign_url_param_public(rng: random.Random) -> Draft:
    """A legitimate use of a URL-taking parameter -- the key hard negative."""
    target = f"https://{public_host(rng)}{public_path(rng)}"
    return Draft(
        url=_wrap_in_fetch_endpoint(rng, target),
        method=rng.choice(("GET", "GET", "POST")),
        notes="link-preview/import of a public resource",
    )


def _benign_webhook_public(rng: random.Random) -> Draft:
    target = f"https://{public_host(rng)}/hooks/{rng.randint(1000, 999999)}"
    body = json.dumps({"event": rng.choice(("order.created", "user.updated", "ping")),
                       "callback_url": target}, separators=(",", ":"))
    url = f"https://{public_host(rng)}/api/v1/webhooks"
    return Draft(url=url, method="POST", body=body, notes="webhook registration, public callback")


def _benign_rss_feed(rng: random.Random) -> Draft:
    target = f"https://{public_host(rng)}/feed.xml"
    url = f"https://{public_host(rng)}/reader/subscribe?feed={quote(target, safe='')}"
    return Draft(url=url, notes="RSS subscription to a public feed")


def _benign_oauth_callback(rng: random.Random) -> Draft:
    target = f"https://{public_host(rng)}/auth/callback"
    url = (f"https://{public_host(rng)}/oauth/authorize?response_type=code"
           f"&client_id={rng.randint(10000, 99999)}&redirect_uri={quote(target, safe='')}"
           f"&scope=openid+profile&state={rng.getrandbits(48):012x}")
    return Draft(url=url, notes="OAuth authorize with public redirect_uri")


def _benign_public_ip_literal(rng: random.Random) -> Draft:
    """Public IP literal: an IP in the host is suspicious, but not by itself SSRF."""
    address = random_public_ipv4(rng)
    port = f":{rng.choice((80, 443, 8080))}" if rng.random() < 0.4 else ""
    scheme = "https" if rng.random() < 0.5 else "http"
    url = f"{scheme}://{address}{port}{public_path(rng)}"
    return Draft(url=url, notes="health/uptime check against a public IP literal")


def _benign_public_high_port(rng: random.Random) -> Draft:
    url = f"https://{public_host(rng)}:{rng.choice((8080, 8443, 3000, 5000, 9443))}{public_path(rng)}"
    return Draft(url=url, notes="public host on a non-standard port")


def _benign_public_redirect(rng: random.Random) -> Draft:
    """A redirect that stays in public space -- redirects alone are not SSRF.

    A third of these carry **no observed redirect**: the gateway sees the
    shortlink before anything has followed it.  Those samples are deliberately
    indistinguishable from the unresolved half of
    :func:`_ssrf_redirect_chain` -- see the note there.
    """
    url = f"https://{public_host(rng)}/r/{rng.getrandbits(32):08x}"
    if rng.random() < 0.35:
        return Draft(url=url, notes="shortlink, redirect not yet followed")
    return Draft(
        url=url,
        redirect_location=f"https://{public_host(rng)}{public_path(rng)}",
        redirect_hops=rng.randint(1, 2),
        notes="shortlink redirecting to another public host",
    )


def _benign_long_query(rng: random.Random) -> Draft:
    url = f"https://{public_host(rng)}{public_path(rng)}?{query_string(rng, rng.randint(6, 12))}"
    return Draft(url=url, notes="long but ordinary query string")


def _benign_form_post(rng: random.Random) -> Draft:
    body = "&".join(
        f"{key}={quote(str(rng.choice(('Alice', 'Bob', 42, 'yes', 'no', 'hello world'))))}"
        for key in ("name", "comment", "rating", "subscribe")
    )
    url = f"https://{public_host(rng)}/forms/{rng.choice(('contact', 'review', 'signup'))}"
    return Draft(url=url, method="POST", body=body, notes="form submission without any URL")


def _benign_encoded_path(rng: random.Random) -> Draft:
    name = rng.choice(("Annual Report 2024", "Résumé – final", "Quarterly P&L", "naïve-bayes notes"))
    url = f"https://{public_host(rng)}/files/{quote(name)}.pdf"
    return Draft(url=url, notes="percent-encoded file name in the path")


def _benign_punycode_host(rng: random.Random) -> Draft:
    host = rng.choice(("xn--bcher-kva.example.com", "xn--caf-dma.example.org",
                       "xn--mnchen-3ya.example.net", "xn--80akhbyknj4f.example.com"))
    url = f"https://{host}{public_path(rng)}"
    return Draft(url=url, notes="internationalised (punycode) public host")


def _benign_userinfo_public(rng: random.Random) -> Draft:
    url = f"https://{rng.choice(('svc', 'reader', 'bot'))}@{public_host(rng)}{public_path(rng)}"
    return Draft(url=url, notes="userinfo present but host is public")


def _benign_mentions_internal(rng: random.Random) -> Draft:
    """Docs/search traffic that *talks about* internal addresses without fetching them.

    A substring rule ("contains 127.0.0.1") flags these; a good model must not.
    """
    if rng.random() < 0.5:
        param = rng.choice(SEARCH_PARAMS)
        phrase = rng.choice(INTERNAL_MENTION_PHRASES)
        url = f"https://{public_host(rng)}/search?{param}={quote(phrase)}"
        notes = "search text mentioning internal addresses"
    else:
        url = f"https://{public_host(rng)}/docs/{rng.choice(DOC_SLUGS)}"
        notes = "documentation page about internal networking"
    return Draft(url=url, notes=notes)


def _benign_internal_url_as_text(rng: random.Random) -> Draft:
    """An internal URL pasted into a *free-text* field: a bug report, not a fetch.

    This is the dataset's sharpest hard negative.  The URL genuinely contains
    ``http://127.0.0.1:8080/``, so "does an internal destination appear
    anywhere?" is true -- yet the request is harmless.  Separating it from
    :func:`_ssrf_open_redirect_param` requires reading *which* parameter carries
    the URL and whether the path is a fetch endpoint, which is exactly the kind
    of combination a single deterministic rule gets wrong.
    """
    host = public_host(rng)
    param = rng.choice(TEXT_PARAMS)
    text = rng.choice(INTERNAL_URL_MENTIONS)
    endpoint = rng.choice(("/issues/new", "/support/ticket", "/forum/post",
                           "/paste", "/feedback", "/comments"))
    if rng.random() < 0.35:
        return Draft(
            url=f"https://{host}{endpoint}",
            method="POST",
            body=f"{param}={quote(text)}&priority={rng.choice(('low', 'normal', 'high'))}",
            notes="internal URL discussed in a free-text body field",
        )
    return Draft(
        url=f"https://{host}{endpoint}?{param}={quote(text)}",
        notes="internal URL discussed in a free-text query parameter",
    )


def _benign_dev_referrer(rng: random.Random) -> Draft:
    """Analytics beacon whose referrer is a developer's own localhost server."""
    local = rng.choice(("http://localhost:3000/", "http://127.0.0.1:8080/dashboard",
                        "http://localhost:5173/", "http://127.0.0.1:4200/home"))
    param = rng.choice(("ref", "referrer", "referer", "from", "origin_page"))
    url = (f"https://{public_host(rng)}/collect?{param}={quote(local, safe='')}"
           f"&event={rng.choice(('pageview', 'click', 'load'))}&t={rng.getrandbits(32)}")
    return Draft(url=url, notes="analytics beacon referred from a local dev server")


def _benign_cdn_image_resize(rng: random.Random) -> Draft:
    target = f"https://{public_host(rng)}/uploads/{rng.getrandbits(32):08x}.jpg"
    url = (f"https://{public_host(rng)}/resize?image_url={quote(target, safe='')}"
           f"&w={rng.choice((160, 320, 640, 1280))}&fit=cover")
    return Draft(url=url, notes="image resizing proxy pointed at public storage")


def _benign_pagination(rng: random.Random) -> Draft:
    url = (f"https://{public_host(rng)}/api/v2/{rng.choice(('orders', 'users', 'events'))}"
           f"?page={rng.randint(1, 400)}&limit={rng.choice((10, 25, 50, 100))}"
           f"&sort={rng.choice(('created_at', '-created_at', 'name'))}")
    return Draft(url=url, notes="paginated listing endpoint")


# ---------------------------------------------------------------------------
# SSRF families
# ---------------------------------------------------------------------------


def _ssrf_loopback_direct(rng: random.Random) -> Draft:
    host = random_loopback_ipv4(rng) if rng.random() < 0.6 else rng.choice(("localhost", "localhost.localdomain"))
    return Draft(
        url=_present(rng, _internal_target(rng, host)),
        method=rng.choice(METHODS_SSRF),
        notes="direct loopback access",
    )


def _ssrf_private_network(rng: random.Random) -> Draft:
    return Draft(
        url=_present(rng, _internal_target(rng, random_private_ipv4(rng))),
        method=rng.choice(METHODS_SSRF),
        notes="RFC1918 private-network access",
    )


def _ssrf_link_local_metadata(rng: random.Random) -> Draft:
    """Instance-metadata scenario, expressed against simulated endpoints only."""
    if rng.random() < 0.5:
        host = random_link_local_ipv4(rng)
    else:
        from mlwsg.net.addresses import SIMULATED_METADATA_HOSTS

        host = rng.choice(SIMULATED_METADATA_HOSTS)
    path = rng.choice(SIMULATED_METADATA_PATHS)
    return Draft(
        url=_present(rng, f"http://{host}{path}"),
        notes="simulated instance-metadata access (link-local / metadata.sim)",
    )


def _ssrf_decimal_ip(rng: random.Random) -> Draft:
    address = random_loopback_ipv4(rng) if rng.random() < 0.5 else random_private_ipv4(rng)
    return Draft(
        url=_present(rng, _internal_target(rng, to_decimal_notation(address))),
        notes="IP written in 32-bit decimal notation",
    )


def _ssrf_hex_ip(rng: random.Random) -> Draft:
    address = random_loopback_ipv4(rng) if rng.random() < 0.5 else random_private_ipv4(rng)
    host = to_hex_notation(address, dotted=rng.random() < 0.4)
    return Draft(url=_present(rng, _internal_target(rng, host)), notes="IP written in hexadecimal")


def _ssrf_octal_ip(rng: random.Random) -> Draft:
    address = random_loopback_ipv4(rng) if rng.random() < 0.5 else random_private_ipv4(rng)
    host = to_octal_notation(address, padded=rng.random() < 0.5)
    return Draft(url=_present(rng, _internal_target(rng, host)), notes="IP written in octal")


def _ssrf_short_ip(rng: random.Random) -> Draft:
    address = random_loopback_ipv4(rng) if rng.random() < 0.6 else random_private_ipv4(rng)
    return Draft(
        url=_present(rng, _internal_target(rng, to_short_notation(address))),
        notes="abbreviated inet_aton notation (127.1)",
    )


def _ssrf_ipv6_loopback(rng: random.Random) -> Draft:
    host = rng.choice(("::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::"))
    return Draft(url=_present(rng, _internal_target(rng, _bracket(host))), notes="IPv6 loopback form")


def _ssrf_ipv6_unique_local(rng: random.Random) -> Draft:
    host = _bracket(random_unique_local_ipv6(rng))
    return Draft(url=_present(rng, _internal_target(rng, host)), notes="IPv6 unique-local (fd00::/8) target")


def _ssrf_percent_encoded(rng: random.Random) -> Draft:
    host = random_loopback_ipv4(rng) if rng.random() < 0.5 else random_private_ipv4(rng)
    encoded_host = quote(host, safe="")
    path = quote(rng.choice(INTERNAL_PATHS), safe="")
    return Draft(url=f"http://{encoded_host}{path}", notes="percent-encoded host and path")


def _ssrf_double_encoded(rng: random.Random) -> Draft:
    target = f"http://{random_loopback_ipv4(rng)}{rng.choice(INTERNAL_PATHS)}"
    once = quote(target, safe="")
    twice = quote(once, safe="")
    host = public_host(rng)
    return Draft(
        url=f"https://{host}{rng.choice(FETCH_ENDPOINTS)}?{rng.choice(REDIRECT_PARAMS)}={twice}",
        notes="double percent-encoded internal target",
    )


def _ssrf_userinfo_confusion(rng: random.Random) -> Draft:
    trusted = rng.choice(USER_AGENT_HOSTS)
    host = rng.choice((random_loopback_ipv4(rng), random_private_ipv4(rng), "localhost"))
    port = f":{rng.choice(ADMIN_PORTS + SENSITIVE_PORTS)}" if rng.random() < 0.5 else ""
    url = f"http://{trusted}@{host}{port}{rng.choice(INTERNAL_PATHS)}"
    return Draft(url=_present(rng, url, wrap_prob=0.25), notes="trusted host smuggled into userinfo")


def _ssrf_dns_embedded_ip(rng: random.Random) -> Draft:
    """Wildcard-DNS bypass: the target address is carried inside the hostname."""
    address = random_loopback_ipv4(rng) if rng.random() < 0.5 else random_private_ipv4(rng)
    separator = "." if rng.random() < 0.5 else "-"
    suffix = rng.choice(("rebind.test", "wildcard.test", "anyip.test", "resolver.sim"))
    host = f"{address.replace('.', separator)}.{suffix}"
    return Draft(url=_present(rng, _internal_target(rng, host)), notes="IP embedded in a wildcard DNS name")


def _ssrf_open_redirect_param(rng: random.Random) -> Draft:
    target = _internal_target(rng, rng.choice((random_private_ipv4(rng), random_loopback_ipv4(rng),
                                               rng.choice(INTERNAL_HOSTNAMES))))
    return Draft(
        url=_wrap_in_fetch_endpoint(rng, target, encode_prob=0.5),
        method=rng.choice(("GET", "GET", "POST")),
        notes="internal URL supplied in a URL-taking parameter",
    )


def _ssrf_redirect_chain(rng: random.Random) -> Draft:
    """Public URL whose redirect lands internally -- only the final hop is internal.

    A third of these are emitted with **no observed redirect**, modelling the
    gateway seeing the request *before* anything followed the ``Location``
    header.  Those samples are byte-for-byte the same shape as the unresolved
    variant of :func:`_benign_public_redirect`, so no URL-only classifier can
    separate them.  That is the point: they are the honest, irreducible error
    floor of an inbound detector, and the reason Phase 2 needs an egress guard
    that classifies the *resolved* destination.
    """
    url = f"https://{public_host(rng)}/r/{rng.getrandbits(32):08x}"
    if rng.random() < 0.35:
        return Draft(url=url, notes="redirect into internal space, not yet observed at ingress")
    internal = _internal_target(
        rng, rng.choice((random_loopback_ipv4(rng), random_private_ipv4(rng),
                         random_link_local_ipv4(rng), rng.choice(INTERNAL_HOSTNAMES)))
    )
    return Draft(
        url=url,
        redirect_location=internal,
        redirect_hops=rng.randint(1, 3),
        notes="public entry point redirecting into internal space",
    )


def _ssrf_dns_rebinding(rng: random.Random) -> Draft:
    """An attacker domain that *resolves* to an internal address at fetch time.

    Nothing in the URL *destination* gives this away: the scheme is https, the
    path is unremarkable, and the host is public.  Half of these use a hostname
    drawn from the same distribution as benign traffic, making them genuinely
    indistinguishable; the other half use a freshly-registered-looking
    high-entropy label, which the entropy and digit-ratio features can pick up
    on weakly.  The family therefore lands at a partial detection rate rather
    than at zero or one -- an honest recall ceiling for a URL-only detector,
    and the concrete motivation for Phase 2's resolution-time egress guard.
    """
    if rng.random() < 0.5:
        host = public_host(rng)
    else:
        label = f"{rng.getrandbits(40):010x}"
        host = f"{label}.{rng.choice(BRANDS)}.{rng.choice(('com', 'net', 'io'))}"
    target = f"https://{host}{public_path(rng)}"
    return Draft(
        url=_present(rng, target, wrap_prob=0.5),
        notes="attacker-controlled host that resolves to an internal IP (DNS rebinding)",
    )


def _ssrf_alt_scheme(rng: random.Random) -> Draft:
    scheme, path = rng.choice(DANGEROUS_SCHEME_TARGETS)
    if scheme == "file":
        url = f"file://{path}"
    else:
        host = rng.choice((random_loopback_ipv4(rng), random_private_ipv4(rng), "localhost"))
        port = f":{rng.choice(SENSITIVE_PORTS)}"
        url = f"{scheme}://{host}{port}{path}"
    return Draft(url=_present(rng, url, wrap_prob=0.3), notes=f"{scheme}:// scheme abuse")


def _ssrf_internal_hostname(rng: random.Random) -> Draft:
    host = rng.choice(INTERNAL_HOSTNAMES)
    return Draft(
        url=_present(rng, _internal_target(rng, host)),
        method=rng.choice(METHODS_SSRF),
        notes="internal-only DNS name",
    )


def _ssrf_internal_port_probe(rng: random.Random) -> Draft:
    host = rng.choice((random_loopback_ipv4(rng), random_private_ipv4(rng), "localhost"))
    port = rng.choice(SENSITIVE_PORTS)
    url = f"http://{host}:{port}/"
    return Draft(url=_present(rng, url), notes=f"probe of internal service port {port}")


def _ssrf_unspecified_address(rng: random.Random) -> Draft:
    host = rng.choice(("0.0.0.0", "0", "0x0", "[::]", "0000.0000.0000.0000"))
    port = f":{rng.choice(ADMIN_PORTS)}" if rng.random() < 0.6 else ""
    url = f"http://{host}{port}{rng.choice(INTERNAL_PATHS)}"
    return Draft(url=_present(rng, url), notes="unspecified address (0.0.0.0) routing to localhost")


def _ssrf_cgnat_shared(rng: random.Random) -> Draft:
    return Draft(
        url=_present(rng, _internal_target(rng, random_cgnat_ipv4(rng))),
        notes="carrier-grade NAT / shared address space (100.64.0.0/10)",
    )


def _ssrf_whitespace_obfuscation(rng: random.Random) -> Draft:
    host = rng.choice((random_loopback_ipv4(rng), "localhost", random_private_ipv4(rng)))
    filler = rng.choice(("%09", "%0a", "%0d", "%20", "\t", " "))
    url = f"http://{host}{filler}{rng.choice(INTERNAL_PATHS)}"
    return Draft(url=url, notes="whitespace/control character obfuscation")


def _ssrf_backslash_obfuscation(rng: random.Random) -> Draft:
    host = rng.choice((random_loopback_ipv4(rng), "localhost", random_private_ipv4(rng)))
    url = rng.choice((
        f"http:\\\\{host}\\{rng.choice(INTERNAL_PATHS).lstrip('/')}",
        f"http://{host}\\{rng.choice(INTERNAL_PATHS).lstrip('/')}",
        f"https:/\\{host}/{rng.choice(INTERNAL_PATHS).lstrip('/')}",
    ))
    return Draft(url=url, notes="backslash path/authority confusion")


def _ssrf_case_and_trailing_dot(rng: random.Random) -> Draft:
    host = rng.choice(("LOCALHOST", "LocalHost", "127.0.0.1.", "localhost.", "LOCALHOST."))
    port = f":{rng.choice(ADMIN_PORTS)}" if rng.random() < 0.5 else ""
    scheme = rng.choice(("http", "HTTP", "HtTp"))
    url = f"{scheme}://{host}{port}{rng.choice(INTERNAL_PATHS)}"
    return Draft(url=url, notes="case variation and trailing-dot host")


def _ssrf_unicode_obfuscation(rng: random.Random) -> Draft:
    address = random_loopback_ipv4(rng) if rng.random() < 0.6 else random_private_ipv4(rng)
    url = f"http://{to_fullwidth(address)}{rng.choice(INTERNAL_PATHS)}"
    return Draft(url=url, notes="fullwidth-digit host that NFKC-normalises to an internal IP")


def _ssrf_body_payload(rng: random.Random) -> Draft:
    target = _internal_target(
        rng, rng.choice((random_loopback_ipv4(rng), random_private_ipv4(rng),
                         rng.choice(INTERNAL_HOSTNAMES)))
    )
    body = json.dumps({"callback_url": target, "retries": rng.randint(0, 5)}, separators=(",", ":"))
    url = f"https://{public_host(rng)}/api/v1/{rng.choice(('webhooks', 'imports', 'jobs'))}"
    return Draft(url=url, method="POST", body=body, notes="internal URL hidden in the request body")


def _ssrf_metadata_via_redirect(rng: random.Random) -> Draft:
    """Two-stage: a URL parameter points at a public host that redirects to metadata."""
    stage_one = f"https://{public_host(rng)}/go/{rng.getrandbits(24):06x}"
    from mlwsg.net.addresses import SIMULATED_METADATA_HOSTS

    host = rng.choice(SIMULATED_METADATA_HOSTS) if rng.random() < 0.5 else random_link_local_ipv4(rng)
    return Draft(
        url=_wrap_in_fetch_endpoint(rng, stage_one),
        redirect_location=f"http://{host}{rng.choice(SIMULATED_METADATA_PATHS)}",
        redirect_hops=rng.randint(1, 2),
        notes="redirect chain ending at the simulated metadata service",
    )


# ---------------------------------------------------------------------------
# Family registry
# ---------------------------------------------------------------------------

FAMILIES: tuple[Family, ...] = (
    # --- benign ----------------------------------------------------------
    Family("benign_static_asset", LABEL_BENIGN, 8.0, "CDN and static asset requests", _benign_static_asset),
    Family("benign_api_call", LABEL_BENIGN, 8.0, "Ordinary JSON API traffic", _benign_api_call),
    Family("benign_search", LABEL_BENIGN, 5.0, "Encoded search terms (hard negative for encoding)", _benign_search),
    Family("benign_url_param_public", LABEL_BENIGN, 6.0, "Legitimate URL-taking parameter (hard negative)", _benign_url_param_public),
    Family("benign_webhook_public", LABEL_BENIGN, 3.0, "Webhook registration with a public callback", _benign_webhook_public),
    Family("benign_rss_feed", LABEL_BENIGN, 2.5, "Public RSS subscription", _benign_rss_feed),
    Family("benign_oauth_callback", LABEL_BENIGN, 2.5, "OAuth flow with public redirect_uri", _benign_oauth_callback),
    Family("benign_public_ip_literal", LABEL_BENIGN, 4.0, "Public IP literal (hard negative for IP-in-host)", _benign_public_ip_literal),
    Family("benign_public_high_port", LABEL_BENIGN, 3.0, "Public host on a non-standard port (hard negative)", _benign_public_high_port),
    Family("benign_public_redirect", LABEL_BENIGN, 3.5, "Redirect that stays public (hard negative)", _benign_public_redirect),
    Family("benign_long_query", LABEL_BENIGN, 3.0, "Long ordinary query strings", _benign_long_query),
    Family("benign_form_post", LABEL_BENIGN, 3.0, "Form POSTs without any URL", _benign_form_post),
    Family("benign_encoded_path", LABEL_BENIGN, 2.5, "Percent-encoded file names", _benign_encoded_path),
    Family("benign_punycode_host", LABEL_BENIGN, 2.0, "Internationalised public hosts", _benign_punycode_host),
    Family("benign_userinfo_public", LABEL_BENIGN, 2.0, "Userinfo present, host public (hard negative)", _benign_userinfo_public),
    Family("benign_mentions_internal", LABEL_BENIGN, 3.0, "Docs/search that mention internal IPs (hard negative)", _benign_mentions_internal),
    Family("benign_internal_url_as_text", LABEL_BENIGN, 3.0, "Internal URL quoted in a free-text field (hard negative)", _benign_internal_url_as_text),
    Family("benign_dev_referrer", LABEL_BENIGN, 2.0, "Analytics beacon referred from localhost (hard negative)", _benign_dev_referrer),
    Family("benign_cdn_image_resize", LABEL_BENIGN, 3.0, "Image proxy pointed at public storage", _benign_cdn_image_resize),
    Family("benign_pagination", LABEL_BENIGN, 3.0, "Paginated listing endpoints", _benign_pagination),
    # --- ssrf -------------------------------------------------------------
    Family("ssrf_loopback_direct", LABEL_SSRF, 5.0, "Direct loopback access", _ssrf_loopback_direct),
    Family("ssrf_private_network", LABEL_SSRF, 5.0, "RFC1918 private ranges", _ssrf_private_network),
    Family("ssrf_link_local_metadata", LABEL_SSRF, 4.5, "Simulated instance metadata via link-local", _ssrf_link_local_metadata),
    Family("ssrf_decimal_ip", LABEL_SSRF, 2.5, "Decimal IP notation", _ssrf_decimal_ip),
    Family("ssrf_hex_ip", LABEL_SSRF, 2.5, "Hexadecimal IP notation", _ssrf_hex_ip),
    Family("ssrf_octal_ip", LABEL_SSRF, 2.5, "Octal IP notation", _ssrf_octal_ip),
    Family("ssrf_short_ip", LABEL_SSRF, 2.0, "Abbreviated inet_aton notation", _ssrf_short_ip),
    Family("ssrf_ipv6_loopback", LABEL_SSRF, 2.0, "IPv6 loopback and IPv4-mapped forms", _ssrf_ipv6_loopback),
    Family("ssrf_ipv6_unique_local", LABEL_SSRF, 1.5, "IPv6 unique-local targets", _ssrf_ipv6_unique_local),
    Family("ssrf_percent_encoded", LABEL_SSRF, 2.5, "Percent-encoded internal host", _ssrf_percent_encoded),
    Family("ssrf_double_encoded", LABEL_SSRF, 2.0, "Double percent-encoded target", _ssrf_double_encoded),
    Family("ssrf_userinfo_confusion", LABEL_SSRF, 2.5, "Trusted host in the userinfo slot", _ssrf_userinfo_confusion),
    Family("ssrf_dns_embedded_ip", LABEL_SSRF, 2.5, "Wildcard DNS carrying the target IP", _ssrf_dns_embedded_ip),
    Family("ssrf_open_redirect_param", LABEL_SSRF, 4.0, "Internal URL in a URL-taking parameter", _ssrf_open_redirect_param),
    Family("ssrf_redirect_chain", LABEL_SSRF, 3.5, "Public entry point redirecting internally", _ssrf_redirect_chain),
    Family("ssrf_dns_rebinding", LABEL_SSRF, 2.0, "Attacker host resolving to internal space (not visible in the URL)", _ssrf_dns_rebinding),
    Family("ssrf_alt_scheme", LABEL_SSRF, 2.5, "file/gopher/dict/ftp scheme abuse", _ssrf_alt_scheme),
    Family("ssrf_internal_hostname", LABEL_SSRF, 4.0, "Internal-only DNS names", _ssrf_internal_hostname),
    Family("ssrf_internal_port_probe", LABEL_SSRF, 3.0, "Internal service port probing", _ssrf_internal_port_probe),
    Family("ssrf_unspecified_address", LABEL_SSRF, 1.5, "0.0.0.0 and equivalents", _ssrf_unspecified_address),
    Family("ssrf_cgnat_shared", LABEL_SSRF, 1.5, "Shared/CGNAT address space", _ssrf_cgnat_shared),
    Family("ssrf_whitespace_obfuscation", LABEL_SSRF, 1.5, "Whitespace/control-char obfuscation", _ssrf_whitespace_obfuscation),
    Family("ssrf_backslash_obfuscation", LABEL_SSRF, 1.5, "Backslash authority confusion", _ssrf_backslash_obfuscation),
    Family("ssrf_case_and_trailing_dot", LABEL_SSRF, 1.5, "Case variation and trailing-dot hosts", _ssrf_case_and_trailing_dot),
    Family("ssrf_unicode_obfuscation", LABEL_SSRF, 1.5, "Fullwidth-digit hosts", _ssrf_unicode_obfuscation),
    Family("ssrf_body_payload", LABEL_SSRF, 2.5, "Internal URL hidden in the request body", _ssrf_body_payload),
    Family("ssrf_metadata_via_redirect", LABEL_SSRF, 2.0, "Redirect chain into simulated metadata", _ssrf_metadata_via_redirect),
)

FAMILIES_BY_NAME = {family.name: family for family in FAMILIES}

#: SSRF families that carry **no signal in the request itself**.  A URL-only
#: classifier cannot be expected to catch these, and the test suite exempts them
#: from the "every SSRF sample has an internal indicator" invariant.  They set
#: the honest recall ceiling for Phase 1 and define the work for Phase 2's
#: resolution-time egress guard.
STATICALLY_UNDETECTABLE_FAMILIES = frozenset({"ssrf_dns_rebinding", "ssrf_redirect_chain"})


def benign_families() -> tuple[Family, ...]:
    return tuple(f for f in FAMILIES if f.label == LABEL_BENIGN)


def ssrf_families() -> tuple[Family, ...]:
    return tuple(f for f in FAMILIES if f.label == LABEL_SSRF)


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _sample_id(draft: Draft) -> str:
    digest = hashlib.sha1(
        "|".join((draft.method, draft.url, draft.body, draft.redirect_location)).encode("utf-8")
    ).hexdigest()
    return digest[:12]


def _dedup_key(draft: Draft) -> tuple[str, str, str, str]:
    return (draft.method, draft.url, draft.body, draft.redirect_location)


def generate_dataset(
    n_samples: int = 12000,
    seed: int = RANDOM_SEED,
    benign_ratio: float = 0.6,
    min_per_family: int = 40,
) -> list[DatasetSample]:
    """Generate *n_samples* unique labelled requests.

    Args:
        n_samples: Target dataset size after de-duplication.
        seed: Seed for the generator; the same seed always yields the same rows.
        benign_ratio: Share of benign samples in the final dataset.
        min_per_family: Guaranteed minimum number of samples per family, so no
            technique is left unrepresented by chance.

    Returns:
        A shuffled list of :class:`~mlwsg.schema.DatasetSample`.
    """
    if n_samples <= 0:
        raise ValueError("n_samples must be positive")
    if not 0.0 < benign_ratio < 1.0:
        raise ValueError("benign_ratio must be strictly between 0 and 1")

    rng = random.Random(seed)
    benign_target = int(round(n_samples * benign_ratio))
    targets = {LABEL_BENIGN: benign_target, LABEL_SSRF: n_samples - benign_target}

    seen: set[tuple[str, str, str, str]] = set()
    samples: list[DatasetSample] = []

    def emit(family: Family) -> bool:
        for _ in range(24):  # bounded retries to escape duplicate-heavy families
            draft = family.builder(rng)
            if not draft.url:
                continue
            key = _dedup_key(draft)
            if key in seen:
                continue
            seen.add(key)
            samples.append(
                DatasetSample(
                    id=_sample_id(draft),
                    label=family.label,
                    family=family.name,
                    record=RequestRecord(
                        url=draft.url,
                        method=draft.method,
                        body=draft.body,
                        redirect_location=draft.redirect_location,
                        redirect_hops=draft.redirect_hops,
                    ),
                    notes=draft.notes,
                )
            )
            return True
        return False

    counts: dict[str, int] = {family.name: 0 for family in FAMILIES}

    # Pass 1: guarantee coverage of every technique.
    for family in FAMILIES:
        budget = min(min_per_family, targets[family.label])
        for _ in range(budget):
            if counts[family.name] >= targets[family.label]:
                break
            if emit(family):
                counts[family.name] += 1
                targets[family.label] -= 1

    # Pass 2: fill the remainder proportionally to the family weights.
    for label in (LABEL_BENIGN, LABEL_SSRF):
        pool = [f for f in FAMILIES if f.label == label]
        weights = [f.weight for f in pool]
        remaining = targets[label]
        stalls = 0
        while remaining > 0 and stalls < 500:
            family = rng.choices(pool, weights=weights, k=1)[0]
            if emit(family):
                counts[family.name] += 1
                remaining -= 1
                stalls = 0
            else:
                stalls += 1

    rng.shuffle(samples)
    return samples


def dataset_metadata(samples: Sequence[DatasetSample], seed: int, csv_sha256: str | None = None) -> dict:
    """Summary of a generated dataset, written alongside the CSV."""
    family_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {}
    for sample in samples:
        family_counts[sample.family] = family_counts.get(sample.family, 0) + 1
        label_counts[sample.label] = label_counts.get(sample.label, 0) + 1
    return {
        "dataset_version": DATASET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": seed,
        "n_samples": len(samples),
        "label_counts": dict(sorted(label_counts.items())),
        "family_counts": dict(sorted(family_counts.items())),
        "families": [
            {"name": f.name, "label": f.label, "weight": f.weight, "description": f.description}
            for f in FAMILIES
        ],
        "columns": list(DATASET_COLUMNS),
        "csv_sha256": csv_sha256,
        "notes": (
            "Fully synthetic. No real external hosts are contacted and no real cloud "
            "metadata endpoint is referenced; the metadata scenario uses this project's "
            "simulated hosts plus randomly drawn link-local addresses. The 'url' column "
            "is the URL under evaluation: either the inbound request URL or a "
            "user-supplied URL extracted from it."
        ),
    }


def write_dataset(
    samples: Iterable[DatasetSample],
    csv_path: Path = DATASET_PATH,
    metadata_path: Path | None = DATASET_METADATA_PATH,
    seed: int = RANDOM_SEED,
) -> Path:
    """Write the dataset to CSV (plus a JSON metadata sidecar) and return the path."""
    import pandas as pd

    samples = list(samples)
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    frame = pd.DataFrame([sample.to_row() for sample in samples], columns=list(DATASET_COLUMNS))
    frame.to_csv(csv_path, index=False)

    if metadata_path is not None:
        digest = hashlib.sha256(csv_path.read_bytes()).hexdigest()
        metadata_path = Path(metadata_path)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(
            json.dumps(dataset_metadata(samples, seed, digest), indent=2) + "\n", encoding="utf-8"
        )
    return csv_path


def load_dataset(csv_path: Path = DATASET_PATH):
    """Load the dataset CSV as a ``pandas.DataFrame`` with stable dtypes."""
    import pandas as pd

    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(
            f"dataset not found at {csv_path}; run `python -m mlwsg generate-dataset` first"
        )
    frame = pd.read_csv(csv_path, keep_default_na=False, na_values=[])
    frame["redirect_hops"] = frame["redirect_hops"].fillna(0).astype(int)
    for column in ("url", "method", "body", "redirect_location", "label", "family", "notes"):
        frame[column] = frame[column].fillna("").astype(str)
    return frame


def main() -> None:  # pragma: no cover - thin CLI shim
    ensure_directories()
    samples = generate_dataset()
    write_dataset(samples)
    print(f"wrote {len(samples)} samples to {DATASET_PATH}")


if __name__ == "__main__":  # pragma: no cover
    main()
