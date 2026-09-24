"""Vocabulary and random-value helpers for the synthetic dataset.

Two rules govern everything in this module:

* **No real external targets.**  Public hostnames are assembled from invented
  brand words, or use the RFC 2606 ``example.*`` reservations.  Nothing here
  names a real third-party service.
* **No real cloud metadata endpoints.**  The instance-metadata scenario is
  represented by the project's own simulated hosts (``metadata.sim.local``)
  and by randomly drawn link-local addresses, never by a live provider's
  well-known metadata IP.
"""

from __future__ import annotations

import ipaddress
import random

from mlwsg.net.addresses import CATEGORY_PUBLIC, classify_ip

# ---------------------------------------------------------------------------
# Public (benign) hostname vocabulary
# ---------------------------------------------------------------------------

BRANDS = (
    "acmeworks", "northwind", "bluebird", "corevault", "lumenly", "quantix",
    "driftwood", "pixelforge", "harborline", "cascadia", "nimbusly", "orchardio",
    "redwoodlabs", "silverline", "tandemworks", "vertexly", "wayfarer", "zephyrco",
    "beaconhill", "cloverleaf", "dynamoware", "emberfield", "fathomly", "glacierpeak",
    "halcyonlabs", "ironwoodco", "junipergrove", "kestrelworks", "lanternly",
    "marbleworks", "northgate", "opalstone", "pinecrestco", "quarrylane",
    "riversend", "summitfold", "thistlewood", "umberline", "violetbay", "windrowco",
)

SUBDOMAINS = (
    "www", "api", "cdn", "static", "assets", "img", "images", "media", "files",
    "docs", "blog", "shop", "store", "app", "dashboard", "auth", "id", "feeds",
    "news", "status", "help", "support", "downloads", "uploads", "content", "edge",
)

PUBLIC_TLDS = (
    "com", "net", "org", "io", "dev", "co", "app", "cloud", "shop", "news",
    "co.uk", "com.au", "de", "in", "ca", "fr", "nl", "se",
)

EXAMPLE_DOMAINS = ("example.com", "example.org", "example.net")

PATH_SEGMENTS = (
    "v1", "v2", "api", "users", "orders", "products", "articles", "posts", "media",
    "assets", "static", "images", "downloads", "catalog", "reports", "search",
    "profile", "settings", "billing", "notifications", "collections", "threads",
)

FILE_NAMES = (
    "index.html", "main.css", "bundle.js", "logo.png", "hero.jpg", "report.pdf",
    "data.json", "feed.xml", "sitemap.xml", "avatar.webp", "styles.min.css",
    "app.min.js", "terms.html", "whitepaper.pdf", "chart.svg",
)

QUERY_KEYS = (
    "q", "page", "limit", "offset", "sort", "order", "lang", "locale", "ref",
    "category", "size", "format", "v", "fields", "include", "filter", "cursor",
    "utm_source", "utm_medium", "utm_campaign", "theme", "currency",
)

QUERY_VALUES = (
    "latest", "popular", "asc", "desc", "en-us", "de-de", "2", "10", "25", "50",
    "json", "compact", "full", "newsletter", "homepage", "dark", "light", "usd",
    "eur", "true", "false", "summer-sale", "2024", "featured",
)

SEARCH_PHRASES = (
    "annual report 2024", "wireless headphones", "how to reset password",
    "café résumé template", "size guide", "shipping & returns",
    "open source licence", "naïve bayes tutorial", "año nuevo promoción",
    "python decorators explained", "best running shoes", "договор оферты",
)

# Text that *mentions* internal infrastructure without pointing at it -- the
# hard negatives that stop the model from keyword-matching.
INTERNAL_MENTION_PHRASES = (
    "how to configure localhost", "127.0.0.1 refused to connect",
    "redis on 10.0.0.5 tuning", "192.168.0.1 router login",
    "docker bind 0.0.0.0 explained", "ssh tunnel to 172.16.4.10",
    "why is my metadata service slow", "link local addressing 169.254",
)

# Free-text parameters that carry prose, not a fetch destination.  An internal
# URL pasted into one of these is a bug report, not an attack.
TEXT_PARAMS = ("description", "body", "message", "comment", "note", "content",
               "title", "summary", "details", "log")

# Free-text snippets in which an internal URL is being *discussed*.
INTERNAL_URL_MENTIONS = (
    "http://127.0.0.1:8080/ is refusing connections",
    "curl http://10.0.0.5:9200/_cat/indices returns 403",
    "why does http://localhost:3000/api hang on startup",
    "the docs say to open http://127.0.0.1:5000/ after running the server",
    "getting ECONNREFUSED from http://192.168.1.10:8000/health",
    "replace http://localhost/ with your public hostname",
)

DOC_SLUGS = (
    "networking/192-168-0-1-setup", "guides/localhost-development",
    "faq/why-127-0-0-1-is-special", "kb/internal-dns-explained",
    "blog/ssrf-prevention-checklist", "runbooks/private-network-access",
)

# ---------------------------------------------------------------------------
# Internal (SSRF target) vocabulary -- all simulated
# ---------------------------------------------------------------------------

INTERNAL_HOSTNAMES = (
    "localhost", "localhost.localdomain", "db.internal", "redis.internal",
    "cache.internal", "queue.internal", "admin.intranet", "jenkins.corp",
    "gitlab.corp", "vault.internal", "grafana.lan", "kibana.lan",
    "backend.svc.cluster.local", "payments.svc.cluster.local", "api.internal.sim",
    "metadata.sim.local", "metadata.internal.sim", "instance-data.internal.sim",
    "admin.internal.sim", "printer.home", "nas.private", "router.lan",
)

INTERNAL_PATHS = (
    "/admin", "/admin/users", "/actuator/env", "/actuator/health", "/debug/vars",
    "/server-status", "/.env", "/config.json", "/internal/api/keys",
    "/metrics", "/console", "/manage/health", "/v1/secrets", "/api/internal/users",
)

# Paths on the *simulated* metadata service.  Shaped like a real one so the
# scenario is recognisable, but served only by this project's dummy app.
SIMULATED_METADATA_PATHS = (
    "/metadata/v1/instance",
    "/metadata/v1/instance/identity",
    "/metadata/v1/credentials",
    "/metadata/v1/network",
    "/latest/simulated-meta-data/hostname",
)

SENSITIVE_PORTS = (22, 23, 25, 445, 1433, 2375, 2379, 3306, 3389, 5432, 5672,
                   6379, 8500, 9200, 11211, 15672, 27017)

ADMIN_PORTS = (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 10000)

DANGEROUS_SCHEME_TARGETS = (
    ("file", "/etc/passwd"),
    ("file", "/etc/shadow"),
    ("file", "/proc/self/environ"),
    ("file", "/var/log/app/application.log"),
    ("dict", "/info"),
    ("gopher", "/_SET%20session%20admin"),
    ("ftp", "/backup/db.sql"),
    ("ldap", "/dc=corp,dc=sim"),
)

# Fetch-style endpoints on the application under protection.
FETCH_ENDPOINTS = (
    "/fetch", "/api/fetch", "/proxy", "/api/v1/proxy", "/import", "/render",
    "/preview", "/thumbnail", "/webhook/test", "/api/link/preview", "/pdf/convert",
)

REDIRECT_PARAMS = ("url", "uri", "target", "dest", "redirect", "redirect_uri",
                   "next", "callback", "image_url", "feed", "webhook", "src")

SEARCH_PARAMS = ("q", "query", "search", "keywords", "filter", "term")

USER_AGENT_HOSTS = ("trusted.example.com", "www.example.com", "cdn.example.net")

METHODS_BENIGN = ("GET", "GET", "GET", "GET", "POST", "POST", "PUT")
METHODS_SSRF = ("GET", "GET", "GET", "POST", "POST", "PUT", "DELETE")


# ---------------------------------------------------------------------------
# Random helpers
# ---------------------------------------------------------------------------


def public_host(rng: random.Random) -> str:
    """A plausible public hostname built from invented brand words."""
    if rng.random() < 0.12:
        base = rng.choice(EXAMPLE_DOMAINS)
        return f"{rng.choice(SUBDOMAINS)}.{base}" if rng.random() < 0.6 else base
    brand = rng.choice(BRANDS)
    tld = rng.choice(PUBLIC_TLDS)
    roll = rng.random()
    if roll < 0.55:
        return f"{rng.choice(SUBDOMAINS)}.{brand}.{tld}"
    if roll < 0.75:
        return f"{brand}.{tld}"
    return f"{rng.choice(SUBDOMAINS)}.{rng.choice(SUBDOMAINS)}.{brand}.{tld}"


def public_path(rng: random.Random) -> str:
    """A believable public path, occasionally ending in a file name."""
    depth = rng.randint(0, 4)
    segments = [rng.choice(PATH_SEGMENTS) for _ in range(depth)]
    if rng.random() < 0.35:
        segments.append(rng.choice(FILE_NAMES))
    elif rng.random() < 0.3:
        segments.append(str(rng.randint(100, 99999)))
    return "/" + "/".join(segments) if segments else "/"


def query_string(rng: random.Random, count: int | None = None) -> str:
    """A query string of ordinary, non-URL parameters."""
    count = rng.randint(1, 4) if count is None else count
    keys = rng.sample(QUERY_KEYS, k=min(count, len(QUERY_KEYS)))
    return "&".join(f"{key}={rng.choice(QUERY_VALUES)}" for key in keys)


def random_public_ipv4(rng: random.Random) -> str:
    """A globally routable IPv4 address.

    Rejection-samples against :func:`classify_ip` so a benign "public IP"
    sample can never accidentally land in a private or documentation range.
    """
    for _ in range(64):
        address = ipaddress.IPv4Address(rng.randint(1 << 24, (1 << 32) - 2))
        if classify_ip(address) == CATEGORY_PUBLIC:
            return str(address)
    return "93.184.216.34"  # deterministic fallback, still public space


def random_loopback_ipv4(rng: random.Random) -> str:
    if rng.random() < 0.7:
        return "127.0.0.1"
    return f"127.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_private_ipv4(rng: random.Random) -> str:
    block = rng.choice(("10", "172", "192"))
    if block == "10":
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if block == "172":
        return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_link_local_ipv4(rng: random.Random) -> str:
    """A link-local address (169.254.0.0/16), the range cloud metadata lives in.

    The well-known metadata address itself is deliberately never emitted.
    """
    for _ in range(16):
        candidate = f"169.254.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        if candidate != "169.254.169.254":
            return candidate
    return "169.254.42.7"


def random_cgnat_ipv4(rng: random.Random) -> str:
    return f"100.{rng.randint(64, 127)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def random_unique_local_ipv6(rng: random.Random) -> str:
    groups = ":".join(f"{rng.randint(0, 0xFFFF):x}" for _ in range(3))
    return f"fd{rng.randint(0, 255):02x}:{groups}::{rng.randint(1, 0xFFFF):x}"


def to_decimal_notation(address: str) -> str:
    return str(int(ipaddress.IPv4Address(address)))


def to_hex_notation(address: str, dotted: bool = False) -> str:
    if dotted:
        return ".".join(f"0x{int(part):02x}" for part in address.split("."))
    return f"0x{int(ipaddress.IPv4Address(address)):08x}"


def to_octal_notation(address: str, padded: bool = True) -> str:
    """``127.0.0.1`` -> ``0177.0000.0000.0001`` (or the unpadded ``0177.00.00.01``)."""
    parts = []
    for part in address.split("."):
        value = int(part)
        parts.append(f"{value:04o}" if padded else f"0{value:o}")
    return ".".join(parts)


def to_short_notation(address: str) -> str:
    """``127.0.0.1`` -> ``127.1``: drop zero middle octets (inet_aton form)."""
    octets = address.split(".")
    if octets[1] == "0" and octets[2] == "0":
        return f"{octets[0]}.{octets[3]}"
    if octets[2] == "0":
        return f"{octets[0]}.{octets[1]}.{octets[3]}"
    return f"{octets[0]}.{int(octets[1]) * 65536 + int(octets[2]) * 256 + int(octets[3])}"


FULLWIDTH_DIGITS = str.maketrans("0123456789.", "０１２３４５６７８９．")


def to_fullwidth(text: str) -> str:
    """Render digits as fullwidth characters -- an IDNA/NFKC normalisation trick."""
    return text.translate(FULLWIDTH_DIGITS)
