"""Network address primitives shared by the detector and the Phase 2 egress guard."""

from mlwsg.net.addresses import (
    AddressInfo,
    INTERNAL_CATEGORIES,
    INTERNAL_HOST_SUFFIXES,
    SENSITIVE_INTERNAL_PORTS,
    SIMULATED_METADATA_HOSTS,
    classify_host,
    classify_ip,
    embedded_ip_in_hostname,
    hostname_is_internal,
    normalize_host,
    parse_ip_literal,
)

__all__ = [
    "AddressInfo",
    "INTERNAL_CATEGORIES",
    "INTERNAL_HOST_SUFFIXES",
    "SENSITIVE_INTERNAL_PORTS",
    "SIMULATED_METADATA_HOSTS",
    "classify_host",
    "classify_ip",
    "embedded_ip_in_hostname",
    "hostname_is_internal",
    "normalize_host",
    "parse_ip_literal",
]
