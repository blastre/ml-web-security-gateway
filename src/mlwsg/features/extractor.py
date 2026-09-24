"""Security feature engineering for SSRF detection.

The extractor turns a :class:`~mlwsg.schema.RequestRecord` into a fixed-length
vector of numeric features.  Three ideas drive the feature set:

1. **Where does this request point?**  The host is parsed in every notation a
   HTTP client accepts and classified as loopback / private / link-local /
   public (see :mod:`mlwsg.net.addresses`).
2. **How hard is it trying to hide that?**  Percent-decoding rounds, userinfo
   abuse, backslashes and dangerous schemes are recorded as features in their
   own right -- obfuscation is signal, not noise.
3. **Where else could it end up?**  Redirect parameters, URLs embedded in the
   query string and observed ``Location`` headers each contribute their own
   destination classification, because the final hop is what matters.

The same code path runs at training time and at prediction time: the extractor
is a scikit-learn transformer, so it is serialised *inside* each model pipeline
and cannot drift away from the model it was fitted with.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from mlwsg.features.normalize import (
    DANGEROUS_SCHEMES,
    FETCH_PATH_MARKERS,
    NormalizedURL,
    extract_urls_from_text,
    normalize_url,
)
from mlwsg.net.addresses import (
    AddressInfo,
    CATEGORY_LINK_LOCAL,
    CATEGORY_LOOPBACK,
    CATEGORY_MULTICAST,
    CATEGORY_PRIVATE,
    CATEGORY_PUBLIC,
    CATEGORY_RESERVED,
    CATEGORY_SHARED,
    CATEGORY_UNIQUE_LOCAL,
    CATEGORY_UNSPECIFIED,
    LOCALHOST_NAMES,
    SENSITIVE_INTERNAL_PORTS,
    SIMULATED_METADATA_HOSTS,
    STANDARD_WEB_PORTS,
    classify_host,
    hostname_is_internal,
)
from mlwsg.schema import RequestRecord, coerce_record

#: Bumped whenever the feature set changes, so a stale model artifact can be
#: detected instead of silently producing garbage predictions.
FEATURE_VERSION = "1.0.0"

#: Canonical feature order.  Model artifacts are only valid for this exact
#: sequence; :func:`extract_features` is asserted against it by the test suite.
FEATURE_NAMES: tuple[str, ...] = (
    # --- URL shape -------------------------------------------------------
    "url_length",
    "url_decoded_length",
    "url_decode_shrinkage",
    "host_length",
    "path_length",
    "query_length",
    "path_depth",
    "num_query_params",
    "url_digit_ratio",
    "url_special_ratio",
    "url_entropy",
    # --- Scheme ----------------------------------------------------------
    "scheme_missing",
    "scheme_is_http",
    "scheme_is_https",
    "scheme_is_dangerous",
    # --- Host notation ---------------------------------------------------
    "host_is_ip_literal",
    "host_ip_is_ipv4",
    "host_ip_is_ipv6",
    "host_notation_dotted_quad",
    "host_notation_decimal",
    "host_notation_hex",
    "host_notation_octal",
    "host_notation_short",
    "host_notation_ipv4_mapped",
    "host_is_punycode",
    "host_had_unicode",
    "host_trailing_dot",
    "host_label_count",
    "host_max_label_length",
    "host_digit_ratio",
    "host_hyphen_count",
    "host_embeds_ip",
    # --- Destination classification --------------------------------------
    "dest_is_loopback",
    "dest_is_private",
    "dest_is_link_local",
    "dest_is_unique_local",
    "dest_is_shared_cgnat",
    "dest_is_multicast_or_unspecified",
    "dest_is_reserved",
    "dest_is_public",
    "dest_is_internal",
    "host_is_localhost_name",
    "host_has_internal_suffix",
    "host_is_simulated_metadata",
    "any_destination_internal",
    "internal_destination_count",
    # --- Port ------------------------------------------------------------
    "port_present",
    "port_log_value",
    "port_is_standard_web",
    "port_is_sensitive_internal",
    "port_malformed",
    # --- Encoding / obfuscation ------------------------------------------
    "percent_sequence_count",
    "decode_rounds",
    "is_double_encoded",
    "has_encoded_dot",
    "has_encoded_slash",
    "has_encoded_colon",
    "has_userinfo",
    "userinfo_looks_like_host",
    "has_backslash",
    "has_whitespace",
    "has_control_chars",
    "has_fragment",
    "parse_failed",
    # --- Embedded URLs and redirects --------------------------------------
    "embedded_url_count",
    "embedded_scheme_is_dangerous",
    "has_redirect_param",
    "redirect_param_target_is_internal",
    "redirect_param_target_is_ip",
    "path_has_fetch_marker",
    "redirect_observed",
    "redirect_hops",
    "redirect_target_is_internal",
    "redirect_target_is_ip",
    "redirect_changes_host",
    # --- Request level -----------------------------------------------------
    "method_is_get",
    "method_is_post",
    "method_is_other",
    "has_body",
    "body_contains_url",
    "body_target_is_internal",
)

N_FEATURES = len(FEATURE_NAMES)

_SPECIAL_CHARS = set("%@:/?#&=+~!$'()*,;[]\\<>\"{}|^`")
_ENCODED_MARKERS = {
    "has_encoded_dot": ("%2e", "%252e"),
    "has_encoded_slash": ("%2f", "%252f", "%5c"),
    "has_encoded_colon": ("%3a", "%253a"),
}


def _entropy(text: str) -> float:
    """Shannon entropy of *text* in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def _destination_infos(normalized: NormalizedURL, extra: Sequence[str]) -> list[AddressInfo]:
    """Classify every host this request could reach."""
    infos: list[AddressInfo] = []
    seen: set[str] = set()
    candidates: list[str] = []
    if normalized.host:
        candidates.append(normalized.host)
    for url in normalized.embedded_urls:
        candidates.append(normalize_url(url).host)
    for _, value in normalized.destination_params:
        candidates.append(normalize_url(value).host)
    candidates.extend(extra)

    for host in candidates:
        if not host or host in seen:
            continue
        seen.add(host)
        infos.append(classify_host(host))
    return infos


def extract_features(record: Any) -> dict[str, float]:
    """Extract the full feature dictionary for one request.

    Accepts a :class:`~mlwsg.schema.RequestRecord`, a mapping with the same
    keys, or a bare URL string.  The returned dictionary always has exactly the
    keys in :data:`FEATURE_NAMES`, in that order.
    """
    request: RequestRecord = coerce_record(record)
    url = request.url or ""
    normalized = normalize_url(url)
    lowered = url.lower()

    host_info = classify_host(normalized.host) if normalized.host else classify_host("")
    category = host_info.category

    # --- redirect-related destinations ------------------------------------
    redirect_norm = normalize_url(request.redirect_location) if request.redirect_location else None
    redirect_info = classify_host(redirect_norm.host) if redirect_norm and redirect_norm.host else None

    # Bodies are free text (JSON, form-encoded, XML): pull every URL out of
    # them rather than trying to parse the whole payload as one URL.
    body = request.body or ""
    body_urls = extract_urls_from_text(body)
    body_normalized = [normalize_url(candidate) for candidate in body_urls]
    body_infos = [classify_host(item.host) for item in body_normalized if item.host]

    extra_hosts = [info.host for info in ([redirect_info] if redirect_info else [])]
    extra_hosts.extend(info.host for info in body_infos)
    destinations = _destination_infos(normalized, extra_hosts)
    internal_destinations = [info for info in destinations if info.is_internal]

    redirect_param_normalized = [normalize_url(value) for _, value in normalized.destination_params]
    redirect_param_infos = [
        classify_host(item.host) for item in redirect_param_normalized if item.host
    ]

    # A dangerous scheme (file://, gopher://, dict://) is just as serious when it
    # is nested inside a parameter or a body as when it is the outer URL.
    nested = [normalize_url(candidate) for candidate in normalized.embedded_urls]
    nested.extend(redirect_param_normalized)
    nested.extend(body_normalized)
    nested_dangerous = any(item.scheme in DANGEROUS_SCHEMES for item in nested)

    path = normalized.path or ""
    host = normalized.host or ""
    method = (request.method or "GET").upper()

    features: dict[str, float] = {}

    # --- URL shape ---------------------------------------------------------
    features["url_length"] = float(len(url))
    features["url_decoded_length"] = float(len(normalized.decoded))
    features["url_decode_shrinkage"] = float(len(url) - len(normalized.decoded))
    features["host_length"] = float(len(host))
    features["path_length"] = float(len(path))
    features["query_length"] = float(len(normalized.query))
    features["path_depth"] = float(len([seg for seg in path.split("/") if seg]))
    features["num_query_params"] = float(len(normalized.params))
    features["url_digit_ratio"] = _ratio(sum(ch.isdigit() for ch in url), len(url))
    features["url_special_ratio"] = _ratio(sum(ch in _SPECIAL_CHARS for ch in url), len(url))
    features["url_entropy"] = _entropy(url)

    # --- Scheme ------------------------------------------------------------
    features["scheme_missing"] = float(not normalized.scheme_present)
    features["scheme_is_http"] = float(normalized.scheme == "http" and normalized.scheme_present)
    features["scheme_is_https"] = float(normalized.scheme == "https")
    features["scheme_is_dangerous"] = float(normalized.scheme_is_dangerous)

    # --- Host notation -----------------------------------------------------
    notation = host_info.notation
    features["host_is_ip_literal"] = float(host_info.is_ip_literal)
    features["host_ip_is_ipv4"] = float(host_info.family == "ipv4")
    features["host_ip_is_ipv6"] = float(host_info.family == "ipv6")
    features["host_notation_dotted_quad"] = float(notation == "dotted_quad")
    features["host_notation_decimal"] = float(notation == "decimal")
    features["host_notation_hex"] = float(notation == "hex")
    features["host_notation_octal"] = float(notation == "octal")
    features["host_notation_short"] = float(notation == "short")
    features["host_notation_ipv4_mapped"] = float(notation == "ipv4_mapped_ipv6")
    features["host_is_punycode"] = float("xn--" in host)
    features["host_had_unicode"] = float(any(ord(ch) > 127 for ch in normalized.host_raw))
    features["host_trailing_dot"] = float(normalized.had_trailing_dot)
    labels = [label for label in host.split(".") if label]
    features["host_label_count"] = float(len(labels))
    features["host_max_label_length"] = float(max((len(label) for label in labels), default=0))
    features["host_digit_ratio"] = _ratio(sum(ch.isdigit() for ch in host), len(host))
    features["host_hyphen_count"] = float(host.count("-"))
    features["host_embeds_ip"] = float(host_info.embeds_ip and not host_info.is_ip_literal)

    # --- Destination classification ----------------------------------------
    features["dest_is_loopback"] = float(category == CATEGORY_LOOPBACK)
    features["dest_is_private"] = float(category == CATEGORY_PRIVATE)
    features["dest_is_link_local"] = float(category == CATEGORY_LINK_LOCAL)
    features["dest_is_unique_local"] = float(category == CATEGORY_UNIQUE_LOCAL)
    features["dest_is_shared_cgnat"] = float(category == CATEGORY_SHARED)
    features["dest_is_multicast_or_unspecified"] = float(
        category in (CATEGORY_MULTICAST, CATEGORY_UNSPECIFIED)
    )
    features["dest_is_reserved"] = float(category == CATEGORY_RESERVED)
    features["dest_is_public"] = float(category == CATEGORY_PUBLIC)
    features["dest_is_internal"] = float(host_info.is_internal)
    features["host_is_localhost_name"] = float(host in LOCALHOST_NAMES)
    features["host_has_internal_suffix"] = float(
        hostname_is_internal(host) and host not in LOCALHOST_NAMES
    )
    features["host_is_simulated_metadata"] = float(host in SIMULATED_METADATA_HOSTS)
    features["any_destination_internal"] = float(bool(internal_destinations))
    features["internal_destination_count"] = float(len(internal_destinations))

    # --- Port ---------------------------------------------------------------
    port = normalized.port
    features["port_present"] = float(port is not None)
    features["port_log_value"] = float(math.log1p(port)) if port is not None else 0.0
    features["port_is_standard_web"] = float(port in STANDARD_WEB_PORTS) if port is not None else 0.0
    features["port_is_sensitive_internal"] = (
        float(port in SENSITIVE_INTERNAL_PORTS) if port is not None else 0.0
    )
    features["port_malformed"] = float(normalized.port_malformed)

    # --- Encoding / obfuscation ---------------------------------------------
    features["percent_sequence_count"] = float(normalized.percent_sequences)
    features["decode_rounds"] = float(normalized.decode_rounds)
    features["is_double_encoded"] = float(normalized.decode_rounds >= 2)
    for name, markers in _ENCODED_MARKERS.items():
        features[name] = float(any(marker in lowered for marker in markers))
    features["has_userinfo"] = float(bool(normalized.userinfo))
    features["userinfo_looks_like_host"] = float(normalized.userinfo_looks_like_host)
    features["has_backslash"] = float(normalized.had_backslash)
    features["has_whitespace"] = float(normalized.had_whitespace)
    features["has_control_chars"] = float(normalized.had_control_chars)
    features["has_fragment"] = float(bool(normalized.fragment))
    features["parse_failed"] = float(not normalized.parse_ok)

    # --- Embedded URLs and redirects -----------------------------------------
    features["embedded_url_count"] = float(len(normalized.embedded_urls))
    features["embedded_scheme_is_dangerous"] = float(nested_dangerous)
    features["has_redirect_param"] = float(bool(normalized.redirect_params))
    features["redirect_param_target_is_internal"] = float(
        any(info.is_internal for info in redirect_param_infos)
    )
    features["redirect_param_target_is_ip"] = float(
        any(info.is_ip_literal for info in redirect_param_infos)
    )
    features["path_has_fetch_marker"] = float(
        any(marker in path.lower() for marker in FETCH_PATH_MARKERS)
    )
    features["redirect_observed"] = float(bool(request.redirect_location))
    features["redirect_hops"] = float(request.redirect_hops or 0)
    features["redirect_target_is_internal"] = float(
        redirect_info.is_internal if redirect_info else False
    )
    features["redirect_target_is_ip"] = float(
        redirect_info.is_ip_literal if redirect_info else False
    )
    features["redirect_changes_host"] = float(
        bool(redirect_info) and redirect_info.host != host
    )

    # --- Request level --------------------------------------------------------
    features["method_is_get"] = float(method == "GET")
    features["method_is_post"] = float(method == "POST")
    features["method_is_other"] = float(method not in ("GET", "POST"))
    features["has_body"] = float(bool(body))
    features["body_contains_url"] = float(bool(body_urls))
    features["body_target_is_internal"] = float(any(info.is_internal for info in body_infos))

    # Guarantee the canonical order regardless of assignment order above.
    return {name: features[name] for name in FEATURE_NAMES}


def extract_feature_vector(record: Any) -> np.ndarray:
    """Feature vector for a single request, in :data:`FEATURE_NAMES` order."""
    values = extract_features(record)
    return np.fromiter((values[name] for name in FEATURE_NAMES), dtype=np.float64, count=N_FEATURES)


class RequestFeatureExtractor(BaseEstimator, TransformerMixin):
    """scikit-learn transformer wrapping :func:`extract_features`.

    Placed as the first step of every model pipeline so that a saved artifact
    carries its own preprocessing: Phase 2 loads one ``.joblib`` file and can
    score a raw request without re-implementing any of this.

    The transformer is **stateless** -- ``fit`` learns nothing.  That matters
    twice over: it rules out train/test leakage through the features, and it
    lets cross-validation reuse one pre-computed feature matrix instead of
    re-extracting per fold.
    """

    def __init__(self, version: str = FEATURE_VERSION) -> None:
        self.version = version

    # -- scikit-learn API --------------------------------------------------
    def fit(self, X: Iterable[Any], y: Any = None) -> "RequestFeatureExtractor":  # noqa: N803, ARG002
        self.n_features_in_ = N_FEATURES
        self.feature_names_in_ = np.asarray(FEATURE_NAMES, dtype=object)
        return self

    def transform(self, X: Iterable[Any]) -> np.ndarray:  # noqa: N803
        records = _iter_records(X)
        matrix = np.zeros((len(records), N_FEATURES), dtype=np.float64)
        for row, record in enumerate(records):
            values = extract_features(record)
            for col, name in enumerate(FEATURE_NAMES):
                matrix[row, col] = values[name]
        return matrix

    def fit_transform(self, X: Iterable[Any], y: Any = None) -> np.ndarray:  # noqa: N803
        return self.fit(X, y).transform(X)

    def get_feature_names_out(self, input_features: Any = None) -> np.ndarray:  # noqa: ARG002
        return np.asarray(FEATURE_NAMES, dtype=object)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"RequestFeatureExtractor(version={self.version!r})"


def _iter_records(X: Any) -> list[Any]:  # noqa: N803
    """Normalise the many shapes of ``X`` into a list of record-like objects."""
    # pandas DataFrame -> list of row dicts (duck-typed to avoid a hard import).
    if hasattr(X, "to_dict") and hasattr(X, "columns"):
        return X.to_dict(orient="records")
    if isinstance(X, (str, Mapping, RequestRecord)):
        return [X]
    return list(X)


def feature_frame(records: Iterable[Any]):
    """Return a ``pandas.DataFrame`` of features -- handy for notebooks/reports."""
    import pandas as pd

    rows = [extract_features(record) for record in _iter_records(records)]
    return pd.DataFrame(rows, columns=list(FEATURE_NAMES))
