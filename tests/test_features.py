"""Feature extraction: stability of the contract and correctness of the signals."""

from __future__ import annotations

import numpy as np
import pytest

from mlwsg.features import FEATURE_NAMES, RequestFeatureExtractor, extract_features
from mlwsg.features.extractor import N_FEATURES, extract_feature_vector, feature_frame
from mlwsg.schema import RequestRecord


def test_feature_names_are_unique_and_complete():
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) == N_FEATURES


def test_extracted_keys_match_the_declared_order_exactly():
    """The saved models depend on this order; drift must fail loudly."""
    values = extract_features("https://example.com/")
    assert tuple(values) == FEATURE_NAMES


def test_every_feature_is_a_finite_number():
    values = extract_feature_vector("http://%31%32%37%2e%30%2e%30%2e%31:6379/admin")
    assert values.shape == (N_FEATURES,)
    assert np.all(np.isfinite(values))


@pytest.mark.parametrize(
    "url,flag",
    [
        ("http://127.0.0.1/admin", "dest_is_loopback"),
        ("http://10.0.0.5/admin", "dest_is_private"),
        ("http://169.254.42.7/meta", "dest_is_link_local"),
        ("http://100.64.1.1/", "dest_is_shared_cgnat"),
        ("http://0.0.0.0:8080/", "dest_is_multicast_or_unspecified"),
        ("http://localhost/admin", "host_is_localhost_name"),
        ("http://db.internal/", "host_has_internal_suffix"),
        ("http://metadata.sim.local/metadata/v1/instance", "host_is_simulated_metadata"),
        ("http://2130706433/", "host_notation_decimal"),
        ("http://0x7f000001/", "host_notation_hex"),
        ("http://0177.0.0.1/", "host_notation_octal"),
        ("http://127.1/", "host_notation_short"),
        ("http://[::ffff:127.0.0.1]/", "host_notation_ipv4_mapped"),
        ("http://127.0.0.1.rebind.test/", "host_embeds_ip"),
        ("file:///etc/passwd", "scheme_is_dangerous"),
        ("http://trusted.example.com@127.0.0.1/", "userinfo_looks_like_host"),
        ("http:\\\\127.0.0.1\\admin", "has_backslash"),
        ("http://127.0.0.1:22/", "port_is_sensitive_internal"),
        ("https://app.example.com/fetch?url=http://10.0.0.5/", "path_has_fetch_marker"),
    ],
)
def test_attack_indicators_fire(url, flag):
    assert extract_features(url)[flag] == 1.0


@pytest.mark.parametrize(
    "url",
    [
        "https://cdn.example.com/static/app.js?v=3",
        "https://api.acmeworks.io/v2/orders?page=12&limit=50",
        "https://shop.example.org/search?q=annual%20report%202024",
        "https://104.18.32.11/health",
        "https://files.example.net:8443/downloads/report.pdf",
    ],
)
def test_benign_urls_do_not_look_internal(url):
    values = extract_features(url)
    assert values["dest_is_internal"] == 0.0
    assert values["any_destination_internal"] == 0.0


def test_double_encoding_is_detected():
    url = "https://app.example.com/fetch?url=http%253A%252F%252F127.0.0.1%252Fadmin"
    values = extract_features(url)
    assert values["is_double_encoded"] == 1.0
    assert values["decode_rounds"] >= 2


def test_redirect_information_is_used():
    record = RequestRecord(
        url="https://short.example.com/r/abc123",
        redirect_location="http://169.254.42.7/metadata/v1/credentials",
        redirect_hops=2,
    )
    values = extract_features(record)
    assert values["redirect_observed"] == 1.0
    assert values["redirect_target_is_internal"] == 1.0
    assert values["redirect_changes_host"] == 1.0
    assert values["redirect_hops"] == 2.0


def test_internal_url_in_the_body_is_found():
    record = RequestRecord(
        url="https://api.example.com/v1/webhooks",
        method="POST",
        body='{"callback_url":"http://192.168.1.10/admin"}',
    )
    values = extract_features(record)
    assert values["body_contains_url"] == 1.0
    assert values["body_target_is_internal"] == 1.0


def test_nested_dangerous_scheme_is_detected():
    values = extract_features("https://app.example.com/import?url=file%3A%2F%2F%2Fetc%2Fpasswd")
    assert values["embedded_scheme_is_dangerous"] == 1.0


def test_free_text_mentioning_an_internal_url_is_not_a_fetch_parameter():
    """The hard-negative case: an internal URL quoted in a bug report."""
    values = extract_features(
        "https://tracker.example.com/issues/new?description=http%3A%2F%2F127.0.0.1%3A8080%2F%20refused"
    )
    assert values["any_destination_internal"] == 1.0   # it is present ...
    assert values["has_redirect_param"] == 0.0         # ... but not in a fetch parameter
    assert values["path_has_fetch_marker"] == 0.0


def test_method_is_one_hot_encoded():
    assert extract_features({"url": "https://example.com/", "method": "GET"})["method_is_get"] == 1.0
    assert extract_features({"url": "https://example.com/", "method": "POST"})["method_is_post"] == 1.0
    assert extract_features({"url": "https://example.com/", "method": "DELETE"})["method_is_other"] == 1.0


def test_extractor_accepts_strings_dicts_and_records():
    extractor = RequestFeatureExtractor()
    matrix = extractor.fit_transform(
        [
            "https://example.com/",
            {"url": "http://127.0.0.1/", "method": "POST"},
            RequestRecord(url="http://10.0.0.5/"),
        ]
    )
    assert matrix.shape == (3, N_FEATURES)


def test_extractor_accepts_a_dataframe():
    import pandas as pd

    frame = pd.DataFrame(
        [{"url": "https://example.com/", "method": "GET", "body": "",
          "redirect_location": "", "redirect_hops": 0}]
    )
    assert RequestFeatureExtractor().transform(frame).shape == (1, N_FEATURES)


def test_extractor_is_stateless_so_fit_changes_nothing():
    """CV and inference both rely on this: fitting must not alter the output."""
    extractor = RequestFeatureExtractor()
    urls = ["https://example.com/", "http://127.0.0.1/"]
    before = extractor.transform(urls)
    after = extractor.fit(urls).transform(urls)
    assert np.array_equal(before, after)


def test_get_feature_names_out_matches_the_contract():
    assert list(RequestFeatureExtractor().get_feature_names_out()) == list(FEATURE_NAMES)


def test_feature_frame_has_named_columns():
    frame = feature_frame(["https://example.com/", "http://127.0.0.1/"])
    assert list(frame.columns) == list(FEATURE_NAMES)
    assert len(frame) == 2


def test_malformed_input_does_not_raise():
    for url in ["", "http://", "://nonsense", "http://[unclosed", "%%%%", "http://:::::/"]:
        values = extract_features(url)
        assert len(values) == N_FEATURES
