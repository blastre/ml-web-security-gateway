"""Dataset generation: reproducibility, coverage and label integrity."""

from __future__ import annotations

from collections import Counter

import pytest

from mlwsg.config import LABEL_BENIGN, LABEL_SSRF
from mlwsg.dataset import (
    FAMILIES,
    STATICALLY_UNDETECTABLE_FAMILIES,
    benign_families,
    generate_dataset,
    ssrf_families,
    write_dataset,
)
from mlwsg.dataset.generator import load_dataset
from mlwsg.features import extract_features
from mlwsg.schema import DATASET_COLUMNS

#: Features any statically detectable SSRF sample must trigger at least one of.
INTERNAL_INDICATORS = (
    "any_destination_internal",
    "scheme_is_dangerous",
    "embedded_scheme_is_dangerous",
    "redirect_target_is_internal",
    "body_target_is_internal",
)


@pytest.fixture(scope="module")
def samples():
    return generate_dataset(n_samples=1500, seed=99, min_per_family=12)


def test_generation_is_reproducible():
    first = generate_dataset(n_samples=400, seed=123, min_per_family=5)
    second = generate_dataset(n_samples=400, seed=123, min_per_family=5)
    assert [s.to_row() for s in first] == [s.to_row() for s in second]


def test_different_seeds_produce_different_data():
    first = generate_dataset(n_samples=400, seed=1, min_per_family=5)
    second = generate_dataset(n_samples=400, seed=2, min_per_family=5)
    assert [s.record.url for s in first] != [s.record.url for s in second]


def test_requested_size_is_produced(samples):
    assert len(samples) == 1500


def test_only_known_labels_are_used(samples):
    assert {s.label for s in samples} == {LABEL_BENIGN, LABEL_SSRF}


def test_benign_ratio_is_respected(samples):
    counts = Counter(s.label for s in samples)
    assert counts[LABEL_BENIGN] / len(samples) == pytest.approx(0.6, abs=0.02)


def test_every_family_is_represented(samples):
    produced = {s.family for s in samples}
    assert produced == {family.name for family in FAMILIES}


def test_families_are_split_between_the_two_labels():
    assert len(benign_families()) >= 15
    assert len(ssrf_families()) >= 20
    assert not {f.name for f in benign_families()} & {f.name for f in ssrf_families()}


def test_no_duplicate_requests(samples):
    keys = [
        (s.record.method, s.record.url, s.record.body, s.record.redirect_location)
        for s in samples
    ]
    assert len(keys) == len(set(keys))


def test_family_labels_agree_with_sample_labels(samples):
    by_name = {family.name: family.label for family in FAMILIES}
    assert all(by_name[s.family] == s.label for s in samples)


def test_no_benign_sample_points_at_an_internal_host(samples):
    """A benign request may *mention* an internal address; it must never target one."""
    offenders = [
        s.record.url
        for s in samples
        if s.label == LABEL_BENIGN and extract_features(s.record)["dest_is_internal"]
    ]
    assert offenders == []


def test_detectable_ssrf_samples_carry_an_internal_indicator(samples):
    """Every SSRF sample must be detectable, unless its family is documented as not."""
    offenders = [
        (s.family, s.record.url)
        for s in samples
        if s.label == LABEL_SSRF
        and s.family not in STATICALLY_UNDETECTABLE_FAMILIES
        and not any(extract_features(s.record)[name] for name in INTERNAL_INDICATORS)
    ]
    assert offenders == []


def test_the_dataset_contains_genuinely_ambiguous_hard_negatives(samples):
    """Benign traffic that carries a real internal URL, so the task is non-trivial."""
    ambiguous = [
        s for s in samples
        if s.label == LABEL_BENIGN and extract_features(s.record)["any_destination_internal"]
    ]
    assert len(ambiguous) >= 20
    assert {s.family for s in ambiguous} <= {"benign_internal_url_as_text", "benign_dev_referrer"}


def test_no_real_cloud_metadata_endpoint_appears(samples):
    """The project simulates metadata access; it never references the real address."""
    assert not any("169.254.169.254" in s.record.url for s in samples)


def test_urls_are_non_empty(samples):
    assert all(s.record.url.strip() for s in samples)


def test_ssrf_families_cover_the_expected_techniques():
    names = {family.name for family in ssrf_families()}
    for technique in (
        "ssrf_loopback_direct", "ssrf_private_network", "ssrf_link_local_metadata",
        "ssrf_decimal_ip", "ssrf_hex_ip", "ssrf_octal_ip", "ssrf_short_ip",
        "ssrf_ipv6_loopback", "ssrf_percent_encoded", "ssrf_double_encoded",
        "ssrf_userinfo_confusion", "ssrf_dns_embedded_ip", "ssrf_open_redirect_param",
        "ssrf_redirect_chain", "ssrf_alt_scheme", "ssrf_internal_hostname",
        "ssrf_internal_port_probe", "ssrf_unicode_obfuscation", "ssrf_body_payload",
    ):
        assert technique in names


def test_invalid_arguments_are_rejected():
    with pytest.raises(ValueError):
        generate_dataset(n_samples=0)
    with pytest.raises(ValueError):
        generate_dataset(n_samples=10, benign_ratio=1.5)


def test_written_csv_round_trips(tmp_path, samples):
    csv_path = tmp_path / "dataset.csv"
    metadata_path = tmp_path / "metadata.json"
    write_dataset(samples, csv_path=csv_path, metadata_path=metadata_path, seed=99)

    assert csv_path.exists() and metadata_path.exists()
    frame = load_dataset(csv_path)
    assert list(frame.columns) == list(DATASET_COLUMNS)
    assert len(frame) == len(samples)
    assert frame["redirect_hops"].dtype.kind == "i"

    import json

    metadata = json.loads(metadata_path.read_text())
    assert metadata["n_samples"] == len(samples)
    assert metadata["seed"] == 99
    assert metadata["csv_sha256"]
    assert sum(metadata["family_counts"].values()) == len(samples)


def test_loading_a_missing_dataset_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="generate-dataset"):
        load_dataset(tmp_path / "nope.csv")
