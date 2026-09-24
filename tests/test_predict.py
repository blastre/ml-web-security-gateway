"""Inference: loading artifacts and scoring live requests."""

from __future__ import annotations

from pathlib import Path

import pytest

from mlwsg.config import LABEL_BENIGN, LABEL_SSRF
from mlwsg.models.predict import (
    Prediction,
    SSRFDetector,
    available_models,
    explain_request,
    load_all_detectors,
    load_manifest,
)
from mlwsg.models.train import SUPERVISED_MODELS
from mlwsg.schema import RequestRecord

pytestmark = pytest.mark.slow

#: Unambiguous attacks: every supervised model is expected to catch these.
SSRF_CASES = [
    "http://127.0.0.1:8080/admin",
    "http://localhost/internal/api/keys",
    "http://10.0.0.5:6379/",
    "http://169.254.42.7/metadata/v1/credentials",
    "http://metadata.sim.local/metadata/v1/instance",
    "http://2130706433/admin",
    "http://0x7f000001/admin",
    "http://0177.0.0.1/admin",
    "http://127.1/admin",
    "http://[::1]:8080/admin",
    "http://trusted.example.com@127.0.0.1/admin",
    "http://127.0.0.1.rebind.test/admin",
    "file:///etc/passwd",
    "http://%31%32%37%2e%30%2e%30%2e%31/admin",
    "https://app.example.com/fetch?url=http%3A%2F%2F192.168.1.10%2Fadmin",
]

#: Unambiguous legitimate traffic: none of it may be blocked.
BENIGN_CASES = [
    "https://cdn.example.com/static/js/bundle.js?v=42",
    "https://api.acmeworks.io/v2/orders?page=12&limit=50",
    "https://shop.example.org/search?q=annual%20report%202024",
    "https://files.example.net:8443/downloads/report.pdf",
    "https://app.example.com/preview?url=https%3A%2F%2Fblog.example.org%2Fpost%2F1",
]


@pytest.fixture(scope="module", params=list(SUPERVISED_MODELS))
def detector(request, model_dir: Path) -> SSRFDetector:
    return SSRFDetector.load(request.param, model_dir)


def test_available_models_lists_the_artifacts(model_dir: Path):
    assert set(available_models(model_dir)) >= set(SUPERVISED_MODELS)


def test_available_models_is_empty_for_a_missing_directory(tmp_path: Path):
    assert available_models(tmp_path / "absent") == []


def test_manifest_is_loaded_alongside_the_model(model_dir: Path):
    assert load_manifest(model_dir)["phase"] == 1


def test_missing_model_raises_a_helpful_error(tmp_path: Path):
    with pytest.raises(FileNotFoundError, match="mlwsg train"):
        SSRFDetector.load("random_forest", tmp_path)


@pytest.mark.parametrize("url", SSRF_CASES)
def test_clear_attacks_are_blocked(detector: SSRFDetector, url: str):
    prediction = detector.predict(url)
    assert prediction.label == LABEL_SSRF, f"{detector.model_name} missed {url}"
    assert prediction.is_ssrf
    assert prediction.score >= 0.5


@pytest.mark.parametrize("url", BENIGN_CASES)
def test_legitimate_traffic_is_allowed(detector: SSRFDetector, url: str):
    prediction = detector.predict(url)
    assert prediction.label == LABEL_BENIGN, f"{detector.model_name} blocked {url}"
    assert not prediction.is_ssrf


def test_prediction_carries_timing_and_provenance(detector: SSRFDetector):
    prediction = detector.predict("http://127.0.0.1/admin")
    assert isinstance(prediction, Prediction)
    assert prediction.model == detector.model_name
    assert prediction.latency_ms > 0
    assert 0.0 <= prediction.score <= 1.0


def test_prediction_serialises_to_json_friendly_types(detector: SSRFDetector):
    payload = detector.predict("http://10.0.0.5/").to_dict()
    assert payload["label"] in (LABEL_BENIGN, LABEL_SSRF)
    assert isinstance(payload["is_ssrf"], bool)
    assert isinstance(payload["reasons"], list)


def test_redirect_context_changes_the_decision(detector: SSRFDetector):
    """The same entry URL is benign or malicious depending on where it lands."""
    url = "https://short.example.com/r/abc123"
    benign = detector.predict(
        RequestRecord(url=url, redirect_location="https://blog.example.org/post/1", redirect_hops=1)
    )
    malicious = detector.predict(
        RequestRecord(url=url, redirect_location="http://169.254.42.7/meta", redirect_hops=1)
    )
    assert malicious.score > benign.score


def test_body_borne_ssrf_is_detected(detector: SSRFDetector):
    prediction = detector.predict(
        RequestRecord(
            url="https://api.example.com/v1/webhooks",
            method="POST",
            body='{"callback_url":"http://192.168.1.10/admin"}',
        )
    )
    assert prediction.label == LABEL_SSRF


def test_batch_prediction_agrees_with_single_prediction(detector: SSRFDetector):
    urls = SSRF_CASES[:5] + BENIGN_CASES[:3]
    batch = detector.predict_batch(urls)
    assert len(batch) == len(urls)
    for url, batched in zip(urls, batch):
        assert batched.label == detector.predict(url).label


def test_batch_prediction_handles_an_empty_input(detector: SSRFDetector):
    assert detector.predict_batch([]) == []


def test_detector_accepts_strings_dicts_and_records(detector: SSRFDetector):
    for request in (
        "http://127.0.0.1/admin",
        {"url": "http://127.0.0.1/admin", "method": "GET"},
        RequestRecord(url="http://127.0.0.1/admin"),
    ):
        assert detector.predict(request).label == LABEL_SSRF


def test_isolation_forest_loads_and_scores(model_dir: Path):
    detector = SSRFDetector.load("isolation_forest", model_dir)
    assert detector.is_anomaly_model
    prediction = detector.predict("http://127.0.0.1:6379/")
    assert prediction.model == "isolation_forest"
    assert 0.0 <= prediction.score <= 1.0


def test_isolation_forest_scores_attacks_as_more_anomalous(model_dir: Path):
    detector = SSRFDetector.load("isolation_forest", model_dir)
    attack = detector.predict("http://169.254.42.7/metadata/v1/credentials")
    benign = detector.predict("https://cdn.example.com/static/js/bundle.js")
    assert attack.raw_score < benign.raw_score


def test_load_all_detectors_returns_every_model(model_dir: Path):
    detectors = load_all_detectors(model_dir)
    assert set(detectors) == set(available_models(model_dir))


def test_explanations_name_the_indicators_that_fired():
    reasons = explain_request("http://0x7f000001:6379/admin")
    assert any("loopback" in reason for reason in reasons)
    assert any("hexadecimal" in reason for reason in reasons)
    assert explain_request("https://cdn.example.com/static/app.js") == []


def test_explanations_are_capped(detector: SSRFDetector):
    assert len(explain_request("http://trusted.example.com@0177.0.0.1:22/admin", limit=3)) <= 3
