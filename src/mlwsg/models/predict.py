"""Loading trained models and scoring live requests.

This is the module Phase 2's gateway imports.  It hides the one awkward detail
of the model zoo: the supervised pipelines expose ``predict_proba`` and treat
``1`` as SSRF, while the Isolation Forest exposes ``decision_function`` and
treats *low* scores as anomalous.  :class:`SSRFDetector` normalises both onto a
single ``Prediction``.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
from sklearn.pipeline import Pipeline

from mlwsg.config import LABEL_BENIGN, LABEL_SSRF, MODEL_DIR
from mlwsg.features import FEATURE_NAMES, extract_features
from mlwsg.schema import RequestRecord, coerce_record

DEFAULT_MODEL = "random_forest"


@dataclass
class Prediction:
    """A single scoring decision."""

    label: str
    is_ssrf: bool
    score: float
    model: str
    latency_ms: float
    #: Raw model output: the SSRF probability, or the Isolation Forest's
    #: ``decision_function`` value (negative means more anomalous).
    raw_score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "is_ssrf": self.is_ssrf,
            "score": round(self.score, 6),
            "raw_score": round(self.raw_score, 6),
            "model": self.model,
            "latency_ms": round(self.latency_ms, 4),
            "reasons": self.reasons,
        }


def available_models(model_dir: Path | str = MODEL_DIR) -> list[str]:
    """Names of the trained models present in *model_dir*."""
    directory = Path(model_dir)
    if not directory.exists():
        return []
    return sorted(path.stem for path in directory.glob("*.joblib"))


def load_manifest(model_dir: Path | str = MODEL_DIR) -> dict[str, Any]:
    """Read the training manifest, or return ``{}`` when it is absent."""
    path = Path(model_dir) / "manifest.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


#: Features whose presence is worth surfacing to a human reviewer, mapped to a
#: plain-English reason.  Phase 3's agent consumes these alongside the score.
_REASON_FEATURES: tuple[tuple[str, str], ...] = (
    ("dest_is_loopback", "destination is a loopback address"),
    ("dest_is_private", "destination is in a private (RFC1918) range"),
    ("dest_is_link_local", "destination is link-local (instance-metadata range)"),
    ("dest_is_unique_local", "destination is an IPv6 unique-local address"),
    ("dest_is_shared_cgnat", "destination is in shared/CGNAT space"),
    ("dest_is_multicast_or_unspecified", "destination is unspecified or multicast"),
    ("host_is_localhost_name", "host resolves to the local machine"),
    ("host_has_internal_suffix", "host uses an internal-only DNS suffix"),
    ("host_is_simulated_metadata", "host is the simulated metadata service"),
    ("host_embeds_ip", "hostname embeds an IP literal (wildcard-DNS bypass)"),
    ("host_notation_decimal", "host written in decimal IP notation"),
    ("host_notation_hex", "host written in hexadecimal IP notation"),
    ("host_notation_octal", "host written in octal IP notation"),
    ("host_notation_short", "host written in abbreviated inet_aton notation"),
    ("host_notation_ipv4_mapped", "host is an IPv4-mapped IPv6 literal"),
    ("scheme_is_dangerous", "non-HTTP scheme (file/gopher/dict/ftp)"),
    ("embedded_scheme_is_dangerous", "non-HTTP scheme nested in a parameter or body"),
    ("is_double_encoded", "URL is double percent-encoded"),
    ("userinfo_looks_like_host", "a hostname is hidden in the userinfo slot"),
    ("has_backslash", "backslashes used in the authority"),
    ("has_control_chars", "control characters embedded in the URL"),
    ("port_is_sensitive_internal", "port belongs to an internal-only service"),
    ("redirect_param_target_is_internal", "a URL parameter points at an internal host"),
    ("redirect_target_is_internal", "the redirect target is internal"),
    ("body_target_is_internal", "the request body contains an internal URL"),
)


def explain_request(record: Any, limit: int = 6) -> list[str]:
    """Human-readable reasons a request looks like SSRF.

    Derived from the feature vector rather than from the model, so the same
    explanation is available for every model -- including the unsupervised one.
    """
    values = extract_features(record)
    reasons = [text for name, text in _REASON_FEATURES if values.get(name)]
    return reasons[:limit]


class SSRFDetector:
    """Load a trained pipeline and score requests with it.

    Example:
        >>> detector = SSRFDetector.load("random_forest")     # doctest: +SKIP
        >>> detector.predict("http://169.254.42.7/metadata/v1/credentials").label
        'ssrf'
    """

    def __init__(
        self,
        pipeline: Pipeline,
        model_name: str,
        anomaly_threshold: float | None = None,
        manifest: dict[str, Any] | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.model_name = model_name
        self.manifest = manifest or {}
        self.is_anomaly_model = not hasattr(pipeline, "predict_proba")
        self.anomaly_threshold = (
            anomaly_threshold
            if anomaly_threshold is not None
            else float(self.manifest.get("anomaly_threshold", 0.0))
        )

    # -- construction -------------------------------------------------------
    @classmethod
    def load(
        cls, model_name: str = DEFAULT_MODEL, model_dir: Path | str = MODEL_DIR
    ) -> "SSRFDetector":
        """Load ``<model_dir>/<model_name>.joblib`` and its manifest."""
        directory = Path(model_dir)
        path = directory / f"{model_name}.joblib"
        if not path.exists():
            present = available_models(directory)
            raise FileNotFoundError(
                f"no trained model at {path}. Available: {present or 'none'}. "
                "Run `python -m mlwsg train` first."
            )
        manifest = load_manifest(directory)
        pipeline = joblib.load(path)
        _assert_feature_compatibility(pipeline, manifest)
        return cls(pipeline=pipeline, model_name=model_name, manifest=manifest)

    # -- scoring ------------------------------------------------------------
    def predict(self, record: Any, with_reasons: bool = True) -> Prediction:
        """Score one request end to end (feature extraction included)."""
        started = time.perf_counter()
        request: RequestRecord = coerce_record(record)
        payload = [request.to_dict()]

        if self.is_anomaly_model:
            raw = float(self.pipeline.decision_function(payload)[0])
            is_ssrf = raw < self.anomaly_threshold
            score = _anomaly_to_score(raw, self.anomaly_threshold)
        else:
            raw = float(self.pipeline.predict_proba(payload)[0, 1])
            is_ssrf = raw >= 0.5
            score = raw

        latency_ms = (time.perf_counter() - started) * 1000.0
        return Prediction(
            label=LABEL_SSRF if is_ssrf else LABEL_BENIGN,
            is_ssrf=bool(is_ssrf),
            score=score,
            model=self.model_name,
            latency_ms=latency_ms,
            raw_score=raw,
            reasons=explain_request(request) if with_reasons else [],
        )

    def predict_batch(self, records: Sequence[Any], with_reasons: bool = False) -> list[Prediction]:
        """Score many requests in one pass -- much faster than a loop."""
        requests = [coerce_record(record) for record in records]
        if not requests:
            return []
        payload = [request.to_dict() for request in requests]

        started = time.perf_counter()
        if self.is_anomaly_model:
            raw_scores = np.asarray(self.pipeline.decision_function(payload), dtype=float)
            flags = raw_scores < self.anomaly_threshold
            scores = np.array([_anomaly_to_score(r, self.anomaly_threshold) for r in raw_scores])
        else:
            raw_scores = np.asarray(self.pipeline.predict_proba(payload)[:, 1], dtype=float)
            flags = raw_scores >= 0.5
            scores = raw_scores
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        per_request = elapsed_ms / len(requests)

        return [
            Prediction(
                label=LABEL_SSRF if bool(flag) else LABEL_BENIGN,
                is_ssrf=bool(flag),
                score=float(score),
                model=self.model_name,
                latency_ms=per_request,
                raw_score=float(raw),
                reasons=explain_request(request) if with_reasons else [],
            )
            for request, flag, score, raw in zip(requests, flags, scores, raw_scores)
        ]

    def feature_names(self) -> tuple[str, ...]:
        return FEATURE_NAMES

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"SSRFDetector(model={self.model_name!r}, anomaly={self.is_anomaly_model})"


def _anomaly_to_score(raw: float, threshold: float) -> float:
    """Squash an Isolation Forest margin into a monotone 0-1 pseudo-probability.

    This is *not* a calibrated probability -- it exists so anomaly output can be
    ranked and thresholded alongside the supervised scores.
    """
    return 1.0 / (1.0 + math.exp(min(60.0, max(-60.0, (raw - threshold) * 20.0))))


def _feature_version_of(pipeline: Pipeline) -> str | None:
    step = getattr(pipeline, "named_steps", {}).get("features")
    return getattr(step, "version", None)


def _assert_feature_compatibility(pipeline: Pipeline, manifest: dict[str, Any]) -> None:
    """Refuse to serve predictions from a model built on a different feature set."""
    expected = manifest.get("feature_version")
    actual = _feature_version_of(pipeline)
    if expected and actual and expected != actual:
        raise RuntimeError(
            f"model was trained with feature version {actual!r} but the manifest "
            f"declares {expected!r}; retrain with `python -m mlwsg train`"
        )
    n_expected = manifest.get("n_features")
    if n_expected and n_expected != len(FEATURE_NAMES):
        raise RuntimeError(
            f"model expects {n_expected} features but the installed extractor "
            f"produces {len(FEATURE_NAMES)}; retrain with `python -m mlwsg train`"
        )


def load_all_detectors(model_dir: Path | str = MODEL_DIR) -> dict[str, SSRFDetector]:
    """Load every trained model found in *model_dir*."""
    return {name: SSRFDetector.load(name, model_dir) for name in available_models(model_dir)}
