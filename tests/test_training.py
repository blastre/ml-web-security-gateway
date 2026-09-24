"""Training: artifacts, split integrity and end-to-end model quality."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pytest

from mlwsg.config import LABEL_BENIGN
from mlwsg.dataset.generator import load_dataset
from mlwsg.features import FEATURE_NAMES
from mlwsg.models.evaluate import classification_metrics
from mlwsg.models.train import (
    MODEL_NAMES,
    SUPERVISED_MODELS,
    TrainConfig,
    build_pipeline,
    labels_to_int,
    load_split,
    make_split,
    records_for,
)

pytestmark = pytest.mark.slow


def test_all_three_models_are_trained(trained):
    assert set(trained.pipelines) == set(MODEL_NAMES)


def test_artifacts_are_written(model_dir: Path):
    for name in MODEL_NAMES:
        assert (model_dir / f"{name}.joblib").exists()
    for extra in ("manifest.json", "feature_metadata.json", "split.json"):
        assert (model_dir / extra).exists()


def test_manifest_records_what_is_needed_to_reproduce(model_dir: Path):
    manifest = json.loads((model_dir / "manifest.json").read_text())
    assert manifest["phase"] == 1
    assert manifest["positive_class"] == "ssrf"
    assert manifest["n_features"] == len(FEATURE_NAMES)
    assert manifest["dataset_sha256"]
    assert manifest["environment"]["scikit_learn"]
    assert manifest["config"]["seed"]


def test_feature_metadata_pins_the_feature_contract(model_dir: Path):
    metadata = json.loads((model_dir / "feature_metadata.json").read_text())
    assert metadata["feature_names"] == list(FEATURE_NAMES)
    assert metadata["n_features"] == len(FEATURE_NAMES)


def test_train_and_test_sets_do_not_overlap(trained):
    train_ids = set(trained.train_frame["id"])
    test_ids = set(trained.test_frame["id"])
    assert not train_ids & test_ids


def test_split_proportions_match_the_config(trained, train_config: TrainConfig):
    total = len(trained.train_frame) + len(trained.test_frame)
    assert len(trained.test_frame) / total == pytest.approx(train_config.test_size, abs=0.02)


def test_split_is_stratified_across_families(trained):
    train_families = set(trained.train_frame["family"])
    test_families = set(trained.test_frame["family"])
    assert test_families <= train_families


def test_split_is_reproducible(train_config: TrainConfig):
    frame = load_dataset(train_config.dataset_path)
    first_train, first_test = make_split(frame, train_config)
    second_train, second_test = make_split(frame, train_config)
    assert list(first_train["id"]) == list(second_train["id"])
    assert list(first_test["id"]) == list(second_test["id"])


def test_saved_split_can_be_reloaded(trained, model_dir: Path, train_config: TrainConfig):
    frame = load_dataset(train_config.dataset_path)
    train_frame, test_frame = load_split(frame, model_dir / "split.json")
    assert list(train_frame["id"]) == list(trained.train_frame["id"])
    assert list(test_frame["id"]) == list(trained.test_frame["id"])


@pytest.mark.parametrize("name", SUPERVISED_MODELS)
def test_supervised_models_are_accurate_on_held_out_data(trained, name):
    pipeline = trained.pipelines[name]
    scores = pipeline.predict_proba(records_for(trained.test_frame))[:, 1]
    metrics = classification_metrics(trained.y_test, (scores >= 0.5).astype(int), scores)
    assert metrics["f1"] > 0.90
    assert metrics["recall"] > 0.88
    # An inline gateway cannot afford to block much legitimate traffic.
    assert metrics["false_positive_rate"] < 0.05


def test_isolation_forest_separates_the_two_classes(trained):
    pipeline = trained.pipelines["isolation_forest"]
    scores = np.asarray(pipeline.decision_function(records_for(trained.test_frame)))
    benign_mean = scores[trained.y_test == 0].mean()
    ssrf_mean = scores[trained.y_test == 1].mean()
    # Lower decision_function means more anomalous.
    assert ssrf_mean < benign_mean


def test_isolation_forest_is_trained_only_on_benign_traffic(trained, model_dir: Path):
    manifest = json.loads((model_dir / "manifest.json").read_text())
    benign_in_train = int((trained.train_frame["label"] == LABEL_BENIGN).sum())
    assert 0 < manifest["anomaly_training_samples"] <= benign_in_train


def test_anomaly_threshold_is_tuned_without_touching_the_test_set(trained):
    assert trained.manifest["anomaly_validation_f1"] > 0.5
    assert trained.anomaly_threshold == trained.manifest["anomaly_threshold"]


def test_saved_pipelines_reload_and_predict_identically(trained, model_dir: Path):
    records = records_for(trained.test_frame.head(50))
    for name in SUPERVISED_MODELS:
        reloaded = joblib.load(model_dir / f"{name}.joblib")
        expected = trained.pipelines[name].predict_proba(records)[:, 1]
        assert np.allclose(reloaded.predict_proba(records)[:, 1], expected)


def test_saved_models_are_single_threaded_for_inference(model_dir: Path):
    """Inference is single-request; a thread pool costs more than it saves."""
    for name in MODEL_NAMES:
        classifier = joblib.load(model_dir / f"{name}.joblib").named_steps.get("clf")
        if hasattr(classifier, "n_jobs"):
            assert classifier.n_jobs == 1


def test_pipelines_carry_their_own_preprocessing(trained):
    """Phase 2 must be able to score a raw request from the artifact alone."""
    for name, pipeline in trained.pipelines.items():
        assert "features" in pipeline.named_steps
        score = (
            pipeline.predict_proba([{"url": "http://127.0.0.1/admin"}])[:, 1]
            if hasattr(pipeline, "predict_proba")
            else pipeline.decision_function([{"url": "http://127.0.0.1/admin"}])
        )
        assert np.isfinite(score).all()


def test_unknown_model_name_is_rejected(train_config: TrainConfig):
    with pytest.raises(ValueError, match="unknown model"):
        build_pipeline("gradient_boosting", train_config)


def test_labels_to_int_maps_ssrf_to_the_positive_class(trained):
    frame = trained.test_frame
    encoded = labels_to_int(frame)
    assert set(encoded) <= {0, 1}
    assert all(encoded[frame["label"] == "ssrf"] == 1)
