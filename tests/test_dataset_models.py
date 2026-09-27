import csv
from collections import defaultdict
from urllib.parse import parse_qs, urlsplit

import joblib
import pytest

from mlwsg.catalogue import load
from mlwsg.dataset import generate
from mlwsg.models import FEATURE_NAMES, predict_url, train, url_features


def _rows(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_generation_is_reproducible_and_held_out_by_family(tmp_path):
    first, second, changed = (tmp_path / name for name in ("a.csv", "b.csv", "c.csv"))
    summary = generate(first, n_per_family=8, seed=73)
    generate(second, n_per_family=8, seed=73)
    generate(changed, n_per_family=8, seed=74)
    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes() != changed.read_bytes()

    rows = _rows(first)
    assert summary["rows"] == len(rows) == 8 * (len(load().attacks) + summary["benign_families"])
    assert len({row["url"] for row in rows}) == len(rows)
    family_splits = defaultdict(set)
    labels = defaultdict(set)
    for row in rows:
        family_splits[row["family"]].add(row["split"])
        labels[row["split"]].add(row["label"])
        assert row["label"] == ("0" if row["family"].startswith("benign:") else "1")
    assert all(len(splits) == 1 for splits in family_splits.values())
    assert labels == {"train": {"0", "1"}, "test": {"0", "1"}}
    assert {attack.id for attack in load().attacks} <= family_splits.keys()
    address_splits = defaultdict(set)
    for attack in load().attacks:
        if attack.resolves_to is not None:
            address_splits[str(attack.resolves_to)].update(family_splits[attack.id])
    assert all(len(splits) == 1 for splits in address_splits.values())


def test_variants_preserve_catalogue_targets_and_redirect_destination(tmp_path):
    path = tmp_path / "examples.csv"
    generate(path, n_per_family=12)
    by_family = defaultdict(set)
    for row in _rows(path):
        by_family[row["family"]].add(row["url"])
    for attack in load().attacks:
        variants = by_family[attack.id]
        assert len(variants) == 12
        assert attack.payload in variants
        base = urlsplit(attack.payload)
        for variant in variants:
            parts = urlsplit(variant)
            assert parts.scheme == base.scheme
            assert parts.netloc == base.netloc
            assert parts.path == base.path
            if attack.vector == "redirect":
                assert parse_qs(parts.query)["to"] == parse_qs(base.query)["to"]


def test_training_artifact_metrics_and_prediction_are_reproducible(tmp_path):
    data = tmp_path / "examples.csv"
    generate(data, n_per_family=6, seed=55)
    first, second = tmp_path / "first.joblib", tmp_path / "second.joblib"
    report = train(data, first)
    assert train(data, second)["classifiers"] == report["classifiers"]
    artifact = joblib.load(first)
    assert tuple(artifact["feature_names"]) == FEATURE_NAMES
    assert set(report["classifiers"]) == {
        "logistic_regression",
        "random_forest",
        "isolation_forest",
    }
    rows = _rows(data)
    for name, metrics in report["classifiers"].items():
        assert sum(map(sum, metrics["confusion_matrix"])) == report["split"]["test"]["rows"]
        assert all(0 <= metrics[key] <= 1 for key in ("precision", "recall", "f1", "fpr")), name
    assert sum(report["split"][side]["rows"] for side in ("train", "test")) == len(rows)
    score = predict_url("http://127.1:6379/", first)
    assert 0 <= score <= 1
    assert score == pytest.approx(
        artifact["logistic_regression"].predict_proba([url_features("http://127.1:6379/")])[0, 1]
    )


def test_features_do_not_embed_literal_target_address_and_reject_leaky_splits(tmp_path):
    assert url_features("http://10.10.0.10/admin") == url_features("http://10.20.0.20/admin")
    path = tmp_path / "leaky.csv"
    path.write_text(
        "url,label,family,split\n"
        "https://example.com/,0,shared,train\n"
        "http://10.10.0.10/,1,attack,train\n"
        "https://example.net/,0,shared,test\n"
        "http://10.20.0.20/,1,other,test\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="both splits"):
        train(path, tmp_path / "not-created.joblib")
    assert not (tmp_path / "not-created.joblib").exists()


def test_training_rejects_single_class_split(tmp_path):
    path = tmp_path / "single-class.csv"
    path.write_text(
        "url,label,family,split\n"
        "https://example.com/,0,benign-a,train\n"
        "https://example.net/,0,benign-b,test\n"
        "http://10.10.0.10/,1,attack-a,test\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="both train and test"):
        train(path, tmp_path / "not-created.joblib")
