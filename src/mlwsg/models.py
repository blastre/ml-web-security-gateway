"""Lexical URL baselines trained only on locally generated CSV examples.

No hostname lookup or HTTP request occurs here. Scores are research signals, not
an egress policy or a measure of generalisation to real-world traffic.
"""

import csv
import math
from functools import cache
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import unquote, urlsplit

import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

FEATURE_NAMES = (
    "scheme_http",
    "scheme_https",
    "scheme_other",
    "url_length",
    "host_length",
    "host_labels",
    "host_digit_fraction",
    "host_has_percent_encoding",
    "host_has_hex_label",
    "host_has_leading_zero_label",
    "host_is_numeric",
    "host_ipv4",
    "host_ipv6",
    "host_is_non_global_ip",
    "host_is_loopback_ip",
    "host_is_link_local_ip",
    "host_is_unspecified_ip",
    "host_is_mapped_ipv6",
    "host_is_single_label",
    "userinfo_present",
    "backslash_present",
    "explicit_port",
    "path_depth",
    "path_length",
    "path_percent_encoding",
    "query_present",
    "query_length",
    "query_has_url",
    "fragment_present",
)


def url_features(url: str) -> list[float]:
    """Extract host *shape*, never hostname/IP identity or destination addresses."""
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    decoded_host = unquote(host)
    try:
        literal = ip_address(decoded_host)
    except ValueError:
        literal = None
    labels = decoded_host.split(".") if decoded_host else []
    numeric = bool(labels) and all(
        part.isdigit() or part.lower().startswith("0x") for part in labels
    )
    mapped = getattr(literal, "ipv4_mapped", None)
    # Categories are deliberately coarse: neither octets nor host tokens enter
    # the vector, even when two catalogue techniques share a destination.
    return [
        float(parsed.scheme == "http"),
        float(parsed.scheme == "https"),
        float(parsed.scheme not in ("http", "https")),
        float(len(url)),
        float(len(host)),
        float(len(labels)),
        sum(char.isdigit() for char in host) / max(1, len(host)),
        float("%" in host),
        float(any(part.lower().startswith("0x") for part in labels)),
        float(any(len(part) > 1 and part[0] == "0" and part.isdigit() for part in labels)),
        float(numeric),
        float(literal is not None and literal.version == 4),
        float(literal is not None and literal.version == 6),
        float(literal is not None and not literal.is_global),
        float(literal is not None and literal.is_loopback),
        float(literal is not None and literal.is_link_local),
        float(literal is not None and literal.is_unspecified),
        float(mapped is not None),
        float(bool(host) and "." not in host and ":" not in host),
        float("@" in parsed.netloc),
        float("\\" in url),
        float(parsed.port is not None),
        float(len([segment for segment in parsed.path.split("/") if segment])),
        float(len(parsed.path)),
        float("%" in parsed.path),
        float(bool(parsed.query)),
        float(len(parsed.query)),
        float("http://" in parsed.query.lower() or "https://" in parsed.query.lower()),
        float(bool(parsed.fragment)),
    ]


def _metrics(expected: list[int], predicted: list[int]) -> dict:
    tn, fp, fn, tp = confusion_matrix(expected, predicted, labels=[0, 1]).ravel()
    precision, recall, f1, _ = precision_recall_fscore_support(
        expected, predicted, average="binary", zero_division=0
    )
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fp / (tn + fp)) if tn + fp else 0.0,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def train(dataset_path: str | Path, output_path: str | Path) -> dict:
    """Fit three reproducible baselines, evaluate grouped holdout, persist artifact."""
    with Path(dataset_path).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not {"url", "label", "family", "split"} <= set(reader.fieldnames or ()):
            raise ValueError("dataset must contain url,label,family,split columns")
        rows = list(reader)

    groups: dict[str, str] = {}
    samples: dict[str, list[tuple[list[float], int]]] = {"train": [], "test": []}
    techniques: list[str] = []  # train-split technique label per row, for the multi-class model
    counts: dict[str, dict[str, int]] = {
        "train": {"benign": 0, "attack": 0},
        "test": {"benign": 0, "attack": 0},
    }
    for row in rows:
        split, family, label = row["split"], row["family"], row["label"]
        if split not in samples or label not in ("0", "1") or not family:
            raise ValueError("each row requires a family, binary label and train/test split")
        if family in groups and groups[family] != split:
            raise ValueError(f"family {family!r} appears in both splits")
        groups[family] = split
        target = int(label)
        samples[split].append((url_features(row["url"]), target))
        if split == "train":
            techniques.append(family if target else "benign")
        counts[split]["attack" if target else "benign"] += 1
    if any(0 in counts[split].values() for split in samples):
        raise ValueError("both train and test splits must contain attack and benign examples")

    train_x, train_y = map(list, zip(*samples["train"], strict=True))
    test_x, test_y = map(list, zip(*samples["test"], strict=True))
    logistic = make_pipeline(
        StandardScaler(), LogisticRegression(max_iter=1000, random_state=20240501)
    )
    forest = RandomForestClassifier(n_estimators=100, random_state=20240501, n_jobs=1)
    isolation = IsolationForest(n_estimators=100, contamination=0.1, random_state=20240501)
    logistic.fit(train_x, train_y)
    forest.fit(train_x, train_y)
    isolation.fit([features for features, label in samples["train"] if label == 0])
    # Multi-class head for the agent's top-k technique predictions. It only knows
    # train-split techniques; held-out families are "zero-day" for it by design.
    technique_forest = RandomForestClassifier(n_estimators=100, random_state=20240501, n_jobs=1)
    technique_forest.fit(train_x, techniques)
    classifiers = {
        "logistic_regression": _metrics(test_y, logistic.predict(test_x)),
        "random_forest": _metrics(test_y, forest.predict(test_x)),
        "isolation_forest": _metrics(
            test_y, [int(prediction == -1) for prediction in isolation.predict(test_x)]
        ),
    }
    split_stats = {
        split: {
            "rows": len(samples[split]),
            "families": sum(side == split for side in groups.values()),
            **counts[split],
        }
        for split in samples
    }
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "feature_names": FEATURE_NAMES,
            "logistic_regression": logistic,
            "random_forest": forest,
            "isolation_forest": isolation,
            "technique_forest": technique_forest,
            "classifiers": classifiers,
            "split": split_stats,
        },
        destination,
    )
    return {"path": str(destination), "classifiers": classifiers, "split": split_stats}


@cache
def load_artifact(path: str) -> dict:
    artifact = joblib.load(path)
    if tuple(artifact["feature_names"]) != FEATURE_NAMES:
        raise ValueError("model features do not match this version")
    return artifact


def predict_url(url: str, model_path: str | Path) -> float:
    """Return the logistic-regression attack probability from a trusted artifact."""
    model = load_artifact(str(model_path))["logistic_regression"]
    return float(model.predict_proba([url_features(url)])[0, 1])


CLASSIFIERS = ("logistic_regression", "random_forest", "isolation_forest", "technique_forest")


def classify(url: str, model_path: str | Path, name: str, k: int = 3) -> list[tuple[str, float]]:
    """Top-k (label, confidence) from one classifier, as IDS-Agent's classification tool.

    Binary models return ``ssrf``/``benign``. The isolation forest has no probability, so
    its anomaly margin is squashed into [0, 1]. The technique forest returns catalogue IDs.
    """
    if name not in CLASSIFIERS:
        raise ValueError(f"unknown classifier: {name}")
    artifact = load_artifact(str(model_path))
    if name not in artifact:
        raise ValueError(f"{name} missing from model artifact; rerun uv run mlwsg train")
    features = [url_features(url)]
    model = artifact[name]
    if name == "isolation_forest":
        margin = float(model.decision_function(features)[0])
        anomaly = 1 / (1 + math.exp(12 * margin))
        ranked = [("ssrf", anomaly), ("benign", 1 - anomaly)]
    elif name == "technique_forest":
        ranked = list(zip(model.classes_, model.predict_proba(features)[0], strict=True))
    else:
        attack = float(model.predict_proba(features)[0, 1])
        ranked = [("ssrf", attack), ("benign", 1 - attack)]
    ranked.sort(key=lambda pair: -pair[1])
    return [(str(label), round(float(score), 4)) for label, score in ranked[:k]]
