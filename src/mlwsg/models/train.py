"""Training for the three Phase 1 detectors.

Three models, deliberately chosen to span the space:

``logistic_regression``
    A linear, fully interpretable baseline.  Its coefficients read directly as
    "how much does this feature push a request towards SSRF", which is what a
    security reviewer wants from a blocking decision.

``random_forest``
    A tree ensemble that captures the feature *interactions* the linear model
    cannot -- notably "an internal URL appears somewhere" AND "it sits in a
    fetch parameter on a fetch endpoint", the combination that separates a real
    SSRF attempt from a bug report that quotes ``http://127.0.0.1:8080/``.

``isolation_forest``
    Unsupervised anomaly detection, fitted on **benign traffic only**.  It is
    the answer to the obvious objection against the supervised models: they can
    only recognise attack families someone thought to put in the training set.
    The Isolation Forest never sees an attack during training, so it stands in
    for the novel bypass that Phase 2 will still have to survive.

Every model is stored as a complete scikit-learn ``Pipeline`` whose first step
is the feature extractor, so a Phase 2 gateway loads one file and scores a raw
request -- no preprocessing code to keep in sync.
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from mlwsg.config import (
    DATASET_PATH,
    LABEL_BENIGN,
    LABEL_TO_INT,
    MODEL_DIR,
    RANDOM_SEED,
    ensure_directories,
    to_project_relative,
)
from mlwsg.dataset.generator import load_dataset
from mlwsg.features import FEATURE_NAMES, FEATURE_VERSION, RequestFeatureExtractor

#: Canonical model names; also the artifact file stems.
MODEL_NAMES = ("logistic_regression", "random_forest", "isolation_forest")

#: Models that learn from labels (the Isolation Forest does not).
SUPERVISED_MODELS = ("logistic_regression", "random_forest")

SPLIT_PATH = MODEL_DIR / "split.json"


@dataclass
class TrainConfig:
    """Everything that determines the outcome of a training run."""

    dataset_path: Path = DATASET_PATH
    model_dir: Path = MODEL_DIR
    test_size: float = 0.3
    #: Share of the *training* set held out to tune the anomaly threshold.
    validation_size: float = 0.2
    seed: int = RANDOM_SEED

    logreg_max_iter: int = 2000
    logreg_c: float = 1.0
    # 100 trees measured identical in F1 to 300 on this dataset (0.9803) while
    # cutting single-request latency from ~6.5 ms to ~2.5 ms. On an inline
    # gateway that difference is the whole budget, so the smaller forest wins.
    forest_estimators: int = 100
    forest_max_depth: int | None = None
    forest_min_samples_leaf: int = 1
    isolation_estimators: int = 200
    isolation_contamination: float = 0.05

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["dataset_path"] = to_project_relative(self.dataset_path)
        payload["model_dir"] = to_project_relative(self.model_dir)
        return payload


@dataclass
class TrainingResult:
    """Fitted pipelines plus the exact data split they were produced from."""

    pipelines: dict[str, Pipeline]
    train_frame: pd.DataFrame
    test_frame: pd.DataFrame
    y_train: np.ndarray
    y_test: np.ndarray
    anomaly_threshold: float
    config: TrainConfig
    manifest: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Data handling
# ---------------------------------------------------------------------------


def labels_to_int(frame: pd.DataFrame) -> np.ndarray:
    """Map the ``label`` column onto ``{benign: 0, ssrf: 1}``."""
    return frame["label"].map(LABEL_TO_INT).to_numpy(dtype=int)


def make_split(frame: pd.DataFrame, config: TrainConfig) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stratified train/test split, reproducible from ``config.seed``.

    Stratifying on ``family`` rather than on ``label`` keeps every attack
    technique and every benign pattern represented on both sides, so the
    per-family breakdown in the evaluation report is meaningful.
    """
    stratify = frame["family"]
    # A family with a single member cannot be stratified; fall back to labels.
    if stratify.value_counts().min() < 2:
        stratify = frame["label"]
    train_frame, test_frame = train_test_split(
        frame,
        test_size=config.test_size,
        random_state=config.seed,
        stratify=stratify,
        shuffle=True,
    )
    return train_frame.reset_index(drop=True), test_frame.reset_index(drop=True)


def save_split(train_frame: pd.DataFrame, test_frame: pd.DataFrame, path: Path = SPLIT_PATH) -> None:
    """Record which samples went where, so evaluation cannot drift from training."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "train_ids": train_frame["id"].tolist(),
        "test_ids": test_frame["id"].tolist(),
        "n_train": int(len(train_frame)),
        "n_test": int(len(test_frame)),
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def load_split(frame: pd.DataFrame, path: Path = SPLIT_PATH) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Reconstruct the saved split against *frame*, keyed by sample id."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    indexed = frame.set_index("id", drop=False)
    train_ids = [i for i in payload["train_ids"] if i in indexed.index]
    test_ids = [i for i in payload["test_ids"] if i in indexed.index]
    return (
        indexed.loc[train_ids].reset_index(drop=True),
        indexed.loc[test_ids].reset_index(drop=True),
    )


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


def build_pipeline(name: str, config: TrainConfig) -> Pipeline:
    """Construct an untrained pipeline for *name*."""
    extractor = RequestFeatureExtractor()

    if name == "logistic_regression":
        return Pipeline(
            [
                ("features", extractor),
                ("scale", StandardScaler()),
                (
                    "clf",
                    LogisticRegression(
                        C=config.logreg_c,
                        max_iter=config.logreg_max_iter,
                        class_weight="balanced",
                        solver="lbfgs",
                        random_state=config.seed,
                    ),
                ),
            ]
        )

    if name == "random_forest":
        # No scaler: trees are scale-invariant, and unscaled features keep the
        # reported importances readable.
        return Pipeline(
            [
                ("features", extractor),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=config.forest_estimators,
                        max_depth=config.forest_max_depth,
                        min_samples_leaf=config.forest_min_samples_leaf,
                        class_weight="balanced_subsample",
                        n_jobs=-1,
                        random_state=config.seed,
                    ),
                ),
            ]
        )

    if name == "isolation_forest":
        return Pipeline(
            [
                ("features", extractor),
                ("scale", StandardScaler()),
                (
                    "clf",
                    IsolationForest(
                        n_estimators=config.isolation_estimators,
                        contamination=config.isolation_contamination,
                        n_jobs=-1,
                        random_state=config.seed,
                    ),
                ),
            ]
        )

    raise ValueError(f"unknown model {name!r}; expected one of {MODEL_NAMES}")


def records_for(frame: pd.DataFrame) -> list[dict[str, Any]]:
    """Frame rows as plain dicts, the input the extractor expects."""
    columns = ["url", "method", "body", "redirect_location", "redirect_hops"]
    return frame[columns].to_dict(orient="records")


# ---------------------------------------------------------------------------
# Isolation Forest threshold tuning
# ---------------------------------------------------------------------------


def tune_anomaly_threshold(
    pipeline: Pipeline, frame: pd.DataFrame, y_true: np.ndarray
) -> tuple[float, float]:
    """Pick the ``decision_function`` cut-off that maximises F1 on *frame*.

    The Isolation Forest's built-in ``contamination`` cut-off is a guess about
    how much of the data is anomalous, which is not the same question as "where
    should this gateway block".  The threshold is tuned on a validation split
    carved out of the **training** data -- never on the test set.

    Returns ``(threshold, f1)``.  Scores below the threshold are anomalies.
    """
    scores = pipeline.decision_function(records_for(frame))
    best_threshold = float(np.median(scores))
    best_f1 = -1.0
    for candidate in np.quantile(scores, np.linspace(0.01, 0.99, 99)):
        predicted = (scores < candidate).astype(int)
        tp = int(np.sum((predicted == 1) & (y_true == 1)))
        fp = int(np.sum((predicted == 1) & (y_true == 0)))
        fn = int(np.sum((predicted == 0) & (y_true == 1)))
        denominator = 2 * tp + fp + fn
        f1 = (2 * tp / denominator) if denominator else 0.0
        if f1 > best_f1:
            best_f1, best_threshold = f1, float(candidate)
    return best_threshold, best_f1


# ---------------------------------------------------------------------------
# Training entry point
# ---------------------------------------------------------------------------


def train_models(config: TrainConfig | None = None, verbose: bool = True) -> TrainingResult:
    """Train all three models and persist them to ``config.model_dir``."""
    config = config or TrainConfig()
    ensure_directories()
    model_dir = Path(config.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    frame = load_dataset(config.dataset_path)
    train_frame, test_frame = make_split(frame, config)
    y_train = labels_to_int(train_frame)
    y_test = labels_to_int(test_frame)
    save_split(train_frame, test_frame, model_dir / "split.json")

    train_records = records_for(train_frame)
    if verbose:
        print(
            f"dataset {config.dataset_path} -> {len(frame)} rows "
            f"({len(train_frame)} train / {len(test_frame)} test)"
        )

    pipelines: dict[str, Pipeline] = {}

    for name in SUPERVISED_MODELS:
        pipeline = build_pipeline(name, config)
        pipeline.fit(train_records, y_train)
        pipelines[name] = pipeline
        if verbose:
            print(f"  trained {name}")

    # --- Isolation Forest: benign-only fit, threshold tuned on validation ---
    fit_frame, validation_frame = train_test_split(
        train_frame,
        test_size=config.validation_size,
        random_state=config.seed,
        stratify=train_frame["label"],
        shuffle=True,
    )
    benign_fit = fit_frame[fit_frame["label"] == LABEL_BENIGN]
    isolation = build_pipeline("isolation_forest", config)
    isolation.fit(records_for(benign_fit))
    pipelines["isolation_forest"] = isolation
    threshold, validation_f1 = tune_anomaly_threshold(
        isolation, validation_frame, labels_to_int(validation_frame)
    )
    if verbose:
        print(
            f"  trained isolation_forest on {len(benign_fit)} benign samples "
            f"(threshold={threshold:.4f}, validation F1={validation_f1:.3f})"
        )

    # --- persist ------------------------------------------------------------
    # Training benefits from every core; *inference* does not. A gateway scores
    # one request at a time, where forking work across a thread pool costs far
    # more than the trees it parallelises -- measured at ~25 ms/request with
    # n_jobs=-1 versus well under 1 ms single-threaded. Pin the saved estimators
    # to one thread so the artifact is shaped for how Phase 2 will call it.
    for pipeline in pipelines.values():
        classifier = pipeline.named_steps.get("clf")
        if hasattr(classifier, "n_jobs"):
            classifier.n_jobs = 1

    for name, pipeline in pipelines.items():
        joblib.dump(pipeline, model_dir / f"{name}.joblib")

    dataset_digest = hashlib.sha256(Path(config.dataset_path).read_bytes()).hexdigest()
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "phase": 1,
        "models": list(pipelines),
        "supervised_models": list(SUPERVISED_MODELS),
        "positive_class": "ssrf",
        "label_encoding": LABEL_TO_INT,
        "feature_version": FEATURE_VERSION,
        "n_features": len(FEATURE_NAMES),
        "anomaly_threshold": threshold,
        "anomaly_validation_f1": validation_f1,
        "anomaly_training_samples": int(len(benign_fit)),
        "dataset_path": to_project_relative(config.dataset_path),
        "dataset_sha256": dataset_digest,
        "n_samples": int(len(frame)),
        "n_train": int(len(train_frame)),
        "n_test": int(len(test_frame)),
        "config": config.to_dict(),
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "joblib": joblib.__version__,
        },
    }
    (model_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (model_dir / "feature_metadata.json").write_text(
        json.dumps(
            {
                "feature_version": FEATURE_VERSION,
                "n_features": len(FEATURE_NAMES),
                "feature_names": list(FEATURE_NAMES),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if verbose:
        print(f"  artifacts written to {model_dir}")

    return TrainingResult(
        pipelines=pipelines,
        train_frame=train_frame,
        test_frame=test_frame,
        y_train=y_train,
        y_test=y_test,
        anomaly_threshold=threshold,
        config=config,
        manifest=manifest,
    )


def main() -> None:  # pragma: no cover - thin CLI shim
    train_models()


if __name__ == "__main__":  # pragma: no cover
    main()
