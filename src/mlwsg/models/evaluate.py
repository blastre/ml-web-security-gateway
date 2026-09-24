"""Evaluation: metrics, cross-validation, latency and the written report.

The report answers four questions a security team would actually ask:

1. **How often does it block real traffic?**  False Positive Rate is reported
   next to precision/recall/F1, because on an inline gateway a 1% FPR is an
   outage, not a rounding error.
2. **Which attacks slip through?**  Recall is broken down per attack family, so
   "98% recall" cannot hide a technique that is missed every single time.
3. **Can it run inline?**  End-to-end latency (feature extraction *plus*
   inference) is measured per request, single-sample, the way a gateway calls it.
4. **Does it generalise?**  Stratified 5-fold cross-validation on the training
   split, reported as mean +/- standard deviation.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    matthews_corrcoef,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from mlwsg.config import (
    EVALUATION_JSON_PATH,
    EVALUATION_REPORT_PATH,
    LABEL_BENIGN,
    LABEL_SSRF,
    MODEL_DIR,
    ensure_directories,
    from_project_relative,
    to_project_relative,
)
from mlwsg.dataset.generator import load_dataset
from mlwsg.features import FEATURE_NAMES, RequestFeatureExtractor
from mlwsg.models.predict import available_models, load_manifest
from mlwsg.models.train import (
    SUPERVISED_MODELS,
    TrainConfig,
    build_pipeline,
    labels_to_int,
    load_split,
    make_split,
    records_for,
)

import joblib


@dataclass
class ModelEvaluation:
    """Everything measured about one model."""

    name: str
    metrics: dict[str, float]
    confusion: dict[str, int]
    latency: dict[str, float]
    per_family: dict[str, dict[str, float]]
    extra: dict[str, Any]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def classification_metrics(
    y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None
) -> dict[str, float]:
    """Precision, recall, F1, FPR and friends for the SSRF-positive class."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    metrics = {
        "accuracy": float((tp + tn) / max(1, tp + tn + fp + fn)),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        # False Positive Rate: share of benign traffic this model would block.
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "specificity": float(tn / (tn + fp)) if (tn + fp) else 0.0,
        "mcc": float(matthews_corrcoef(y_true, y_pred)) if len(set(y_true)) > 1 else 0.0,
    }
    if y_score is not None and len(set(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
        metrics["pr_auc"] = float(average_precision_score(y_true, y_score))
    return metrics


def confusion_dict(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, int]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def per_family_breakdown(
    frame: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray
) -> dict[str, dict[str, float]]:
    """Detection rate per attack family, false-positive rate per benign family."""
    breakdown: dict[str, dict[str, float]] = {}
    for family, group in frame.groupby("family", sort=True):
        index = group.index.to_numpy()
        truth = y_true[index]
        predicted = y_pred[index]
        label = LABEL_SSRF if truth[0] == 1 else LABEL_BENIGN
        if label == LABEL_SSRF:
            rate = float(np.mean(predicted == 1))
            breakdown[family] = {
                "label": label,
                "n": int(len(index)),
                "detection_rate": rate,
                "missed": int(np.sum(predicted == 0)),
            }
        else:
            rate = float(np.mean(predicted == 1))
            breakdown[family] = {
                "label": label,
                "n": int(len(index)),
                "false_positive_rate": rate,
                "false_positives": int(np.sum(predicted == 1)),
            }
    return breakdown


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------


def measure_latency(
    pipeline: Pipeline,
    records: Sequence[dict],
    is_anomaly: bool,
    n_requests: int = 300,
    warmup: int = 25,
) -> dict[str, float]:
    """Per-request latency, measured the way an inline gateway would see it.

    Each measurement covers the whole path -- URL parsing, feature extraction
    and model inference -- for a *single* request, because a gateway cannot
    batch.  Batch throughput is reported separately as an upper bound.
    """
    sample = list(records[:n_requests]) or list(records)
    score = pipeline.decision_function if is_anomaly else pipeline.predict_proba

    for record in sample[:warmup]:
        score([record])

    timings: list[float] = []
    for record in sample:
        started = time.perf_counter()
        score([record])
        timings.append((time.perf_counter() - started) * 1000.0)

    batch_started = time.perf_counter()
    score(sample)
    batch_ms = (time.perf_counter() - batch_started) * 1000.0

    values = np.asarray(timings, dtype=float)
    return {
        "n_requests": int(len(values)),
        "mean_ms": float(values.mean()),
        "median_ms": float(np.median(values)),
        "p95_ms": float(np.percentile(values, 95)),
        "p99_ms": float(np.percentile(values, 99)),
        "max_ms": float(values.max()),
        "batch_per_request_ms": float(batch_ms / max(1, len(sample))),
        "throughput_rps_single": float(1000.0 / values.mean()) if values.mean() else 0.0,
    }


# ---------------------------------------------------------------------------
# Cross-validation
# ---------------------------------------------------------------------------


def cross_validate_supervised(
    train_frame: pd.DataFrame, config: TrainConfig, folds: int = 5
) -> dict[str, dict[str, float]]:
    """Stratified k-fold CV for the supervised models.

    The feature extractor is stateless, so features are computed once and the
    folds only refit the classifier (and the scaler, which *is* stateful).
    This is mathematically identical to cross-validating the whole pipeline and
    roughly ``folds`` times cheaper.
    """
    extractor = RequestFeatureExtractor()
    X = extractor.transform(records_for(train_frame))
    y = labels_to_int(train_frame)

    splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=config.seed)
    results: dict[str, dict[str, float]] = {}

    for name in SUPERVISED_MODELS:
        template = build_pipeline(name, config)
        scores: dict[str, list[float]] = {"precision": [], "recall": [], "f1": [], "false_positive_rate": []}
        for train_index, test_index in splitter.split(X, y):
            steps = [(step_name, step) for step_name, step in template.steps if step_name != "features"]
            model = Pipeline([(n, _fresh(s)) for n, s in steps])
            model.fit(X[train_index], y[train_index])
            predicted = model.predict(X[test_index])
            fold = classification_metrics(y[test_index], predicted)
            for key in scores:
                scores[key].append(fold[key])
        results[name] = {
            f"{key}_{stat}": float(value)
            for key, series in scores.items()
            for stat, value in (("mean", np.mean(series)), ("std", np.std(series)))
        }
        results[name]["folds"] = folds
    return results


def _fresh(step):
    """A clean, unfitted copy of a pipeline step."""
    from sklearn.base import clone

    return clone(step) if not isinstance(step, StandardScaler) else StandardScaler()


# ---------------------------------------------------------------------------
# Feature attribution
# ---------------------------------------------------------------------------


def feature_attribution(pipelines: dict[str, Pipeline], top_k: int = 15) -> dict[str, Any]:
    """Top features by Random Forest importance and Logistic Regression weight."""
    attribution: dict[str, Any] = {}

    forest = pipelines.get("random_forest")
    if forest is not None:
        importances = forest.named_steps["clf"].feature_importances_
        order = np.argsort(importances)[::-1][:top_k]
        attribution["random_forest_importances"] = [
            {"feature": FEATURE_NAMES[i], "importance": float(importances[i])} for i in order
        ]

    logistic = pipelines.get("logistic_regression")
    if logistic is not None:
        coefficients = logistic.named_steps["clf"].coef_[0]
        order = np.argsort(np.abs(coefficients))[::-1][:top_k]
        attribution["logistic_regression_coefficients"] = [
            {
                "feature": FEATURE_NAMES[i],
                "coefficient": float(coefficients[i]),
                "direction": "ssrf" if coefficients[i] > 0 else "benign",
            }
            for i in order
        ]
    return attribution


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def evaluate_models(
    model_dir: Path | str = MODEL_DIR,
    dataset_path: Path | str | None = None,
    config: TrainConfig | None = None,
    run_cross_validation: bool = True,
    latency_requests: int = 300,
    verbose: bool = True,
) -> dict[str, Any]:
    """Evaluate every trained model and return a structured result dictionary."""
    model_dir = Path(model_dir)
    manifest = load_manifest(model_dir)
    config = config or TrainConfig(**_config_from_manifest(manifest))
    dataset_path = from_project_relative(
        dataset_path or manifest.get("dataset_path") or config.dataset_path
    )

    frame = load_dataset(dataset_path)
    split_file = model_dir / "split.json"
    if split_file.exists():
        train_frame, test_frame = load_split(frame, split_file)
    else:  # pragma: no cover - only when artifacts are hand-assembled
        train_frame, test_frame = make_split(frame, config)

    y_test = labels_to_int(test_frame)
    test_records = records_for(test_frame)

    names = [name for name in available_models(model_dir)]
    if not names:
        raise FileNotFoundError(f"no trained models in {model_dir}; run `python -m mlwsg train`")

    pipelines = {name: joblib.load(model_dir / f"{name}.joblib") for name in names}
    evaluations: dict[str, ModelEvaluation] = {}

    for name, pipeline in pipelines.items():
        is_anomaly = not hasattr(pipeline, "predict_proba")
        extra: dict[str, Any] = {"is_anomaly_model": is_anomaly}

        if is_anomaly:
            raw = np.asarray(pipeline.decision_function(test_records), dtype=float)
            threshold = float(manifest.get("anomaly_threshold", 0.0))
            y_pred = (raw < threshold).astype(int)
            # Higher = more anomalous = more SSRF-like, for AUC purposes.
            y_score = -raw
            default_pred = (np.asarray(pipeline.predict(test_records)) == -1).astype(int)
            extra.update(
                {
                    "tuned_threshold": threshold,
                    "threshold_tuned_on": "validation split of the training data",
                    "default_contamination_metrics": classification_metrics(y_test, default_pred),
                    "default_contamination_confusion": confusion_dict(y_test, default_pred),
                    "score_mean_benign": float(raw[y_test == 0].mean()),
                    "score_mean_ssrf": float(raw[y_test == 1].mean()),
                    "training_samples": int(manifest.get("anomaly_training_samples", 0)),
                }
            )
        else:
            y_score = np.asarray(pipeline.predict_proba(test_records)[:, 1], dtype=float)
            y_pred = (y_score >= 0.5).astype(int)

        evaluations[name] = ModelEvaluation(
            name=name,
            metrics=classification_metrics(y_test, y_pred, y_score),
            confusion=confusion_dict(y_test, y_pred),
            latency=measure_latency(pipeline, test_records, is_anomaly, n_requests=latency_requests),
            per_family=per_family_breakdown(test_frame, y_test, y_pred),
            extra=extra,
        )
        if verbose:
            metrics = evaluations[name].metrics
            print(
                f"  {name:20} f1={metrics['f1']:.4f} precision={metrics['precision']:.4f} "
                f"recall={metrics['recall']:.4f} fpr={metrics['false_positive_rate']:.4f} "
                f"median={evaluations[name].latency['median_ms']:.3f} ms"
            )

    cross_validation: dict[str, Any] = {}
    if run_cross_validation:
        if verbose:
            print("  running 5-fold cross-validation ...")
        cross_validation = cross_validate_supervised(train_frame, config)

    results = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "phase": 1,
        "dataset": {
            "path": to_project_relative(dataset_path),
            "n_samples": int(len(frame)),
            "n_train": int(len(train_frame)),
            "n_test": int(len(test_frame)),
            "test_label_counts": test_frame["label"].value_counts().to_dict(),
            "n_families": int(frame["family"].nunique()),
        },
        "feature_count": len(FEATURE_NAMES),
        "models": {
            name: {
                "metrics": evaluation.metrics,
                "confusion_matrix": evaluation.confusion,
                "latency": evaluation.latency,
                "per_family": evaluation.per_family,
                **evaluation.extra,
            }
            for name, evaluation in evaluations.items()
        },
        "cross_validation": cross_validation,
        "feature_attribution": feature_attribution(pipelines),
        "manifest": manifest,
    }
    return results


def _config_from_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the TrainConfig kwargs recorded at training time."""
    stored = dict(manifest.get("config") or {})
    if not stored:
        return {}
    stored["dataset_path"] = from_project_relative(stored.get("dataset_path", ""))
    stored["model_dir"] = from_project_relative(stored.get("model_dir", MODEL_DIR))
    valid = set(TrainConfig.__dataclass_fields__)
    return {key: value for key, value in stored.items() if key in valid}


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _display_path(path: str | Path) -> str:
    """Show a path relative to the repository root, so reports are portable."""
    from mlwsg.config import PROJECT_ROOT

    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def render_report(results: dict[str, Any]) -> str:
    """Render the evaluation results as a Markdown report."""
    dataset = results["dataset"]
    models: dict[str, Any] = results["models"]

    parts: list[str] = []
    parts.append("# Phase 1 Evaluation Report\n")
    parts.append("ML-Assisted Web Security Gateway - SSRF detection models\n")
    parts.append(f"*Generated {results['generated_at']} (UTC). This file is produced by "
                 "`python -m mlwsg evaluate`; do not edit by hand.*\n")

    parts.append("## 1. Setup\n")
    parts.append(_table(
        ["Property", "Value"],
        [
            ["Dataset", f"`{_display_path(dataset['path'])}`"],
            ["Samples", f"{dataset['n_samples']:,}"],
            ["Train / test", f"{dataset['n_train']:,} / {dataset['n_test']:,} (stratified by family)"],
            ["Test label counts", ", ".join(f"{k}={v:,}" for k, v in sorted(dataset["test_label_counts"].items()))],
            ["Traffic families", dataset["n_families"]],
            ["Features per request", results["feature_count"]],
            ["Positive class", "`ssrf`"],
        ],
    ))
    parts.append("")

    parts.append("## 2. Headline results (held-out test set)\n")
    rows = []
    for name, payload in models.items():
        metrics = payload["metrics"]
        rows.append([
            f"`{name}`",
            f"{metrics['precision']:.4f}",
            f"{metrics['recall']:.4f}",
            f"{metrics['f1']:.4f}",
            f"{metrics['false_positive_rate']:.4f}",
            f"{metrics['accuracy']:.4f}",
            f"{metrics.get('roc_auc', float('nan')):.4f}",
            f"{metrics.get('pr_auc', float('nan')):.4f}",
        ])
    parts.append(_table(
        ["Model", "Precision", "Recall", "F1", "FPR", "Accuracy", "ROC-AUC", "PR-AUC"], rows))
    parts.append("\n*FPR is the share of benign requests that would be blocked -- "
                 "the number that decides whether a gateway can run inline.*\n")

    parts.append("## 3. Confusion matrices\n")
    rows = []
    for name, payload in models.items():
        c = payload["confusion_matrix"]
        rows.append([f"`{name}`", c["true_negative"], c["false_positive"],
                     c["false_negative"], c["true_positive"]])
    parts.append(_table(
        ["Model", "TN (benign allowed)", "FP (benign blocked)",
         "FN (attack missed)", "TP (attack blocked)"], rows))
    parts.append("")

    parts.append("## 4. Prediction latency\n")
    rows = []
    for name, payload in models.items():
        latency = payload["latency"]
        rows.append([
            f"`{name}`",
            f"{latency['mean_ms']:.3f}",
            f"{latency['median_ms']:.3f}",
            f"{latency['p95_ms']:.3f}",
            f"{latency['p99_ms']:.3f}",
            f"{latency['batch_per_request_ms']:.4f}",
            f"{latency['throughput_rps_single']:,.0f}",
        ])
    parts.append(_table(
        ["Model", "Mean (ms)", "Median (ms)", "p95 (ms)", "p99 (ms)",
         "Batched (ms/req)", "Single-request throughput (req/s)"], rows))
    parts.append("\n*Measured end to end: URL normalisation, feature extraction and inference, "
                 "one request at a time, as an inline gateway would call it.*\n")

    cross_validation = results.get("cross_validation") or {}
    if cross_validation:
        parts.append("## 5. Cross-validation (5-fold, training split)\n")
        rows = []
        for name, scores in cross_validation.items():
            rows.append([
                f"`{name}`",
                f"{scores['precision_mean']:.4f} +/- {scores['precision_std']:.4f}",
                f"{scores['recall_mean']:.4f} +/- {scores['recall_std']:.4f}",
                f"{scores['f1_mean']:.4f} +/- {scores['f1_std']:.4f}",
                f"{scores['false_positive_rate_mean']:.4f} +/- {scores['false_positive_rate_std']:.4f}",
            ])
        parts.append(_table(["Model", "Precision", "Recall", "F1", "FPR"], rows))
        parts.append("")

    anomaly = {n: p for n, p in models.items() if p.get("is_anomaly_model")}
    if anomaly:
        parts.append("## 6. Isolation Forest (anomaly detection)\n")
        parts.append(
            "The Isolation Forest is fitted on **benign traffic only** and never sees a "
            "labelled attack. It is evaluated against the same labelled test set, which "
            "measures the thing that matters for Phase 2: how much of the attack surface "
            "is recoverable without knowing the attack in advance.\n"
        )
        for name, payload in anomaly.items():
            tuned = payload["metrics"]
            default = payload["default_contamination_metrics"]
            parts.append(f"**`{name}`** - trained on {payload['training_samples']:,} benign samples, "
                         f"tuned threshold `{payload['tuned_threshold']:.4f}` "
                         f"({payload['threshold_tuned_on']}).\n")
            parts.append(_table(
                ["Decision rule", "Precision", "Recall", "F1", "FPR"],
                [
                    [f"Tuned threshold ({payload['tuned_threshold']:.4f})",
                     f"{tuned['precision']:.4f}", f"{tuned['recall']:.4f}",
                     f"{tuned['f1']:.4f}", f"{tuned['false_positive_rate']:.4f}"],
                    ["Default `contamination` cut-off",
                     f"{default['precision']:.4f}", f"{default['recall']:.4f}",
                     f"{default['f1']:.4f}", f"{default['false_positive_rate']:.4f}"],
                ],
            ))
            parts.append(
                f"\nMean anomaly score: benign `{payload['score_mean_benign']:.4f}` vs "
                f"SSRF `{payload['score_mean_ssrf']:.4f}` (lower = more anomalous). "
                f"Ranking quality is better read from ROC-AUC `{tuned.get('roc_auc', float('nan')):.4f}` "
                "than from the thresholded scores.\n"
            )

    parts.append("## 7. Detection rate per attack family\n")
    parts.append("Recall broken down by technique. A family at 1.0000 is fully covered; "
                 "anything lower is a concrete gap for Phase 2's deterministic rules to close.\n")
    families = sorted(
        {family for payload in models.values() for family, stats in payload["per_family"].items()
         if stats["label"] == LABEL_SSRF}
    )
    model_names = list(models)
    rows = []
    for family in families:
        row = [f"`{family}`", models[model_names[0]]["per_family"][family]["n"]]
        for name in model_names:
            row.append(f"{models[name]['per_family'][family]['detection_rate']:.4f}")
        rows.append(row)
    parts.append(_table(["Attack family", "n"] + [f"`{n}`" for n in model_names], rows))
    parts.append("")

    parts.append("## 8. False positives per benign family\n")
    parts.append("The benign families marked *hard negative* are adversarial by design: "
                 "public IP literals, encoded search text, non-standard ports, and internal "
                 "URLs quoted inside free-text fields.\n")
    benign_families = sorted(
        {family for payload in models.values() for family, stats in payload["per_family"].items()
         if stats["label"] == LABEL_BENIGN}
    )
    rows = []
    for family in benign_families:
        row = [f"`{family}`", models[model_names[0]]["per_family"][family]["n"]]
        for name in model_names:
            row.append(f"{models[name]['per_family'][family]['false_positive_rate']:.4f}")
        rows.append(row)
    parts.append(_table(["Benign family", "n"] + [f"`{n}`" for n in model_names], rows))
    parts.append("")

    attribution = results.get("feature_attribution") or {}
    if attribution:
        parts.append("## 9. What the models learned\n")
        if "random_forest_importances" in attribution:
            parts.append("**Random Forest - top features by impurity importance**\n")
            parts.append(_table(
                ["Rank", "Feature", "Importance"],
                [[i + 1, f"`{item['feature']}`", f"{item['importance']:.4f}"]
                 for i, item in enumerate(attribution["random_forest_importances"])],
            ))
            parts.append("")
        if "logistic_regression_coefficients" in attribution:
            parts.append("**Logistic Regression - largest absolute coefficients** "
                         "(on standardised features)\n")
            parts.append(_table(
                ["Rank", "Feature", "Coefficient", "Pushes towards"],
                [[i + 1, f"`{item['feature']}`", f"{item['coefficient']:+.4f}", item["direction"]]
                 for i, item in enumerate(attribution["logistic_regression_coefficients"])],
            ))
            parts.append("")

    parts.append("## 10. Reading these numbers honestly\n")
    parts.append(
        "- **The dataset is synthetic.** It is generated from a family registry, so every "
        "attack in the test set is a variation of an attack in the training set. Scores here "
        "are an upper bound on what the same models would do against live traffic.\n"
        "- **The feature extractor does most of the work.** URL normalisation, permissive IP "
        "parsing and destination classification are deterministic; the models mostly learn how "
        "to weigh those signals against each other. That is intentional -- it is also why the "
        "per-family table matters more than the headline F1.\n"
        "- **The genuinely hard cases are the ambiguous benign families.** "
        "`benign_internal_url_as_text` and `benign_dev_referrer` contain a real internal URL "
        "inside a harmless request. Separating them from `ssrf_open_redirect_param` needs the "
        "*interaction* between 'an internal URL is present' and 'it sits in a fetch parameter "
        "on a fetch endpoint' -- which is where the tree ensemble earns its place over the "
        "linear model.\n"
        "- **Resolution-time attacks are out of scope for Phase 1.** A hostname that looks "
        "public and resolves to 10.0.0.5 (DNS rebinding) cannot be caught from the URL string. "
        "That is exactly the job of the Phase 2 egress guard.\n"
    )
    return "\n".join(parts) + "\n"


def write_reports(
    results: dict[str, Any],
    json_path: Path | str = EVALUATION_JSON_PATH,
    markdown_path: Path | str = EVALUATION_REPORT_PATH,
) -> tuple[Path, Path]:
    """Write both the machine-readable and human-readable reports."""
    ensure_directories()
    json_path, markdown_path = Path(json_path), Path(markdown_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
    markdown_path.write_text(render_report(results), encoding="utf-8")
    return json_path, markdown_path


def main() -> None:  # pragma: no cover - thin CLI shim
    results = evaluate_models()
    json_path, markdown_path = write_reports(results)
    print(f"wrote {json_path} and {markdown_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
