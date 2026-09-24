"""Command-line interface: ``python -m mlwsg <command>``.

One entry point for the whole Phase 1 pipeline, so a reviewer can reproduce
every artifact in the repository from a clean checkout::

    python -m mlwsg all        # dataset -> training -> evaluation
    python -m mlwsg testbed    # run the vulnerable app and simulated internals
    python -m mlwsg predict --url 'http://169.254.42.7/metadata/v1/credentials'
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mlwsg import __version__
from mlwsg.config import (
    DATASET_PATH,
    INTERNAL_SERVICES_PORT,
    MODEL_DIR,
    RANDOM_SEED,
    REPORT_DIR,
    TESTBED_HOST,
    VULNERABLE_APP_PORT,
    ensure_directories,
)


def _add_dataset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--samples", type=int, default=12000, help="target dataset size")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED, help="random seed")
    parser.add_argument("--benign-ratio", type=float, default=0.6, help="share of benign samples")
    parser.add_argument("--out", type=Path, default=DATASET_PATH, help="output CSV path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mlwsg",
        description="ML-Assisted Web Security Gateway - Phase 1 pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"mlwsg {__version__} (phase 1)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate-dataset", help="generate the synthetic dataset")
    _add_dataset_arguments(generate)

    train = subparsers.add_parser("train", help="train the three detection models")
    train.add_argument("--dataset", type=Path, default=DATASET_PATH)
    train.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    train.add_argument("--test-size", type=float, default=0.3)
    train.add_argument("--seed", type=int, default=RANDOM_SEED)

    evaluate = subparsers.add_parser("evaluate", help="evaluate models and write the report")
    evaluate.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    evaluate.add_argument("--dataset", type=Path, default=None)
    evaluate.add_argument("--no-cv", action="store_true", help="skip cross-validation")
    evaluate.add_argument("--latency-requests", type=int, default=300)
    evaluate.add_argument("--report-dir", type=Path, default=REPORT_DIR)

    run_all = subparsers.add_parser("all", help="generate, train and evaluate in one go")
    _add_dataset_arguments(run_all)
    run_all.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    run_all.add_argument("--report-dir", type=Path, default=REPORT_DIR)
    run_all.add_argument("--no-cv", action="store_true", help="skip cross-validation")

    predict = subparsers.add_parser("predict", help="score a single request")
    predict.add_argument("--url", required=True)
    predict.add_argument("--method", default="GET")
    predict.add_argument("--body", default="")
    predict.add_argument("--redirect-location", default="")
    predict.add_argument("--model", default="random_forest")
    predict.add_argument("--model-dir", type=Path, default=MODEL_DIR)
    predict.add_argument("--all-models", action="store_true", help="score with every trained model")
    predict.add_argument("--json", action="store_true", help="emit JSON instead of text")

    features = subparsers.add_parser("features", help="show the extracted features for a URL")
    features.add_argument("--url", required=True)
    features.add_argument("--method", default="GET")
    features.add_argument("--non-zero", action="store_true", help="only show non-zero features")

    testbed = subparsers.add_parser("testbed", help="run the vulnerable app + simulated internals")
    testbed.add_argument("--host", default=TESTBED_HOST)
    testbed.add_argument("--app-port", type=int, default=VULNERABLE_APP_PORT)
    testbed.add_argument("--internal-port", type=int, default=INTERNAL_SERVICES_PORT)
    testbed.add_argument("--log-level", default="warning")

    return parser


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_generate_dataset(args: argparse.Namespace) -> int:
    from mlwsg.dataset import generate_dataset, write_dataset

    ensure_directories()
    samples = generate_dataset(
        n_samples=args.samples, seed=args.seed, benign_ratio=args.benign_ratio
    )
    path = write_dataset(samples, csv_path=args.out, seed=args.seed)
    benign = sum(1 for s in samples if s.label == "benign")
    print(
        f"generated {len(samples):,} samples "
        f"({benign:,} benign / {len(samples) - benign:,} ssrf) -> {path}"
    )
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from mlwsg.models.train import TrainConfig, train_models

    config = TrainConfig(
        dataset_path=args.dataset,
        model_dir=args.model_dir,
        test_size=args.test_size,
        seed=args.seed,
    )
    train_models(config)
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    from mlwsg.models.evaluate import evaluate_models, write_reports

    results = evaluate_models(
        model_dir=args.model_dir,
        dataset_path=args.dataset,
        run_cross_validation=not args.no_cv,
        latency_requests=args.latency_requests,
    )
    json_path, markdown_path = write_reports(
        results,
        json_path=args.report_dir / "evaluation_results.json",
        markdown_path=args.report_dir / "evaluation_report.md",
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    from mlwsg.models.evaluate import evaluate_models, write_reports
    from mlwsg.models.train import TrainConfig, train_models

    cmd_generate_dataset(args)
    config = TrainConfig(dataset_path=args.out, model_dir=args.model_dir, seed=args.seed)
    train_models(config)
    results = evaluate_models(
        model_dir=args.model_dir,
        dataset_path=args.out,
        run_cross_validation=not args.no_cv,
    )
    _, markdown_path = write_reports(
        results,
        json_path=args.report_dir / "evaluation_results.json",
        markdown_path=args.report_dir / "evaluation_report.md",
    )
    print(f"\nPhase 1 pipeline complete. Report: {markdown_path}")
    return 0


def cmd_predict(args: argparse.Namespace) -> int:
    from mlwsg.models.predict import SSRFDetector, available_models

    record = {
        "url": args.url,
        "method": args.method,
        "body": args.body,
        "redirect_location": args.redirect_location,
        "redirect_hops": 1 if args.redirect_location else 0,
    }
    names = available_models(args.model_dir) if args.all_models else [args.model]
    if not names:
        print("no trained models found; run `python -m mlwsg train` first", file=sys.stderr)
        return 1

    outputs = []
    for name in names:
        try:
            detector = SSRFDetector.load(name, args.model_dir)
        except FileNotFoundError as exc:
            print(f"no trained models: {exc}", file=sys.stderr)
            return 1
        outputs.append(detector.predict(record))

    if args.json:
        print(json.dumps([prediction.to_dict() for prediction in outputs], indent=2))
        return 0

    print(f"URL: {args.url}")
    for prediction in outputs:
        flag = "BLOCK" if prediction.is_ssrf else "ALLOW"
        print(
            f"  {prediction.model:20} {flag:5} label={prediction.label:6} "
            f"score={prediction.score:.4f} ({prediction.latency_ms:.2f} ms)"
        )
    if outputs and outputs[0].reasons:
        print("  indicators:")
        for reason in outputs[0].reasons:
            print(f"    - {reason}")
    return 0


def cmd_features(args: argparse.Namespace) -> int:
    from mlwsg.features import extract_features

    values = extract_features({"url": args.url, "method": args.method})
    width = max(len(name) for name in values)
    for name, value in values.items():
        if args.non_zero and not value:
            continue
        print(f"  {name:<{width}}  {value:g}")
    return 0


def cmd_testbed(args: argparse.Namespace) -> int:
    from mlwsg.testbed.runner import run_testbed

    run_testbed(
        host=args.host,
        app_port=args.app_port,
        internal_port=args.internal_port,
        log_level=args.log_level,
    )
    return 0


COMMANDS = {
    "generate-dataset": cmd_generate_dataset,
    "train": cmd_train,
    "evaluate": cmd_evaluate,
    "all": cmd_all,
    "predict": cmd_predict,
    "features": cmd_features,
    "testbed": cmd_testbed,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return COMMANDS[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
