"""The ``python -m mlwsg`` command line."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mlwsg.cli import build_parser, main


def test_parser_exposes_every_command():
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices  # type: ignore[attr-defined]
    assert set(commands) == {
        "generate-dataset", "train", "evaluate", "all", "predict", "features", "testbed",
    }


def test_version_flag_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "phase 1" in capsys.readouterr().out


def test_missing_command_is_rejected():
    with pytest.raises(SystemExit):
        main([])


def test_generate_dataset_writes_a_csv(tmp_path: Path, capsys):
    out = tmp_path / "dataset.csv"
    assert main(["generate-dataset", "--samples", "300", "--seed", "5", "--out", str(out)]) == 0
    assert out.exists()
    assert "generated 300 samples" in capsys.readouterr().out


def test_features_command_prints_the_vector(capsys):
    assert main(["features", "--url", "http://127.0.0.1/admin"]) == 0
    output = capsys.readouterr().out
    assert "dest_is_loopback" in output
    assert "url_length" in output


def test_features_command_can_filter_to_non_zero(capsys):
    assert main(["features", "--url", "http://127.0.0.1/admin", "--non-zero"]) == 0
    output = capsys.readouterr().out
    assert "dest_is_loopback" in output
    assert "host_notation_hex" not in output


@pytest.mark.slow
def test_predict_command_reports_a_decision(model_dir: Path, capsys):
    assert main(["predict", "--url", "http://169.254.42.7/meta",
                 "--model-dir", str(model_dir)]) == 0
    output = capsys.readouterr().out
    assert "BLOCK" in output
    assert "indicators:" in output


@pytest.mark.slow
def test_predict_command_emits_json(model_dir: Path, capsys):
    assert main(["predict", "--url", "https://cdn.example.com/app.js",
                 "--model-dir", str(model_dir), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["label"] == "benign"


@pytest.mark.slow
def test_predict_command_can_use_every_model(model_dir: Path, capsys):
    assert main(["predict", "--url", "http://127.0.0.1/admin",
                 "--model-dir", str(model_dir), "--all-models"]) == 0
    output = capsys.readouterr().out
    for name in ("logistic_regression", "random_forest", "isolation_forest"):
        assert name in output


def test_predict_without_trained_models_fails_cleanly(tmp_path: Path, capsys):
    assert main(["predict", "--url", "http://127.0.0.1/", "--model-dir", str(tmp_path)]) == 1
    assert "no trained models" in capsys.readouterr().err


@pytest.mark.slow
def test_full_pipeline_runs_end_to_end(tmp_path: Path, capsys):
    """generate-dataset -> train -> evaluate, all into a temporary directory."""
    assert main([
        "all",
        "--samples", "600",
        "--seed", "11",
        "--out", str(tmp_path / "dataset.csv"),
        "--model-dir", str(tmp_path / "models"),
        "--report-dir", str(tmp_path / "reports"),
        "--no-cv",
    ]) == 0

    assert (tmp_path / "dataset.csv").exists()
    for name in ("logistic_regression", "random_forest", "isolation_forest"):
        assert (tmp_path / "models" / f"{name}.joblib").exists()

    report = (tmp_path / "reports" / "evaluation_report.md").read_text()
    assert "Phase 1 Evaluation Report" in report
    assert "False Positive Rate" in report or "FPR" in report

    results = json.loads((tmp_path / "reports" / "evaluation_results.json").read_text())
    assert set(results["models"]) == {"logistic_regression", "random_forest", "isolation_forest"}
    for payload in results["models"].values():
        assert 0.0 <= payload["metrics"]["f1"] <= 1.0
        assert payload["latency"]["median_ms"] > 0
    assert "Phase 1 pipeline complete" in capsys.readouterr().out
