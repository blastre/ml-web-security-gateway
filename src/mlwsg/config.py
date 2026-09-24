"""Project-wide paths and shared constants.

Every path is derived from the repository root so the project runs unchanged
from any working directory.
"""

from __future__ import annotations

import os
from pathlib import Path

# src/mlwsg/config.py -> src/mlwsg -> src -> <repo root>
PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
ARTIFACT_DIR = PROJECT_ROOT / "artifacts"
MODEL_DIR = ARTIFACT_DIR / "models"
REPORT_DIR = PROJECT_ROOT / "reports"

DATASET_PATH = DATA_DIR / "ssrf_dataset.csv"
DATASET_METADATA_PATH = DATA_DIR / "dataset_metadata.json"

MANIFEST_PATH = MODEL_DIR / "manifest.json"
FEATURE_METADATA_PATH = MODEL_DIR / "feature_metadata.json"

EVALUATION_JSON_PATH = REPORT_DIR / "evaluation_results.json"
EVALUATION_REPORT_PATH = REPORT_DIR / "evaluation_report.md"

# Reproducibility: one seed drives dataset generation, splitting and training.
RANDOM_SEED = 20240501

LABEL_BENIGN = "benign"
LABEL_SSRF = "ssrf"
LABELS = (LABEL_BENIGN, LABEL_SSRF)

# Integer encoding used by the supervised models: SSRF is the positive class.
LABEL_TO_INT = {LABEL_BENIGN: 0, LABEL_SSRF: 1}
INT_TO_LABEL = {v: k for k, v in LABEL_TO_INT.items()}

# ---------------------------------------------------------------------------
# Testbed network layout (everything is loopback-only and simulated).
# ---------------------------------------------------------------------------
TESTBED_HOST = "127.0.0.1"
VULNERABLE_APP_PORT = int(os.environ.get("MLWSG_APP_PORT", "9100"))
INTERNAL_SERVICES_PORT = int(os.environ.get("MLWSG_INTERNAL_PORT", "9101"))


def to_project_relative(path: Path | str) -> str:
    """Render *path* relative to the repository root when it lives inside it.

    Artifacts such as the training manifest are committed, so they must not
    carry one machine's absolute directory layout.
    """
    resolved = Path(path).resolve()
    try:
        return str(resolved.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(resolved)


def from_project_relative(value: Path | str) -> Path:
    """Inverse of :func:`to_project_relative`, independent of the working directory."""
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path)


def ensure_directories() -> None:
    """Create the output directories the pipeline writes into."""
    for directory in (DATA_DIR, ARTIFACT_DIR, MODEL_DIR, REPORT_DIR):
        directory.mkdir(parents=True, exist_ok=True)
