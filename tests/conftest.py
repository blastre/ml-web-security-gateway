"""Shared fixtures.

Training fixtures are session-scoped and use a deliberately small dataset and
small forests: the goal is to prove the pipeline works end to end, not to
reproduce the headline numbers (that is what ``python -m mlwsg evaluate`` is
for).
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from mlwsg.dataset import generate_dataset, write_dataset
from mlwsg.models.train import TrainConfig, train_models

SMALL_DATASET_SIZE = 1500
SMALL_SEED = 4242


@pytest.fixture(scope="session")
def small_dataset(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A small but structurally complete dataset written to a temp directory."""
    directory = tmp_path_factory.mktemp("dataset")
    csv_path = directory / "ssrf_dataset.csv"
    samples = generate_dataset(n_samples=SMALL_DATASET_SIZE, seed=SMALL_SEED, min_per_family=12)
    write_dataset(samples, csv_path=csv_path, metadata_path=directory / "metadata.json",
                  seed=SMALL_SEED)
    return csv_path


@pytest.fixture(scope="session")
def train_config(small_dataset: Path, tmp_path_factory: pytest.TempPathFactory) -> TrainConfig:
    return TrainConfig(
        dataset_path=small_dataset,
        model_dir=tmp_path_factory.mktemp("models"),
        seed=SMALL_SEED,
        forest_estimators=40,
        isolation_estimators=50,
    )


@pytest.fixture(scope="session")
def trained(train_config: TrainConfig):
    """Train all three models once and reuse them across the suite."""
    return train_models(train_config, verbose=False)


@pytest.fixture(scope="session")
def model_dir(trained, train_config: TrainConfig) -> Path:
    return Path(train_config.model_dir)


def port_is_free(host: str, port: int) -> bool:
    """True when nothing is listening on *host:port*."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        return probe.connect_ex((host, port)) != 0
