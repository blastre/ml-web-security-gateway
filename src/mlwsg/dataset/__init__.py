"""Reproducible synthetic dataset of benign and SSRF web requests."""

from mlwsg.dataset.generator import (
    DATASET_VERSION,
    FAMILIES,
    benign_families,
    generate_dataset,
    ssrf_families,
    write_dataset,
    STATICALLY_UNDETECTABLE_FAMILIES,
)

__all__ = [
    "DATASET_VERSION",
    "FAMILIES",
    "benign_families",
    "generate_dataset",
    "ssrf_families",
    "write_dataset",
    "STATICALLY_UNDETECTABLE_FAMILIES",
]
