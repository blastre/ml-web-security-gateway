"""The request schema shared by the dataset, the features and inference."""

from __future__ import annotations

import pytest

from mlwsg.schema import DATASET_COLUMNS, DatasetSample, RequestRecord, coerce_record


def test_defaults_describe_a_plain_get():
    record = RequestRecord(url="https://example.com/")
    assert record.method == "GET"
    assert record.body == ""
    assert record.redirect_hops == 0


def test_from_mapping_ignores_unrelated_keys():
    record = RequestRecord.from_mapping(
        {"url": "https://example.com/", "label": "benign", "family": "x", "notes": "y"}
    )
    assert record.url == "https://example.com/"


def test_from_mapping_normalises_types():
    record = RequestRecord.from_mapping({"url": "https://example.com/", "method": "post",
                                         "redirect_hops": "2"})
    assert record.method == "POST"
    assert record.redirect_hops == 2


def test_from_mapping_treats_nan_as_missing():
    record = RequestRecord.from_mapping({"url": "https://example.com/", "body": float("nan")})
    assert record.body == ""


def test_coerce_record_accepts_the_shapes_the_detector_is_called_with():
    assert coerce_record("https://example.com/").url == "https://example.com/"
    assert coerce_record({"url": "https://example.com/"}).method == "GET"
    assert coerce_record(RequestRecord(url="https://example.com/")).url == "https://example.com/"


def test_coerce_record_rejects_unsupported_types():
    with pytest.raises(TypeError):
        coerce_record(42)


def test_dataset_row_matches_the_csv_column_order():
    sample = DatasetSample(
        id="abc", label="ssrf", family="ssrf_loopback_direct",
        record=RequestRecord(url="http://127.0.0.1/"), notes="n",
    )
    assert tuple(sample.to_row()) == DATASET_COLUMNS
