import sqlite3

import pytest

from mlwsg.incidents import IncidentStore


def test_redacted_incident_is_durable_and_contains_no_payload(tmp_path):
    db_path = tmp_path / "incidents.sqlite"
    store = IncidentStore(db_path)
    id = store.record(
        "egress",
        "http://user:password@169.254.169.254/latest/meta-data/?token=private-query#fragment",
        "blocked private-query body=metadata-response\nbody=other-response",
        score=0.98,
    )
    incident = IncidentStore(db_path).get(id)
    assert incident["status"] == "blocked"
    assert incident["stage"] == "egress"
    assert incident["score"] == 0.98
    assert incident["url"] == "http://169.254.169.254/[redacted]"
    assert store.list()[0] == incident
    with sqlite3.connect(db_path) as db:
        raw = repr(db.execute("SELECT * FROM incidents").fetchall())
    for secret in (
        "private-query",
        "password",
        "metadata-response",
        "other-response",
        "fragment",
        "meta-data",
    ):
        assert secret not in raw


def test_review_is_explicit_and_terminal(tmp_path):
    store = IncidentStore(tmp_path / "incidents.sqlite")
    approved = store.record("egress", "http://internal.lab/?k=secret", "private IP")
    rejected = store.record("model", "http://metadata.lab/", "suspicious URL")
    with pytest.raises(ValueError, match="analysed"):
        store.approve(approved)
    with pytest.raises(ValueError, match="analysed"):
        store.reject(rejected)
    report = {
        "root_cause": "unsafe destination",
        "patch_proposal": "Apply DNS pinning",
        "regression_tests": ["Block redirect to metadata"],
        "reasoning": "Resolved address was private",
    }
    store.set_report(approved, report)
    assert store.get(approved)["status"] == "analysed"
    assert store.get(approved)["report"] == report
    with pytest.raises(ValueError, match="blocked"):
        store.set_report(approved, report)
    store.approve(approved)
    assert store.get(approved)["status"] == "approved"
    with pytest.raises(ValueError, match="analysed"):
        store.reject(approved)
    store.set_report(rejected, report)
    store.reject(rejected)
    assert store.get(rejected)["status"] == "rejected"
    with pytest.raises(ValueError, match="analysed"):
        store.approve(rejected)
    with pytest.raises(KeyError):
        store.get(123456)


def test_report_storage_redacts_nested_diagnostics(tmp_path):
    store = IncidentStore(tmp_path / "incidents.sqlite")
    id = store.record("egress", "http://public.lab/", "blocked")
    store.set_report(
        id,
        {
            "regression_tests": ["check https://host/?token=hidden"],
            "reasoning": "body=raw-response",
        },
    )
    raw = (tmp_path / "incidents.sqlite").read_bytes()
    assert b"hidden" not in raw
    assert b"raw-response" not in raw


@pytest.mark.parametrize("url", ["file:///etc/passwd", "http://[::1"])
def test_invalid_urls_can_be_recorded_without_persisting_payload(tmp_path, url):
    store = IncidentStore(tmp_path / "incidents.sqlite")
    incident = store.get(store.record("inbound", url, "invalid URL"))
    assert incident["status"] == "blocked"
    assert "etc/passwd" not in incident["url"]
    assert "::1" not in incident["url"]
