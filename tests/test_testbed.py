"""Testbed: the simulated internals, the vulnerable app and its guard rails."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mlwsg.config import INTERNAL_SERVICES_PORT, TESTBED_HOST
from mlwsg.testbed import internal_services, vulnerable_app
from mlwsg.testbed.internal_services import INTERNAL_PROOF_TOKEN, SIMULATION_BANNER
from mlwsg.testbed.network import (
    SANDBOX_ENV_VAR,
    SIMULATED_DNS,
    SandboxViolation,
    resolve_simulated_url,
    sandbox_enabled,
)
from mlwsg.testbed.runner import ServerThread, _assert_safe_bind
from tests.conftest import port_is_free


# ---------------------------------------------------------------------------
# Simulated internal services
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def internal_client() -> TestClient:
    return TestClient(internal_services.app)


def test_internal_index_lists_the_simulated_services(internal_client: TestClient):
    response = internal_client.get("/")
    assert response.status_code == 200
    assert SIMULATION_BANNER in response.text


def test_internal_healthcheck(internal_client: TestClient):
    payload = internal_client.get("/healthz").json()
    assert payload["status"] == "ok"
    assert payload["simulated"] is True


@pytest.mark.parametrize(
    "path",
    [
        "/admin",
        "/admin/users",
        "/internal/api/keys",
        "/actuator/env",
        "/server-status",
        "/metadata/v1/instance",
        "/metadata/v1/credentials",
        "/metadata/v1/network",
    ],
)
def test_every_internal_endpoint_carries_the_proof_token(internal_client: TestClient, path: str):
    """The token is what an SSRF proof-of-concept greps for."""
    assert INTERNAL_PROOF_TOKEN in internal_client.get(path).text


def test_simulated_credentials_are_obviously_fake(internal_client: TestClient):
    payload = internal_client.get("/metadata/v1/credentials").json()
    assert payload["simulated"] is True
    assert "SIMULATED" in payload["AccessKeyId"]
    assert "SIMULATED" in payload["SecretAccessKey"]
    assert "fabricated" in payload["warning"].lower()


def test_metadata_hostname_endpoint(internal_client: TestClient):
    assert internal_client.get("/latest/simulated-meta-data/hostname").text == "metadata.sim.local"


# ---------------------------------------------------------------------------
# Simulated DNS and sandbox policy
# ---------------------------------------------------------------------------


def test_simulated_dns_maps_every_name_to_loopback():
    assert SIMULATED_DNS
    assert all(host == TESTBED_HOST for host, _ in SIMULATED_DNS.values())
    assert "metadata.sim.local" in SIMULATED_DNS


def test_simulated_hostname_is_rewritten_onto_the_internal_port():
    target = resolve_simulated_url("http://metadata.sim.local/metadata/v1/instance")
    assert target.simulated
    assert target.resolved_host == TESTBED_HOST
    assert target.port == INTERNAL_SERVICES_PORT
    assert target.original_host == "metadata.sim.local"
    assert "/metadata/v1/instance" in target.request_url


def test_loopback_targets_pass_the_sandbox():
    target = resolve_simulated_url("http://127.0.0.1:9101/admin")
    assert not target.simulated
    assert target.resolved_host == "127.0.0.1"


def test_sandbox_blocks_non_loopback_destinations():
    assert sandbox_enabled(), "sandbox must default to on"
    with pytest.raises(SandboxViolation, match="open proxy"):
        resolve_simulated_url("http://example.com/")


def test_sandbox_can_be_disabled_for_controlled_experiments(monkeypatch):
    monkeypatch.setenv(SANDBOX_ENV_VAR, "0")
    assert not sandbox_enabled()
    target = resolve_simulated_url("http://example.com/")
    assert target.resolved_host == "example.com"


# ---------------------------------------------------------------------------
# The vulnerable application
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app_client() -> TestClient:
    return TestClient(vulnerable_app.app)


@pytest.fixture(scope="module")
def internal_server():
    """Run the simulated internal services so outbound fetches have a target."""
    if not port_is_free(TESTBED_HOST, INTERNAL_SERVICES_PORT):
        pytest.skip(f"port {INTERNAL_SERVICES_PORT} is already in use")
    server = ServerThread(
        "mlwsg.testbed.internal_services:app", TESTBED_HOST, INTERNAL_SERVICES_PORT, "error"
    )
    server.start()
    if not server.wait_until_started(timeout=20):
        server.stop()
        pytest.skip("internal services server did not start in time")
    yield server
    server.stop()
    server.join(timeout=5)


def test_vulnerable_app_index_warns_that_it_is_vulnerable(app_client: TestClient):
    assert "deliberately vulnerable" in app_client.get("/").text.lower()


def test_vulnerable_app_healthcheck(app_client: TestClient):
    payload = app_client.get("/healthz").json()
    assert payload["status"] == "ok"
    assert payload["sandbox"] is True


def test_public_sim_endpoint_is_available(app_client: TestClient):
    assert app_client.get("/public-sim/hello").json()["simulated"] is True


def test_fetch_requires_a_url(app_client: TestClient):
    assert app_client.get("/fetch").status_code == 422


def test_sandbox_blocks_an_outbound_fetch_to_the_internet(app_client: TestClient):
    payload = app_client.get("/fetch", params={"url": "http://example.com/"}).json()
    assert payload["ok"] is False
    assert payload["error"] == "sandbox_blocked"


def test_ssrf_by_ip_literal_reaches_the_internal_network(app_client, internal_server):
    """The core demonstration: no validation, so an internal URL is fetched."""
    payload = app_client.get(
        "/fetch", params={"url": f"http://127.0.0.1:{INTERNAL_SERVICES_PORT}/admin"}
    ).json()
    assert payload["ok"] is True
    assert payload["status_code"] == 200
    assert INTERNAL_PROOF_TOKEN in payload["body_preview"]


def test_ssrf_by_simulated_hostname_reaches_the_metadata_service(app_client, internal_server):
    payload = app_client.get(
        "/fetch", params={"url": "http://metadata.sim.local/metadata/v1/credentials"}
    ).json()
    assert payload["ok"] is True
    assert payload["simulated_dns"] is True
    assert "SIMULATED-ACCESS-KEY-DO-NOT-USE" in payload["body_preview"]


def test_ssrf_through_the_post_body(app_client, internal_server):
    payload = app_client.post(
        "/fetch", json={"url": f"http://127.0.0.1:{INTERNAL_SERVICES_PORT}/internal/api/keys"}
    ).json()
    assert payload["ok"] is True
    assert INTERNAL_PROOF_TOKEN in payload["body_preview"]


def test_webhook_registration_fetches_the_callback(app_client, internal_server):
    payload = app_client.post(
        "/webhook/register",
        json={"callback_url": f"http://127.0.0.1:{INTERNAL_SERVICES_PORT}/healthz"},
    ).json()
    assert payload["registered"] is True


def test_link_preview_extracts_an_internal_page_title(app_client, internal_server):
    payload = app_client.get(
        "/preview", params={"url": f"http://127.0.0.1:{INTERNAL_SERVICES_PORT}/admin"}
    ).json()
    assert payload["ok"] is True
    assert "SIMULATED" in (payload["title"] or "")


def test_open_redirect_returns_a_302(app_client: TestClient):
    response = app_client.get(
        "/redirect", params={"to": "http://127.0.0.1:9101/admin"}, follow_redirects=False
    )
    assert response.status_code == 302
    assert response.headers["location"] == "http://127.0.0.1:9101/admin"


def test_redirect_chain_lands_on_the_internal_target(app_client, internal_server):
    """A destination check on the requested URL alone would have allowed this."""
    if not port_is_free(TESTBED_HOST, 9100):
        pytest.skip("vulnerable app port is in use; cannot exercise the redirect chain")
    server = ServerThread("mlwsg.testbed.vulnerable_app:app", TESTBED_HOST, 9100, "error")
    server.start()
    try:
        if not server.wait_until_started(timeout=20):
            pytest.skip("vulnerable app did not start in time")
        payload = app_client.get(
            "/fetch-chain",
            params={"url": f"http://127.0.0.1:{INTERNAL_SERVICES_PORT}/admin"},
        ).json()
        assert payload["ok"] is True
        assert payload["redirected"] is True
        assert INTERNAL_PROOF_TOKEN in payload["body_preview"]
    finally:
        server.stop()
        server.join(timeout=5)


def test_unreachable_target_reports_a_fetch_error(app_client: TestClient):
    payload = app_client.get("/fetch", params={"url": "http://127.0.0.1:9/closed"}).json()
    assert payload["ok"] is False
    assert payload["error"] == "fetch_failed"


# ---------------------------------------------------------------------------
# Bind safety
# ---------------------------------------------------------------------------


def test_loopback_bind_is_allowed():
    for host in ("127.0.0.1", "::1", "localhost"):
        _assert_safe_bind(host)


def test_binding_to_a_public_interface_is_refused():
    with pytest.raises(SystemExit, match="deliberately vulnerable"):
        _assert_safe_bind("0.0.0.0")


def test_external_bind_requires_an_explicit_opt_in(monkeypatch, capsys):
    monkeypatch.setenv("MLWSG_ALLOW_EXTERNAL_BIND", "1")
    _assert_safe_bind("0.0.0.0")
    assert "WARNING" in capsys.readouterr().out
