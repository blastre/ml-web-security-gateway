"""Simulated internal network: admin panels, data stores and a metadata service.

Everything served here is fabricated.  The "credentials" are obvious
placeholders, the metadata document is shaped like a cloud instance-metadata
response but belongs to no provider, and the whole app binds to loopback.  Its
only job is to give an SSRF attempt something recognisable to reach, so the
impact of the vulnerability is visible without touching anything real.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

#: Stamped into every response so nothing here can be mistaken for real data.
SIMULATION_BANNER = "SIMULATED-DATA-FOR-SECURITY-TESTING-ONLY"

#: A marker an SSRF proof-of-concept can grep for to prove it reached the
#: internal network.  It is not a secret; it is a flag in the CTF sense.
INTERNAL_PROOF_TOKEN = "MLWSG-INTERNAL-REACHED-a7f3c1"  # noqa: S105 - not a credential

app = FastAPI(
    title="MLWSG Simulated Internal Services",
    description=(
        "Stand-in for an internal network segment. All data is fabricated. "
        "Loopback only."
    ),
    version="1.0.0",
)


def _wrap(payload: dict[str, Any]) -> dict[str, Any]:
    return {"simulated": True, "banner": SIMULATION_BANNER, **payload}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    """Directory of the simulated internal services."""
    return f"""<!doctype html>
<html><head><title>Internal Services (SIMULATED)</title></head>
<body>
<h1>Internal Services &mdash; SIMULATED</h1>
<p>{SIMULATION_BANNER}</p>
<p>This host stands in for an internal network segment. Nothing here is real.</p>
<ul>
  <li><a href="/admin">/admin</a> &mdash; admin panel</li>
  <li><a href="/admin/users">/admin/users</a> &mdash; user directory</li>
  <li><a href="/internal/api/keys">/internal/api/keys</a> &mdash; placeholder API keys</li>
  <li><a href="/actuator/env">/actuator/env</a> &mdash; application environment</li>
  <li><a href="/metadata/v1/instance">/metadata/v1/instance</a> &mdash; instance metadata</li>
  <li><a href="/metadata/v1/credentials">/metadata/v1/credentials</a> &mdash; placeholder credentials</li>
  <li><a href="/server-status">/server-status</a> &mdash; server status page</li>
</ul>
</body></html>"""


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return _wrap({"status": "ok", "service": "internal-services"})


@app.get("/admin", response_class=HTMLResponse)
def admin_panel() -> str:
    return f"""<!doctype html>
<html><head><title>Admin Panel (SIMULATED)</title></head>
<body>
<h1>Administration Console &mdash; SIMULATED</h1>
<p>{SIMULATION_BANNER}</p>
<p>proof token: <code>{INTERNAL_PROOF_TOKEN}</code></p>
<p>If this page was reached through the application's URL-fetching feature,
an SSRF vulnerability has been demonstrated.</p>
</body></html>"""


@app.get("/admin/users")
def admin_users() -> dict[str, Any]:
    return _wrap(
        {
            "proof_token": INTERNAL_PROOF_TOKEN,
            "users": [
                {"id": 1, "name": "simulated-admin", "role": "admin", "email": "admin@internal.sim"},
                {"id": 2, "name": "simulated-operator", "role": "operator", "email": "ops@internal.sim"},
                {"id": 3, "name": "simulated-analyst", "role": "read-only", "email": "analyst@internal.sim"},
            ],
        }
    )


@app.get("/internal/api/keys")
def internal_keys() -> dict[str, Any]:
    return _wrap(
        {
            "proof_token": INTERNAL_PROOF_TOKEN,
            "keys": [
                {"name": "billing-service", "value": "PLACEHOLDER-NOT-A-REAL-KEY-0001"},
                {"name": "search-indexer", "value": "PLACEHOLDER-NOT-A-REAL-KEY-0002"},
            ],
            "note": "These values are fabricated placeholders and authenticate nothing.",
        }
    )


@app.get("/actuator/env")
def actuator_env() -> dict[str, Any]:
    return _wrap(
        {
            "proof_token": INTERNAL_PROOF_TOKEN,
            "activeProfiles": ["simulation"],
            "propertySources": [
                {
                    "name": "applicationConfig",
                    "properties": {
                        "spring.datasource.url": {"value": "jdbc:postgresql://db.internal:5432/appdb"},
                        "spring.datasource.password": {"value": "PLACEHOLDER-NOT-A-REAL-PASSWORD"},
                        "app.environment": {"value": "simulated"},
                    },
                }
            ],
        }
    )


@app.get("/server-status", response_class=PlainTextResponse)
def server_status() -> str:
    return (
        f"{SIMULATION_BANNER}\n"
        f"proof_token: {INTERNAL_PROOF_TOKEN}\n"
        "Server Version: SimulatedHTTPD/1.0\n"
        "Total accesses: 4127 - Total Traffic: 18.3 MB\n"
        "1 requests currently being processed\n"
    )


# ---------------------------------------------------------------------------
# Simulated instance-metadata service
# ---------------------------------------------------------------------------
#
# Shaped like a cloud instance-metadata document because that is the scenario
# being studied, but it belongs to no real provider, lives on loopback, and
# every value in it is fabricated. No real metadata address is used anywhere in
# this project.


@app.get("/metadata/v1/instance")
def metadata_instance() -> dict[str, Any]:
    return _wrap(
        {
            "proof_token": INTERNAL_PROOF_TOKEN,
            "instance_id": "sim-instance-0f3a9c21",
            "instance_type": "sim.medium",
            "region": "simulation-region-1",
            "availability_zone": "simulation-region-1a",
            "hostname": "metadata.sim.local",
            "image_id": "sim-image-2024-01",
        }
    )


@app.get("/metadata/v1/instance/identity")
def metadata_identity() -> dict[str, Any]:
    return _wrap(
        {
            "proof_token": INTERNAL_PROOF_TOKEN,
            "account_id": "000000000000",
            "instance_id": "sim-instance-0f3a9c21",
            "signature": "SIMULATED-SIGNATURE-NOT-VALID",
        }
    )


@app.get("/metadata/v1/credentials")
def metadata_credentials() -> JSONResponse:
    """Placeholder credentials.

    Deliberately shaped like a metadata credential response so an SSRF
    proof-of-concept is convincing, while the values authenticate nothing
    anywhere and are obviously marked as such.
    """
    return JSONResponse(
        _wrap(
            {
                "proof_token": INTERNAL_PROOF_TOKEN,
                "AccessKeyId": "SIMULATED-ACCESS-KEY-DO-NOT-USE",
                "SecretAccessKey": "SIMULATED-SECRET-DO-NOT-USE-NOT-A-REAL-CREDENTIAL",
                "Token": "SIMULATED-SESSION-TOKEN-DO-NOT-USE",
                "Expiration": "2099-01-01T00:00:00Z",
                "warning": (
                    "Fabricated placeholder values. They grant no access to anything "
                    "and exist only to demonstrate SSRF impact in a lab."
                ),
            }
        )
    )


@app.get("/metadata/v1/network")
def metadata_network() -> dict[str, Any]:
    return _wrap(
        {
            "proof_token": INTERNAL_PROOF_TOKEN,
            "interfaces": [
                {"mac": "02:00:00:00:00:01", "local_ipv4": "10.0.4.21", "subnet": "10.0.4.0/24"}
            ],
            "vpc_id": "sim-vpc-77c1",
        }
    )


@app.get("/latest/simulated-meta-data/hostname", response_class=PlainTextResponse)
def metadata_hostname() -> str:
    return "metadata.sim.local"
