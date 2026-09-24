"""Simulated DNS and the testbed's containment policy.

Two jobs:

**A resolver stand-in.**  SSRF by *hostname* (``http://metadata.sim.local/``)
is a distinct technique from SSRF by IP literal, and the testbed has to be able
to demonstrate it.  Rather than asking anyone to edit ``/etc/hosts``,
:func:`resolve_simulated_url` rewrites known simulated names onto the local
internal-services port while preserving the original ``Host`` header.

**Containment.**  The vulnerable app is deliberately broken, which makes it an
open proxy.  Sandbox mode -- on by default -- confines its outbound requests to
loopback.  Note carefully what this is *not*: it permits exactly the traffic an
egress guard would block (reaching internal services) and blocks the traffic an
egress guard would allow (the public Internet).  It is an operational guard
rail that keeps a deliberately vulnerable app from being pointed at a third
party; it is not a fix, and it is not the Phase 2 egress guard.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from mlwsg.config import INTERNAL_SERVICES_PORT, TESTBED_HOST

#: Set to ``0`` to let the vulnerable app reach non-loopback destinations.
SANDBOX_ENV_VAR = "MLWSG_TESTBED_SANDBOX"

#: Set to ``1`` to allow binding the testbed to a non-loopback interface.
EXTERNAL_BIND_ENV_VAR = "MLWSG_ALLOW_EXTERNAL_BIND"

#: Hostnames the testbed "resolves" to the simulated internal services app.
#: Every one of them maps to loopback -- there is no real DNS involved.
SIMULATED_DNS: dict[str, tuple[str, int]] = {
    host: (TESTBED_HOST, INTERNAL_SERVICES_PORT)
    for host in (
        "metadata.sim",
        "metadata.sim.local",
        "metadata.internal.sim",
        "instance-data.internal.sim",
        "admin.internal.sim",
        "api.internal.sim",
        "db.internal",
        "redis.internal",
        "cache.internal",
        "vault.internal",
        "admin.intranet",
        "jenkins.corp",
        "backend.svc.cluster.local",
        "internal.sim",
    )
}


class SandboxViolation(RuntimeError):
    """Raised when the testbed sandbox blocks an outbound destination."""


@dataclass(frozen=True)
class ResolvedTarget:
    """Where a requested URL will actually be sent."""

    request_url: str
    original_host: str
    resolved_host: str
    port: int | None
    simulated: bool


def sandbox_enabled() -> bool:
    """True unless the operator explicitly disabled containment."""
    return os.environ.get(SANDBOX_ENV_VAR, "1") not in ("0", "false", "False", "no")


def external_bind_allowed() -> bool:
    return os.environ.get(EXTERNAL_BIND_ENV_VAR, "0") in ("1", "true", "True", "yes")


def _is_loopback(host: str) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return candidate.lower() in ("localhost", "localhost.localdomain")


def resolve_simulated_url(url: str) -> ResolvedTarget:
    """Rewrite *url* onto the simulated internal network where applicable.

    Raises:
        SandboxViolation: when sandbox mode is on and the destination is not
            loopback after rewriting.
    """
    parts = urlsplit(url)
    original_host = (parts.hostname or "").lower()
    mapping = SIMULATED_DNS.get(original_host)

    if mapping is not None:
        host, port = mapping
        netloc = f"{host}:{port}"
        request_url = urlunsplit((parts.scheme or "http", netloc, parts.path, parts.query, ""))
        target = ResolvedTarget(request_url, original_host, host, port, simulated=True)
    else:
        target = ResolvedTarget(url, original_host, original_host, parts.port, simulated=False)

    if sandbox_enabled() and not _is_loopback(target.resolved_host):
        raise SandboxViolation(
            f"testbed sandbox blocked an outbound request to {original_host or url!r}. "
            f"The sandbox confines this deliberately vulnerable app to loopback so it "
            f"cannot be used as an open proxy. Set {SANDBOX_ENV_VAR}=0 to disable it "
            f"for a controlled experiment."
        )
    return target
