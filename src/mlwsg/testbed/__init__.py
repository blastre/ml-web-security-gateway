"""Controlled, loopback-only testbed: a vulnerable app plus simulated internals.

Nothing in this package talks to a real network destination, and no real
credentials or cloud metadata endpoints appear anywhere in it.
"""

from mlwsg.testbed.network import (
    SANDBOX_ENV_VAR,
    SIMULATED_DNS,
    SandboxViolation,
    resolve_simulated_url,
    sandbox_enabled,
)

__all__ = [
    "SANDBOX_ENV_VAR",
    "SIMULATED_DNS",
    "SandboxViolation",
    "resolve_simulated_url",
    "sandbox_enabled",
]
