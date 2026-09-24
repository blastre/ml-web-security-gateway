"""Start the testbed: the vulnerable app and the simulated internal services.

Both servers are started in background threads so one command brings the whole
environment up::

    python -m mlwsg testbed
"""

from __future__ import annotations

import threading
import time
from typing import Any

import uvicorn

from mlwsg.config import INTERNAL_SERVICES_PORT, TESTBED_HOST, VULNERABLE_APP_PORT
from mlwsg.testbed.network import EXTERNAL_BIND_ENV_VAR, external_bind_allowed, sandbox_enabled


class ServerThread(threading.Thread):
    """A uvicorn server running in a daemon thread."""

    def __init__(self, app_path: str, host: str, port: int, log_level: str = "warning") -> None:
        super().__init__(daemon=True, name=f"uvicorn:{port}")
        self.config = uvicorn.Config(app_path, host=host, port=port, log_level=log_level)
        self.server = uvicorn.Server(self.config)

    def run(self) -> None:  # pragma: no cover - exercised by the runner, not tests
        self.server.run()

    def wait_until_started(self, timeout: float = 15.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if getattr(self.server, "started", False):
                return True
            time.sleep(0.05)
        return False

    def stop(self) -> None:
        self.server.should_exit = True


def _assert_safe_bind(host: str) -> None:
    """Refuse to expose a deliberately vulnerable app beyond loopback."""
    if host in ("127.0.0.1", "::1", "localhost"):
        return
    if external_bind_allowed():
        print(
            f"!! WARNING: binding the vulnerable testbed to {host}. It has no input "
            f"validation and will fetch any URL it is given. Do not do this on a "
            f"network you do not control."
        )
        return
    raise SystemExit(
        f"refusing to bind the vulnerable testbed to {host!r}. This application is "
        f"deliberately vulnerable and must stay on loopback. Set "
        f"{EXTERNAL_BIND_ENV_VAR}=1 only if you understand the consequences."
    )


def run_testbed(
    host: str = TESTBED_HOST,
    app_port: int = VULNERABLE_APP_PORT,
    internal_port: int = INTERNAL_SERVICES_PORT,
    log_level: str = "warning",
) -> None:  # pragma: no cover - long-running process
    """Run both servers until interrupted."""
    _assert_safe_bind(host)

    internal = ServerThread("mlwsg.testbed.internal_services:app", host, internal_port, log_level)
    vulnerable = ServerThread("mlwsg.testbed.vulnerable_app:app", host, app_port, log_level)

    internal.start()
    vulnerable.start()
    for server in (internal, vulnerable):
        server.wait_until_started()

    sandbox = "ON  (outbound confined to loopback)" if sandbox_enabled() else "OFF (unconfined)"
    print(
        "\n".join(
            [
                "",
                "  MLWSG Phase 1 testbed",
                "  " + "-" * 56,
                f"  Vulnerable application   http://{host}:{app_port}/",
                f"  Simulated internals      http://{host}:{internal_port}/",
                f"  Sandbox                  {sandbox}",
                "",
                "  The application performs NO destination validation. Try:",
                f"    curl 'http://{host}:{app_port}/fetch?url=http://metadata.sim.local/metadata/v1/credentials'",
                f"    curl 'http://{host}:{app_port}/fetch?url=http://127.0.0.1:{internal_port}/admin'",
                "",
                "  Ctrl-C to stop.",
                "",
            ]
        )
    )

    try:
        while internal.is_alive() and vulnerable.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  stopping testbed ...")
    finally:
        for server in (vulnerable, internal):
            server.stop()
        for server in (vulnerable, internal):
            server.join(timeout=5)


def main(**kwargs: Any) -> None:  # pragma: no cover
    run_testbed(**kwargs)


if __name__ == "__main__":  # pragma: no cover
    main()
