"""Synthetic HTTP services for the isolated SSRF lab; no real secrets or cloud APIs."""

import os
import re
from ipaddress import ip_address

import aiohttp
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from mlwsg.egress import Blocked, FetchError, Guard, _system_resolve

SERVICES = frozenset({"app", "metadata", "internal", "public", "redirect"})


def _result(status: int, body: bytes, content_type: str) -> dict:
    return {
        "status": status,
        "body": body.decode("utf-8", errors="replace"),
        "content_type": content_type,
    }


def create_testbed_app(service: str) -> FastAPI:
    """Create one lab service, selected by name in the container entrypoint."""
    if service not in SERVICES:
        raise ValueError(f"unknown lab service: {service}")
    app = FastAPI(title=f"SSRF lab: {service}")

    @app.get("/health")
    async def health() -> dict:
        return {"service": service, "status": "ok"}

    if service == "app":
        app.state.guard = Guard()

        @app.get("/fetch", response_model=None)
        async def fetch(url: str) -> dict | JSONResponse:
            try:
                fetched = await app.state.guard.fetch(url)
            except Blocked as exc:
                return JSONResponse(
                    status_code=403, content={"stage": "egress", "reason": str(exc)}
                )
            except FetchError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            return _result(fetched.status, fetched.body, fetched.content_type)

        @app.get("/resolve")
        async def resolve(host: str) -> dict:
            """DNS answers for the gateway's agent. One lookup; nothing is connected to."""
            if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                raise HTTPException(status_code=400, detail="invalid hostname")
            try:
                answers = await _system_resolve(host, 80)
            except OSError:
                answers = []
            return {"host": host, "answers": list(dict.fromkeys(answers))[:16]}

        @app.get("/unsafe-fetch")
        async def unsafe_fetch(url: str, request: Request) -> dict:
            # Explicitly opt in *inside* the isolated app container. The container
            # has no published port and only local callers can use this baseline.
            client = request.client
            if (
                os.environ.get("MLWSG_ENABLE_UNSAFE_FETCH") != "1"
                or client is None
                or not ip_address(client.host).is_loopback
            ):
                raise HTTPException(status_code=404)
            try:
                async with (
                    aiohttp.ClientSession(
                        trust_env=False,
                        cookie_jar=aiohttp.DummyCookieJar(),
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as session,
                    session.get(url) as response,
                ):
                    body = await response.content.read(1_048_577)
                    if len(body) > 1_048_576:
                        raise HTTPException(status_code=502, detail="lab response body too large")
                    return _result(response.status, body, response.headers.get("Content-Type", ""))
            except (aiohttp.ClientError, TimeoutError, ValueError) as exc:
                raise HTTPException(status_code=502, detail="lab baseline fetch failed") from exc

    elif service == "metadata":

        @app.get("/computeMetadata/v1/instance/service-accounts/default/token")
        async def gcp_token() -> dict:
            return {"access_token": "DUMMY_LAB_TOKEN_NOT_A_CREDENTIAL", "expires_in": 0}

        @app.get("/computeMetadata/v1/{path:path}")
        @app.get("/latest/meta-data/{path:path}")
        async def metadata_path(path: str) -> dict:
            return {"service": "fake-metadata", "path": path, "value": "DUMMY_LAB_VALUE"}

    elif service == "internal":

        @app.get("/admin")
        async def admin() -> dict:
            return {"service": "fake-internal-admin", "message": "DUMMY_LAB_PRIVATE_DATA"}

        @app.get("/")
        async def internal_root() -> dict:
            return {"service": "fake-internal", "message": "DUMMY_LAB_PRIVATE_DATA"}

    elif service == "public":

        @app.get("/")
        @app.get("/ok")
        async def public_page() -> dict:
            return {"service": "public-lab", "message": "hello from the lab"}

    else:

        @app.get("/r")
        async def redirect(to: str) -> RedirectResponse:
            return RedirectResponse(to, status_code=302)

    return app


app = create_testbed_app(os.environ.get("MLWSG_SERVICE", "app"))
